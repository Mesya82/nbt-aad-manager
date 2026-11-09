//! Host-side transaction journal and the apply/recover engine (sans-IO).
//!
//! The journal is an append-only text log. Each line is hash-chained to the
//! previous one, so truncation, reordering and edits are detectable. An
//! `Intent` line is durably appended **before** every mutation (CLAUDE.md
//! rule 4). A torn final line (crash during append) is reported separately
//! from corruption.
//!
//! The engine drives an [`Executor`]. In this repository the only executor
//! is the simulator (`testkit::sim`); there is no device apply path.

use crate::plan::{Mutation, UpdatePlan, Verify};
use crate::transport::sha256_hex;

pub const JOURNAL_VERSION: u32 = 1;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Begin {
        op_id: String,
        profile_id: String,
        from: String,
        to: String,
        plan_sha256: String,
    },
    /// About to run mutation `index` (global, in plan order) of `step`.
    Intent {
        step: String,
        index: usize,
        mutation: String,
    },
    Done {
        step: String,
        index: usize,
    },
    Failed {
        step: String,
        reason: String,
    },
    Verified {
        step: String,
    },
    /// Automatic steps done; waiting for the operator (e.g. restart).
    Awaiting {
        step: String,
    },
    Complete,
    /// Recovery finished: the original state was restored and verified.
    RolledBack,
}

impl Event {
    fn encode(&self) -> String {
        match self {
            Event::Begin {
                op_id,
                profile_id,
                from,
                to,
                plan_sha256,
            } => format!("BEGIN\t{op_id}\t{profile_id}\t{from}\t{to}\t{plan_sha256}"),
            Event::Intent {
                step,
                index,
                mutation,
            } => format!("INTENT\t{step}\t{index}\t{mutation}"),
            Event::Done { step, index } => format!("DONE\t{step}\t{index}"),
            Event::Failed { step, reason } => format!("FAILED\t{step}\t{reason}"),
            Event::Verified { step } => format!("VERIFIED\t{step}"),
            Event::Awaiting { step } => format!("AWAITING\t{step}"),
            Event::Complete => "COMPLETE".into(),
            Event::RolledBack => "ROLLEDBACK".into(),
        }
    }

    fn decode(s: &str) -> Option<Self> {
        let f: Vec<&str> = s.split('\t').collect();
        Some(match f.as_slice() {
            ["BEGIN", op, prof, from, to, sha] => Event::Begin {
                op_id: (*op).into(),
                profile_id: (*prof).into(),
                from: (*from).into(),
                to: (*to).into(),
                plan_sha256: (*sha).into(),
            },
            ["INTENT", step, i, m] => Event::Intent {
                step: (*step).into(),
                index: i.parse().ok()?,
                mutation: (*m).into(),
            },
            ["DONE", step, i] => Event::Done {
                step: (*step).into(),
                index: i.parse().ok()?,
            },
            ["FAILED", step, r] => Event::Failed {
                step: (*step).into(),
                reason: (*r).into(),
            },
            ["VERIFIED", step] => Event::Verified {
                step: (*step).into(),
            },
            ["AWAITING", step] => Event::Awaiting {
                step: (*step).into(),
            },
            ["COMPLETE"] => Event::Complete,
            ["ROLLEDBACK"] => Event::RolledBack,
            _ => return None,
        })
    }
}

/// Free text inside a journal field: no separators, bounded.
fn field(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("journal store: {0}")]
    Io(String),
}

/// Durable append-only storage. `append` must not return `Ok` before the
/// line is persisted (fsync for files).
pub trait JournalStore {
    fn append(&mut self, line: &str) -> Result<(), StoreError>;
    fn load(&self) -> Result<String, StoreError>;
    /// Remove bytes after the last complete line (a crash during append).
    fn drop_torn_tail(&mut self) -> Result<(), StoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("journal corrupt at line {line}: {why}")]
    Corrupt { line: usize, why: String },
    #[error("journal already exists; refusing to start a new operation over it")]
    NotEmpty,
}

/// Result of reading a journal back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub events: Vec<Event>,
    /// The last line was incomplete (crash during append): its event is
    /// unknown. Recovery must then be state-driven only.
    pub torn_tail: bool,
}

pub struct Journal<S: JournalStore> {
    store: S,
    seq: u64,
    last: String,
}

fn line_hash(prev: &str, seq: u64, body: &str) -> String {
    sha256_hex(format!("{prev}\t{seq}\t{body}").as_bytes())
}

/// Parse and verify a journal's text.
pub fn parse(text: &str) -> Result<(Loaded, u64, String), JournalError> {
    let mut events = Vec::new();
    let mut prev = GENESIS.to_owned();
    let mut seq = 0u64;
    let mut torn_tail = false;
    let ends_clean = text.is_empty() || text.ends_with('\n');
    let lines: Vec<&str> = text.split_terminator('\n').collect();
    for (i, l) in lines.iter().enumerate() {
        let last = i + 1 == lines.len();
        let bad = |why: &str| JournalError::Corrupt {
            line: i + 1,
            why: why.into(),
        };
        let parts: Vec<&str> = l.splitn(3, '\t').collect();
        let ok = (|| {
            let [s, h, body] = parts.as_slice() else {
                return Err("malformed");
            };
            let s: u64 = s.parse().map_err(|_| "bad sequence")?;
            if s != seq + 1 {
                return Err("sequence gap");
            }
            if *h != line_hash(&prev, s, body) {
                return Err("hash chain broken");
            }
            let e = Event::decode(body).ok_or("unknown event")?;
            Ok((s, (*h).to_owned(), e))
        })();
        match ok {
            Ok((s, h, e)) if !(last && !ends_clean) => {
                // Event order: BEGIN first and only once; nothing after a
                // terminal event; each DONE directly follows its INTENT.
                match (events.last(), &e) {
                    (None, Event::Begin { .. }) => {}
                    (None, _) => return Err(bad("first event is not BEGIN")),
                    (Some(_), Event::Begin { .. }) => return Err(bad("second BEGIN")),
                    (Some(Event::Complete | Event::RolledBack), _) => {
                        return Err(bad("event after a terminal event"));
                    }
                    (
                        Some(Event::Intent {
                            step: s0,
                            index: i0,
                            ..
                        }),
                        Event::Done { step, index },
                    ) if s0 == step && i0 == index => {}
                    (_, Event::Done { .. }) => return Err(bad("DONE without its INTENT")),
                    _ => {}
                }
                seq = s;
                prev = h;
                events.push(e);
            }
            // An incomplete final line is a torn append, not corruption.
            _ if last && !ends_clean => torn_tail = true,
            Err(why) => return Err(bad(why)),
            Ok(_) => unreachable!("guarded above"),
        }
    }
    Ok((Loaded { events, torn_tail }, seq, prev))
}

impl<S: JournalStore> Journal<S> {
    /// Start a new operation. The store must be empty.
    pub fn begin(store: S, plan: &UpdatePlan) -> Result<Self, JournalError> {
        if !store.load()?.is_empty() {
            return Err(JournalError::NotEmpty);
        }
        let mut j = Self {
            store,
            seq: 0,
            last: GENESIS.to_owned(),
        };
        j.append(&Event::Begin {
            op_id: plan.op_id.clone(),
            profile_id: plan.profile_id.into(),
            from: plan.from.tag.into(),
            to: plan.to.tag.into(),
            plan_sha256: plan_digest(plan),
        })?;
        Ok(j)
    }

    /// Reopen an existing journal to continue appending (recovery). A torn
    /// tail is first dropped by the store, so the chain continues from the
    /// last complete line; the caller keeps the `Loaded` it read *before*
    /// the repair, which records that the tail was torn.
    pub fn reopen(mut store: S) -> Result<(Self, Loaded), JournalError> {
        let text = store.load()?;
        let (loaded, _, _) = parse(&text)?;
        if loaded.torn_tail {
            store.drop_torn_tail()?;
        }
        let (_, seq, last) = parse(&store.load()?)?;
        Ok((Self { store, seq, last }, loaded))
    }

    pub fn append(&mut self, e: &Event) -> Result<(), JournalError> {
        let body = e.encode();
        let seq = self.seq + 1;
        let h = line_hash(&self.last, seq, &body);
        self.store.append(&format!("{seq}\t{h}\t{body}\n"))?;
        self.seq = seq;
        self.last = h;
        Ok(())
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

/// Digest binding a journal to one exact plan rendering.
pub fn plan_digest(plan: &UpdatePlan) -> String {
    sha256_hex(plan.render().as_bytes())
}

/// Performs mutations and read-only checks. Implemented by the simulator
/// only. Every call distinguishes "false" from "could not tell" (`Err`): a
/// transport error must never be read as "absent" or "not running".
pub trait Executor {
    fn exec(&mut self, m: &Mutation) -> Result<(), String>;
    fn verify(&mut self, v: &Verify) -> Result<bool, String>;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("step {step}: mutation failed: {reason}")]
    Mutation { step: String, reason: String },
    #[error("step {step}: precondition not met: {what}")]
    Precondition { step: String, what: String },
    #[error("step {step}: verification failed: {what}")]
    Verification { step: String, what: String },
    #[error("step {step}: device check failed: {reason}")]
    Check { step: String, reason: String },
    #[error("journal does not belong to this plan")]
    WrongPlan,
    #[error("all active changes are already verified; this needs a rollback, not a recovery")]
    UpdateAlreadyApplied,
}

/// How `apply` ended without error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// All automatic steps done; the operator must act (restart) before the
    /// operation may be marked complete with [`confirm_complete`].
    AwaitingOperator { step: String },
}

fn fail<S: JournalStore>(j: &mut Journal<S>, step: &str, reason: &str) {
    let _ = j.append(&Event::Failed {
        step: step.into(),
        reason: field(reason),
    });
}

/// Check all conditions; any `false` or `Err` stops with a journaled failure.
fn require<S: JournalStore, E: Executor>(
    j: &mut Journal<S>,
    ex: &mut E,
    step: &str,
    checks: &[Verify],
    post: bool,
) -> Result<(), ApplyError> {
    for v in checks {
        match ex.verify(v) {
            Ok(true) => {}
            Ok(false) => {
                let what = format!("{v:?}");
                fail(j, step, &what);
                return Err(if post {
                    ApplyError::Verification {
                        step: step.into(),
                        what,
                    }
                } else {
                    ApplyError::Precondition {
                        step: step.into(),
                        what,
                    }
                });
            }
            Err(reason) => {
                fail(j, step, &reason);
                return Err(ApplyError::Check {
                    step: step.into(),
                    reason,
                });
            }
        }
    }
    Ok(())
}

fn run<S: JournalStore, E: Executor>(
    j: &mut Journal<S>,
    ex: &mut E,
    step: &str,
    index: usize,
    m: &Mutation,
) -> Result<(), ApplyError> {
    j.append(&Event::Intent {
        step: step.into(),
        index,
        mutation: field(&m.render()),
    })?;
    if let Err(reason) = ex.exec(m) {
        fail(j, step, &reason);
        return Err(ApplyError::Mutation {
            step: step.into(),
            reason,
        });
    }
    j.append(&Event::Done {
        step: step.into(),
        index,
    })?;
    Ok(())
}

/// Run the plan's automatic steps. Each step's preconditions are re-checked
/// on the device first; every mutation is preceded by a durable `Intent`;
/// every step ends with its verifications. Stops at the first failure and
/// at the first operator step (never marks the operation complete itself).
pub fn apply<S: JournalStore, E: Executor>(
    plan: &UpdatePlan,
    j: &mut Journal<S>,
    ex: &mut E,
) -> Result<ApplyOutcome, ApplyError> {
    let mut index = 0usize;
    for st in &plan.steps {
        if st.verify.iter().any(|v| matches!(v, Verify::Operator(_))) {
            j.append(&Event::Awaiting { step: st.id.into() })?;
            return Ok(ApplyOutcome::AwaitingOperator { step: st.id.into() });
        }
        require(j, ex, st.id, &st.pre, false)?;
        for m in &st.mutations {
            run(j, ex, st.id, index, m)?;
            index += 1;
        }
        require(j, ex, st.id, &st.verify, true)?;
        j.append(&Event::Verified { step: st.id.into() })?;
    }
    Err(ApplyError::Verification {
        step: "PLAN".into(),
        what: "plan has no operator step".into(),
    })
}

/// Record completion after the operator restarted the unit **and** a fresh
/// inspection verified the target (`post_restart_verified`).
pub fn confirm_complete<S: JournalStore>(
    j: &mut Journal<S>,
    post_restart_verified: bool,
) -> Result<(), ApplyError> {
    if !post_restart_verified {
        fail(
            j,
            "S10",
            "post-restart inspection did not verify the target",
        );
        return Err(ApplyError::Verification {
            step: "S10".into(),
            what: "post-restart inspection".into(),
        });
    }
    j.append(&Event::Complete)?;
    Ok(())
}

/// Recover after an interruption, fully state-driven: walk **all** steps
/// backwards and run each undo only when its `only_if` state (exact digests
/// and absences) proves the forward mutation happened. The journal binds
/// the run to this plan and records each recovery mutation; it is not
/// trusted for which steps ran (it may be truncated). Re-establishes the
/// remount first if a restart reverted it. Refuses when all active changes
/// were already verified (that is a rollback, a separate operation).
pub fn recover<S: JournalStore, E: Executor>(
    plan: &UpdatePlan,
    j: &mut Journal<S>,
    loaded: &Loaded,
    ex: &mut E,
    verify_original: impl FnOnce(&mut E) -> Result<bool, String>,
) -> Result<(), ApplyError> {
    match loaded.events.first() {
        Some(Event::Begin {
            op_id, plan_sha256, ..
        }) if *op_id == plan.op_id && *plan_sha256 == plan_digest(plan) => {}
        _ => return Err(ApplyError::WrongPlan),
    }
    let last_active = plan
        .steps
        .iter()
        .rev()
        .find(|s| !s.undo.is_empty())
        .map(|s| s.id);
    if loaded.events.iter().any(|e| {
        matches!(e, Event::Awaiting { .. } | Event::Complete)
            || matches!(e, Event::Verified { step } if Some(step.as_str()) == last_active)
    }) {
        return Err(ApplyError::UpdateAlreadyApplied);
    }
    require(j, ex, "RECOVER", &[Verify::DaemonNotRunning], false)?;

    let mut index = 0usize;
    // A restart reverts the remount: re-establish it (journaled) if needed.
    if let Some(s1) = plan.steps.first() {
        let writable: Vec<Verify> = s1.verify.clone();
        let ok = writable
            .iter()
            .map(|v| ex.verify(v))
            .collect::<Result<Vec<bool>, String>>()
            .map_err(|reason| ApplyError::Check {
                step: "RS1".into(),
                reason,
            })?;
        if ok.iter().any(|b| !b) {
            for m in &s1.mutations {
                run(j, ex, "RS1", index, m)?;
                index += 1;
            }
            require(j, ex, "RS1", &writable, true)?;
        }
    }
    for st in plan.steps.iter().rev() {
        let uid = format!("U{}", st.id);
        for u in st.undo.iter().rev() {
            let mut proven = true;
            for v in &u.only_if {
                match ex.verify(v) {
                    Ok(true) => {}
                    Ok(false) => {
                        proven = false;
                        break;
                    }
                    Err(reason) => {
                        fail(j, &uid, &reason);
                        return Err(ApplyError::Check { step: uid, reason });
                    }
                }
            }
            if proven {
                run(j, ex, &uid, index, &u.mutation)?;
                index += 1;
            }
        }
    }
    match verify_original(ex) {
        Ok(true) => {}
        Ok(false) => {
            fail(j, "RECOVER", "original state not restored");
            return Err(ApplyError::Verification {
                step: "RECOVER".into(),
                what: "original state not restored".into(),
            });
        }
        Err(reason) => {
            fail(j, "RECOVER", &reason);
            return Err(ApplyError::Check {
                step: "RECOVER".into(),
                reason,
            });
        }
    }
    j.append(&Event::RolledBack)?;
    Ok(())
}

#[cfg(test)]
mod tests;
