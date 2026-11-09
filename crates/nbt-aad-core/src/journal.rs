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
            ["COMPLETE"] => Event::Complete,
            ["ROLLEDBACK"] => Event::RolledBack,
            _ => return None,
        })
    }
}

/// Free text inside a journal field: no separators, bounded.
fn field(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
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
                if i == 0 {
                    match &e {
                        Event::Begin { .. } => {}
                        _ => return Err(bad("first event is not BEGIN")),
                    }
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

/// Performs mutations and read-only verification. Implemented by the
/// simulator only.
pub trait Executor {
    fn exec(&mut self, m: &Mutation) -> Result<(), String>;
    fn verify(&mut self, v: &Verify) -> bool;
    /// Whether a path exists (for state-driven recovery).
    fn exists(&mut self, path: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("step {step}: mutation failed: {reason}")]
    Mutation { step: String, reason: String },
    #[error("step {step}: verification failed: {what}")]
    Verification { step: String, what: String },
    #[error("journal does not belong to this plan")]
    WrongPlan,
}

/// Run the plan. Every mutation is preceded by a durable `Intent` and
/// followed by `Done`; every step ends with its verifications. Any failure
/// stops immediately (no retries, no skipping).
pub fn apply<S: JournalStore, E: Executor>(
    plan: &UpdatePlan,
    j: &mut Journal<S>,
    ex: &mut E,
) -> Result<(), ApplyError> {
    let mut index = 0usize;
    for st in &plan.steps {
        for m in &st.mutations {
            j.append(&Event::Intent {
                step: st.id.into(),
                index,
                mutation: field(&m.render()),
            })?;
            if let Err(reason) = ex.exec(m) {
                let _ = j.append(&Event::Failed {
                    step: st.id.into(),
                    reason: field(&reason),
                });
                return Err(ApplyError::Mutation {
                    step: st.id.into(),
                    reason,
                });
            }
            j.append(&Event::Done {
                step: st.id.into(),
                index,
            })?;
            index += 1;
        }
        for v in &st.verify {
            if !ex.verify(v) {
                let what = format!("{v:?}");
                let _ = j.append(&Event::Failed {
                    step: st.id.into(),
                    reason: field(&what),
                });
                return Err(ApplyError::Verification {
                    step: st.id.into(),
                    what,
                });
            }
        }
        j.append(&Event::Verified { step: st.id.into() })?;
    }
    j.append(&Event::Complete)?;
    Ok(())
}

/// Steps that may have changed the device: every step with an `Intent`
/// (a mutation may have run even if its `Done` is missing). With a torn
/// tail, the step after the last recorded one may also have started.
fn started_steps(plan: &UpdatePlan, loaded: &Loaded) -> usize {
    let mut started = 0;
    for e in &loaded.events {
        if let Event::Intent { step, .. } = e
            && let Some(i) = plan.steps.iter().position(|s| s.id == step)
        {
            started = started.max(i + 1);
        }
    }
    if loaded.torn_tail {
        started = (started + 1).min(plan.steps.len());
    }
    started
}

/// Recover after an interruption: undo started steps backwards, applying
/// each undo `mv` only if its source exists and its target is free
/// (state-driven), journaling each
/// as an `Intent`/`Done` under `U<step>`. Then verify the original state via
/// `verify_original` and record `RolledBack`.
pub fn recover<S: JournalStore, E: Executor>(
    plan: &UpdatePlan,
    j: &mut Journal<S>,
    loaded: &Loaded,
    ex: &mut E,
    verify_original: impl FnOnce(&mut E) -> bool,
) -> Result<(), ApplyError> {
    match loaded.events.first() {
        Some(Event::Begin {
            op_id, plan_sha256, ..
        }) if *op_id == plan.op_id && *plan_sha256 == plan_digest(plan) => {}
        _ => return Err(ApplyError::WrongPlan),
    }
    let started = started_steps(plan, loaded);
    let mut index = 0usize;
    for st in plan.steps[..started].iter().rev() {
        let uid = format!("U{}", st.id);
        for u in st.undo.iter().rev() {
            let Mutation::Mv { from, to } = u else {
                continue;
            };
            // The forward move happened iff its result is present and its
            // origin is free: every forward move targets a fresh path. Both
            // present means the forward move never ran (e.g. a torn
            // journal tail made the step look started): leave it.
            if !ex.exists(from) || ex.exists(to) {
                continue;
            }
            j.append(&Event::Intent {
                step: uid.clone(),
                index,
                mutation: field(&u.render()),
            })?;
            if let Err(reason) = ex.exec(u) {
                let _ = j.append(&Event::Failed {
                    step: uid.clone(),
                    reason: field(&reason),
                });
                return Err(ApplyError::Mutation { step: uid, reason });
            }
            j.append(&Event::Done {
                step: uid.clone(),
                index,
            })?;
            index += 1;
        }
    }
    if !verify_original(ex) {
        let _ = j.append(&Event::Failed {
            step: "RECOVER".into(),
            reason: "original state not restored".into(),
        });
        return Err(ApplyError::Verification {
            step: "RECOVER".into(),
            what: "original state not restored".into(),
        });
    }
    j.append(&Event::RolledBack)?;
    Ok(())
}

#[cfg(test)]
mod tests;
