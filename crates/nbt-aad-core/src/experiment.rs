//! Hardware experiment E1 (`docs/HARDWARE_EXPERIMENT_E1.md`), approved by
//! the operator on 2026-11-09: remount behaviour, scratch-only writes,
//! Force Stop / autostart, and durability across a restart.
//!
//! Writes are restricted to one scratch directory and the profile's remount
//! command; every command is a typed [`MutatingCommand`] or a guarded
//! read-only command, and every execution is recorded. The run stops before
//! the first write unless `inspect` matches the profile and verifies the
//! install, the scratch directory does not exist yet, and exactly one USB
//! stick carries the test files with the expected digests.

use std::time::Duration;

use crate::guard::{Consent, Context, GuardedCommand, MutatingCommand, NodePath, SafePath};
use crate::inspect::{self, InspectConfig, InspectError, InspectReport, Verdict};
use crate::probe::{LsEntry, guarded_plan, parse_ls, parse_ls_dirs};
use crate::profile::{HeadUnitProfile, ids};
use crate::release::KnownRelease;
use crate::transport::{
    ExecLimits, ExecResult, ExitOutcome, HeadUnitTransport, Policy, RecordedError, Recorder,
    TranscriptSink, TransportError, sha256_hex,
};

pub const SCRATCH: &str = "/opt/aa/nbt-aad-e1-scratch";
pub const USB_DIR: &str = "nbt-e1";
pub const FILES: [&str; 3] = ["f1", "f2", "f3"];
/// What the operator must type to allow E1's scratch writes.
pub const CONSENT_WORD: &str = "SCRATCH-WRITES";
pub const PIDIN_POLLS: usize = 12;
pub const PIDIN_INTERVAL: Duration = Duration::from_secs(10);
pub const SETTLE_BEFORE_RESTART: Duration = Duration::from_secs(5);

/// Expected test files on the stick (host-generated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E1Files {
    pub sha256: [String; 3],
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum E1Error {
    #[error("E1 plan invalid: {0}")]
    Plan(String),
    #[error("not starting E1 (no write was made): {0}")]
    Precondition(String),
    #[error("connection lost after {executed} recorded executions: {reason}")]
    ConnectionLost { executed: u32, reason: String },
    #[error(transparent)]
    Sink(#[from] crate::transport::SinkError),
    #[error(transparent)]
    Inspect(#[from] InspectError),
}

/// Operator interaction during phase 1.
#[allow(async_fn_in_trait)]
pub trait E1Operator {
    /// Ask the operator to use iDrive Force Stop; returns when they confirm.
    async fn force_stop(&mut self);
    async fn sleep(&mut self, d: Duration);
}

#[derive(Debug)]
pub struct Phase1 {
    pub inspect: InspectReport,
    pub usb_mount: Option<String>,
    /// Human-readable result lines (also written to the report).
    pub lines: Vec<String>,
    /// A remount rw was executed (a restart is needed to return to ro).
    pub remounted: bool,
    /// Why the run stopped early, if it did.
    pub stopped: Option<String>,
}

#[derive(Debug)]
pub struct Phase2 {
    pub inspect: InspectReport,
    pub lines: Vec<String>,
    /// `f3b` read back after the restart with the expected digest.
    pub f3_survived: Option<bool>,
}

fn node(p: &HeadUnitProfile) -> Result<NodePath, E1Error> {
    NodePath::new(p.daemon_node).map_err(|e| E1Error::Plan(e.to_string()))
}

fn plan_cmd(p: &HeadUnitProfile, id: &str) -> Result<GuardedCommand, E1Error> {
    guarded_plan(&node(p)?)
        .map_err(|e| E1Error::Plan(e.to_string()))?
        .into_iter()
        .find(|(i, _)| i == id)
        .map(|(_, c)| c)
        .ok_or_else(|| E1Error::Plan(format!("probe plan has no {id}")))
}

fn lost(rec_executed: u32, e: TransportError) -> E1Error {
    E1Error::ConnectionLost {
        executed: rec_executed,
        reason: e.to_string(),
    }
}

fn rc(r: &ExecResult) -> String {
    r.outcome.to_string()
}

async fn read<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    id: &str,
    policy: Policy,
    cmd: &GuardedCommand,
    limits: ExecLimits,
) -> Result<Option<ExecResult>, E1Error> {
    match rec.exec(id, policy, cmd, limits).await {
        Ok(r) => Ok(Some(r)),
        Err(RecordedError::Sink(e)) => Err(e.into()),
        Err(RecordedError::Transport(TransportError::Rejected(_))) => Ok(None),
        Err(RecordedError::Transport(e)) => Err(lost(rec.executed(), e)),
    }
}

async fn mutate<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    id: &str,
    cmd: &MutatingCommand,
    consent: &Consent,
    limits: ExecLimits,
) -> Result<Option<ExecResult>, E1Error> {
    match rec.exec_mutating(id, cmd, consent, limits).await {
        Ok(r) => Ok(Some(r)),
        Err(RecordedError::Sink(e)) => Err(e.into()),
        Err(RecordedError::Transport(TransportError::Rejected(_))) => Ok(None),
        Err(RecordedError::Transport(e)) => Err(lost(rec.executed(), e)),
    }
}

fn safe(path: &str) -> Result<SafePath, E1Error> {
    SafePath::new(path).ok_or_else(|| E1Error::Plan(format!("unsafe path {path}")))
}

fn hu(p: &HeadUnitProfile) -> Result<Context, E1Error> {
    Ok(Context::Node(node(p)?))
}

/// `cat` a file and return its digest (None if unreadable or truncated).
async fn digest<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    id: &str,
    path: &str,
    cfg: &InspectConfig,
) -> Result<Option<(u64, String)>, E1Error> {
    let cmd =
        GuardedCommand::cat(hu(p)?, &safe(path)?).map_err(|e| E1Error::Plan(e.to_string()))?;
    let r = read(
        rec,
        id,
        Policy::Binary {
            label: format!("e1{path}"),
        },
        &cmd,
        cfg.readback_limits,
    )
    .await?;
    Ok(
        r.filter(|r| r.outcome.is_success() && r.stdout_dropped == 0)
            .map(|r| (r.stdout.len() as u64, sha256_hex(&r.stdout))),
    )
}

async fn ls<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    id: &str,
    path: &str,
    cfg: &InspectConfig,
) -> Result<Option<ExecResult>, E1Error> {
    let cmd =
        GuardedCommand::ls_la(hu(p)?, &safe(path)?).map_err(|e| E1Error::Plan(e.to_string()))?;
    read(rec, id, Policy::Text, &cmd, cfg.text_limits).await
}

fn is_usb_name(n: &str) -> bool {
    n.strip_prefix("umass").is_some_and(|r| {
        !r.is_empty()
            && r.len() <= 16
            && r.bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
    })
}

/// Phase 1: everything before the operator's restart.
#[allow(clippy::too_many_arguments)]
pub async fn phase1<T, S, O>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    table: &'static [KnownRelease],
    cfg: &InspectConfig,
    banner: Option<String>,
    files: &E1Files,
    consent: &Consent,
    op: &mut O,
) -> Result<Phase1, E1Error>
where
    T: HeadUnitTransport,
    S: TranscriptSink,
    O: E1Operator,
{
    if consent.what() != CONSENT_WORD {
        return Err(E1Error::Plan("consent is not for E1".into()));
    }
    let report = inspect::run(rec, p, table, cfg, banner).await?;
    let mut lines = vec![format!("before: inspect verdict {:?}", report.verdict())];
    let mut out = Phase1 {
        inspect: report,
        usb_mount: None,
        lines: Vec::new(),
        remounted: false,
        stopped: None,
    };
    if out.inspect.verdict() != Verdict::Verified {
        return Err(E1Error::Precondition(
            "inspect did not verify the profile and the installed release".into(),
        ));
    }
    let scratch_name = SCRATCH.rsplit('/').next().unwrap_or_default();
    // Any entry with the scratch name (directory, file, link) stops E1.
    let listing = out
        .inspect
        .observation
        .records
        .get(ids::LS_DAEMON_DIR)
        .map(|r| r.stdout.clone())
        .unwrap_or_default();
    if listing
        .lines()
        .any(|l| l.split_ascii_whitespace().any(|w| w == scratch_name))
    {
        return Err(E1Error::Precondition(format!(
            "{SCRATCH} already exists (earlier E1 run?)"
        )));
    }

    // Locate the stick by the digests of the test files.
    let mnt = ls(rec, p, "e1-ls-mnt", "/mnt", cfg).await?;
    let candidates: Vec<String> = mnt
        .filter(|r| r.outcome.is_success())
        .map(|r| parse_ls_dirs(&String::from_utf8_lossy(&r.stdout)))
        .unwrap_or_default()
        .into_iter()
        .filter(|n| is_usb_name(n))
        .take(8)
        .collect();
    let mut found = Vec::new();
    for c in candidates {
        let dir = format!("/mnt/{c}/{USB_DIR}");
        let listed = ls(rec, p, "e1-ls-usb", &dir, cfg).await?;
        if !listed.is_some_and(|r| r.outcome.is_success()) {
            continue;
        }
        let mut ok = true;
        for (i, f) in FILES.iter().enumerate() {
            let d = digest(rec, p, "e1-usb-readback", &format!("{dir}/{f}"), cfg).await?;
            ok &= d == Some((files.size, files.sha256[i].clone()));
        }
        if ok {
            found.push(format!("/mnt/{c}"));
        }
    }
    if found.len() != 1 {
        return Err(E1Error::Precondition(format!(
            "expected exactly one USB stick with {USB_DIR}/ and matching test files, found {}",
            found.len()
        )));
    }
    let usb = found.remove(0);
    lines.push(format!("usb: {usb}/{USB_DIR} verified (3 files)"));
    out.usb_mount = Some(usb.clone());

    let pidin = plan_cmd(p, "hu-pidin-arg")?;
    let test_w = plan_cmd(p, "hu-test-w-opt-aa")?;
    let pid_line = |r: &Option<ExecResult>| -> String {
        r.as_ref().map_or("rejected".into(), |r| {
            let running = String::from_utf8_lossy(&r.stdout)
                .contains(&format!("{}/{}", p.daemon_dir, p.daemon_name));
            format!("rc={} daemon_running={running}", rc(r))
        })
    };
    let r = read(rec, "e1-pidin-start", Policy::Text, &pidin, cfg.text_limits).await?;
    lines.push(format!("start: pidin {}", pid_line(&r)));

    let login = Context::Login;
    let s = |rel: &str| format!("{SCRATCH}{rel}");
    let rw = MutatingCommand::new(
        login.clone(),
        &format!("mount -o remount rw {}", remount_target(p)?),
    );
    let ro = MutatingCommand::new(
        login,
        &format!("mount -o remount ro {}", remount_target(p)?),
    );
    let lim = cfg.text_limits;

    // E1a / E1b
    let r = mutate(rec, "e1a-remount-rw", &rw, consent, lim).await?;
    out.remounted = true;
    lines.push(format!(
        "E1a remount rw: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    let r = read(rec, "e1a-test-w", Policy::Text, &test_w, lim).await?;
    lines.push(format!(
        "E1a test -w /opt/aa: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    let r = mutate(rec, "e1b-remount-ro", &ro, consent, lim).await?;
    lines.push(format!(
        "E1b remount ro: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    let r = read(rec, "e1b-test-w", Policy::Text, &test_w, lim).await?;
    lines.push(format!(
        "E1b test -w /opt/aa: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));

    // E1c: scratch writes (stop at the first failure).
    let r = mutate(rec, "e1c-remount-rw", &rw, consent, lim).await?;
    lines.push(format!(
        "E1c remount rw: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    let r = read(rec, "e1c-test-w", Policy::Text, &test_w, lim).await?;
    let writable = r
        .as_ref()
        .is_some_and(|r| r.outcome == ExitOutcome::Code(0));
    lines.push(format!(
        "E1c test -w /opt/aa: {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    if !writable {
        out.stopped =
            Some("remount rw did not make /opt/aa writable; no scratch write attempted".into());
        out.lines = lines;
        return Ok(out);
    }
    let hu_ctx = hu(p)?;
    let usbf = |f: &str| format!("{usb}/{USB_DIR}/{f}");
    let steps: Vec<(&str, String)> = vec![
        ("e1c-mkdir", format!("mkdir {}", s(""))),
        ("e1c-cp-f1", format!("cp {} {}", usbf("f1"), s("/f1"))),
        ("e1c-chmod-f1", format!("chmod 755 {}", s("/f1"))),
        ("e1c-mkdir-d", format!("mkdir {}", s("/d"))),
        ("e1c-cp-f2", format!("cp {} {}", usbf("f2"), s("/d/f2"))),
        ("e1c-mv-dir", format!("mv {} {}", s("/d"), s("/d2"))),
        ("e1c-mv-file", format!("mv {} {}", s("/f1"), s("/f1b"))),
    ];
    for (id, body) in &steps {
        let cmd = MutatingCommand::new(hu_ctx.clone(), body);
        let r = mutate(rec, id, &cmd, consent, lim).await?;
        let ok = r
            .as_ref()
            .is_some_and(|r| r.outcome == ExitOutcome::Code(0));
        lines.push(format!(
            "E1c {body}: {}",
            r.as_ref().map_or("rejected".into(), rc)
        ));
        if !ok {
            out.stopped = Some(format!("{id} failed; later steps skipped"));
            out.lines = lines;
            return Ok(out);
        }
        if *id == "e1c-cp-f1" {
            let d = digest(rec, p, "e1c-readback-f1", &s("/f1"), cfg).await?;
            lines.push(format!(
                "E1c read-back f1 matches: {}",
                d == Some((files.size, files.sha256[0].clone()))
            ));
        }
    }
    for (id, path) in [("e1c-ls", s("")), ("e1c-ls-d2", s("/d2"))] {
        let r = ls(rec, p, id, &path, cfg).await?;
        if let Some(r) = r {
            for e in parse_ls(&String::from_utf8_lossy(&r.stdout)) {
                if let LsEntry::File { name, size } = e {
                    lines.push(format!("E1c ls {path}: {name} size={size:?}"));
                }
            }
            lines.push(format!(
                "E1c ls -la {path} (raw in transcript): rc={}",
                rc(&r)
            ));
        }
    }
    for (id, path, i) in [
        ("e1c-readback-f1b", s("/f1b"), 0),
        ("e1c-readback-f2", s("/d2/f2"), 1),
    ] {
        let d = digest(rec, p, id, &path, cfg).await?;
        lines.push(format!(
            "E1c read-back {path} matches: {}",
            d == Some((files.size, files.sha256[i].clone()))
        ));
    }

    // E1d: Force Stop and watch for autostart.
    op.force_stop().await;
    for k in 0..PIDIN_POLLS {
        let r = read(rec, "e1d-pidin", Policy::Text, &pidin, lim).await?;
        lines.push(format!(
            "E1d t+{:>3}s pidin {}",
            k as u64 * PIDIN_INTERVAL.as_secs(),
            pid_line(&r)
        ));
        if k + 1 < PIDIN_POLLS {
            op.sleep(PIDIN_INTERVAL).await;
        }
    }

    // E1e: write, settle, then the operator restarts.
    for (id, body) in [
        ("e1e-cp-f3", format!("cp {} {}", usbf("f3"), s("/f3"))),
        ("e1e-mv-f3", format!("mv {} {}", s("/f3"), s("/f3b"))),
    ] {
        let cmd = MutatingCommand::new(hu_ctx.clone(), &body);
        let r = mutate(rec, id, &cmd, consent, lim).await?;
        let ok = r
            .as_ref()
            .is_some_and(|r| r.outcome == ExitOutcome::Code(0));
        lines.push(format!(
            "E1e {body}: {}",
            r.as_ref().map_or("rejected".into(), rc)
        ));
        if !ok {
            out.stopped = Some(format!("{id} failed"));
            out.lines = lines;
            return Ok(out);
        }
    }
    let d = digest(rec, p, "e1e-readback-f3b", &s("/f3b"), cfg).await?;
    lines.push(format!(
        "E1e read-back f3b before restart matches: {}",
        d == Some((files.size, files.sha256[2].clone()))
    ));
    op.sleep(SETTLE_BEFORE_RESTART).await;
    lines.push(format!(
        "E1e waited {} s; operator restart next",
        SETTLE_BEFORE_RESTART.as_secs()
    ));
    out.lines = lines;
    Ok(out)
}

/// The remount target from the profile's remount command (last word).
fn remount_target(p: &HeadUnitProfile) -> Result<&'static str, E1Error> {
    let c = p.remount.value.command;
    match c.split(' ').collect::<Vec<_>>().as_slice() {
        ["mount", "-o", "remount", "rw", target] if SafePath::new(target).is_some() => Ok(target),
        _ => Err(E1Error::Plan(format!("unexpected remount command {c:?}"))),
    }
}

/// Phase 2: after the operator's restart, on a new session.
pub async fn phase2<T, S>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    table: &'static [KnownRelease],
    cfg: &InspectConfig,
    banner: Option<String>,
    files: &E1Files,
    before: &Phase1,
) -> Result<Phase2, E1Error>
where
    T: HeadUnitTransport,
    S: TranscriptSink,
{
    let report = inspect::run(rec, p, table, cfg, banner).await?;
    let mut lines = vec![format!("after: inspect verdict {:?}", report.verdict())];
    let same = report.state == before.inspect.state;
    lines.push(format!("after: install state unchanged by E1: {same}"));
    let test_w = plan_cmd(p, "hu-test-w-opt-aa")?;
    let r = read(rec, "e1f-test-w", Policy::Text, &test_w, cfg.text_limits).await?;
    lines.push(format!(
        "E1e after restart test -w /opt/aa (1 = read-only again): {}",
        r.as_ref().map_or("rejected".into(), rc)
    ));
    let mut f3_survived = None;
    if before.stopped.is_none() {
        let r = ls(rec, p, "e1f-ls", SCRATCH, cfg).await?;
        if let Some(r) = r {
            for e in parse_ls(&String::from_utf8_lossy(&r.stdout)) {
                if let LsEntry::File { name, size } = e {
                    lines.push(format!("E1e after restart ls: {name} size={size:?}"));
                }
            }
        }
        for (id, rel, i) in [
            ("e1f-readback-f3b", "/f3b", 2),
            ("e1f-readback-f1b", "/f1b", 0),
            ("e1f-readback-f2", "/d2/f2", 1),
        ] {
            let d = digest(rec, p, id, &format!("{SCRATCH}{rel}"), cfg).await?;
            let ok = d == Some((files.size, files.sha256[i].clone()));
            if rel == "/f3b" {
                f3_survived = Some(ok);
            }
            lines.push(format!("E1e after restart {rel} present and intact: {ok}"));
        }
    }
    Ok(Phase2 {
        inspect: report,
        lines,
        f3_survived,
    })
}

#[cfg(test)]
mod tests;
