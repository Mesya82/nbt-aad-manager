//! Read-only inspection: match the live unit against a profile and name its
//! install state by exact digests (workflow C.3–C.4).
//!
//! Sends only commands from the probe's static plan (byte-identical to what
//! ran on the pilot car) plus `cat` read-backs of the daemon, plugin and
//! backup files. Every execution goes through the [`Recorder`].

use std::collections::BTreeSet;

use crate::guard::{Context, GuardedCommand, NodePath, SafePath};
use crate::probe::{LsEntry, guarded_plan, parse_ls, parse_ls_dirs};
use crate::profile::{
    HeadUnitProfile, InstallState, Mismatch, OPS_ROOT_ID, Observation, OpBackup, Rec, classify_in,
    classify_ops, ids, is_op_id, match_profile, op_record_id,
};
use crate::release::{KnownRelease, PLUGIN_FILES};
use crate::transport::{
    ExecLimits, ExitOutcome, HeadUnitTransport, Policy, RecordedError, Recorder, TranscriptSink,
    TransportError, sha256_hex,
};

#[derive(Clone, Debug)]
pub struct InspectConfig {
    pub text_limits: ExecLimits,
    pub readback_limits: ExecLimits,
    /// Files larger than this (per `ls -la`) are not read back.
    pub max_readback_bytes: u64,
}

impl Default for InspectConfig {
    fn default() -> Self {
        Self {
            text_limits: ExecLimits::default(),
            readback_limits: ExecLimits::default(),
            max_readback_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("inspection plan invalid: {0}")]
    Plan(String),
    #[error("connection lost after {executed} recorded executions: {reason}")]
    ConnectionLost { executed: u32, reason: String },
    #[error(transparent)]
    Sink(#[from] crate::transport::SinkError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectReport {
    pub observation: Observation,
    pub profile: Result<(), Vec<Mismatch>>,
    /// Only computed when the profile matched; otherwise `None` (no claim).
    pub state: Option<InstallState>,
    pub executed: u32,
    pub readbacks: u32,
    /// Operation directories and the backups they hold (profile match only).
    pub ops: Option<Result<Vec<OpBackup>, String>>,
}

/// At most this many operation directories are inspected.
pub const MAX_OPS: usize = 16;

/// Probe-plan ids the inspection runs, in plan order.
pub fn plan_ids(p: &HeadUnitProfile) -> BTreeSet<&'static str> {
    let mut s: BTreeSet<&'static str> = [
        ids::LOGIN_UNAME,
        ids::ON_BARE,
        ids::ON_SHELL,
        ids::DAEMON_UNAME,
        ids::FIRMWARE,
        ids::LS_DAEMON_DIR,
        ids::LS_PLUGIN,
        ids::LS_PLUGIN_BACKUP,
        ids::LS_STATE,
    ]
    .into_iter()
    .collect();
    s.extend(p.writable.value.iter().map(|w| w.probe_id));
    s
}

/// The exact guarded commands the inspection may send before read-backs.
pub fn plan(p: &HeadUnitProfile) -> Result<Vec<(String, GuardedCommand)>, InspectError> {
    let node = NodePath::new(p.daemon_node).map_err(|e| InspectError::Plan(e.to_string()))?;
    let want = plan_ids(p);
    let all = guarded_plan(&node).map_err(|e| InspectError::Plan(e.to_string()))?;
    let out: Vec<_> = all
        .into_iter()
        .filter(|(id, _)| want.contains(id.as_str()))
        .collect();
    for id in &want {
        if !out.iter().any(|(i, _)| i == id) {
            return Err(InspectError::Plan(format!("probe plan has no {id}")));
        }
    }
    Ok(out)
}

fn rc_of(o: &ExitOutcome) -> i64 {
    match o {
        ExitOutcome::Code(c) => i64::from(*c),
        _ => -1,
    }
}

async fn exec<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    id: &str,
    policy: Policy,
    cmd: &GuardedCommand,
    limits: ExecLimits,
) -> Result<Option<crate::transport::ExecResult>, InspectError> {
    match rec.exec(id, policy, cmd, limits).await {
        Ok(r) => Ok(Some(r)),
        Err(RecordedError::Sink(e)) => Err(e.into()),
        Err(RecordedError::Transport(TransportError::Rejected(_))) => Ok(None),
        Err(RecordedError::Transport(e)) => Err(InspectError::ConnectionLost {
            executed: rec.executed(),
            reason: e.to_string(),
        }),
    }
}

/// Run the inspection over an established transport.
pub async fn run<T, S>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    table: &'static [KnownRelease],
    cfg: &InspectConfig,
    ssh_banner: Option<String>,
) -> Result<InspectReport, InspectError>
where
    T: HeadUnitTransport,
    S: TranscriptSink,
{
    let node = NodePath::new(p.daemon_node).map_err(|e| InspectError::Plan(e.to_string()))?;
    let mut o = Observation {
        ssh_banner,
        ..Observation::default()
    };
    for (id, cmd) in plan(p)? {
        let r = exec(rec, &id, Policy::Text, &cmd, cfg.text_limits).await?;
        if let Some(r) = r.filter(|r| r.stdout_dropped == 0) {
            o.records.insert(
                id,
                Rec {
                    rc: rc_of(&r.outcome),
                    stdout: String::from_utf8_lossy(&r.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&r.stderr).into_owned(),
                },
            );
        }
    }

    // Read-backs only on a unit that matches the profile (text facts) and
    // whose daemon-node shell demonstrably works.
    let mut readbacks = 0;
    let shell_ok = match_profile(p, &o).is_ok()
        && o.records
            .get(ids::ON_SHELL)
            .is_some_and(|r| r.rc == 0 && r.stdout.trim_end() == "probe-ok");
    if shell_ok {
        let daemon_names = [p.daemon_name, p.daemon_backup_name];
        let sets: [(&str, &str, &[&str]); 3] = [
            (ids::LS_DAEMON_DIR, p.daemon_dir, &daemon_names),
            (ids::LS_PLUGIN, p.plugin_dir, &PLUGIN_FILES),
            (ids::LS_PLUGIN_BACKUP, p.plugin_backup_dir, &PLUGIN_FILES),
        ];
        for (id, dir, names) in sets {
            let Some(listing) = o.records.get(id).filter(|r| r.rc == 0) else {
                continue;
            };
            let files: Vec<(String, u64)> = parse_ls(&listing.stdout)
                .into_iter()
                .filter_map(|e| match e {
                    LsEntry::File {
                        name,
                        size: Some(s),
                    } if names.contains(&name.as_str()) && s <= cfg.max_readback_bytes => {
                        Some((name, s))
                    }
                    _ => None,
                })
                .collect();
            for (name, _) in files {
                let path = format!("{dir}/{name}");
                let Some(sp) = SafePath::new(&path) else {
                    continue;
                };
                let cmd = GuardedCommand::cat(Context::Node(node.clone()), &sp)
                    .map_err(|e| InspectError::Plan(e.to_string()))?;
                let policy = Policy::Binary {
                    label: format!("inspect{path}"),
                };
                let r = exec(rec, "readback", policy, &cmd, cfg.readback_limits).await?;
                readbacks += 1;
                if let Some(r) = r.filter(|r| r.outcome.is_success() && r.stdout_dropped == 0) {
                    o.digests
                        .insert(path, (r.stdout.len() as u64, sha256_hex(&r.stdout)));
                }
            }
        }
    }

    if shell_ok {
        readbacks += inspect_ops(rec, p, &node, cfg, &mut o).await?;
    }

    let profile = match_profile(p, &o);
    let state = profile.is_ok().then(|| classify_in(p, &o, table));
    let ops = profile.is_ok().then(|| classify_ops(p, &o, table));
    Ok(InspectReport {
        observation: o,
        profile,
        state,
        executed: rec.executed(),
        readbacks,
        ops,
    })
}

async fn text<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    node: &NodePath,
    cfg: &InspectConfig,
    o: &mut Observation,
    id: String,
    path: &str,
) -> Result<bool, InspectError> {
    let Some(sp) = SafePath::new(path) else {
        return Ok(false);
    };
    let cmd = GuardedCommand::ls_la(Context::Node(node.clone()), &sp)
        .map_err(|e| InspectError::Plan(e.to_string()))?;
    let r = exec(rec, &id, Policy::Text, &cmd, cfg.text_limits).await?;
    let Some(r) = r.filter(|r| r.stdout_dropped == 0) else {
        return Ok(false);
    };
    let ok = r.outcome.is_success();
    o.records.insert(
        id,
        Rec {
            rc: rc_of(&r.outcome),
            stdout: String::from_utf8_lossy(&r.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&r.stderr).into_owned(),
        },
    );
    Ok(ok)
}

async fn cat_files<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    node: &NodePath,
    cfg: &InspectConfig,
    o: &mut Observation,
    listing_id: &str,
    dir: &str,
    names: &[&str],
) -> Result<u32, InspectError> {
    let Some(listing) = o.records.get(listing_id).filter(|r| r.rc == 0) else {
        return Ok(0);
    };
    let files: Vec<String> = parse_ls(&listing.stdout)
        .into_iter()
        .filter_map(|e| match e {
            LsEntry::File {
                name,
                size: Some(s),
            } if names.contains(&name.as_str()) && s <= cfg.max_readback_bytes => Some(name),
            _ => None,
        })
        .collect();
    let mut n = 0;
    for name in files {
        let path = format!("{dir}/{name}");
        let Some(sp) = SafePath::new(&path) else {
            continue;
        };
        let cmd = GuardedCommand::cat(Context::Node(node.clone()), &sp)
            .map_err(|e| InspectError::Plan(e.to_string()))?;
        let policy = Policy::Binary {
            label: format!("inspect{path}"),
        };
        let r = exec(rec, "readback", policy, &cmd, cfg.readback_limits).await?;
        n += 1;
        if let Some(r) = r.filter(|r| r.outcome.is_success() && r.stdout_dropped == 0) {
            o.digests
                .insert(path, (r.stdout.len() as u64, sha256_hex(&r.stdout)));
        }
    }
    Ok(n)
}

/// List `<daemon_dir>/nbt-aad-ops` (only if the daemon directory shows it)
/// and read back each operation's saved release.
async fn inspect_ops<T: HeadUnitTransport, S: TranscriptSink>(
    rec: &mut Recorder<T, S>,
    p: &HeadUnitProfile,
    node: &NodePath,
    cfg: &InspectConfig,
    o: &mut Observation,
) -> Result<u32, InspectError> {
    let has_root = o
        .records
        .get(ids::LS_DAEMON_DIR)
        .filter(|r| r.rc == 0)
        .is_some_and(|r| parse_ls_dirs(&r.stdout).iter().any(|d| d == "nbt-aad-ops"));
    if !has_root {
        return Ok(0);
    }
    let root = format!("{}/nbt-aad-ops", p.daemon_dir);
    if !text(rec, node, cfg, o, OPS_ROOT_ID.into(), &root).await? {
        return Ok(0);
    }
    let ops: Vec<String> = o
        .records
        .get(OPS_ROOT_ID)
        .map(|r| parse_ls_dirs(&r.stdout))
        .unwrap_or_default()
        .into_iter()
        .filter(|d| is_op_id(d))
        .take(MAX_OPS)
        .collect();
    let mut n = 0;
    for op in ops {
        let dir = format!("{root}/{op}");
        let old = format!("{dir}/old");
        let oldp = format!("{old}/NbtAad");
        text(rec, node, cfg, o, op_record_id(&op, "dir"), &dir).await?;
        text(rec, node, cfg, o, op_record_id(&op, "old"), &old).await?;
        text(rec, node, cfg, o, op_record_id(&op, "old-plugin"), &oldp).await?;
        n += cat_files(
            rec,
            node,
            cfg,
            o,
            &op_record_id(&op, "old"),
            &old,
            &[p.daemon_name],
        )
        .await?;
        n += cat_files(
            rec,
            node,
            cfg,
            o,
            &op_record_id(&op, "old-plugin"),
            &oldp,
            &PLUGIN_FILES,
        )
        .await?;
    }
    Ok(n)
}

/// Overall verdict for exit codes and summaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Profile matched and the installed set is verified by digest.
    Verified,
    /// Profile matched, install state is anything but verified.
    NotVerified,
    /// The unit does not match the profile: no claims are made.
    ProfileMismatch,
}

impl InspectReport {
    pub fn verdict(&self) -> Verdict {
        match (&self.profile, &self.state) {
            (Err(_), _) | (Ok(()), None) => Verdict::ProfileMismatch,
            (Ok(()), Some(InstallState::Verified { .. })) => Verdict::Verified,
            (Ok(()), Some(_)) => Verdict::NotVerified,
        }
    }

    /// Human-readable report (no secrets: only paths, sizes and digests).
    pub fn render(&self, p: &HeadUnitProfile) -> String {
        let mut s = format!(
            "profile: {} ({})
remote commands executed: {} (read-backs: {})
",
            p.id, p.description, self.executed, self.readbacks
        );
        match &self.profile {
            Ok(()) => s.push_str(
                "profile match: YES
",
            ),
            Err(ms) => {
                s.push_str(
                    "profile match: NO (no install-state claim is made)
",
                );
                for m in ms {
                    s.push_str(&format!(
                        "  - {m:?}
"
                    ));
                }
            }
        }
        match &self.state {
            None => {}
            Some(InstallState::Verified { installed, backup }) => {
                s.push_str(&format!(
                    "install state: VERIFIED {} (title {:?}, {}, plugin {})
",
                    installed.tag,
                    installed.title.trim(),
                    installed.daemon_build,
                    installed.plugin_marker
                ));
                match backup {
                    crate::profile::Backup::None => s.push_str(
                        "backup: none present
",
                    ),
                    crate::profile::Backup::Known(k) => {
                        s.push_str(&format!(
                            "backup: VERIFIED {} ({})
",
                            k.tag, k.daemon_build
                        ));
                    }
                    crate::profile::Backup::NotIdentified(why) => {
                        s.push_str(
                            "backup: present but NOT identified
",
                        );
                        for w in why {
                            s.push_str(&format!(
                                "  - {w}
"
                            ));
                        }
                    }
                }
            }
            Some(InstallState::Unverified { candidate }) => s.push_str(&format!(
                "install state: UNVERIFIED (no complete read-backs; size-only candidate: {})
",
                candidate.unwrap_or("none")
            )),
            Some(InstallState::Mixed { daemon, plugin }) => s.push_str(&format!(
                "install state: MIXED daemon {} with plugin {}
",
                daemon.tag, plugin.tag
            )),
            Some(InstallState::MidUpdate(why)) => {
                s.push_str(
                    "install state: HALF-APPLIED UPDATE (recovery needed, never an update)
",
                );
                for w in why {
                    s.push_str(&format!(
                        "  - {w}
"
                    ));
                }
            }
            Some(InstallState::Unknown(why)) => {
                s.push_str(
                    "install state: UNKNOWN
",
                );
                for w in why {
                    s.push_str(&format!(
                        "  - {w}
"
                    ));
                }
            }
        }
        match &self.ops {
            None => {}
            Some(Err(e)) => s.push_str(&format!("operation backups: UNKNOWN ({e})\n")),
            Some(Ok(v)) if v.is_empty() => s.push_str("operation backups: none\n"),
            Some(Ok(v)) => {
                s.push_str("operation backups:\n");
                for b in v {
                    let what = match &b.backup {
                        crate::profile::Backup::Known(k) => format!("VERIFIED {}", k.tag),
                        crate::profile::Backup::None => "none".into(),
                        crate::profile::Backup::NotIdentified(why) => {
                            format!("NOT identified ({})", why.join("; "))
                        }
                    };
                    s.push_str(&format!(
                        "  {}  complete={}  backup: {what}\n",
                        b.op_id, b.complete
                    ));
                }
            }
        }
        s.push_str(
            "read-back digests (host-computed):
",
        );
        for (path, (size, sha)) in &self.observation.digests {
            s.push_str(&format!(
                "  {sha}  {size:>9}  {path}
"
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests;
