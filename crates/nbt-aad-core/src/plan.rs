//! Update planning (pure; nothing is executed). Implements the step table of
//! `docs/WRITE_PATH_DESIGN.md` as typed data so it can be printed, reviewed,
//! simulated and tested long before any apply path exists.

use std::sync::LazyLock;

use regex::Regex;

use crate::guard::SafePath;
use crate::profile::{Backup, HeadUnitProfile, InstallState, RunOn};
use crate::release::{self, KnownRelease};

/// One remote mutation, in typed form. Rendering is for display only; there
/// is deliberately no way to turn this into a sendable command here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mutation {
    Remount { run_on: RunOn, command: String },
    Mkdir(String),
    Cp { from: String, to: String },
    Chmod755(String),
    Mv { from: String, to: String },
}

impl Mutation {
    pub fn render(&self) -> String {
        match self {
            Mutation::Remount { run_on, command } => match run_on {
                RunOn::Login => format!("[login node] {command}"),
                RunOn::DaemonNodeShell => format!("[daemon node] {command}"),
            },
            Mutation::Mkdir(p) => format!("mkdir {p}"),
            Mutation::Cp { from, to } => format!("cp {from} {to}"),
            Mutation::Chmod755(p) => format!("chmod 755 {p}"),
            Mutation::Mv { from, to } => format!("mv {from} {to}"),
        }
    }

    /// Every path this mutation names.
    pub fn paths(&self) -> Vec<&str> {
        match self {
            Mutation::Remount { .. } => vec![],
            Mutation::Mkdir(p) | Mutation::Chmod755(p) => vec![p],
            Mutation::Cp { from, to } | Mutation::Mv { from, to } => vec![from, to],
        }
    }
}

/// What must be observed (read-only) after a step before the next one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verify {
    Writable(String),
    DirExists(String),
    Absent(String),
    Digest {
        path: String,
        size: u64,
        sha256: &'static str,
    },
    ModeExecutable(String),
    Operator(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub id: &'static str,
    pub purpose: &'static str,
    pub mutations: Vec<Mutation>,
    pub verify: Vec<Verify>,
    /// Mutations that return the device to the state before this step.
    pub undo: Vec<Mutation>,
    /// Facts that must be established on hardware before this step may be
    /// implemented for real (`docs/WRITE_PATH_DESIGN.md` section 6).
    pub evidence_needed: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan {
    pub op_id: String,
    pub profile_id: &'static str,
    pub from: &'static KnownRelease,
    pub to: &'static KnownRelease,
    pub usb_dir: String,
    pub preconditions: Vec<String>,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("install state is not verified ({0}); run recovery or inspect first")]
    NotVerified(String),
    #[error("target {0:?} is not a pinned release")]
    UnknownTarget(String),
    #[error("target {0:?} is already installed")]
    AlreadyInstalled(&'static str),
    #[error("invalid operation id {0:?}")]
    BadOpId(String),
    #[error("invalid USB mount {0:?} (expected /mnt/umass<id>)")]
    BadUsbMount(String),
    #[error("internal: unsafe path {0:?}")]
    UnsafePath(String),
}

static OP_ID: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6}$").expect("static regex")
});
static USB: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^/mnt/umass[0-9a-z]{1,16}$").expect("static regex")
});

/// Root of all operation directories on the daemon filesystem.
pub fn ops_root(p: &HeadUnitProfile) -> String {
    format!("{}/nbt-aad-ops", p.daemon_dir)
}

const EV_REMOUNT: &[&str] = &["remount persistence and revert without restart (6.1)"];
const EV_MV: &[&str] = &[
    "qnx6 durability without sync (6.2)",
    "atomic directory rename within /fs/sda0 (6.3)",
];
const EV_CP: &[&str] = &["cp from FAT: mode/mtime (6.5)"];
const EV_MV_STOP: &[&str] = &[
    "qnx6 durability without sync (6.2)",
    "atomic directory rename within /fs/sda0 (6.3)",
    "Force Stop / autostart behaviour (6.4)",
];
const EV_MV_PLUGIN: &[&str] = &[
    "qnx6 durability without sync (6.2)",
    "atomic directory rename within /fs/sda0 (6.3)",
    "loaded plugin after directory rename (6.6)",
];

/// Build the update plan. Pure: inspects nothing and executes nothing.
pub fn plan_update(
    p: &HeadUnitProfile,
    state: &InstallState,
    target_tag: &str,
    table: &'static [KnownRelease],
    op_id: &str,
    usb_mount: &str,
) -> Result<UpdatePlan, PlanError> {
    let (from, backup) = match state {
        InstallState::Verified { installed, backup } => (*installed, backup),
        other => return Err(PlanError::NotVerified(format!("{other:?}"))),
    };
    let to = release::find_known(table, target_tag)
        .ok_or_else(|| PlanError::UnknownTarget(target_tag.to_owned()))?;
    if to.tag == from.tag {
        return Err(PlanError::AlreadyInstalled(to.tag));
    }
    if !OP_ID.is_match(op_id) {
        return Err(PlanError::BadOpId(op_id.to_owned()));
    }
    if !USB.is_match(usb_mount) {
        return Err(PlanError::BadUsbMount(usb_mount.to_owned()));
    }

    let root = ops_root(p);
    let op = format!("{root}/{op_id}");
    let new = format!("{op}/new");
    let old = format!("{op}/old");
    let usb = format!("{usb_mount}/nbt-aad-{op_id}");
    let daemon = format!("{}/{}", p.daemon_dir, p.daemon_name);
    let plugin = p.plugin_dir.to_owned();

    let mut steps = Vec::new();
    let remount = p.remount.value;
    steps.push(Step {
        id: "S1",
        purpose: "make the daemon/plugin filesystem writable",
        mutations: vec![Mutation::Remount {
            run_on: remount.run_on,
            command: remount.command.to_owned(),
        }],
        verify: vec![Verify::Writable(remount.verify_writable.to_owned())],
        undo: vec![],
        evidence_needed: EV_REMOUNT,
    });
    steps.push(Step {
        id: "S2",
        purpose: "create the operation directories (the ops root only if absent)",
        mutations: vec![
            Mutation::Mkdir(root.clone()),
            Mutation::Mkdir(op.clone()),
            Mutation::Mkdir(new.clone()),
            Mutation::Mkdir(format!("{new}/NbtAad")),
        ],
        verify: vec![
            Verify::DirExists(new.clone()),
            Verify::DirExists(format!("{new}/NbtAad")),
        ],
        undo: vec![],
        evidence_needed: &[],
    });
    let mut s3 = vec![Mutation::Cp {
        from: format!("{usb}/nbt-aad"),
        to: format!("{new}/nbt-aad"),
    }];
    let mut v3 = vec![Verify::Digest {
        path: format!("{new}/nbt-aad"),
        size: to.daemon.size,
        sha256: to.daemon.sha256,
    }];
    for f in &to.plugin {
        s3.push(Mutation::Cp {
            from: format!("{usb}/Releases/{}", f.name),
            to: format!("{new}/NbtAad/{}", f.name),
        });
        v3.push(Verify::Digest {
            path: format!("{new}/NbtAad/{}", f.name),
            size: f.size,
            sha256: f.sha256,
        });
    }
    s3.push(Mutation::Cp {
        from: format!("{usb}/MANIFEST"),
        to: format!("{op}/MANIFEST"),
    });
    steps.push(Step {
        id: "S3",
        purpose: "stage the verified release next to the targets (same filesystem)",
        mutations: s3,
        verify: v3,
        undo: vec![],
        evidence_needed: EV_CP,
    });
    steps.push(Step {
        id: "S4",
        purpose: "make the staged daemon executable",
        mutations: vec![Mutation::Chmod755(format!("{new}/nbt-aad"))],
        verify: vec![Verify::ModeExecutable(format!("{new}/nbt-aad"))],
        undo: vec![],
        evidence_needed: &[],
    });
    let mv = |a: &str, b: &str| Mutation::Mv {
        from: a.to_owned(),
        to: b.to_owned(),
    };
    steps.push(Step {
        id: "S5",
        purpose: "move the stopped daemon into the operation backup",
        mutations: vec![
            Mutation::Mkdir(old.clone()),
            mv(&daemon, &format!("{old}/nbt-aad")),
        ],
        verify: vec![
            Verify::Absent(daemon.clone()),
            Verify::Digest {
                path: format!("{old}/nbt-aad"),
                size: from.daemon.size,
                sha256: from.daemon.sha256,
            },
        ],
        undo: vec![mv(&format!("{old}/nbt-aad"), &daemon)],
        evidence_needed: EV_MV_STOP,
    });
    steps.push(Step {
        id: "S6",
        purpose: "promote the new daemon",
        mutations: vec![mv(&format!("{new}/nbt-aad"), &daemon)],
        verify: vec![Verify::Digest {
            path: daemon.clone(),
            size: to.daemon.size,
            sha256: to.daemon.sha256,
        }],
        undo: vec![mv(&daemon, &format!("{new}/nbt-aad"))],
        evidence_needed: EV_MV,
    });
    let mut v7 = vec![Verify::Absent(plugin.clone())];
    for f in &from.plugin {
        v7.push(Verify::Digest {
            path: format!("{old}/NbtAad/{}", f.name),
            size: f.size,
            sha256: f.sha256,
        });
    }
    steps.push(Step {
        id: "S7",
        purpose: "move the active plugin directory into the operation backup",
        mutations: vec![mv(&plugin, &format!("{old}/NbtAad"))],
        verify: v7,
        undo: vec![mv(&format!("{old}/NbtAad"), &plugin)],
        evidence_needed: EV_MV_PLUGIN,
    });
    let v8 = to
        .plugin
        .iter()
        .map(|f| Verify::Digest {
            path: format!("{plugin}/{}", f.name),
            size: f.size,
            sha256: f.sha256,
        })
        .collect();
    steps.push(Step {
        id: "S8",
        purpose: "promote the new plugin directory",
        mutations: vec![mv(&format!("{new}/NbtAad"), &plugin)],
        verify: v8,
        undo: vec![mv(&plugin, &format!("{new}/NbtAad"))],
        evidence_needed: EV_MV,
    });
    steps.push(Step {
        id: "S9",
        purpose: "mark the operation complete on the device",
        mutations: vec![Mutation::Cp {
            from: format!("{usb}/COMPLETE"),
            to: format!("{op}/COMPLETE"),
        }],
        verify: vec![Verify::DirExists(op.clone())],
        undo: vec![],
        evidence_needed: &[],
    });
    steps.push(Step {
        id: "S10",
        purpose: "operator restarts the head unit; then inspect must verify the target",
        mutations: vec![],
        verify: vec![Verify::Operator(
            "hold the power button ~30 s, reconnect, run inspect: expect the target verified and the backup = previous release",
        )],
        undo: vec![],
        evidence_needed: EV_MV,
    });

    for s in &steps {
        for m in s.mutations.iter().chain(&s.undo) {
            for path in m.paths() {
                if SafePath::new(path).is_none() {
                    return Err(PlanError::UnsafePath(path.to_owned()));
                }
            }
        }
    }

    let mut pre = vec![
        format!(
            "inspect: profile {} matches and {} is verified by digest",
            p.id, from.tag
        ),
        format!("target {} is pinned (daemon {})", to.tag, to.daemon_build),
        format!(
            "USB: {usb}/ holds nbt-aad, Releases/<5 files>, MANIFEST, COMPLETE; each read back on the head unit and equal to the pins"
        ),
        format!(
            "df -k {}: free space >= 2x the new payload + margin",
            p.daemon_dir
        ),
        "daemon not running (operator used iDrive Force Stop; pidin shows no nbt-aad)".into(),
        format!("no unfinished operation under {root} and no open host journal"),
    ];
    match backup {
        Backup::None => pre.push("existing backups: none".into()),
        Backup::Known(k) => pre.push(format!(
            "existing foreign backup ({} = {}) stays untouched",
            p.plugin_backup_dir, k.tag
        )),
        Backup::NotIdentified(_) => pre.push(format!(
            "existing unidentified backup under {} stays untouched",
            p.daemon_dir
        )),
    }
    Ok(UpdatePlan {
        op_id: op_id.to_owned(),
        profile_id: p.id,
        from,
        to,
        usb_dir: usb,
        preconditions: pre,
        steps,
    })
}

impl UpdatePlan {
    /// Human-readable plan. States plainly that nothing is executed.
    pub fn render(&self) -> String {
        let mut s = format!(
            "UPDATE PLAN (NOT EXECUTED; no apply path exists in this version)\noperation {}  profile {}\nfrom {} ({})\nto   {} ({})\n\nPreconditions (re-checked read-only before any step):\n",
            self.op_id,
            self.profile_id,
            self.from.tag,
            self.from.daemon_build,
            self.to.tag,
            self.to.daemon_build
        );
        for p in &self.preconditions {
            s.push_str(&format!("  - {p}\n"));
        }
        for st in &self.steps {
            s.push_str(&format!("\n{} {}\n", st.id, st.purpose));
            for m in &st.mutations {
                s.push_str(&format!("    do:     {}\n", m.render()));
            }
            for v in &st.verify {
                s.push_str(&format!("    verify: {v:?}\n"));
            }
            for u in &st.undo {
                s.push_str(&format!("    undo:   {}\n", u.render()));
            }
            for e in st.evidence_needed {
                s.push_str(&format!("    BLOCKED until hardware evidence: {e}\n"));
            }
        }
        s
    }
}

#[cfg(test)]
mod tests;
