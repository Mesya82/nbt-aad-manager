//! Head-unit profiles: everything the manager may assume about one exact
//! head-unit type, each fact tagged with its evidence (sans-IO).
//!
//! A live unit is used only if it matches a profile exactly
//! ([`match_profile`]); anything missing or different is a mismatch, never a
//! fallback. [`classify`] then names the install state from exact digests.

use std::collections::BTreeMap;

use crate::probe::{LsEntry, parse_ls};
use crate::release::{self, Identification, KnownRelease, Observed, PLUGIN_FILES};

/// Where a fact comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Seen in sanitized probe fixtures (paths relative to the repo root).
    Observed(&'static [&'static str]),
    /// Reported by the operator, not yet observed by a probe.
    OperatorReported(&'static str),
    /// Not known. Operations depending on it are unavailable.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fact<T> {
    pub value: T,
    pub evidence: Evidence,
}

/// Where a command must run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOn {
    /// The SSH login node, directly.
    Login,
    /// The daemon node via `on -f <node> /bin/sh -c '…'`.
    DaemonNodeShell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritableExpectation {
    pub path: &'static str,
    /// Probe record id of `test -w <path>` (through `/bin/sh -c` on the daemon node).
    pub probe_id: &'static str,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remount {
    pub run_on: RunOn,
    pub command: &'static str,
    /// Path whose `test -w` must succeed afterwards.
    pub verify_writable: &'static str,
    /// Whether the rw state persists until restart (unknown: never assume).
    pub persists_until_restart: Fact<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadUnitProfile {
    pub id: &'static str,
    pub description: &'static str,
    /// `/opt/sys/etc/nbt_version.txt` on the daemon node, trimmed.
    pub firmware: Fact<&'static str>,
    pub ssh_banner: Fact<&'static str>,
    /// Full `uname -a` of the login and daemon nodes.
    pub login_uname: Fact<&'static str>,
    pub daemon_uname: Fact<&'static str>,
    pub daemon_node: &'static str,
    /// `on` runs binaries without a shell: built-ins must go through `/bin/sh -c`.
    pub on_requires_shell: Fact<bool>,
    pub daemon_dir: &'static str,
    pub daemon_name: &'static str,
    pub daemon_backup_name: &'static str,
    pub plugin_dir: &'static str,
    pub plugin_backup_dir: &'static str,
    pub state_dir: &'static str,
    pub writable: Fact<&'static [WritableExpectation]>,
    pub remount: Fact<Remount>,
    pub tools_present: Fact<&'static [&'static str]>,
    pub tools_absent: Fact<&'static [&'static str]>,
    /// Never written, renamed or deleted by the manager.
    pub protected: &'static [&'static str],
    /// Owned by the running daemon: never created, edited or deleted.
    pub daemon_owned: &'static [&'static str],
    /// Command shapes forbidden on this unit even if read-only.
    pub forbidden: &'static [&'static str],
}

const RUN4: &str = "tests/fixtures/pilot-g31/run4-20261109-aa-running-usb";
const RUN5: &str = "tests/fixtures/pilot-g31/run5-20261109-aa-stopped";
const RUNS_2_5: &[&str] = &[
    "tests/fixtures/pilot-g31/run2-20261109-aa-stopped",
    "tests/fixtures/pilot-g31/run3-20261109-aa-running",
    RUN4,
    RUN5,
];
const RUNS_4_5: &[&str] = &[RUN4, RUN5];

/// The pilot car: BMW G31 530i (2018), NBT EVO `NBTevo_Y23236I`.
pub const PILOT_G31: HeadUnitProfile = HeadUnitProfile {
    id: "pilot-g31-NBTevo_Y23236I",
    description: "BMW G31 530i 2018, NBT EVO ID6, firmware NBTevo_Y23236I (single pilot car)",
    firmware: Fact {
        value: "NBTevo_Y23236I",
        evidence: Evidence::Observed(RUNS_2_5),
    },
    ssh_banner: Fact {
        value: "SSH-2.0-OpenSSH_5.2 QNX_Secure_Shell-20090621-hpn13v6",
        evidence: Evidence::Observed(&["tests/fixtures/pilot-g31/run1-20261109", RUN4, RUN5]),
    },
    login_uname: Fact {
        value: "QNX hu-jacinto 6.5.0 2015/12/01-10:59:38EST J5_Evo armle",
        evidence: Evidence::Observed(RUNS_2_5),
    },
    daemon_uname: Fact {
        value: "QNX hu-omap 6.5.0 2015/12/01-11:00:56EST TI-OMAP5432-uEVM armle",
        evidence: Evidence::Observed(RUNS_2_5),
    },
    daemon_node: "/net/hu-omap/",
    on_requires_shell: Fact {
        value: true,
        evidence: Evidence::Observed(RUNS_2_5),
    },
    daemon_dir: "/opt/aa",
    daemon_name: "nbt-aad",
    daemon_backup_name: "nbt-aad.old",
    plugin_dir: "/opt/hmi/ID5/data/ro/Plugins/NbtAad",
    plugin_backup_dir: "/opt/aa/NbtAad.old",
    state_dir: "/var/opt/aa",
    writable: Fact {
        value: &[
            WritableExpectation {
                path: "/opt/aa",
                probe_id: "hu-test-w-opt-aa",
                writable: false,
            },
            WritableExpectation {
                path: "/opt/hmi/ID5/data/ro/Plugins/NbtAad",
                probe_id: "hu-test-w-plugin",
                writable: false,
            },
            WritableExpectation {
                path: "/var/opt/aa",
                probe_id: "hu-test-w-var-opt-aa",
                writable: true,
            },
            WritableExpectation {
                path: "/dev/shmem",
                probe_id: "hu-test-w-dev-shmem",
                writable: true,
            },
        ],
        evidence: Evidence::Observed(RUNS_4_5),
    },
    remount: Fact {
        value: Remount {
            run_on: RunOn::Login,
            command: "mount -o remount rw /net/hu-omap/fs/sda0",
            verify_writable: "/opt/aa",
            persists_until_restart: Fact {
                value: false,
                evidence: Evidence::Unknown,
            },
        },
        evidence: Evidence::OperatorReported(
            "operator's manual update 2026-11-09 (docs/UPSTREAM_RESEARCH.md, runs 4 and 5)",
        ),
    },
    tools_present: Fact {
        value: &[
            "ls", "cat", "df", "mount", "pidin", "use", "grep", "sed", "wc", "tail", "find",
            "gzip", "mv", "cp", "ln", "mkdir", "rm", "chmod", "dd", "slay", "sleep", "date",
            "sort", "diff",
        ],
        evidence: Evidence::Observed(RUNS_2_5),
    },
    tools_absent: Fact {
        value: &[
            "sha256sum",
            "sha256",
            "sha1sum",
            "md5sum",
            "md5",
            "cksum",
            "sum",
            "openssl",
            "stat",
            "tar",
            "mktemp",
            "touch",
            "rmdir",
            "sync",
            "head",
            "awk",
            "xargs",
        ],
        evidence: Evidence::Observed(RUNS_2_5),
    },
    protected: &[
        "/opt/aa/nbt-aad.env",
        "/opt/aa/nbt-aad.env.bak",
        "/var/opt/aa",
        "/etc/pf.conf",
    ],
    daemon_owned: &["/var/opt/aa/bootguard"],
    forbidden: &["bare `df` (all block devices; coincided with an AA disconnect, run 3)"],
};

/// One probe record as the matcher needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rec {
    /// Exit status; -1 for timeouts, signals or a missing status.
    pub rc: i64,
    pub stdout: String,
    pub stderr: String,
}

/// QNX `ls` failure for a missing path, exactly as observed on the pilot
/// unit (run 2: `ls: No such file or directory (/opt/aa/NbtAad.old)`).
/// Only this counts as "absent"; any other failure is "not observed".
pub fn listing_says_absent(r: &Rec, path: &str) -> bool {
    r.rc == 1
        && r.stdout.trim().is_empty()
        && r.stderr.trim_end() == format!("ls: No such file or directory ({path})")
}

/// What a read-only inspection observed. Source-agnostic: built from a live
/// run or from fixtures by probe record id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    pub ssh_banner: Option<String>,
    /// Probe record id → result.
    pub records: BTreeMap<String, Rec>,
    /// Absolute path → (size, sha256) from host-hashed read-backs.
    pub digests: BTreeMap<String, (u64, String)>,
}

/// Probe record ids the matcher and classifier read.
pub mod ids {
    pub const FIRMWARE: &str = "hu-nbt-version";
    pub const LOGIN_UNAME: &str = "outer-uname";
    pub const DAEMON_UNAME: &str = "hu-uname";
    pub const ON_SHELL: &str = "hu-sh-echo";
    pub const ON_BARE: &str = "hu-echo";
    pub const LS_DAEMON_DIR: &str = "hu-ls-opt-aa";
    pub const LS_PLUGIN: &str = "hu-ls-plugin-nbtaad";
    pub const LS_PLUGIN_BACKUP: &str = "hu-ls-nbtaad-old";
    pub const LS_STATE: &str = "hu-ls-var-opt-aa";
}

impl Observation {
    /// Add host-side digests from a probe `readback.tsv`
    /// (`path rc bytes sha256 …`, header first). Rows with rc ≠ 0 are skipped.
    /// Conflicting digests for one path are an error.
    pub fn add_readback_tsv(&mut self, tsv: &str) -> Result<(), String> {
        for line in tsv.lines().skip(1) {
            let c: Vec<&str> = line.split('\t').collect();
            if c.len() < 4 {
                return Err(format!("short readback row: {line:?}"));
            }
            if c[1] != "0" {
                continue;
            }
            let size: u64 = c[2]
                .parse()
                .map_err(|_| format!("bad size in readback row: {line:?}"))?;
            let v = (size, c[3].to_ascii_lowercase());
            match self.digests.get(c[0]) {
                Some(old) if *old != v => {
                    return Err(format!("conflicting read-backs for {}", c[0]));
                }
                _ => {
                    self.digests.insert(c[0].to_owned(), v);
                }
            }
        }
        Ok(())
    }

    fn rec(&self, id: &str) -> Option<&Rec> {
        self.records.get(id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// A required observation is absent (e.g. older probe version).
    NotObserved(&'static str),
    Differs {
        what: &'static str,
        expected: String,
        found: String,
    },
    /// A listing has entries the parser could not read as plain files.
    UnreadableListing { path: &'static str, line: String },
}

/// Exact profile match. Every fact the profile states as observed must be
/// observed again and be equal; nothing is defaulted.
pub fn match_profile(p: &HeadUnitProfile, o: &Observation) -> Result<(), Vec<Mismatch>> {
    let mut bad = Vec::new();
    let mut text = |what: &'static str, id: &'static str, expected: &str| match o.rec(id) {
        None => bad.push(Mismatch::NotObserved(what)),
        Some(r) if r.rc != 0 || r.stdout.trim_end() != expected => bad.push(Mismatch::Differs {
            what,
            expected: expected.to_owned(),
            found: format!("rc={} {:?}", r.rc, r.stdout.trim_end()),
        }),
        Some(_) => {}
    };
    text("firmware", ids::FIRMWARE, p.firmware.value);
    text("login node uname", ids::LOGIN_UNAME, p.login_uname.value);
    text("daemon node uname", ids::DAEMON_UNAME, p.daemon_uname.value);
    text("on + /bin/sh -c works", ids::ON_SHELL, "probe-ok");

    match &o.ssh_banner {
        None => bad.push(Mismatch::NotObserved("ssh banner")),
        Some(b) if b != p.ssh_banner.value => bad.push(Mismatch::Differs {
            what: "ssh banner",
            expected: p.ssh_banner.value.to_owned(),
            found: b.clone(),
        }),
        Some(_) => {}
    }

    if p.on_requires_shell.value {
        // Bare built-ins through `on` must fail on this unit; if they work,
        // it is a different `on` and the command forms do not apply.
        match o.rec(ids::ON_BARE) {
            None => bad.push(Mismatch::NotObserved("on without shell")),
            Some(r) if r.rc == 0 => bad.push(Mismatch::Differs {
                what: "on without shell",
                expected: "built-in fails".into(),
                found: "built-in succeeded".into(),
            }),
            Some(_) => {}
        }
    }

    for w in p.writable.value {
        match o.rec(w.probe_id) {
            None => bad.push(Mismatch::NotObserved("writability (test -w)")),
            Some(r) if !(r.rc == 0 || r.rc == 1) => bad.push(Mismatch::Differs {
                what: "writability (test -w)",
                expected: format!("{} rc 0 or 1", w.path),
                found: format!("rc={}", r.rc),
            }),
            Some(r) if (r.rc == 0) != w.writable => bad.push(Mismatch::Differs {
                what: "writability (test -w)",
                expected: format!("{} writable={}", w.path, w.writable),
                found: format!("writable={}", r.rc == 0),
            }),
            Some(_) => {}
        }
    }

    for (what, id, path) in [
        ("daemon directory", ids::LS_DAEMON_DIR, p.daemon_dir),
        ("state directory", ids::LS_STATE, p.state_dir),
    ] {
        match o.rec(id) {
            None => bad.push(Mismatch::NotObserved(what)),
            Some(r) if r.rc != 0 => bad.push(Mismatch::Differs {
                what,
                expected: format!("{path} exists"),
                found: format!("rc={}", r.rc),
            }),
            Some(r) => unreadable(path, &r.stdout, &mut bad),
        }
    }
    if let Some(r) = o.rec(ids::LS_PLUGIN).filter(|r| r.rc == 0) {
        unreadable(p.plugin_dir, &r.stdout, &mut bad);
    }
    if let Some(r) = o.rec(ids::LS_PLUGIN_BACKUP).filter(|r| r.rc == 0) {
        unreadable(p.plugin_backup_dir, &r.stdout, &mut bad);
    }

    if bad.is_empty() { Ok(()) } else { Err(bad) }
}

fn unreadable(path: &'static str, listing: &str, bad: &mut Vec<Mismatch>) {
    for e in parse_ls(listing) {
        if let LsEntry::Unparsed { line, .. } = e {
            bad.push(Mismatch::UnreadableListing { path, line });
        }
    }
}

/// A set of files that may or may not be present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetState {
    Absent,
    /// Present with these plain files (name, size).
    Present(Vec<(String, u64)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallState {
    /// Active daemon + plugin identified by exact digests; backup state too.
    Verified {
        installed: &'static KnownRelease,
        backup: Backup,
    },
    /// Structure is consistent but digests were not read back: no
    /// identification is claimed. `candidate` is a size-only hint.
    Unverified { candidate: Option<&'static str> },
    /// Active daemon and plugin are from different known releases.
    Mixed {
        daemon: &'static KnownRelease,
        plugin: &'static KnownRelease,
    },
    /// Half-applied update or half-made backup. Needs recovery, never an update.
    MidUpdate(Vec<String>),
    /// Anything else.
    Unknown(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backup {
    None,
    Known(&'static KnownRelease),
    /// Present but not a single known release (mixed, unknown or unhashed).
    NotIdentified(Vec<String>),
}

fn files_of(o: &Observation, id: &str, path: &str) -> Result<SetState, String> {
    match o.rec(id) {
        None => Err(format!("{id} not observed")),
        Some(r) if listing_says_absent(r, path) => Ok(SetState::Absent),
        Some(r) if r.rc != 0 => Err(format!(
            "{id}: listing of {path} failed (rc {}) without a 'No such file' answer",
            r.rc
        )),
        Some(r) => {
            let mut v = Vec::new();
            for e in parse_ls(&r.stdout) {
                match e {
                    LsEntry::File {
                        name,
                        size: Some(s),
                    } => v.push((name, s)),
                    LsEntry::File { name, size: None } => {
                        return Err(format!("{id}: unreadable size for {name}"));
                    }
                    LsEntry::Unparsed { line, .. } => return Err(format!("{id}: {line}")),
                    LsEntry::Symlink { line } => return Err(format!("{id}: symlink {line}")),
                    LsEntry::Other { .. } => {}
                }
            }
            Ok(SetState::Present(v))
        }
    }
}

fn observed(
    o: &Observation,
    dir: &str,
    name: &str,
    as_name: &str,
    listed: u64,
) -> Result<Observed, String> {
    let path = format!("{dir}/{name}");
    let (size, sha) = o
        .digests
        .get(&path)
        .ok_or_else(|| format!("no read-back for {path}"))?;
    if *size != listed {
        return Err(format!("{path}: listed {listed} bytes, read back {size}"));
    }
    Ok(Observed {
        name: as_name.to_owned(),
        size: *size,
        sha256: sha.clone(),
    })
}

fn plugin_set(
    o: &Observation,
    dir: &str,
    files: &[(String, u64)],
) -> Result<Vec<Observed>, String> {
    files
        .iter()
        .map(|(n, s)| observed(o, dir, n, n, *s))
        .collect()
}

fn size_candidate(
    table: &'static [KnownRelease],
    daemon: u64,
    plugin: &[(String, u64)],
) -> Option<&'static str> {
    table
        .iter()
        .find(|k| {
            k.daemon.size == daemon
                && plugin.len() == 5
                && k.plugin
                    .iter()
                    .all(|f| plugin.iter().any(|(n, s)| n == f.name && *s == f.size))
        })
        .map(|k| k.tag)
}

/// Name the install state. Fails closed: any inconsistency or missing
/// evidence yields `MidUpdate`, `Unknown` or `Unverified`, never `Verified`.
pub fn classify(p: &HeadUnitProfile, o: &Observation) -> InstallState {
    classify_in(p, o, release::KNOWN)
}

/// [`classify`] against an explicit pin table.
pub fn classify_in(
    p: &HeadUnitProfile,
    o: &Observation,
    table: &'static [KnownRelease],
) -> InstallState {
    let dir = match files_of(o, ids::LS_DAEMON_DIR, p.daemon_dir) {
        Ok(SetState::Present(v)) => v,
        Ok(SetState::Absent) => {
            return InstallState::Unknown(vec![format!("{} missing", p.daemon_dir)]);
        }
        Err(e) => return InstallState::Unknown(vec![e]),
    };
    let (plugin, plugin_bak) = match (
        files_of(o, ids::LS_PLUGIN, p.plugin_dir),
        files_of(o, ids::LS_PLUGIN_BACKUP, p.plugin_backup_dir),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            let why = [a.err(), b.err()].into_iter().flatten().collect();
            return InstallState::Unknown(why);
        }
    };
    let size_of = |n: &str| dir.iter().find(|(x, _)| x == n).map(|(_, s)| *s);
    let daemon = size_of(p.daemon_name);
    let daemon_bak = size_of(p.daemon_backup_name);

    // Structural consistency first.
    let mut mid = Vec::new();
    let five = |s: &SetState| match s {
        SetState::Present(v) => {
            let mut names: Vec<&str> = v.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            let mut want = PLUGIN_FILES.to_vec();
            want.sort_unstable();
            names == want
        }
        SetState::Absent => false,
    };
    if daemon.is_none() {
        mid.push(format!("{}/{} missing", p.daemon_dir, p.daemon_name));
    }
    if !five(&plugin) {
        mid.push(format!("{} is not the exact 5-file plugin", p.plugin_dir));
    }
    if plugin_bak != SetState::Absent && !five(&plugin_bak) {
        mid.push(format!(
            "{} present but not the exact 5-file plugin",
            p.plugin_backup_dir
        ));
    }
    if daemon_bak.is_some() != (plugin_bak != SetState::Absent) {
        mid.push("daemon and plugin backups are not both present or both absent".into());
    }
    if !mid.is_empty() {
        return InstallState::MidUpdate(mid);
    }
    let (Some(daemon), SetState::Present(plugin)) = (daemon, &plugin) else {
        return InstallState::Unknown(vec!["internal: structure".into()]);
    };

    // Identification by digest.
    let active = observed(o, p.daemon_dir, p.daemon_name, "nbt-aad", daemon)
        .and_then(|d| Ok((d, plugin_set(o, p.plugin_dir, plugin)?)));
    let (d, pl) = match active {
        Ok(x) => x,
        Err(e) if e.starts_with("no read-back") => {
            return InstallState::Unverified {
                candidate: size_candidate(table, daemon, plugin),
            };
        }
        Err(e) => return InstallState::Unknown(vec![e]),
    };
    let installed = match release::identify_in(table, &d, &pl) {
        Identification::Known(k) => k,
        Identification::Mixed { daemon, plugin } => return InstallState::Mixed { daemon, plugin },
        Identification::Unknown(why) => return InstallState::Unknown(why),
    };
    let backup = match (daemon_bak, &plugin_bak) {
        (Some(ds), SetState::Present(pb)) => {
            let r = observed(o, p.daemon_dir, p.daemon_backup_name, "nbt-aad", ds)
                .and_then(|d| Ok((d, plugin_set(o, p.plugin_backup_dir, pb)?)));
            match r {
                Err(e) => Backup::NotIdentified(vec![e]),
                Ok((d, pb)) => match release::identify_in(table, &d, &pb) {
                    Identification::Known(k) => Backup::Known(k),
                    Identification::Mixed { daemon, plugin } => {
                        Backup::NotIdentified(vec![format!(
                            "mixed backup: daemon {}, plugin {}",
                            daemon.tag, plugin.tag
                        )])
                    }
                    Identification::Unknown(why) => Backup::NotIdentified(why),
                },
            }
        }
        _ => Backup::None,
    };
    InstallState::Verified { installed, backup }
}

#[cfg(test)]
mod tests;
