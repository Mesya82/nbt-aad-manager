//! The update plan executed against the stateful filesystem model, with an
//! interruption after every single mutation (power loss / connection loss)
//! and state-driven recovery from each point.

use crate::plan::{Mutation, UpdatePlan, Verify, ops_root, plan_update};
use crate::profile::{Backup, InstallState, PILOT_G31, classify_in};
use crate::release::{FileDigest, KnownRelease, PLUGIN_FILES};
use crate::testkit::sim::{SimError, SimFs, SimNode};
use crate::transport::sha256_hex;

const OP: &str = "20261109T170000Z-abc123";
const USB: &str = "/mnt/umass0";
const PD: &str = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";
const ENV: &[u8] = b"NBT_ALT_WIFI=CARPLAY\n";

fn content(tag: &str, n: &str) -> Vec<u8> {
    format!("{tag} {n} payload\n").into_bytes()
}

fn fd(tag: &str, n: &'static str) -> FileDigest {
    let d = content(tag, n);
    FileDigest {
        name: n,
        size: d.len() as u64,
        sha256: Box::leak(sha256_hex(&d).into_boxed_str()),
    }
}

fn pin(tag: &'static str) -> KnownRelease {
    KnownRelease {
        tag,
        title: tag,
        daemon_build: "Build: v0",
        plugin_marker: "rhmiapp-0",
        daemon: fd(tag, "nbt-aad"),
        archive: fd(tag, "Releases.zip"),
        plugin: PLUGIN_FILES.map(|n| fd(tag, n)),
    }
}

fn table() -> &'static [KnownRelease] {
    static T: std::sync::LazyLock<Vec<KnownRelease>> =
        std::sync::LazyLock::new(|| vec![pin("older"), pin("old"), pin("new")]);
    T.as_slice()
}

/// The pilot after an upstream update: `old` active, upstream-style foreign
/// backup `older`, protected env, and a USB stick prepared for `new`.
fn unit() -> SimFs {
    let mut fs = SimFs::new(&["/opt"]);
    fs.put("/opt/aa/nbt-aad", &content("old", "nbt-aad"), 0o777);
    fs.put("/opt/aa/nbt-aad.old", &content("older", "nbt-aad"), 0o777);
    fs.put("/opt/aa/nbt-aad.env", ENV, 0o666);
    for n in PLUGIN_FILES {
        fs.put(&format!("{PD}/{n}"), &content("old", n), 0o666);
        fs.put(
            &format!("/opt/aa/NbtAad.old/{n}"),
            &content("older", n),
            0o666,
        );
    }
    let usb = format!("{USB}/nbt-aad-{OP}");
    fs.put(&format!("{usb}/nbt-aad"), &content("new", "nbt-aad"), 0o666);
    for n in PLUGIN_FILES {
        fs.put(&format!("{usb}/Releases/{n}"), &content("new", n), 0o666);
    }
    fs.put(&format!("{usb}/MANIFEST"), b"op\n", 0o666);
    fs.put(&format!("{usb}/COMPLETE"), b"done\n", 0o666);
    fs
}

fn state(fs: &SimFs) -> InstallState {
    classify_in(&PILOT_G31, &fs.observe(&PILOT_G31), table())
}

fn the_plan(fs: &SimFs, root_exists: bool) -> UpdatePlan {
    plan_update(&PILOT_G31, &state(fs), "new", table(), OP, USB, root_exists).unwrap()
}

fn remount() -> &'static str {
    PILOT_G31.remount.value.command
}

fn check(fs: &SimFs, v: &Verify) -> bool {
    match v {
        Verify::Writable(_) => fs.remounted,
        Verify::DirExists(p) => matches!(fs.nodes.get(p), Some(SimNode::Dir)),
        Verify::Absent(p) => !fs.nodes.contains_key(p),
        Verify::Digest { path, size, sha256 } => fs
            .file(path)
            .is_some_and(|d| d.len() as u64 == *size && sha256_hex(d) == *sha256),
        Verify::ModeExecutable(p) => {
            matches!(fs.nodes.get(p), Some(SimNode::File { mode, .. }) if mode & 0o111 != 0)
        }
        Verify::Operator(_) => true,
    }
}

type Snapshot = Vec<(String, Option<Vec<u8>>)>;

/// Everything outside the plan's reach, byte for byte.
fn untouchable(fs: &SimFs) -> Snapshot {
    let mut paths = vec![
        "/opt/aa/nbt-aad.env".to_owned(),
        "/opt/aa/nbt-aad.old".to_owned(),
    ];
    paths.extend(
        PLUGIN_FILES
            .iter()
            .map(|n| format!("/opt/aa/NbtAad.old/{n}")),
    );
    paths
        .into_iter()
        .map(|p| {
            let d = fs.file(&p).map(<[u8]>::to_vec);
            (p, d)
        })
        .collect()
}

#[test]
fn starting_state_is_verified_old_with_foreign_backup() {
    match state(&unit()) {
        InstallState::Verified { installed, backup } => {
            assert_eq!(installed.tag, "old");
            assert!(matches!(backup, Backup::Known(k) if k.tag == "older"));
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn full_apply_reaches_the_target_and_every_verify_holds() {
    let mut fs = unit();
    let keep = untouchable(&fs);
    let plan = the_plan(&fs, false);
    for s in &plan.steps {
        for m in &s.mutations {
            fs.apply(m, remount())
                .unwrap_or_else(|e| panic!("{} {m:?}: {e:?}", s.id));
        }
        for v in &s.verify {
            assert!(check(&fs, v), "{}: {v:?}", s.id);
        }
    }
    match state(&fs) {
        InstallState::Verified { installed, .. } => assert_eq!(installed.tag, "new"),
        s => panic!("{s:?}"),
    }
    assert_eq!(untouchable(&fs), keep, "foreign backups and env untouched");
    // The previous release is completely preserved in the op backup.
    let old = format!("{}/{OP}/old", ops_root(&PILOT_G31));
    assert_eq!(
        fs.file(&format!("{old}/nbt-aad")).unwrap(),
        content("old", "nbt-aad")
    );
    for n in PLUGIN_FILES {
        assert_eq!(
            fs.file(&format!("{old}/NbtAad/{n}")).unwrap(),
            content("old", n)
        );
    }
}

#[test]
fn nothing_is_writable_before_the_remount() {
    let mut fs = unit();
    let plan = the_plan(&fs, false);
    let first_write = &plan.steps[1].mutations[0];
    assert!(matches!(
        fs.apply(first_write, remount()),
        Err(SimError::ReadOnly(_))
    ));
    assert!(fs.applied.is_empty());
}

#[test]
fn a_second_operation_needs_the_ops_root_flag() {
    let mut fs = unit();
    fs.mkdirs(&ops_root(&PILOT_G31));
    let wrong = the_plan(&fs, false);
    fs.apply(&wrong.steps[0].mutations[0], remount()).unwrap();
    assert!(matches!(
        fs.apply(&wrong.steps[1].mutations[0], remount()),
        Err(SimError::Exists(_))
    ));
    let mut fs2 = unit();
    fs2.mkdirs(&ops_root(&PILOT_G31));
    let right = the_plan(&fs2, true);
    for s in &right.steps {
        for m in &s.mutations {
            fs2.apply(m, remount()).unwrap();
        }
    }
    assert!(
        matches!(state(&fs2), InstallState::Verified { installed, .. } if installed.tag == "new")
    );
}

/// All (step index, mutation) pairs in execution order.
fn flat(plan: &UpdatePlan) -> Vec<(usize, Mutation)> {
    plan.steps
        .iter()
        .enumerate()
        .flat_map(|(i, s)| s.mutations.iter().map(move |m| (i, m.clone())))
        .collect()
}

#[test]
fn every_interruption_point_is_classified_safely() {
    let base = unit();
    let plan = the_plan(&base, false);
    let muts = flat(&plan);
    for k in 0..=muts.len() {
        let mut fs = base.clone();
        for (_, m) in &muts[..k] {
            fs.apply(m, remount()).unwrap();
        }
        let s = state(&fs);
        let ok = match &s {
            InstallState::Verified { installed, .. } => ["old", "new"].contains(&installed.tag),
            InstallState::MidUpdate(_) => true,
            InstallState::Mixed { daemon, plugin } => daemon.tag == "new" && plugin.tag == "old",
            _ => false,
        };
        assert!(ok, "after {k} mutations: {s:?}");
        assert_eq!(untouchable(&fs), untouchable(&base), "after {k}");
    }
}

/// Recovery after an interruption: walk the started steps backwards and
/// apply each undo whose source still exists (state-driven, as the design
/// requires: never assume an interrupted step completed or not).
#[test]
fn recovery_from_every_interruption_point_restores_the_original() {
    let base = unit();
    let plan = the_plan(&base, false);
    let muts = flat(&plan);
    for k in 0..=muts.len() {
        let mut fs = base.clone();
        for (_, m) in &muts[..k] {
            fs.apply(m, remount()).unwrap();
        }
        let started = muts[..k].last().map_or(0, |(i, _)| i + 1);
        for s in plan.steps[..started].iter().rev() {
            for u in s.undo.iter().rev() {
                if let Mutation::Mv { from, .. } = u
                    && fs.nodes.contains_key(from)
                {
                    fs.apply(u, remount())
                        .unwrap_or_else(|e| panic!("k={k} {}: {e:?}", s.id));
                }
            }
        }
        match state(&fs) {
            InstallState::Verified { installed, backup } => {
                assert_eq!(installed.tag, "old", "k={k}");
                assert!(
                    matches!(backup, Backup::Known(b) if b.tag == "older"),
                    "k={k}"
                );
            }
            s => panic!("k={k}: not restored: {s:?}"),
        }
        assert_eq!(
            fs.file("/opt/aa/nbt-aad").unwrap(),
            content("old", "nbt-aad"),
            "k={k}"
        );
        for n in PLUGIN_FILES {
            assert_eq!(
                fs.file(&format!("{PD}/{n}")).unwrap(),
                content("old", n),
                "k={k}"
            );
        }
        assert_eq!(untouchable(&fs), untouchable(&base), "k={k}");
    }
}

#[test]
fn the_plan_never_targets_an_existing_path() {
    let fs = unit();
    let plan = the_plan(&fs, false);
    for (_, m) in flat(&plan) {
        if let Mutation::Cp { to, .. } | Mutation::Mkdir(to) = &m {
            assert!(!fs.nodes.contains_key(to), "{to}");
        }
    }
}
