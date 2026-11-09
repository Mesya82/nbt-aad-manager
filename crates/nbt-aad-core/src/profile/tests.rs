//! Profile matching and install-state classification against the real pilot
//! fixtures, and against single-fact deviations of them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use super::*;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Load a sanitized probe report directory as an [`Observation`].
fn load(run: &str) -> Observation {
    let dir = repo().join("tests/fixtures/pilot-g31").join(run);
    let mut o = Observation::default();
    let kex = std::fs::read_to_string(dir.join("ssh-kexinit.txt")).unwrap();
    o.ssh_banner = kex
        .lines()
        .find_map(|l| l.strip_prefix("banner: "))
        .map(str::to_owned);
    for e in std::fs::read_dir(dir.join("exec")).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        let id = name.split_once('-').unwrap().1.to_owned();
        let rc = std::fs::read_to_string(e.path().join("rc")).unwrap();
        let stdout = std::fs::read_to_string(e.path().join("stdout")).unwrap_or_default();
        let stderr = std::fs::read_to_string(e.path().join("stderr")).unwrap_or_default();
        o.records.entry(id).or_insert(Rec {
            rc: rc.trim().parse().unwrap(),
            stdout,
            stderr,
        });
    }
    if let Ok(tsv) = std::fs::read_to_string(dir.join("readback.tsv")) {
        o.add_readback_tsv(&tsv).unwrap();
    }
    o
}

const R2: &str = "run2-20261109-aa-stopped";
const R3: &str = "run3-20261109-aa-running";
const R4: &str = "run4-20261109-aa-running-usb";
const R5: &str = "run5-20261109-aa-stopped";

fn set_rc(o: &mut Observation, id: &str, rc: i64) {
    o.records.get_mut(id).unwrap().rc = rc;
}

/// The exact QNX answer for a missing directory.
fn make_absent(o: &mut Observation, id: &str, path: &str) {
    let r = o.records.get_mut(id).unwrap();
    r.rc = 1;
    r.stdout.clear();
    r.stderr = format!("ls: No such file or directory ({path})\n");
}

fn edit_listing(o: &mut Observation, id: &str, f: impl Fn(&str) -> Option<String>) {
    let r = o.records.get_mut(id).unwrap();
    r.stdout = r.stdout.lines().filter_map(&f).map(|l| l + "\n").collect();
}

fn drop_file(o: &mut Observation, id: &str, name: &str) {
    let suffix = format!(" {name}");
    edit_listing(o, id, |l| (!l.ends_with(&suffix)).then(|| l.to_owned()));
}

fn add_line(o: &mut Observation, id: &str, line: &str) {
    o.records
        .get_mut(id)
        .unwrap()
        .stdout
        .push_str(&format!("{line}\n"));
}

// ---- profile matching ----

#[test]
fn v3_runs_match_the_pilot_profile() {
    for run in [R4, R5] {
        assert_eq!(match_profile(&PILOT_G31, &load(run)), Ok(()), "{run}");
    }
}

#[test]
fn v2_runs_are_refused_for_missing_evidence_only() {
    for run in [R2, R3] {
        let err = match_profile(&PILOT_G31, &load(run)).unwrap_err();
        assert!(!err.is_empty());
        for m in &err {
            assert!(
                matches!(
                    m,
                    Mismatch::NotObserved("on + /bin/sh -c works")
                        | Mismatch::NotObserved("writability (test -w)")
                ),
                "{run}: unexpected {m:?}"
            );
        }
    }
}

#[test]
fn any_single_fact_deviation_is_a_mismatch() {
    type Mutate = fn(&mut Observation);
    let cases: &[(&str, Mutate)] = &[
        ("firmware text", |o| {
            o.records.get_mut(ids::FIRMWARE).unwrap().stdout = "NBTevo_Y23236J\n".into()
        }),
        ("firmware rc", |o| set_rc(o, ids::FIRMWARE, 1)),
        ("login uname", |o| {
            o.records
                .get_mut(ids::LOGIN_UNAME)
                .unwrap()
                .stdout
                .insert(0, 'x')
        }),
        ("daemon uname", |o| {
            o.records.get_mut(ids::DAEMON_UNAME).unwrap().stdout = "QNX other\n".into()
        }),
        ("banner", |o| {
            o.ssh_banner = Some("SSH-2.0-OpenSSH_7.4".into())
        }),
        ("no banner", |o| o.ssh_banner = None),
        ("on shell fails", |o| set_rc(o, ids::ON_SHELL, 2)),
        ("on runs built-ins", |o| set_rc(o, ids::ON_BARE, 0)),
        ("opt/aa writable", |o| set_rc(o, "hu-test-w-opt-aa", 0)),
        ("plugin writable", |o| set_rc(o, "hu-test-w-plugin", 0)),
        ("var not writable", |o| set_rc(o, "hu-test-w-var-opt-aa", 1)),
        ("test -w error (writable path)", |o| {
            set_rc(o, "hu-test-w-dev-shmem", 2)
        }),
        ("test -w error (read-only path)", |o| {
            set_rc(o, "hu-test-w-opt-aa", 2)
        }),
        ("unparsable daemon dir entry", |o| {
            add_line(
                o,
                ids::LS_DAEMON_DIR,
                "-rwxrwxrwx  1 root   5 Nov 08 14:57 nbt-aad.new",
            )
        }),
        ("unparsable state dir entry", |o| {
            add_line(
                o,
                ids::LS_STATE,
                "-rw-rw-rw-  1 root   5 Nov 08 14:57 usb-aa",
            )
        }),
        ("daemon dir missing", |o| set_rc(o, ids::LS_DAEMON_DIR, 1)),
        ("state dir missing", |o| set_rc(o, ids::LS_STATE, 1)),
        ("unparsable plugin entry", |o| {
            add_line(
                o,
                ids::LS_PLUGIN,
                "-rw-rw-rw-  1 root      root   5 Nov 08 14:57 lib NbtAad.so",
            )
        }),
        ("unparsable backup entry", |o| {
            add_line(
                o,
                ids::LS_PLUGIN_BACKUP,
                "-rw-rw-rw-  1 root   5 Nov 08 14:57 x",
            )
        }),
    ];
    for (what, f) in cases {
        let mut o = load(R4);
        f(&mut o);
        assert!(match_profile(&PILOT_G31, &o).is_err(), "{what}");
    }
    // Every record the matcher reads is required.
    for id in [
        ids::FIRMWARE,
        ids::LOGIN_UNAME,
        ids::DAEMON_UNAME,
        ids::ON_SHELL,
        ids::ON_BARE,
        ids::LS_DAEMON_DIR,
        ids::LS_STATE,
        "hu-test-w-opt-aa",
        "hu-test-w-plugin",
        "hu-test-w-var-opt-aa",
        "hu-test-w-dev-shmem",
    ] {
        let mut o = load(R4);
        o.records.remove(id);
        assert!(match_profile(&PILOT_G31, &o).is_err(), "removed {id}");
    }
}

// ---- classification ----

fn verified(s: &InstallState) -> (&'static str, &Backup) {
    match s {
        InstallState::Verified { installed, backup } => (installed.tag, backup),
        other => panic!("not verified: {other:?}"),
    }
}

#[test]
fn pilot_after_update_is_gps_with_volslider_backup() {
    for run in [R4, R5] {
        let s = classify(&PILOT_G31, &load(run));
        let (tag, backup) = verified(&s);
        assert_eq!(tag, "gps", "{run}");
        assert!(
            matches!(backup, Backup::Known(k) if k.tag == "volsliderfixforreal"),
            "{run}: {backup:?}"
        );
    }
}

#[test]
fn pilot_before_update_is_unverified_without_digests() {
    for run in [R2, R3] {
        assert_eq!(
            classify(&PILOT_G31, &load(run)),
            InstallState::Unverified {
                candidate: Some("volsliderfixforreal")
            },
            "{run}"
        );
    }
}

fn mid(o: &Observation) -> bool {
    matches!(classify(&PILOT_G31, o), InstallState::MidUpdate(_))
}

#[test]
fn half_applied_updates_are_mid_update() {
    type Mutate = fn(&mut Observation);
    let cases: &[(&str, Mutate)] = &[
        ("daemon moved away, new not copied", |o| {
            drop_file(o, ids::LS_DAEMON_DIR, "nbt-aad")
        }),
        ("plugin moved away, new dir not created", |o| {
            make_absent(o, ids::LS_PLUGIN, PILOT_G31.plugin_dir)
        }),
        ("plugin dir created, nothing copied", |o| {
            o.records.get_mut(ids::LS_PLUGIN).unwrap().stdout = "total 0\n".into()
        }),
        ("plugin copy interrupted", |o| {
            drop_file(o, ids::LS_PLUGIN, "libNbtAad.so")
        }),
        ("extra plugin file", |o| {
            add_line(
                o,
                ids::LS_PLUGIN,
                "-rw-rw-rw-  1 root      root   5 Nov 08 14:57 LibNbtAad.so.old",
            )
        }),
        ("case variant plugin file", |o| {
            edit_listing(o, ids::LS_PLUGIN, |l| {
                Some(l.replace("libNbtAad.so", "libnbtaad.so"))
            })
        }),
        ("daemon backed up, plugin not yet", |o| {
            make_absent(o, ids::LS_PLUGIN_BACKUP, PILOT_G31.plugin_backup_dir)
        }),
        ("plugin backed up, daemon not", |o| {
            drop_file(o, ids::LS_DAEMON_DIR, "nbt-aad.old")
        }),
        ("incomplete plugin backup", |o| {
            drop_file(o, ids::LS_PLUGIN_BACKUP, "NbtAad.xml")
        }),
    ];
    for (what, f) in cases {
        let mut o = load(R4);
        f(&mut o);
        assert!(mid(&o), "{what}: {:?}", classify(&PILOT_G31, &o));
    }
}

#[test]
fn no_backups_is_verified_without_backup() {
    let mut o = load(R4);
    drop_file(&mut o, ids::LS_DAEMON_DIR, "nbt-aad.old");
    make_absent(&mut o, ids::LS_PLUGIN_BACKUP, PILOT_G31.plugin_backup_dir);
    assert_eq!(*verified(&classify(&PILOT_G31, &o)).1, Backup::None);
}

#[test]
fn digest_problems_never_verify() {
    let flip = |o: &mut Observation, path: &str| {
        let d = o.digests.get_mut(path).unwrap();
        d.1 =
            d.1.replacen(&d.1[..1], if d.1.starts_with('0') { "1" } else { "0" }, 1);
    };
    let pd = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";

    let mut o = load(R4);
    flip(&mut o, "/opt/aa/nbt-aad");
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));

    let mut o = load(R4);
    flip(&mut o, &format!("{pd}/NbtAad.xml"));
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));

    // Listing and read-back disagree on size (file changed between the two).
    let mut o = load(R4);
    o.digests.get_mut("/opt/aa/nbt-aad").unwrap().0 += 1;
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));

    // A missing read-back is unverified, not verified.
    let mut o = load(R4);
    o.digests.remove(&format!("{pd}/libNbtAad.so"));
    assert!(matches!(
        classify(&PILOT_G31, &o),
        InstallState::Unverified {
            candidate: Some("gps")
        }
    ));

    // Backup problems keep the active identification but flag the backup.
    let mut o = load(R4);
    flip(&mut o, "/opt/aa/nbt-aad.old");
    assert!(matches!(
        verified(&classify(&PILOT_G31, &o)).1,
        Backup::NotIdentified(_)
    ));
    let mut o = load(R4);
    o.digests.remove("/opt/aa/NbtAad.old/libNbtAad.so");
    assert!(matches!(
        verified(&classify(&PILOT_G31, &o)).1,
        Backup::NotIdentified(_)
    ));
}

#[test]
fn mixed_active_set_is_reported() {
    // Old plugin in the active slot with the new daemon (same sizes/digests
    // as the backup set).
    let mut o = load(R4);
    let pd = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";
    let old = o.records[ids::LS_PLUGIN_BACKUP].stdout.clone();
    o.records.get_mut(ids::LS_PLUGIN).unwrap().stdout = old;
    for f in PLUGIN_FILES {
        let v = o.digests[&format!("/opt/aa/NbtAad.old/{f}")].clone();
        o.digests.insert(format!("{pd}/{f}"), v);
    }
    assert!(matches!(
        classify(&PILOT_G31, &o),
        InstallState::Mixed { daemon, plugin } if daemon.tag == "gps" && plugin.tag == "volsliderfixforreal"
    ));
}

#[test]
fn symlinks_and_missing_records_are_unknown() {
    let mut o = load(R4);
    add_line(
        &mut o,
        ids::LS_PLUGIN,
        "lrwxrwxrwx  1 root      root   8 Nov 08 14:57 x -> /tmp/x",
    );
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));
    for id in [ids::LS_DAEMON_DIR, ids::LS_PLUGIN, ids::LS_PLUGIN_BACKUP] {
        let mut o = load(R4);
        o.records.remove(id);
        assert!(
            matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)),
            "{id}"
        );
    }
    let mut o = load(R4);
    set_rc(&mut o, ids::LS_DAEMON_DIR, 1);
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));
}

#[test]
fn readback_conflicts_are_errors() {
    let mut o = Observation::default();
    let tsv = "path\trc\tbytes\tsha256\n/a\t0\t1\taa\n/a\t0\t1\tAA\n";
    assert!(
        o.add_readback_tsv(tsv).is_ok(),
        "same digest, different case"
    );
    assert!(o.add_readback_tsv("h\n/a\t0\t1\tbb\n").is_err());
    assert!(o.add_readback_tsv("h\n/b\t0\tx\tbb\n").is_err());
    assert!(o.add_readback_tsv("h\n/b\t0\n").is_err());
    assert!(o.add_readback_tsv("h\n/c\t1\t0\t\n").is_ok());
    assert!(
        !o.digests.contains_key("/c"),
        "failed reads are not digests"
    );
}

// ---- the profile itself ----

#[test]
fn every_cited_evidence_path_exists() {
    let p = PILOT_G31;
    let facts = [
        p.firmware.evidence,
        p.ssh_banner.evidence,
        p.login_uname.evidence,
        p.daemon_uname.evidence,
        p.on_requires_shell.evidence,
        p.writable.evidence,
        p.tools_present.evidence,
        p.tools_absent.evidence,
    ];
    for e in facts {
        let Evidence::Observed(paths) = e else {
            panic!("observed fact without fixtures: {e:?}")
        };
        assert!(!paths.is_empty());
        for path in paths {
            assert!(repo().join(path).is_dir(), "{path}");
        }
    }
    // The remount is operator-reported and its persistence unknown: it must
    // not be presented as observed.
    assert!(matches!(p.remount.evidence, Evidence::OperatorReported(_)));
    assert_eq!(
        p.remount.value.persists_until_restart.evidence,
        Evidence::Unknown
    );
}

#[test]
fn profile_paths_are_guard_safe() {
    let p = PILOT_G31;
    for path in [
        p.daemon_dir,
        p.plugin_dir,
        p.plugin_backup_dir,
        p.state_dir,
        p.remount.value.verify_writable,
    ]
    .into_iter()
    .chain(p.writable.value.iter().map(|w| w.path))
    .chain(p.protected.iter().copied())
    .chain(p.daemon_owned.iter().copied())
    {
        assert!(
            crate::guard::GuardedCommand::new(
                crate::guard::Context::Node(crate::guard::NodePath::new(p.daemon_node).unwrap()),
                &format!("ls -la {path}")
            )
            .is_ok(),
            "{path}"
        );
    }
    assert!(p.protected.contains(&"/opt/aa/nbt-aad.env"));
}

#[test]
fn tool_lists_are_disjoint_and_cover_the_hazards() {
    let p = PILOT_G31;
    for t in p.tools_present.value {
        assert!(!p.tools_absent.value.contains(t), "{t}");
    }
    for t in ["sync", "sha256sum", "stat", "mktemp"] {
        assert!(p.tools_absent.value.contains(&t), "{t}");
    }
}

#[test]
fn listing_order_does_not_matter() {
    let mut o = load(R4);
    let r = o.records.get_mut(ids::LS_PLUGIN).unwrap();
    let mut lines: Vec<&str> = r.stdout.lines().collect();
    lines.reverse();
    r.stdout = lines.join("\n") + "\n";
    assert_eq!(verified(&classify(&PILOT_G31, &o)).0, "gps");
}

#[test]
fn listing_size_must_equal_read_back_size() {
    // The read-back is the known release, but the listing (taken earlier)
    // shows another size: the file changed in between. Never verified.
    let mut o = load(R4);
    edit_listing(&mut o, ids::LS_DAEMON_DIR, |l| {
        Some(if l.ends_with(" nbt-aad") {
            l.replace("773142", "773143")
        } else {
            l.to_owned()
        })
    });
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));
}

/// A listing that failed for any reason other than the exact "No such file"
/// answer is not evidence of absence (reviewer finding: a timed-out
/// `ls NbtAad.old` must not become "no backup present").
#[test]
fn failed_listings_are_never_taken_as_absent() {
    let failures: [(i64, &str); 4] = [
        (-1, ""),
        (1, "ls: Permission denied (/opt/aa/NbtAad.old)\n"),
        (2, "ls: No such file or directory (/opt/aa/NbtAad.old)\n"),
        (1, "ls: No such file or directory (/opt/aa/NbtAad.ol)\n"),
    ];
    for (rc, stderr) in failures {
        let mut o = load(R4);
        drop_file(&mut o, ids::LS_DAEMON_DIR, "nbt-aad.old");
        let r = o.records.get_mut(ids::LS_PLUGIN_BACKUP).unwrap();
        r.rc = rc;
        r.stdout.clear();
        r.stderr = stderr.into();
        assert!(
            matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)),
            "rc {rc} {stderr:?}: {:?}",
            classify(&PILOT_G31, &o)
        );
    }
    // Same for the active plugin directory: unknown, not "half-applied".
    let mut o = load(R4);
    set_rc(&mut o, ids::LS_PLUGIN, -1);
    assert!(matches!(classify(&PILOT_G31, &o), InstallState::Unknown(_)));
    // The real observed answer (run 2) is absence.
    let o = load(R2);
    assert!(listing_says_absent(
        &o.records[ids::LS_PLUGIN_BACKUP],
        PILOT_G31.plugin_backup_dir
    ));
}
