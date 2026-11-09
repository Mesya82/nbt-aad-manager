#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::profile::PILOT_G31;
use crate::release::{KNOWN, PLUGIN_FILES};

const OP: &str = "20261109T170000Z-abc123";
const USB: &str = "/mnt/umass01200t12";

fn gps_with_backup() -> InstallState {
    InstallState::Verified {
        installed: release::find_known(KNOWN, "gps").unwrap(),
        backup: Backup::Known(release::find_known(KNOWN, "volsliderfixforreal").unwrap()),
    }
}

fn plan() -> UpdatePlan {
    plan_update(
        &PILOT_G31,
        &gps_with_backup(),
        "volsliderfixforreal",
        KNOWN,
        OP,
        USB,
    )
    .unwrap()
}

#[test]
fn plan_has_the_designed_steps_in_order() {
    let p = plan();
    let ids: Vec<_> = p.steps.iter().map(|s| s.id).collect();
    assert_eq!(
        ids,
        ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"]
    );
    assert_eq!(p.from.tag, "gps");
    assert_eq!(p.to.tag, "volsliderfixforreal");
}

#[test]
fn only_allowlisted_mutation_kinds_and_no_deletions() {
    for s in plan().steps {
        for m in s.mutations.iter().chain(&s.undo) {
            let r = m.render();
            for bad in [
                "rm ", "rmdir", "kill", "slay", ">", "*", ";", "&", "|", "$", "`",
            ] {
                assert!(!r.contains(bad), "{}: {r}", s.id);
            }
        }
    }
}

#[test]
fn every_write_target_is_inside_the_op_dir_or_an_exact_active_path() {
    let p = plan();
    let op = format!("{}/{OP}", ops_root(&PILOT_G31));
    let daemon = "/opt/aa/nbt-aad";
    let plugin = PILOT_G31.plugin_dir;
    for s in &p.steps {
        for m in s.mutations.iter().chain(&s.undo) {
            let targets: Vec<&str> = match m {
                Mutation::Remount { command, .. } => {
                    assert_eq!(command, PILOT_G31.remount.value.command);
                    vec![]
                }
                Mutation::Mkdir(t) | Mutation::Chmod755(t) => vec![t],
                Mutation::Cp { from, to } => {
                    assert!(from.starts_with(&format!("{USB}/nbt-aad-{OP}/")), "{from}");
                    vec![to]
                }
                Mutation::Mv { from, to } => vec![from, to],
            };
            for t in targets {
                assert!(
                    t == ops_root(&PILOT_G31) || t.starts_with(&op) || t == daemon || t == plugin,
                    "{}: {t}",
                    s.id
                );
            }
        }
    }
}

#[test]
fn foreign_backups_and_protected_paths_are_never_touched() {
    let p = plan();
    for s in &p.steps {
        for m in s.mutations.iter().chain(&s.undo) {
            for path in m.paths() {
                assert!(!path.starts_with("/opt/aa/nbt-aad.old"), "{path}");
                assert!(!path.starts_with(PILOT_G31.plugin_backup_dir), "{path}");
                for prot in PILOT_G31.protected {
                    assert!(!path.starts_with(prot), "{path} touches protected {prot}");
                }
                for own in PILOT_G31.daemon_owned {
                    assert_ne!(path, *own);
                }
            }
        }
    }
}

#[test]
fn every_mv_has_an_exact_inverse_undo() {
    for s in plan().steps {
        let mvs: Vec<_> = s
            .mutations
            .iter()
            .filter_map(|m| match m {
                Mutation::Mv { from, to } => Some((from.clone(), to.clone())),
                _ => None,
            })
            .collect();
        for (from, to) in mvs {
            assert!(
                s.undo.contains(&Mutation::Mv {
                    from: to.clone(),
                    to: from.clone()
                }),
                "{}: no undo for mv {from} {to}",
                s.id
            );
        }
    }
}

#[test]
fn moves_stay_on_the_daemon_filesystem() {
    // /opt/aa and the plugin tree share /fs/sda0 (pilot runs 2-5): every
    // mv must be a rename, never a cross-filesystem copy.
    for s in plan().steps {
        for m in &s.mutations {
            if let Mutation::Mv { from, to } = m {
                for p in [from, to] {
                    assert!(
                        p.starts_with("/opt/aa/") || p.starts_with("/opt/hmi/"),
                        "{p}"
                    );
                }
            }
        }
    }
}

#[test]
fn verification_covers_every_promoted_and_backed_up_file() {
    let p = plan();
    let digests: Vec<(String, &str)> = p
        .steps
        .iter()
        .flat_map(|s| &s.verify)
        .filter_map(|v| match v {
            Verify::Digest { path, sha256, .. } => Some((path.clone(), *sha256)),
            _ => None,
        })
        .collect();
    let has = |path: &str, sha: &str| digests.iter().any(|(p, s)| p == path && *s == sha);
    assert!(has("/opt/aa/nbt-aad", p.to.daemon.sha256));
    let old = format!("{}/{OP}/old", ops_root(&PILOT_G31));
    assert!(has(&format!("{old}/nbt-aad"), p.from.daemon.sha256));
    for (i, f) in PLUGIN_FILES.iter().enumerate() {
        assert!(has(
            &format!("{}/{f}", PILOT_G31.plugin_dir),
            p.to.plugin[i].sha256
        ));
        assert!(has(&format!("{old}/NbtAad/{f}"), p.from.plugin[i].sha256));
    }
}

#[test]
fn steps_needing_hardware_evidence_are_marked() {
    let p = plan();
    for id in ["S1", "S5", "S6", "S7", "S8"] {
        let s = p.steps.iter().find(|s| s.id == id).unwrap();
        assert!(!s.evidence_needed.is_empty(), "{id}");
    }
    let r = p.render();
    assert!(r.starts_with("UPDATE PLAN (NOT EXECUTED"));
    assert!(r.contains("BLOCKED until hardware evidence"));
}

#[test]
fn refusals() {
    use PlanError as E;
    let ok = gps_with_backup();
    let p = &PILOT_G31;
    assert!(matches!(
        plan_update(p, &ok, "gps", KNOWN, OP, USB),
        Err(E::AlreadyInstalled(_))
    ));
    assert!(matches!(
        plan_update(p, &ok, "brwsr-ap", KNOWN, OP, USB),
        Err(E::UnknownTarget(_))
    ));
    for bad in [
        "",
        "x",
        "20261109T170000Z-ABC123",
        "20261109T170000Z-abc123/..",
        "../x",
    ] {
        assert!(
            matches!(
                plan_update(p, &ok, "volsliderfixforreal", KNOWN, bad, USB),
                Err(E::BadOpId(_))
            ),
            "{bad}"
        );
    }
    for bad in [
        "/mnt",
        "/mnt/umass",
        "/fs/usb0",
        "/mnt/umass0/../..",
        "/mnt/umass0 x",
    ] {
        assert!(
            matches!(
                plan_update(p, &ok, "volsliderfixforreal", KNOWN, OP, bad),
                Err(E::BadUsbMount(_))
            ),
            "{bad}"
        );
    }
    for st in [
        InstallState::Unverified {
            candidate: Some("gps"),
        },
        InstallState::MidUpdate(vec!["x".into()]),
        InstallState::Unknown(vec![]),
        InstallState::Mixed {
            daemon: &KNOWN[0],
            plugin: &KNOWN[1],
        },
    ] {
        assert!(
            matches!(
                plan_update(p, &st, "volsliderfixforreal", KNOWN, OP, USB),
                Err(E::NotVerified(_))
            ),
            "{st:?}"
        );
    }
}
