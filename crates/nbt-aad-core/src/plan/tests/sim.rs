//! The update plan executed against the stateful filesystem model, with an
//! interruption after every single mutation (power loss / connection loss)
//! and state-driven recovery from each point.

use crate::plan::{Mutation, UpdatePlan, Verify, ops_root, plan_update};
use crate::profile::{Backup, InstallState, PILOT_G31, classify_in};
use crate::release::PLUGIN_FILES;
use crate::testkit::sim::scenario::{OP, PD, USB, content, table, unit, untouchable};
use crate::testkit::sim::{SimError, SimFs};

fn state(fs: &SimFs) -> InstallState {
    classify_in(&PILOT_G31, &fs.observe(&PILOT_G31), table())
}

fn the_plan(fs: &SimFs, root_exists: bool) -> UpdatePlan {
    plan_update(&PILOT_G31, &state(fs), "new", table(), OP, USB, root_exists).unwrap()
}

fn remount() -> &'static str {
    PILOT_G31.remount.value.command
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
        if s.verify.iter().any(|v| matches!(v, Verify::Operator(_))) {
            break;
        }
        for v in &s.pre {
            assert!(fs.check(v), "{} pre: {v:?}", s.id);
        }
        for m in &s.mutations {
            fs.apply(m, remount())
                .unwrap_or_else(|e| panic!("{} {m:?}: {e:?}", s.id));
        }
        for v in &s.verify {
            assert!(fs.check(v), "{}: {v:?}", s.id);
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
        // Model-level recovery (the engine's `recover` is tested in
        // journal/tests.rs): every step, backwards, each undo only when its
        // exact-state guard holds. No knowledge of k is used.
        for s in plan.steps.iter().rev() {
            for u in s.undo.iter().rev() {
                if u.only_if.iter().all(|v| fs.check(v)) {
                    fs.apply(&u.mutation, remount())
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
