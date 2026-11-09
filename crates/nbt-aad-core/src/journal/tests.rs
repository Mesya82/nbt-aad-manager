//! Journal + apply/recover engine against the simulator, with journal-write
//! failures (clean and torn), execution failures, lost replies, check
//! errors, restarts and journal truncation injected at every point.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::plan::{UpdatePlan, plan_update};
use crate::profile::{InstallState, PILOT_G31, classify_in};
use crate::testkit::sim::scenario::{OP, USB, active, table, unit, untouchable};
use crate::testkit::sim::{MemStore, SimExecutor, SimFs};

fn state(fs: &SimFs) -> InstallState {
    classify_in(&PILOT_G31, &fs.observe(&PILOT_G31), table())
}

fn plan_for(fs: &SimFs) -> UpdatePlan {
    plan_update(&PILOT_G31, &state(fs), "new", table(), OP, USB, false).unwrap()
}

fn executor(fs: SimFs) -> SimExecutor {
    SimExecutor::new(fs, PILOT_G31.remount.value.command)
}

fn mutation_count(p: &UpdatePlan) -> usize {
    p.steps.iter().map(|s| s.mutations.len()).sum()
}

fn is_old(fs: &SimFs, orig: &SimFs) -> bool {
    matches!(state(fs), InstallState::Verified { installed, .. } if installed.tag == "old")
        && active(fs) == active(orig)
}

fn is_new(fs: &SimFs) -> bool {
    matches!(state(fs), InstallState::Verified { installed, .. } if installed.tag == "new")
}

fn events(store: &MemStore) -> Vec<Event> {
    parse(&store.text).unwrap().0.events
}

fn s8_verified(store: &MemStore) -> bool {
    events(store)
        .iter()
        .any(|e| matches!(e, Event::Verified { step } if step == "S8"))
}

/// After a failure: if all active changes were already verified, recovery
/// must refuse (rollback case) and leave the new release in place;
/// otherwise it must restore the original. Returns false in the first case.
fn recover_or_refuse(plan: &UpdatePlan, store: MemStore, fs: SimFs, orig: &SimFs) -> bool {
    if s8_verified(&store) {
        let (mut j, loaded) = Journal::reopen(store).unwrap();
        let mut ex = executor(fs);
        assert!(matches!(
            recover(plan, &mut j, &loaded, &mut ex, |_| Ok(true)),
            Err(ApplyError::UpdateAlreadyApplied)
        ));
        assert!(is_new(&ex.fs));
        assert_eq!(ex.executed, 0);
        return false;
    }
    let fs = recover_ok(plan, store, fs, orig);
    assert!(is_old(&fs, orig));
    true
}

/// Recover with a healthy store/executor; asserts success.
fn recover_ok(plan: &UpdatePlan, store: MemStore, fs: SimFs, orig: &SimFs) -> SimFs {
    let (mut j, loaded) = Journal::reopen(store).unwrap();
    let mut ex = executor(fs);
    let o = orig.clone();
    recover(plan, &mut j, &loaded, &mut ex, |e| Ok(is_old(&e.fs, &o)))
        .unwrap_or_else(|e| panic!("recover: {e}"));
    assert_eq!(events(j.store()).last(), Some(&Event::RolledBack));
    ex.fs
}

#[test]
fn apply_stops_for_the_operator_and_never_self_completes() {
    let fs = unit();
    let plan = plan_for(&fs);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(fs);
    let out = apply(&plan, &mut j, &mut ex).unwrap();
    assert_eq!(out, ApplyOutcome::AwaitingOperator { step: "S10".into() });
    assert!(is_new(&ex.fs));
    let ev = events(j.store());
    assert_eq!(ev.last(), Some(&Event::Awaiting { step: "S10".into() }));
    assert!(!ev.contains(&Event::Complete));
    let intents = ev
        .iter()
        .filter(|e| matches!(e, Event::Intent { .. }))
        .count();
    assert_eq!(intents, mutation_count(&plan));
    assert!(confirm_complete(&mut j, false).is_err());
    let mut j2 = Journal::begin(MemStore::default(), &plan).unwrap();
    apply(&plan, &mut j2, &mut executor(unit())).unwrap();
    confirm_complete(&mut j2, true).unwrap();
    assert_eq!(events(j2.store()).last(), Some(&Event::Complete));
}

#[test]
fn no_mutation_ever_runs_without_a_durable_intent_and_all_recover() {
    let base = unit();
    let plan = plan_for(&base);
    let total = {
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        apply(&plan, &mut j, &mut executor(base.clone())).unwrap();
        j.store().appends
    };
    for torn in [false, true] {
        for k in 0..total {
            let store = MemStore {
                fail_at: Some(k),
                torn,
                ..MemStore::default()
            };
            let mut ex = executor(base.clone());
            let Ok(mut j) = Journal::begin(store, &plan) else {
                assert_eq!((k, ex.executed), (0, 0));
                continue;
            };
            let r = apply(&plan, &mut j, &mut ex);
            let store = j.into_store();
            let (l, _, _) = parse(&store.text).unwrap();
            let intents = l
                .events
                .iter()
                .filter(|e| matches!(e, Event::Intent { .. }))
                .count();
            assert!(ex.executed <= intents, "k={k} torn={torn}");
            assert_eq!(untouchable(&ex.fs), untouchable(&base), "k={k}");
            assert!(r.is_err(), "k={k}: every append failure must stop apply");
            let applied = l
                .events
                .iter()
                .any(|e| matches!(e, Event::Verified { step } if step == "S8"));
            if applied {
                // All active changes verified: a rollback case, not recovery.
                let (mut j, loaded) = Journal::reopen(store).unwrap();
                assert!(matches!(
                    recover(&plan, &mut j, &loaded, &mut ex, |_| Ok(true)),
                    Err(ApplyError::UpdateAlreadyApplied)
                ));
                assert!(is_new(&ex.fs));
                continue;
            }
            let fs = recover_ok(&plan, store, ex.fs, &base);
            assert!(is_old(&fs, &base), "k={k} torn={torn}");
            assert_eq!(untouchable(&fs), untouchable(&base));
        }
    }
}

#[test]
fn failed_and_ambiguous_mutations_at_every_point_recover() {
    let base = unit();
    let plan = plan_for(&base);
    for ambiguous in [false, true] {
        for k in 0..mutation_count(&plan) {
            let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
            let mut ex = executor(base.clone());
            if ambiguous {
                ex.ambiguous_at = Some(k);
            } else {
                ex.fail_at = Some(k);
            }
            assert!(
                matches!(
                    apply(&plan, &mut j, &mut ex),
                    Err(ApplyError::Mutation { .. })
                ),
                "k={k}"
            );
            recover_or_refuse(&plan, j.into_store(), ex.fs, &base);
        }
    }
}

#[test]
fn a_check_that_cannot_be_performed_stops_apply_and_recover() {
    let base = unit();
    let plan = plan_for(&base);
    let total_checks = {
        let mut ex = executor(base.clone());
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        apply(&plan, &mut j, &mut ex).unwrap();
        ex.checks
    };
    for k in 0..total_checks {
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        let mut ex = executor(base.clone());
        ex.check_error_at = Some(k);
        let e = apply(&plan, &mut j, &mut ex).unwrap_err();
        assert!(matches!(e, ApplyError::Check { .. }), "k={k}: {e}");
        let store = j.into_store();
        if s8_verified(&store) {
            recover_or_refuse(&plan, store, ex.fs, &base);
            continue;
        }
        // Recovery must also stop (not guess) when a check errors.
        let (mut j2, loaded) = Journal::reopen(store.clone()).unwrap();
        let mut ex2 = executor(ex.fs.clone());
        ex2.check_error_at = Some(0);
        assert!(matches!(
            recover(&plan, &mut j2, &loaded, &mut ex2, |_| Ok(true)),
            Err(ApplyError::Check { .. })
        ));
        assert_eq!(
            ex2.executed, 0,
            "k={k}: nothing runs after an unknown check"
        );
        let fs = recover_ok(&plan, store, ex.fs, &base);
        assert!(is_old(&fs, &base), "k={k}");
    }
}

#[test]
fn recovery_after_a_restart_re_establishes_the_remount() {
    let base = unit();
    let plan = plan_for(&base);
    for k in 1..mutation_count(&plan) {
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        let mut ex = executor(base.clone());
        ex.fail_at = Some(k);
        let _ = apply(&plan, &mut j, &mut ex);
        ex.fs.restart();
        recover_or_refuse(&plan, j.into_store(), ex.fs, &base);
    }
}

#[test]
fn autostart_before_the_daemon_move_stops_before_any_active_change() {
    let mut fs = unit();
    fs.daemon_running = true;
    let plan = plan_for(&unit());
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(fs);
    let e = apply(&plan, &mut j, &mut ex).unwrap_err();
    assert!(
        matches!(&e, ApplyError::Precondition { step, .. } if step == "S5"),
        "{e}"
    );
    assert_eq!(active(&ex.fs), active(&unit()));
    let store = j.into_store();
    let (mut j2, loaded) = Journal::reopen(store.clone()).unwrap();
    let mut ex2 = executor(ex.fs.clone());
    assert!(matches!(
        recover(&plan, &mut j2, &loaded, &mut ex2, |_| Ok(true)),
        Err(ApplyError::Precondition { .. })
    ));
    assert_eq!(ex2.executed, 0);
    ex.fs.daemon_running = false;
    let fs = recover_ok(&plan, store, ex.fs, &unit());
    assert!(is_old(&fs, &unit()));
}

#[test]
fn journal_truncated_at_a_line_boundary_still_recovers() {
    // Recovery is state-driven: losing whole trailing lines (which the chain
    // cannot detect) does not prevent a correct recovery.
    let base = unit();
    let plan = plan_for(&base);
    for k in 0..mutation_count(&plan) {
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        let mut ex = executor(base.clone());
        ex.fail_at = Some(k);
        let _ = apply(&plan, &mut j, &mut ex);
        let mut store = j.into_store();
        let first_line = store.text.find('\n').unwrap() + 1;
        store.text.truncate(first_line); // only BEGIN left
        let fs = recover_ok(&plan, store, ex.fs, &base);
        assert!(is_old(&fs, &base), "k={k}");
    }
}

#[test]
fn tampered_usb_copy_stops_before_any_active_change() {
    let mut fs = unit();
    fs.put(
        &format!("{USB}/nbt-aad-{OP}/Releases/libNbtAad.so"),
        b"evil",
        0o666,
    );
    let plan = plan_for(&unit());
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(fs);
    let e = apply(&plan, &mut j, &mut ex).unwrap_err();
    assert!(
        matches!(&e, ApplyError::Verification { step, .. } if step == "S3"),
        "{e}"
    );
    assert_eq!(active(&ex.fs), active(&unit()));
}

#[test]
fn applied_updates_are_not_recovered() {
    let base = unit();
    let plan = plan_for(&base);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(base);
    apply(&plan, &mut j, &mut ex).unwrap();
    let (mut j2, loaded) = Journal::reopen(j.into_store()).unwrap();
    assert!(matches!(
        recover(&plan, &mut j2, &loaded, &mut ex, |_| Ok(true)),
        Err(ApplyError::UpdateAlreadyApplied)
    ));
    assert!(is_new(&ex.fs));
}

#[test]
fn corruption_order_and_foreign_journals_are_refused() {
    let base = unit();
    let plan = plan_for(&base);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(base.clone());
    ex.fail_at = Some(12);
    let _ = apply(&plan, &mut j, &mut ex);
    let text = j.into_store().text;

    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines[3].push('x');
    assert!(matches!(
        parse(&(lines.join("\n") + "\n")),
        Err(JournalError::Corrupt { line: 4, .. })
    ));
    let mut l2: Vec<&str> = text.lines().collect();
    l2.remove(2);
    assert!(matches!(
        parse(&(l2.join("\n") + "\n")),
        Err(JournalError::Corrupt { .. })
    ));

    // Well-chained but out-of-order events are corrupt too.
    let mut jj = Journal::begin(MemStore::default(), &plan).unwrap();
    jj.append(&Event::Done {
        step: "S1".into(),
        index: 0,
    })
    .unwrap();
    assert!(parse(&jj.store().text).is_err(), "DONE without INTENT");
    let mut jj = Journal::begin(MemStore::default(), &plan).unwrap();
    jj.append(&Event::Complete).unwrap();
    jj.append(&Event::Verified { step: "S1".into() }).unwrap();
    assert!(parse(&jj.store().text).is_err(), "event after COMPLETE");

    let other = plan_update(
        &PILOT_G31,
        &state(&base),
        "new",
        table(),
        "20261109T170001Z-zzz999",
        USB,
        false,
    )
    .unwrap();
    let (mut jr, loaded) = Journal::reopen(MemStore {
        text: text.clone(),
        ..MemStore::default()
    })
    .unwrap();
    assert!(matches!(
        recover(&other, &mut jr, &loaded, &mut ex, |_| Ok(true)),
        Err(ApplyError::WrongPlan)
    ));
    assert!(matches!(
        Journal::begin(
            MemStore {
                text,
                ..MemStore::default()
            },
            &plan
        ),
        Err(JournalError::NotEmpty)
    ));
}

#[test]
fn recovery_that_cannot_restore_is_reported_not_claimed() {
    let base = unit();
    let plan = plan_for(&base);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(base.clone());
    ex.fail_at = Some(15); // S6: the old daemon is already in the op backup
    let _ = apply(&plan, &mut j, &mut ex);
    let old = format!("{}/{OP}/old/nbt-aad", crate::plan::ops_root(&PILOT_G31));
    ex.fs.nodes.remove(&old);
    let (mut j2, loaded) = Journal::reopen(j.into_store()).unwrap();
    let o = base.clone();
    let e = recover(&plan, &mut j2, &loaded, &mut ex, |e| Ok(is_old(&e.fs, &o))).unwrap_err();
    assert!(matches!(e, ApplyError::Verification { .. }), "{e}");
    assert!(!events(j2.store()).contains(&Event::RolledBack));
}

#[test]
fn control_characters_never_reach_the_journal() {
    assert_eq!(field("a\tb\nc\rd\u{1b}[31me"), "a b c d [31me");
}

#[test]
fn a_check_error_anywhere_in_recovery_stops_it() {
    let base = unit();
    let plan = plan_for(&base);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(base.clone());
    ex.fail_at = Some(17); // inside the plugin moves
    let _ = apply(&plan, &mut j, &mut ex);
    let store = j.into_store();
    let total = {
        let (mut j2, loaded) = Journal::reopen(store.clone()).unwrap();
        let mut e2 = executor(ex.fs.clone());
        let o = base.clone();
        recover(&plan, &mut j2, &loaded, &mut e2, |e| Ok(is_old(&e.fs, &o))).unwrap();
        e2.checks
    };
    assert!(total > 5);
    for k in 0..total {
        let (mut j2, loaded) = Journal::reopen(store.clone()).unwrap();
        let mut e2 = executor(ex.fs.clone());
        e2.check_error_at = Some(k);
        let o = base.clone();
        let r = recover(&plan, &mut j2, &loaded, &mut e2, |e| Ok(is_old(&e.fs, &o)));
        assert!(matches!(r, Err(ApplyError::Check { .. })), "k={k}: {r:?}");
        assert!(!events(j2.store()).contains(&Event::RolledBack), "k={k}");
    }
}

#[test]
fn a_second_begin_is_corrupt() {
    let plan = plan_for(&unit());
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    j.append(&Event::Begin {
        op_id: "x".into(),
        profile_id: "y".into(),
        from: "a".into(),
        to: "b".into(),
        plan_sha256: "c".into(),
    })
    .unwrap();
    assert!(matches!(
        parse(&j.store().text),
        Err(JournalError::Corrupt { line: 2, .. })
    ));
}
