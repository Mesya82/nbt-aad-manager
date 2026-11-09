//! Journal + apply/recover engine against the simulator, with journal-write
//! failures (clean and torn) and execution failures injected at every point.
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
    SimExecutor {
        fs,
        remount: PILOT_G31.remount.value.command,
        fail_at: None,
        executed: 0,
    }
}

fn mutation_count(p: &UpdatePlan) -> usize {
    p.steps.iter().map(|s| s.mutations.len()).sum()
}

fn is_old(fs: &SimFs, orig: &SimFs) -> bool {
    matches!(state(fs), InstallState::Verified { installed, .. } if installed.tag == "old")
        && active(fs) == active(orig)
}

/// Recover from whatever the store holds, with a healthy store/executor.
fn recover_from(plan: &UpdatePlan, store: MemStore, ex: &mut SimExecutor, orig: &SimFs) {
    let (mut j, loaded) = Journal::reopen(store).unwrap();
    let o = orig.clone();
    recover(plan, &mut j, &loaded, ex, |e| is_old(&e.fs, &o)).unwrap();
    let (after, _, _) = parse(&j.store().text).unwrap();
    assert_eq!(after.events.last(), Some(&Event::RolledBack));
}

#[test]
fn happy_path_journals_every_mutation_before_running_it() {
    let fs = unit();
    let plan = plan_for(&fs);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(fs);
    apply(&plan, &mut j, &mut ex).unwrap();
    assert!(
        matches!(state(&ex.fs), InstallState::Verified { installed, .. } if installed.tag == "new")
    );
    let (l, _, _) = parse(&j.store().text).unwrap();
    assert!(!l.torn_tail);
    let n = mutation_count(&plan);
    let intents = l
        .events
        .iter()
        .filter(|e| matches!(e, Event::Intent { .. }))
        .count();
    let dones = l
        .events
        .iter()
        .filter(|e| matches!(e, Event::Done { .. }))
        .count();
    assert_eq!((intents, dones), (n, n));
    assert_eq!(l.events.last(), Some(&Event::Complete));
    // Ordering: each Done directly follows its own Intent.
    for w in l.events.windows(2) {
        if let Event::Done { index, .. } = &w[1] {
            assert!(matches!(&w[0], Event::Intent { index: i, .. } if i == index));
        }
    }
}

#[test]
fn no_mutation_ever_runs_without_a_durable_intent() {
    let base = unit();
    let plan = plan_for(&base);
    // Total appends in a clean run.
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
                assert_eq!(k, 0);
                assert_eq!(ex.executed, 0, "nothing runs without BEGIN");
                continue;
            };
            assert!(apply(&plan, &mut j, &mut ex).is_err(), "k={k}");
            let store = j.into_store();
            let (l, _, _) = parse(&store.text).unwrap();
            assert_eq!(l.torn_tail, torn, "k={k}");
            let intents = l
                .events
                .iter()
                .filter(|e| matches!(e, Event::Intent { .. }))
                .count();
            assert!(
                ex.executed <= intents,
                "k={k} torn={torn}: {} mutations ran, {intents} intents recorded",
                ex.executed
            );
            assert_eq!(untouchable(&ex.fs), untouchable(&base), "k={k}");
            recover_from(&plan, store, &mut ex, &base);
            assert!(is_old(&ex.fs, &base), "k={k} torn={torn}: not restored");
            assert_eq!(untouchable(&ex.fs), untouchable(&base));
        }
    }
}

#[test]
fn execution_failure_at_every_mutation_stops_and_recovers() {
    let base = unit();
    let plan = plan_for(&base);
    for k in 0..mutation_count(&plan) {
        let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
        let mut ex = executor(base.clone());
        ex.fail_at = Some(k);
        assert!(
            matches!(
                apply(&plan, &mut j, &mut ex),
                Err(ApplyError::Mutation { .. })
            ),
            "k={k}"
        );
        assert_eq!(ex.executed, k + 1, "stops at the failure");
        let store = j.into_store();
        let (l, _, _) = parse(&store.text).unwrap();
        assert!(
            matches!(l.events.last(), Some(Event::Failed { .. })),
            "k={k}"
        );
        let mut ex = executor(ex.fs);
        recover_from(&plan, store, &mut ex, &base);
        assert!(is_old(&ex.fs, &base), "k={k}");
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
    assert_eq!(active(&ex.fs), active(&unit()), "active files untouched");
}

#[test]
fn corruption_and_foreign_journals_are_refused() {
    let base = unit();
    let plan = plan_for(&base);
    let mut j = Journal::begin(MemStore::default(), &plan).unwrap();
    let mut ex = executor(base.clone());
    ex.fail_at = Some(12);
    let _ = apply(&plan, &mut j, &mut ex);
    let text = j.into_store().text;

    // Edited middle line.
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines[3].push('x');
    let edited = lines.join("\n") + "\n";
    assert!(matches!(
        parse(&edited),
        Err(JournalError::Corrupt { line: 4, .. })
    ));
    // Dropped middle line.
    let mut l2: Vec<&str> = text.lines().collect();
    l2.remove(2);
    assert!(matches!(
        parse(&(l2.join("\n") + "\n")),
        Err(JournalError::Corrupt { .. })
    ));
    // A journal from another plan (different op id) is not recovered.
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
    let (mut jj, loaded) = Journal::reopen(MemStore {
        text: text.clone(),
        ..MemStore::default()
    })
    .unwrap();
    assert!(matches!(
        recover(&other, &mut jj, &loaded, &mut ex, |_| true),
        Err(ApplyError::WrongPlan)
    ));
    // A new operation never starts over an existing journal.
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
    // Someone deleted the operation backup meanwhile.
    let old = format!("{}/{OP}/old/nbt-aad", crate::plan::ops_root(&PILOT_G31));
    ex.fs.nodes.remove(&old);
    let (mut j2, loaded) = Journal::reopen(j.into_store()).unwrap();
    let o = base.clone();
    let e = recover(&plan, &mut j2, &loaded, &mut ex, |e| is_old(&e.fs, &o)).unwrap_err();
    assert!(matches!(e, ApplyError::Verification { .. }), "{e}");
    let (l, _, _) = parse(&j2.store().text).unwrap();
    assert!(!l.events.contains(&Event::RolledBack));
}
