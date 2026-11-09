//! E1 against the stateful fake head unit: full run across a restart, and
//! every precondition / failure path stopping before or at the right write.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::*;
use crate::inspect::tests::{BANNER, fake_profile, table, updated_unit};
use crate::testkit::{FakeHu, MemSink, Node};

const SIZE: usize = 4096;

fn file_data(i: usize) -> Vec<u8> {
    (0..SIZE).map(|k| (k * 31 + i * 7) as u8).collect()
}

fn files() -> E1Files {
    E1Files {
        sha256: [0, 1, 2].map(|i| sha256_hex(&file_data(i))),
        size: SIZE as u64,
    }
}

fn with_stick(mut hu: FakeHu, mount: &str) -> FakeHu {
    hu.fs.insert(mount.into(), Node::Dir);
    hu.fs.insert(format!("{mount}/{USB_DIR}"), Node::Dir);
    for (i, f) in FILES.iter().enumerate() {
        hu.fs
            .insert(format!("{mount}/{USB_DIR}/{f}"), Node::File(file_data(i)));
    }
    hu
}

fn unit() -> FakeHu {
    with_stick(updated_unit(), "/mnt/umass01200t12")
}

#[derive(Default)]
struct Op {
    force_stops: usize,
    slept: Vec<Duration>,
}

impl E1Operator for Op {
    async fn force_stop(&mut self) {
        self.force_stops += 1;
    }
    async fn sleep(&mut self, d: Duration) {
        self.slept.push(d);
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn consent() -> Consent {
    Consent::from_typed("SCRATCH-WRITES", CONSENT_WORD).unwrap()
}

fn run1(hu: FakeHu) -> (Result<Phase1, E1Error>, FakeHu, MemSink, Op) {
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let mut op = Op::default();
    let r = block_on(phase1(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
        &files(),
        &consent(),
        &mut op,
    ));
    let (hu, sink) = rec.into_parts();
    (r, hu, sink, op)
}

fn mutations(hu: &FakeHu) -> Vec<&String> {
    hu.seen
        .iter()
        .filter(|c| {
            ["mount -o", "mkdir ", "cp ", "chmod ", "mv "]
                .iter()
                .any(|m| c.contains(m))
        })
        .collect()
}

/// Everything except the scratch directory, byte for byte.
fn outside_scratch(hu: &FakeHu) -> Vec<(String, Vec<u8>)> {
    hu.snapshot()
        .into_iter()
        .filter(|(p, _)| !p.starts_with(SCRATCH))
        .collect()
}

#[test]
fn full_run_across_a_restart() {
    let hu = unit();
    let before = outside_scratch(&hu);
    let (r, mut hu, sink, op) = run1(hu);
    let p1 = r.unwrap();
    assert_eq!(p1.stopped, None, "{:#?}", p1.lines);
    assert!(p1.remounted);
    let text = p1.lines.join("\n");
    assert!(text.contains("E1a test -w /opt/aa: 0"), "{text}");
    assert!(text.contains("E1b test -w /opt/aa: 1"), "{text}");
    assert!(text.contains("E1c read-back f1 matches: true"), "{text}");
    assert!(
        text.contains(&format!("E1c read-back {SCRATCH}/d2/f2 matches: true")),
        "{text}"
    );
    assert!(
        text.contains("E1e read-back f3b before restart matches: true"),
        "{text}"
    );
    assert_eq!(op.force_stops, 1);
    assert_eq!(op.slept.len(), PIDIN_POLLS);
    assert_eq!(*op.slept.last().unwrap(), SETTLE_BEFORE_RESTART);
    // Every execution is recorded.
    assert_eq!(sink.records.len(), hu.seen.len());
    // Writes: only the profile remount (login) and scratch-only operations.
    for m in mutations(&hu) {
        let ok = m == "mount -o remount rw /net/hu-omap/fs/sda0"
            || m == "mount -o remount ro /net/hu-omap/fs/sda0"
            || {
                let w: Vec<&str> = m.split_whitespace().collect();
                w.len() >= 5
                    && w[..3] == ["on", "-f", "/net/hu-omap/"]
                    && w.last().unwrap().starts_with(SCRATCH)
            };
        assert!(ok, "unexpected mutation {m}");
    }
    assert_eq!(
        outside_scratch(&hu),
        before,
        "nothing outside the scratch dir changed"
    );

    // Operator restart, then a new session.
    hu.restart();
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let p2 = block_on(phase2(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
        &files(),
        &p1,
    ))
    .unwrap();
    assert_eq!(p2.f3_survived, Some(true));
    let t2 = p2.lines.join("\n");
    assert!(t2.contains("(1 = read-only again): 1"), "{t2}");
    assert!(t2.contains("install state unchanged by E1: true"), "{t2}");
    let (hu, _) = rec.into_parts();
    assert!(
        mutations(&hu).len() == mutations(&unit_after()).len(),
        "phase 2 is read-only"
    );
}

/// Mutation count of a phase-1 run (phase 2 must add none).
fn unit_after() -> FakeHu {
    run1(unit()).1
}

fn assert_no_writes(hu: &FakeHu) {
    assert!(mutations(hu).is_empty(), "{:?}", mutations(hu));
}

#[test]
fn profile_mismatch_stops_before_any_write() {
    let mut hu = unit();
    hu.fs.insert(
        "/opt/sys/etc/nbt_version.txt".into(),
        Node::File(b"OTHER\n".to_vec()),
    );
    let (r, hu, _, _) = run1(hu);
    assert!(matches!(r, Err(E1Error::Precondition(_))));
    assert_no_writes(&hu);
}

#[test]
fn existing_scratch_entry_of_any_kind_stops_before_any_write() {
    for node in [Node::Dir, Node::File(b"x".to_vec())] {
        let mut hu = unit();
        hu.fs.insert(SCRATCH.into(), node);
        let (r, hu, _, _) = run1(hu);
        assert!(matches!(r, Err(E1Error::Precondition(_))));
        assert_no_writes(&hu);
    }
}

#[test]
fn missing_wrong_or_ambiguous_stick_stops_before_any_write() {
    // No stick.
    let (r, hu, _, _) = run1(updated_unit());
    assert!(matches!(r, Err(E1Error::Precondition(_))));
    assert_no_writes(&hu);
    // Wrong content.
    let mut hu = unit();
    hu.fs.insert(
        format!("/mnt/umass01200t12/{USB_DIR}/f2"),
        Node::File(b"other".to_vec()),
    );
    let (r, hu, _, _) = run1(hu);
    assert!(matches!(r, Err(E1Error::Precondition(_))));
    assert_no_writes(&hu);
    // Two sticks with the files.
    let hu = with_stick(unit(), "/mnt/umass01201t4");
    let (r, hu, _, _) = run1(hu);
    assert!(matches!(r, Err(E1Error::Precondition(_))));
    assert_no_writes(&hu);
}

#[test]
fn a_failed_mutation_stops_the_run_at_that_step() {
    let mut hu = unit();
    hu.hang_on = Some("chmod 755".into());
    let (r, hu, _, op) = run1(hu);
    let p1 = r.unwrap();
    assert!(p1.stopped.as_deref().unwrap().contains("e1c-chmod-f1"));
    assert!(
        !hu.seen
            .iter()
            .any(|c| c.contains("mkdir") && c.ends_with("/d"))
    );
    assert!(!hu.seen.iter().any(|c| c.contains(" mv ")));
    assert_eq!(op.force_stops, 0, "no later steps");
}

#[test]
fn a_read_only_transport_cannot_be_made_to_write() {
    struct ReadOnly(FakeHu);
    impl HeadUnitTransport for ReadOnly {
        async fn exec(
            &mut self,
            c: &GuardedCommand,
            l: ExecLimits,
        ) -> Result<ExecResult, TransportError> {
            self.0.exec(c, l).await
        }
    }
    let p = fake_profile();
    let mut rec = Recorder::new(ReadOnly(unit()), MemSink::default());
    let p1 = block_on(phase1(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
        &files(),
        &consent(),
        &mut Op::default(),
    ))
    .unwrap();
    assert!(
        p1.stopped
            .as_deref()
            .unwrap()
            .contains("remount rw did not make /opt/aa writable"),
        "{:?}",
        p1.stopped
    );
    let (ro, sink) = rec.into_parts();
    assert!(
        !sink
            .records
            .iter()
            .any(|(r, _, _)| r.id.starts_with("e1c-mkdir")),
        "no scratch write is even attempted"
    );
    assert!(
        !ro.0
            .seen
            .iter()
            .any(|c| c.contains("mkdir") || c.contains("mount -o"))
    );
    // The refused attempts are still in the transcript.
    assert!(
        sink.records
            .iter()
            .any(|(r, _, _)| r.id == "e1a-remount-rw" && r.transport_error.is_some())
    );
}

#[test]
fn consent_must_be_the_exact_word() {
    assert!(Consent::from_typed("scratch-writes", CONSENT_WORD).is_none());
    assert!(Consent::from_typed("SCRATCH-WRITES ", CONSENT_WORD).is_some());
    assert!(Consent::from_typed("", CONSENT_WORD).is_none());
}

#[test]
fn connection_loss_mid_run_is_an_error_with_everything_recorded() {
    let mut hu = unit();
    hu.lose_after = Some(40);
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let e = block_on(phase1(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
        &files(),
        &consent(),
        &mut Op::default(),
    ))
    .unwrap_err();
    assert!(matches!(e, E1Error::ConnectionLost { .. }), "{e}");
    assert_eq!(rec.into_parts().1.records.len(), 41);
}

#[test]
fn consent_for_something_else_is_refused_before_any_command() {
    let p = fake_profile();
    let other = Consent::from_typed("OTHER", "OTHER").unwrap();
    let mut rec = Recorder::new(unit(), MemSink::default());
    let r = block_on(phase1(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
        &files(),
        &other,
        &mut Op::default(),
    ));
    assert!(matches!(r, Err(E1Error::Plan(_))));
    assert_eq!(rec.executed(), 0);
}
