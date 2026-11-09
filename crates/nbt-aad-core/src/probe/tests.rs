//! Probe tests against an in-memory, read-only fake head unit.

use super::*;
use crate::testkit::{FakeHu, MemSink, Node, Usb};
use crate::transport::ExitOutcome;

fn run_with(
    hu: FakeHu,
    sink: MemSink,
    usb: Option<String>,
) -> (Result<ProbeSummary, ProbeError>, FakeHu, MemSink) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut rec = Recorder::new(hu, sink);
    let res = rt.block_on(run(&mut rec, &ProbeConfig::default(), &mut Usb(usb)));
    let (hu, sink) = rec.into_parts();
    (res, hu, sink)
}

fn report_text(sink: &MemSink) -> String {
    let mut s: String = sink.files.values().cloned().collect();
    for v in sink.texts.values() {
        s.push_str(v);
    }
    s
}

#[test]
fn static_plan_is_fully_guarded_and_unique() {
    let plan = guarded_plan(&NodePath::default()).unwrap();
    assert!(plan.len() > 150);
    let ids: BTreeSet<_> = plan.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(ids.len(), plan.len(), "duplicate probe IDs");
}

#[test]
fn full_run_records_every_exec_and_never_mutates() {
    let hu = FakeHu::new();
    let before = hu.snapshot();
    let (res, hu, sink) = run_with(hu, MemSink::default(), None);
    let summary = res.unwrap();
    assert_eq!(hu.snapshot(), before, "fake device changed");
    assert_eq!(sink.records.len(), hu.seen.len(), "every exec has a record");
    assert_eq!(summary.executed as usize, hu.seen.len());
    let seqs: Vec<u32> = sink.records.iter().map(|r| r.0.seq).collect();
    assert_eq!(seqs, (1..=seqs.len() as u32).collect::<Vec<_>>());
    for (cmd, (rec, ..)) in hu.seen.iter().zip(&sink.records) {
        assert_eq!(cmd, &rec.command, "transcript order matches device order");
        assert!(crate::guard::check(cmd, &NodePath::default()).is_ok());
    }
    assert!(summary.hu_context_works);
}

#[test]
fn readback_hashes_versions_and_skips() {
    let (res, _hu, sink) = run_with(FakeHu::new(), MemSink::default(), None);
    res.unwrap();
    let tsv = &sink.files["readback.tsv"];
    let bytes: &[u8] = b"\x7fELF\x00\x00  Build: v1.9.36-combo (Nov 8)\x00";
    let daemon = sha256_hex(bytes);
    assert!(
        tsv.contains(&format!(
            "/opt/aa/nbt-aad\t0\t{}\t{daemon}\tBuild: v1.9.36-combo",
            bytes.len()
        )),
        "{tsv}"
    );
    assert_eq!(tsv.matches(&daemon).count(), 3, "two repeat readbacks");
    assert!(tsv.contains("rhmiapp-43-combo"));
    let notes = &sink.files["readback-notes.txt"];
    assert!(notes.contains("SKIP unsafe file name"));
    assert!(!notes.contains("bad;name"));
    assert!(notes.contains("symlink") && notes.contains("link-to-xml"));
    assert!(notes.contains("SKIP credential path"), "{notes}");
}

#[test]
fn report_has_no_secrets_and_text_copies_are_allowlisted() {
    let (res, hu, sink) = run_with(FakeHu::new(), MemSink::default(), None);
    res.unwrap();
    let report = report_text(&sink);
    for leak in [
        "SuperSecretPass1",
        "WBAJA11010B123456",
        "00-11-22-33-44-55",
        "PhoneOwnerName",
        "wifi=secret",
    ] {
        assert!(!report.contains(leak), "leaked {leak}");
    }
    assert!(sink.texts["opt-aa__nbt-aad.env"].contains("NBT_ALT_WIFI=CARPLAY"));
    assert!(sink.texts["opt-aa__nbt-aad.env"].contains("NBT_WFD_PASS=<REDACTED>"));
    assert!(sink.texts.contains_key("var-opt-aa__bootguard"));
    assert!(!sink.texts.contains_key("var-opt-aa__spp-model"));
    assert!(!hu.seen.iter().any(|c| c.contains("iap2")));
    let logs = &sink.files["log-versions.txt"];
    assert!(logs.contains("Build: v1.9.36-combo") && !logs.contains("phone"));
    // Secret policy: raw log bytes are handed to the sink only as digest input.
    let log_rec = sink
        .records
        .iter()
        .find(|r| r.0.id == "log-nbt-aad.log")
        .unwrap();
    assert_eq!(log_rec.0.policy, Policy::Secret);
}

#[test]
fn exit_status_and_streams_are_captured() {
    let (res, _hu, sink) = run_with(FakeHu::new(), MemSink::default(), None);
    res.unwrap();
    let get = |id: &str| sink.records.iter().find(|r| r.0.id == id).unwrap();
    assert_eq!(get("hu-rc-sh7").0.outcome, Some(ExitOutcome::Code(7)));
    let split = get("hu-split-streams");
    assert_eq!(split.0.outcome, Some(ExitOutcome::Code(3)));
    assert_eq!(split.2, b"to-stderr\n");
    assert_eq!(get("hu-quoting").1, b"[a b]\n[c]\n[d'e]\n");
    assert_eq!(get("hu-digest-md5").0.outcome, Some(ExitOutcome::Code(127)));
}

#[test]
fn connection_loss_stops_immediately_without_reconnect() {
    let mut hu = FakeHu::new();
    hu.lose_after = Some(40);
    let (res, hu, sink) = run_with(hu, MemSink::default(), None);
    match res {
        Err(ProbeError::ConnectionLost { executed, .. }) => assert_eq!(executed, 41),
        other => panic!("expected ConnectionLost, got {other:?}"),
    }
    assert_eq!(hu.seen.len(), 40);
    assert_eq!(sink.records.len(), 41, "the failed attempt is recorded too");
    assert!(sink.records[40].0.transport_error.is_some());
}

#[test]
fn transcript_failure_stops_before_next_command() {
    let sink = MemSink {
        fail_at: Some(10),
        ..MemSink::default()
    };
    let (res, hu, sink) = run_with(FakeHu::new(), sink, None);
    assert!(matches!(res, Err(ProbeError::Sink(_))));
    assert_eq!(hu.seen.len(), 10, "no command after the unrecorded one");
    assert_eq!(sink.records.len(), 9);
}

#[test]
fn hung_command_is_recorded_as_timeout_and_run_continues() {
    let mut hu = FakeHu::new();
    hu.hang_on = Some("pidin -p nbt-aad arg".into());
    let (res, _hu, sink) = run_with(hu, MemSink::default(), None);
    res.unwrap();
    let r = sink
        .records
        .iter()
        .find(|r| r.0.id == "hu-pidin-arg")
        .unwrap();
    assert_eq!(r.0.outcome, Some(ExitOutcome::TimedOut));
    assert!(sink.files.contains_key("readback.tsv"));
}

#[test]
fn unexpected_ls_layout_is_never_guessed() {
    let mut hu = FakeHu::new();
    hu.eight_col_ls = true;
    let (res, _hu, sink) = run_with(hu, MemSink::default(), None);
    res.unwrap();
    assert!(sink.files["readback-notes.txt"].contains("UNPARSED ls line"));
    assert!(!sink.files["readback.tsv"].contains(PLUGIN_DIR));
}

#[test]
fn broken_on_skips_readbacks() {
    let mut hu = FakeHu::new();
    hu.on_broken = true;
    let (res, hu, sink) = run_with(hu, MemSink::default(), None);
    assert!(!res.unwrap().hu_context_works);
    assert!(!hu.seen.iter().any(|c| c.contains("cat /opt/aa/nbt-aad")));
    assert!(sink.files["notes.txt"].contains("did not work"));
}

#[test]
fn usb_step_checks_marker() {
    let mut hu = FakeHu::new();
    hu.fs.insert("/mnt/umass0".into(), Node::Dir);
    hu.fs.insert(
        format!("/mnt/umass0/{USB_MARKER_NAME}"),
        Node::File(b"marker\n".to_vec()),
    );
    let (res, _hu, sink) = run_with(hu, MemSink::default(), Some(sha256_hex(b"marker\n")));
    assert!(res.unwrap().usb_tested);
    assert!(
        sink.files["notes.txt"].contains("MATCH"),
        "{}",
        sink.files["notes.txt"]
    );
}

#[test]
fn ls_parser_is_strict() {
    let out = "total 3\n-rw-r--r-- 1 root root 12 Nov 8 12:00 a.txt\n-rw-r--r-- 1 root 12 Nov 8 12:00 b\nlrwxrwxrwx 1 root root 4 Nov 8 12:00 l -> x\ncrw------- 1 root root 1, 2 Nov 8 12:00 dev\ndrwxr-xr-x 2 root root 0 Nov 8 12:00 d\n";
    let e = parse_ls(out);
    assert_eq!(
        e[0],
        LsEntry::File {
            name: "a.txt".into(),
            size: Some(12)
        }
    );
    assert!(matches!(e[1], LsEntry::Unparsed { fields: 8, .. }));
    assert!(matches!(e[2], LsEntry::Symlink { .. }));
    assert!(matches!(e[3], LsEntry::Other { .. }));
    assert_eq!(e.len(), 4);
}

#[test]
fn embedded_versions_extracts_markers() {
    let v = embedded_versions(
        b"\x00\x01  Build: v1.9.36-combo (%s)\x00xx rhmiapp-43-combo\x00short\x00",
    );
    assert_eq!(v, vec!["Build: v1.9.36-combo", "rhmiapp-43-combo"]);
}
