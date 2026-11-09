#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::*;
use crate::profile::{
    Backup, Evidence, Fact, OpBackup, PILOT_G31, Remount, RunOn, WritableExpectation,
};
use crate::release::{FileDigest, KNOWN};
use crate::testkit::{FakeHu, MemSink, Node};
use crate::transport::ExecResult;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

// ---- replay of a real pilot run ----

/// Answers exactly the commands recorded in a fixture run; anything else is
/// a test failure. Records without stored stdout (binary read-backs) are
/// answered as rejected, so no digest can be fabricated.
/// stdout (None for binary records), stderr, exit status.
type Answer = (Option<Vec<u8>>, Vec<u8>, u32);

struct Replay {
    answers: BTreeMap<String, Answer>,
    unknown: Vec<String>,
}

impl Replay {
    fn load(run: &str) -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pilot-g31")
            .join(run)
            .join("exec");
        let mut answers = BTreeMap::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let cmd = std::fs::read_to_string(p.join("cmd")).unwrap();
            let rc: u32 = std::fs::read_to_string(p.join("rc"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let out = std::fs::read(p.join("stdout")).ok();
            let err = std::fs::read(p.join("stderr")).unwrap_or_default();
            answers
                .entry(cmd.trim_end_matches(['\r', '\n']).to_owned())
                .or_insert((out, err, rc));
        }
        Self {
            answers,
            unknown: Vec::new(),
        }
    }
}

impl HeadUnitTransport for Replay {
    async fn exec(
        &mut self,
        command: &GuardedCommand,
        _limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        match self.answers.get(command.as_str()) {
            Some((Some(out), err, rc)) => Ok(ExecResult {
                stdout: out.clone(),
                stderr: err.clone(),
                stdout_dropped: 0,
                stderr_dropped: 0,
                outcome: ExitOutcome::Code(*rc),
                started: SystemTime::now(),
                duration: Duration::from_millis(1),
            }),
            Some((None, _, _)) => Err(TransportError::Rejected(
                "binary record not replayable".into(),
            )),
            None => {
                self.unknown.push(command.as_str().to_owned());
                Err(TransportError::Rejected("not in fixture".into()))
            }
        }
    }
}

pub(crate) const BANNER: &str = "SSH-2.0-OpenSSH_5.2 QNX_Secure_Shell-20090621-hpn13v6";

#[test]
fn every_inspect_command_ran_verbatim_on_the_pilot_car() {
    for run in ["run4-20261109-aa-running-usb", "run5-20261109-aa-stopped"] {
        let mut rec = Recorder::new(Replay::load(run), MemSink::default());
        let r = block_on(run_inspect(
            &mut rec,
            &PILOT_G31,
            KNOWN,
            Some(BANNER.into()),
        ))
        .unwrap();
        let (replay, sink) = rec.into_parts();
        assert!(
            replay.unknown.is_empty(),
            "{run}: commands never sent to the car: {:?}",
            replay.unknown
        );
        assert_eq!(r.profile, Ok(()), "{run}");
        // Read-backs are not replayable from sanitized fixtures: no claim.
        assert_eq!(
            r.state,
            Some(InstallState::Unverified {
                candidate: Some("gps")
            }),
            "{run}"
        );
        assert_eq!(r.readbacks, 12, "{run}: daemon x2 + plugin x5 + backup x5");
        assert_eq!(
            sink.records.len() as u32,
            r.executed,
            "{run}: every exec recorded"
        );
    }
}

fn run_inspect<'a, T: HeadUnitTransport>(
    rec: &'a mut Recorder<T, MemSink>,
    p: &'a HeadUnitProfile,
    table: &'static [KnownRelease],
    banner: Option<String>,
) -> impl std::future::Future<Output = Result<InspectReport, InspectError>> + 'a {
    run(rec, p, table, &INSPECT_CFG, banner)
}

static INSPECT_CFG: std::sync::LazyLock<InspectConfig> =
    std::sync::LazyLock::new(InspectConfig::default);

#[test]
fn plan_is_a_subset_of_the_probe_plan_and_read_only() {
    let p = plan(&PILOT_G31).unwrap();
    assert_eq!(p.len(), plan_ids(&PILOT_G31).len());
    for (id, c) in &p {
        assert!(!c.as_str().contains("df -k "), "{id}");
        assert!(!c.as_str().contains(" df"), "{id}");
    }
}

// ---- full path against the stateful fake, synthetic profile and pins ----

const FAKE_UNAME: &str = "QNX hu-omap 6.5.0 fake armle";
const PD: &str = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";

pub(crate) fn fake_profile() -> HeadUnitProfile {
    let obs = Evidence::Observed(&["tests/fixtures/pilot-g31"]);
    HeadUnitProfile {
        id: "fake",
        firmware: Fact {
            value: "HU_SW=FAKE",
            evidence: obs,
        },
        login_uname: Fact {
            value: FAKE_UNAME,
            evidence: obs,
        },
        daemon_uname: Fact {
            value: FAKE_UNAME,
            evidence: obs,
        },
        writable: Fact {
            value: &[
                WritableExpectation {
                    path: "/opt/aa",
                    probe_id: "hu-test-w-opt-aa",
                    writable: false,
                },
                WritableExpectation {
                    path: PD,
                    probe_id: "hu-test-w-plugin",
                    writable: false,
                },
                WritableExpectation {
                    path: "/var/opt/aa",
                    probe_id: "hu-test-w-var-opt-aa",
                    writable: false,
                },
                WritableExpectation {
                    path: "/dev/shmem",
                    probe_id: "hu-test-w-dev-shmem",
                    writable: true,
                },
            ],
            evidence: obs,
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
            evidence: Evidence::Unknown,
        },
        ..PILOT_G31
    }
}

fn file(data: &[u8], name: &'static str) -> FileDigest {
    FileDigest {
        name,
        size: data.len() as u64,
        sha256: Box::leak(sha256_hex(data).into_boxed_str()),
    }
}

pub(crate) fn content(tag: &str, n: &str) -> Vec<u8> {
    format!("{tag} {n} payload\n").into_bytes()
}

fn pin(tag: &'static str) -> KnownRelease {
    KnownRelease {
        tag,
        title: tag,
        daemon_build: "Build: v0",
        plugin_marker: "rhmiapp-0",
        daemon: file(&content(tag, "nbt-aad"), "nbt-aad"),
        archive: file(b"zip", "Releases.zip"),
        plugin: PLUGIN_FILES.map(|n| file(&content(tag, n), n)),
    }
}

pub(crate) fn table() -> &'static [KnownRelease] {
    static T: std::sync::LazyLock<Vec<KnownRelease>> =
        std::sync::LazyLock::new(|| vec![pin("old"), pin("new")]);
    T.as_slice()
}

/// A fake unit in the "after update" state: `new` active, `old` as backup.
pub(crate) fn updated_unit() -> FakeHu {
    let mut hu = FakeHu::new();
    hu.fs.retain(|k, _| {
        !(k.starts_with(PD) && k != PD)
            && !k.starts_with("/opt/aa/NbtAad.old/")
            && k != "/opt/aa/nbt-aad"
            && k != "/opt/aa/nbt-aad.old"
    });
    let mut f = |p: String, b: Vec<u8>| {
        hu.fs.insert(p, Node::File(b));
    };
    f("/opt/aa/nbt-aad".into(), content("new", "nbt-aad"));
    f("/opt/aa/nbt-aad.old".into(), content("old", "nbt-aad"));
    for n in PLUGIN_FILES {
        f(format!("{PD}/{n}"), content("new", n));
        f(format!("/opt/aa/NbtAad.old/{n}"), content("old", n));
    }
    hu
}

fn inspect_fake(hu: FakeHu) -> (InspectReport, FakeHu) {
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let r = block_on(run(
        &mut rec,
        &p,
        table(),
        &InspectConfig::default(),
        Some(BANNER.into()),
    ))
    .unwrap();
    (r, rec.into_parts().0)
}

#[test]
fn updated_fake_unit_is_verified_with_backup_and_untouched() {
    let hu = updated_unit();
    let before = hu.snapshot();
    let (r, hu) = inspect_fake(hu);
    assert_eq!(r.profile, Ok(()));
    match r.state.unwrap() {
        InstallState::Verified { installed, backup } => {
            assert_eq!(installed.tag, "new");
            assert!(matches!(backup, Backup::Known(k) if k.tag == "old"));
        }
        s => panic!("{s:?}"),
    }
    assert_eq!(hu.snapshot(), before, "inspection must not change the unit");
}

#[test]
fn tampered_or_unreadable_files_never_verify() {
    // Same size, different content.
    let mut hu = updated_unit();
    let mut d = content("new", "libNbtAad.so");
    d[0] ^= 1;
    hu.fs.insert(format!("{PD}/libNbtAad.so"), Node::File(d));
    assert!(matches!(
        inspect_fake(hu).0.state,
        Some(InstallState::Unknown(_))
    ));

    // Truncated read-back (output cap) gives no digest: unverified.
    let mut hu = updated_unit();
    hu.fs
        .insert("/opt/aa/nbt-aad".into(), Node::File(vec![b'x'; 5000]));
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let cfg = InspectConfig {
        readback_limits: ExecLimits {
            max_output: 1000,
            ..ExecLimits::default()
        },
        ..InspectConfig::default()
    };
    let r = block_on(run(&mut rec, &p, table(), &cfg, Some(BANNER.into()))).unwrap();
    assert!(
        matches!(r.state, Some(InstallState::Unverified { .. })),
        "{:?}",
        r.state
    );
}

#[test]
fn profile_mismatch_means_no_state_claim() {
    let mut hu = updated_unit();
    hu.fs.insert(
        "/opt/sys/etc/nbt_version.txt".into(),
        Node::File(b"HU_SW=OTHER\n".to_vec()),
    );
    let (r, hu) = inspect_fake(hu);
    assert!(r.profile.is_err());
    assert_eq!(r.state, None);
    assert_eq!(r.readbacks, 0, "no read-backs on a non-matching unit");
    assert!(!hu.seen.iter().any(|c| c.contains("cat /opt/aa/")));
}

#[test]
fn broken_on_skips_read_backs() {
    let mut hu = updated_unit();
    hu.on_broken = true;
    let (r, hu) = inspect_fake(hu);
    assert_eq!(r.readbacks, 0);
    assert!(r.profile.is_err());
    assert!(
        !hu.seen
            .iter()
            .any(|c| c.contains("cat /opt/aa/") || c.contains("cat /opt/hmi/"))
    );
}

#[test]
fn connection_loss_is_an_error_after_recording() {
    let mut hu = updated_unit();
    hu.lose_after = Some(5);
    let p = fake_profile();
    let mut rec = Recorder::new(hu, MemSink::default());
    let e = block_on(run(&mut rec, &p, table(), &InspectConfig::default(), None)).unwrap_err();
    assert!(
        matches!(e, InspectError::ConnectionLost { executed: 6, .. }),
        "{e}"
    );
    assert_eq!(
        rec.into_parts().1.records.len(),
        6,
        "the failed attempt is recorded too"
    );
}

#[test]
fn only_allowlisted_names_are_read_back() {
    let mut hu = updated_unit();
    hu.fs.insert(
        "/opt/aa/nbt-aad.env".into(),
        Node::File(b"NBT_WFD_PASS=secret\n".to_vec()),
    );
    hu.fs
        .insert(format!("{PD}/extra.bin"), Node::File(b"x".to_vec()));
    let (r, hu) = inspect_fake(hu);
    let cats: Vec<_> = hu.seen.iter().filter(|c| c.contains(" cat ")).collect();
    assert!(
        cats.iter()
            .all(|c| !c.contains("nbt-aad.env") && !c.contains("extra.bin")),
        "{cats:?}"
    );
    // The extra plugin file still makes the state non-verified.
    assert!(matches!(r.state, Some(InstallState::MidUpdate(_))));
}

#[test]
fn verdicts_and_rendering() {
    let (r, _) = inspect_fake(updated_unit());
    assert_eq!(r.verdict(), Verdict::Verified);
    let text = r.render(&fake_profile());
    assert!(text.contains("profile match: YES"));
    assert!(text.contains("install state: VERIFIED new"));
    assert!(text.contains("backup: VERIFIED old"));
    assert!(text.contains("/opt/aa/nbt-aad.old"));
    assert!(!text.contains("payload"), "file contents never rendered");

    let mut hu = updated_unit();
    hu.fs.remove("/opt/aa/nbt-aad");
    let (r, _) = inspect_fake(hu);
    assert_eq!(r.verdict(), Verdict::NotVerified);
    assert!(r.render(&fake_profile()).contains("HALF-APPLIED"));

    let mut hu = updated_unit();
    hu.fs.insert(
        "/opt/sys/etc/nbt_version.txt".into(),
        Node::File(b"X\n".to_vec()),
    );
    let (r, _) = inspect_fake(hu);
    assert_eq!(r.verdict(), Verdict::ProfileMismatch);
    let t = r.render(&fake_profile());
    assert!(t.contains("profile match: NO") && !t.contains("install state"));
}

#[test]
fn truncated_text_output_is_not_an_observation() {
    let p = fake_profile();
    let mut rec = Recorder::new(updated_unit(), MemSink::default());
    let cfg = InspectConfig {
        text_limits: ExecLimits {
            max_output: 200,
            ..ExecLimits::default()
        },
        ..InspectConfig::default()
    };
    let r = block_on(run(&mut rec, &p, table(), &cfg, Some(BANNER.into()))).unwrap();
    // Listings exceed 200 bytes: dropped, never parsed as partial listings.
    assert!(!r.observation.records.contains_key(ids::LS_PLUGIN));
    assert!(!r.observation.records.contains_key(ids::LS_DAEMON_DIR));
    assert!(r.observation.records.contains_key(ids::FIRMWARE));
    assert_eq!(r.verdict(), Verdict::ProfileMismatch);
}

#[test]
fn failed_shell_sentinel_skips_read_backs_even_if_listings_work() {
    let mut hu = updated_unit();
    hu.hang_on = Some("echo probe-ok".into());
    let (r, hu) = inspect_fake(hu);
    assert!(
        r.observation.records[ids::LS_PLUGIN].rc == 0,
        "listings still work"
    );
    assert_eq!(r.readbacks, 0);
    assert!(!hu.seen.iter().any(|c| c.contains("cat /opt/aa/")));
    assert!(r.observation.digests.is_empty());
}

#[test]
fn profile_citing_unknown_probe_ids_is_refused() {
    let mut p = fake_profile();
    p.writable.value = &[WritableExpectation {
        path: "/opt/aa",
        probe_id: "hu-test-w-nonexistent",
        writable: false,
    }];
    assert!(matches!(plan(&p), Err(InspectError::Plan(_))));
    let mut rec = Recorder::new(updated_unit(), MemSink::default());
    assert!(block_on(run(&mut rec, &p, table(), &InspectConfig::default(), None)).is_err());
    assert_eq!(rec.executed(), 0, "nothing sent with an invalid plan");
}

/// Pre-update pilot runs (no backups yet): replay with real stderr gives
/// "absent" for NbtAad.old only because the unit said "No such file".
#[test]
fn replayed_absent_backup_uses_the_real_qnx_answer() {
    let mut rec = Recorder::new(Replay::load("run2-20261109-aa-stopped"), MemSink::default());
    let r = block_on(run_inspect(
        &mut rec,
        &PILOT_G31,
        KNOWN,
        Some(BANNER.into()),
    ))
    .unwrap();
    // Run 2 used probe v2: no `hu-sh-echo`/`test -w` records, so the
    // profile does not match and nothing is claimed or read back.
    assert!(r.profile.is_err());
    assert_eq!(r.readbacks, 0);
    let rec_old = &r.observation.records[ids::LS_PLUGIN_BACKUP];
    assert!(crate::profile::listing_says_absent(
        rec_old,
        PILOT_G31.plugin_backup_dir
    ));
}

// ---- operation backups (nbt-aad-ops) ----

const OPID: &str = "20261109T170000Z-abc123";

/// The updated unit plus one operation directory holding `old` as backup.
fn unit_with_op(complete: bool, drop_plugin_file: Option<&str>) -> FakeHu {
    let mut hu = updated_unit();
    let root = "/opt/aa/nbt-aad-ops";
    let op = format!("{root}/{OPID}");
    for d in [
        root.to_owned(),
        op.clone(),
        format!("{op}/old"),
        format!("{op}/old/NbtAad"),
        format!("{op}/new"),
    ] {
        hu.fs.insert(d, Node::Dir);
    }
    hu.fs.insert(
        format!("{op}/old/nbt-aad"),
        Node::File(content("old", "nbt-aad")),
    );
    for n in PLUGIN_FILES {
        if Some(n) != drop_plugin_file {
            hu.fs.insert(
                format!("{op}/old/NbtAad/{n}"),
                Node::File(content("old", n)),
            );
        }
    }
    if complete {
        hu.fs.insert(
            format!("{op}/COMPLETE"),
            Node::File(crate::plan::complete_marker(OPID).into_bytes()),
        );
    }
    hu
}

fn ops_of(r: &InspectReport) -> Vec<OpBackup> {
    r.ops.clone().expect("profile matched").expect("ops listed")
}

#[test]
fn completed_operation_backup_is_verified() {
    let (r, hu) = inspect_fake(unit_with_op(true, None));
    let ops = ops_of(&r);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].op_id, OPID);
    assert!(ops[0].complete);
    assert!(matches!(&ops[0].backup, Backup::Known(k) if k.tag == "old"));
    assert!(
        r.render(&fake_profile())
            .contains(&format!("{OPID}  complete=true  backup: VERIFIED old"))
    );
    // Read-only: the fake unit is unchanged.
    assert_eq!(hu.snapshot(), unit_with_op(true, None).snapshot());
}

#[test]
fn incomplete_or_unmarked_operations_are_not_verified() {
    let (r, _) = inspect_fake(unit_with_op(false, None));
    assert!(!ops_of(&r)[0].complete);
    let (r, _) = inspect_fake(unit_with_op(true, Some("NbtAad.xml")));
    assert!(matches!(ops_of(&r)[0].backup, Backup::NotIdentified(_)));
}

#[test]
fn foreign_names_under_the_ops_root_are_reported_not_read() {
    let mut hu = unit_with_op(true, None);
    hu.fs
        .insert("/opt/aa/nbt-aad-ops/manual-backup".into(), Node::Dir);
    hu.fs.insert(
        "/opt/aa/nbt-aad-ops/manual-backup/nbt-aad".into(),
        Node::File(b"x".to_vec()),
    );
    let (r, hu) = inspect_fake(hu);
    let ops = ops_of(&r);
    let foreign = ops.iter().find(|o| o.op_id == "manual-backup").unwrap();
    assert!(matches!(foreign.backup, Backup::NotIdentified(_)));
    assert!(!hu.seen.iter().any(|c| c.contains("manual-backup")));
}

#[test]
fn without_an_ops_root_nothing_extra_is_sent() {
    let (r, hu) = inspect_fake(updated_unit());
    assert_eq!(ops_of(&r), vec![]);
    assert!(!hu.seen.iter().any(|c| c.contains("nbt-aad-ops")));
    assert!(
        r.render(&fake_profile())
            .contains("operation backups: none")
    );
}

#[test]
fn profile_mismatch_means_no_ops_claim_and_no_ops_reads() {
    let mut hu = unit_with_op(true, None);
    hu.fs.insert(
        "/opt/sys/etc/nbt_version.txt".into(),
        Node::File(b"X\n".to_vec()),
    );
    let (r, hu) = inspect_fake(hu);
    assert_eq!(r.ops, None);
    assert!(!hu.seen.iter().any(|c| c.contains("nbt-aad-ops")));
}
