//! End-to-end: the real `nbt-aad-manager` binary against an in-process fake
//! head-unit SSH server. Runs on Linux and Windows CI (loopback only).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nbt_aad_core::testkit::FakeHu;
use nbt_aad_transport_ssh::testkit::{self, FakeServer, ServerOptions};
use russh::keys::Algorithm;

struct Env {
    _rt: tokio::runtime::Runtime,
    server: FakeServer,
    dir: tempfile::TempDir,
}

fn env(opts: ServerOptions) -> Env {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(testkit::start(opts, FakeHu::new()));
    Env {
        _rt: rt,
        server,
        dir: tempfile::tempdir().unwrap(),
    }
}

fn run(e: &Env, extra: &[&str], stdin: &str) -> (i32, String, PathBuf) {
    let port = e.server.addr.port().to_string();
    let mut args = vec![
        "probe",
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--password-stdin",
        "--cmd-timeout",
        "5",
    ];
    args.extend_from_slice(extra);
    args.push("--out");
    let out = e.dir.path().to_str().unwrap().to_owned();
    args.push(&out);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nbt-aad-manager"))
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    let console = String::from_utf8_lossy(&o.stderr).into_owned();
    let probe_dir = std::fs::read_dir(e.dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|d| d.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("nbt-probe-")
        })
        .expect("probe dir");
    (o.status.code().unwrap_or(-1), console, probe_dir)
}

const ANSWERS: &str = "test-password\nPROBE\nno\ne2e test\nyes\n\n";

fn all_files(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            v.extend(all_files(&p))
        } else {
            v.push(p)
        }
    }
    v
}

fn contains(dir: &Path, needle: &[u8]) -> Option<PathBuf> {
    all_files(dir).into_iter().find(|p| {
        std::fs::read(p)
            .unwrap()
            .windows(needle.len())
            .any(|w| w == needle)
    })
}

#[test]
fn full_run_produces_bash_compatible_report_without_leaks() {
    let e = env(ServerOptions::default());
    let (code, console, dir) = run(&e, &[], ANSWERS);
    assert_eq!(code, 0, "{console}");
    let report = dir.join("report");
    let received = e.server.received.lock().unwrap().clone();
    let records: Vec<_> = std::fs::read_dir(report.join("exec")).unwrap().collect();
    assert_eq!(
        records.len(),
        received.len(),
        "one transcript record per remote exec"
    );
    let log = std::fs::read_to_string(report.join("exec-log.tsv")).unwrap();
    assert_eq!(log.lines().count(), received.len());
    for f in [
        "meta.txt",
        "ssh-kexinit.txt",
        "known_hosts",
        "ssh-hostkey-fingerprints.txt",
        "summary.txt",
        "readback.tsv",
        "log-versions.txt",
        "console.log",
        "text/opt-aa__nbt-aad.env",
    ] {
        assert!(report.join(f).is_file(), "missing {f}");
    }
    assert!(dir.join("report.tgz").is_file());
    assert!(dir.join("private/readback/opt-aa/nbt-aad").is_file());
    assert!(
        std::fs::read_to_string(report.join("meta.txt"))
            .unwrap()
            .contains("implementation=rust")
    );
    for secret in [
        &b"SuperSecretPass1"[..],
        b"WBAJA11010B123456",
        b"PhoneOwnerName",
        b"00-11-22-33-44-55",
        b"test-password",
    ] {
        assert_eq!(
            contains(&report, secret),
            None,
            "leak of {:?}",
            String::from_utf8_lossy(secret)
        );
    }
    assert_eq!(
        contains(&dir, b"test-password"),
        None,
        "password stored somewhere"
    );
    let env_txt = std::fs::read_to_string(report.join("text/opt-aa__nbt-aad.env")).unwrap();
    assert!(
        env_txt.contains("NBT_ALT_WIFI=CARPLAY") && env_txt.contains("NBT_WFD_PASS=<REDACTED>")
    );
    let rec = |id: &str| {
        std::fs::read_dir(report.join("exec"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|d| d.path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!("-{id}"))
            })
            .unwrap()
    };
    assert_eq!(
        std::fs::read_to_string(rec("hu-rc-sh7").join("rc"))
            .unwrap()
            .trim(),
        "7"
    );
    assert_eq!(
        std::fs::read_to_string(rec("hu-split-streams").join("stderr")).unwrap(),
        "to-stderr\n"
    );
}

#[test]
fn pinned_wrong_host_key_refuses_with_zero_commands() {
    let e = env(ServerOptions::default());
    let other = nbt_aad_transport_ssh::HostKey(
        testkit::generate_key(Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let line = other.to_openssh().unwrap();
    let (code, console, _dir) = run(&e, &["--host-key", &line], "test-password\nPROBE\nno\n\n");
    assert_eq!(code, 2, "{console}");
    assert!(console.contains("does NOT match"));
    assert!(e.server.received.lock().unwrap().is_empty());
}

#[test]
fn declined_fingerprint_sends_nothing() {
    let e = env(ServerOptions::default());
    let (code, _console, _dir) = run(&e, &[], "test-password\nPROBE\nno\n\nno\n");
    assert_eq!(code, 1);
    assert!(e.server.received.lock().unwrap().is_empty());
}

#[test]
fn connection_loss_exits_3_with_partial_report() {
    let e = env(ServerOptions {
        drop_at_exec: Some(30),
        ..ServerOptions::default()
    });
    let (code, console, dir) = run(&e, &[], ANSWERS);
    assert_eq!(code, 3, "{console}");
    assert!(dir.join("report.tgz").is_file());
    assert!(
        std::fs::read_to_string(dir.join("report/notes.txt"))
            .unwrap()
            .contains("connection lost")
    );
    assert_eq!(e.server.received.lock().unwrap().len(), 30);
}

#[test]
fn dsa_only_server_stops_before_login_and_suggests_opt_in() {
    let p = russh::Preferred {
        key: vec![Algorithm::Dsa].into(),
        ..Default::default()
    };
    let e = env(ServerOptions {
        host_key: Algorithm::Dsa,
        preferred: Some(p.clone()),
        ..ServerOptions::default()
    });
    let (code, console, dir) = run(&e, &[], ANSWERS);
    assert_eq!(code, 2, "{console}");
    assert!(console.contains("--allow-legacy-weak"));
    assert!(
        std::fs::read_to_string(dir.join("report/ssh-kexinit.txt"))
            .unwrap()
            .contains("host_key: ssh-dss")
    );
    assert_eq!(
        e.server.sessions.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the unauthenticated greeting"
    );

    let e = env(ServerOptions {
        host_key: Algorithm::Dsa,
        preferred: Some(p),
        ..ServerOptions::default()
    });
    let (code, console, dir) = run(&e, &["--allow-legacy-weak"], ANSWERS);
    assert_eq!(code, 0, "{console}");
    assert!(
        std::fs::read_to_string(dir.join("report/meta.txt"))
            .unwrap()
            .contains("algorithm_profile=legacy-weak")
    );
    assert!(console.contains("WARNING: --allow-legacy-weak"));
}

#[test]
fn print_commands_lists_only_guarded_plan() {
    let o = Command::new(env!("CARGO_BIN_EXE_nbt-aad-manager"))
        .args(["probe", "--print-commands"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.lines().count() > 150);
    assert!(
        s.contains("on -f /net/hu-omap/ cat /opt/aa/nbt-aad") || s.contains("hu-digest-sha256sum")
    );
}

/// The Rust and bash probes must send the identical static plan, so their
/// transcripts stay interchangeable as fixtures.
#[cfg(unix)]
#[test]
fn static_plan_matches_bash_probe() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/probe/nbt-probe.sh");
    let static_lines = |out: &[u8]| -> Vec<String> {
        String::from_utf8_lossy(out)
            .lines()
            .take_while(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let bash = Command::new("bash")
        .arg(&script)
        .arg("--print-commands")
        .output()
        .unwrap();
    assert!(bash.status.success());
    let rust = Command::new(env!("CARGO_BIN_EXE_nbt-aad-manager"))
        .args(["probe", "--print-commands"])
        .output()
        .unwrap();
    let (b, r) = (static_lines(&bash.stdout), static_lines(&rust.stdout));
    assert!(b.len() > 150);
    for (i, (x, y)) in b.iter().zip(&r).enumerate() {
        assert_eq!(x, y, "line {i} differs");
    }
    assert_eq!(b.len(), r.len());
}

/// Regression (review finding): a password on stdin must never end up in
/// console.log or anywhere else, even if the prompt answers are missing.
#[test]
fn password_stdin_never_lands_in_output_even_when_answers_are_missing() {
    let e = env(ServerOptions::default());
    let (code, _console, dir) = run(&e, &[], "test-password\n");
    assert_eq!(code, 1, "cancelled at the PROBE prompt");
    assert_eq!(contains(&dir, b"test-password"), None);
    assert!(e.server.received.lock().unwrap().is_empty());
}

#[test]
fn cmd_timeout_is_bounded() {
    let o = Command::new(env!("CARGO_BIN_EXE_nbt-aad-manager"))
        .args([
            "probe",
            "--host",
            "127.0.0.1",
            "--cmd-timeout",
            "18446744073709551615",
        ])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("cmd-timeout"));
}
