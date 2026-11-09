//! Transport + probe tests over the real SSH protocol against an in-process
//! fake head unit. Runs on Linux and Windows CI; no network beyond loopback.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use nbt_aad_core::guard::{Context, GuardedCommand, NodePath};
use nbt_aad_core::kexinit::{self, AlgorithmProfile};
use nbt_aad_core::probe::{self, ProbeConfig, ProbeError};
use nbt_aad_core::testkit::{FakeHu, MemSink, Usb};
use nbt_aad_core::transport::{
    ExecLimits, ExitOutcome, HeadUnitTransport, Recorder, TransportError, sha256_hex,
};
use nbt_aad_transport_ssh::testkit::{self, AuthMode, FakeServer, ServerOptions};
use nbt_aad_transport_ssh::{self as ssh, HostKey, SshError, SshOptions};
use russh::Preferred;
use russh::keys::{Algorithm, HashAlg};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

async fn tcp(s: &FakeServer) -> TcpStream {
    TcpStream::connect(s.addr).await.unwrap()
}

async fn login(s: &FakeServer, opts: &SshOptions) -> Result<ssh::SshTransport, SshError> {
    let key = ssh::fetch_host_key(tcp(s).await, opts).await?;
    ssh::connect(tcp(s).await, opts, key, "root", &pw("test-password")).await
}

fn hu_cmd(body: &str) -> GuardedCommand {
    GuardedCommand::new(Context::Node(NodePath::default()), body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_probe_over_ssh_records_everything_and_mutates_nothing() {
    let hu = FakeHu::new();
    let before = hu.snapshot();
    let server = testkit::start(ServerOptions::default(), hu).await;
    let opts = SshOptions::default();

    let algs = ssh::capture_server_algorithms(tcp(&server).await, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(algs.banner.starts_with("SSH-2.0-"));
    assert!(kexinit::negotiable(&kexinit::negotiate(
        &opts.profile,
        &algs
    )));

    let key = ssh::fetch_host_key(tcp(&server).await, &opts)
        .await
        .unwrap();
    assert!(key.same_key(&server.host_key));
    assert!(
        server.received.lock().unwrap().is_empty(),
        "no exec before authentication"
    );

    let t = ssh::connect(tcp(&server).await, &opts, key, "root", &pw("test-password"))
        .await
        .unwrap();
    let mut rec = Recorder::new(t, MemSink::default());
    let summary = probe::run(&mut rec, &ProbeConfig::default(), &mut Usb(None))
        .await
        .unwrap();
    let (t, sink) = rec.into_parts();
    t.close().await;

    let received = server.received.lock().unwrap().clone();
    assert_eq!(sink.records.len(), received.len());
    assert_eq!(summary.executed as usize, received.len());
    for (r, sent) in sink.records.iter().zip(&received) {
        assert_eq!(&r.0.command, sent, "transcript order = wire order");
    }
    assert_eq!(server.hu.lock().unwrap().snapshot(), before);
    let daemon = match &server.hu.lock().unwrap().fs["/opt/aa/nbt-aad"] {
        nbt_aad_core::testkit::Node::File(b) => sha256_hex(b),
        _ => unreachable!(),
    };
    assert_eq!(sink.files["readback.tsv"].matches(&daemon).count(), 3);
    let get = |id: &str| sink.records.iter().find(|r| r.0.id == id).unwrap();
    assert_eq!(get("hu-rc-sh7").0.outcome, Some(ExitOutcome::Code(7)));
    assert_eq!(get("hu-split-streams").2, b"to-stderr\n");
    assert_eq!(get("hu-split-streams").1, b"to-stdout\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn host_key_mismatch_refuses_before_authentication() {
    let server = testkit::start(ServerOptions::default(), FakeHu::new()).await;
    let other = HostKey(
        testkit::generate_key(Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let r = ssh::connect(
        tcp(&server).await,
        &SshOptions::default(),
        other,
        "root",
        &pw("test-password"),
    )
    .await;
    assert!(matches!(r, Err(SshError::HostKeyMismatch)), "{:?}", r.err());
    assert!(server.received.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_fails_without_exec() {
    let server = testkit::start(ServerOptions::default(), FakeHu::new()).await;
    let opts = SshOptions::default();
    let key = ssh::fetch_host_key(tcp(&server).await, &opts)
        .await
        .unwrap();
    let r = ssh::connect(tcp(&server).await, &opts, key, "root", &pw("nope")).await;
    assert!(matches!(r, Err(SshError::AuthFailed(_))), "{:?}", r.err());
    assert!(server.received.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_single_hidden_prompt_only() {
    let opts = SshOptions::default();
    let ok = ServerOptions {
        auth: AuthMode::KeyboardInteractive {
            password: "test-password",
            prompts: 1,
            text: "Password",
        },
        ..ServerOptions::default()
    };
    let server = testkit::start(ok, FakeHu::new()).await;
    login(&server, &opts).await.unwrap().close().await;

    let two = ServerOptions {
        auth: AuthMode::KeyboardInteractive {
            password: "test-password",
            prompts: 2,
            text: "Password",
        },
        ..ServerOptions::default()
    };
    let server = testkit::start(two, FakeHu::new()).await;
    let r = login(&server, &opts).await;
    assert!(
        matches!(r, Err(SshError::AuthFailed(ref m)) if m.contains("not answering")),
        "{:?}",
        r.err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hung_command_times_out_and_session_stays_usable() {
    let server = testkit::start(
        ServerOptions {
            hang_on: Some("pidin".into()),
            ..ServerOptions::default()
        },
        FakeHu::new(),
    )
    .await;
    let mut t = login(&server, &SshOptions::default()).await.unwrap();
    let limits = ExecLimits {
        timeout: Duration::from_millis(500),
        ..ExecLimits::default()
    };
    let r = t.exec(&hu_cmd("pidin"), limits).await.unwrap();
    assert_eq!(r.outcome, ExitOutcome::TimedOut);
    let r = t
        .exec(&hu_cmd("echo probe-ok"), ExecLimits::default())
        .await
        .unwrap();
    assert_eq!(r.stdout, b"probe-ok\n");
    assert_eq!(r.outcome, ExitOutcome::Code(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_exec_is_reported_and_session_stays_usable() {
    let server = testkit::start(
        ServerOptions {
            reject_on: Some("uname".into()),
            ..ServerOptions::default()
        },
        FakeHu::new(),
    )
    .await;
    let mut t = login(&server, &SshOptions::default()).await.unwrap();
    let r = t.exec(&hu_cmd("uname -a"), ExecLimits::default()).await;
    assert!(matches!(r, Err(TransportError::Rejected(_))), "{r:?}");
    assert!(
        t.exec(&hu_cmd("true"), ExecLimits::default())
            .await
            .unwrap()
            .outcome
            .is_success()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_loss_stops_probe_and_is_recorded() {
    let server = testkit::start(
        ServerOptions {
            drop_at_exec: Some(5),
            ..ServerOptions::default()
        },
        FakeHu::new(),
    )
    .await;
    let t = login(&server, &SshOptions::default()).await.unwrap();
    let mut rec = Recorder::new(t, MemSink::default());
    let r = probe::run(&mut rec, &ProbeConfig::default(), &mut Usb(None)).await;
    assert!(matches!(r, Err(ProbeError::ConnectionLost { .. })), "{r:?}");
    let (_t, sink) = rec.into_parts();
    let received = server.received.lock().unwrap().len();
    assert_eq!(received, 5, "nothing sent after the link dropped");
    assert_eq!(sink.records.len(), 5);
    assert!(sink.records[4].0.transport_error.is_some());
    assert_eq!(
        server.sessions.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "no reconnect (key fetch + login only)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn output_cap_counts_dropped_bytes() {
    let server = testkit::start(
        ServerOptions {
            extra_output: 300_000,
            ..ServerOptions::default()
        },
        FakeHu::new(),
    )
    .await;
    let mut t = login(&server, &SshOptions::default()).await.unwrap();
    let limits = ExecLimits {
        max_output: 100_000,
        ..ExecLimits::default()
    };
    let r = t
        .exec(&hu_cmd("cat /opt/aa/nbt-aad"), limits)
        .await
        .unwrap();
    assert_eq!(r.stdout.len(), 100_000);
    assert!(r.stdout_dropped > 200_000);
    assert_eq!(r.outcome, ExitOutcome::Code(0));
}

fn restricted(
    kex: &[russh::kex::Name],
    key: Algorithm,
    cipher: &[russh::cipher::Name],
    mac: &[russh::mac::Name],
) -> Preferred {
    Preferred {
        kex: kex.to_vec().into(),
        key: vec![key].into(),
        cipher: cipher.to_vec().into(),
        mac: mac.to_vec().into(),
        compression: (&[russh::compression::NONE][..]).into(),
        host_key_certificates: (&[][..]).into(),
    }
}

/// An OpenSSH-like server limited to what upstream's update guide enables on
/// top of modern defaults: ssh-rsa (SHA-1) host key and hmac-sha1.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_documented_legacy_server_works_with_default_profile() {
    let rsa = Algorithm::Rsa { hash: None };
    let opts_srv = ServerOptions {
        host_key: rsa.clone(),
        preferred: Some(restricted(
            &[russh::kex::DH_G14_SHA256],
            rsa,
            &[russh::cipher::AES_128_CTR],
            &[russh::mac::HMAC_SHA1],
        )),
        ..ServerOptions::default()
    };
    let server = testkit::start(opts_srv, FakeHu::new()).await;
    let opts = SshOptions::default();
    let algs = ssh::capture_server_algorithms(tcp(&server).await, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(algs.host_key, vec!["ssh-rsa"]);
    assert_eq!(algs.mac_ctos, vec!["hmac-sha1"]);
    let choices = kexinit::negotiate(&opts.profile, &algs);
    assert!(kexinit::negotiable(&choices));
    assert!(choices.iter().all(|c| c.chosen.is_some()));

    let key = ssh::fetch_host_key(tcp(&server).await, &opts)
        .await
        .unwrap();
    assert_eq!(key.algorithm(), "ssh-rsa");
    assert!(key.fingerprint().starts_with("SHA256:"));
    let mut t = ssh::connect(tcp(&server).await, &opts, key, "root", &pw("test-password"))
        .await
        .unwrap();
    assert_eq!(
        t.exec(&hu_cmd("echo probe-ok"), ExecLimits::default())
            .await
            .unwrap()
            .stdout,
        b"probe-ok\n"
    );
}

/// CBC/3DES-only server: refused by the default profile, works only with the
/// explicit legacy-weak opt-in — and the KEXINIT prediction agrees.
#[tokio::test(flavor = "multi_thread")]
async fn cbc_only_server_requires_legacy_weak_opt_in() {
    let opts_srv = ServerOptions {
        preferred: Some(restricted(
            &[russh::kex::DH_G14_SHA1],
            Algorithm::Ed25519,
            &[russh::cipher::TRIPLE_DES_CBC],
            &[russh::mac::HMAC_SHA1],
        )),
        ..ServerOptions::default()
    };
    let server = testkit::start(opts_srv, FakeHu::new()).await;
    let algs = ssh::capture_server_algorithms(tcp(&server).await, Duration::from_secs(5))
        .await
        .unwrap();
    let default = SshOptions::default();
    let weak = SshOptions {
        profile: AlgorithmProfile::legacy_weak(),
        ..SshOptions::default()
    };
    assert!(!kexinit::negotiable(&kexinit::negotiate(
        &default.profile,
        &algs
    )));
    assert!(kexinit::negotiable(&kexinit::negotiate(
        &weak.profile,
        &algs
    )));
    assert!(login(&server, &default).await.is_err());
    let mut t = login(&server, &weak).await.unwrap();
    assert!(
        t.exec(&hu_cmd("true"), ExecLimits::default())
            .await
            .unwrap()
            .outcome
            .is_success()
    );
}

/// DSA-only host key (the `install.md` case): needs the legacy-weak opt-in.
#[tokio::test(flavor = "multi_thread")]
async fn dsa_only_server_requires_legacy_weak_opt_in() {
    let opts_srv = ServerOptions {
        host_key: Algorithm::Dsa,
        preferred: Some(restricted(
            &[russh::kex::DH_G14_SHA1],
            Algorithm::Dsa,
            &[russh::cipher::AES_128_CTR],
            &[russh::mac::HMAC_SHA1],
        )),
        ..ServerOptions::default()
    };
    let server = testkit::start(opts_srv, FakeHu::new()).await;
    let algs = ssh::capture_server_algorithms(tcp(&server).await, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(algs.host_key, vec!["ssh-dss"]);
    let default = SshOptions::default();
    let weak = SshOptions {
        profile: AlgorithmProfile::legacy_weak(),
        ..SshOptions::default()
    };
    assert!(!kexinit::negotiable(&kexinit::negotiate(
        &default.profile,
        &algs
    )));
    assert!(
        ssh::fetch_host_key(tcp(&server).await, &default)
            .await
            .is_err()
    );
    let key = ssh::fetch_host_key(tcp(&server).await, &weak)
        .await
        .unwrap();
    assert_eq!(key.algorithm(), "ssh-dss");
    let mut t = ssh::connect(tcp(&server).await, &weak, key, "root", &pw("test-password"))
        .await
        .unwrap();
    assert!(
        t.exec(&hu_cmd("true"), ExecLimits::default())
            .await
            .unwrap()
            .outcome
            .is_success()
    );
}

#[test]
fn host_key_openssh_roundtrip() {
    let k = HostKey(
        testkit::generate_key(Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let line = k.to_openssh().unwrap();
    assert!(line.starts_with("ssh-ed25519 "));
    let back = HostKey::from_openssh(&line).unwrap();
    assert!(back.same_key(&k.0));
    assert_eq!(
        k.fingerprint(),
        k.0.fingerprint(HashAlg::Sha256).to_string()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_prompt_is_never_answered() {
    let opts = ServerOptions {
        auth: AuthMode::KeyboardInteractive {
            password: "test-password",
            prompts: 1,
            text: "New password",
        },
        ..ServerOptions::default()
    };
    let server = testkit::start(opts, FakeHu::new()).await;
    let r = login(&server, &SshOptions::default()).await;
    assert!(
        matches!(r, Err(SshError::AuthFailed(ref m)) if m.contains("not answering")),
        "{:?}",
        r.err()
    );
    assert!(server.received.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn sha1_kex_only_server_requires_legacy_weak_opt_in() {
    let rsa = Algorithm::Rsa { hash: None };
    let opts_srv = ServerOptions {
        host_key: rsa.clone(),
        preferred: Some(restricted(
            &[russh::kex::DH_G14_SHA1],
            rsa,
            &[russh::cipher::AES_128_CTR],
            &[russh::mac::HMAC_SHA1],
        )),
        ..ServerOptions::default()
    };
    let server = testkit::start(opts_srv, FakeHu::new()).await;
    assert!(login(&server, &SshOptions::default()).await.is_err());
    let weak = SshOptions {
        profile: AlgorithmProfile::legacy_weak(),
        ..SshOptions::default()
    };
    assert!(login(&server, &weak).await.is_ok());
}
