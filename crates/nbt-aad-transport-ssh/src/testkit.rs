//! In-process fake head-unit SSH server for tests (feature `testkit`).
//!
//! Real SSH protocol (russh server) in front of the core's read-only
//! [`FakeHu`] interpreter, with fault injection. Never part of a release build.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nbt_aad_core::testkit::FakeHu;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, Preferred};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub enum AuthMode {
    Password(&'static str),
    /// Keyboard-interactive with `prompts` hidden prompts labelled `text`;
    /// only the first answer is checked.
    KeyboardInteractive {
        password: &'static str,
        prompts: usize,
        text: &'static str,
    },
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub host_key: Algorithm,
    /// Restrict the server's algorithms (to emulate old OpenSSH builds).
    pub preferred: Option<Preferred>,
    pub auth: AuthMode,
    /// Disconnect the whole session when the N-th exec arrives (1-based).
    pub drop_at_exec: Option<usize>,
    /// Accept but never answer commands containing this text.
    pub hang_on: Option<String>,
    /// Refuse exec for commands containing this text.
    pub reject_on: Option<String>,
    /// Send this many extra stdout bytes for `cat /opt/aa/nbt-aad`.
    pub extra_output: usize,
    /// Answer every DH group-exchange request with the 2048-bit group14
    /// prime, regardless of the requested range — what OpenSSH 5.x does
    /// without a usable moduli file (observed on a real NBT EVO, 2026-11-09).
    pub gex_always_group14: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            host_key: Algorithm::Ed25519,
            preferred: None,
            auth: AuthMode::Password("test-password"),
            drop_at_exec: None,
            hang_on: None,
            reject_on: None,
            extra_output: 0,
            gex_always_group14: false,
        }
    }
}

pub struct FakeServer {
    pub addr: SocketAddr,
    pub host_key: PublicKey,
    pub hu: Arc<Mutex<FakeHu>>,
    /// Every exec request received, in order.
    pub received: Arc<Mutex<Vec<String>>>,
    pub sessions: Arc<AtomicUsize>,
}

pub fn generate_key(alg: Algorithm) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), alg).expect("key generation")
}

/// Start a fake server on 127.0.0.1 with a fresh host key.
pub async fn start(opts: ServerOptions, hu: FakeHu) -> FakeServer {
    start_with_key(opts, hu, None).await
}

pub async fn start_with_key(
    opts: ServerOptions,
    hu: FakeHu,
    key: Option<PrivateKey>,
) -> FakeServer {
    let key = key.unwrap_or_else(|| generate_key(opts.host_key.clone()));
    let host_key = key.public_key().clone();
    let mut cfg = server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::KeyboardInteractive][..]),
        ..server::Config::default()
    };
    if let Some(p) = opts.preferred.clone() {
        cfg.preferred = p;
    }
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hu = Arc::new(Mutex::new(hu));
    let received = Arc::new(Mutex::new(Vec::new()));
    let sessions = Arc::new(AtomicUsize::new(0));
    let opts = Arc::new(opts);
    {
        let (hu, received, sessions) = (hu.clone(), received.clone(), sessions.clone());
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                sessions.fetch_add(1, Ordering::SeqCst);
                let h = Handler {
                    hu: hu.clone(),
                    opts: opts.clone(),
                    received: received.clone(),
                };
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(cfg, sock, h).await {
                        let _ = s.await;
                    }
                });
            }
        });
    }
    FakeServer {
        addr,
        host_key,
        hu,
        received,
        sessions,
    }
}

struct Handler {
    hu: Arc<Mutex<FakeHu>>,
    opts: Arc<ServerOptions>,
    received: Arc<Mutex<Vec<String>>>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn lookup_dh_gex_group(
        &mut self,
        gex_params: &russh::client::GexParams,
    ) -> Result<Option<russh::kex::dh::groups::DhGroup>, Self::Error> {
        if self.opts.gex_always_group14 {
            return Ok(Some(russh::kex::dh::groups::DH_GROUP14.clone()));
        }
        // Default russh behaviour: a built-in group within the requested range.
        let best = [
            &russh::kex::dh::groups::DH_GROUP14,
            &russh::kex::dh::groups::DH_GROUP16,
        ]
        .into_iter()
        .rev()
        .find(|g| {
            g.bit_size() >= gex_params.min_group_size()
                && g.bit_size() <= gex_params.max_group_size()
        })
        .cloned();
        Ok(best)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        let m = match self.opts.auth {
            AuthMode::Password(_) => MethodKind::Password,
            AuthMode::KeyboardInteractive { .. } => MethodKind::KeyboardInteractive,
        };
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[m][..])),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(match self.opts.auth {
            AuthMode::Password(p) if user == "root" && password == p => Auth::Accept,
            _ => Auth::reject(),
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let AuthMode::KeyboardInteractive {
            password,
            prompts,
            text,
        } = self.opts.auth
        else {
            return Ok(Auth::reject());
        };
        match response {
            None => {
                let p: Vec<(Cow<'static, str>, bool)> = (0..prompts)
                    .map(|i| (Cow::Owned(format!("{text} {i}: ")), false))
                    .collect();
                Ok(Auth::Partial {
                    name: "".into(),
                    instructions: "".into(),
                    prompts: p.into(),
                })
            }
            Some(mut r) => {
                let first = r.next().map(|b| b.to_vec()).unwrap_or_default();
                Ok(if user == "root" && first == password.as_bytes() {
                    Auth::Accept
                } else {
                    Auth::reject()
                })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let n = {
            let mut r = self.received.lock().unwrap();
            r.push(cmd.clone());
            r.len()
        };
        if self.opts.drop_at_exec.is_some_and(|d| n >= d) {
            session.disconnect(Disconnect::ByApplication, "fake link down", "en")?;
            return Ok(());
        }
        if self
            .opts
            .reject_on
            .as_deref()
            .is_some_and(|r| cmd.contains(r))
        {
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        if self
            .opts
            .hang_on
            .as_deref()
            .is_some_and(|h| cmd.contains(h))
        {
            return Ok(());
        }
        let (mut out, err, rc) = self.hu.lock().unwrap().run(&cmd);
        if cmd.ends_with("cat /opt/aa/nbt-aad") && self.opts.extra_output > 0 {
            out.extend(std::iter::repeat_n(b'x', self.opts.extra_output));
        }
        for chunk in out.chunks(16 * 1024) {
            session.data(channel, chunk.to_vec())?;
        }
        if !err.is_empty() {
            session.extended_data(channel, 1, err)?;
        }
        session.exit_status_request(channel, rc)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
