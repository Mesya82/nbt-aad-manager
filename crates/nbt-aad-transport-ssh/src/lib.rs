//! SSH implementation of [`HeadUnitTransport`] on top of `russh`.
//!
//! The caller supplies an already-connected byte stream (desktop: a TCP
//! socket; Android later: a socket bound to the Ethernet network). This crate
//! never resolves or dials hosts, never retries, never reconnects, and never
//! accepts an unpinned host key on an authenticated connection.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use nbt_aad_core::guard::{Consent, GuardedCommand, MutatingCommand};
use nbt_aad_core::kexinit::{self, AlgorithmProfile, Parse, ServerAlgorithms};
use nbt_aad_core::transport::{
    ExecLimits, ExecResult, ExitOutcome, HeadUnitTransport, TransportError,
};
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, MethodKind, Preferred};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

#[cfg(feature = "testkit")]
pub mod testkit;

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        match e {
            russh::Error::KexInit => SshError::KeyExchange,
            other => SshError::Ssh(other),
        }
    }
}

pub const CLIENT_ID: &str = "SSH-2.0-nbt-aad-manager";

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("server greeting: {0}")]
    Greeting(#[from] kexinit::KexInitError),
    #[error("algorithm {0:?} in profile is not supported by this build")]
    UnsupportedAlgorithm(String),
    #[error("server host key does not match the pinned key")]
    HostKeyMismatch,
    #[error("server did not present a plain host key")]
    NoHostKey,
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error(
        "key exchange failed: the server's reply did not match the negotiated algorithms or limits \
         (for diffie-hellman-group-exchange-*: DH prime outside the accepted size range)"
    )]
    KeyExchange,
    #[error("ssh: {0}")]
    Ssh(russh::Error),
}

#[derive(Clone, Debug)]
pub struct SshOptions {
    pub profile: AlgorithmProfile,
    /// Keepalive interval; the session is declared dead after
    /// `keepalive_max` unanswered keepalives.
    pub keepalive: Duration,
    pub keepalive_max: usize,
    pub handshake_timeout: Duration,
    /// Accepted DH group-exchange prime sizes (bits): (min, preferred, max).
    /// Minimum 2048 = OpenSSH's own client minimum (DH_GRP_MIN). russh's
    /// default minimum of 3072 rejects old servers such as the pilot head
    /// unit's OpenSSH 5.2, which always answers with the 2048-bit group14 prime.
    pub gex_bits: (usize, usize, usize),
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            profile: AlgorithmProfile::upstream_documented(),
            keepalive: Duration::from_secs(10),
            keepalive_max: 3,
            handshake_timeout: Duration::from_secs(20),
            gex_bits: (2048, 3072, 8192),
        }
    }
}

/// Map a core algorithm profile to a russh configuration. Fails if any name
/// is unknown to this build (tested for both shipped profiles).
pub fn russh_config(opts: &SshOptions) -> Result<client::Config, SshError> {
    let unsupported = |n: &str| SshError::UnsupportedAlgorithm(n.to_owned());
    let mut kex = Vec::new();
    for n in &opts.profile.kex {
        kex.push(russh::kex::Name::try_from(*n).map_err(|_| unsupported(n))?);
    }
    // Protocol extensions (not algorithms): ext-info and strict KEX (Terrapin).
    kex.push(russh::kex::EXTENSION_SUPPORT_AS_CLIENT);
    kex.push(russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT);
    let mut key = Vec::new();
    for n in &opts.profile.host_key {
        key.push(Algorithm::new(n).map_err(|_| unsupported(n))?);
    }
    let mut cipher = Vec::new();
    for n in &opts.profile.cipher {
        cipher.push(russh::cipher::Name::try_from(*n).map_err(|_| unsupported(n))?);
    }
    let mut mac = Vec::new();
    for n in &opts.profile.mac {
        mac.push(russh::mac::Name::try_from(*n).map_err(|_| unsupported(n))?);
    }
    Ok(client::Config {
        client_id: russh::SshId::Standard(CLIENT_ID.into()),
        preferred: Preferred {
            kex: kex.into(),
            key: key.into(),
            cipher: cipher.into(),
            mac: mac.into(),
            compression: (&[russh::compression::NONE][..]).into(),
            host_key_certificates: (&[][..]).into(),
        },
        gex: client::GexParams::new(opts.gex_bits.0, opts.gex_bits.1, opts.gex_bits.2)?,
        keepalive_interval: Some(opts.keepalive),
        keepalive_max: opts.keepalive_max,
        inactivity_timeout: None,
        ..client::Config::default()
    })
}

/// Read the server greeting and its KEXINIT without authenticating.
pub async fn capture_server_algorithms<S>(
    mut stream: S,
    timeout: Duration,
) -> Result<ServerAlgorithms, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let work = async {
        stream
            .write_all(format!("{CLIENT_ID}\r\n").as_bytes())
            .await?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            if let Parse::Done(s) = kexinit::parse(&buf)? {
                return Ok(*s);
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(SshError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "server closed before sending KEXINIT",
                )));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| SshError::Timeout("server greeting"))?
}

/// A host key as presented by the server.
#[derive(Clone, Debug)]
pub struct HostKey(pub PublicKey);

impl HostKey {
    pub fn algorithm(&self) -> String {
        self.0.algorithm().as_str().to_owned()
    }
    /// OpenSSH-style `SHA256:...` fingerprint.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint(HashAlg::Sha256).to_string()
    }
    /// `<algorithm> <base64>` (no comment), as in known_hosts.
    pub fn to_openssh(&self) -> Result<String, SshError> {
        let mut k = self.0.clone();
        k.set_comment("");
        Ok(k.to_openssh()
            .map_err(|e| SshError::Ssh(russh::Error::from(e)))?
            .trim()
            .to_owned())
    }
    pub fn from_openssh(s: &str) -> Result<Self, SshError> {
        PublicKey::from_openssh(s)
            .map(Self)
            .map_err(|e| SshError::Ssh(russh::Error::from(e)))
    }
    pub fn same_key(&self, other: &PublicKey) -> bool {
        self.0.key_data() == other.key_data()
    }
}

/// Handler that records the presented key and either rejects it (capture
/// mode) or accepts only the pinned key.
struct KeyHandler {
    pinned: Option<HostKey>,
    seen: Arc<Mutex<Option<PublicKey>>>,
}

impl client::Handler for KeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server else {
            return Ok(false);
        };
        if let Ok(mut s) = self.seen.lock() {
            *s = Some(key.clone());
        }
        Ok(self.pinned.as_ref().is_some_and(|p| p.same_key(key)))
    }
}

/// Complete a key exchange only to learn the server's host key; the
/// connection is always rejected afterwards (no authentication happens).
pub async fn fetch_host_key<S>(stream: S, opts: &SshOptions) -> Result<HostKey, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen = Arc::new(Mutex::new(None));
    let handler = KeyHandler {
        pinned: None,
        seen: seen.clone(),
    };
    let cfg = Arc::new(russh_config(opts)?);
    let res = tokio::time::timeout(
        opts.handshake_timeout,
        client::connect_stream(cfg, stream, handler),
    )
    .await;
    let key = seen.lock().ok().and_then(|mut s| s.take());
    match (key, res) {
        (Some(k), _) => Ok(HostKey(k)),
        (None, Err(_)) => Err(SshError::Timeout("host key exchange")),
        (None, Ok(Err(e))) => Err(e.into()),
        (None, Ok(Ok(_))) => Err(SshError::NoHostKey),
    }
}

/// An authenticated session to the head unit.
pub struct SshTransport {
    handle: Handle<KeyHandler>,
}

/// Connect, verify the pinned host key, authenticate with a password.
pub async fn connect<S>(
    stream: S,
    opts: &SshOptions,
    pinned: HostKey,
    user: &str,
    password: &Zeroizing<String>,
) -> Result<SshTransport, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen = Arc::new(Mutex::new(None));
    let handler = KeyHandler {
        pinned: Some(pinned.clone()),
        seen: seen.clone(),
    };
    let cfg = Arc::new(russh_config(opts)?);
    let res = tokio::time::timeout(
        opts.handshake_timeout,
        client::connect_stream(cfg, stream, handler),
    )
    .await
    .map_err(|_| SshError::Timeout("handshake"))?;
    let mut handle = match res {
        Ok(h) => h,
        Err(e) => {
            let presented = seen.lock().ok().and_then(|s| s.clone());
            if presented.is_some_and(|k| !pinned.same_key(&k)) {
                return Err(SshError::HostKeyMismatch);
            }
            return Err(e.into());
        }
    };
    let auth = tokio::time::timeout(
        opts.handshake_timeout,
        authenticate(&mut handle, user, password),
    )
    .await
    .map_err(|_| SshError::Timeout("authentication"))?;
    auth?;
    Ok(SshTransport { handle })
}

/// Is this keyboard-interactive prompt a plain login password prompt?
/// Anything mentioning a new/changed/expired password is refused, so the
/// probe can never drive a password change (a remote write).
pub fn is_plain_password_prompt(prompt: &str) -> bool {
    let p = prompt.to_ascii_lowercase();
    p.contains("password")
        && ![
            "new", "retype", "again", "current", "old", "expire", "change", "confirm", "verify",
        ]
        .iter()
        .any(|w| p.contains(w))
}

/// At most ONE password attempt in total: `password` if offered, otherwise
/// keyboard-interactive with exactly one hidden plain-password prompt,
/// answered once. Never retried (no lockout, no guessed answers).
async fn authenticate(
    handle: &mut Handle<KeyHandler>,
    user: &str,
    password: &Zeroizing<String>,
) -> Result<(), SshError> {
    let methods = match handle.authenticate_none(user).await? {
        russh::client::AuthResult::Success => return Ok(()),
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    let offered: Vec<&str> = methods.iter().map(<&str>::from).collect();
    if methods.contains(&MethodKind::Password) {
        let r = handle
            .authenticate_password(user, password.as_str())
            .await?;
        return if r.success() {
            Ok(())
        } else {
            Err(SshError::AuthFailed(
                "password rejected (one attempt, not retried)".into(),
            ))
        };
    }
    if methods.contains(&MethodKind::KeyboardInteractive) {
        let mut resp = handle
            .authenticate_keyboard_interactive_start(user, None::<String>)
            .await?;
        let mut answered = false;
        // Empty info requests (no prompts) are tolerated a few times.
        for _ in 0..4 {
            match resp {
                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                KeyboardInteractiveAuthResponse::Failure { .. } => break,
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers = match prompts.as_slice() {
                        [] => Vec::new(),
                        [p] if !answered && !p.echo && is_plain_password_prompt(&p.prompt) => {
                            answered = true;
                            vec![password.as_str().to_owned()]
                        }
                        _ => {
                            return Err(SshError::AuthFailed(format!(
                                "unexpected keyboard-interactive prompt(s) {:?}; not answering",
                                prompts
                                    .iter()
                                    .map(|p| p.prompt.as_str())
                                    .collect::<Vec<_>>()
                            )));
                        }
                    };
                    resp = handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await?;
                }
            }
        }
        return Err(SshError::AuthFailed(
            "keyboard-interactive rejected (one attempt, not retried)".into(),
        ));
    }
    Err(SshError::AuthFailed(format!(
        "no supported method (server offers: {})",
        offered.join(",")
    )))
}

impl SshTransport {
    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "probe finished", "en")
            .await;
    }
}

fn keep(buf: &mut Vec<u8>, dropped: &mut u64, data: &[u8], max: usize) {
    let room = max.saturating_sub(buf.len());
    let take = room.min(data.len());
    buf.extend_from_slice(&data[..take]);
    *dropped += (data.len() - take) as u64;
}

impl HeadUnitTransport for SshTransport {
    async fn exec(
        &mut self,
        command: &GuardedCommand,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        self.exec_str(command.as_str(), limits).await
    }

    async fn exec_mutating(
        &mut self,
        command: &MutatingCommand,
        _consent: &Consent,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        self.exec_str(command.as_str(), limits).await
    }
}

impl SshTransport {
    /// One command on a fresh channel. Only reachable through the typed
    /// trait methods above (guarded read-only or consented mutation).
    async fn exec_str(
        &mut self,
        command: &str,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        if self.handle.is_closed() {
            return Err(TransportError::ConnectionLost("session closed".into()));
        }
        let started = SystemTime::now();
        let t0 = tokio::time::Instant::now();
        let deadline = t0
            .checked_add(limits.timeout)
            .unwrap_or_else(|| t0 + Duration::from_secs(86_400));
        let lost_or_rejected = |h: &Handle<KeyHandler>, e: russh::Error| {
            if h.is_closed() {
                TransportError::ConnectionLost(e.to_string())
            } else {
                TransportError::Rejected(e.to_string())
            }
        };
        let mut channel =
            match tokio::time::timeout_at(deadline, self.handle.channel_open_session()).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => return Err(lost_or_rejected(&self.handle, e)),
                Err(_) => {
                    return Err(TransportError::ConnectionLost(
                        "timeout opening channel".into(),
                    ));
                }
            };
        if let Err(e) = channel.exec(true, command).await {
            let _ = channel.close().await;
            return Err(lost_or_rejected(&self.handle, e));
        }
        let (mut stdout, mut stderr, mut sd, mut ed) = (Vec::new(), Vec::new(), 0u64, 0u64);
        let mut outcome = None;
        loop {
            match tokio::time::timeout_at(deadline, channel.wait()).await {
                Err(_) => {
                    let _ = channel.close().await;
                    outcome = Some(ExitOutcome::TimedOut);
                    break;
                }
                Ok(None) | Ok(Some(ChannelMsg::Close)) => break,
                Ok(Some(ChannelMsg::Data { data })) => {
                    keep(&mut stdout, &mut sd, &data, limits.max_output)
                }
                Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => {
                    keep(&mut stderr, &mut ed, &data, limits.max_output)
                }
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    outcome = Some(ExitOutcome::Code(exit_status))
                }
                Ok(Some(ChannelMsg::ExitSignal { signal_name, .. })) => {
                    outcome = Some(ExitOutcome::Signal(format!("{signal_name:?}")))
                }
                Ok(Some(ChannelMsg::Failure)) => {
                    // Close explicitly: servers keep a refused channel open,
                    // which would exhaust their MaxSessions.
                    let _ = channel.close().await;
                    return Err(TransportError::Rejected(
                        "server refused exec request".into(),
                    ));
                }
                Ok(Some(_)) => {}
            }
        }
        let outcome = match outcome {
            Some(o) => o,
            None if self.handle.is_closed() => {
                return Err(TransportError::ConnectionLost(
                    "session closed during command".into(),
                ));
            }
            None => ExitOutcome::NoStatus,
        };
        Ok(ExecResult {
            stdout,
            stderr,
            stdout_dropped: sd,
            stderr_dropped: ed,
            outcome,
            started,
            duration: t0.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gex_range_accepts_2048_bit_groups_like_openssh() {
        let o = SshOptions::default();
        assert_eq!(o.gex_bits.0, 2048);
        let cfg = russh_config(&o).unwrap();
        assert_eq!(cfg.gex.min_group_size(), 2048);
        assert_eq!(cfg.gex.max_group_size(), 8192);
    }

    #[test]
    fn both_profiles_map_to_this_build() {
        for profile in [
            AlgorithmProfile::upstream_documented(),
            AlgorithmProfile::legacy_weak(),
        ] {
            let opts = SshOptions {
                profile,
                ..SshOptions::default()
            };
            russh_config(&opts).unwrap();
        }
    }

    #[test]
    fn only_plain_password_prompts_are_answered() {
        for ok in ["Password: ", "root@hu's password:", "PASSWORD"] {
            assert!(is_plain_password_prompt(ok), "{ok}");
        }
        for bad in [
            "New password: ",
            "Retype new password:",
            "(current) UNIX password:",
            "Your password has expired",
            "Verification code:",
            "OTP:",
            "Old Password:",
        ] {
            assert!(!is_plain_password_prompt(bad), "{bad}");
        }
    }

    #[test]
    fn output_cap_counts_dropped_bytes() {
        let (mut b, mut d) = (Vec::new(), 0);
        keep(&mut b, &mut d, b"hello", 3);
        keep(&mut b, &mut d, b"world", 3);
        assert_eq!(b, b"hel");
        assert_eq!(d, 7);
    }
}
