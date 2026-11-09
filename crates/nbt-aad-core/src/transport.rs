//! Head-unit transport abstraction and the mandatory transcript recorder.

use std::fmt;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::guard::{Consent, GuardedCommand, MutatingCommand};

/// How a remote command ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitOutcome {
    /// Exit status reported by the server.
    Code(u32),
    /// Terminated by a signal (name as reported).
    Signal(String),
    /// Channel closed without an exit status.
    NoStatus,
    /// Local timeout; the channel was closed.
    TimedOut,
}

impl ExitOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, ExitOutcome::Code(0))
    }
}

impl fmt::Display for ExitOutcome {
    /// Numeric code, or a word (`timeout`, `signal:<name>`, `none`).
    /// Compatible with the bash probe, which wrote 124 for timeouts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitOutcome::Code(c) => write!(f, "{c}"),
            ExitOutcome::Signal(s) => write!(f, "signal:{s}"),
            ExitOutcome::NoStatus => f.write_str("none"),
            ExitOutcome::TimedOut => f.write_str("timeout"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecLimits {
    pub timeout: Duration,
    /// Bytes kept per stream; the rest is drained and counted.
    pub max_output: usize,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_output: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Bytes received beyond `max_output` (discarded).
    pub stdout_dropped: u64,
    pub stderr_dropped: u64,
    pub outcome: ExitOutcome,
    pub started: SystemTime,
    pub duration: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The session is gone. No further command can be sent.
    #[error("connection lost: {0}")]
    ConnectionLost(String),
    /// The server refused to open a channel or run the command.
    #[error("command rejected by server: {0}")]
    Rejected(String),
}

/// Executes guarded commands on a head unit. Implementations must not retry,
/// reconnect or alter the command.
#[allow(async_fn_in_trait)]
pub trait HeadUnitTransport {
    async fn exec(
        &mut self,
        command: &GuardedCommand,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError>;

    /// Execute a mutation. Default: refused (transports are read-only unless
    /// they explicitly opt in).
    async fn exec_mutating(
        &mut self,
        command: &MutatingCommand,
        _consent: &Consent,
        _limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        Err(TransportError::Rejected(format!(
            "this transport does not execute mutations: {command}"
        )))
    }
}

/// What a transcript sink keeps of stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Stored raw (private) and redacted (report).
    Text,
    /// Stored raw only (private), under `label`; report gets digest + size.
    Binary { label: String },
    /// Digest + size only; raw bytes are discarded.
    Secret,
}

impl Policy {
    pub fn name(&self) -> &'static str {
        match self {
            Policy::Text => "text",
            Policy::Binary { .. } => "binary",
            Policy::Secret => "secret",
        }
    }
}

/// One transcript entry. The layout on disk is defined by the sink and matches
/// `tools/probe/nbt-probe.sh` (`report/exec/NNNN-id/...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRecord {
    pub seq: u32,
    pub id: String,
    pub policy: Policy,
    pub context: &'static str,
    pub command: String,
    /// `None` when the transport failed (connection lost / rejected).
    pub outcome: Option<ExitOutcome>,
    pub transport_error: Option<String>,
    pub started: SystemTime,
    pub duration: Duration,
    pub stdout_sha256: String,
    pub stdout_len: u64,
    pub stderr_sha256: String,
    pub stderr_len: u64,
    pub stdout_dropped: u64,
    pub stderr_dropped: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("transcript sink failed: {0}")]
pub struct SinkError(pub String);

/// Persists transcript records and report artifacts.
pub trait TranscriptSink {
    /// Must durably store the record before returning `Ok`.
    fn record(
        &mut self,
        record: &ExecRecord,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<(), SinkError>;
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Debug, thiserror::Error)]
pub enum RecordedError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// AC-44: a transcript gap is a stop condition.
    #[error(transparent)]
    Sink(#[from] SinkError),
}

/// Wraps a transport; every execution is recorded before its result is
/// returned, including failed ones. If recording fails, the result is
/// withheld and the caller must stop.
pub struct Recorder<T, S> {
    inner: T,
    sink: S,
    seq: u32,
}

impl<T: HeadUnitTransport, S: TranscriptSink> Recorder<T, S> {
    pub fn new(inner: T, sink: S) -> Self {
        Self {
            inner,
            sink,
            seq: 0,
        }
    }

    /// Continue a transcript on a new transport (e.g. after a reconnect):
    /// sequence numbers continue after `seq`, so no record is overwritten.
    pub fn resume(inner: T, sink: S, seq: u32) -> Self {
        Self { inner, sink, seq }
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub fn into_parts(self) -> (T, S) {
        (self.inner, self.sink)
    }

    pub fn executed(&self) -> u32 {
        self.seq
    }

    pub async fn exec(
        &mut self,
        id: &str,
        policy: Policy,
        command: &GuardedCommand,
        limits: ExecLimits,
    ) -> Result<ExecResult, RecordedError> {
        self.seq += 1;
        let started = SystemTime::now();
        let result = self.inner.exec(command, limits).await;
        self.record(
            id,
            policy,
            command.context().label(),
            command.as_str(),
            started,
            result,
        )
    }

    /// Execute and record a mutation (same transcript format; the record's
    /// id should name the operation, e.g. `e1-mkdir-scratch`).
    pub async fn exec_mutating(
        &mut self,
        id: &str,
        command: &MutatingCommand,
        consent: &Consent,
        limits: ExecLimits,
    ) -> Result<ExecResult, RecordedError> {
        self.seq += 1;
        let started = SystemTime::now();
        let result = self.inner.exec_mutating(command, consent, limits).await;
        self.record(
            id,
            Policy::Text,
            command.context().label(),
            command.as_str(),
            started,
            result,
        )
    }

    fn record(
        &mut self,
        id: &str,
        policy: Policy,
        context: &'static str,
        command: &str,
        started: SystemTime,
        result: Result<ExecResult, TransportError>,
    ) -> Result<ExecResult, RecordedError> {
        let (stdout, stderr, outcome, terr, started, duration, sd, ed) = match &result {
            Ok(r) => (
                r.stdout.as_slice(),
                r.stderr.as_slice(),
                Some(r.outcome.clone()),
                None,
                r.started,
                r.duration,
                r.stdout_dropped,
                r.stderr_dropped,
            ),
            Err(e) => (
                &[][..],
                &[][..],
                None,
                Some(e.to_string()),
                started,
                started.elapsed().unwrap_or_default(),
                0,
                0,
            ),
        };
        let record = ExecRecord {
            seq: self.seq,
            id: id.to_owned(),
            policy,
            context,
            command: command.to_owned(),
            outcome,
            transport_error: terr,
            started,
            duration,
            stdout_sha256: sha256_hex(stdout),
            stdout_len: stdout.len() as u64,
            stderr_sha256: sha256_hex(stderr),
            stderr_len: stderr.len() as u64,
            stdout_dropped: sd,
            stderr_dropped: ed,
        };
        self.sink.record(&record, stdout, stderr)?;
        Ok(result?)
    }
}
