//! Read-only head-unit probe (Phase 0 evidence collection).
//!
//! Same plan, IDs and report layout as `tools/probe/nbt-probe.sh`, so both
//! produce interchangeable transcripts. Steps that need the user or the
//! network before a session exists (algorithm discovery, host-key
//! confirmation, login) live in the adapter; this module runs once a
//! transport is available.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::guard::{Context, GuardError, GuardedCommand, NodePath, SafeName, SafePath};
use crate::redact::{redact, redact_bytes};
use crate::transport::{
    ExecLimits, HeadUnitTransport, Policy, RecordedError, Recorder, TranscriptSink, TransportError,
    sha256_hex,
};

pub const PROBE_VERSION: u32 = 2;
pub const PLUGIN_DIR: &str = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";
pub const USB_MARKER_NAME: &str = "NBT-Probe-Marker.txt";

/// Shareable report files the probe appends to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFile {
    Summary,
    Readback,
    ReadbackNotes,
    LogVersions,
    Notes,
}

impl ReportFile {
    pub fn file_name(self) -> &'static str {
        match self {
            ReportFile::Summary => "summary.txt",
            ReportFile::Readback => "readback.tsv",
            ReportFile::ReadbackNotes => "readback-notes.txt",
            ReportFile::LogVersions => "log-versions.txt",
            ReportFile::Notes => "notes.txt",
        }
    }
}

/// Report output beyond the per-exec transcript.
pub trait Reports {
    fn append(&mut self, file: ReportFile, text: &str) -> Result<(), crate::transport::SinkError>;
    /// `report/text/<name>` — already redacted content.
    fn write_text(
        &mut self,
        name: &SafeName,
        content: &str,
    ) -> Result<(), crate::transport::SinkError>;
}

/// User interaction needed mid-run.
#[allow(async_fn_in_trait)]
pub trait Interaction {
    /// Offer the optional USB step. Returns the expected SHA-256 of the marker
    /// file if the user inserted the stick, `None` to skip.
    async fn usb_step(&mut self) -> Option<String>;
}

#[derive(Clone, Debug)]
pub struct ProbeConfig {
    pub node: NodePath,
    pub text_limits: ExecLimits,
    pub readback_limits: ExecLimits,
    /// Files larger than this (per `ls -la`) are not read back.
    pub max_readback_bytes: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            node: NodePath::default(),
            text_limits: ExecLimits {
                max_output: 4 * 1024 * 1024,
                ..ExecLimits::default()
            },
            readback_limits: ExecLimits::default(),
            max_readback_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("static probe plan contains a rejected command ({id}): {source}")]
    PlanInvalid { id: String, source: GuardError },
    #[error("connection lost after {executed} recorded executions: {reason}")]
    ConnectionLost { executed: u32, reason: String },
    #[error(transparent)]
    Sink(#[from] crate::transport::SinkError),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProbeSummary {
    pub executed: u32,
    pub hu_context_works: bool,
    pub readbacks: u32,
    pub usb_tested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ctx {
    Outer,
    Hu,
}

/// One static probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanEntry {
    pub id: String,
    pub ctx: Ctx,
    pub body: String,
}

const P: &str = "/opt/hmi/ID5/data/ro/Plugins";

const TOOLS_CMDV: &[&str] = &[
    "sh",
    "ksh",
    "on",
    "ls",
    "cat",
    "df",
    "mount",
    "pidin",
    "use",
    "sha256sum",
    "sha256",
    "sha1sum",
    "md5sum",
    "md5",
    "cksum",
    "sum",
    "openssl",
    "od",
    "hexdump",
    "strings",
    "grep",
    "sed",
    "awk",
    "wc",
    "head",
    "tail",
    "find",
    "stat",
    "readlink",
    "realpath",
    "basename",
    "dirname",
    "tar",
    "pax",
    "gzip",
    "zip",
    "unzip",
    "mktemp",
    "mv",
    "cp",
    "ln",
    "mkdir",
    "rmdir",
    "rm",
    "chmod",
    "chown",
    "touch",
    "dd",
    "sync",
    "fsync",
    "kill",
    "slay",
    "pidof",
    "shutdown",
    "sleep",
    "date",
    "printf",
    "test",
    "xargs",
    "base64",
    "uuencode",
    "sort",
    "uniq",
    "cmp",
    "diff",
    "fsysinfo",
    "chkqnx6fs",
    "mkqnx6fs",
    "devb-umass",
    "qconn",
    "pfctl",
];
const TOOLS_USE: &[&str] = &[
    "ls",
    "cp",
    "mv",
    "df",
    "mount",
    "pidin",
    "cksum",
    "md5",
    "sha256sum",
    "on",
    "mkdir",
    "ln",
    "chmod",
    "sync",
    "slay",
    "find",
    "stat",
    "tar",
    "pax",
    "mktemp",
];
const DIGEST_TOOLS: &[&str] = &["sha256sum", "sha256", "md5sum", "md5", "cksum", "sum"];

/// The static plan; identical IDs and command text to the bash probe.
pub fn static_plan() -> Vec<PlanEntry> {
    use Ctx::{Hu, Outer};
    let shell = r#"echo "0=$0 SHELL=$SHELL KSH=$KSH_VERSION PATH=$PATH PWD=$PWD""#;
    let mut v: Vec<(String, Ctx, String)> = [
        ("outer-echo", Outer, "echo probe-ok".to_owned()),
        ("outer-uname", Outer, "uname -a".into()),
        ("outer-shell", Outer, shell.into()),
        ("outer-id", Outer, "id".into()),
        ("outer-date", Outer, "date".into()),
        ("outer-rc-true", Outer, "true".into()),
        ("outer-rc-false", Outer, "false".into()),
        ("outer-rc-sh7", Outer, "/bin/sh -c 'exit 7'".into()),
        ("outer-rc-missing-file", Outer, "ls /nonexistent-nbt-probe".into()),
        ("outer-rc-missing-cmd", Outer, "nonexistent-nbt-probe-cmd".into()),
        ("outer-split-streams", Outer, "echo to-stdout; echo to-stderr 1>&2; exit 3".into()),
        ("outer-ls-root", Outer, "ls -la /".into()),
        ("outer-ls-net", Outer, "ls -la /net".into()),
        ("outer-ls-fs", Outer, "ls -la /fs".into()),
        ("outer-ls-mnt", Outer, "ls -la /mnt".into()),
        ("outer-ls-opt", Outer, "ls -la /opt".into()),
        ("outer-ls-opt-aa", Outer, "ls -la /opt/aa".into()),
        ("outer-which-on", Outer, "command -v on".into()),
        ("outer-mount", Outer, "mount".into()),
        ("outer-df", Outer, "df -k".into()),
        ("outer-df-P", Outer, "df -kP".into()),
        ("outer-nbt-version", Outer, "cat /opt/sys/etc/nbt_version.txt".into()),
        ("outer-pidin", Outer, "pidin".into()),
        ("hu-echo", Hu, "echo probe-ok".into()),
        ("hu-rc-true", Hu, "true".into()),
        ("hu-rc-false", Hu, "false".into()),
        ("hu-rc-sh7", Hu, "/bin/sh -c 'exit 7'".into()),
        ("hu-rc-missing-file", Hu, "ls /nonexistent-nbt-probe".into()),
        ("hu-rc-missing-cmd", Hu, "nonexistent-nbt-probe-cmd".into()),
        ("hu-split-streams", Hu, "/bin/sh -c 'echo to-stdout; echo to-stderr 1>&2; exit 3'".into()),
        ("hu-quoting", Hu, crate::guard::QUOTING_PROBE.into()),
        ("hu-uname", Hu, "uname -a".into()),
        ("hu-shell", Hu, format!("/bin/sh -c '{shell}'")),
        ("hu-id", Hu, "id".into()),
        ("hu-date", Hu, "date".into()),
        ("hu-nbt-version", Hu, "cat /opt/sys/etc/nbt_version.txt".into()),
        ("hu-ls-root", Hu, "ls -la /".into()),
        ("hu-ls-net", Hu, "ls -la /net".into()),
        ("hu-ls-fs", Hu, "ls -la /fs".into()),
        ("hu-ls-mnt", Hu, "ls -la /mnt".into()),
        ("hu-ls-opt", Hu, "ls -la /opt".into()),
        ("hu-ls-fs-sda0", Hu, "ls -la /fs/sda0".into()),
        ("hu-ls-fs-sda0-opt", Hu, "ls -la /fs/sda0/opt".into()),
        ("hu-ls-opt-aa", Hu, "ls -la /opt/aa".into()),
        ("hu-ls-fs-sda0-opt-aa", Hu, "ls -la /fs/sda0/opt/aa".into()),
        ("hu-lsR-opt-aa", Hu, "ls -laR /opt/aa".into()),
        ("hu-ls-plugins", Hu, format!("ls -la {P}")),
        ("hu-ls-plugin-nbtaad", Hu, format!("ls -la {P}/NbtAad")),
        ("hu-ls-plugin-nbtaad-lower", Hu, format!("ls -la {P}/nbtaad")),
        ("hu-ls-nbtaad-old", Hu, "ls -la /opt/aa/NbtAad.old".into()),
        ("hu-ls-var-opt", Hu, "ls -la /var/opt".into()),
        ("hu-ls-var-opt-aa", Hu, "ls -la /var/opt/aa".into()),
        ("hu-ls-dev-shmem", Hu, "ls -la /dev/shmem".into()),
        ("hu-lsd-paths", Hu, format!("ls -ld /opt /opt/aa /opt/hmi /opt/hmi/ID5 /opt/hmi/ID5/data /opt/hmi/ID5/data/ro {P} {P}/NbtAad /fs/sda0 /fs/sda0/opt /fs/sda0/opt/aa /fs/sda1 /var /var/opt /var/opt/aa /mnt /dev/shmem")),
        ("hu-lsdi-paths", Hu, format!("ls -ldi /opt/aa {P} {P}/NbtAad /fs/sda0/opt/aa /var/opt/aa /dev/shmem")),
        ("hu-mount", Hu, "mount".into()),
        ("hu-df", Hu, "df -k".into()),
        ("hu-df-P", Hu, "df -kP".into()),
        ("hu-df-paths", Hu, format!("df -k /opt/aa {P} {P}/NbtAad /var/opt/aa /fs/sda0 /fs/sda1 /dev/shmem")),
        ("hu-pidin", Hu, "pidin".into()),
        ("hu-pidin-arg", Hu, "pidin -p nbt-aad arg".into()),
        ("hu-pf-conf", Hu, "cat /fs/sda0/etc/pf.conf".into()),
        ("hu-etc-pf-conf", Hu, "cat /etc/pf.conf".into()),
        ("hu-ls-pf-bak", Hu, "ls -la /opt/aa/pf.bak".into()),
    ]
    .into_iter()
    .map(|(id, c, b)| (id.to_owned(), c, b))
    .collect();
    for t in TOOLS_CMDV {
        v.push((
            format!("hu-cmdv-{t}"),
            Hu,
            format!("/bin/sh -c 'command -v {t}'"),
        ));
    }
    for t in TOOLS_USE {
        v.push((format!("hu-use-{t}"), Hu, format!("use {t}")));
    }
    for t in DIGEST_TOOLS {
        v.push((format!("hu-digest-{t}"), Hu, format!("{t} /opt/aa/nbt-aad")));
    }
    v.push((
        "hu-digest-openssl".into(),
        Hu,
        "openssl dgst -sha256 /opt/aa/nbt-aad".into(),
    ));
    v.into_iter()
        .map(|(id, ctx, body)| PlanEntry { id, ctx, body })
        .collect()
}

fn context(ctx: Ctx, node: &NodePath) -> Context {
    match ctx {
        Ctx::Outer => Context::Login,
        Ctx::Hu => Context::Node(node.clone()),
    }
}

/// Validate every static command before anything connects.
pub fn guarded_plan(node: &NodePath) -> Result<Vec<(String, GuardedCommand)>, ProbeError> {
    static_plan()
        .into_iter()
        .map(|e| {
            GuardedCommand::new(context(e.ctx, node), &e.body)
                .map(|c| (e.id.clone(), c))
                .map_err(|source| ProbeError::PlanInvalid { id: e.id, source })
        })
        .collect()
}

/// A parsed `ls -la` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsEntry {
    /// Regular file with exactly 9 fields.
    File {
        name: String,
        size: Option<u64>,
    },
    /// Regular file in an unexpected layout: never read back, only noted.
    Unparsed {
        line: String,
        fields: usize,
    },
    Symlink {
        line: String,
    },
    Other {
        line: String,
    },
}

/// Strict `ls -la` parsing; anything unexpected is surfaced, never guessed.
pub fn parse_ls(output: &str) -> Vec<LsEntry> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let Some(first) = fields.first() else {
            continue;
        };
        if first.starts_with('-') {
            if fields.len() == 9 {
                out.push(LsEntry::File {
                    name: fields[8].to_owned(),
                    size: fields[4].parse().ok(),
                });
            } else {
                out.push(LsEntry::Unparsed {
                    line: line.to_owned(),
                    fields: fields.len(),
                });
            }
        } else if first.starts_with('l') {
            out.push(LsEntry::Symlink {
                line: line.to_owned(),
            });
        } else if !first.starts_with('d') && *first != "total" && fields.len() > 2 {
            out.push(LsEntry::Other {
                line: line.to_owned(),
            });
        }
    }
    out
}

/// Version markers embedded in binaries (`strings -n 6` + pattern), unique, sorted.
pub fn embedded_versions(data: &[u8]) -> Vec<String> {
    static RX: LazyLock<Regex> = LazyLock::new(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"Build: v[^ ]+|rhmiapp-[A-Za-z0-9._-]+").expect("static regex")
    });
    let mut found = BTreeSet::new();
    for run in data.split(|b| !(0x20..=0x7e).contains(b) && *b != b'\t') {
        if run.len() < 6 {
            continue;
        }
        let s = String::from_utf8_lossy(run);
        for m in RX.find_iter(&s) {
            found.insert(m.as_str().to_owned());
        }
    }
    found.into_iter().collect()
}

/// Files under these labels are copied (redacted) into `report/text/`;
/// everything else stays hash-only (may identify the user's phone).
fn text_copy_allowed(label: &str, name: &str) -> bool {
    match label {
        "opt-aa" => matches!(name, "nbt-aad.env" | "pf.bak" | "mic.disable"),
        "var-opt-aa" => matches!(
            name,
            "bootguard" | "usb-aa" | "usblog" | "menu-idrive" | "show-drivemode" | "kombi-nav"
        ),
        _ => false,
    }
}

struct Runner<'a, T, S> {
    rec: &'a mut Recorder<T, S>,
    cfg: &'a ProbeConfig,
    summary: ProbeSummary,
}

fn lost(e: TransportError, executed: u32) -> ProbeError {
    ProbeError::ConnectionLost {
        executed,
        reason: e.to_string(),
    }
}

impl<T, S> Runner<'_, T, S>
where
    T: HeadUnitTransport,
    S: TranscriptSink + Reports,
{
    fn hu(&self) -> Context {
        Context::Node(self.cfg.node.clone())
    }

    fn append(&mut self, f: ReportFile, text: &str) -> Result<(), ProbeError> {
        Ok(self.rec.sink_mut().append(f, text)?)
    }

    /// Run one command. `Ok(None)` = the server rejected it (recorded, continue).
    async fn exec(
        &mut self,
        id: &str,
        policy: Policy,
        cmd: &GuardedCommand,
    ) -> Result<Option<crate::transport::ExecResult>, ProbeError> {
        let limits = match policy {
            Policy::Binary { .. } => self.cfg.readback_limits,
            _ => self.cfg.text_limits,
        };
        match self.rec.exec(id, policy, cmd, limits).await {
            Ok(r) => Ok(Some(r)),
            Err(RecordedError::Sink(e)) => Err(e.into()),
            Err(RecordedError::Transport(TransportError::Rejected(_))) => Ok(None),
            Err(RecordedError::Transport(e)) => Err(lost(e, self.rec.executed())),
        }
    }

    async fn probe(
        &mut self,
        id: &str,
        cmd: &GuardedCommand,
    ) -> Result<Option<Vec<u8>>, ProbeError> {
        let r = self.exec(id, Policy::Text, cmd).await?;
        let rc = r
            .as_ref()
            .map_or("rejected".to_owned(), |r| r.outcome.to_string());
        self.append(
            ReportFile::Summary,
            &format!("{id:<30} rc={rc:<4} {}\n", redact(cmd.as_str())),
        )?;
        Ok(r.map(|r| r.stdout))
    }

    async fn readback(
        &mut self,
        path: &SafePath,
        label: &str,
    ) -> Result<Option<Vec<u8>>, ProbeError> {
        let cmd = match GuardedCommand::cat(self.hu(), path) {
            Ok(c) => c,
            Err(e) => {
                self.append(
                    ReportFile::ReadbackNotes,
                    &redact(&format!("SKIP {}: {}\n", e.reason, path.as_str())),
                )?;
                return Ok(None);
            }
        };
        let r = self
            .exec(
                "readback",
                Policy::Binary {
                    label: label.to_owned(),
                },
                &cmd,
            )
            .await?;
        self.summary.readbacks += 1;
        let (rc, data, stderr) = match r {
            Some(r) => (r.outcome.to_string(), r.stdout, r.stderr),
            None => ("rejected".to_owned(), Vec::new(), Vec::new()),
        };
        let versions = embedded_versions(&data).join(" ");
        self.append(
            ReportFile::Readback,
            &format!(
                "{}\t{rc}\t{}\t{}\t{versions}\t{}\n",
                redact(path.as_str()),
                data.len(),
                sha256_hex(&data),
                redact_bytes(&stderr).replace('\n', " ")
            ),
        )?;
        Ok(Some(data))
    }

    async fn readback_dir(&mut self, dir: &str, label: &str) -> Result<(), ProbeError> {
        let Some(dirp) = SafePath::new(dir) else {
            return Ok(());
        };
        let cmd =
            GuardedCommand::ls_la(self.hu(), &dirp).map_err(|source| ProbeError::PlanInvalid {
                id: format!("list {dir}"),
                source,
            })?;
        let Some(r) = self.exec("list", Policy::Text, &cmd).await? else {
            return Ok(());
        };
        if !r.outcome.is_success() {
            let note = format!(
                "NOTE {dir} not listable (rc={}): {}\n",
                r.outcome,
                redact_bytes(&r.stderr).replace('\n', " ")
            );
            return self.append(ReportFile::ReadbackNotes, &note);
        }
        let listing = String::from_utf8_lossy(&r.stdout).into_owned();
        for entry in parse_ls(&listing) {
            match entry {
                LsEntry::File { name, size } => {
                    let Some(safe) = SafeName::new(&name) else {
                        self.append(ReportFile::ReadbackNotes, &format!("SKIP unsafe file name in {dir} (name not recorded)\n"))?;
                        continue;
                    };
                    if size.is_some_and(|s| s > self.cfg.max_readback_bytes) {
                        self.append(ReportFile::ReadbackNotes, &redact(&format!("SKIP too large ({} bytes): {dir}/{name}\n", size.unwrap_or(0))))?;
                        continue;
                    }
                    let path = dirp.join(&safe);
                    let file_label = format!("{label}/{name}");
                    if let Some(data) = self.readback(&path, &file_label).await? {
                        self.text_copy(label, &safe, &data)?;
                    }
                }
                LsEntry::Unparsed { line, fields } => self.append(
                    ReportFile::ReadbackNotes,
                    &redact(&format!("NOTE UNPARSED ls line in {dir} ({fields} fields, file not read back): {line}\n")),
                )?,
                LsEntry::Symlink { line } => {
                    self.append(ReportFile::ReadbackNotes, &redact(&format!("NOTE symlink in {dir} (not followed): {line}\n")))?
                }
                LsEntry::Other { line } => {
                    self.append(ReportFile::ReadbackNotes, &redact(&format!("NOTE non-regular entry in {dir}: {line}\n")))?
                }
            }
        }
        Ok(())
    }

    fn text_copy(&mut self, label: &str, name: &SafeName, data: &[u8]) -> Result<(), ProbeError> {
        if !text_copy_allowed(label, name.as_str()) || data.len() > 65_536 || data.contains(&0) {
            return Ok(());
        }
        let Some(out) = SafeName::new(&format!("{label}__{}", name.as_str())) else {
            return Ok(());
        };
        Ok(self.rec.sink_mut().write_text(&out, &redact_bytes(data))?)
    }

    async fn logs(&mut self) -> Result<(), ProbeError> {
        static RX: LazyLock<Regex> = LazyLock::new(|| {
            #[allow(clippy::expect_used)]
            Regex::new(r"Build:|create\(name=|rhmiapp-").expect("static regex")
        });
        for lg in ["nbt-aad.log", "nbt-aad-app.log"] {
            let path = SafePath::new(&format!("/dev/shmem/{lg}"));
            let Some(path) = path else { continue };
            let Ok(cmd) = GuardedCommand::cat(self.hu(), &path) else {
                continue;
            };
            let r = self
                .exec(&format!("log-{lg}"), Policy::Secret, &cmd)
                .await?;
            let (rc, data) = r.map_or(("rejected".to_owned(), Vec::new()), |r| {
                (r.outcome.to_string(), r.stdout)
            });
            let mut text = format!("# /dev/shmem/{lg} rc={rc} bytes={}\n", data.len());
            let s = String::from_utf8_lossy(&data);
            for line in s.lines().filter(|l| RX.is_match(l)).take(20) {
                text.push_str(&redact(line));
                text.push('\n');
            }
            self.append(ReportFile::LogVersions, &text)?;
        }
        Ok(())
    }

    async fn usb(&mut self, expected_sha: String) -> Result<(), ProbeError> {
        self.summary.usb_tested = true;
        self.append(
            ReportFile::Notes,
            &format!("usb marker expected sha256: {expected_sha}\n"),
        )?;
        let hu = self.hu();
        for (id, body) in [
            ("hu-usb-ls-mnt", "ls -la /mnt"),
            ("hu-usb-mount", "mount"),
            ("hu-usb-df", "df -k"),
        ] {
            let cmd = GuardedCommand::new(hu.clone(), body).map_err(|source| {
                ProbeError::PlanInvalid {
                    id: id.into(),
                    source,
                }
            })?;
            self.probe(id, &cmd).await?;
        }
        let cmd = GuardedCommand::new(hu.clone(), "ls /mnt").map_err(|source| {
            ProbeError::PlanInvalid {
                id: "usb-ls-mnt-short".into(),
                source,
            }
        })?;
        let Some(r) = self.exec("usb-ls-mnt-short", Policy::Text, &cmd).await? else {
            return Ok(());
        };
        static UMASS: LazyLock<Regex> = LazyLock::new(|| {
            #[allow(clippy::expect_used)]
            Regex::new(r"^umass[A-Za-z0-9_]*$").expect("static regex")
        });
        let listing = String::from_utf8_lossy(&r.stdout).into_owned();
        for m in listing
            .split_ascii_whitespace()
            .filter(|m| UMASS.is_match(m))
        {
            let Some(mp) = SafePath::new(&format!("/mnt/{m}")) else {
                continue;
            };
            for (id, body) in [
                (format!("hu-usb-ls-{m}"), format!("ls -la /mnt/{m}")),
                (format!("hu-usb-df-{m}"), format!("df -k /mnt/{m}")),
            ] {
                if let Ok(cmd) = GuardedCommand::new(hu.clone(), &body) {
                    self.probe(&id, &cmd).await?;
                }
            }
            for cand in [
                USB_MARKER_NAME,
                "nbt-probe-marker.txt",
                "NBT-PROBE-MARKER.TXT",
            ] {
                if let Some(n) = SafeName::new(cand) {
                    let data = self
                        .readback(&mp.join(&n), &format!("usb/{m}/{cand}"))
                        .await?;
                    if let Some(d) = data.filter(|d| !d.is_empty()) {
                        let ok = sha256_hex(&d) == expected_sha;
                        self.append(
                            ReportFile::Notes,
                            &format!(
                                "usb marker /mnt/{m}/{cand}: {}\n",
                                if ok { "MATCH" } else { "MISMATCH" }
                            ),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Run the probe over an established transport. On `ConnectionLost` the
/// caller should package what was recorded and stop; it must not reconnect.
pub async fn run<T, S, I>(
    rec: &mut Recorder<T, S>,
    cfg: &ProbeConfig,
    io: &mut I,
) -> Result<ProbeSummary, ProbeError>
where
    T: HeadUnitTransport,
    S: TranscriptSink + Reports,
    I: Interaction,
{
    let plan = guarded_plan(&cfg.node)?;
    let mut r = Runner {
        rec,
        cfg,
        summary: ProbeSummary::default(),
    };
    let mut hu_echo = None;
    for (id, cmd) in &plan {
        let out = r.probe(id, cmd).await?;
        if id == "hu-echo" {
            hu_echo = out;
        }
    }
    r.summary.hu_context_works = hu_echo
        .as_deref()
        .is_some_and(|o| o.starts_with(b"probe-ok"));
    if !r.summary.hu_context_works {
        r.append(
            ReportFile::Notes,
            &format!(
                "'on -f {}' did not work; read-back steps skipped\n",
                cfg.node.as_str()
            ),
        )?;
    } else {
        r.append(
            ReportFile::Readback,
            "path\trc\tbytes\tsha256\tembedded_versions\tstderr\n",
        )?;
        r.readback_dir("/opt/aa", "opt-aa").await?;
        r.readback_dir(PLUGIN_DIR, "plugin-NbtAad").await?;
        r.readback_dir("/opt/aa/NbtAad.old", "opt-aa-NbtAad.old")
            .await?;
        r.readback_dir("/var/opt/aa", "var-opt-aa").await?;
        if let Some(p) = SafePath::new("/opt/aa/nbt-aad") {
            r.readback(&p, "repeat/nbt-aad.2").await?;
            r.readback(&p, "repeat/nbt-aad.3").await?;
        }
        r.logs().await?;
        if let Some(sha) = io.usb_step().await {
            r.usb(sha).await?;
        }
    }
    r.summary.executed = r.rec.executed();
    Ok(r.summary)
}

#[cfg(test)]
mod tests;
