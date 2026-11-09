//! Test kit: an in-memory, read-only fake head unit and an in-memory
//! transcript sink. Compiled only for tests or with the `testkit` feature;
//! never part of a release build.
#![allow(clippy::unwrap_used)]

pub mod sim;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use crate::guard::{GuardedCommand, SafeName};
use crate::probe::{Interaction, PLUGIN_DIR, ReportFile, Reports};
use crate::transport::{
    ExecLimits, ExecRecord, ExecResult, ExitOutcome, HeadUnitTransport, SinkError, TranscriptSink,
    TransportError,
};

#[derive(Clone, Debug)]
pub enum Node {
    Dir,
    File(Vec<u8>),
    Link(String),
}

/// Minimal interpreter for exactly the allowlisted shapes. Unknown programs
/// behave like a shell (`127`), and are counted so tests can assert that the
/// probe never sent anything outside the plan's vocabulary.
pub struct FakeHu {
    pub fs: BTreeMap<String, Node>,
    pub seen: Vec<String>,
    pub lose_after: Option<usize>,
    pub hang_on: Option<String>,
    pub on_broken: bool,
    pub eight_col_ls: bool,
    /// Paths (prefixes) on a read-only mount: `test -w` fails there.
    pub read_only: Vec<String>,
}

impl FakeHu {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut fs = BTreeMap::new();
        for d in [
            "/",
            "/opt",
            "/opt/aa",
            "/opt/aa/NbtAad.old",
            "/opt/hmi/ID5/data/ro/Plugins",
            PLUGIN_DIR,
            "/var/opt/aa",
            "/mnt",
            "/dev/shmem",
            "/opt/sys/etc",
        ] {
            fs.insert(d.to_owned(), Node::Dir);
        }
        let mut f = |p: &str, b: &[u8]| {
            fs.insert(p.to_owned(), Node::File(b.to_vec()));
        };
        f(
            "/opt/aa/nbt-aad",
            b"\x7fELF\x00\x00  Build: v1.9.36-combo (Nov 8)\x00",
        );
        f("/opt/aa/nbt-aad.old", b"\x7fELF old Build: v1.9.30-old\x00");
        f(
            "/opt/aa/nbt-aad.env",
            b"NBT_ALT_WIFI=CARPLAY\nNBT_KEEP_PF=1\nNBT_WFD_PASS=SuperSecretPass1\n",
        );
        f("/opt/aa/pf.bak", b"pass in all\n");
        for n in [
            "libNbtAad.so",
            "NbtAad.manifest",
            "NbtAad.xml",
            "NbtAad_ALL_Texts.zip",
            "NbtAad_ALL_Images.zip",
        ] {
            f(
                &format!("{PLUGIN_DIR}/{n}"),
                format!("payload {n} rhmiapp-43-combo").as_bytes(),
            );
        }
        f(&format!("{PLUGIN_DIR}/bad;name"), b"evil");
        f("/opt/aa/NbtAad.old/libNbtAad.so", b"old");
        f("/var/opt/aa/bootguard", b"1\n");
        f("/var/opt/aa/spp-model", b"Alex's Pixel PhoneOwnerName\n");
        f("/var/opt/aa/00-11-22-33-44-55.bin", b"peer\n");
        f("/var/opt/aa/iap2.cfg", b"wifi=secret\n");
        f("/opt/sys/etc/nbt_version.txt", b"HU_SW=FAKE\n");
        f(
            "/dev/shmem/nbt-aad.log",
            b"line\n  Build: v1.9.36-combo (Nov 8)\nphone WBAJA11010B123456\n",
        );
        f(
            "/dev/shmem/nbt-aad-app.log",
            b"create(name=NbtAad) rhmiapp-43-combo\n",
        );
        fs.insert(
            format!("{PLUGIN_DIR}/link-to-xml"),
            Node::Link("NbtAad.xml".into()),
        );
        Self {
            fs,
            seen: Vec::new(),
            lose_after: None,
            hang_on: None,
            on_broken: false,
            eight_col_ls: false,
            read_only: vec!["/opt".into(), "/var".into()],
        }
    }

    fn is_ro(&self, p: &str) -> bool {
        self.read_only.iter().any(|r| p.starts_with(r.as_str()))
    }

    fn parent_is_dir(&self, p: &str) -> bool {
        let parent = match p.rfind('/') {
            Some(0) => "/",
            Some(i) => &p[..i],
            None => return false,
        };
        matches!(self.fs.get(parent), Some(Node::Dir))
    }

    fn m_mkdir(&mut self, p: &str, err: &mut String) -> u32 {
        if self.is_ro(p) {
            err.push_str(&format!("mkdir: {p}: Read-only file system\n"));
            return 1;
        }
        if self.fs.contains_key(p) || !self.parent_is_dir(p) {
            err.push_str(&format!("mkdir: {p}: cannot create\n"));
            return 1;
        }
        self.fs.insert(p.to_owned(), Node::Dir);
        0
    }

    fn m_cp(&mut self, a: &str, b: &str, err: &mut String) -> u32 {
        if self.is_ro(b) {
            err.push_str(&format!("cp: {b}: Read-only file system\n"));
            return 1;
        }
        let Some(Node::File(data)) = self.fs.get(a).cloned() else {
            err.push_str(&format!("cp: {a}: No such file or directory\n"));
            return 1;
        };
        if !self.parent_is_dir(b) || matches!(self.fs.get(b), Some(Node::Dir)) {
            err.push_str(&format!("cp: {b}: cannot create\n"));
            return 1;
        }
        self.fs.insert(b.to_owned(), Node::File(data));
        0
    }

    fn m_mv(&mut self, a: &str, b: &str, err: &mut String) -> u32 {
        if self.is_ro(a) || self.is_ro(b) {
            err.push_str("mv: Read-only file system\n");
            return 1;
        }
        if !self.fs.contains_key(a) || self.fs.contains_key(b) || !self.parent_is_dir(b) {
            err.push_str(&format!("mv: cannot move {a} to {b}\n"));
            return 1;
        }
        let prefix = format!("{a}/");
        let keys: Vec<String> = self
            .fs
            .keys()
            .filter(|k| *k == a || k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in keys {
            if let Some(n) = self.fs.remove(&k) {
                self.fs.insert(format!("{b}{}", &k[a.len()..]), n);
            }
        }
        0
    }

    /// A head-unit restart: the remount is lost (read-only again).
    pub fn restart(&mut self) {
        if !self.read_only.iter().any(|r| r == "/opt") {
            self.read_only.push("/opt".into());
        }
    }

    pub fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        self.fs
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v {
                        Node::File(b) => b.clone(),
                        Node::Dir => b"<dir>".to_vec(),
                        Node::Link(t) => t.clone().into_bytes(),
                    },
                )
            })
            .collect()
    }

    fn ls(&self, flags: &str, path: &str, out: &mut String, err: &mut String) -> u32 {
        let Some(node) = self.fs.get(path) else {
            err.push_str(&format!("ls: No such file or directory ({path})\n"));
            return 1;
        };
        let line = |name: &str, n: &Node| -> String {
            let (t, size) = match n {
                Node::Dir => ('d', 0),
                Node::File(b) => ('-', b.len()),
                Node::Link(_) => ('l', 4),
            };
            let tail = match n {
                Node::Link(target) => format!(" -> {target}"),
                _ => String::new(),
            };
            if self.eight_col_ls {
                format!("{t}rw-r--r-- 1 root {size} Nov  8 12:00 {name}{tail}\n")
            } else {
                format!("{t}rw-r--r-- 1 root root {size} Nov  8 12:00 {name}{tail}\n")
            }
        };
        if flags.contains('d') || !matches!(node, Node::Dir) {
            out.push_str(&line(path, node));
            return 0;
        }
        out.push_str("total 1\n");
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        for (p, n) in self.fs.range(prefix.clone()..) {
            let Some(rest) = p.strip_prefix(&prefix) else {
                break;
            };
            if !rest.is_empty() && !rest.contains('/') {
                out.push_str(&line(rest, n));
            }
        }
        0
    }

    fn run_simple(&mut self, s: &str, out: &mut Vec<u8>, err: &mut String) -> u32 {
        let s = s.trim();
        let words: Vec<&str> = s.split_whitespace().collect();
        let mut o = String::new();
        let rc = match words.as_slice() {
            ["echo", "to-stderr", "1>&2"] => {
                err.push_str("to-stderr\n");
                0
            }
            ["echo", rest @ ..] => {
                o.push_str(&rest.join(" ").replace('"', ""));
                o.push('\n');
                0
            }
            ["true"] => 0,
            ["false"] => 1,
            ["exit", n] => n.parse().unwrap_or(255),
            ["uname", "-a"] => {
                o.push_str("QNX hu-omap 6.5.0 fake armle\n");
                0
            }
            ["id"] => {
                o.push_str("uid=0(root) gid=0(root)\n");
                0
            }
            ["test", "-w", p] => {
                u32::from(self.read_only.iter().any(|ro| p.starts_with(ro.as_str())))
            }
            ["date"] | ["mount"] | ["pidin"] => {
                o.push_str("fake\n");
                0
            }
            ["df", ..] => {
                o.push_str("/dev/hd0 1000 500 500 50% /\n");
                0
            }
            ["ls", flags, paths @ ..] if flags.starts_with('-') => {
                let mut rc = 0;
                for p in paths {
                    rc = rc.max(self.ls(flags, p, &mut o, err));
                }
                rc
            }
            ["ls", paths @ ..] => {
                let mut rc = 0;
                for p in paths {
                    if *p == "/mnt" {
                        o.push_str("umass0\n");
                    } else {
                        rc = rc.max(self.ls("", p, &mut o, err));
                    }
                }
                rc
            }
            ["cat", p] => match self.fs.get(*p) {
                Some(Node::File(b)) => {
                    out.extend_from_slice(b);
                    0
                }
                _ => {
                    err.push_str(&format!("cat: {p}: No such file or directory\n"));
                    1
                }
            },
            ["command", "-v", t] if ["ls", "cat", "on"].contains(t) => {
                o.push_str(&format!("/bin/{t}\n"));
                0
            }
            ["command", "-v", _] => 1,
            ["use", t] => {
                o.push_str(&format!("usage: {t}\n"));
                0
            }
            ["mount", "-o", "remount", mode, "/net/hu-omap/fs/sda0"] => match *mode {
                "rw" => {
                    self.read_only.retain(|r| r != "/opt");
                    0
                }
                "ro" => {
                    if !self.read_only.iter().any(|r| r == "/opt") {
                        self.read_only.push("/opt".into());
                    }
                    0
                }
                _ => 1,
            },
            ["mkdir", p] => self.m_mkdir(p, err),
            ["cp", a, b] => self.m_cp(a, b, err),
            ["chmod", "755", p] => {
                if self.is_ro(p) {
                    err.push_str(&format!("chmod: {p}: Read-only file system\n"));
                    1
                } else if self.fs.contains_key(*p) {
                    0
                } else {
                    err.push_str(&format!("chmod: {p}: No such file or directory\n"));
                    1
                }
            }
            ["mv", a, b] => self.m_mv(a, b, err),
            [prog, ..] => {
                err.push_str(&format!("sh: {prog}: not found\n"));
                127
            }
            [] => 0,
        };
        out.extend_from_slice(o.as_bytes());
        rc
    }

    /// Execute one command (as the remote shell would). Pure: never mutates `fs`.
    pub fn run(&mut self, cmd: &str) -> (Vec<u8>, Vec<u8>, u32) {
        let mut body = cmd;
        if let Some(rest) = body.strip_prefix("on -f /net/hu-omap/ ") {
            if self.on_broken {
                return (Vec::new(), b"on: not supported\n".to_vec(), 1);
            }
            // Real QNX `on` executes a binary directly, without a shell:
            // shell built-ins are not found (observed on the pilot head unit).
            let prog = rest.split_whitespace().next().unwrap_or("");
            if ["echo", "true", "test", "kill", "command", "exit", "cd"].contains(&prog) {
                return (
                    Vec::new(),
                    format!("on: No such file or directory ({prog})\n").into_bytes(),
                    2,
                );
            }
            body = rest;
        }
        if body == crate::guard::QUOTING_PROBE {
            return (b"[a b]\n[c]\n[d'e]\n".to_vec(), Vec::new(), 0);
        }
        let inner = body
            .strip_prefix("/bin/sh -c '")
            .and_then(|r| r.strip_suffix('\''))
            .unwrap_or(body);
        let (mut out, mut err, mut rc) = (Vec::new(), String::new(), 0);
        for seg in inner.split(';') {
            if seg.trim().starts_with("exit ") {
                rc = self.run_simple(seg, &mut out, &mut err);
                break;
            }
            rc = self.run_simple(seg, &mut out, &mut err);
        }
        (out, err.into_bytes(), rc)
    }
}

impl HeadUnitTransport for FakeHu {
    async fn exec(
        &mut self,
        command: &GuardedCommand,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        if self.lose_after.is_some_and(|n| self.seen.len() >= n) {
            return Err(TransportError::ConnectionLost("fake link down".into()));
        }
        self.seen.push(command.as_str().to_owned());
        let started = SystemTime::now();
        if self
            .hang_on
            .as_deref()
            .is_some_and(|h| command.as_str().contains(h))
        {
            return Ok(ExecResult {
                stdout: vec![],
                stderr: vec![],
                stdout_dropped: 0,
                stderr_dropped: 0,
                outcome: ExitOutcome::TimedOut,
                started,
                duration: limits.timeout,
            });
        }
        let (mut stdout, stderr, rc) = self.run(command.as_str());
        let dropped = stdout.len().saturating_sub(limits.max_output) as u64;
        stdout.truncate(limits.max_output);
        Ok(ExecResult {
            stdout,
            stderr,
            stdout_dropped: dropped,
            stderr_dropped: 0,
            outcome: ExitOutcome::Code(rc),
            started,
            duration: Duration::from_millis(1),
        })
    }

    async fn exec_mutating(
        &mut self,
        command: &crate::guard::MutatingCommand,
        _consent: &crate::guard::Consent,
        limits: ExecLimits,
    ) -> Result<ExecResult, TransportError> {
        if self.lose_after.is_some_and(|n| self.seen.len() >= n) {
            return Err(TransportError::ConnectionLost("fake link down".into()));
        }
        self.seen.push(command.as_str().to_owned());
        let started = SystemTime::now();
        if self
            .hang_on
            .as_deref()
            .is_some_and(|h| command.as_str().contains(h))
        {
            return Ok(ExecResult {
                stdout: vec![],
                stderr: vec![],
                stdout_dropped: 0,
                stderr_dropped: 0,
                outcome: ExitOutcome::TimedOut,
                started,
                duration: limits.timeout,
            });
        }
        let (mut stdout, stderr, rc) = self.run(command.as_str());
        stdout.truncate(limits.max_output);
        Ok(ExecResult {
            stdout,
            stderr,
            stdout_dropped: 0,
            stderr_dropped: 0,
            outcome: ExitOutcome::Code(rc),
            started,
            duration: Duration::from_millis(1),
        })
    }
}

#[derive(Default)]
pub struct MemSink {
    pub records: Vec<(ExecRecord, Vec<u8>, Vec<u8>)>,
    pub files: BTreeMap<&'static str, String>,
    pub texts: BTreeMap<String, String>,
    pub fail_at: Option<usize>,
}

impl TranscriptSink for MemSink {
    fn record(&mut self, r: &ExecRecord, stdout: &[u8], stderr: &[u8]) -> Result<(), SinkError> {
        if self.fail_at.is_some_and(|n| self.records.len() + 1 >= n) {
            return Err(SinkError("disk full".into()));
        }
        self.records
            .push((r.clone(), stdout.to_vec(), stderr.to_vec()));
        Ok(())
    }
}

impl Reports for MemSink {
    fn append(&mut self, file: ReportFile, text: &str) -> Result<(), SinkError> {
        self.files
            .entry(file.file_name())
            .or_default()
            .push_str(text);
        Ok(())
    }
    fn write_text(&mut self, name: &SafeName, content: &str) -> Result<(), SinkError> {
        self.texts
            .insert(name.as_str().to_owned(), content.to_owned());
        Ok(())
    }
}

pub struct Usb(pub Option<String>);
impl Interaction for Usb {
    async fn usb_step(&mut self) -> Option<String> {
        self.0.take()
    }
}
