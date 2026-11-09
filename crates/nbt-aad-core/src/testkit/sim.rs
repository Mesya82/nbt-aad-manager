//! Stateful model of the daemon filesystem for write-path tests: read-only
//! until remounted, QNX-like `mkdir`/`cp`/`mv`/`chmod` semantics, and
//! observation in the same form `inspect` produces (listings + digests).

use std::collections::BTreeMap;

use crate::plan::Mutation;
use crate::profile::{HeadUnitProfile, Observation, Rec, ids};
use crate::transport::sha256_hex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimNode {
    Dir,
    File { data: Vec<u8>, mode: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimFs {
    pub nodes: BTreeMap<String, SimNode>,
    /// Paths (prefixes) on the read-only filesystem until remounted.
    pub ro_prefixes: Vec<String>,
    pub remounted: bool,
    /// An `nbt-aad` process is running (autostart / not force-stopped).
    pub daemon_running: bool,
    /// Every mutation applied, in order (the "mutation counter" of AC-01).
    pub applied: Vec<Mutation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimError {
    ReadOnly(String),
    Exists(String),
    NoSuchFile(String),
    NotADirectory(String),
    IsADirectory(String),
    WrongRemount(String),
}

fn parent(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => "",
    }
}

impl SimFs {
    pub fn new(ro_prefixes: &[&str]) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert("/".to_owned(), SimNode::Dir);
        Self {
            nodes,
            ro_prefixes: ro_prefixes.iter().map(|s| (*s).to_owned()).collect(),
            remounted: false,
            daemon_running: false,
            applied: Vec::new(),
        }
    }

    /// Create a directory and all parents (setup only, ignores read-only).
    pub fn mkdirs(&mut self, p: &str) {
        let mut cur = String::new();
        for c in p.split('/').filter(|c| !c.is_empty()) {
            cur.push('/');
            cur.push_str(c);
            self.nodes.entry(cur.clone()).or_insert(SimNode::Dir);
        }
    }

    /// Put a file (setup only).
    pub fn put(&mut self, p: &str, data: &[u8], mode: u32) {
        self.mkdirs(parent(p));
        self.nodes.insert(
            p.to_owned(),
            SimNode::File {
                data: data.to_vec(),
                mode,
            },
        );
    }

    fn writable(&self, p: &str) -> Result<(), SimError> {
        if !self.remounted && self.ro_prefixes.iter().any(|r| p.starts_with(r.as_str())) {
            return Err(SimError::ReadOnly(p.to_owned()));
        }
        Ok(())
    }

    fn need_dir(&self, p: &str) -> Result<(), SimError> {
        match self.nodes.get(p) {
            Some(SimNode::Dir) => Ok(()),
            Some(_) => Err(SimError::NotADirectory(p.to_owned())),
            None => Err(SimError::NoSuchFile(p.to_owned())),
        }
    }

    /// Apply one mutation with QNX-like semantics. A failed mutation leaves
    /// the model unchanged.
    pub fn apply(&mut self, m: &Mutation, expected_remount: &str) -> Result<(), SimError> {
        match m {
            Mutation::Remount { command, .. } => {
                if command != expected_remount {
                    return Err(SimError::WrongRemount(command.clone()));
                }
                self.remounted = true;
            }
            Mutation::Mkdir(p) => {
                self.writable(p)?;
                self.need_dir(parent(p))?;
                if self.nodes.contains_key(p) {
                    return Err(SimError::Exists(p.clone()));
                }
                self.nodes.insert(p.clone(), SimNode::Dir);
            }
            Mutation::Cp { from, to } => {
                self.writable(to)?;
                let data = match self.nodes.get(from) {
                    Some(SimNode::File { data, .. }) => data.clone(),
                    Some(SimNode::Dir) => return Err(SimError::IsADirectory(from.clone())),
                    None => return Err(SimError::NoSuchFile(from.clone())),
                };
                self.need_dir(parent(to))?;
                if matches!(self.nodes.get(to), Some(SimNode::Dir)) {
                    return Err(SimError::IsADirectory(to.clone()));
                }
                // cp from FAT: rw-rw-rw- (observed on the pilot after cp).
                self.nodes
                    .insert(to.clone(), SimNode::File { data, mode: 0o666 });
            }
            Mutation::Chmod755(p) => {
                self.writable(p)?;
                match self.nodes.get_mut(p) {
                    Some(SimNode::File { mode, .. }) => *mode = 0o755,
                    Some(SimNode::Dir) => {}
                    None => return Err(SimError::NoSuchFile(p.clone())),
                }
            }
            Mutation::Mv { from, to } => {
                self.writable(from)?;
                self.writable(to)?;
                if !self.nodes.contains_key(from) {
                    return Err(SimError::NoSuchFile(from.clone()));
                }
                self.need_dir(parent(to))?;
                // The plan must never rely on rename-over-existing: model it
                // as an error so such a plan fails the tests.
                if self.nodes.contains_key(to) {
                    return Err(SimError::Exists(to.clone()));
                }
                let prefix = format!("{from}/");
                let moved: Vec<String> = self
                    .nodes
                    .keys()
                    .filter(|k| *k == from || k.starts_with(&prefix))
                    .cloned()
                    .collect();
                for k in moved {
                    let n = self.nodes.remove(&k).unwrap_or(SimNode::Dir);
                    let nk = format!("{to}{}", &k[from.len()..]);
                    self.nodes.insert(nk, n);
                }
            }
        }
        self.applied.push(m.clone());
        Ok(())
    }

    /// `ls -la` output in the pilot's QNX format, or the exact QNX error.
    fn ls(&self, dir: &str) -> Rec {
        if !matches!(self.nodes.get(dir), Some(SimNode::Dir)) {
            return Rec {
                rc: 1,
                stdout: String::new(),
                stderr: format!("ls: No such file or directory ({dir})\n"),
            };
        }
        let mut out = String::from("total 1\n");
        out.push_str("drwxrwxrwx  2 root      root           4096 Nov 09 13:39 .\n");
        out.push_str("drwxrwxrwx  2 root      root           4096 Nov 09 13:39 ..\n");
        let prefix = if dir == "/" {
            "/".to_owned()
        } else {
            format!("{dir}/")
        };
        for (k, n) in &self.nodes {
            let Some(name) = k.strip_prefix(&prefix) else {
                continue;
            };
            if name.is_empty() || name.contains('/') {
                continue;
            }
            match n {
                SimNode::Dir => out.push_str(&format!(
                    "drwxrwxrwx  2 root      root           4096 Nov 09 13:39 {name}\n"
                )),
                SimNode::File { data, mode } => {
                    let m = if *mode & 0o111 != 0 {
                        "-rwxr-xr-x"
                    } else {
                        "-rw-rw-rw-"
                    };
                    out.push_str(&format!(
                        "{m}  1 root      root   {:>12} Nov 09 13:39 {name}\n",
                        data.len()
                    ));
                }
            }
        }
        Rec {
            rc: 0,
            stdout: out,
            stderr: String::new(),
        }
    }

    /// What `inspect` would observe (listings + host-side digests of every
    /// listed file in the three inspected directories).
    pub fn observe(&self, p: &HeadUnitProfile) -> Observation {
        let mut o = Observation::default();
        for (id, dir) in [
            (ids::LS_DAEMON_DIR, p.daemon_dir),
            (ids::LS_PLUGIN, p.plugin_dir),
            (ids::LS_PLUGIN_BACKUP, p.plugin_backup_dir),
        ] {
            o.records.insert(id.to_owned(), self.ls(dir));
            let prefix = format!("{dir}/");
            for (k, n) in &self.nodes {
                if let (Some(name), SimNode::File { data, .. }) = (k.strip_prefix(&prefix), n)
                    && !name.contains('/')
                {
                    o.digests
                        .insert(k.clone(), (data.len() as u64, sha256_hex(data)));
                }
            }
        }
        o
    }

    /// A head-unit restart: the remount is lost (observed on the pilot).
    /// Files are kept as they were (the model assumes durable mutations).
    pub fn restart(&mut self) {
        self.remounted = false;
    }

    /// Content of a file, if present.
    pub fn file(&self, p: &str) -> Option<&[u8]> {
        match self.nodes.get(p) {
            Some(SimNode::File { data, .. }) => Some(data),
            _ => None,
        }
    }
}

impl SimFs {
    /// Read-only check of a plan verification against the model.
    pub fn check(&self, v: &crate::plan::Verify) -> bool {
        use crate::plan::Verify;
        match v {
            Verify::Writable(_) => self.remounted,
            Verify::DirExists(p) => matches!(self.nodes.get(p), Some(SimNode::Dir)),
            Verify::Absent(p) => !self.nodes.contains_key(p),
            Verify::Digest { path, size, sha256 } => self
                .file(path)
                .is_some_and(|d| d.len() as u64 == *size && sha256_hex(d) == *sha256),
            Verify::ModeExecutable(p) => {
                matches!(self.nodes.get(p), Some(SimNode::File { mode, .. }) if mode & 0o111 != 0)
            }
            Verify::Content { path, data } => self.file(path) == Some(data.as_slice()),
            Verify::DaemonNotRunning => !self.daemon_running,
            // Never satisfied automatically.
            Verify::Operator(_) => false,
        }
    }
}

/// The simulator as an apply-engine executor, with failure injection.
pub struct SimExecutor {
    pub fs: SimFs,
    pub remount: &'static str,
    /// Fail (without effect) the N-th mutation (0-based).
    pub fail_at: Option<usize>,
    /// Apply the N-th mutation but report an error (lost reply).
    pub ambiguous_at: Option<usize>,
    /// Make the N-th check return an error (device could not tell).
    pub check_error_at: Option<usize>,
    pub executed: usize,
    pub checks: usize,
}

impl SimExecutor {
    pub fn new(fs: SimFs, remount: &'static str) -> Self {
        Self {
            fs,
            remount,
            fail_at: None,
            ambiguous_at: None,
            check_error_at: None,
            executed: 0,
            checks: 0,
        }
    }
}

impl crate::journal::Executor for SimExecutor {
    fn exec(&mut self, m: &Mutation) -> Result<(), String> {
        let n = self.executed;
        self.executed += 1;
        if self.fail_at == Some(n) {
            return Err("injected failure".into());
        }
        let r = self.fs.apply(m, self.remount).map_err(|e| format!("{e:?}"));
        if self.ambiguous_at == Some(n) && r.is_ok() {
            return Err("injected: reply lost after the mutation ran".into());
        }
        r
    }
    fn verify(&mut self, v: &crate::plan::Verify) -> Result<bool, String> {
        let n = self.checks;
        self.checks += 1;
        if self.check_error_at == Some(n) {
            return Err("injected: check could not be performed".into());
        }
        Ok(self.fs.check(v))
    }
}

/// In-memory journal store with fault injection.
#[derive(Default, Clone)]
pub struct MemStore {
    pub text: String,
    /// Fail the N-th append (0-based). With `torn`, half the line is
    /// written first (crash during append).
    pub fail_at: Option<usize>,
    pub torn: bool,
    pub appends: usize,
}

impl crate::journal::JournalStore for MemStore {
    fn append(&mut self, line: &str) -> Result<(), crate::journal::StoreError> {
        if self.fail_at == Some(self.appends) {
            self.appends += 1;
            if self.torn {
                self.text.push_str(&line[..line.len() / 2]);
            }
            return Err(crate::journal::StoreError::Io("injected".into()));
        }
        self.appends += 1;
        self.text.push_str(line);
        Ok(())
    }
    fn load(&self) -> Result<String, crate::journal::StoreError> {
        Ok(self.text.clone())
    }
    fn drop_torn_tail(&mut self) -> Result<(), crate::journal::StoreError> {
        let keep = self.text.rfind('\n').map_or(0, |i| i + 1);
        self.text.truncate(keep);
        Ok(())
    }
}

/// A complete scenario: the pilot layout after an upstream update
/// (`old` active, upstream-style foreign backup `older`, protected env) and
/// a USB stick prepared for `new`, with synthetic pins for all three.
pub mod scenario {
    use super::SimFs;
    use crate::release::{FileDigest, KnownRelease, PLUGIN_FILES};
    use crate::transport::sha256_hex;

    pub const OP: &str = "20261109T170000Z-abc123";
    pub const USB: &str = "/mnt/umass0";
    pub const PD: &str = "/opt/hmi/ID5/data/ro/Plugins/NbtAad";
    pub const ENV: &[u8] = b"NBT_ALT_WIFI=CARPLAY\n";

    pub fn content(tag: &str, n: &str) -> Vec<u8> {
        format!("{tag} {n} payload\n").into_bytes()
    }

    fn fd(tag: &str, n: &'static str) -> FileDigest {
        let d = content(tag, n);
        FileDigest {
            name: n,
            size: d.len() as u64,
            sha256: Box::leak(sha256_hex(&d).into_boxed_str()),
        }
    }

    fn pin(tag: &'static str) -> KnownRelease {
        KnownRelease {
            tag,
            title: tag,
            daemon_build: "Build: v0",
            plugin_marker: "rhmiapp-0",
            daemon: fd(tag, "nbt-aad"),
            archive: fd(tag, "Releases.zip"),
            plugin: PLUGIN_FILES.map(|n| fd(tag, n)),
        }
    }

    pub fn table() -> &'static [KnownRelease] {
        static T: std::sync::LazyLock<Vec<KnownRelease>> =
            std::sync::LazyLock::new(|| vec![pin("older"), pin("old"), pin("new")]);
        T.as_slice()
    }

    pub fn unit() -> SimFs {
        let mut fs = SimFs::new(&["/opt"]);
        fs.put("/opt/aa/nbt-aad", &content("old", "nbt-aad"), 0o777);
        fs.put("/opt/aa/nbt-aad.old", &content("older", "nbt-aad"), 0o777);
        fs.put("/opt/aa/nbt-aad.env", ENV, 0o666);
        for n in PLUGIN_FILES {
            fs.put(&format!("{PD}/{n}"), &content("old", n), 0o666);
            fs.put(
                &format!("/opt/aa/NbtAad.old/{n}"),
                &content("older", n),
                0o666,
            );
        }
        let usb = format!("{USB}/nbt-aad-{OP}");
        fs.put(&format!("{usb}/nbt-aad"), &content("new", "nbt-aad"), 0o666);
        for n in PLUGIN_FILES {
            fs.put(&format!("{usb}/Releases/{n}"), &content("new", n), 0o666);
        }
        fs.put(&format!("{usb}/MANIFEST"), b"op\n", 0o666);
        fs.put(
            &format!("{usb}/COMPLETE"),
            crate::plan::complete_marker(OP).as_bytes(),
            0o666,
        );
        fs
    }

    pub type Snapshot = Vec<(String, Option<Vec<u8>>)>;

    /// Everything outside the plan's reach, byte for byte.
    pub fn untouchable(fs: &SimFs) -> Snapshot {
        let mut paths = vec![
            "/opt/aa/nbt-aad.env".to_owned(),
            "/opt/aa/nbt-aad.old".to_owned(),
        ];
        paths.extend(
            PLUGIN_FILES
                .iter()
                .map(|n| format!("/opt/aa/NbtAad.old/{n}")),
        );
        paths
            .into_iter()
            .map(|p| {
                let d = fs.file(&p).map(<[u8]>::to_vec);
                (p, d)
            })
            .collect()
    }

    /// Active daemon + plugin bytes (to compare with the original).
    pub fn active(fs: &SimFs) -> Snapshot {
        let mut paths = vec!["/opt/aa/nbt-aad".to_owned()];
        paths.extend(PLUGIN_FILES.iter().map(|n| format!("{PD}/{n}")));
        paths
            .into_iter()
            .map(|p| {
                let d = fs.file(&p).map(<[u8]>::to_vec);
                (p, d)
            })
            .collect()
    }
}
