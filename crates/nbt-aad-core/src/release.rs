//! Exact-digest release allowlist and archive layout validation (sans-IO).
//!
//! Upstream releases are non-SemVer, their titles, tags and embedded version
//! strings disagree (tag `gps`, title "v1.9.35-combined-prs", binary
//! `Build: v1.9.36-combo`), and asset names vary in case. Identification is
//! therefore by exact SHA-256 of every file, never by name or ordering.
//! Anything not in [`KNOWN`] is unknown and must stop a write workflow.

/// One file with its exact size and SHA-256 (lowercase hex).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDigest {
    pub name: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

/// The five plugin file names, exact case, in the order used below.
pub const PLUGIN_FILES: [&str; 5] = [
    "NbtAad.manifest",
    "NbtAad.xml",
    "NbtAad_ALL_Images.zip",
    "NbtAad_ALL_Texts.zip",
    "libNbtAad.so",
];

/// Archive top-level directory names observed upstream.
pub const ARCHIVE_DIRS: [&str; 4] = ["Release", "release", "Releases", "releases"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownRelease {
    /// GitHub release tag (the only stable key upstream offers).
    pub tag: &'static str,
    /// Release title at the time of pinning (informational only).
    pub title: &'static str,
    /// `Build: …` string embedded in the daemon (informational only).
    pub daemon_build: &'static str,
    /// `rhmiapp-…` marker in `libNbtAad.so` (informational only).
    pub plugin_marker: &'static str,
    /// GitHub asset `nbt-aad`.
    pub daemon: FileDigest,
    /// GitHub plugin archive asset (name as published).
    pub archive: FileDigest,
    /// Plugin files, in [`PLUGIN_FILES`] order.
    pub plugin: [FileDigest; 5],
}

const fn f(name: &'static str, size: u64, sha256: &'static str) -> FileDigest {
    FileDigest { name, size, sha256 }
}

/// Releases whose every file was digest-verified against GitHub asset digests
/// and archive contents, and observed installed on the pilot car
/// (`tests/fixtures/pilot-g31/run4-*`, `docs/UPSTREAM_RESEARCH.md`).
pub const KNOWN: &[KnownRelease] = &[
    KnownRelease {
        tag: "volsliderfixforreal",
        title: "[STABLE]  Volume Slider Fix - v1.9.18",
        daemon_build: "Build: v1.9.18-osd1281",
        plugin_marker: "rhmiapp-36-overlays",
        daemon: f(
            "nbt-aad",
            731_847,
            "8b4b45be0e213f0bc2039c1ae99d1b4775fc70567f364d52111980383412b81c",
        ),
        archive: f(
            "Releases.zip",
            90_850,
            "547921567f0836112ffaa85a54ca30f64ede4333b9e78014b36da535e6a34d3f",
        ),
        plugin: [
            f(
                "NbtAad.manifest",
                568,
                "cc09123717fea5c41698c1ff4c08b4cd5dde620fda1b3d00b0e8699a3c621af2",
            ),
            f(
                "NbtAad.xml",
                6_713,
                "e051c9bd0668794f23fc707460d27c327d43d0bce1a2e52e7d3b2bcaa69ba585",
            ),
            f(
                "NbtAad_ALL_Images.zip",
                55_671,
                "38539939b8cf14343176e765d82144447918e6f26298f813fa6597381537047c",
            ),
            f(
                "NbtAad_ALL_Texts.zip",
                4_682,
                "27f23c24c68bb7036be7db271140e4d1ba745c377b34bc3539b964113a756503",
            ),
            f(
                "libNbtAad.so",
                66_843,
                "3704116418d8bd6048732c3813126317b34a14774c0792c4a7173e78c6276f15",
            ),
        ],
    },
    KnownRelease {
        tag: "gps",
        title: "v1.9.35-combined-prs",
        daemon_build: "Build: v1.9.36-combo",
        plugin_marker: "rhmiapp-43-combo",
        daemon: f(
            "nbt-aad",
            773_142,
            "1ec14876503b0bac597e8871b7099deb334c6401e3696bd2d8cf2db8cbc972b3",
        ),
        archive: f(
            "Releases.zip",
            92_668,
            "02baed4a40ec4ac53bbafe5cdfacd96d0280af3c9d2e88e3e767d77906cf1f92",
        ),
        plugin: [
            f(
                "NbtAad.manifest",
                568,
                "cc09123717fea5c41698c1ff4c08b4cd5dde620fda1b3d00b0e8699a3c621af2",
            ),
            f(
                "NbtAad.xml",
                7_924,
                "830f8ae13e0914acc4eb1a3e35c36de72d733cbcfb16d717557ad7f24d67896d",
            ),
            f(
                "NbtAad_ALL_Images.zip",
                55_671,
                "38539939b8cf14343176e765d82144447918e6f26298f813fa6597381537047c",
            ),
            f(
                "NbtAad_ALL_Texts.zip",
                4_914,
                "05b4bc49f51cf2662b97830947c02faaa03e30f3671f1989d790e292c8049783",
            ),
            f(
                "libNbtAad.so",
                71_008,
                "becea0044b79a683420c16caa32c51cef3d1d4d54a89335071c57b44d57b6b06",
            ),
        ],
    },
];

/// An observed file: name as listed, size and host-computed SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identification {
    /// Daemon and all five plugin files match one known release exactly.
    Known(&'static KnownRelease),
    /// Daemon and plugin each match a known release, but different ones.
    Mixed {
        daemon: &'static KnownRelease,
        plugin: &'static KnownRelease,
    },
    /// Anything else. Carries the reasons; a write workflow must stop.
    Unknown(Vec<String>),
}

fn same(o: &Observed, k: &FileDigest) -> bool {
    o.name == k.name && o.size == k.size && o.sha256.eq_ignore_ascii_case(k.sha256)
}

fn plugin_match(plugin: &[Observed], k: &KnownRelease) -> bool {
    plugin.len() == 5 && k.plugin.iter().all(|kf| plugin.iter().any(|o| same(o, kf)))
}

/// Identify an installed (or staged) daemon + plugin set by exact digests.
/// Extra, missing, renamed or case-variant plugin files make it unknown.
pub fn identify(daemon: &Observed, plugin: &[Observed]) -> Identification {
    let d = KNOWN.iter().find(|k| same(daemon, &k.daemon));
    let p = KNOWN.iter().find(|k| plugin_match(plugin, k));
    match (d, p) {
        (Some(d), Some(p)) if d.tag == p.tag => Identification::Known(d),
        (Some(daemon), Some(plugin)) => Identification::Mixed { daemon, plugin },
        (d, p) => {
            let mut why = Vec::new();
            if d.is_none() {
                why.push(format!(
                    "daemon {} ({} bytes) matches no known release",
                    daemon.name, daemon.size
                ));
            }
            if p.is_none() {
                why.push(format!(
                    "plugin set ({} files) matches no known release",
                    plugin.len()
                ));
            }
            Identification::Unknown(why)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutError {
    UnsafePath(String),
    NoTopDir,
    UnknownTopDir(String),
    SeveralTopDirs,
    Unexpected(String),
    Missing(&'static str),
    Duplicate(String),
}

/// Validate a plugin archive's entry list (names as stored; a trailing `/`
/// marks a directory). Accepts exactly one allowlisted top directory holding
/// exactly the five plugin files in exact case, and nothing else. Returns the
/// top directory name.
pub fn validate_archive_layout(entries: &[&str]) -> Result<String, LayoutError> {
    let mut top: Option<&str> = None;
    let mut seen: Vec<&str> = Vec::new();
    for &e in entries {
        if e.is_empty()
            || e.starts_with('/')
            || e.contains('\\')
            || e.contains('\0')
            || e.split('/').any(|c| c == ".." || c == ".")
        {
            return Err(LayoutError::UnsafePath(e.to_owned()));
        }
        let (dir, rest) = e.split_once('/').ok_or(LayoutError::NoTopDir)?;
        if !ARCHIVE_DIRS.contains(&dir) {
            return Err(LayoutError::UnknownTopDir(dir.to_owned()));
        }
        match top {
            None => top = Some(dir),
            Some(t) if t != dir => return Err(LayoutError::SeveralTopDirs),
            Some(_) => {}
        }
        if rest.is_empty() {
            continue; // the directory entry itself
        }
        if !PLUGIN_FILES.contains(&rest) {
            return Err(LayoutError::Unexpected(e.to_owned()));
        }
        if seen.contains(&rest) {
            return Err(LayoutError::Duplicate(e.to_owned()));
        }
        seen.push(rest);
    }
    let top = top.ok_or(LayoutError::NoTopDir)?;
    for name in PLUGIN_FILES {
        if !seen.contains(&name) {
            return Err(LayoutError::Missing(name));
        }
    }
    Ok(top.to_owned())
}

#[cfg(test)]
mod tests;
