//! Fetch a pinned upstream NBT-AAD release and verify it before it touches
//! disk in its final place.
//!
//! Order of trust: the compiled-in pin table ([`nbt_aad_core::release::KNOWN`])
//! is the only authority. GitHub metadata must agree with the pin *before*
//! any download; downloaded bytes must match the pin; the archive must have
//! the allowlisted layout and every extracted file must match the pin. Only
//! then is the staging directory renamed into place. Every read is bounded.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nbt_aad_core::release::{
    self, AssetMeta, KnownRelease, ReleaseMeta, VerifyError, select_assets,
    verify_archive_contents, verify_blob,
};
use serde::Deserialize;

/// Upper bounds for everything read from the network or an archive.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_metadata: u64,
    pub max_asset: u64,
    pub max_entries: usize,
    pub max_entry: u64,
    pub max_uncompressed_total: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_metadata: 2 * 1024 * 1024,
            max_asset: 64 * 1024 * 1024,
            max_entries: 32,
            max_entry: 32 * 1024 * 1024,
            max_uncompressed_total: 64 * 1024 * 1024,
        }
    }
}

/// Where to fetch from.
#[derive(Clone, Debug)]
pub struct Source {
    /// `https://api.github.com`
    pub api_base: String,
    /// `Sq00ky/Supra-iDrive6-Android-Auto`
    pub repo: String,
    /// Every asset URL must start with this (checked before download).
    pub download_prefix: String,
    /// Tests only: allow `http://127.0.0.1` URLs. Never set by the CLI.
    pub allow_http_loopback: bool,
}

pub const UPSTREAM_REPO: &str = "Sq00ky/Supra-iDrive6-Android-Auto";

impl Source {
    pub fn upstream() -> Self {
        Self {
            api_base: "https://api.github.com".into(),
            repo: UPSTREAM_REPO.into(),
            download_prefix: format!("https://github.com/{UPSTREAM_REPO}/releases/download/"),
            allow_http_loopback: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("refusing URL {0:?} (not under the allowed prefix or scheme)")]
    UrlRefused(String),
    #[error("HTTP error for {url}: {msg}")]
    Http { url: String, msg: String },
    #[error("release metadata is not valid: {0}")]
    Metadata(String),
    #[error("archive rejected: {0}")]
    Archive(String),
    #[error("output {0} already exists; refusing to overwrite")]
    Exists(PathBuf),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Minimal HTTP GET with a hard byte cap. Implemented with `ureq` for real
/// use; tests may substitute their own.
pub trait Http {
    fn get(&mut self, url: &str, accept: &str, max_bytes: u64) -> Result<Vec<u8>, FetchError>;
}

/// `ureq`-based client (rustls + ring, webpki roots).
pub struct UreqHttp {
    agent: ureq::Agent,
}

impl UreqHttp {
    pub fn new(allow_http: bool) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(!allow_http)
            .timeout_global(Some(Duration::from_secs(300)))
            .max_redirects(5)
            .user_agent(concat!("nbt-aad-manager/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent }
    }
}

impl Http for UreqHttp {
    fn get(&mut self, url: &str, accept: &str, max_bytes: u64) -> Result<Vec<u8>, FetchError> {
        let err = |e: ureq::Error| FetchError::Http {
            url: url.into(),
            msg: e.to_string(),
        };
        let mut resp = self
            .agent
            .get(url)
            .header("Accept", accept)
            .call()
            .map_err(err)?;
        resp.body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(err)
    }
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    size: u64,
    digest: Option<String>,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    draft: bool,
    assets: Vec<GhAsset>,
}

/// Parse GitHub's `GET /repos/{repo}/releases/tags/{tag}` response.
pub fn parse_release_json(body: &[u8]) -> Result<ReleaseMeta, FetchError> {
    let r: GhRelease =
        serde_json::from_slice(body).map_err(|e| FetchError::Metadata(e.to_string()))?;
    Ok(ReleaseMeta {
        tag: r.tag_name,
        draft: r.draft,
        assets: r
            .assets
            .into_iter()
            .map(|a| AssetMeta {
                name: a.name,
                size: a.size,
                digest: a.digest,
                url: a.browser_download_url,
            })
            .collect(),
    })
}

/// Whether anything (file, directory, symlink — even dangling) is at `p`.
/// Errors other than "not found" fail closed.
fn occupied(p: &Path) -> Result<bool, FetchError> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(FetchError::Io {
            path: p.to_owned(),
            source: e,
        }),
    }
}

fn write_synced(p: &Path, data: &[u8]) -> Result<(), FetchError> {
    use std::io::Write;
    let mut f = std::fs::File::create(p).map_err(io(p))?;
    f.write_all(data).map_err(io(p))?;
    f.sync_all().map_err(io(p))
}

/// Persist directory entries (Unix); a no-op where directories cannot be
/// opened for syncing.
fn sync_dir(p: &Path) -> Result<(), FetchError> {
    #[cfg(unix)]
    {
        std::fs::File::open(p)
            .and_then(|d| d.sync_all())
            .map_err(io(p))?;
    }
    #[cfg(not(unix))]
    let _ = p;
    Ok(())
}

fn url_allowed(src: &Source, url: &str) -> bool {
    let scheme_ok = url.starts_with("https://")
        || (src.allow_http_loopback && url.starts_with("http://127.0.0.1:"));
    scheme_ok && !url.contains("..") && !url.contains('@')
}

/// Read a ZIP with hard limits. Directory entries are returned with a
/// trailing `/` and no data. Encrypted entries, symlinks, non-UTF-8 or
/// unsafe names and anything over the limits are rejected.
pub fn read_zip(bytes: &[u8], limits: &Limits) -> Result<Vec<(String, Vec<u8>)>, FetchError> {
    let bad = |m: String| FetchError::Archive(m);
    let mut z = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| bad(e.to_string()))?;
    if z.len() > limits.max_entries {
        return Err(bad(format!(
            "{} entries (max {})",
            z.len(),
            limits.max_entries
        )));
    }
    let mut total = 0u64;
    let mut out = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(|e| bad(format!("entry {i}: {e}")))?;
        let name = f
            .name()
            .map_err(|e| bad(format!("entry {i}: unreadable name: {e}")))?
            .into_owned();
        if f.encrypted() {
            return Err(bad(format!("{name:?} is encrypted")));
        }
        if f.is_symlink() {
            return Err(bad(format!("{name:?} is a symlink")));
        }
        match f.enclosed_name() {
            Some(p)
                if p.to_str().map(|s| s.replace('\\', "/"))
                    == Some(name.trim_end_matches('/').to_owned()) => {}
            _ => return Err(bad(format!("unsafe entry name {name:?}"))),
        }
        if f.is_dir() {
            out.push((name, Vec::new()));
            continue;
        }
        if f.size() > limits.max_entry {
            return Err(bad(format!("{name:?} declares {} bytes", f.size())));
        }
        let mut data = Vec::new();
        (&mut f)
            .take(limits.max_entry + 1)
            .read_to_end(&mut data)
            .map_err(|e| bad(format!("{name:?}: {e}")))?;
        if data.len() as u64 > limits.max_entry || data.len() as u64 != f.size() {
            return Err(bad(format!("{name:?}: size does not match its header")));
        }
        total += data.len() as u64;
        if total > limits.max_uncompressed_total {
            return Err(bad("archive expands beyond the limit".into()));
        }
        out.push((name, data));
    }
    Ok(out)
}

/// A verified, staged release.
#[derive(Debug)]
pub struct Fetched {
    pub tag: &'static str,
    pub dir: PathBuf,
    /// `sha256  relative/path` lines, as written to `SHA256SUMS`.
    pub sums: String,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> FetchError + '_ {
    move |source| FetchError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Fetch `tag` (must be pinned in `table`), verify everything, and stage it as
/// `<out>/<tag>/{nbt-aad, Releases/<5 files>, <archive>, SHA256SUMS}`.
/// Nothing appears at the final path unless every check passed.
pub fn fetch(
    http: &mut dyn Http,
    src: &Source,
    table: &'static [KnownRelease],
    tag: &str,
    out: &Path,
    limits: &Limits,
) -> Result<Fetched, FetchError> {
    let known =
        release::find_known(table, tag).ok_or_else(|| VerifyError::UnknownTag(tag.to_owned()))?;
    let final_dir = out.join(known.tag);
    if occupied(&final_dir)? {
        return Err(FetchError::Exists(final_dir));
    }

    let meta_url = format!(
        "{}/repos/{}/releases/tags/{}",
        src.api_base, src.repo, known.tag
    );
    if !url_allowed(src, &meta_url) {
        return Err(FetchError::UrlRefused(meta_url));
    }
    let body = http.get(
        &meta_url,
        "application/vnd.github+json",
        limits.max_metadata,
    )?;
    let meta = parse_release_json(&body)?;
    let sel = select_assets(table, known.tag, &meta)?;

    let mut get = |a: &AssetMeta| -> Result<Vec<u8>, FetchError> {
        // Defense in depth (the digest is checked anyway): the URL must be
        // this tag's asset of this name under the allowed prefix. Redirects
        // (GitHub serves assets from another host) stay https-only.
        let suffix = format!("/{}/{}", known.tag, a.name);
        if !url_allowed(src, &a.url)
            || !a.url.starts_with(&src.download_prefix)
            || !a.url.ends_with(&suffix)
        {
            return Err(FetchError::UrlRefused(a.url.clone()));
        }
        // ureq treats a body equal to the limit as over it; the exact size
        // is enforced by verify_blob afterwards.
        http.get(
            &a.url,
            "application/octet-stream",
            a.size.min(limits.max_asset) + 1,
        )
    };
    let daemon = get(&sel.daemon)?;
    verify_blob(&known.daemon, &daemon)?;
    let archive = get(&sel.archive)?;
    verify_blob(&known.archive, &archive)?;
    let entries = read_zip(&archive, limits)?;
    let plugin = verify_archive_contents(known, &entries)?;

    // Stage in a unique directory (removed automatically on any failure),
    // fsync, re-read, then rename into place only if the target is still free.
    std::fs::create_dir_all(out).map_err(io(out))?;
    let tmp = tempfile::Builder::new()
        .prefix(&format!(".{}.partial-", known.tag))
        .tempdir_in(out)
        .map_err(io(out))?;
    let staging = tmp.path().to_owned();
    let rel = staging.join("Releases");
    std::fs::create_dir(&rel).map_err(io(&rel))?;
    let mut sums = String::new();
    let mut write = |relpath: &str, data: &[u8], sha: &str| -> Result<(), FetchError> {
        write_synced(&staging.join(relpath), data)?;
        sums.push_str(&format!("{sha}  {relpath}\n"));
        Ok(())
    };
    write("nbt-aad", &daemon, known.daemon.sha256)?;
    for ((name, data), fd) in plugin.iter().zip(known.plugin.iter()) {
        write(&format!("Releases/{name}"), data, fd.sha256)?;
    }
    write(known.archive.name, &archive, known.archive.sha256)?;
    write_synced(&staging.join("SHA256SUMS"), sums.as_bytes())?;
    sync_dir(&rel)?;
    sync_dir(&staging)?;

    // Re-read what was written before declaring success.
    for line in sums.lines() {
        let (sha, relpath) = line.split_once("  ").unwrap_or_default();
        let p = staging.join(relpath);
        let data = std::fs::read(&p).map_err(io(&p))?;
        if nbt_aad_core::transport::sha256_hex(&data) != sha {
            return Err(FetchError::Archive(format!(
                "{relpath}: re-read digest differs"
            )));
        }
    }
    // Re-check right before the rename (another process may have created
    // the target during the download). A remaining race window is between
    // this check and the rename; on Unix an existing non-empty directory
    // makes the rename fail rather than be replaced.
    if occupied(&final_dir)? {
        return Err(FetchError::Exists(final_dir));
    }
    let staging = tmp.keep();
    if let Err(e) = std::fs::rename(&staging, &final_dir) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(FetchError::Io {
            path: final_dir,
            source: e,
        });
    }
    sync_dir(out)?;
    Ok(Fetched {
        tag: known.tag,
        dir: final_dir,
        sums,
    })
}
