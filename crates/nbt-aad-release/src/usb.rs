//! Host-side USB preparation (workflow B): copy a fetched release onto a
//! user-chosen stick as `nbt-aad-<op>/`, re-verified against the pin.
//!
//! Never formats, deletes or overwrites anything on the stick: everything is
//! staged in a unique hidden directory next to the target, verified by
//! re-reading, and renamed into place only if the target name (compared
//! case-insensitively, as FAT/exFAT do) is still free.

use std::path::{Path, PathBuf};

use nbt_aad_core::release::{KnownRelease, find_known, verify_blob};

use crate::{FetchError, occupied, sync_dir, write_synced};

/// Files the plan copies from `<usb>/nbt-aad-<op>/`.
pub const MANIFEST: &str = "MANIFEST";
pub const COMPLETE: &str = "COMPLETE";

#[derive(Debug)]
pub struct Prepared {
    pub dir: PathBuf,
    pub manifest: String,
}

fn valid_op_id(op: &str) -> bool {
    // Same shape as nbt_aad_core::plan (YYYYMMDDTHHMMSSZ-xxxxxx).
    let b = op.as_bytes();
    b.len() == 23
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'Z'
        && b[16] == b'-'
        && b[17..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Re-read a fetched release directory (`release fetch` output) and verify
/// every payload file against the pin. `SHA256SUMS` is not trusted.
pub fn load_fetched(
    known: &KnownRelease,
    dir: &Path,
) -> Result<Vec<(String, Vec<u8>)>, FetchError> {
    let read = |rel: &str| -> Result<Vec<u8>, FetchError> {
        let p = dir.join(rel);
        std::fs::read(&p).map_err(|source| FetchError::Io { path: p, source })
    };
    let mut out = Vec::new();
    let d = read("nbt-aad")?;
    verify_blob(&known.daemon, &d)?;
    out.push(("nbt-aad".to_owned(), d));
    for f in &known.plugin {
        let rel = format!("Releases/{}", f.name);
        let d = read(&rel)?;
        verify_blob(f, &d)?;
        out.push((rel, d));
    }
    Ok(out)
}

/// The text of `MANIFEST` (also binds the stick to one operation).
pub fn manifest_text(known: &KnownRelease, op: &str, files: &[(String, Vec<u8>)]) -> String {
    let mut s = format!("nbt-aad-manager operation {op}\nrelease {}\n", known.tag);
    for (rel, d) in files {
        s.push_str(&format!(
            "{}  {}\n",
            nbt_aad_core::transport::sha256_hex(d),
            rel
        ));
    }
    s
}

/// Stage `<usb_root>/nbt-aad-<op>/` from a fetched release of `tag`.
pub fn prepare(
    table: &'static [KnownRelease],
    tag: &str,
    fetched_dir: &Path,
    usb_root: &Path,
    op: &str,
) -> Result<Prepared, FetchError> {
    let known = find_known(table, tag)
        .ok_or_else(|| nbt_aad_core::release::VerifyError::UnknownTag(tag.to_owned()))?;
    if !valid_op_id(op) {
        return Err(FetchError::Archive(format!("invalid operation id {op:?}")));
    }
    if !usb_root.is_dir() {
        return Err(FetchError::Io {
            path: usb_root.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "USB root is not a directory",
            ),
        });
    }
    let name = format!("nbt-aad-{op}");
    let final_dir = usb_root.join(&name);
    let taken = |root: &Path| -> Result<bool, FetchError> {
        if occupied(&root.join(&name))? {
            return Ok(true);
        }
        // FAT/exFAT are case-insensitive: refuse any case variant too.
        let rd = std::fs::read_dir(root).map_err(|source| FetchError::Io {
            path: root.to_owned(),
            source,
        })?;
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().eq_ignore_ascii_case(&name) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if taken(usb_root)? {
        return Err(FetchError::Exists(final_dir));
    }

    let files = load_fetched(known, fetched_dir)?;
    let manifest = manifest_text(known, op, &files);

    let tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}.partial-"))
        .tempdir_in(usb_root)
        .map_err(|source| FetchError::Io {
            path: usb_root.to_owned(),
            source,
        })?;
    let staging = tmp.path().to_owned();
    let rel = staging.join("Releases");
    std::fs::create_dir(&rel).map_err(|source| FetchError::Io {
        path: rel.clone(),
        source,
    })?;
    for (relpath, d) in &files {
        write_synced(&staging.join(relpath), d)?;
    }
    write_synced(&staging.join(MANIFEST), manifest.as_bytes())?;
    write_synced(
        &staging.join(COMPLETE),
        nbt_aad_core::plan::complete_marker(op).as_bytes(),
    )?;
    sync_dir(&rel)?;
    sync_dir(&staging)?;

    // Re-read everything from the stick before declaring it ready.
    let reread = load_fetched(known, &staging)?;
    if manifest_text(known, op, &reread) != manifest {
        return Err(FetchError::Archive("USB re-read differs".into()));
    }
    if taken(usb_root)? {
        return Err(FetchError::Exists(final_dir));
    }
    let staging = tmp.keep();
    if let Err(source) = std::fs::rename(&staging, &final_dir) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(FetchError::Io {
            path: final_dir,
            source,
        });
    }
    sync_dir(usb_root)?;
    Ok(Prepared {
        dir: final_dir,
        manifest,
    })
}

#[cfg(test)]
mod tests;
