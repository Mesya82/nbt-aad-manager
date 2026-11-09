//! `release` commands: list the pinned allowlist, fetch + verify a pinned
//! release into a local staging directory. Host-side only; nothing here
//! talks to a head unit.

use std::path::PathBuf;
use std::process::ExitCode;

use nbt_aad_core::release::KNOWN;
use nbt_aad_release::{Limits, Source, UreqHttp, fetch};

#[derive(clap::Subcommand)]
pub enum ReleaseCmd {
    /// List the pinned releases (exact digests; the only ones accepted).
    Known,
    /// Download a pinned release from GitHub, verify every file against the
    /// pin and stage it as `<out>/<tag>/` (USB layout: `nbt-aad`, `Releases/`).
    Fetch {
        /// Exact release tag, e.g. `gps`. Titles and versions are not accepted.
        #[arg(long)]
        tag: String,
        /// Directory in which `<tag>/` is created (never overwritten).
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
}

pub fn main(cmd: ReleaseCmd) -> ExitCode {
    match cmd {
        ReleaseCmd::Known => {
            for k in KNOWN {
                println!("{}", k.tag);
                println!("  title:  {}", k.title.trim());
                println!(
                    "  daemon: {} ({} bytes) sha256 {}",
                    k.daemon_build, k.daemon.size, k.daemon.sha256
                );
                println!(
                    "  plugin: {} (libNbtAad.so sha256 {})",
                    k.plugin_marker, k.plugin[4].sha256
                );
                println!("  archive: {} sha256 {}", k.archive.name, k.archive.sha256);
            }
            ExitCode::SUCCESS
        }
        ReleaseCmd::Fetch { tag, out } => {
            if nbt_aad_core::release::find_known(KNOWN, &tag).is_none() {
                eprintln!("error: release tag {tag:?} is not pinned. Pinned tags:");
                for k in KNOWN {
                    eprintln!("  {}", k.tag);
                }
                return ExitCode::from(2);
            }
            match fetch(
                &mut UreqHttp::new(false),
                &Source::upstream(),
                KNOWN,
                &tag,
                &out,
                &Limits::default(),
            ) {
                Ok(f) => {
                    println!("Verified and staged {} in {}", f.tag, f.dir.display());
                    print!("{}", f.sums);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    eprintln!("Nothing was placed at the final location (staging data removed).");
                    ExitCode::from(1)
                }
            }
        }
    }
}
