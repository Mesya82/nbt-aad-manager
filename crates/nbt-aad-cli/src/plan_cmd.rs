//! `plan`: offline dry-run of an update. Prints every step; executes nothing
//! and contacts nothing. The installed state is taken from the arguments
//! (normally copied from an `inspect` report), so the output says so.

use std::process::ExitCode;

use nbt_aad_core::plan::plan_update;
use nbt_aad_core::profile::{Backup, InstallState, PILOT_G31};
use nbt_aad_core::release::{KNOWN, find_known};

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Installed release tag as verified by `inspect` (e.g. `gps`).
    #[arg(long)]
    pub installed: String,
    /// Existing foreign backup tag as verified by `inspect`, if any.
    #[arg(long)]
    pub backup: Option<String>,
    /// Target release tag (must be pinned).
    #[arg(long)]
    pub target: String,
    /// USB mount on the head unit as listed by inspect/probe (e.g. /mnt/umass01200t12).
    #[arg(long)]
    pub usb: String,
}

fn op_id() -> String {
    let now = time::OffsetDateTime::now_utc();
    let stamp = now
        .format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap_or_else(|_| "19700101T000000Z".into());
    let mut r = [0u8; 6];
    let _ = getrandom::fill(&mut r);
    let suffix: String = r
        .iter()
        .map(|b| char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[usize::from(*b) % 36]))
        .collect();
    format!("{stamp}-{suffix}")
}

pub fn main(a: PlanArgs) -> ExitCode {
    let Some(installed) = find_known(KNOWN, &a.installed) else {
        eprintln!(
            "error: --installed {:?} is not a pinned release",
            a.installed
        );
        return ExitCode::from(2);
    };
    let backup = match a.backup.as_deref() {
        None => Backup::None,
        Some(t) => match find_known(KNOWN, t) {
            Some(k) => Backup::Known(k),
            None => {
                eprintln!("error: --backup {t:?} is not a pinned release");
                return ExitCode::from(2);
            }
        },
    };
    let state = InstallState::Verified { installed, backup };
    match plan_update(&PILOT_G31, &state, &a.target, KNOWN, &op_id(), &a.usb) {
        Ok(p) => {
            println!("OFFLINE DRY-RUN: installed state taken from the arguments, not observed.");
            println!("Nothing is executed; no apply path exists in this version.\n");
            print!("{}", p.render());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
