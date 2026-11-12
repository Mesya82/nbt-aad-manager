//! `nbt-aad-manager experiment-e1`: inspect + hardware experiment E1 in one
//! guided run (`docs/HARDWARE_EXPERIMENT_E1.md`, approved 2026-11-09).
//!
//! 1. Writes three random test files onto the USB stick (on this computer).
//! 2. Connects exactly like `probe`/`inspect` (same SSH path, pinned key).
//! 3. Phase 1 (core): inspect must verify the unit; scratch-only writes;
//!    Force Stop observation; write before restart.
//! 4. The operator restarts the head unit; the tool reconnects with the same
//!    pinned host key.
//! 5. Phase 2 (core): durability read-backs and a second inspect.
//!
//! Every remote command of both sessions is in one transcript.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use nbt_aad_core::experiment::{self, E1Error, E1Files, E1Operator, FILES, SCRATCH, USB_DIR};
use nbt_aad_core::guard::Consent;
use nbt_aad_core::inspect::InspectConfig;
use nbt_aad_core::profile::PILOT_G31;
use nbt_aad_core::release::KNOWN;
use nbt_aad_core::transport::{Recorder, sha256_hex};
use nbt_aad_transport_ssh::{self as ssh, HostKey, SshOptions, SshTransport};
use zeroize::Zeroizing;

use crate::ProbeArgs;
use crate::probe_cmd::{self, Console, Mode, Run, read_line, tcp};
use crate::sink::FsSink;

pub const FILE_SIZE: usize = 1024 * 1024;
const RECONNECT_ATTEMPTS: u32 = 30;
const RECONNECT_WAIT: Duration = Duration::from_secs(10);

#[derive(clap::Args)]
pub struct ExperimentArgs {
    #[command(flatten)]
    pub conn: ProbeArgs,
    /// Root of the USB stick as mounted on THIS computer (e.g. E:\). The
    /// test files are written to <usb>/nbt-e1/ before connecting.
    #[arg(long, required_unless_present = "print_commands")]
    pub usb: Option<PathBuf>,
}

/// Test files prepared on the stick.
pub struct E1Prep {
    pub files: E1Files,
    pub usb_dir: PathBuf,
}

fn write_synced(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(p)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Create `<usb>/nbt-e1/f1..f3` (random, 1 MiB) or reuse an earlier set made
/// by this tool. Never overwrites anything.
pub fn prepare_stick(usb: &Path) -> Result<E1Prep, String> {
    if !usb.is_dir() {
        return Err(format!("{} is not a directory", usb.display()));
    }
    let dir = usb.join(USB_DIR);
    if !dir.exists() {
        let tmp = usb.join(format!(".{USB_DIR}.partial"));
        if tmp.exists() {
            return Err(format!("{} exists; remove it first", tmp.display()));
        }
        std::fs::create_dir(&tmp).map_err(|e| e.to_string())?;
        for f in FILES {
            let mut data = vec![0u8; FILE_SIZE];
            getrandom::fill(&mut data).map_err(|e| format!("randomness: {e}"))?;
            write_synced(&tmp.join(f), &data).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &dir).map_err(|e| e.to_string())?;
    }
    let mut sha: Vec<String> = Vec::new();
    for f in FILES {
        let data = std::fs::read(dir.join(f)).map_err(|e| format!("{f}: {e}"))?;
        if data.len() != FILE_SIZE {
            return Err(format!(
                "{} has {} bytes, expected {FILE_SIZE}; not made by this tool?",
                dir.join(f).display(),
                data.len()
            ));
        }
        sha.push(sha256_hex(&data));
    }
    let sha256: [String; 3] = sha.try_into().map_err(|_| "internal".to_owned())?;
    Ok(E1Prep {
        files: E1Files {
            sha256,
            size: FILE_SIZE as u64,
        },
        usb_dir: dir,
    })
}

pub fn banner_text(e1: &E1Prep) -> String {
    format!(
        "\nHARDWARE EXPERIMENT E1 (approved; docs/HARDWARE_EXPERIMENT_E1.md)\n\
         Test files are on the stick: {}\n\
         What E1 will do on the head unit:\n\
         \x20 - inspect first; stop before any write unless the unit and install verify\n\
         \x20 - remount /fs/sda0 rw, then ro, then rw again (as upstream updates do)\n\
         \x20 - write ONLY inside {SCRATCH} (mkdir, cp from the stick, chmod, mv)\n\
         \x20 - ask you to Force Stop Android Auto in iDrive, then watch for up to 1 minute\n\
         \x20 - ask you to restart the head unit (hold power ~30 s), reconnect, re-check\n\
         It never touches the daemon, plugin, settings or backups.\n\
         Before continuing: move the stick to the car's USB port.",
        e1.usb_dir.display()
    )
}

pub fn print_commands() {
    println!(
        "\nE1 mutations (only with typed consent {}):\n  [login] mount -o remount rw|ro <profile remount target>\n  on -f /net/hu-omap/ mkdir {SCRATCH}[/d]\n  on -f /net/hu-omap/ cp /mnt/<umass>/{USB_DIR}/f1|f2|f3 {SCRATCH}/...\n  on -f /net/hu-omap/ chmod 755 {SCRATCH}/f1\n  on -f /net/hu-omap/ mv {SCRATCH}/d {SCRATCH}/d2 | f1 f1b | f3 f3b\nE1 reads: ls -la /mnt, /mnt/<umass>/{USB_DIR}, {SCRATCH}[/d2]; cat of the test files; pidin -p nbt-aad arg; test -w /opt/aa",
        experiment::CONSENT_WORD
    );
}

pub fn main(a: ExperimentArgs) -> ExitCode {
    if a.conn.print_commands {
        return probe_cmd::main_with(a.conn, Mode::ExperimentE1, None);
    }
    let Some(usb) = a.usb.as_deref() else {
        eprintln!("ERROR: --usb is required");
        return ExitCode::from(1);
    };
    let prep = match prepare_stick(usb) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: cannot prepare the USB stick: {e}");
            return ExitCode::from(1);
        }
    };
    probe_cmd::main_with(a.conn, Mode::ExperimentE1, Some(prep))
}

/// Everything the experiment needs from the established first session.
pub struct Session {
    pub run: Run,
    pub transport: SshTransport,
    pub sink: FsSink,
    pub addr: SocketAddr,
    pub opts: SshOptions,
    pub key: HostKey,
    pub user: String,
    pub password: Zeroizing<String>,
    pub banner: String,
    pub cfg: InspectConfig,
    pub e1: E1Prep,
    pub consent: Consent,
}

struct CliOperator<'a> {
    console: &'a mut Console,
}

impl E1Operator for CliOperator<'_> {
    async fn force_stop(&mut self) {
        self.console.say(
            "\n==> E1d: In iDrive go to Media/Radio > Android Auto > Force Stop now\n    (if Android Auto is not running, just continue).",
        );
        let _ = tokio::task::spawn_blocking(|| {
            eprint!("Press Enter when done: ");
            let _ = std::io::stderr().flush();
            read_line()
        })
        .await;
        self.console
            .say("Watching nbt-aad for up to 1 minute (do not touch iDrive meanwhile)...");
    }
    async fn sleep(&mut self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

fn result_text(title: &str, lines: &[String]) -> String {
    let mut s = format!("== {title}\n");
    for l in lines {
        s.push_str(l);
        s.push('\n');
    }
    s
}

pub async fn run(s: Session) -> ExitCode {
    let Session {
        mut run,
        transport,
        sink,
        addr,
        opts,
        key,
        user,
        password,
        banner,
        cfg,
        e1,
        consent,
    } = s;
    run.console.ask(
        "Is the stick with nbt-e1/ now plugged into the CAR (wait ~10 s after plugging)? Press Enter: ",
    );
    run.console.say("==> Phase 1: inspect, then E1a-E1e");
    let mut rec = Recorder::new(transport, sink);
    let p1 = {
        let mut op = CliOperator {
            console: &mut run.console,
        };
        experiment::phase1(
            &mut rec,
            &PILOT_G31,
            KNOWN,
            &cfg,
            Some(banner.clone()),
            &e1.files,
            &consent,
            &mut op,
        )
        .await
    };
    let seq = rec.executed();
    let (transport, sink) = rec.into_parts();
    transport.close().await;
    let p1 = match p1 {
        Ok(p) => p,
        Err(E1Error::Precondition(m)) => {
            run.write("e1-results.txt", &format!("not started: {m}\n"));
            run.console
                .say(&format!("E1 not started, nothing was written: {m}"));
            run.writes_note = "Nothing was written on the head unit.";
            return run.finish(6);
        }
        Err(E1Error::ConnectionLost { executed, reason }) => {
            run.console.say(&format!(
                "connection lost after {executed} recorded executions ({reason}).\nIf a remount happened, restart the head unit (hold power ~30 s) to return it to read-only."
            ));
            return run.finish(3);
        }
        Err(E1Error::Sink(e)) => {
            run.console
                .say(&format!("ERROR: transcript could not be written ({e})"));
            return run.finish(4);
        }
        Err(e) => {
            run.console.say(&format!("ERROR: {e}"));
            return run.finish(5);
        }
    };
    let mut results = result_text("phase 1", &p1.lines);
    if let Some(stop) = &p1.stopped {
        results.push_str(&format!("STOPPED EARLY: {stop}\n"));
    }
    run.write("inspect-before.txt", &p1.inspect.render(&PILOT_G31));
    run.write("e1-results.txt", &results);
    run.console.say(&results);

    // The operator restart (E1e), also returns /fs/sda0 to read-only.
    run.console.say(
        "\n==> RESTART NOW: hold the head unit's power button for ~30 s until it restarts.\n    The tool keeps retrying for about 5 minutes; no extra waiting is needed.",
    );
    run.console
        .ask("Press Enter as soon as it has started restarting (screen off): ");
    let mut session = None;
    for attempt in 1..=RECONNECT_ATTEMPTS {
        run.console.say(&format!(
            "==> Reconnecting (attempt {attempt}/{RECONNECT_ATTEMPTS})"
        ));
        let r = match tcp(&addr).await {
            Ok(st) => ssh::connect(st, &opts, key.clone(), &user, &password)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        match r {
            Ok(t) => {
                session = Some(t);
                break;
            }
            Err(e) => {
                run.console.say(&format!("    not yet: {e}"));
                tokio::time::sleep(RECONNECT_WAIT).await;
            }
        }
    }
    drop(password);
    let Some(t2) = session else {
        run.console.say(
            "Could not reconnect after the restart. Phase 1 results are saved; run `inspect` later to complete the check.",
        );
        return run.finish(3);
    };
    run.console
        .say("==> Phase 2: durability read-backs and inspect after the restart");
    let mut rec = Recorder::resume(t2, sink, seq);
    let p2 = experiment::phase2(
        &mut rec,
        &PILOT_G31,
        KNOWN,
        &cfg,
        Some(banner),
        &e1.files,
        &p1,
    )
    .await;
    let (t2, _sink) = rec.into_parts();
    t2.close().await;
    match p2 {
        Ok(p2) => {
            results.push_str(&result_text("phase 2 (after restart)", &p2.lines));
            run.write("inspect-after.txt", &p2.inspect.render(&PILOT_G31));
            run.write("e1-results.txt", &results);
            run.console
                .say(&result_text("phase 2 (after restart)", &p2.lines));
            run.finish(0)
        }
        Err(E1Error::ConnectionLost { executed, reason }) => {
            run.write("e1-results.txt", &results);
            run.console.say(&format!(
                "connection lost after {executed} recorded executions ({reason})"
            ));
            run.finish(3)
        }
        Err(e) => {
            run.write("e1-results.txt", &results);
            run.console.say(&format!("ERROR: {e}"));
            run.finish(5)
        }
    }
}
