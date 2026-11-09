//! `nbt-aad-manager probe` (native port of `tools/probe/nbt-probe.sh`) and
//! `nbt-aad-manager inspect` (profile match + digest-verified install state).
//! Both share the same audited SSH path and transcript sink; both are
//! read-only.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;
use std::time::Duration;

use nbt_aad_core::guard::NodePath;
use nbt_aad_core::inspect::{self, InspectConfig, InspectError, Verdict};
use nbt_aad_core::kexinit::{self, AlgorithmProfile};
use nbt_aad_core::probe::{
    self, Interaction, PROBE_VERSION, ProbeConfig, ProbeError, USB_MARKER_NAME,
};
use nbt_aad_core::profile::PILOT_G31;
use nbt_aad_core::redact::redact;
use nbt_aad_core::release::KNOWN;
use nbt_aad_core::transport::{ExecLimits, Recorder, sha256_hex};
use nbt_aad_transport_ssh::{self as ssh, HostKey, SshOptions};
use regex_lite_host::is_valid_host;
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::ProbeArgs;
use crate::sink::{FsSink, utc};

mod regex_lite_host {
    /// Hostname or IPv4/IPv6 literal; no shell or path characters.
    pub fn is_valid_host(h: &str) -> bool {
        !h.is_empty()
            && h.len() <= 253
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".:-".contains(c))
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Which read-only operation runs after login.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Probe,
    Inspect,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Mode::Probe => "PROBE",
            Mode::Inspect => "INSPECT",
        }
    }
    fn dir_prefix(self) -> &'static str {
        match self {
            Mode::Probe => "nbt-probe",
            Mode::Inspect => "nbt-inspect",
        }
    }
}

/// Prints to stderr and keeps a redacted copy in `report/console.log`.
struct Console {
    log: Option<fs::File>,
}

impl Console {
    fn say(&mut self, text: &str) {
        eprintln!("{text}");
        if let Some(f) = &mut self.log {
            let _ = writeln!(f, "{}", redact(text));
        }
    }
    fn ask(&mut self, prompt: &str) -> String {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let answer = read_line();
        // Answers are never logged: a mis-ordered stdin could put a secret
        // here. The relevant ones are recorded (redacted) in meta.txt.
        if let Some(f) = &mut self.log {
            let _ = writeln!(f, "{}<answer not logged>", redact(prompt));
        }
        answer
    }
}

/// Read one line as a secret: never copied into a non-zeroizing buffer.
fn read_secret_line() -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::new());
    let _ = std::io::stdin().lock().read_line(&mut s);
    while s.ends_with(['\r', '\n']) {
        s.pop();
    }
    s
}

fn read_line() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim_end_matches(['\r', '\n']).to_owned()
}

struct Run {
    out: PathBuf,
    report: PathBuf,
    console: Console,
}

impl Run {
    fn finish(mut self, code: u8) -> ExitCode {
        if let Err(e) = package(&self.out) {
            self.console
                .say(&format!("WARNING: could not create report.tgz: {e}"));
        }
        // 6/7 are inspection verdicts (profile mismatch / not verified), not
        // early stops.
        let head = if matches!(code, 0 | 6 | 7) {
            "Done.".to_owned()
        } else {
            format!("Stopped early (code {code}); the partial report is still useful.")
        };
        self.console.say(&format!(
            "\n{head} Nothing was written on the head unit.\n  Report for Claude: {}   (also {})\n  Raw copies:        {}  (keep local; contains upstream binaries and unredacted state)\nGlance through report/ before posting it anywhere public.",
            self.report.display(),
            self.out.join("report.tgz").display(),
            self.out.join("private").display()
        ));
        ExitCode::from(code)
    }

    fn write(&self, name: &str, content: &str) {
        let _ = fs::write(self.report.join(name), content);
    }
}

fn package(out: &Path) -> std::io::Result<()> {
    let f = fs::File::create(out.join("report.tgz"))?;
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    tar.append_dir_all("report", out.join("report"))?;
    tar.into_inner()?.finish()?.sync_all()
}

struct CliInteraction {
    out: PathBuf,
}

impl Interaction for CliInteraction {
    async fn usb_step(&mut self) -> Option<String> {
        let mut raw = [0u8; 2048];
        getrandom::fill(&mut raw).ok()?;
        let marker = format!("{}\n", hex::encode(raw));
        let path = self.out.join(USB_MARKER_NAME);
        fs::write(&path, &marker).ok()?;
        eprintln!(
            "\nOptional USB test: copy {}\nto the ROOT of a FAT32/exFAT stick (keep the exact file name), plug it into the car,\nwait ~10 s. Type 'usb' when ready, or just press Enter to skip.",
            path.display()
        );
        eprint!("> ");
        let _ = std::io::stderr().flush();
        let answer = tokio::task::spawn_blocking(read_line).await.ok()?;
        (answer.trim() == "usb").then(|| sha256_hex(marker.as_bytes()))
    }
}

fn print_inspect_commands() -> ExitCode {
    match inspect::plan(&PILOT_G31) {
        Ok(plan) => {
            for (id, cmd) in plan {
                println!("{id:<28} {cmd}");
            }
            println!(
                "\nDynamic commands: on -f {n} cat <file> for the daemon and its .old backup in {d},\nand the five plugin files in {pd} and {pb} (only names listed by ls -la; hashed on this computer).",
                n = PILOT_G31.daemon_node,
                d = PILOT_G31.daemon_dir,
                pd = PILOT_G31.plugin_dir,
                pb = PILOT_G31.plugin_backup_dir
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("internal error: {e}");
            ExitCode::from(5)
        }
    }
}

fn print_commands(node: &NodePath) -> ExitCode {
    match probe::guarded_plan(node) {
        Ok(plan) => {
            for (id, cmd) in plan {
                println!("{id:<28} {cmd}");
            }
            println!(
                "\nDynamic commands (built at runtime from device listings; names must match ^[A-Za-z0-9._-]+$\nand pass the same guard, otherwise they are skipped):\n  on -f {n} ls -la <dir>         for /opt/aa, the NbtAad plugin dir, /opt/aa/NbtAad.old, /var/opt/aa\n  on -f {n} cat <dir>/<file>     regular files listed there (hashed on this computer)\n  on -f {n} cat /dev/shmem/nbt-aad.log, nbt-aad-app.log   (only version lines kept)\n  on -f {n} ls /mnt, ls -la /mnt/<umass*>, df -k /mnt/<umass*>, cat of the USB marker (optional USB step)",
                n = node.as_str()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("internal error: {e}");
            ExitCode::from(5)
        }
    }
}

pub fn main(args: ProbeArgs, mode: Mode) -> ExitCode {
    let node = match NodePath::new(&args.hu_node) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ERROR: --hu-node: {e}");
            return ExitCode::from(1);
        }
    };
    if mode == Mode::Inspect && node.as_str() != PILOT_G31.daemon_node {
        eprintln!(
            "ERROR: --hu-node must be {} for profile {}",
            PILOT_G31.daemon_node, PILOT_G31.id
        );
        return ExitCode::from(1);
    }
    if args.print_commands {
        return match mode {
            Mode::Probe => print_commands(&node),
            Mode::Inspect => print_inspect_commands(),
        };
    }
    if mode == Mode::Inspect
        && let Err(e) = inspect::plan(&PILOT_G31)
    {
        eprintln!("internal error, not connecting: {e}");
        return ExitCode::from(5);
    }
    // Validate the complete static plan before touching the network.
    if let Err(e) = probe::guarded_plan(&node) {
        eprintln!("internal error, not connecting: {e}");
        return ExitCode::from(5);
    }
    let Some(host) = args.host.clone().filter(|h| is_valid_host(h)) else {
        eprintln!("ERROR: invalid --host");
        return ExitCode::from(1);
    };
    if !args
        .user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
        || args.user.is_empty()
    {
        eprintln!("ERROR: invalid --user");
        return ExitCode::from(1);
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ERROR: runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(run(args, host, node, mode))
}

static STAMP_FMT: LazyLock<Vec<time::format_description::BorrowedFormatItem<'static>>> =
    LazyLock::new(|| {
        time::macros::format_description!("[year][month][day]T[hour][minute][second]Z").to_vec()
    });

fn setup_out(base: &Path, prefix: &str) -> std::io::Result<(PathBuf, PathBuf, PathBuf)> {
    let now = time::OffsetDateTime::now_utc();
    let stamp = now
        .format(&STAMP_FMT[..])
        .unwrap_or_else(|_| "unknown".into());
    let out = base.join(format!("{prefix}-{stamp}"));
    if out.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists", out.display()),
        ));
    }
    let report = out.join("report");
    let private = out.join("private");
    fs::create_dir_all(report.join("exec"))?;
    fs::create_dir_all(&private)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    }
    Ok((out, report, private))
}

async fn tcp(addr: &std::net::SocketAddr) -> Result<TcpStream, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(format!("TCP connect to {addr} failed: {e}")),
        Err(_) => Err(format!("TCP connect to {addr} timed out")),
    }
}

async fn run(args: ProbeArgs, host: String, node: NodePath, mode: Mode) -> ExitCode {
    // --password-stdin: the password is the FIRST stdin line, read before
    // any prompt, so it can never be consumed as a prompt answer.
    let stdin_password = args.password_stdin.then(read_secret_line);
    let (out, report, private) = match setup_out(&args.out, mode.dir_prefix()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: cannot create output directory: {e}");
            return ExitCode::from(1);
        }
    };
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(report.join("console.log"))
        .ok();
    let mut run = Run {
        out: out.clone(),
        report: report.clone(),
        console: Console { log },
    };
    let profile = if args.allow_legacy_weak {
        AlgorithmProfile::legacy_weak()
    } else {
        AlgorithmProfile::upstream_documented()
    };
    let opts = SshOptions {
        profile: profile.clone(),
        ..SshOptions::default()
    };

    run.console.say(&format!(
        "\nNBT-AAD Manager READ-ONLY {} (probe plan v{PROBE_VERSION}; {} {})\nTarget: {}@{host}:{}   HU node: {}\nOutput: {}\n\nPreconditions (you confirm):\n  - vehicle is parked; you control power; nobody is driving\n  - SSH on the head unit is ALREADY enabled (this tool does not enable it)\n  - you have NOT remounted anything read-write in another session\nThis tool makes NO writes on the head unit. Review commands with --print-commands.",
        mode.word().to_lowercase(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        args.user,
        args.port,
        node.as_str(),
        out.display()
    ));
    if cfg!(windows) {
        run.console.say("NOTE (Windows): the private\\ folder cannot be permission-restricted by this tool.\nKeep the output folder inside your user profile and do not share it.");
    }
    if args.allow_legacy_weak {
        run.console.say("WARNING: --allow-legacy-weak enables SHA-1 key exchange, DSA host keys and CBC/3DES ciphers.\nUse it only on a direct cable to your own head unit, and only if ssh-kexinit.txt shows no better option.");
    }
    if run
        .console
        .ask(&format!("Type {} to continue: ", mode.word()))
        != mode.word()
    {
        run.console.say("cancelled");
        return run.finish(1);
    }
    let aa = run
        .console
        .ask("Is Android Auto currently running on the head unit? (yes/no/unknown): ");
    let note = run
        .console
        .ask("Optional free-text note for this run (e.g. 'after fresh boot'): ");
    run.write(
        "meta.txt",
        &format!(
            "mode={}\nprobe_version={PROBE_VERSION}\nimplementation=rust\ntool_version={}\nutc={}\ntarget={}@{host}:{}\nhu_node={}\naa_running_user_reported={}\nnote={}\nhost_os={} {}\nalgorithm_profile={}\ncmd_timeout_s={}\n",
            mode.word().to_lowercase(),
            env!("CARGO_PKG_VERSION"),
            utc(std::time::SystemTime::now()),
            args.user,
            args.port,
            node.as_str(),
            redact(&aa),
            redact(&note),
            std::env::consts::OS,
            std::env::consts::ARCH,
            profile.name,
            args.cmd_timeout
        ),
    );

    let addr = match (host.as_str(), args.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    {
        Some(a) => a,
        None => {
            run.console.say(&format!("ERROR: cannot resolve {host}"));
            return run.finish(2);
        }
    };

    // 1. Unauthenticated algorithm discovery.
    run.console
        .say("==> Capturing server SSH algorithm proposal (no login)");
    let algs = match tcp(&addr).await {
        Ok(s) => ssh::capture_server_algorithms(s, CONNECT_TIMEOUT)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    let algs = match algs {
        Ok(a) => a,
        Err(e) => {
            run.write("ssh-kexinit.txt", &format!("error: {e}\n"));
            run.console.say(&format!("ERROR: {e}"));
            return run.finish(2);
        }
    };
    let banner = algs.banner.clone();
    let choices = kexinit::negotiate(&profile, &algs);
    let mut kx = kexinit::describe(&algs);
    kx.push_str(&format!(
        "\nclient profile: {}\nclient group-exchange prime range: {}..{} bits (preferred {})\n",
        profile.name, opts.gex_bits.0, opts.gex_bits.2, opts.gex_bits.1
    ));
    for c in &choices {
        kx.push_str(&format!("negotiated {c}\n"));
    }
    run.write("ssh-kexinit.txt", &redact(&kx));
    run.console.say(&kx);
    if !kexinit::negotiable(&choices) {
        let hint = if !args.allow_legacy_weak
            && kexinit::negotiable(&kexinit::negotiate(&AlgorithmProfile::legacy_weak(), &algs))
        {
            "The server only offers weak legacy algorithms. If this is your own head unit on a direct cable,\nrerun with --allow-legacy-weak."
        } else {
            "No common algorithm set even with --allow-legacy-weak. Send this report as is."
        };
        run.console.say(&format!(
            "No usable algorithm combination. {hint}\nStopping before login."
        ));
        return run.finish(2);
    }

    // 2. Host key (TOFU with explicit confirmation, or pinned via --host-key).
    run.console.say("==> Fetching host key");
    let key = match tcp(&addr).await {
        Ok(s) => ssh::fetch_host_key(s, &opts)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    let key = match key {
        Ok(k) => k,
        Err(e) => {
            run.console
                .say(&format!("ERROR: could not obtain host key: {e}"));
            return run.finish(2);
        }
    };
    let line = key.to_openssh().unwrap_or_default();
    let host_field = if args.port == 22 {
        host.clone()
    } else {
        format!("[{host}]:{}", args.port)
    };
    run.write("known_hosts", &format!("{host_field} {line}\n"));
    run.write(
        "ssh-hostkey-fingerprints.txt",
        &format!("{} {}\n", key.algorithm(), key.fingerprint()),
    );
    run.console.say(&format!(
        "Host key: {} {}",
        key.algorithm(),
        key.fingerprint()
    ));
    match &args.host_key {
        Some(expected) => match HostKey::from_openssh(expected) {
            Ok(exp) if exp.same_key(&key.0) => run.console.say("Host key matches --host-key."),
            Ok(_) => {
                run.console
                    .say("ERROR: host key does NOT match --host-key. Not logging in.");
                return run.finish(2);
            }
            Err(e) => {
                run.console
                    .say(&format!("ERROR: --host-key unparsable: {e}"));
                return run.finish(1);
            }
        },
        None => {
            run.console.say(&format!(
                "Pinned for this probe only (in {}).",
                report.join("known_hosts").display()
            ));
            if run.console.ask(
                "You are directly cabled to your own car and accept this fingerprint? (yes/no): ",
            ) != "yes"
            {
                run.console.say("host key not accepted");
                return run.finish(1);
            }
        }
    }

    // 3. Login (password never stored or logged).
    let password = if let Some(p) = stdin_password {
        p
    } else {
        match rpassword::prompt_password(format!("{}@{host} password: ", args.user)) {
            Ok(p) => Zeroizing::new(p),
            Err(e) => {
                run.console
                    .say(&format!("ERROR: cannot read password: {e}"));
                return run.finish(1);
            }
        }
    };
    run.console.say("==> Logging in");
    let transport = match tcp(&addr).await {
        Ok(s) => ssh::connect(s, &opts, key, &args.user, &password)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    drop(password);
    let transport = match transport {
        Ok(t) => t,
        Err(e) => {
            run.write("ssh-login.txt", &format!("{}\n", redact(&e)));
            run.console.say(&format!("ERROR: SSH login failed: {e}"));
            return run.finish(2);
        }
    };

    // 4.-7. Probe.
    let sink = match FsSink::new(&report, &private) {
        Ok(s) => s,
        Err(e) => {
            run.console.say(&format!("ERROR: {e}"));
            return run.finish(4);
        }
    };
    let timeout = Duration::from_secs(args.cmd_timeout.max(1));
    let cfg = ProbeConfig {
        node,
        text_limits: ExecLimits {
            timeout,
            max_output: 4 * 1024 * 1024,
        },
        readback_limits: ExecLimits {
            timeout,
            max_output: 16 * 1024 * 1024,
        },
        ..ProbeConfig::default()
    };
    let mut rec = Recorder::new(transport, sink);
    if mode == Mode::Inspect {
        run.console.say("==> Inspecting (read-only)");
        let icfg = InspectConfig {
            text_limits: cfg.text_limits,
            readback_limits: cfg.readback_limits,
            ..InspectConfig::default()
        };
        let result = inspect::run(&mut rec, &PILOT_G31, KNOWN, &icfg, Some(banner)).await;
        let (transport, _sink) = rec.into_parts();
        transport.close().await;
        return match result {
            Ok(r) => {
                let text = r.render(&PILOT_G31);
                run.write("inspect.txt", &text);
                run.console.say(&text);
                match r.verdict() {
                    Verdict::Verified => run.finish(0),
                    Verdict::NotVerified => run.finish(7),
                    Verdict::ProfileMismatch => run.finish(6),
                }
            }
            Err(InspectError::ConnectionLost { executed, reason }) => {
                run.console.say(&format!(
                    "connection lost after {executed} recorded executions ({reason}); stopping, no reconnect"
                ));
                run.finish(3)
            }
            Err(InspectError::Sink(e)) => {
                run.console.say(&format!(
                    "ERROR: transcript could not be written ({e}); stopped before the next command."
                ));
                run.finish(4)
            }
            Err(e) => {
                run.console.say(&format!("ERROR: {e}"));
                run.finish(5)
            }
        };
    }
    run.console.say("==> Running probes");
    let mut io = CliInteraction { out: out.clone() };
    let result = probe::run(&mut rec, &cfg, &mut io).await;
    let executed = rec.executed();
    let (transport, _sink) = rec.into_parts();
    transport.close().await;
    match result {
        Ok(s) => {
            run.console.say(&format!(
                "{executed} remote commands executed and recorded (on-node context works: {}).",
                s.hu_context_works
            ));
            run.finish(0)
        }
        Err(ProbeError::ConnectionLost { executed, reason }) => {
            let msg = format!(
                "connection lost after {executed} recorded executions ({reason}); stopping, no reconnect\n"
            );
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open(report.join("notes.txt"))
                .and_then(|mut f| f.write_all(msg.as_bytes()));
            run.console.say(&msg);
            run.finish(3)
        }
        Err(ProbeError::Sink(e)) => {
            run.console.say(&format!(
                "ERROR: transcript could not be written ({e}); stopped before the next command."
            ));
            run.finish(4)
        }
        Err(e) => {
            run.console.say(&format!("ERROR: {e}"));
            run.finish(5)
        }
    }
}
