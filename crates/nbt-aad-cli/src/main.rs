//! NBT-AAD Manager CLI. Only the READ-ONLY `probe` command and host-side
//! `release` commands exist; no vehicle-modifying functionality is implemented.

mod probe_cmd;
mod release_cmd;
mod sink;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nbt-aad-manager",
    version,
    about = "NBT-AAD Manager (experimental; read-only probe and host-side release verification only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only evidence probe of a head unit (makes no writes on the head unit).
    Probe(ProbeArgs),
    /// Read-only: match the unit against the pilot profile and verify the
    /// installed release by exact digests (exit 0 verified, 6 profile
    /// mismatch, 7 not verified). Same SSH options as `probe`.
    Inspect(ProbeArgs),
    /// Pinned upstream releases: list, fetch and verify (host-side only).
    #[command(subcommand)]
    Release(release_cmd::ReleaseCmd),
}

#[derive(clap::Args)]
pub struct ProbeArgs {
    /// Head-unit address (IP or name), e.g. 169.254.199.99. Never guessed.
    #[arg(long, required_unless_present = "print_commands")]
    pub host: Option<String>,
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    #[arg(long, default_value = "root")]
    pub user: String,
    /// QNX node used for `on -f` (as in the upstream guides).
    #[arg(long, default_value = "/net/hu-omap/")]
    pub hu_node: String,
    /// Directory in which `nbt-probe-<UTC>/` is created.
    #[arg(long, default_value = ".")]
    pub out: PathBuf,
    /// Also allow SHA-1 key exchange, DSA host keys and CBC/3DES
    /// ciphers. Weak; use only on a direct cable to your own head unit.
    #[arg(long)]
    pub allow_legacy_weak: bool,
    /// Expected host key (`<algorithm> <base64>`, e.g. from a previous
    /// run's known_hosts). Without it, the key is shown for confirmation.
    #[arg(long)]
    pub host_key: Option<String>,
    /// Read the password from the FIRST line of stdin (before any prompt
    /// answers) instead of the terminal (automation/tests). It is never
    /// stored or logged.
    #[arg(long)]
    pub password_stdin: bool,
    /// Per-command timeout in seconds.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub cmd_timeout: u64,
    /// Print every remote command the probe can send, then exit.
    #[arg(long)]
    pub print_commands: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => {
            eprintln!(
                "NBT-AAD Manager is NOT ready for vehicle use. Only `nbt-aad-manager probe` (read-only) exists."
            );
            eprintln!("Run `nbt-aad-manager probe --help`.");
            ExitCode::from(2)
        }
        Some(Command::Probe(args)) => probe_cmd::main(args, probe_cmd::Mode::Probe),
        Some(Command::Inspect(args)) => probe_cmd::main(args, probe_cmd::Mode::Inspect),
        Some(Command::Release(cmd)) => release_cmd::main(cmd),
    }
}
