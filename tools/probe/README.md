# Read-only head-unit probe (Phase 0 evidence)

`nbt-probe.sh` collects the facts the manager's design and test suite depend on,
**without writing anything on the head unit**. Each remote command is recorded
in a transcript; the transcripts become the pinned QNX fixtures and the
reference data for the simulator and the replay transport.

## Before you run it

- Vehicle parked, you control power, nobody driving.
- SSH on the head unit **already enabled** (the probe never enables it).
- Do **not** have a read-write remount active from another session.
- Host: Linux, or **Windows 10 with Ubuntu 22.04 under WSL1** (see below). Needs bash,
  OpenSSH client, coreutils and binutils (`strings`). Git Bash, PowerShell, Windows' own
  OpenSSH and PuTTY are **not** supported (no SSH multiplexing).
- Review the exact command list first:

```bash
bash tools/probe/nbt-probe.sh --print-commands
bash tools/probe/nbt-probe.sh --self-test
```

## Windows 10 setup (WSL1)

On Windows 10, WSL2 sits behind a virtual NAT and normally **cannot reach the car's
link-local 169.254.x.x address** on the laptop's Ethernet port; WSL2's mirrored networking
is Windows 11 only. **WSL1** shares the Windows network stack and reaches it directly.
Ubuntu 22.04's OpenSSH 8.9 also still supports a DSA-only head unit via `--allow-ssh-dss`.

PowerShell **as Administrator** (one-time; may ask for a reboot):

```powershell
wsl --set-default-version 1
wsl --install -d Ubuntu-22.04
wsl -l -v                         # Ubuntu-22.04 must show VERSION 1
# If it shows 2:  wsl --set-version Ubuntu-22.04 1
```

In the Ubuntu window. Keep everything in the Linux home directory, **not** under `/mnt/c`:

```bash
sudo apt update && sudo apt install -y git openssh-client binutils
git clone https://github.com/Mesya82/nbt-aad-manager.git ~/nbt-aad-manager
cd ~/nbt-aad-manager
git switch phase0-probe            # only until the branch is merged into main
bash tools/probe/nbt-probe.sh --self-test
bash tools/probe/nbt-probe.sh --print-commands | less
```

At the car:

1. Connect the ENET cable to the laptop's Ethernet port. With no DHCP server,
   Windows gives the adapter a 169.254.x.x address after about a minute.
2. Use the head-unit address you know from the upstream install (often 169.254.199.99,
   but it varies). The probe never guesses it.
3. In Ubuntu, check reachability with `ping -c 3 <hu-ip>`, then run the probe.

To bring the result back, copy `report.tgz` out of WSL:
`cp ~/nbt-aad-manager/nbt-probe-*/report.tgz /mnt/c/Users/<you>/Desktop/`.
Put it in `probe-runs/` in the repository on the development machine; that folder
is git-ignored. Keep `private/` on the laptop.

*Not yet verified on real WSL1:* the probe was tested on Linux with a fake head unit.
If anything on the host side doesn't work (e.g. SSH multiplexing), the probe stops with
a message before or without touching the head unit. Send me the console output in that case.

## Run

```bash
bash tools/probe/nbt-probe.sh --host 169.254.199.99            # direct ENET
bash tools/probe/nbt-probe.sh --host 127.0.0.1 --port 6969     # via proxy
```

It asks you to type `PROBE`, whether Android Auto is running, an optional note,
and to confirm the host-key fingerprint. ssh then asks for the password once
(the probe never sees or stores it). One run takes a few minutes.

**Please run it twice if you can:** once with Android Auto stopped and once
while it is running (it changes process/log/state evidence). The optional USB step
asks you to copy a generated marker file to a FAT32/exFAT stick and plug it in.

## Output

`./nbt-probe-<UTC>/`

| Path | Content | Share? |
| --- | --- | --- |
| `report/exec/NNNN-<id>/` | one record per remote call: `cmd`, `rc`, `ms`, `started_utc`, `policy`, stdout/stderr sha256 + byte counts, redacted `stdout`/`stderr` | yes (with Claude) |
| `report/exec-log.tsv` | `record, policy, rc, ms, stdout_bytes, stderr_bytes, cmd` per call, in order | yes |
| `report/readback.tsv` | path, rc, size, sha256, embedded build strings of every read-back file | yes |
| `report/ssh-*.txt` | server algorithm proposal, host-key fingerprints | yes |
| `report/text/` | redacted copies of *known* state files only (`nbt-aad.env`, `pf.bak`, `mic.disable`, `/var/opt/aa/{bootguard,usb-aa,usblog,menu-idrive,show-drivemode,kombi-nav}`); every other file is hash-only | yes, after a glance |
| `report/log-versions.txt` | only `Build:` / `create(name=` lines from volatile logs | yes |
| `private/` (mode 700) | raw unredacted stdout/stderr, read-back copies of binaries | **local only, never publish** |

Transcript policies: `text` (stdout stored), `binary` (read-back; only hash in
`report/`, raw copy in `private/readback/`), `secret` (volatile logs; hashed, raw discarded).

Redaction is best-effort (VIN-like 17-character tokens, MAC addresses, env keys
containing PASS/PSK/KEY/SECRET/TOKEN/SSID/PIN). Look through `report/` before
posting anything publicly.

## What it does NOT establish

Write-path behaviour (remount, `mv`/`cp` semantics and atomicity, permission
preservation, renaming a running binary, process stop, reboot/RO restore) stays
**unknown and blocks writes** until a separately reviewed, scratch-only write
probe exists.

## Safety design

- Guard on every remote command: each `;`-separated segment must match an exact
  read-only **command shape** (program *and* arguments, e.g. `ls [-laRdi] PATH…`,
  `cat PATH`, `df -k[P] [PATH…]`, bare `mount`, `command -v NAME`, `use NAME`);
  only `on -f <hu-node>` and a single `/bin/sh -c '…'` wrapper are accepted; no
  pipes, `&`, redirection (except `1>&2` in one fixed probe), substitution, globs,
  `..` or credential paths. A rejection of a static command aborts the run; a
  device-derived file that fails the guard is skipped and noted. The guard is
  unit-tested by `--self-test` (61 rejection cases) and the whole static table is
  checked before connecting.
- If the SSH connection is lost, the probe stops immediately (no reconnect, no
  password re-prompt), packages what it has, and exits with code 3.
- ssh runs with `-F /dev/null` (your `~/.ssh/config` cannot change targets or
  options), no public keys, no agent, no GSSAPI.
- Names discovered on the device are used in commands only if they match
  `^[A-Za-z0-9._-]+$`; symlinks are recorded, never followed.
- Upstream binaries (`nbt-aad`, `pf_aa`) are read, never executed.
- Host key: fingerprints are shown and must be confirmed; pinned in a probe-local
  `known_hosts`; `StrictHostKeyChecking=yes` for all authenticated calls. `~/.ssh` is not touched.
  The first, unauthenticated algorithm-discovery call (`BatchMode`, dummy user) cannot log in.

## Tests

`tests/fake-device-test.sh` (Linux + bubblewrap) runs the full probe against a
synthetic head-unit tree mounted **read-only** in a sandbox, and asserts the tree
is bit-identical afterwards, that secrets and personal data don't leak, that
read-back hashes match, and that every remote call has a complete transcript
record in device order. Fault scenarios: control master dies mid-run, a command
hangs (`NBT_PROBE_CMD_TIMEOUT`), server host key mismatch, unexpected `ls -l` layout.
Pass a real `nbt-aad` and `Releases.zip` to use genuine release payloads.
