# Hardware experiment E1: remount, scratch writes, durability (APPROVED; IMPLEMENTED; NOT YET RUN)

Purpose: answer `docs/WRITE_PATH_DESIGN.md` section 6, items 1–5, on the pilot car. Every write targets a **scratch directory** that no software on the head unit uses. The real daemon, plugin, env, `/var/opt/aa` and upstream backups are never touched.

Status: approved by the operator on 2026-11-09 and implemented as `nbt-aad-manager experiment-e1`. It hasn't run on the car yet.

## How to run it (one command, with inspect first)

1. Plug the USB stick into the laptop and note its drive letter (e.g. `E:`).
2. Run `.\nbt-aad-manager.exe experiment-e1 --host 169.254.199.99 --usb E:\`.
   - The tool writes `nbt-e1\f1..f3` (random, 1 MiB each) onto the stick before it connects. A set from an earlier attempt is reused, and nothing is overwritten.
3. Follow the prompts:
   1. Type `EXPERIMENT`, then `SCRATCH-WRITES`. That is the consent for the scratch writes and the remounts.
   2. Answer the usual probe questions and accept the host key.
   3. Move the stick to the car and press Enter.
   4. The tool runs `inspect`. If the unit or the install doesn't verify, it **stops before any write** (exit 6).
   5. E1a–E1c run, then Force Stop when asked (E1d, up to 1 minute of observation; it ends early once the answer is known), then E1e.
   6. Restart the head unit when asked (hold power about 30 s) and press Enter once the screen goes off. The tool retries the connection every 10 s for about 5 minutes, then reconnects with the same pinned host key and runs phase 2, including a second `inspect`.
4. Results: `report/e1-results.txt`, `inspect-before.txt` and `inspect-after.txt`, plus the full transcript of both sessions in `report/exec/`. Copy `report.tgz` as usual.

Exit codes:
- 0: done.
- 1: cancelled or no consent.
- 3: connection lost. If it happened after a remount, restart the head unit.
- 4: transcript failure.
- 5: internal error.
- 6: preconditions not met; nothing was written.

## Safeguards in the implementation

- **Separate write type.** Writes use a separate `MutatingCommand` type, built only from the fixed E1 set, and the transport sends it only with the typed consent token.
- **Recorded.** Every write is recorded in the same transcript as the reads.
- **Precondition order.** It stops before any write unless all of these hold:
  - `inspect` matches the profile and verifies the install;
  - nothing named like the scratch folder exists in `/opt/aa`;
  - exactly one stick holds the three files with the expected digests.
- **Remount check.** If the remount doesn't make `/opt/aa` writable, no scratch write is attempted.
- **Stops on failure.** Any write with a non-zero exit stops the run at that step.
- **Reconnect identity.** The reconnect after the restart accepts only the host key pinned in session 1.
- **Tested** against the stateful fake head unit for the full run across a restart, every precondition, a failed write, a read-only transport, a lost connection and consent misuse. A mutation check of the safety gates killed every mutant.

## Preconditions

- The vehicle is parked, the operator controls power, and a direct ENET cable is connected, as for the probe runs.
- `inspect` shows profile match and `Verified gps` with backup `volsliderfixforreal`.
- A USB stick holds `nbt-e1/` with three test files. Each file is random, 1 MiB, with a known SHA-256, prepared by the tool.
- Android Auto may be running for E1a/E1b. For E1d it's stopped via iDrive.

## Steps

The `[login]` and `[omap]` contexts are as in the probe. `S` = `/opt/aa/nbt-aad-e1-scratch`.

| Step | Commands | Records | Answers |
| --- | --- | --- | --- |
| E1a remount | `[login] mount -o remount rw /net/hu-omap/fs/sda0`, then `[omap] sh -c 'test -w /opt/aa'` | rc of both; the operator notes any HMI glitch | 6.1: does it work and disturb anything? |
| E1b revert | `[login] mount -o remount ro /net/hu-omap/fs/sda0`, then `test -w` again | rc | 6.1: revert without a restart? (if this fails, the restart in E1e restores read-only, as observed in run 4) |
| E1c scratch writes | remount rw again; `mkdir S`; `cp <usb>/nbt-e1/f1 S/f1`; `cat S/f1` (hash on the laptop); `chmod 755 S/f1`; `ls -la S`; `mkdir S/d`; `cp <usb>/nbt-e1/f2 S/d/f2`; `mv S/d S/d2`; `mv S/f1 S/f1b`; `ls -la S S/d2`; read back all | rc, modes, digests | 6.3 (file and directory rename), 6.5 (cp mode and mtime, chmod) |
| E1d stop | the operator uses Force Stop in iDrive; `pidin -p nbt-aad arg` every 10 s for up to 1 min, ending early when it is still running at the first poll or comes back | presence of the process over time | 6.4 (does autostart restart it?) |
| E1e durability | `cp <usb>/nbt-e1/f3 S/f3`; `mv S/f3 S/f3b`; wait **5 s**; the operator holds the power button for 30 s; reconnect; `ls -la S`; read back `f3b` | presence and digest after the restart | 6.2 at 5 s (repeat with 60 s if 5 s loses data) |
| E1f re-inspect | `inspect` | must still be `Verified gps` with an unchanged backup | proves that nothing else changed |

**Cleanup:** the scratch directory `S` stays in place (a few MiB). Deleting it requires `rm`, which the MVP design excludes. It will be removed later by a reviewed command, or left in place.

## What it does not answer

Item 6.6, the loaded plugin after a directory rename, would require moving the real plugin directory. For now, the operator's successful upstream update (runs 3→4) is the evidence, recorded as *operator-reported*.

## Risks

- **Remount while the HMI runs:** upstream does exactly this in every update, so the risk is low but not zero.
- **Power-cycle during E1e:** this is the same 30 s hold that upstream documents, and the operator already did it after the update.
- **Scratch writes:** they use about 3 MiB of the roughly 1.25 GB free on `/fs/sda0`.
