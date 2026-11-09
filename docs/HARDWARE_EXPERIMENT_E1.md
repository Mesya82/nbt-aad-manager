# Hardware experiment E1: remount, scratch writes, durability (PROPOSAL; NOT YET RUN)

Purpose: answer `docs/WRITE_PATH_DESIGN.md` section 6, items 1–5, on the pilot car. Every write targets a **scratch directory** that no software on the head unit uses. The real daemon, plugin, env, `/var/opt/aa` and upstream backups are never touched.

Status: proposal. It needs the operator's explicit approval before it runs. There's no tool command for it yet. When approved, it should be implemented as a guarded, transcript-recorded `experiment e1` command, so every execution is logged as for `probe` and `inspect`.

## Preconditions

- The vehicle is parked, the operator controls power, and a direct ENET cable is connected, as for the probe runs.
- `inspect` shows profile match and `Verified gps` with backup `volsliderfixforreal`.
- A USB stick holds `e1/` with three test files. Each file is random, 1 MiB, with a known SHA-256, prepared by the tool.
- Android Auto may be running for E1a/E1b. For E1d it's stopped via iDrive.

## Steps

The `[login]` and `[omap]` contexts are as in the probe. `S` = `/opt/aa/nbt-aad-e1-scratch`.

| Step | Commands | Records | Answers |
| --- | --- | --- | --- |
| E1a remount | `[login] mount -o remount rw /net/hu-omap/fs/sda0`, then `[omap] sh -c 'test -w /opt/aa'` | rc of both; the operator notes any HMI glitch | 6.1: does it work and disturb anything? |
| E1b revert | `[login] mount -o remount ro /net/hu-omap/fs/sda0`, then `test -w` again | rc | 6.1: revert without a restart? (if this fails, the restart in E1e restores read-only, as observed in run 4) |
| E1c scratch writes | remount rw again; `mkdir S`; `cp <usb>/e1/f1 S/f1`; `cat S/f1` (hash on the laptop); `chmod 755 S/f1`; `ls -la S`; `mkdir S/d`; `cp <usb>/e1/f2 S/d/f2`; `mv S/d S/d2`; `mv S/f1 S/f1b`; `ls -la S S/d2`; read back all | rc, modes, digests | 6.3 (file and directory rename), 6.5 (cp mode and mtime, chmod) |
| E1d stop | the operator uses Force Stop in iDrive; `pidin -p nbt-aad arg` every 10 s for 2 min | presence of the process over time | 6.4 (does autostart restart it?) |
| E1e durability | `cp <usb>/e1/f3 S/f3`; `mv S/f3 S/f3b`; wait **5 s**; the operator holds the power button for 30 s; reconnect; `ls -la S`; read back `f3b` | presence and digest after the restart | 6.2 at 5 s (repeat with 60 s if 5 s loses data) |
| E1f re-inspect | `inspect` | must still be `Verified gps` with an unchanged backup | proves that nothing else changed |

**Cleanup:** the scratch directory `S` stays in place (a few MiB). Deleting it requires `rm`, which the MVP design excludes. It will be removed later by a reviewed command, or left in place.

## What it does not answer

Item 6.6, the loaded plugin after a directory rename, would require moving the real plugin directory. For now, the operator's successful upstream update (runs 3→4) is the evidence, recorded as *operator-reported*.

## Risks

- **Remount while the HMI runs:** upstream does exactly this in every update, so the risk is low but not zero.
- **Power-cycle during E1e:** this is the same 30 s hold that upstream documents, and the operator already did it after the update.
- **Scratch writes:** they use about 3 MiB of the roughly 1.25 GB free on `/fs/sda0`.
