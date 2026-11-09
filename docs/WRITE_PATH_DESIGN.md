# Write-path design (update and rollback): DRAFT, NOT IMPLEMENTED

Status: design only. No code in this repository can write to a head unit. This document defines what `plan` will print and what the simulator must model before any `--apply` exists (CLAUDE.md Phase 4/5). Everything marked **EVIDENCE NEEDED** blocks implementation of the step that depends on it.

Inputs come from the read-only work already done:
- the profile (`PILOT_G31`, `crates/nbt-aad-core/src/profile.rs`);
- `inspect` (install state by exact digests);
- `release fetch` (a pinned, verified release staged on the laptop);
- the operator's own upstream update (`docs/UPSTREAM_RESEARCH.md`, runs 3→4).

## 1. Principles applied here

| Rule (CLAUDE.md) | Consequence in this design |
| --- | --- |
| 5, 7 Backups mandatory; never delete the only good backup | The *active* files become the backup by same-filesystem **rename** into a per-operation directory. Nothing is deleted. Upstream's `nbt-aad.old` / `NbtAad.old` are left untouched. |
| 6 Never overwrite running binaries or loaded plugins | New files are staged under a new name, then renamed into place after the old ones were renamed away. No `cp` onto a live path. |
| 2, 3 Fail closed; no assumptions | Every step has a precondition re-checked on the device immediately before it, and a postcondition verified by read-back digest. Unknown device state stops the run. |
| 4 Journal before irreversible steps | A host-side journal entry is written and flushed **before** each mutation and updated after its verification. |
| 8 Minimal mutation | No firewall, env, `/var/opt/aa` or firmware changes. No `kill` in MVP: the operator stops AA in iDrive and the tool verifies that it stopped. |
| 9 Read-only by default | `plan` prints all steps and makes no remote call that writes. `apply` (future) requires per-operation consent. |

## 2. Preconditions (all read-only, re-checked at apply time)

1. `inspect` gives a profile match and `Verified { installed, backup }`. A half-applied update (`MidUpdate`) or `Unknown` leads to the recovery flow (section 5), never to a new update.
2. The target release is pinned (`release::KNOWN`) and differs from the installed one.
3. The USB stick, prepared by the tool from `release fetch` output, holds `nbt-aad-<op-id>/{nbt-aad, Releases/<5 files>, MANIFEST}`. Every file is read back on the head unit with `cat` and must match the pin (no hashing on the head unit; see run 2).
4. `df -k /opt/aa` (path-scoped, never bare `df`) shows free space of at least 2× the new payload plus a margin.
5. The daemon is not running (`pidin -p nbt-aad arg` shows no process) after the operator's iDrive *Force Stop*.
6. No earlier operation directory `/opt/aa/nbt-aad-ops/<id>/` exists without a `COMPLETE` marker, and the host journal has no open operation.

## 3. Forward steps

Paths are for `PILOT_G31`; `<op>` is a fresh id (UTC timestamp plus random suffix); `<usb>` is the verified stick mount.

| # | Mutation (exact form) | Verify after | Undo if stopped right after |
| --- | --- | --- | --- |
| S1 | login node: `mount -o remount rw /net/hu-omap/fs/sda0` | `test -w /opt/aa` rc 0 | none; a restart returns it to read-only (observed once; **EVIDENCE NEEDED**: does the rw state persist until restart, and can it be reverted without one?) |
| S2 | `mkdir /opt/aa/nbt-aad-ops` (if absent), `mkdir /opt/aa/nbt-aad-ops/<op>`, `mkdir …/<op>/new`, `mkdir …/<op>/new/NbtAad` | `ls -la` shows the empty directories | leave them (empty directories are harmless; no `rmdir` on the unit) |
| S3 | `cp <usb>/nbt-aad-<op>/nbt-aad …/<op>/new/nbt-aad`; `cp <usb>/…/Releases/<f> …/<op>/new/NbtAad/<f>` (×5); `cp <usb>/…/MANIFEST …/<op>/MANIFEST` | `cat` read-back digests equal the pins | staged copies stay inside the op directory; nothing active changed |
| S4 | `chmod 755 …/<op>/new/nbt-aad` | `ls -la` mode | none needed |
| S5 | `mkdir …/<op>/old`, then `mv /opt/aa/nbt-aad …/<op>/old/nbt-aad` | daemon path absent; backup digest equals the pre-op digest | `mv …/<op>/old/nbt-aad /opt/aa/nbt-aad` |
| S6 | `mv …/<op>/new/nbt-aad /opt/aa/nbt-aad` | read-back digest equals the target pin | `mv /opt/aa/nbt-aad …/<op>/new/nbt-aad`, then S5 undo |
| S7 | `mv /opt/hmi/ID5/data/ro/Plugins/NbtAad …/<op>/old/NbtAad` | plugin path absent; the backup set's 5 digests equal the pre-op digests | `mv …/<op>/old/NbtAad /opt/hmi/ID5/data/ro/Plugins/NbtAad` |
| S8 | `mv …/<op>/new/NbtAad /opt/hmi/ID5/data/ro/Plugins/NbtAad` | the 5 digests equal the target pins | reverse the S8 move, then S7 undo |
| S9 | `cp <usb>/nbt-aad-<op>/COMPLETE …/<op>/COMPLETE` | read-back | n/a |
| S10 | the operator restarts the head unit (30 s button hold, as upstream) | after reconnecting: `inspect` gives `Verified { target, backup: <op>/old = previous }`, daemon `Build:` line in the log | rollback flow |

Notes:
- **All moves stay on one filesystem.** S5–S8 move within `/fs/sda0` (observed: `/opt/aa` and the plugin tree share `/dev/sda0t179`), so each `mv` is a rename, not a copy. **EVIDENCE NEEDED:** whether QNX `mv` of a directory within qnx6 is a single atomic rename.
- **No shell redirection.** Every file the tool needs on the head unit (`MANIFEST`, `COMPLETE`) is prepared on the USB stick and copied with `cp`, so the guard never has to admit `>`.
- **The daemon is absent between S5 and S6, and the plugin between S7 and S8.** These windows are deliberate and short. A stop inside them is a `MidUpdate` that `classify` already detects. Recovery is the listed undo, chosen from the host journal *and* re-verified device state.
- **Durability.** There's no `sync` on hu-omap (run 2), and qnx6 commits filesystem snapshots on its own schedule. **EVIDENCE NEEDED:** what state survives a power cut a few seconds after a `mv`? Until that's known, the tool requires the operator to wait a fixed settle time before restarting, and the post-restart `inspect` must re-verify everything.
- **Backup retention.** `…/<op>/old/` is a complete, digest-verified backup that is never deleted automatically. Cleanup is a separate, explicit, later command (rule 7).

### Simulated so far (no hardware)

`crates/nbt-aad-core/src/plan/tests/sim.rs` runs the plan against `testkit::sim::SimFs`. The model is read-only until the remount, and `mv` or `cp` onto an existing path is an error.

The tests cover:
- the full apply, with every `verify` holding;
- an interruption after **each single mutation**, where the state is classified as `Verified(old)`, `MidUpdate`, `Mixed(new daemon, old plugin)` or `Verified(new)`, and foreign backups and env stay byte-identical;
- state-driven recovery from every interruption point, which restores the original install byte for byte;
- a second operation with an existing ops root.

A manual mutation check of the plan killed all 8 mutants. The model assumes that each `mv` and `cp` is all-or-nothing, which is exactly what the hardware evidence in section 6 must confirm or refute.

## 4. Command allowlist for mutations (to be implemented as a separate type)

The read-only `GuardedCommand` will **never** admit these. A new `MutatingCommand` type will be constructible only from typed plan steps, accepted only by an apply-mode transport method that requires an explicit consent token. Exact shapes:
- `mount -o remount rw /net/hu-omap/fs/sda0` (login node only, exactly this string per profile)
- `mkdir <path>` with `<path>` under `/opt/aa/nbt-aad-ops/`
- `cp <usb-path> <path>` from the verified stick into the op directory
- `chmod 755 <path>` on the staged daemon only
- `mv <a> <b>` for exactly the eight path pairs above (forward and undo)

There's no `rm`, `rm -r`, `kill`, `slay`, redirection or wildcard. Each `<path>` is built from the profile and the op id, never from device output.

## 5. Recovery and rollback

- **Journal and engine** (implemented in `crates/nbt-aad-core/src/journal.rs`, simulator-only):
  - **Format.** An append-only, hash-chained, line-based journal. `BEGIN` binds it to the plan digest and op id. An `INTENT` line is durably appended before every mutation, and `DONE` after it. A torn final line counts as a crash during append, not as corruption.
  - **Tests.** A journal-write failure, clean or torn, was injected at every append, and an execution failure at every mutation. In every case no mutation ran without a recorded intent, foreign backups and env stayed untouched, and recovery restored the original.
  - **Engine rules after the second review.**
    - **Preconditions.** Each step's typed preconditions are re-checked on the device immediately before it: daemon not running, exact source digests, target absent. Autostart between steps therefore stops the run.
    - **No guessing on errors.** A check that can't be performed (`Err`) stops apply *and* recovery; it is never taken as "absent" or "not running".
    - **Operator step.** `apply` stops at S10 with `AWAITING`. `COMPLETE` is written only by `confirm_complete` after a verified post-restart `inspect`.
    - **Recovery is fully state-driven.** It covers all steps, and each undo runs only if its `only_if` state (exact digests and absences) proves the forward move happened. A journal truncated at a line boundary is therefore harmless.
    - **Remount.** Recovery re-establishes the remount if a restart reverted it.
    - **Daemon.** Recovery refuses while the daemon runs.
    - **Rollback is separate.** Recovery refuses once S8 has been verified, since that is a rollback, a separate operation.
    - **S9.** S9 verifies the `COMPLETE` bytes.
  - **Tests.** Clean and torn journal-write failures, failed and lost-reply mutations, and check errors were injected at every point. Restart before recovery, autostart before S5, and a journal truncated to `BEGIN` were also covered.
  - **Operation backups.** `inspect` identifies them (`classify_ops`) when the daemon directory shows `nbt-aad-ops`. It lists the root, reads back each `<op>/old` set by exact digest and reports the `COMPLETE` marker. Names that aren't operation ids are reported but never read. Post-restart verification must require `Known(previous)` for the operation's backup.
  - **Rule found by testing.** An undo `mv a b` runs only when `a` exists **and** `b` is absent. Every forward move targets a fresh path, so this pair proves the forward move happened. The earlier rule, "source exists" alone, would have moved the still-active old daemon into staging after a torn journal tail.
- **Recovery** applies when `inspect` gives `MidUpdate`. Match the device state to the journal's last completed step. Then either finish forward (only if every staged digest still verifies) or undo backwards using the table, verifying after each move. If device and journal disagree in any way not covered by the table, stop and print manual instructions.
- **Rollback** after a completed update swaps active and `…/<op>/old` back with the same S5–S8 pattern into a new `…/<op'>/` directory. The rolled-back-from release is kept, not deleted.
- Upstream-style `.old` copies (`/opt/aa/nbt-aad.old`, `/opt/aa/NbtAad.old`) count as *foreign backups*. They are reported by `inspect` and never moved or deleted.

## 6. Hardware evidence needed before implementing `apply`

Each item below needs a documented parked-car run and is listed in `docs/COMPATIBILITY.md` when obtained.

1. The remount behaviour (S1): how long the rw state lasts, whether it can be reverted without a restart, and whether it disturbs the running HMI.
2. qnx6 durability without `sync`: the state after a power cut at a few seconds and at a few minutes after a `mv` or `cp`.
3. Whether a directory `mv` within `/fs/sda0` is atomic, and what is visible after an interrupted `mv`.
4. Whether *Force Stop* reliably stops `nbt-aad`, and whether `autostart` restarts it before the restart (or between S5 and S6).
5. `cp` from the FAT USB stick: the resulting mode and mtime, and whether `chmod 755` behaves as expected.
6. The memory use or locking of a loaded `libNbtAad.so` after its directory is renamed (S7). Upstream's procedure shows this works once; the tool needs it recorded.

The read-only probe can't answer these. They require an operator-run experiment on the parked car, which needs explicit approval and a reviewed experiment plan using scratch files only (never the real daemon or plugin).
