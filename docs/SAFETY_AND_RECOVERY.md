# Safety and Recovery Model

## Risk model

This tool interfaces with an automotive infotainment head unit that may require professional recovery if misconfigured or damaged. Risk is not limited to data loss. The tool must not alter any vehicle coding, firmware, emergency function, power management or safety-relevant process outside the specifically documented NBT-AAD update scope. Hardware/vehicle operation is exclusively human-controlled and must occur while parked.

## Safety invariants (MUST)

**S1. Read-only by default.** Listing, release inspection, SSH connection, capability detection, inventory, and plan creation make no remote writes, remounts, kills, reboots or deletes.

**S2. Recognized target only.** A write is forbidden if device identity, profile, filesystem paths, command behavior, filesystem space, or selected release compatibility is ambiguous.

**S3. Verified copy first.** No installed file is moved/modified until a distinct snapshot of every potentially touched object exists, is verified and can be mapped back to its original location.

**S4. No overwrite of in-use files.** No replacement by opening and truncating an active daemon or loaded plugin. Promotion occurs from verified staged objects via reviewed filesystem operations.

**S5. Never silently delete last good data.** Cleanup must not remove the only prior known-good daemon/plugin/config or critical journal; backup retention is explicit and separate.

**S6. Journal before mutation.** Any side effect must have a durable intent record and an idempotency/reconciliation strategy. A killed process or moved file cannot be treated as a completed operation without observation.

**S7. Scoped filesystem effects.** Every remote write path comes from an explicit allowlist and a validated HU profile; normalization and symlink handling prevent escaping its intended scope.

**S8. Config preservation.** A config existing before update must remain byte-for-byte equal unless a separately reviewed, user-approved migration requires a change.

**S9. Backups must be restorable, not merely present.** Verify bytes and metadata using supported commands. A snapshot that cannot be restored accurately is an installation blocker.

**S10. Visible uncertainty.** If confirmation cannot be obtained, report `unverified` or `requires manual intervention`; never mark success merely because SSH disconnected during reboot.

**S11. Authentication safety.** No secrets in code, command-line arguments, logs, telemetry, or GitHub issues. SSH server identity must be verified. Do not silently accept weaker SSH settings.

**S12. Minimal rights.** Use only necessary remote operations; never run arbitrary downloaded scripts or destructive unreviewed upstream commands.

## Update state machine

```text
IDLE
  -> RELEASE_VALIDATED
  -> USB_PREPARED
  -> CONNECTED_READ_ONLY
  -> PREFLIGHT_VALIDATED
  -> PLAN_CONFIRMED
  -> SNAPSHOT_CREATING
  -> SNAPSHOT_VERIFIED
  -> STAGING
  -> STAGED_VERIFIED
  -> DAEMON_QUIESCED
  -> PROMOTING
  -> FILES_VERIFIED
  -> REBOOT_PENDING            (manual action)
  -> POST_REBOOT_VALIDATING
  -> COMPLETED

Any state may -> PAUSED / NEEDS_RECONCILIATION / FAILED
Mutation states may -> ROLLBACK_REQUESTED -> RESTORING -> RESTORED_PENDING_REBOOT -> ROLLED_BACK
Unrecoverable uncertainty -> MANUAL_RECOVERY_REQUIRED
```

Transitions require typed preconditions, verified postconditions and a durable journal record. The journal itself needs checksums, versioning and write durability. Use a host-side record plus an on-device persistent record where reliable; do not assume two copies remain synchronized after power loss.

Important: transitions like `PROMOTING` are **not globally atomic**. Disconnected SSH, QNX process behavior, mount errors, or power loss may leave an intermediate state. Recovery logic must inspect reality and reconcile, never assume the last issued command succeeded.

## Snapshot contents

A conservative initial inventory is:

- `/opt/aa/nbt-aad` (daemon), plus any existing `.old` variants and existing operation-specific staging paths.
- `/opt/hmi/ID5/data/ro/Plugins/NbtAad/` including exact case and any currently installed plugin payload.
- `/opt/aa/nbt-aad.env` (which also contains installer-written state such as `NBT_KEEP_PF=1`), and other discovered NBT-AAD config only when explicitly in-scope.
- Daemon persistent state under `/var/opt/aa/` (e.g. `bootguard`, `usb-aa`, `usblog`, `menu-idrive`, `show-drivemode`, `kombi-nav`, `spp-model`, `touch-peer`). Byte-exact capture and restore; some files may identify the user's phone, so keep them out of shareable logs.
- `/opt/aa/pf.bak` and `/opt/aa/mic.disable` when present. Record `/fs/sda0/etc/pf.conf` as an observation (digest + presence); never edit it in MVP.
- File permissions, executable bits, symlinks, source paths, original presence/absence and supported owner/group metadata.
- Relevant system observations such as installed build, process state, filesystem mount mode, available disk space and available recovery commands. These observations are not themselves necessarily restorable state.
- Relevant persistent changes such as a previously installed firewall helper or startup marker must be *identified and documented*; never edit them in MVP without dedicated profile-specific evidence and safe migration design.

Do not back up an entire arbitrary system directory by default. Make the backup scope machine-readable and derived from the *specific planned writes*. If a side effect cannot be scoped, **do not apply**.

## Disk space and backup integrity

Before changing files: calculate sufficient headroom for old install + validated snapshot + staged new artifacts + temporary journal + recovery margin. Do not use hardcoded sizes. Refuse if free-space query is unreliable or insufficient.

Use cryptographic digests where available. If target QNX lacks SHA-256, establish an authenticated transfer/readback to compute hashes on host **or explicitly block apply** until an equally robust integrity mechanism is validated. Do not silently downgrade to file size alone. Check that symlinks and directory boundaries are captured correctly.

Preserve prior generations; retention controls must be disabled until thoroughly tested. Host-side backup export later should use integrity-checked streaming and encryption at rest if sensitive settings are included. Never publish raw backup archives or Wi-Fi credentials.

## SSH and QNX hazards

- Upstream documentation has examples using legacy `ssh-rsa`/`ssh-dss` and SHA-1 MAC; verify target requirements and current host support. Do not silently relax host-key policy.
- Upstream update guide uses `mount -o remount rw /net/hu-omap/fs/sda0` and `on -f /net/hu-omap/ /bin/sh`; understand the two namespaces and exact scope before implementation.
- Upstream update guide conflicts on the on-USB directory case (`release` vs `Releases`) and `.so` capitalization; never auto-correct remote paths without comparing actual disk layout and a verified compatibility profile.
- The upstream guide replaces `.old` by deleting the previous copy before each run. **Do not reproduce this deletion**: create immutable, uniquely named snapshots so recovery history survives repeated updates.
- Avoid any assumption that `scp`, `sftp`, `tar`, `sha256sum`, `stat`, `sync`, `killall`, GNU `mv`, or `rm -r` behave as on Linux.
- Process quiescence and plugin state must be observed, not assumed; reboot must remain human-confirmed until validated.
- `on -f <node> <cmd>` exit status, stdout/stderr separation and argument quoting must be measured per profile; if any is lost or altered, the profile is unsupported for writes.
- A `mv` between different filesystems is copy plus delete, not an atomic rename. Determine the filesystem of every source/destination pair from observation; treat cross-filesystem moves as multi-step, interruptible operations with their own journal entries.
- Never execute upstream binaries (`nbt-aad`, `pf_aa`) for probing; `pf_aa --check` writes to `/dev/shmem`.
- QNX `on` runs a binary directly, with no shell. Built-ins (`echo`, `test`, `kill`, ...) must go through `/bin/sh -c`, or the call fails with status 2. Observed on the pilot head unit.
- Read-only commands can still disturb a live head unit. A bare `df` (all block devices) stalled for 7–10 s and coincided with an Android Auto disconnect. Device-wide commands are forbidden; every command must name its targets.
- The pilot head unit has no digest tool (`sha256sum`, `md5`, `cksum`, `openssl` are all absent) and no `sync`. Integrity checks use host-side hashing of `cat` read-backs; write durability needs a verified mechanism before any write path exists.
- A DSA-only host key is unusable with current OpenSSH; refuse with an explicit diagnosis rather than weakening the client.

## Command transcripts (mandatory)

Every remote command execution, in probing, planning, apply, verify and rollback alike, is recorded before its result is acted upon. Each record holds sequence number, phase, execution context (login shell or `on -f <node>`), the exact command, exit status, start time and duration, and stdout/stderr byte counts and SHA-256.

- `text` output is stored, raw in a private area and redacted in shareable logs.
- `binary` output (file read-back) is stored only as a digest plus a private copy.
- `secret` output (volatile logs) is hashed and discarded.

A gap in the transcript, such as a failed record write or an execution with no record, is a stop condition.

Transcripts serve three purposes:

- They are the evidence for reconciliation after interruption.
- They are the source of the pinned QNX fixtures.
- They are the input of a replay transport. Replaying a transcript must reproduce the identical plan or refusal.

The record layout is shared with `tools/probe/nbt-probe.sh`, so probe runs import directly as fixtures.

## Failure classes

A. Before snapshot verified: abort, no installed-file mutations.
B. Snapshot verified but before promotion: abort and preserve snapshot; clean only own uniquely identified staging if explicitly safe.
C. Partial promotion: move to needs-reconciliation; inspect actual hashes/paths and offer narrow, journal-guided rollback.
D. SSH disconnect/reboot during operation: do not report success or blindly retry; reconnect and re-read before deciding.
E. Backup corrupt/missing: block rollback rather than deleting current files; provide a diagnostics export and manual recovery note.
F. Unknown device/filesystem state: block operations and keep all evidence intact.

## Manual pilot rule

Even after simulated E2E tests pass, real head-unit operations require a reviewed command plan, user control of vehicle power, proof of recovery assets, a tested read-only detection phase, and explicit acknowledgement of risk. Human validation must verify the actual Android Auto UI and rollback capability where appropriate. Update the compatibility matrix with *observed* evidence only.
