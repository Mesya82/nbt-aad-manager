# Implementation Plan

## 0. Objective

Deliver a Rust CLI/TUI that manages safe updates of an **already installed** NBT-AAD instance on a supported NBT EVO/iDrive 6 head unit. Choose any specific upstream GitHub release, verify it, create a recoverable backup, apply a staged update through USB + authenticated SSH, and validate the result. Every state change must be explainable, journaled, testable, and reversible when the target remains functional.

**Non-goals in MVP:** first-time installation, SSH unlocking, new firewall patching, vehicle coding, firmware flashing, indefinite automatic background updates, unsupported head units, and host-side full backup download. Later phases may add these only under separate safety review.

## 1. Target environment and principles

- Host: Windows 11 and Linux x86_64 first; architecture should allow macOS later.
- Target: existing QNX-based NBT EVO, read/write filesystem reached via `on -f /net/hu-omap/ /bin/sh` on verified profiles. Do not assume the command/paths across variants.
- Network: ENET to head unit; direct IP and a user-configured SSH proxy/port supported. Credentials via secure interactive prompt. No hardcoded password.
- Artifact source: official `Sq00ky/Supra-iDrive6-Android-Auto` GitHub Releases API. Tags can be arbitrary strings such as `gps`, `brwsr-ap`, `v1.9...` and release order is not trustworthy semver. Allow search/filter by tag and publish date; make stable/prerelease and missing assets obvious.
- Transport: USB file staging plus authenticated SSH for remote operations in MVP. The USB path must be *discovered and verified*, not hardcoded.
- Avoid automatic partition formatting, firmware/coding changes and unnecessary remounts.

## 2. UX and commands

Desired executable name: `nbt-aad-manager`.

```text
nbt-aad-manager releases list [--all] [--json]
nbt-aad-manager releases inspect <tag>
nbt-aad-manager prepare-usb --release <tag> --mount <path>
nbt-aad-manager connect --host <ip-or-name> [--port N]
nbt-aad-manager inspect --host <ip-or-name> [--json]
nbt-aad-manager plan --release <tag> --host <ip-or-name> --usb <mount-or-id>
nbt-aad-manager apply --plan <id>                 # explicit confirmation
nbt-aad-manager status [--operation <id>]
nbt-aad-manager backups list --host <ip-or-name>
nbt-aad-manager rollback --snapshot <id>          # explicit confirmation
nbt-aad-manager diagnostics collect [--no-secrets]
```

Interactive wizard may offer the same operations and progressive screen states: choose upstream release -> verify downloaded assets -> prepare USB -> connect to parked vehicle -> read-only inspect -> backup plan -> explicit confirmation -> snapshot -> staged install -> restart instructions -> post-boot checks. MVP must expose an accessible noninteractive *read-only* mode, but must not enable unattended mutations.

The command list is a proposed interface, not implemented functionality. UX must always distinguish observations from assumptions and completed steps from steps requiring human action.

## 3. Recommended Rust crates and boundaries

- `clap`: CLI; `ratatui` / `crossterm`: optional interactive TUI; start with simple CLI for correctness.
- `reqwest` + `serde`/`serde_json`: GitHub API and release metadata.
- `sha2`: SHA-256 of downloaded assets and locally staged files; a SHA-256 computed only after download detects transfer corruption, not a compromised upstream publisher; compare trusted, authenticated metadata/checksums when upstream offers them.
- `zip`: safely extract and inspect archive entries with path traversal and ZIP bomb protections.
- `thiserror`/`anyhow`: typed domain errors, context on I/O errors.
- `tracing`: event-oriented logs with redaction.
- `tempfile`: safe temporary directories on host.
- SSH: because of rule 16 and the Android roadmap, the engine-facing transport must be an **embeddable pure-Rust SSH client** (e.g. `russh`). Android cannot run an OpenSSH subprocess. An OpenSSH subprocess may exist only as a desktop-only diagnostic adapter. Before committing to a library, verify its support for the algorithms the pilot head unit actually offers (probe evidence: `ssh-rsa`/SHA-1 host keys, `hmac-sha1`, possibly `ssh-dss`); legacy algorithms are enabled only per verified profile and clearly warned about. Strong host-key verification is mandatory. Never use `StrictHostKeyChecking=no` silently, or pass passwords as CLI arguments.
- **Decided 2026-11-09:** `russh` 0.65.1 with the `ring` backend (no C toolchain on Windows) and the `rsa`, `dsa`, `des` features. Verified in tests: SHA-1 `ssh-rsa` host keys, `hmac-sha1`, group14/group1-sha1 KEX, CBC/3DES, DSA-only servers. All are tested against an in-process server, and against real OpenSSH in the CI interop job. Two algorithm profiles: `upstream-documented` (default: modern + the SHA-1 legacy that upstream's guide uses) and `legacy-weak` (opt-in `--allow-legacy-weak`). Dependency advisory exception: RUSTSEC-2023-0071 (`rsa`, Marvin timing attack on private-key operations) is ignored in `.cargo/audit.toml`, because the client only verifies RSA signatures with public keys; it must be re-reviewed on every `russh` update. The default profile adds only what upstream's guide enables (`ssh-rsa` host keys, `hmac-sha1`); SHA-1 key exchange is opt-in. The server's algorithm lists are captured from its unauthenticated KEXINIT, independently of the library, and negotiation is predicted before login.
- The transport accepts an **already-connected byte stream** supplied by the platform adapter. The core never resolves or dials hosts itself: Android must bind sockets to the Ethernet `Network`, because link-local ENET routes are otherwise not used.
- `proptest`/`cargo-fuzz` and a deterministic fake transport: negative and state-machine testing.

Suggested module separation:

```text
src/
  main.rs                 # entry point (initial scaffold only)
  cli.rs                  # command handling and prompting
  github.rs               # GitHubReleaseProvider
  assets.rs               # archive, hash, and path validation
  profile.rs              # supported HU profiles + capabilities
  transport/mod.rs        # HeadUnitTransport trait
  transport/ssh.rs        # real read-only and write operation driver
  transport/fake.rs       # simulator, fault injection
  usb.rs                  # safe preparation and staging
  inventory.rs            # read-only on-device inspection
  snapshot.rs             # backup + manifest + validation
  journal.rs              # transaction ledger + resume
  planner.rs              # pure installation plan
  executor.rs             # policy-controlled mutations
  recovery.rs             # rollback and recovery guidance
  diagnostics.rs          # sanitized log capture
  security.rs             # secrets, SSH identity, path allowlists
  errors.rs               # structured failure categories
```

Do not add these modules as empty placeholders unless a working phase requires them. The architecture is a guide; preserve small, testable boundaries.

**Workspace layout (decided 2026-11-09, ahead of Android A1):** a Cargo workspace from Phase 1.

- `crates/nbt-aad-core`: domain types, release and layout validation, planner, journal state machine, policies and error taxonomy. **sans-IO**: no network, process or filesystem side effects; storage and transport are traits.
- `crates/nbt-aad-transport-ssh`: the SSH implementation of `HeadUnitTransport`.
- `crates/nbt-aad-cli`: the desktop adapter.

Decide sync vs. async at the core boundary before Phase 1 code lands, since UniFFI bindings depend on it. Journal and snapshot-index storage go through a storage trait, not host paths.

**Implemented (read-only probe only):** `nbt-aad-core` holds the guard (`GuardedCommand` can only be built through the shape allowlist, and the transport trait accepts nothing else), redaction, KEXINIT parsing and negotiation, the `HeadUnitTransport` trait, the `Recorder`, the probe runner and a `testkit` fake head unit. `nbt-aad-transport-ssh` is the `russh` client plus a `testkit` fake SSH server. `nbt-aad-cli` provides `nbt-aad-manager probe`. Not yet implemented: replay transport, storage trait for journals, any write path.

**Command transcripts:** `HeadUnitTransport` is wrapped by a recording decorator that writes one record per execution before the result is returned. A replay backend serves recorded transcripts to tests. The record layout matches `tools/probe/nbt-probe.sh`; see [SAFETY_AND_RECOVERY.md](SAFETY_AND_RECOVERY.md).

## 4. Data contracts

### ReleaseArtifact

`tag`, `release_id`, `published_at`, `prerelease`, `assets[]` (`name`, `size`, `download_url`, `sha256` if trusted and available), `required_contents[]`, `layout_variant`, `source_repo`, `source_url`.

Treat an asset such as `Releases.zip` and an internal folder name such as `Releases`, `release`, or a root file set as *different concepts*. Validate actual case-sensitive entry names. Require the daemon and matching RHMI plugin bundle from the **same release** unless an explicitly tested compatibility policy permits otherwise. Some releases may omit `pf_aa`; updates must not assume it is required or safe to rerun.

### HeadUnitProfile

Profile ID, observed hardware/software identifiers (as available), SSH algorithms, mount/namespace entry procedure, command capabilities, installed daemon path, plugin path, config paths, processes, persistent filesystem/storage constraints, safe staging directory, USB discovery method, reboot method (manual until validated), firewall state observation, and per-profile test evidence.

A profile is *unsupported* by default until reviewed. Unknown paths, unsupported commands, unexpected symlinks, and case differences block apply.

### SnapshotManifest

`schema_version`, `snapshot_id`, `device_profile`, `operation_id`, `created_at`, `upstream_installed_build_if_known`, `files[]` (`source_path`, `backup_path`, `file_type`, `size`, `sha256_or_supported_digest`, `mode`, `owner/group_if_supported`, `symlink_target`, `present/absent`), `config_fingerprints`, `selected_source_release`, `journal_ref`, `verify_result`.

Explicitly capture files that were *absent* originally, so rollback can remove only files created by the update. Treat unknown ownership/mode metadata as blockers if needed to restore correctly. Do not record secrets in human-readable logs. Snapshot manifest storage must survive planned restart and not be included inside a plugin tree that will be replaced.

### TransactionJournal

Monotonic states and completed steps, plus intended/inventory/observed hashes and device identity, persisted before each mutation. On resume verify device/profile, journal consistency, snapshot integrity, and filesystem state. Never blindly repeat non-idempotent steps. Never reuse an old plan against a changed target.

## 5. User-facing workflow

### A. Discover releases

1. Query official GitHub API with pagination, timeout/backoff and optional unauthenticated rate-limit notice.
2. Display raw tag names, publish dates, prerelease flags, asset completeness, and whether supported by current parser.
3. Fetch release assets only from verified GitHub official URL; reject redirects to unexpected hosts and suspicious filenames.
4. Stream downloads to temporary files; enforce maximum sizes and timeouts; compute checksums; reject partial downloads.
5. Securely expand plugin ZIP into an isolated temporary directory; reject absolute paths, `..`, directory links, duplicate/colliding path names, case-fold collisions, and unbounded compression ratios.
6. Map and validate the exact daemon and plugin payload; fail closed on missing/extra executable components or unexpected layout. Display compatibility conclusions with confidence/evidence, not guesses.

### B. USB preparation

1. Require the user to select a drive/mount and confirm its identity. Never format or erase it automatically.
2. Verify writable filesystem, sufficient space, and that it is not a system drive. Detect and refuse ambiguous volume selection.
3. Write to unique staging directory or temp names first; verify written lengths and digests; finalize only after successful staging. Preserve unrelated files.
4. Produce an inventory/manifest file for subsequent matching on QNX; compare observed USB device files to intended artifacts after the user inserts it in the vehicle.
5. Do not assume FAT32/exFAT behavior on every platform; check for file-size limits and case handling.

### C. Connect and inspect (read-only)

1. Confirm vehicle is parked and ignition/power conditions meet published guidance; do not attempt vehicle power control.
2. Resolve the SSH target and obtain credentials interactively, with host key verification/pinning. Support direct HU IP or explicit local proxy endpoint; do not guess a 169.254 address.
3. Identify SSH shell capabilities and QNX topology, then read installed daemon/plugin/config metadata and available space.
4. Verify target against an allowed profile. Detect whether a previous transaction is incomplete and require `resume`/`rollback` rather than a new installation.
5. Verify the selected release and USB files against the stored plan. Refuse mismatched device, wrong USB, unexpected running processes, insufficient storage or incomplete ability to preserve metadata.
6. Generate a human-readable, machine-readable plan listing every path to create/move/change and the recovery strategy. `plan` must cause no writes or remounts.

### D. Snapshot and apply (write-mode only)

1. Ask for explicit confirmation; recheck plan preconditions and device identity immediately before the first write.
2. Temporarily remount the verified filesystem RW only when necessary and verified. Distinguish main SSH shell from HU/OMAP namespace; use explicit, testable command adapters.
3. Create a new backup directory with unique ID on a verified persistent volume, not under the soon-to-be-moved plugin directory. Capture all touched objects, config, modes/links, file presence, and system-state observations.
4. Verify snapshot content and manifest before moving an installed file. Insufficient space or unsupported metadata means abort without modifying installed files.
5. Stop daemon only using verified process discovery and scoped termination; ensure its stopped status. A plugin may remain memory-mapped; do not overwrite the loaded object.
6. Stage all new assets on a verified filesystem; validate sizes/digests via supported mechanism. Never copy over a running file.
7. Move previous daemon/plugin to per-operation retained paths and promote staged assets via validated operations. Do not put an old plugin directory inside the live plugin search path.
8. On failure, pause, preserve logs and journal, attempt bounded verified rollback only when safe; otherwise show exact manual recovery instructions without improvising commands.
9. Return any changed mount to RO when appropriate and verifiably safe, or clearly explain that it could not be restored.
10. Request user-controlled iDrive restart according to verified instructions, then re-establish SSH and inspect runtime logs. Never automatically report success based only on a successful `cp`.
11. Mark operation successful only after on-disk files, process/build evidence and expected user-facing behavior checks are satisfied; warn that human confirmation is required for full functional validation.

### E. Resume / rollback

- Detect incomplete transaction *before* beginning another one.
- Compare journaled stage with actual files and hashes, never assume an interrupted rename completed or failed.
- Offer verified resume or restore; preserve failure logs and any newly installed files in a separate quarantine area when capacity allows.
- Rollback must restore exact previous daemon, plugin tree, config/permissions/links and original absent-file state. Do not modify unrelated files, firmware or firewall.
- Treat rollback as a potentially failing repair operation; stop rather than guess when expected backup objects are missing or corrupt.

## 6. Phase and delivery plan

| Phase | Deliverable | Exit gate |
| --- | --- | --- |
| P0 | Upstream audit, QNX assumptions register, compatibility profile schema, sanitized fixtures | Every write command/path and precondition documented or marked unknown |
| P0b | Read-only probe on the pilot car (`tools/probe/`), run with AA stopped and running; transcripts imported as fixtures | Probe output reviewed; UPSTREAM_RESEARCH unknowns updated; zero writes (probe guard + sandbox tests) |
| P1 | Rust workspace, CLI, pure planner, release parser, asset validation | Unit/property tests, representative real-release fixtures pass |
| P2 | Head-unit simulator, fake SSH/USB, journal model, failure injection | All specified state-machine invariants pass |
| P3 | Read-only SSH detection and dry-run, host-key verification, safe USB prep | Windows/Linux smoke tests; zero write calls in `plan` proven |
| P4 | Snapshot/manifest, reversible staged apply, recovery on simulator | All fault-injection points recover or fail closed; backup integrity proven |
| P5 | Guarded QNX adapter, diagnosed manual restart, post-boot verification | All mandatory CI gates green; independent command review |
| P6 | Controlled real-car pilot | Explicit profile and recorded evidence, no misleading universal compatibility claim |

Only after P6, explore host-side backup download over SSH (including whether streaming via `cat`/`tar` is supported and safe), SSH-only staging, broader profiles and stronger automated checks. A supported download path may arrive earlier if completely tested, but does not relax MVP snapshot requirements.

## 7. Traceability and documentation requirements

Maintain a living table connecting risks -> rules -> code implementation -> tests -> observed validation. Document unknowns honestly. For each release, publish a changelog, supported host OS, verified HU profiles, successful test suite results, failure/recovery behavior, and remaining limitations. Do not describe a release as safe or production-ready based on simulator results alone.

## 8. MVP Definition of Done

**All** acceptance criteria in [TEST_STRATEGY.md](TEST_STRATEGY.md) pass, read-only-by-default invariant holds in code and tests, two-person review is encouraged for command/path changes, a human can reconstruct an update and rollback from the persisted journal, and real-hardware use remains blocked until one target profile has completed an explicit pilot procedure. No silent downgrade to weaker testing is allowed.

## 9. Android client roadmap (future, outside MVP)

Build a phone client without fragmenting the existing Rust safety model. The Android UI may use Kotlin + Jetpack Compose with audited Rust JNI/UniFFI bindings; all release validation, planning, snapshot, journal, rollback and safety checks remain in a platform-independent Rust core.

- **A1: shared Rust core**. Extract domain logic and API contracts, with golden tests proving identical plans/refusals in desktop and Android adapters.
- **A2: Android read-only connectivity**. Investigate USB-C Ethernet/ENET, Android permissions/network routing, QNX SSH compatibility, host-key trust, and head-unit discovery. No modifications to the vehicle, SSH unlock, or unsupported-model probing.
- **A3: Android guarded update**. Depends on **SSH-only staging**: the phone's single USB-C port carries the Ethernet adapter, so USB-stick staging is unavailable. Reuse the same Rust transaction engine. Persist journal and recover safely after USB unplug, network switch, background suspension, process death or SSH timeout. Prove snapshots and rollback through simulator tests before any parked-vehicle pilot.
- **A4: optional SSH unlock**. Separate security/research work only after independently verifying a permitted, documented protocol and validating it. No dependency on third-party opaque APKs or unreviewed binaries. Do not make unlock a prerequisite for using already-enabled SSH.
- **R1: transparent distribution**. Publish complete sources, pinned build inputs, checksums, signatures, attestations/provenance, SBOM, independent verification steps, Android permission/network audit and reproducibility status. Do not bundle upstream binaries.

Android support must pass the existing desktop-core acceptance suite plus distinct `AND-*` gates. A target supported through desktop tests is not automatically an Android-supported target. Record the exact phone, OS, USB Ethernet adapter, ENET and head-unit software combination used in a parked-hardware pilot.

See [Android and release trust](ANDROID_AND_RELEASE_TRUST.md) and [test strategy](TEST_STRATEGY.md).
