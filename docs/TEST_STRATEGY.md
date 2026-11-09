# Test Strategy and Mandatory Acceptance Criteria

> **Release blocker:** This is an automotive head-unit modification tool. No build may be represented as usable on a real vehicle until the gates below are satisfied. Automated simulation improves confidence but is NOT proof of safety for all hardware.

## 1. Test pyramid

### T1. Unit tests (pure Rust core)

- GitHub release parsing with non-SemVer tags, prerelease status, missing assets, pagination, retries/rate limits, bad JSON, redirect restrictions, forged metadata, timeouts, checksums.
- ZIP parsing with path traversal (`../`), absolute paths, symlinks, zip bombs, malformed archives, duplicate paths, case-folding collisions, giant files, incompatible/missing `.so`, unexpected payloads.
- Path allowlists, Windows/FAT32/exFAT path constraints, QNX case-sensitive path handling, unexpected `NbtAad` versus `nbtaad` and plugin library capitalization.
- Strict command constructors and argument escaping; never interpolate untrusted release names or device output into shell text.
- Profile detection, unknown device handling, wrong device identity, unavailable command feature, insufficient headroom.
- Snapshot manifest serialization/versioning and content validation, original present/absent state, metadata restoration, secret redaction.
- Transaction journal persistence, legal/illegal state transitions, idempotency, crash/resume, ambiguity detection.

### T2. Integration and contract tests

- Fixed, sanitized **real upstream metadata/ZIP layout fixtures**, including both full releases and incomplete releases. Never download changing `latest` assets as the only CI contract.
- Deterministic fake USB filesystem: writable, read-only, full, disappearance, wrong medium, simultaneous mounts, case handling.
- Simulated SSH transport: authentication failures, host-key mismatch, old algorithm negotiation, command stdout/stderr/exit-status distinctions, arbitrary latency, truncated responses and disconnects.
- QNX shell adapter: proper namespace distinction, process inspection, read-only and RW mount handling, missing binaries/capabilities, non-GNU command behavior.
- Restore manifests and old file trees from snapshots and verify precise byte-level and supported metadata equivalence.

### T3. End-to-end simulator (mandatory before real writes)

Build a **stateful synthetic NBT EVO/QNX model**, not just a stub returning success. It should emulate:

- target daemon/plugin/config files and their bytes/mode/symlinks; at least one variant that differs in case/layout;
- two shell/processor namespace contexts when relevant;
- SSH commands and failure/exit semantics;
- process running/stopped state, loaded plugin semantics and file-in-use rejection;
- USB mount/discovery and file contents;
- persistent storage accounting, mount RW/RO mode, reboot semantics, in-memory log loss;
- journal persistence and deliberately corrupted/incomplete journal states.

Run **full CLI orchestration** against this simulated device without special-casing the installer. Every command side effect must update simulated state and be observable after a test-run.

### T4. Fault-injection campaign

Inject failure **before and after every external side effect** and across at least every mandatory checkpoint: download, USB staging, connect, mount/remount, snapshot copy, snapshot verify, process stop, staging, daemon rename, plugin rename, promotion, journal update, reconnect, reboot observation, rollback.

For each checkpoint test:

1. operation fails / returns nonzero;
2. operation times out;
3. SSH drops before acknowledgement;
4. SSH drops after device applied the operation but before acknowledgement;
5. process crashes immediately after completed operation (restart program and resume);
6. power-loss model drops volatile state while preserving only modeled persistent state;
7. partial write/transfer where feasible;
8. low-disk / out-of-disk behavior where feasible.

Do not assume the correct remedy is always automatic rollback. The pass condition may be `MANUAL_RECOVERY_REQUIRED` with all evidence preserved and no further writes.

## 2. Named acceptance scenarios (minimum set)

| ID | Scenario | Required behavior |
| --- | --- | --- |
| AC-01 | Read-only `inspect` and `plan` | Zero writes, kills, remounts, reboot requests or persistent state changes (verified by simulator mutation counter) |
| AC-02 | Unsupported/unknown head unit | Reject apply before any changes |
| AC-03 | Wrong or changed device between plan/apply | Reject and require fresh plan |
| AC-04 | Missing daemon, plugin or corrupt ZIP | Reject; no remote writes |
| AC-05 | Tag is non-SemVer / incomplete release | Correct display; incompatible release cannot be applied |
| AC-06 | ZIP slip / symlink escape / path collision | Reject extraction and any install |
| AC-07 | USB absent/wrong/readonly/full | Clear preflight failure; no remote changes |
| AC-08 | SSH auth or host-key mismatch | Abort; never disable identity check |
| AC-09 | Missing QNX command / unexpected shell output | Abort without speculative fallback |
| AC-10 | Insufficient backup+staging space | Reject before mutation |
| AC-11 | Snapshot missing/corrupt/incomplete | Do not move original installed files |
| AC-12 | Prior config including `NBT_ALT_WIFI=CARPLAY` | Exact byte equality after update and rollback |
| AC-13 | Previous `.old` or earlier snapshots exist | Preserve and never overwrite last known good |
| AC-14 | In-use daemon/plugin | Never truncate/overwrite running or loaded files |
| AC-15 | Failure at daemon rename/promotion | Detect actual state and recover or freeze safely |
| AC-16 | Failure at plugin move/promotion | Detect actual state and recover or freeze safely |
| AC-17 | SSH drops just before/after change | Resume reconciles observed state, no blind rerun |
| AC-18 | Host crashes and restarts mid-transaction | Resume safely with durable journal and device checks |
| AC-19 | Simulated power outage mid-transaction | Preserved state remains recoverable or manual recovery flagged; never false success |
| AC-20 | Replay same operation twice | Idempotent, no duplicate destructive side effects |
| AC-21 | Successful update | Installed files match selected release, prior snapshot validates, changes scoped |
| AC-22 | Manual post-reboot runtime validation cannot run | State remains `UNVERIFIED`; no false completion |
| AC-23 | Rollback of successful and partial update | Exact pre-update file state restored where modeled capabilities permit |
| AC-24 | Broken/corrupt backup during rollback | Stop; do not destroy current installation |
| AC-25 | Secrets, passwords, VIN/Wi-Fi settings in outputs | Redaction works in logs, errors, debug and artifacts |
| AC-26 | Arbitrary shell injection via tag/filename/path/SSH output | No command injection, no out-of-scope writes |
| AC-27 | Repeated updates (A->B->C) | Restore target snapshot precisely, retain earlier snapshot history |
| AC-28 | Different plugin file capitalization/layout | Strict profile-specific mapping, no accidental omissions |
| AC-29 | Mount RO restoration on both success/failure | Verified as per profile, or visibly marked failed without unsafe repeated attempts |
| AC-30 | Human declines confirmation | No mutation, credential disclosure or automatic retry |
| AC-31 | Disk fills while creating snapshot or staging | Installed file data unchanged if snapshot unverified; no accidental cleanup |
| AC-32 | Logs stored only in volatile memory | Collect safely before reboot or explain loss; no false claims of persistence |
| AC-33 | Rollback restoration of originally absent files and symlinks | Exact original presence, file content and supported metadata |
| AC-34 | Remote commands return misleading stdout with nonzero status | Status takes precedence and operation stops |
| AC-35 | Installer crashes with corrupt journal | Fail closed, no unjournaled retry, preserve evidence |
| AC-36 | Daemon persistent state (`/var/opt/aa/*`), `pf.bak`, `mic.disable`, `NBT_KEEP_PF` in env | Captured in snapshot; byte-identical after update and after rollback |
| AC-37 | Plugin layout change (7-file <-> 5-file payload), update and rollback | Live plugin dir contains exactly the target release's set; no stale or missing files |
| AC-38 | Archive asset name/case variants (`Release.zip`, `release.zip`, `releases.zip`, `Releases.zip`) and a release without an archive | Exact classification against allowlisted layouts; unknown layout is not applicable; never guessed |
| AC-39 | Plugin tree move turns out to be cross-filesystem (copy+delete), interrupted at every step | Detected from observation, journaled per step, reconciled or `MANUAL_RECOVERY_REQUIRED`; never assumed atomic |
| AC-40 | `on -f` wrapper loses/alters exit status, stream separation or quoting | Capability probe marks profile unsupported; no writes |
| AC-41 | Server offers only host-key/MAC algorithms the client cannot use (e.g. DSA-only) | Refuse with explicit diagnosis; no silent algorithm weakening |
| AC-42 | Installed daemon/plugin digest matches no known release | Treated as unknown installation; read-only; no "upgrade from X" claim |
| AC-43 | Autostart / boot-loop guard state across update and rollback | Preserved byte-equal; the tool never toggles autostart |
| AC-44 | Every remote execution transcribed; transcript write fails or gap appears | Stop before next command; replaying a recorded transcript reproduces the identical plan/refusal |

Each AC must have a stable test identifier, automated test(s), and recorded passing CI run. A passing mocked call counter by itself is not acceptable evidence: verify resulting simulated filesystem contents, mounts, processes, and journal state.

## 3. Coverage and quality gates

**Mandatory for MVP release candidacy:**

1. **100% of defined safety-critical state transitions and rollback edges** tested for success, rejection, interrupted operation, and reconciliation. Maintain a state-transition coverage report.
2. **100% of the AC-01..AC-44 scenarios passing** on the primary simulator profile; additionally run representative secondary layout/command-variant fixtures.
3. **At least 90% line and branch coverage of the pure planner, release validator, path validator, snapshot manifest, journal, and recovery policy modules**. Do not pad coverage with trivial tests; review untested lines explicitly. E2E and CLI adapters have their own behavior-based coverage gate.
4. Property-based testing for arbitrary paths/tags/archive entries and interrupted operations. Ensure reproducible seeds and persist shrinking regression cases.
5. Fuzzing target(s) for archive metadata, manifest/journal parsing, release tag/path handling; check in regression corpus. CI must run a bounded deterministic fuzz/smoke corpus; schedule longer fuzz campaigns outside normal CI.
6. Mutation testing at least for critical planner/journal/snapshot policy invariants, with a documented triage of surviving mutants (target no surviving safety-critical mutant).
7. No `unsafe` Rust in application core without a separately reviewed rationale and dedicated tests.
8. No unreviewed arbitrary-shell execution; all operation templates and allowed paths covered by tests; no secrets in captured logs.
9. No release with failed tests, compile errors, clippy violations, or documented serious unresolved safety bug.
10. Independent command review required before first real-car modification: compare each actual QNX write against an upstream/manual-evidence-backed scope; mark unknowns as blocking.

**Coverage is an indicator, not proof.** Tests must demonstrate actual semantics and state invariants.

## 4. CI design

| Job | Platforms | Scope |
| --- | --- | --- |
| `format` | Linux | `cargo fmt --check` |
| `lint` | Linux | `cargo clippy --all-targets --all-features -- -D warnings` |
| `unit` | Linux + Windows | `cargo test --workspace --all-targets --all-features` |
| `simulator-e2e` | Linux + Windows | Golden CLI flows, read-only invariants, rollback scenarios |
| `fault-matrix` | Linux | Seeded full interruption matrix including journal corruption and power loss |
| `contract` | Linux | Pinned offline release and QNX output fixtures, schema drift check |
| `security` | Linux | Dependency audit, secret scanning, archive/path fuzz regression corpus |
| `coverage` | Linux | Pure-core line + branch threshold and transition coverage report |
| `build` | Linux + Windows | Release-mode compilation for both target OS families |
| `probe` | Linux | `tools/probe/nbt-probe.sh --self-test` and `tools/probe/tests/fake-device-test.sh` (read-only sandbox, fault scenarios) |
| `release-trust` | Linux | Before the first public binary: checksums, SBOM, build provenance attestation, deliberate-failure release-blocker check (REL-01..REL-03) |

CI must never target actual vehicle IPs, enable SSH on vehicles, or run a real remote mutation. Until the suite exists, a green scaffold build **does not imply MVP acceptance**. Track the implementation in a CI gate matrix; do not change README status to ready before all safety gates exist and pass.

## 5. Hardware pilot acceptance (not automated CI)

Only after automated release gates pass:

- test against a parked vehicle with a known-good independently reviewed recovery plan; vehicle power and reboot controlled by a human;
- record sanitized device/profile identification, installation starting version, chosen upstream release, signed/reviewed plan, snapshots and hash verification, and final outcomes;
- run read-only probes first; confirm logs and behavior of QNX commands against real outputs;
- prove on-device snapshot retrieval/restoration with non-destructive checks before mutating installed files;
- complete one normal update and one carefully approved rollback/restore validation when feasible; document what cannot be validated without excessive risk;
- check iDrive entry, Android Auto connect/disconnect, music/audio, rotary input, MENU/BACK behavior, and persistence after a controlled restart;
- never represent the pilot as proving universal compatibility.

Hardware test failure or missing evidence prevents marking that profile `validated`. Compatibility should be tracked by exact vehicle/HU/software configuration, not just BMW model.

## 6. Definition of accepted MVP

**All** mandatory automated acceptance checks pass with evidence; every simulated write is journaled and scoped; installation is blocked on unknown targets/releases; backup integrity and rollback are proven under injected failures; `plan` cannot mutate; a documented, reviewed hardware pilot has passed for an explicitly named profile; and README/compatibility docs honestly reflect the tested scope. Otherwise label builds `experimental / not approved for live use`.

## 7. Future Android, unlock and release-trust acceptance gates

The following are **additional blockers before an Android build may be advertised for vehicle-modifying use**. They do not replace MVP AC-01..AC-44. Simulator tests run only against mock/fixture backends in CI; all real vehicle validation is manual, parked and documented.

| ID | Required scenario | Acceptance evidence |
| --- | --- | --- |
| AND-01 | Desktop and Android adapters share release, plan and recovery logic | Identical canonical plans/refusals on the same Rust fixtures |
| AND-02 | Ethernet permission denied, USB unplug, and changed network routing | No unexpected writes; safe reconnection / failure message |
| AND-03 | Android process death, suspend, screen rotation, lock, and SSH/network loss at each transaction boundary | Durable journal; idempotent resume or explicit manual recovery; no blind repeat |
| AND-04 | SSH host-key mismatch / algorithm incompatibility | Abort and never weaken identity verification silently |
| AND-05 | Android permissions, components, dependencies and network destinations | Documented audit, no unexpected telemetry or embedded credentials |
| AND-06 | FFI panic, cancellation, malformed inputs or lifecycle teardown | No memory-safety violation, secret leak, unjournaled mutation, or lost rollback state |
| AND-07 | Unsupported phone, adapter, head-unit or unknown capabilities | Deny mutation by default |
| AND-08 | Real phone/vehicle combination | Parked read-only pilot first; then reviewed backup, apply, verify and controlled rollback evidence |
| UNLOCK-01 | Unknown/undocumented unlock protocol | Feature unavailable, no speculative probing or hidden executable |
| UNLOCK-02 | Optional supported unlock implementation | Independent protocol/security evidence, explicit consent, exhaustive fault tests and parked-vehicle approval |
| REL-01 | Public release provenance and integrity | Immutable source commit, pinned dependencies, SHA-256, signed artifacts, SBOM and verifiable attestation |
| REL-02 | Source-to-binary transparency | Independent build instructions and comparison report; no unproven reproducibility claim |
| REL-03 | Safety gate release blocker | Deliberately failing required test prevents publishing the binary |
| REL-04 | APK supply-chain audit | Review signing certificate, permissions, libraries, network egress and embedded secrets |

A successful simulator run or signed APK does **not** prove safety or compatibility on arbitrary BMW/Toyota head units. See [ANDROID_AND_RELEASE_TRUST.md](ANDROID_AND_RELEASE_TRUST.md).

## 8. Transcript-driven fixtures and replay

Real-device behaviour enters the test suite only through recorded transcripts (see "Command transcripts" in [SAFETY_AND_RECOVERY.md](SAFETY_AND_RECOVERY.md)). The pipeline:

1. The read-only probe (`tools/probe/`) and every later real run record each remote execution.
2. Sanitized transcripts are committed as pinned fixtures, with provenance (probe version, profile, date, AA running or stopped).
3. The simulator is calibrated against them. For each recorded command, the simulator's stdout, stderr and status shape must match the fixture.
4. A replay transport feeds a transcript to the engine. The resulting plan or refusal must be identical across runs and across adapters (desktop CLI now; Android later, AND-01).

A simulator behaviour without a backing fixture is labelled `assumed` in the test name or metadata. Assumed behaviours cannot be the only evidence for a write-path acceptance criterion.

## 9. Traceability for CLAUDE.md rules 16-20

| Rule | Requirement | Test IDs |
| --- | --- | --- |
| 16 | Single Rust engine; adapters only | AND-01, AC-44 (replay equivalence) |
| 17 | Desktop MVP unchanged; Android separately gated | AND-07, AND-08 |
| 18 | SSH unlock is optional, evidence-gated | UNLOCK-01, UNLOCK-02, AND-04 |
| 19 | Verifiable public releases | REL-01, REL-02, REL-03 |
| 20 | Android release review | AND-05, AND-06, REL-04 |
