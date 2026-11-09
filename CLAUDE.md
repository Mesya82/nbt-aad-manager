# Claude implementation instructions

You are implementing **NBT-AAD Manager**, an independent Rust CLI/TUI for safely updating **already installed** NBT-AAD on NBT EVO QNX head units. Read README.md and **every document under docs/** before modifying code.

## Product mandate

Safety, correct recoverability, testability, and explicit uncertainty are more important than speed of implementation or user convenience. A plausible-looking but unverified implementation MUST NOT be connected to a real vehicle. Do not present partially implemented behavior as working.

## Non-negotiable rules

1. **Test-first / simulator-first:** build pure planning logic and a stateful, intentionally adversarial head-unit simulator before implementing remote mutations. Every destructive state transition must have success, rejection, interruption, and recovery tests. Follow `docs/TEST_STRATEGY.md` exactly.
2. **Fail closed:** every unknown QNX command, path, version, process state, device layout, plugin file case, release layout, or backup state stops the workflow before write. Never silently fall back to guessed paths.
3. **No assumptions about QNX:** POSIX tools (tar, sha256sum, stat, scp, sftp, mktemp, mv flags, shell syntax), command paths, SSH cipher support, and cross-processor namespace behavior must be verified per profile. Keep an explicit capability probe and pinned fixtures from sanitized real outputs.
4. **No shared mutable global installer state:** represent phases and decisions with typed Rust structures. Persist a journal *before* irreversible steps. Every retry and resume must be safe.
5. **Backups are mandatory in MVP**, including affected daemon, plugin tree, config and file metadata. Verify backup completeness and reversibility before applying writes. Host-side download is a future milestone unless safely proven earlier.
6. **Never overwrite running binaries or loaded plugins in place.** Use staged files and controlled rename/move; do not blindly execute upstream snippets with `rm -r`.
7. **Never delete or replace the only known-good backup.** Maintain a backup inventory, use bounded storage calculations, and require separate, explicit retention cleanup after successful verification.
8. **Minimal mutation:** no automatic SSH unlock, coding, vehicle firmware flash, firewall edits, or settings resets in MVP. Do not modify `NBT_ALT_WIFI=CARPLAY` or any unrelated config.
9. **Default to read-only.** The `--apply` pathway must show the exact planned writes and require an explicit per-operation consent. Noninteractive automation must require additional guarded flags and is out of scope for MVP.
10. **Do not embed passwords** from upstream guides. Prompt without echo; never log credentials. Pin or explicitly verify SSH host identity; do not disable host-key checking silently. Legacy compatibility must be isolated and clearly warned about.
11. **No speculative version compatibility.** Many upstream GitHub Releases are non-SemVer and do not have identical assets. Use exact release metadata plus an allowlisted release-layout validator. Never interpret release ordering by semantic version alone.
12. **Never report real-hardware validation without an actual, documented real-hardware run.** Keep `docs/COMPATIBILITY.md` accurate.
13. **No live tests in CI.** All automated integration/E2E tests run against local mock/virtual backends. Hardware tests require explicit human operation on a parked vehicle.
14. **Avoid bundling upstream NBT-AAD binaries or licensed code**, and preserve notices/attribution. The tool's MIT license applies to original code only.
15. **Changes to safety model require tests and docs in the same PR.** Provide a traceability table mapping each safety requirement to test cases.

## Future Android and release-trust requirements

16. The **Rust engine is the single source of truth** for planning, release validation, capabilities, backups, journals, recovery and safety policy. CLI and future Android must be adapters over shared logic, never separate update implementations.
17. Keep the existing desktop USB+SSH MVP unchanged. Android (Kotlin/Compose, Rust JNI/UniFFI, USB Ethernet/ENET) is a separately gated follow-on phase, and must not be marked supported without Android-device and parked-car testing.
18. SSH unlock is a **distinct optional security-sensitive module**. Do not depend on unreviewed third-party APKs, guess proprietary commands, embed credentials, silently bypass host-key checks or implement unknown unlock methods. Require verified protocol evidence, legal permission, explicit consent, threat review, fault tests and hardware approval. An existing enabled SSH service must remain sufficient.
19. Every public binary needs published build source and recipe, pinned toolchains and lockfiles, SHA-256 sums, signatures, machine-verifiable provenance/attestations, SBOM, and independent rebuild/verification instructions. Do not claim reproducibility without independent matching evidence. Signing secrets must never enter source or logs.
20. Android release review must validate app permissions, bundled dependencies, outbound network destinations, FFI/lifecycle behavior, absence of telemetry by default and credential redaction. Android device-writing builds must pass existing safety AC-01..AC-35 plus new Android/SSH/release gates in `docs/TEST_STRATEGY.md`.

Read [ANDROID_AND_RELEASE_TRUST.md](docs/ANDROID_AND_RELEASE_TRUST.md) before implementing any mobile or release automation.

## Recommended implementation order

- Phase 0: research and record facts, unknowns and target QNX command capabilities. Write golden sample fixtures (sanitized), threat model, command allowlist, and profile schema. Do not make writes.
- Phase 1: Cargo workspace, CLI skeleton, typed domain models, transport trait, release provider, deterministic fixtures, and error taxonomy.
- Phase 2: stateful simulator + exhaustive negative tests, faulty response/failing command injection, strict path/schema validation, offline dry-run.
- Phase 3: read-only SSH detection, capability negotiation, host-key verification, idempotent command driver, live dry-run with no mutation.
- Phase 4: USB preparation, archive validation, backups, manifest verification, persistent journal, resumability and explicit rollback on simulator.
- Phase 5: guarded on-device install, validation, non-automatic reboot confirmation, safe rollback. Test with simulator and captured QNX fixtures.
- Phase 6: complete all acceptance gates and review every command; only then perform controlled hardware validation and update the compatibility matrix.

## Development and review workflow

Create small, focused commits. For each phase: summarize assumptions, changed paths, new tests, coverage, simulator scenarios, pass/fail evidence, and remaining risks. Run `cargo fmt --check`, strict `cargo clippy`, `cargo test --all-targets --all-features`, platform builds, scenario/fault-injection tests, and license/security checks. Failing checks are release blockers, not warnings.

Do not call a milestone complete until its acceptance tests exist and pass. Use the acceptance criteria and exact failure matrix in `docs/TEST_STRATEGY.md`. Never replace meaningful tests with assertions that simply check mocks were called; assert filesystem invariants and journal transitions.

## What is explicitly NOT required in MVP

Initial SSH unlocking, vehicle coding, ignition management, full QNX image backup, arbitrary shell execution, general-purpose remote root SSH administration, changing firewall rules, unsupported head-unit models, automatic reboot, and unattended upgrades.

## First task for implementation agent

Prepare an **evidence-based implementation design review**: inspect the current upstream `install.md`, `updating.md`, release API, actual asset layouts and LICENSE; create a risk/assumption register; design the `HeadUnitTransport` and `HeadUnitProfile` interfaces; and start the simulator/test harness. If undocumented critical facts remain, implement a read-only probe and mark mutation paths unavailable. No real-device writes before the evidence gate.
