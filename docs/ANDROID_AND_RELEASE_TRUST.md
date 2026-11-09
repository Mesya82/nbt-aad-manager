# Android Client, SSH Unlock Boundary, and Verifiable Releases

> **Status: roadmap only.** There is currently no implemented or validated Android client, automatic SSH-unlock capability, or verified reproducible APK. The original desktop Rust CLI MVP remains the first deliverable.

## 1. Why Android, and what stays shared

An Android phone connected through USB-C Ethernet and BMW ENET might make updating NBT-AAD practical without a laptop. The manager still operates on an automotive head unit where a mistake may cause loss of service or require professional recovery. Mobile convenience **must not** relax the backup, journal, rollback or test requirements.

Design a reusable `nbt-aad-core` crate that owns release retrieval/validation, device profiles and capabilities, immutable plans, persistent snapshots, journal/recovery state machines, error taxonomy and refusal rules. CLI/TUI and Android are UI/transport adapters. The Android adapter must never implement its own file-replacement logic or bypass safety policy.

Possible Android implementation: Kotlin + Jetpack Compose; versioned UniFFI or JNI binding to the Rust engine; a pluggable Android SSH transport. Validate native resource lifetimes, cancellation, error propagation and app process recovery, and preserve immutable audit logs with redaction.

## 2. Candidate physical connection

`Android device -> USB-C Ethernet adapter -> ENET/OBD cable -> NBT EVO`

This is not a verified supported configuration. Test the Android device's USB-host capability, Ethernet permission and network routing, adapter chipset, link negotiation, QNX IP reachability, SSH algorithms and host-key identity. Do not assume a working Ethernet tether automatically exposes SSH. Existing target SSH access must be authenticated and intentionally selected by the user.

## 3. Optional SSH unlock: strict trust boundary

Automatic SSH unlocking is **not** part of the desktop MVP and must be optional on Android as well. A third-party closed-source installer, even one hosted in a public fork, is not an independently auditable implementation: its claimed SSH unlock, backup and deployment behavior cannot be assumed correct without reviewing the binary and real-device evidence. The absence of source does not itself establish malice, but it also cannot be treated as safety assurance.

Before implementing any unlock integration, require:

- independently verified, legitimately usable protocol/API details and supported hardware identifiers;
- a separate threat model and review of new network/command execution privileges;
- explicit user authorization, on-screen confirmation and clear indication of all intended effects;
- complete offline negative/fault-injection tests for the particular protocol and device profile;
- documented parked-vehicle validation and a recovery procedure.

Never download or invoke opaque unlock executables, copy unreviewed APK code, embed passwords, weaken SSH identity checking silently, or probe an unknown vehicle with guessed commands. If the protocol cannot be independently verified, **do not ship an unlock module**. Android read-only inspection and later management through an already-open SSH session must remain possible.

## 4. Delivery milestones

**A1: Shared core.** Refactor Rust code so all clients use exactly one tested planning/update/backup/recovery engine. Keep golden fixture equivalence checks and independent adapters.

**A2: Android read-only inspector.** Build Compose app with USB Ethernet discovery, permissions, authenticated read-only SSH probe, capability reporting and honest unsupported states. No writes, no unlock.

**A3: Guarded Android manager.** Reuse the Rust core for verified release selection, local staging, snapshots, and explicit apply/rollback. Reconnect and resume correctly after Android lifecycle disruptions. A staged car pilot requires all core and mobile gates to pass first.

**A4: Optional independently verified unlock.** Separate feature only after the evidence and security gates in section 3. May remain unimplemented permanently.

**R1: Release transparency and provenance.** Make independently verifiable public builds a release requirement, rather than a future nicety.

## 5. Build transparency and verifiable APKs

1. **Source availability:** publish the complete original app code, build definitions, CI actions, generated-code recipes, and fixed versions of build dependencies. Do not bundle NBT-AAD binaries or third-party opaque helpers.
2. **Pinned inputs:** check in `Cargo.lock`; pin Rust, Java/JDK, Gradle, Android plugin and NDK versions and verify dependency updates.
3. **Automated gates:** CI must require code quality, unit, integration, simulator E2E, interruption/rollback, security and artifact-policy suites. Never perform live vehicle operations in CI.
4. **Provenance:** tie artifacts to immutable Git commit and build job, publish machine-readable build attestations/provenance, SBOM, artifact checksums and release signatures with verification steps.
5. **Signing:** protect release signing keys outside Git and untrusted logs; document Android certificate identity across updates and secure key rotation.
6. **Independent verification:** provide rebuild instructions and an independent binary-comparison report. **Do not claim bit-for-bit reproducibility until it has actually been independently demonstrated**. Android signing can change APK bytes; describe precisely whether unsigned artifacts or final APKs were compared.
7. **Least privilege and privacy:** audit Android permissions, exported services/activities, network destinations and bundled libraries. No telemetry by default and no embedded vehicle credentials.
8. **Scope of claims:** a valid signature proves origin/integrity, not that modifying a head unit is safe; clearly label validation limits in README and the compatibility matrix.

## 6. Mandatory future acceptance criteria

See [TEST_STRATEGY.md](TEST_STRATEGY.md) for stable test IDs **AND-01..AND-08**, **UNLOCK-01..UNLOCK-02** and **REL-01..REL-04**. The existing desktop/core gates AC-01..AC-44 remain mandatory. Required Android-specific fault injection includes USB permission denial and removal, routing switch, SSH rejection and disconnect, app suspension/process kill, foreground/background changes, device restart, FFI failure, insufficient space and interrupted rollback.

A real Android + vehicle test profile is only supported after parked-hardware evidence identifies the phone model/Android version, USB Ethernet adapter, ENET cable, head-unit hardware/software, installed NBT-AAD version and outcome of guarded backup/update/rollback.

## 7. Explicit non-promises

No universal NBT EVO compatibility. No assumption that any Bavarian/third-party SSH unlock technique is available or safe on Android. No claim that third-party closed-source APKs are malware (or safe). No assurance that simulated restore success guarantees recovery after real hardware or flash failure. Any change to these boundaries requires design review, updated tests and hardware evidence.
