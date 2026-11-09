# NBT-AAD Manager

> [!WARNING]
> **PERSONAL EXPERIMENTAL PROJECT. USE AT YOUR OWN RISK.**
>
> This is an **independent personal hobby project**, not an official BMW, Toyota, Supra, NBT-AAD, or TurboCode tool. It is not affiliated with, supported by, or endorsed by those parties.
>
> **Hardware validation is extremely limited.** The intended first real-world test target is **one privately owned 2018 BMW G31 530i with NBT EVO / iDrive 6**. Until such testing is explicitly documented, **no real-vehicle test has been completed for this manager**. After testing, assume it has been tested **only on that single vehicle, unless the compatibility matrix explicitly says otherwise**. Other head units, versions, cars, retrofits, and environments are **untested and unsupported unless explicitly stated otherwise**.
>
> The head unit is a critical, expensive automotive system. Incorrect operations can cause loss of functionality, a failed boot, or the need for professional reprogramming/recovery. **You are solely responsible for any modifications you make to your vehicle. No warranty or guarantee of safety, compatibility, successful recovery, or fitness for any purpose is provided.** Backups and automated checks reduce risk; they cannot eliminate it. **Never use this tool while driving.**

## Project status

**Planning / early implementation. NOT READY FOR USE ON A VEHICLE.** No installer or updater functionality exists. Implemented commands: the **read-only** evidence probe (`nbt-aad-manager probe`, see [tools/probe/README.md](tools/probe/README.md)), which makes no writes on the head unit and has been run read-only on one pilot car (see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)); the **read-only** `nbt-aad-manager inspect`, which matches the unit against the pilot profile and verifies the installed release by exact digests (same SSH path and transcripts as the probe; not yet run on the car); an offline `nbt-aad-manager plan` dry-run that prints every step an update would take (see [docs/WRITE_PATH_DESIGN.md](docs/WRITE_PATH_DESIGN.md)) and executes nothing; and host-side release handling (`nbt-aad-manager release known|fetch|usb-prepare`), which downloads only releases pinned by exact SHA-256 and verifies every file before staging it locally. Nothing writes to a head unit. Do not assume examples in the design documents are working commands.

This project aims to build a cross-platform, Rust-based, interactive manager for updating an existing [NBT-AAD](https://github.com/Sq00ky/Supra-iDrive6-Android-Auto) installation on supported BMW/Toyota NBT EVO head units.

The initial design prioritizes **recoverability and transparency over convenience**. The user should be able to preview exactly which files will change, create and validate a backup, apply a verified release, and recover from an interrupted operation where technically possible.

## Planned MVP

- Windows and Linux CLI, with a readable interactive terminal experience.
- Discover releases directly from the upstream GitHub Releases API, including non-SemVer tag names; allow a specific release to be selected.
- Download and verify required release assets, validate extracted file names and paths, and prepare a FAT32/exFAT USB drive **without automatically formatting or erasing it**.
- Connect using an already enabled SSH service on NBT EVO (usually through an ENET connection); **no SSH unlocking, vehicle coding, or firmware flashing** in MVP.
- Read-only preflight and dry-run first; detect an installation and unsupported/unknown environments before any writes.
- Create and verify a manifest-based backup of affected binaries, RHMI plugin, configuration, relevant metadata, and any other touched persistent state **before modifications**. Keep backups separate from staging and never silently overwrite previous known-good backups.
- Perform a journaled, staged update without overwriting in-use binaries, preserving the existing configuration.
- Verify installation and offer explicit rollback/recovery steps; do not claim that a reboot or a successful runtime check is guaranteed.
- Provide structured logs with passwords/vehicle identifiers redacted.

**MVP backup scope:** on-device backups with a verified manifest. Downloading complete backups to the host is a planned upgrade, subject to confirming reliable transfer support on the target QNX environment. If no safe, sufficiently complete snapshot can be created, **installation must abort**.

## Android roadmap and release transparency

**Android is a planned client, not part of the desktop MVP.** Our Rust safety engine must remain platform-independent: release validation, head-unit profiles, preflight, snapshots, transaction journal, rollback, and refusal rules belong to one reusable core. A later Kotlin/Jetpack Compose Android UI should call that same engine via an audited, versioned Rust bridge. A USB-C Ethernet/ENET connection is only a candidate transport, **not yet verified on a supported phone/head-unit combination**.

**SSH unlocking is a distinct, optional, high-risk feature.** The first desktop version requires SSH to be already enabled. Android should initially work with existing authenticated SSH and must not rely on closed-source third-party APKs. A future unlock module needs independently verified and legitimately implementable protocol details, separate security review, explicit consent, failure simulation and vehicle-specific validation. Unknown mechanisms stay disabled.

**Public releases must be auditable.** Publish complete source and CI workflows, locked dependencies and toolchains, checksums, signed artifacts, verifiable build provenance and SBOM, permission/network inventories (for Android), and independent build comparison instructions. Never claim bit-for-bit reproducibility until independently demonstrated, especially for signed APKs. A signed build does not guarantee safety on real vehicles. Release jobs must fail when safety tests fail. Do not bundle upstream NBT-AAD binaries.

See [Android architecture and release trust](docs/ANDROID_AND_RELEASE_TRUST.md) for the proposed implementation phases and future acceptance gates.

## Safety principles

1. **Fail closed:** unknown layout, missing asset, inconsistent state, unsupported SSH behavior, insufficient space, or incomplete backup means no write.
2. **Dry-run by default:** connecting and inspecting must not mutate the device. An operation requires deliberate user confirmation and an explicit apply path.
3. **No fake guarantees:** a QNX file copy is not an atomic update of the entire head unit. Rollback can fail if the device or file system is damaged.
4. **Never delete the last known-good snapshot** to make room for a new deployment. Never use a destructive cleanup command on an unverified path.
5. **Configuration preservation:** respect `nbt-aad.env` and user-chosen settings (including `NBT_ALT_WIFI=CARPLAY`, if present); do not replace the configuration from a release archive.
6. **No safety bypass:** dangerous mismatches cannot be overridden by a generic `--force` flag. Any experimental pathway must be separate, opt-in, and documented.
7. **Avoid changes outside the update's documented scope**, particularly vehicle firmware, coding, and firewall, unless a separately reviewed migration requires them.

## Publish this scaffold from Ubuntu WSL

For the repository owner's Ubuntu-on-WSL setup, see [PUBLISHING.md](PUBLISHING.md). The WSL publishing entry point is `bash tools/publish.sh` (not PowerShell). It uses GitHub CLI to create a public repository after verifying the account and asking for explicit confirmation. Publishing requires no car connection and does not mean the updater is usable.

## Documentation for contributors and coding agents

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md): architecture, workflows, milestones, delivery order.
- [Safety and recovery design](docs/SAFETY_AND_RECOVERY.md): state machine, backup contract, filesystem constraints.
- [Test strategy and mandatory acceptance criteria](docs/TEST_STRATEGY.md): simulator, fault injection, coverage, CI, hardware gates.
- [Upstream compatibility research](docs/UPSTREAM_RESEARCH.md): verified upstream guidance and unresolved assumptions.
- [Claude implementation instructions](CLAUDE.md): execution requirements and definition of done.
- [Compatibility matrix](docs/COMPATIBILITY.md): only explicitly verified setups count as tested.
- [Implementation issue backlog](docs/ISSUE_BACKLOG.md): sequenced tasks for Claude.
- [Read-only head-unit probe](tools/probe/README.md): Phase 0 evidence collection; makes no writes.

## Upstream and licensing

This independent manager is intended to be licensed under **MIT** for its own original source code. It does **not** include or relicense NBT-AAD source code or binaries. NBT-AAD itself is covered by **PolyForm Noncommercial License 1.0.0**; see the [upstream license](https://github.com/Sq00ky/Supra-iDrive6-Android-Auto/blob/main/LICENSE.md) and its required notice:

> Required Notice: Copyright (c) 2026 nanaisu - NBT-AAD (https://github.com/Sq00ky/Supra-iDrive6-Android-Auto)

Do not bundle, mirror, or redistribute upstream release binaries without checking the upstream terms and permissions. Obtain assets directly from official upstream GitHub releases at runtime. A distinct installer may have different licensing and must not be copied without permission. This is an independent implementation, not a TurboCode derivative.

## Contributing

Issues, corrections, test fixtures, and pull requests are welcome. Please **do not** test unreviewed builds against a real head unit. In bug reports, redact VIN, passwords, Wi-Fi keys, and other identifying information. Do not upload backups or live logs publicly without sanitizing them.

**No release is approved for real hardware until the test gates in [TEST_STRATEGY.md](docs/TEST_STRATEGY.md) are met and the particular hardware profile is explicitly listed as validated.**
