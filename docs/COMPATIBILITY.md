# Hardware Compatibility and Validation Matrix

**No real-vehicle validation has yet been completed for this new manager.** This matrix documents *evidence*, not plausible support.

| Profile | Vehicle | Head unit | Software | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| planned-pilot-g31 | BMW G31 530i, 2018 | NBT EVO / iDrive 6 (user-reported) | SSH server `OpenSSH_5.2 QNX_Secure_Shell-20090621-hpn13v6` (probe run 1) | **NOT TESTED for this manager** | Read-only probe runs 1–3 (2026-11-09): SSH, shell, `on`, filesystem, tools and installed layout observed; read-backs not yet run; AA disconnect during run 3 (likely bare `df`, removed). `tests/fixtures/pilot-g31/` |
| other | Other BMW/Toyota models | Various | Unknown | **NOT TESTED / UNSUPPORTED** | None |

## Android client profiles

No Android profile exists or is supported. A row requires the exact phone model, Android version, USB Ethernet adapter (chipset), ENET cable, head-unit hardware/software and installed NBT-AAD build, plus parked-hardware evidence (AND-08).

| Profile | Phone / Android | USB Ethernet adapter | ENET cable | Head unit / software | NBT-AAD build | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| (none) | - | - | - | - | - | **NOT TESTED / UNSUPPORTED** | None |

## Rules

- "Tested" means an actual recorded hardware procedure completed, not that upstream NBT-AAD works on a vehicle.
- Record exact HU hardware identifiers, software versions and command capabilities after sanitized inspection; do not record VIN or credentials in this public repo.
- If a profile is only simulator-tested, label it `simulator-only`.
- Any material change to QNX, release layout, process behavior or recovery semantics requires revalidation.
- No default wildcard support for all NBT EVO versions; unknown profiles are read-only.
