# Upstream Research and Evidence Register

This project is based on publicly documented behavior, **not** copied installer source code. Refresh these findings before implementation or release. Dates and release order can change. Evidence checked 2026-11-09.

## Authoritative upstream links

- Main repository: https://github.com/Sq00ky/Supra-iDrive6-Android-Auto
- Installation guide: https://github.com/Sq00ky/Supra-iDrive6-Android-Auto/blob/main/install.md
- Update guide: https://github.com/Sq00ky/Supra-iDrive6-Android-Auto/blob/main/updating.md
- GitHub Releases: https://github.com/Sq00ky/Supra-iDrive6-Android-Auto/releases
- PolyForm Noncommercial license: https://github.com/Sq00ky/Supra-iDrive6-Android-Auto/blob/main/LICENSE.md
- Separate TurboCode installer information: https://turbocode.shop/nbt-evo-android-auto/

## Upstream-confirmed facts (inspect current revisions before coding)

- Upgrade currently concerns two primary components: `nbt-aad` daemon, plus iDrive RHMI plugin tree under `/opt/hmi/ID5/data/ro/Plugins/NbtAad`.
- Existing configuration is expected to remain untouched; `/opt/aa/nbt-aad.env` may exist and must be preserved. Startup settings may be stored separately and need discovery.
- A head-unit shell uses SSH and a command to remount `/net/hu-omap/fs/sda0` RW; commands may enter a QNX host processor namespace through `on -f /net/hu-omap/ /bin/sh`.
- Example root SSH address `169.254.199.99`, but installation guide documents alternatives/proxy; never hardcode.
- Daemon is run from `/opt/aa/nbt-aad`. Upstream warns not to overwrite running files; it renames daemon and plugin before copying new contents.
- An old plugin directory should not remain under the live `Plugins` search directory, to avoid duplicate plugin loading.
- Upstream manual restart uses a long power-button hold; automated restart is not an MVP feature.
- Runtime logs mentioned: `/dev/shmem/nbt-aad.log` and `/dev/shmem/nbt-aad-app.log`, often volatile across reboot.
- Fresh install guides also use `pf_aa` firewall helper; this **does not imply** that every update should rerun it.
- GitHub releases can have **non-SemVer tags** (examples as of evidence check: `gps`, `brwsr-ap`, `winmgr`) and generally include `nbt-aad`, `Releases.zip`, sometimes `pf_aa`; some releases omit assets.
- Upstream license is PolyForm Noncommercial License 1.0.0, with required attribution. Do not copy NBT-AAD source/binaries or license them as MIT.

## Document inconsistencies / hazards to resolve

1. `updating.md` says USB directory `release` in overview, then uses `Releases` in copy command. An actual ZIP inventory must resolve case and layout.
2. The plugin library appears in both `libNbtAad.so` and `LibNbtAad.so` spellings. Determine actual on-disk paths and supported variants.
3. SSH examples vary between `ssh-rsa` and `ssh-dss`; actual algorithm support must be probed safely and host identity checked.
4. Upstream update script example deletes existing `.old` copy before replacing it. The manager must **not** follow this destructive practice.
5. Upstream update does not supply a comprehensive manifest of settings/state; create and verify a profile-specific plan before calling a snapshot complete.
6. SHA-256 availability on QNX is unknown. Determine if reliable remote readback/streaming exists and test it; otherwise block write mode.
7. A generic, complete, crash-proof rollback is not guaranteed by QNX. Treat incomplete state and powered-off reboot as different scenarios, never promise unqualified atomicity.
8. Access to SSH via direct IP or forwarding proxy can affect host-key verification and authentication. Avoid weakening identity checks silently.
9. Versions in separate release tags may not express daemon/plugin compatibility in SemVer form. Do not infer compatibility based solely on naming convention.

## Facts Claude must collect before implementation of remote writes

For at least the pilot head-unit profile: exact QNX version and shell behavior; target paths and case; process launch/stop commands; command exit status; mount state/remount behavior; directory/permission/symlink preservation; available disk/USB discovery; working secure checksum/readback capabilities; journal persistence; actual staged ZIP extraction; restart and runtime verification procedure. Use sanitized command outputs and document each observed behavior. Unknown means blocking.
