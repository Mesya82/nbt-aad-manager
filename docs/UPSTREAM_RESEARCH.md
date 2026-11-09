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
2. The plugin library appears in both `libNbtAad.so` and `LibNbtAad.so` spellings. **Resolved for release assets (2026-11-09):** every inspected ZIP ships `libNbtAad.so`; `LibNbtAad.so` occurs only in an `updating.md` `mv` command (an upstream typo that fails harmlessly). The on-device spelling must still be observed per profile.
3. SSH examples vary between `ssh-rsa` and `ssh-dss`; actual algorithm support must be probed safely and host identity checked.
4. Upstream update script example deletes existing `.old` copy before replacing it. The manager must **not** follow this destructive practice.
5. Upstream update does not supply a comprehensive manifest of settings/state; create and verify a profile-specific plan before calling a snapshot complete.
6. SHA-256 availability on QNX is unknown. Determine if reliable remote readback/streaming exists and test it; otherwise block write mode.
7. A generic, complete, crash-proof rollback is not guaranteed by QNX. Treat incomplete state and powered-off reboot as different scenarios, never promise unqualified atomicity.
8. Access to SSH via direct IP or forwarding proxy can affect host-key verification and authentication. Avoid weakening identity checks silently.
9. Versions in separate release tags may not express daemon/plugin compatibility in SemVer form. Do not infer compatibility based solely on naming convention.

## Facts Claude must collect before implementation of remote writes

For at least the pilot head-unit profile: exact QNX version and shell behavior; target paths and case; process launch/stop commands; command exit status; mount state/remount behavior; directory/permission/symlink preservation; available disk/USB discovery; working secure checksum/readback capabilities; journal persistence; actual staged ZIP extraction; restart and runtime verification procedure. Use sanitized command outputs and document each observed behavior. Unknown means blocking.

## Evidence update 2026-11-09 (GitHub API, release assets, binary strings)

Collected read-only from the upstream GitHub API and by inspecting downloaded release assets on a host (no vehicle involved). Re-check before relying on it; upstream ships several releases per day.

### Releases and assets

- 34 releases between 2026-10-27 and 2026-11-08. Tags are feature-branch names (`gps`, `brwsr-ap`, `winmgr`, `debug`, `Installer`, `stable`, `beta2`, ...), not versions. `stable` is flagged **prerelease** and is one of the oldest. API order is neither chronological nor meaningful.
- The plugin archive asset name varies: `Release.zip`, `release.zip`, `releases.zip`, `Releases.zip`. The single top-level folder inside matches the asset's stem and case. `beta2` has **no** plugin archive. `pf_aa` is absent from many releases. Every observed `pf_aa` asset has the same SHA-256 (`5ae04c87...39bb`).
- Plugin payload changed over time. Older releases (e.g. `dev`, `gesture-trial`, `neutral-fix`) have 7 files, including `NbtAad_Direct.xml` and `NbtAad_Multimedia.xml`. Newer ones (e.g. `Installer`, `gps`) have 5: `libNbtAad.so`, `NbtAad.manifest`, `NbtAad.xml`, `NbtAad_ALL_Texts.zip`, `NbtAad_ALL_Images.zip`. Update and rollback must never leave a mixed set in the live plugin directory.
- ZIP entry modes are inconsistent (`0777`, `0666`, a directory entry with `0600`). Never apply archive modes; set modes from the profile.
- GitHub returns a `digest` (`sha256:...`) for **every** asset. It proves integrity relative to GitHub, not author authenticity; there are no upstream signatures.
- `nbt-aad` and `pf_aa` are 32-bit ARM EABI5 QNX ELF executables (`/usr/lib/ldqnx.so.2`), not stripped.
- The real version is embedded in the binaries, e.g. `Build: v1.9.36-combo` in the daemon; plugin builds log `rhmiapp-<n>-<suffix>`. The installed release can therefore be identified by hashing the on-device daemon against release digests, and the version by host-side string extraction, without executing anything.

### Persistent state not mentioned in `updating.md`

From strings in the `gps` daemon and `pf_aa`; to be confirmed on the device by the read-only probe:

- **Daemon persistent state** under `/var/opt/aa/`: `bootguard` (autostart boot-loop guard), `usb-aa`, `usblog`, `menu-idrive`, `show-drivemode`, `kombi-nav`, `spp-model`, `touch-peer`. The "start with the car" setting probably lives here. Some of these files may identify the user's phone; treat them as personal data.
- `/opt/aa/mic.disable` (a flag file).
- **`pf_aa --install`** rewrites `/fs/sda0/etc/pf.conf`, backs it up to `/opt/aa/pf.bak`, and **adds `NBT_KEEP_PF=1` to `/opt/aa/nbt-aad.env`**. So the env file holds installer-written state, not only user settings. `pf_aa --uninstall` restores from `pf.bak`.
- `pf_aa --check` is **not** a pure read: it writes `/dev/shmem/pf_aa-check.conf` and tests filesystem writability. It must never be used as a read-only probe; read `pf.conf` directly instead.
- The daemon reads `/opt/sys/etc/nbt_version.txt` (a candidate head-unit identity source) and the CarPlay/Wi-Fi credential stores under `/var/opt/conn/` and `/fs/sda1/opt/conn/`. The manager must never read those stores.

### Shell, transport and filesystem

- `on -f /net/hu-omap/ /bin/sh` opens a **nested interactive shell** on another QNX node. A tool cannot assume per-command exec semantics through it. Exit-status, stream and quoting propagation through `on -f <node> <cmd>` must be measured (`tools/probe` does this).
- Install creates `/opt/aa` through `/fs/sda0/opt/aa`. The update moves the plugin tree from `/opt/hmi/ID5/data/ro/Plugins/NbtAad` to `/opt/aa/NbtAad.old`. Whether those are on the same filesystem (a true rename) or not (copy plus delete, non-atomic) is **unknown**.
- Host side: OpenSSH 10.x has **no DSA support at all**. `install.md` uses `HostKeyAlgorithms=+ssh-dss`; `updating.md` uses `+ssh-rsa` and `-m hmac-sha1`. If a head unit offers only an `ssh-dss` host key, current OpenSSH cannot connect. The server's algorithm proposal must be captured, which `tools/probe` does before login.

### Upstream direction

- The upstream `roadmap.md` lists "One Click USB Update" (proposed tar of the plugin archive and `nbt-aad`) and an installer that already transfers files via SSH/SCP. This is evidence that SCP-style transfer works on at least some head units, relevant to SSH-only staging. Upstream may also ship an official updater; re-check before investing in overlapping features.

### Status of the evidence gate

The facts in the previous section still need on-device confirmation. The read-only probe (`tools/probe/nbt-probe.sh`) collects them, and every remote command is transcribed. Until its output has been reviewed for the pilot profile, write mode stays blocked.
