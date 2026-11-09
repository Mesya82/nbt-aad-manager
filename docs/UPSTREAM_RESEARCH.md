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

## Pilot head unit evidence

### Probe run 1, 2026-11-09 (Rust probe, Windows 10, direct ENET)

Fixture: `tests/fixtures/pilot-g31/run1-20261109/`.

- **SSH server:** `SSH-2.0-OpenSSH_5.2 QNX_Secure_Shell-20090621-hpn13v6`.
- **Host keys:** `ssh-rsa`, `ssh-dss`. A modern client needs `ssh-rsa` (SHA-1 signatures), as `updating.md` shows. DSA is **not** required.
- **Key exchange:** `diffie-hellman-group-exchange-sha256`, `-sha1`, `group14-sha1`, `group1-sha1`. There is no curve25519/ECDH. The server answers group exchange with a **2048-bit** prime, likely the built-in fallback (no usable moduli file).
- **Ciphers:** aes{128,192,256}-ctr, arcfour*, CBC variants. The same list in both directions.
- **MACs:** only `hmac-md5`, `hmac-sha1`, `hmac-ripemd160`, and their -96 variants. `hmac-sha1` is required (as in `updating.md`).
- **Compression:** `none`, `zlib@openssh.com`.
- **Result:** stopped before login. The client required GEX primes of ≥3072 bits (the `russh` default). Fixed by accepting 2048..8192 bits, the same minimum as OpenSSH's own client. A regression test reproduces the server's behaviour.
- **Not yet observed:** everything after login (shell, `on -f`, filesystem, installed files).

### Probe runs 2 and 3, 2026-11-09 (Android Auto stopped / connected)

Fixtures: `tests/fixtures/pilot-g31/run2-20261109-aa-stopped/` and `run3-20261109-aa-running/`.

Both runs logged in and executed 162 read-only commands each. The read-back stage was skipped: the probe's `on -f` sentinel used a shell built-in (fixed, see below).

**Topology and shell**

- The SSH login lands on node `hu-jacinto`: `QNX hu-jacinto 6.5.0 … J5_Evo armle`. The shell is `/bin/ksh`, PD KSH v5.2.14, PATH `/usr/bin:/bin:/usr/sbin:/sbin`.
- `on -f /net/hu-omap/` runs on node `hu-omap`: `QNX hu-omap 6.5.0 … TI-OMAP5432-uEVM armle`, with hu-omap's own filesystem view. `/opt` → `/fs/sda0/opt` there; on the login node `/opt` → `/mnt/application/opt`, and `/opt/aa` does not exist.
- **QNX `on` executes a binary directly, without a shell.** Shell built-ins (`echo`, `true`, `test`, `kill`, `command`) fail with `on: No such file or directory (<name>)`, exit status 2. Everything must go through `on -f <node> /bin/sh -c '…'` or name a real binary.
- Through `on … /bin/sh -c`, exit status propagates exactly (7, 3), stdout and stderr stay separate, and nested quoting survives.
- The head-unit software version, read from `/opt/sys/etc/nbt_version.txt` on hu-omap, is `NBTevo_Y23236I`.

**Tools on hu-omap**

- Present: `ls cat df mount pidin use grep sed wc tail find gzip mv cp ln mkdir rm chmod dd slay sleep date sort diff pfctl devb-umass chkqnx6fs mkqnx6fs qconn`.
- **Absent:** `sha256sum sha256 sha1sum md5sum md5 cksum sum openssl od hexdump strings awk head stat readlink realpath basename dirname tar pax zip unzip mktemp rmdir chown touch sync pidof shutdown printf xargs base64 uuencode uniq cmp fsysinfo`. The login node also lacks `id` and `df`.
- Consequences:
  - There is **no on-device digest tool**, so integrity checks must read files back with `cat` and hash them on the host.
  - There is **no `sync`**, so a write path must establish durability differently.
  - There is no `mktemp`, `touch` or `rmdir`.
- QNX `mv` supports only `-f`, `-i` and `-v`; there is no `-n` or `-T`. `slay` can match by name and node (`-n`).

**Filesystems (hu-omap)**

- `/opt/aa`, `/opt/hmi/ID5/data/ro/Plugins` and `…/Plugins/NbtAad` are all on `/dev/sda0t179`, mounted at `/fs/sda0` (qnx6, 6.6 GB, 82% used, about 1.25 GB free). Moving the plugin directory into `/opt/aa` is therefore a **same-filesystem rename**. The `/opt/aa` inode is identical through `/fs/sda0/opt/aa`.
- `/var` → `/fs/sda1` (`/dev/sda0t178`, qnx6, about 438 MB free). `/dev/shmem` is RAM.
- Whether the mounts are read-only is unknown: QNX `mount` output shows no ro/rw flags. Run 4 measures it with `test -w`.

**Installed NBT-AAD**

- `/opt/aa`: `nbt-aad` (731,847 bytes, mode 777), `nbt-aad.env` (113 bytes), `nbt-aad.env.bak` (112 bytes). There is no `.old`, `pf.bak` or `mic.disable`, and no `/opt/aa/NbtAad.old`.
- The daemon's size matches only the `volsliderfixforreal` release asset (2026-11-05). That's a candidate identification; it still needs a read-back digest.
- The plugin is the 5-file layout, with exact case (`libNbtAad.so`, 66,843 bytes, dated 2026-11-05). There is no lowercase `nbtaad` directory.
- `/var/opt/aa` contains `autostart`, `usblog`, `spp-model` and `touch-peer`. There is no `bootguard` at the time of the runs.
- `pf.conf` has no Android Auto rules and `pf.bak` is absent, so `pf_aa --install` was never run on this car.
- With AA connected, the daemon runs on hu-omap as `/opt/aa/nbt-aad`, with no arguments. Its volatile logs `nbt-aad.log` and `nbt-aad-app.log` are in `/dev/shmem`.

**Incident: Android Auto disconnected during run 3**

- The operator reports that AA disconnected unexpectedly about halfway through run 3.
- The only anomalous commands were the bare `on -f /net/hu-omap/ df -k` (7.4 s) and `df -kP` (10.1 s). Together they spanned 4–21 s of the 33 s run. `df -kP` also took 10 s in run 2 with AA stopped, while every other command took under 0.3 s.
- A bare `df` stats every block device, including `/dev/cd0` (DVD drive), `/dev/hd0` (195 GB HDD) and `/dev/sda0`.
- **Likely, not proven:** a multi-second stall of the block-device drivers disturbed the running AA session.
- Mitigation (probe v3): `df` is allowed only with explicit paths (66 ms in the same runs), and all bare `df` calls are removed from both probes.
- **Lesson:** "read-only" is not "side-effect-free". Probe commands must be bounded in scope, not only non-writing.
