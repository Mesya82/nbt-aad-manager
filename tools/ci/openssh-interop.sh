#!/usr/bin/env bash
# CI-only (needs sudo, an ephemeral runner): run the release `nbt-aad-manager
# probe` against REAL OpenSSH servers with a fake read-only head-unit tree.
#   port 2222: sshd restricted like the pilot head unit's OpenSSH 5.2 as far as a
#              modern sshd allows: ssh-rsa/SHA-1 host key, hmac-sha1,
#              diffie-hellman-group-exchange-sha256, aes128-ctr      -> default profile
#   port 2223: stock modern sshd algorithms                         -> default profile
#   port 2224: SHA-1 KEX + CBC only (old OpenSSH)                   -> must refuse by default,
#              work only with --allow-legacy-weak
# Asserts: exit 0, one transcript record per command, read-back digests equal
# the real files, exit-status/stream/quoting semantics through a real shell,
# and that the fake tree is unchanged afterwards.
set -euo pipefail

BIN="${1:?usage: openssh-interop.sh path/to/nbt-aad-manager}"
BIN="$(realpath "$BIN")"
W="$(mktemp -d)"
USER_NAME=nbtprobe
PASS="ci-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

sudo apt-get install -y -qq openssh-server >/dev/null
sudo useradd -m -s /bin/sh "$USER_NAME" 2>/dev/null || true
echo "$USER_NAME:$PASS" | sudo chpasswd

# Fake head-unit tree (root-owned, read-only for the probe user).
sudo mkdir -p /opt/aa/NbtAad.old /opt/hmi/ID5/data/ro/Plugins/NbtAad /var/opt/aa /opt/sys/etc /fs/sda0/etc /dev/shmem
printf '\x7fELF fake daemon  Build: v1.9.36-combo (ci)\n' | sudo tee /opt/aa/nbt-aad >/dev/null
printf 'NBT_ALT_WIFI=CARPLAY\nNBT_WFD_PASS=CiSecretPass9\n' | sudo tee /opt/aa/nbt-aad.env >/dev/null
for f in libNbtAad.so NbtAad.manifest NbtAad.xml NbtAad_ALL_Texts.zip NbtAad_ALL_Images.zip; do
  printf 'fake %s rhmiapp-43-combo\n' "$f" | sudo tee "/opt/hmi/ID5/data/ro/Plugins/NbtAad/$f" >/dev/null
done
printf '1\n' | sudo tee /var/opt/aa/bootguard >/dev/null
printf 'HU_SW=CI\n' | sudo tee /opt/sys/etc/nbt_version.txt >/dev/null
printf 'x\n  Build: v1.9.36-combo (ci)\n' | sudo tee /dev/shmem/nbt-aad.log >/dev/null
sudo chmod -R a+rX /opt/aa /opt/hmi /var/opt/aa /opt/sys /dev/shmem
# `on -f <node> <cmd...>`: run the command locally (single-node emulation).
printf '#!/bin/sh\n[ "$1" = "-f" ] || exit 64\nshift 2\nexec "$@"\n' | sudo tee /usr/local/bin/on >/dev/null
sudo chmod 755 /usr/local/bin/on

tree_hash() { sudo find /opt/aa /opt/hmi /var/opt/aa /opt/sys -print0 | sort -z | sudo xargs -0 stat -c '%n %s %a %Y' | sha256sum; }
BEFORE="$(tree_hash)"

sudo ssh-keygen -q -t rsa -b 3072 -N '' -f "$W/rsa_key"
sudo ssh-keygen -q -t ed25519 -N '' -f "$W/ed_key"
sudo mkdir -p /run/sshd

start_sshd() { # port, extra config lines...
  local port="$1"; shift
  {
    echo "Port $port"; echo "ListenAddress 127.0.0.1"; echo "PasswordAuthentication yes"
    echo "KbdInteractiveAuthentication no"; echo "UsePAM yes"; echo "PermitRootLogin no"
    echo "AllowUsers $USER_NAME"; echo "PidFile $W/sshd-$port.pid"
    printf '%s\n' "$@"
  } >"$W/sshd-$port.conf"
  sudo /usr/sbin/sshd -t -f "$W/sshd-$port.conf"
  sudo /usr/sbin/sshd -f "$W/sshd-$port.conf" -E "$W/sshd-$port.log"
}

start_sshd 2222 "HostKey $W/rsa_key" "HostKeyAlgorithms ssh-rsa" "MACs hmac-sha1" \
  "KexAlgorithms diffie-hellman-group-exchange-sha256" "Ciphers aes128-ctr"
start_sshd 2223 "HostKey $W/ed_key"
start_sshd 2224 "HostKey $W/rsa_key" "HostKeyAlgorithms ssh-rsa" "MACs hmac-sha1" \
  "KexAlgorithms diffie-hellman-group14-sha1" "Ciphers aes128-cbc"
sleep 1

fail=0
check() { if eval "$2"; then echo "ok   [$SC] $1"; else echo "FAIL [$SC] $1"; fail=1; fi; }

probe_run() { # port out-dir [extra args]
  local port="$1" out="$2"; shift 2
  printf '%s\nPROBE\nno\nci interop\nyes\n\n' "$PASS" | \
    "$BIN" probe --host 127.0.0.1 --port "$port" --user "$USER_NAME" --password-stdin --cmd-timeout 20 --out "$out" "$@" \
    >"$out/console.out" 2>&1
}

SC=sshd-2224-default
OUT="$W/out-2224-default"; mkdir -p "$OUT"
set +e; probe_run 2224 "$OUT"; rc=$?; set -e
check "SHA-1 KEX / CBC server refused by default (rc=$rc)" '[[ $rc == 2 ]] && grep -q -- "--allow-legacy-weak" "$OUT/console.out"'

for port in 2222 2223 2224; do
  SC="sshd-$port"
  OUT="$W/out-$port"; mkdir -p "$OUT"
  extra=(); [[ $port == 2224 ]] && extra=(--allow-legacy-weak)
  set +e
  probe_run "$port" "$OUT" "${extra[@]}"
  rc=$?
  set -e
  R="$(echo "$OUT"/nbt-probe-*/report)"
  check "exit 0 (rc=$rc)" '[[ $rc == 0 ]] || { tail -30 "$OUT/console.out"; false; }'
  check "kexinit captured from real OpenSSH" 'grep -q "^banner: SSH-2.0-OpenSSH" "$R/ssh-kexinit.txt"'
  if [[ $port == 2222 ]]; then
    check "legacy negotiation as predicted" 'grep -q "negotiated host_key=ssh-rsa (WEAK)" "$R/ssh-kexinit.txt" && grep -q "negotiated mac_ctos=hmac-sha1 (WEAK)" "$R/ssh-kexinit.txt"'
  fi
  n_recs=$(find "$R/exec" -mindepth 1 -maxdepth 1 -type d | wc -l)
  check "one exec-log line per record ($n_recs)" '[[ $(wc -l <"$R/exec-log.tsv") == "$n_recs" ]] && (( n_recs > 150 ))'
  real_sha=$(sha256sum /opt/aa/nbt-aad | cut -d" " -f1)
  check "daemon read-back digest matches" '[[ $(grep -c "$real_sha" "$R/readback.tsv") -ge 3 ]]'
  check "exit status 7 through on + real sh" '[[ $(cat "$R"/exec/*-hu-rc-sh7/rc) == 7 ]]'
  check "stderr separated, rc 3" '[[ $(cat "$R"/exec/*-hu-split-streams/stderr) == to-stderr && $(cat "$R"/exec/*-hu-split-streams/rc) == 3 ]]'
  check "quoting through real shell" 'grep -qx "\[d'"'"'e\]" "$R"/exec/*-hu-quoting/stdout && grep -qx "\[a b\]" "$R"/exec/*-hu-quoting/stdout'
  check "secret not in report" '! grep -rqa -e CiSecretPass9 -e "$PASS" "$R"'
  check "password not stored anywhere" '! grep -rqa -e "$PASS" "$OUT"/nbt-probe-*'
done

SC=final
check "fake head-unit tree unchanged" '[[ "$BEFORE" == "$(tree_hash)" ]]'
for port in 2222 2223 2224; do sudo kill "$(cat "$W/sshd-$port.pid")" 2>/dev/null || true; done
(( fail )) && { echo "INTEROP FAILED"; exit 1; }
echo "INTEROP PASSED"
