#!/usr/bin/env bash
# NBT-AAD Manager — READ-ONLY head-unit probe (Phase 0 evidence collection).
#
# Collects facts about an NBT EVO head unit with an existing NBT-AAD install:
# SSH algorithms, shell/`on` semantics, tool availability, filesystem layout,
# installed file digests/versions, config and process state.
#
# SAFETY
#   * Every remote command is passed through a guard that rejects anything
#     that could write, move, delete, kill, remount or reboot. The guard fails
#     closed: the script aborts on the first rejected command.
#   * It never runs upstream binaries (nbt-aad, pf_aa) and never reads Wi-Fi
#     credential files (/var/opt/conn/*, iap2*.cfg, WFD*.conf).
#   * The password is entered into ssh's own prompt; it is never stored or logged.
#   * Run `--print-commands` to review the static remote command list first.
#
# USAGE
#   bash tools/probe/nbt-probe.sh --host 169.254.199.99            # direct ENET
#   bash tools/probe/nbt-probe.sh --host 127.0.0.1 --port 6969     # via proxy
#   bash tools/probe/nbt-probe.sh --print-commands
#   bash tools/probe/nbt-probe.sh --self-test
#
# OUTPUT  ./nbt-probe-<UTC timestamp>/
#   report/   sanitized results (safe to hand to Claude; review before posting publicly)
#   private/  raw read-back copies (binaries, unredacted small files) — keep local, never publish
set -uo pipefail

readonly PROBE_VERSION=1
HOST=""
PORT=22
USER_NAME=root
HU_NODE=/net/hu-omap/
OUT_BASE="."
CMD_TIMEOUT="${NBT_PROBE_CMD_TIMEOUT:-60}"
MAX_READBACK_BYTES=$((8 * 1024 * 1024))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*" >&2; }

usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

# --------------------------------------------------------------------------
# Guard: reject any remote command that does not match an exact, read-only
# command shape. Allowlist of full shapes (program AND arguments), not names.
# --------------------------------------------------------------------------
readonly RX_PATH='/[A-Za-z0-9._/-]*'
readonly RX_TOOL='[A-Za-z0-9_.+-]+'
# The single quoting probe is matched literally (it needs characters the
# shape grammar deliberately forbids).
readonly QUOTING_PROBE="/bin/sh -c 'for a in \"a b\" c \"d'\"'\"'e\"; do echo \"[\$a]\"; done'"

credential_path() { printf '%s' "$1" | grep -Eiq '/var/opt/conn|/opt/conn/|iap2|WFD|carplay\.ini|wpa_|hostapd'; }

# segment_ok <segment>: one simple command, no separators.
segment_ok() {
  local s="$1" p
  s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"
  if [[ "$s" =~ ^echo( [^\']*)?$ ]]; then
    [[ "${s//1>&2/}" == *'>'* ]] && { printf 'redirect in echo'; return 1; }
    [[ "$s" == *'1>&2'* && "$s" != 'echo to-stderr 1>&2' ]] && { printf 'redirect in echo'; return 1; }
    return 0
  fi
  [[ "$s" == *'$'* ]] && { printf 'variable outside echo'; return 1; }
  [[ "$s" == *'>'* ]] && { printf 'redirect'; return 1; }
  if [[ "$s" =~ ^(true|false|id|date|uname\ -a|mount|pidin|pidin\ -p\ nbt-aad\ arg|nonexistent-nbt-probe-cmd)$ ]] ||
     [[ "$s" =~ ^exit\ [0-9]{1,3}$ ]] ||
     [[ "$s" =~ ^command\ -v\ ${RX_TOOL}$ ]] ||
     [[ "$s" =~ ^use\ ${RX_TOOL}$ ]] ||
     [[ "$s" =~ ^ls(\ -[laRdi]+)?(\ ${RX_PATH})+$ ]] ||
     [[ "$s" =~ ^cat\ ${RX_PATH}$ ]] ||
     [[ "$s" =~ ^df\ -kP?(\ ${RX_PATH})*$ ]] ||
     [[ "$s" =~ ^(sha256sum|sha256|md5sum|md5|cksum|sum)\ ${RX_PATH}$ ]] ||
     [[ "$s" =~ ^openssl\ dgst\ -sha256\ ${RX_PATH}$ ]]; then
    for p in $s; do
      [[ "$p" == /* ]] || continue
      [[ "$p" == *..* || "$p" == *//* ]] && { printf 'path traversal: %s' "$p"; return 1; }
      credential_path "$p" && { printf 'credential path: %s' "$p"; return 1; }
    done
    return 0
  fi
  printf 'command shape not allowlisted: %s' "$s"; return 1
}

# segments_ok <text>: `;`-separated simple commands.
segments_ok() {
  local seg rest="$1"
  while :; do
    seg="${rest%%;*}"
    segment_ok "$seg" || return 1
    [[ "$rest" == *';'* ]] || break
    rest="${rest#*;}"
  done
}

guard_check() {
  local cmd="$1" body
  case "$cmd" in
    *$'\n'*|*$'\r'*|*'`'*|*'$('*|*'|'*|*'<'*|*'*'*|*'?'*|*'\'*) printf 'forbidden metacharacter'; return 1 ;;
  esac
  local no_dup="${cmd//1>&2/}"
  [[ "$no_dup" == *'&'* ]] && { printf 'background/and operator'; return 1; }
  body="$cmd"
  if [[ "$body" == on* ]]; then
    [[ "$body" == "on -f $HU_NODE "* ]] || { printf 'on: only "on -f %s" is allowed' "$HU_NODE"; return 1; }
    body="${body#"on -f $HU_NODE "}"
  fi
  [[ "$body" == "$QUOTING_PROBE" ]] && return 0
  [[ "$body" == *'['* ]] && { printf 'glob'; return 1; }
  if [[ "$body" == "/bin/sh -c '"*"'" ]]; then
    body="${body#"/bin/sh -c '"}"; body="${body%"'"}"
    [[ "$body" == *"'"* ]] && { printf 'nested quote'; return 1; }
  elif [[ "$body" == *"'"* ]]; then
    printf 'quote outside /bin/sh -c'; return 1
  fi
  segments_ok "$body"
}

# --------------------------------------------------------------------------
# Redaction for text saved into report/ (best effort; private/ keeps raw).
# --------------------------------------------------------------------------
redact() {
  sed -E \
    -e 's/(^|[^A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}([^A-Za-z0-9]|$)/\1<REDACTED-VIN17>\2/g' \
    -e 's/(^|[^0-9A-Fa-f])([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}([^0-9A-Fa-f]|$)/\1<REDACTED-MAC>\3/g' \
    -e 's/(^|[^0-9A-Fa-f])[0-9A-Fa-f]{12}([^0-9A-Fa-f]|$)/\1<REDACTED-HEX12>\2/g' \
    -e 's/^([[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(PASS|PSK|KEY|SECRET|TOKEN|SSID|PIN|WIFI_NAME|PHONE)[A-Za-z0-9_]*[[:space:]]*=).*/\1<REDACTED>/I' \
    -e "s/([\"']?(pass(word|phrase|wd)?|psk|ssid|secret|token|pin|passkey)[\"']?[[:space:]]*[=:][[:space:]]*).*/\\1<REDACTED>/I" \
    -e 's/<(pass(word|phrase)?|psk|ssid|key|secret|passkey)>[^<]*</<\1><REDACTED></Ig'
}

safe_name() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ && "$1" != "." && "$1" != ".." ]]; }
safe_path() { [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ && "$1" != *..* ]]; }

# --------------------------------------------------------------------------
# Static probe table: ID <TAB> CONTEXT(outer|hu) <TAB> remote command
# outer = command runs in the SSH login shell; hu = wrapped as `on -f $HU_NODE ...`
# --------------------------------------------------------------------------
probe_table() {
  local P=/opt/hmi/ID5/data/ro/Plugins
  cat <<EOF
outer-echo	outer	echo probe-ok
outer-uname	outer	uname -a
outer-shell	outer	echo "0=\$0 SHELL=\$SHELL KSH=\$KSH_VERSION PATH=\$PATH PWD=\$PWD"
outer-id	outer	id
outer-date	outer	date
outer-rc-true	outer	true
outer-rc-false	outer	false
outer-rc-sh7	outer	/bin/sh -c 'exit 7'
outer-rc-missing-file	outer	ls /nonexistent-nbt-probe
outer-rc-missing-cmd	outer	nonexistent-nbt-probe-cmd
outer-split-streams	outer	echo to-stdout; echo to-stderr 1>&2; exit 3
outer-ls-root	outer	ls -la /
outer-ls-net	outer	ls -la /net
outer-ls-fs	outer	ls -la /fs
outer-ls-mnt	outer	ls -la /mnt
outer-ls-opt	outer	ls -la /opt
outer-ls-opt-aa	outer	ls -la /opt/aa
outer-which-on	outer	command -v on
outer-mount	outer	mount
outer-df	outer	df -k
outer-df-P	outer	df -kP
outer-nbt-version	outer	cat /opt/sys/etc/nbt_version.txt
outer-pidin	outer	pidin
hu-echo	hu	echo probe-ok
hu-rc-true	hu	true
hu-rc-false	hu	false
hu-rc-sh7	hu	/bin/sh -c 'exit 7'
hu-rc-missing-file	hu	ls /nonexistent-nbt-probe
hu-rc-missing-cmd	hu	nonexistent-nbt-probe-cmd
hu-split-streams	hu	/bin/sh -c 'echo to-stdout; echo to-stderr 1>&2; exit 3'
hu-quoting	hu	/bin/sh -c 'for a in "a b" c "d'"'"'e"; do echo "[\$a]"; done'
hu-uname	hu	uname -a
hu-shell	hu	/bin/sh -c 'echo "0=\$0 SHELL=\$SHELL KSH=\$KSH_VERSION PATH=\$PATH PWD=\$PWD"'
hu-id	hu	id
hu-date	hu	date
hu-nbt-version	hu	cat /opt/sys/etc/nbt_version.txt
hu-ls-root	hu	ls -la /
hu-ls-net	hu	ls -la /net
hu-ls-fs	hu	ls -la /fs
hu-ls-mnt	hu	ls -la /mnt
hu-ls-opt	hu	ls -la /opt
hu-ls-fs-sda0	hu	ls -la /fs/sda0
hu-ls-fs-sda0-opt	hu	ls -la /fs/sda0/opt
hu-ls-opt-aa	hu	ls -la /opt/aa
hu-ls-fs-sda0-opt-aa	hu	ls -la /fs/sda0/opt/aa
hu-lsR-opt-aa	hu	ls -laR /opt/aa
hu-ls-plugins	hu	ls -la $P
hu-ls-plugin-nbtaad	hu	ls -la $P/NbtAad
hu-ls-plugin-nbtaad-lower	hu	ls -la $P/nbtaad
hu-ls-nbtaad-old	hu	ls -la /opt/aa/NbtAad.old
hu-ls-var-opt	hu	ls -la /var/opt
hu-ls-var-opt-aa	hu	ls -la /var/opt/aa
hu-ls-dev-shmem	hu	ls -la /dev/shmem
hu-lsd-paths	hu	ls -ld /opt /opt/aa /opt/hmi /opt/hmi/ID5 /opt/hmi/ID5/data /opt/hmi/ID5/data/ro $P $P/NbtAad /fs/sda0 /fs/sda0/opt /fs/sda0/opt/aa /fs/sda1 /var /var/opt /var/opt/aa /mnt /dev/shmem
hu-lsdi-paths	hu	ls -ldi /opt/aa $P $P/NbtAad /fs/sda0/opt/aa /var/opt/aa /dev/shmem
hu-mount	hu	mount
hu-df	hu	df -k
hu-df-P	hu	df -kP
hu-df-paths	hu	df -k /opt/aa $P $P/NbtAad /var/opt/aa /fs/sda0 /fs/sda1 /dev/shmem
hu-pidin	hu	pidin
hu-pidin-arg	hu	pidin -p nbt-aad arg
hu-pf-conf	hu	cat /fs/sda0/etc/pf.conf
hu-etc-pf-conf	hu	cat /etc/pf.conf
hu-ls-pf-bak	hu	ls -la /opt/aa/pf.bak
EOF
  local t
  for t in sh ksh on ls cat df mount pidin use sha256sum sha256 sha1sum md5sum md5 cksum sum openssl \
           od hexdump strings grep sed awk wc head tail find stat readlink realpath basename dirname \
           tar pax gzip zip unzip mktemp mv cp ln mkdir rmdir rm chmod chown touch dd sync fsync \
           kill slay pidof shutdown sleep date printf test xargs base64 uuencode sort uniq cmp diff \
           fsysinfo chkqnx6fs mkqnx6fs devb-umass qconn pfctl; do
    printf 'hu-cmdv-%s\thu\t/bin/sh -c '"'"'command -v %s'"'"'\n' "$t" "$t"
  done
  for t in ls cp mv df mount pidin cksum md5 sha256sum on mkdir ln chmod sync slay find stat tar pax mktemp; do
    printf 'hu-use-%s\thu\tuse %s\n' "$t" "$t"
  done
  # On-device digests of the daemon (if any digest tool exists).
  for t in sha256sum sha256 md5sum md5 cksum sum; do
    printf 'hu-digest-%s\thu\t%s /opt/aa/nbt-aad\n' "$t" "$t"
  done
  printf 'hu-digest-openssl\thu\topenssl dgst -sha256 /opt/aa/nbt-aad\n'
}

print_commands() {
  local id ctx cmd full why bad=0
  while IFS=$'\t' read -r id ctx cmd; do
    full="$(wrap "$ctx" "$cmd")"
    if why="$(guard_check "$full")"; then
      printf '%-28s %s\n' "$id" "$full"
    else
      printf '%-28s REJECTED(%s): %s\n' "$id" "$why" "$full"; bad=1
    fi
  done < <(probe_table)
  cat <<EOF

Dynamic commands (generated at runtime from device listings; names must match
^[A-Za-z0-9._-]+\$, otherwise they are skipped):
  on -f $HU_NODE cat <dir>/<file>        for regular files in /opt/aa, the NbtAad plugin dir,
                                          /opt/aa/NbtAad.old and /var/opt/aa (hashed on host)
  on -f $HU_NODE cat /dev/shmem/nbt-aad.log | (host-side filter: only Build:/create( lines kept)
  on -f $HU_NODE ls -la /mnt/<umass*>    and cat of NBT-Probe-Marker.txt (optional USB step)
EOF
  return $bad
}

wrap() { if [[ "$1" == hu ]]; then printf 'on -f %s %s' "$HU_NODE" "$2"; else printf '%s' "$2"; fi; }

# --------------------------------------------------------------------------
# SSH plumbing
# --------------------------------------------------------------------------
SSH_OPTS=()
setup_ssh_opts() {
  SSH_OPTS=(
    -F /dev/null -p "$PORT"
    -o "UserKnownHostsFile=$KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=yes
    -o HostKeyAlgorithms=+ssh-rsa
    -o MACs=+hmac-sha1
    -o PubkeyAuthentication=no -o IdentitiesOnly=yes -o IdentityFile=none -o IdentityAgent=none
    -o PreferredAuthentications=keyboard-interactive,password -o GSSAPIAuthentication=no
    -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3
    -o "ControlPath=$CTL_SOCK"
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes
  )
}

# run_remote <id> <policy> <stdout-file> <command>  -> sets RC; never mutates.
# Every call is recorded as one transcript entry (the raw material for test
# fixtures and the future replay transport):
#   report/exec/NNNN-id/{cmd,rc,ms,started_utc,policy,stdout.sha256,stdout.bytes,
#                        stderr.sha256,stderr.bytes,stdout,stderr}
#   report/exec-log.tsv   one line per call
#   private/exec/NNNN-id.{stdout,stderr}  raw, unredacted (text policy only)
# Policies: text   = stdout stored (raw in private/, redacted in report/)
#           binary = stdout kept only at <stdout-file> (private/), hashed in report/
#           secret = stdout hashed then discarded by the caller (volatile logs)
# Stderr is always stored (raw private, redacted report).
# Must be called in the main shell (not inside $(...)) so a guard rejection
# terminates the whole script.
RC=""
EXEC_N=0
run_remote() {
  local id="$1" policy="$2" out="$3" cmd="$4" why t0 t1 rec started
  if ! why="$(guard_check "$cmd")"; then
    die "guard rejected remote command ($why): $cmd"
  fi
  EXEC_N=$((EXEC_N + 1))
  rec="$(printf '%04d' "$EXEC_N")-$id"
  started="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  t0=$(date +%s%N)
  # BatchMode: if the master is gone, fail fast (rc 255) instead of prompting.
  timeout "$CMD_TIMEOUT" ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes -o LogLevel=ERROR -n -T "$USER_NAME@$HOST" "$cmd" >"$out" 2>"$TMPD/err"
  RC=$?
  t1=$(date +%s%N)
  local d="$REPORT/exec/$rec" p="$PRIVATE/exec/$rec"
  mkdir -p "$d" "$PRIVATE/exec"
  printf '%s\n' "$cmd" >"$p.cmd"
  printf '%s\n' "$cmd" | redact >"$d/cmd"
  printf '%s\n' "$RC" >"$d/rc"
  printf '%s\n' $(( (t1 - t0) / 1000000 )) >"$d/ms"
  printf '%s\n' "$started" >"$d/started_utc"
  printf '%s\n' "$policy" >"$d/policy"
  sha256sum <"$out" | cut -d' ' -f1 >"$d/stdout.sha256"; wc -c <"$out" | tr -d ' ' >"$d/stdout.bytes"
  sha256sum <"$TMPD/err" | cut -d' ' -f1 >"$d/stderr.sha256"; wc -c <"$TMPD/err" | tr -d ' ' >"$d/stderr.bytes"
  cp "$TMPD/err" "$p.stderr"; redact <"$TMPD/err" >"$d/stderr"
  if [[ "$policy" == text ]]; then cp "$out" "$p.stdout"; redact <"$out" >"$d/stdout"; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rec" "$policy" "$RC" "$(cat "$d/ms")" "$(cat "$d/stdout.bytes")" "$(cat "$d/stderr.bytes")" "$(cat "$d/cmd")" >>"$REPORT/exec-log.tsv"
  if [[ "$RC" == 255 ]] && ! ssh -F /dev/null -o "ControlPath=$CTL_SOCK" -O check "$USER_NAME@$HOST" 2>/dev/null; then
    printf 'connection lost after record %s; stopping (no reconnect attempts)\n' "$rec" | tee -a "$REPORT/notes.txt" >&2
    finish 3
  fi
}

# probe <id> <context> <command>: one recorded text-policy call.
probe() {
  local id="$1" ctx="$2" full
  full="$(wrap "$ctx" "$3")"
  run_remote "$id" text "$TMPD/out" "$full"
  printf '%-30s rc=%-4s %s\n' "$id" "$RC" "$(printf '%s' "$full" | redact)" >>"$REPORT/summary.txt"
  printf '  %-30s rc=%s\n' "$id" "$RC" >&2
}

# readback <remote-path> <label>: cat a remote file into private/, hash on host.
readback() {
  local path="$1" label="$2" dest rc size sha strs
  local why
  safe_path "$path" || { printf 'SKIP unsafe path\n' >>"$REPORT/readback-notes.txt"; return; }
  if ! why="$(guard_check "on -f $HU_NODE cat $path")"; then
    printf 'SKIP %s: %s\n' "$why" "$path" | redact >>"$REPORT/readback-notes.txt"; return
  fi
  dest="$PRIVATE/readback/${label}"
  mkdir -p "$(dirname "$dest")"
  run_remote "readback" binary "$dest" "on -f $HU_NODE cat $path"; rc="$RC"
  size=$(wc -c <"$dest" | tr -d ' ')
  sha=$(sha256sum "$dest" | cut -d' ' -f1)
  strs=$(strings -n 6 "$dest" 2>/dev/null | grep -Eo 'Build: v[^ ]+|rhmiapp-[A-Za-z0-9._-]+' | sort -u | tr '\n' ' ')
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(printf '%s' "$path" | redact)" "$rc" "$size" "$sha" "$strs" "$(redact <"$TMPD/err" | tr '\n' ' ')" >>"$REPORT/readback.tsv"
}

# list_regular_files <remote-dir> -> writes "name<TAB>size" lines for regular files to $TMPD/files
list_regular_files() {
  local dir="$1"
  : >"$TMPD/files"
  run_remote "list" text "$TMPD/ls" "on -f $HU_NODE ls -la $dir"
  if [[ "$RC" != 0 ]]; then
    printf 'NOTE %s not listable (rc=%s): %s\n' "$dir" "$RC" "$(redact <"$TMPD/err" | tr '\n' ' ')" >>"$REPORT/readback-notes.txt"
    return 0
  fi
  awk '$1 ~ /^-/ && NF == 9 { print $NF "\t" $5 }' "$TMPD/ls" >"$TMPD/files"
  {
    awk -v d="$dir" '$1 ~ /^-/ && NF != 9 { print "NOTE UNPARSED ls line in " d " (" NF " fields, file not read back): " $0 }' "$TMPD/ls"
    awk -v d="$dir" '$1 !~ /^[-dl]/ && $1 !~ /^total/ && NF > 2 { print "NOTE non-regular entry in " d ": " $0 }' "$TMPD/ls"
    awk -v d="$dir" '$1 ~ /^l/ { print "NOTE symlink in " d " (not followed): " $0 }' "$TMPD/ls"
  } | redact >>"$REPORT/readback-notes.txt"
}

readback_dir() {
  local dir="$1" label="$2" name size
  list_regular_files "$dir"
  cp "$TMPD/files" "$TMPD/files.$label"
  while IFS=$'\t' read -r name size; do
    if ! safe_name "$name"; then printf 'SKIP unsafe file name in %s (name not recorded)\n' "$dir" >>"$REPORT/readback-notes.txt"; continue; fi
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size > MAX_READBACK_BYTES )); then
      printf 'SKIP too large (%s bytes): %s/%s\n' "$size" "$dir" "$name" | redact >>"$REPORT/readback-notes.txt"; continue
    fi
    readback "$dir/$name" "$label/$name"
  done <"$TMPD/files.$label"
}

# --------------------------------------------------------------------------
# Self-test (no network): guard + redaction + static table.
# --------------------------------------------------------------------------
self_test() {
  local fail=0 c
  local -a must_reject=(
    'rm -r /opt/aa/nbt-aad.old' 'mv /opt/aa/nbt-aad /opt/aa/x' 'cp a b' 'mount -o remount rw /net/hu-omap/fs/sda0'
    'on -f /net/hu-omap/ mount -uw /fs/sda0' 'kill 123' 'slay nbt-aad' 'echo x > /opt/aa/f' 'cat a >>b'
    'shutdown' 'chmod +x /opt/aa/nbt-aad' '/opt/aa/nbt-aad' '/dev/shmem/pf_aa --check' 'pfctl -sr'
    'on -f /net/hu-omap/ /bin/sh -c '"'"'rm x'"'"'' 'OnOffDSICommander appreset' 'mkdir /opt/aa/x' 'touch /tmp/x'
    'cat /var/opt/conn/WFDPass.conf' 'cat /fs/sda1/opt/conn/carplay/iap2_Wifi.cfg' 'echo $(id)' 'eval rm'
    'ls; rm x' 'ls && mv a b' 'ls | tee f' 'dd if=/dev/zero of=/x' 'sed -i s/a/b/ f' 'umount /fs/usb0' 'ln -s a b'
    'cd /opt/aa' 'tar cf - /opt/aa' 'reboot'
    'ls & /opt/aa/nbt-aad' 'on -f /net/hu-omap/ ls & /bin/rm x' 'command /bin/rm -rf /opt/aa' 'command /opt/aa/nbt-aad'
    'openssl dgst -out /opt/aa/nbt-aad /opt/aa/x' 'openssl enc -out /fs/sda0/x' 'date 202601010000' 'uname -S evil'
    'cat /var/opt/aa/../conn/x' 'cat /var/opt/co*/W*' 'cat /var/opt/c?nn/x' $'ls /\nrm x' 'cat /opt/aa/x$IFS'
    'on -n /net/hu-omap/ ls /' 'on -f /net/other/ ls /' 'on -f /net/hu-omap/ on -f /net/hu-omap/ rm x'
    'ls /opt/[a]a' "/bin/sh -c 'ls /' ; rm x" "/bin/sh -c 'ls / ; rm x'" 'echo hi 1>&2 ; rm x' 'echo x 1>&2'
    'ls -la /opt/aa;/opt/aa/nbt-aad' 'pidin -p x arg' 'df -k /x; /x' 'cat /fs/sda1/opt/conn/WFDPass.conf'
    'sh -c ls' "/bin/sh -c 'cat /opt/aa/x' extra" 'exit 1; /opt/aa/nbt-aad' 'cat\ /x'
  )
  local -a must_allow=(
    'ls -la /opt/aa' 'cat /opt/aa/nbt-aad' 'cat /opt/aa/nbt-aad.env' 'on -f /net/hu-omap/ cat /opt/aa/nbt-aad.old'
    'mount' 'on -f /net/hu-omap/ mount' 'use mv' "/bin/sh -c 'command -v rm'" 'df -k /opt/aa' 'pidin'
    'on -f /net/hu-omap/ /bin/sh -c '"'"'echo to-stdout; echo to-stderr 1>&2; exit 3'"'"''
    'ls -la /opt/hmi/ID5/data/ro/Plugins/NbtAad' 'sha256sum /opt/aa/nbt-aad' 'pidin -p nbt-aad arg'
  )
  for c in "${must_reject[@]}"; do
    if guard_check "$c" >/dev/null; then echo "FAIL guard allowed: $c"; fail=1; fi
  done
  for c in "${must_allow[@]}"; do
    if ! guard_check "$c" >/dev/null; then echo "FAIL guard rejected: $c ($(guard_check "$c"))"; fail=1; fi
  done
  print_commands >/dev/null || { echo "FAIL static probe table contains a rejected command"; fail=1; }
  local r
  r="$(printf 'NBT_ALT_WIFI=CARPLAY\nNBT_WFD_PASS=hunter2\nVIN WBAJA11010B123456 x\nmac 00:11:22:AA:BB:CC\npassword: s3cr3t\n' | redact)"
  [[ "$r" == *'NBT_ALT_WIFI=CARPLAY'* ]] || { echo "FAIL redaction removed NBT_ALT_WIFI"; fail=1; }
  r+="$(printf '{"password": "hunter3", "ssid": "MyNet4"}\n<psk>abc12345</psk>\npassword: two words5\nmac 001122AABBC6\nvin_WBAJA11010B654321_x\n' | redact)"
  for c in hunter2 WBAJA11010B123456 '00:11:22:AA:BB:CC' s3cr3t hunter3 MyNet4 abc12345 words5 001122AABBC6 WBAJA11010B654321; do
    [[ "$r" != *"$c"* ]] || { echo "FAIL redaction leaked: $c"; fail=1; }
  done
  safe_name 'libNbtAad.so' || { echo "FAIL safe_name"; fail=1; }
  ! safe_name '..' && ! safe_name 'a;b' && ! safe_name 'a b' && ! safe_name '$(x)' || { echo "FAIL safe_name accepted unsafe"; fail=1; }
  ! safe_path '/opt/../etc' && ! safe_path 'opt/aa' || { echo "FAIL safe_path accepted unsafe"; fail=1; }
  if (( fail )); then echo "SELF-TEST FAILED"; return 1; fi
  echo "self-test passed (${#must_reject[@]} rejections, ${#must_allow[@]} allowances)"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
MODE=run
need() { (( $1 >= 2 )) || die "option $2 needs a value"; }
while (($#)); do
  case "$1" in
    --host) need $# "$1"; HOST="$2"; shift 2 ;;
    --port) need $# "$1"; PORT="$2"; shift 2 ;;
    --user) need $# "$1"; USER_NAME="$2"; shift 2 ;;
    --hu-node) need $# "$1"; HU_NODE="$2"; shift 2 ;;
    --out) need $# "$1"; OUT_BASE="$2"; shift 2 ;;
    --print-commands) MODE=print; shift ;;
    --self-test) MODE=selftest; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ "$HU_NODE" =~ ^/net/[A-Za-z0-9_-]+/$ ]] || die "--hu-node must look like /net/<name>/"
case "$MODE" in
  print) print_commands; exit $? ;;
  selftest) self_test; exit $? ;;
esac

[[ -n "$HOST" ]] || die "--host is required (see --help)"
[[ "$HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || die "invalid --host"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "invalid --port"
[[ "$CMD_TIMEOUT" =~ ^[0-9]+$ ]] || die "invalid NBT_PROBE_CMD_TIMEOUT"
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid --user"
for t in ssh ssh-keyscan ssh-keygen timeout sha256sum strings awk sed grep tar; do
  command -v "$t" >/dev/null || die "missing host tool: $t"
done
self_test >/dev/null || die "internal self-test failed; not connecting"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_BASE/nbt-probe-$STAMP"
REPORT="$OUT/report"; PRIVATE="$OUT/private"
mkdir -p "$REPORT/exec" "$PRIVATE" || die "cannot create $OUT"
chmod 700 "$OUT" "$PRIVATE"
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/nbtp.XXXXXX")" || die "mktemp failed"
CTL_SOCK="$TMPD/c"
KNOWN_HOSTS="$REPORT/known_hosts"
# finish <exit-code>: package report/ (private/ excluded) and exit.
finish() {
  note "Packaging"
  tar -C "$OUT" -czf "$OUT/report.tgz" report
  cat >&2 <<EOM

$( (( $1 == 0 )) && echo "Done." || echo "Stopped early (code $1) — the partial report is still useful.") Nothing was written on the head unit.
  Report for Claude: $OUT/report/   (also $OUT/report.tgz)
  Raw copies:        $OUT/private/  (keep local; contains upstream binaries and unredacted state)
Glance through report/ before posting it anywhere public.
EOM
  exit "$1"
}
cleanup() {
  [[ -S "$CTL_SOCK" ]] && ssh -F /dev/null -o "ControlPath=$CTL_SOCK" -O exit "$USER_NAME@$HOST" 2>/dev/null
  rm -rf "$TMPD"
}
trap cleanup EXIT

exec 3>&2 2> >(tee -a "$REPORT/console.log" >&3)

cat >&2 <<EOF

NBT-AAD Manager READ-ONLY probe v$PROBE_VERSION
Target: $USER_NAME@$HOST:$PORT   HU node: $HU_NODE
Output: $OUT

Preconditions (you confirm):
  - vehicle is parked; you control power; nobody is driving
  - SSH on the head unit is ALREADY enabled (this script does not enable it)
  - you have NOT remounted anything read-write in another session
This script makes NO writes on the head unit. Review commands with --print-commands.
EOF
read -r -p "Type PROBE to continue: " ans
[[ "$ans" == PROBE ]] || die "cancelled"
read -r -p "Is Android Auto currently running on the head unit? (yes/no/unknown): " aa_state
read -r -p "Optional free-text note for this run (e.g. 'after fresh boot'): " run_note

{
  echo "probe_version=$PROBE_VERSION"
  echo "utc=$STAMP"
  echo "target=$USER_NAME@$HOST:$PORT"
  echo "hu_node=$HU_NODE"
  echo "aa_running_user_reported=$aa_state"
  echo "note=$(printf '%s' "$run_note" | redact)"
  echo "host_uname=$(uname -a)"
  echo "host_ssh=$(ssh -V 2>&1)"
  echo "host_bash=$BASH_VERSION"
  grep -qi microsoft /proc/version 2>/dev/null && echo "host_wsl=yes"
} >"$REPORT/meta.txt"

# 1. Unauthenticated algorithm discovery (KEXINIT) — BatchMode, no password.
note "Capturing server SSH algorithm proposal (no login)"
# StrictHostKeyChecking=no is acceptable ONLY here: BatchMode + dummy user +
# no keys/agent/GSSAPI means this connection can never authenticate.
timeout 30 ssh -F /dev/null -vv -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no \
  -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
  -o PubkeyAuthentication=no -o IdentityAgent=none -o ConnectTimeout=15 \
  "probe-nologin@$HOST" true 2>&1 </dev/null \
  | grep -E 'Remote protocol version|KEXINIT proposal|KEX algorithms|host key algorithms|ciphers ctos|ciphers stoc|MACs ctos|MACs stoc|compression ctos|no matching|Unable to negotiate|kex: algorithm|kex: host key algorithm|kex: server->client|kex: client->server|Authentications that can continue|Connection refused|timed out|No route' \
  | redact >"$REPORT/ssh-kexinit.txt"
cat "$REPORT/ssh-kexinit.txt" >&2

# 2. Host key fingerprint (TOFU with explicit user confirmation).
note "Fetching host keys"
timeout 30 ssh-keyscan -T 10 -p "$PORT" "$HOST" 2>"$REPORT/ssh-keyscan.stderr" >"$TMPD/keys"
if [[ ! -s "$TMPD/keys" ]]; then
  echo "ssh-keyscan returned no keys this OpenSSH can use (a DSA-only server is unusable with OpenSSH >= 10)." >&2
  echo "Evidence saved in $REPORT/ssh-kexinit.txt. Stopping before login." >&2
  exit 2
fi
ssh-keygen -lf "$TMPD/keys" | tee "$REPORT/ssh-hostkey-fingerprints.txt" >&2
cp "$TMPD/keys" "$KNOWN_HOSTS"
echo "Pinned these keys for this probe only (in $KNOWN_HOSTS; ~/.ssh is not modified)." >&2
read -r -p "You are directly cabled to your own car and accept these fingerprints? (yes/no): " ans
[[ "$ans" == yes ]] || die "host key not accepted"

# 3. Single interactive login; all probes reuse it.
setup_ssh_opts
note "Logging in (ssh will prompt for the password; it is not stored)"
if ! ssh "${SSH_OPTS[@]}" -o ControlMaster=yes -o ControlPersist=3600 -o LogLevel=ERROR -fN "$USER_NAME@$HOST" 2> >(redact | tee "$REPORT/ssh-login.stderr" >&2); then
  die "SSH login failed; see $REPORT/ssh-login.stderr and ssh-kexinit.txt"
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -S "$CTL_SOCK" ]] && break; sleep 0.5; done
ssh -F /dev/null -o "ControlPath=$CTL_SOCK" -O check "$USER_NAME@$HOST" 2>>"$REPORT/ssh-login.stderr" || die "SSH multiplexing unavailable"

# 4. Static probes.
note "Running static probes"
while IFS=$'\t' read -r id ctx cmd; do
  probe "$id" "$ctx" "$cmd"
done < <(probe_table)

# Stop early if `on` does not work at all — every remaining step depends on it.
if [[ "$(cat "$REPORT"/exec/*-hu-echo/stdout 2>/dev/null)" != probe-ok* ]]; then
  echo "'on -f $HU_NODE' did not work; skipping read-back steps. Send me the folder anyway." >&2
else
  # 5. Read-back and host-side hashing.
  note "Reading back installed files (hashing on this computer)"
  printf 'path\trc\tbytes\tsha256\tembedded_versions\tstderr\n' >"$REPORT/readback.tsv"
  : >"$REPORT/readback-notes.txt"
  readback_dir /opt/aa opt-aa
  readback_dir /opt/hmi/ID5/data/ro/Plugins/NbtAad plugin-NbtAad
  readback_dir /opt/aa/NbtAad.old opt-aa-NbtAad.old
  readback_dir /var/opt/aa var-opt-aa
  # Read-back reliability: same file twice.
  readback /opt/aa/nbt-aad repeat/nbt-aad.2
  readback /opt/aa/nbt-aad repeat/nbt-aad.3

  # Redacted copies of KNOWN small text state for the report. Anything else
  # (e.g. /var/opt/aa/spp-model, touch-peer: phone identity) stays hash-only.
  mkdir -p "$REPORT/text"
  for f in "$PRIVATE"/readback/opt-aa/{nbt-aad.env,pf.bak,mic.disable} \
           "$PRIVATE"/readback/var-opt-aa/{bootguard,usb-aa,usblog,menu-idrive,show-drivemode,kombi-nav}; do
    [[ -f "$f" ]] || continue
    if (( $(wc -c <"$f") <= 65536 )) && (( $(tr -d '\000' <"$f" | wc -c) == $(wc -c <"$f") )); then
      redact <"$f" >"$REPORT/text/$(basename "$(dirname "$f")")__$(basename "$f")"
    fi
  done

  # 6. Daemon logs: only version lines leave the stream.
  note "Extracting version lines from volatile logs"
  for lg in nbt-aad.log nbt-aad-app.log; do
    run_remote "log-$lg" secret "$TMPD/log" "on -f $HU_NODE cat /dev/shmem/$lg"
    { echo "# /dev/shmem/$lg rc=$RC bytes=$(wc -c <"$TMPD/log" | tr -d ' ')"
      grep -aE 'Build:|create\(name=|rhmiapp-' "$TMPD/log" | head -20 | redact
    } >>"$REPORT/log-versions.txt"
    : >"$TMPD/log"
  done

  # 7. Optional USB discovery and read-back test.
  MARKER_NAME=NBT-Probe-Marker.txt
  head -c 4096 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 4096 >"$OUT/$MARKER_NAME"
  echo >>"$OUT/$MARKER_NAME"
  cat >&2 <<EOF

Optional USB test: copy $OUT/$MARKER_NAME
to the ROOT of a FAT32/exFAT stick (keep the exact file name), plug it into the car,
wait ~10 s. Type 'usb' when ready, or just press Enter to skip.
EOF
  read -r -p "> " ans
  if [[ "$ans" == usb ]]; then
    sha256sum "$OUT/$MARKER_NAME" | cut -d' ' -f1 >"$REPORT/usb-marker-expected.sha256"
    probe hu-usb-ls-mnt hu "ls -la /mnt"
    probe hu-usb-mount hu "mount"
    probe hu-usb-df hu "df -k"
    run_remote "usb-ls-mnt-short" text "$TMPD/mnt" "on -f $HU_NODE ls /mnt"
    tr -s ' \t' '\n\n' <"$TMPD/mnt" >"$TMPD/mnt.list"
    while read -r m; do
      [[ "$m" =~ ^umass[A-Za-z0-9_]*$ ]] || continue
      probe "hu-usb-ls-$m" hu "ls -la /mnt/$m"
      probe "hu-usb-df-$m" hu "df -k /mnt/$m"
      for cand in "$MARKER_NAME" nbt-probe-marker.txt NBT-PROBE-MARKER.TXT; do
        readback "/mnt/$m/$cand" "usb/$m/$cand"
      done
    done <"$TMPD/mnt.list"
  fi
fi

finish 0
