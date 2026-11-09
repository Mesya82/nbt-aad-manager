#!/usr/bin/env bash
# End-to-end tests of nbt-probe.sh against a fake head unit (Linux + bubblewrap).
#
# A fake `ssh` executes each remote command inside a bwrap sandbox whose root
# is a synthetic NBT EVO tree mounted READ-ONLY. It honours ControlPath
# (master socket), BatchMode, `-O check/exit` and the pinned known_hosts, and
# supports fault injection via FAKE_* variables.
#
# Scenarios:
#   main        full run; no writes; no leaks; read-back hashes; transcript completeness
#   master-dies control master disappears mid-run -> fast stop, partial report, no further calls
#   hang        one command hangs -> timeout rc 124 recorded, run continues
#   wrong-key   server key differs from the pinned one -> login refused, zero remote calls
#   ls-8col     unexpected `ls -l` layout -> files reported UNPARSED, nothing guessed
#
# Usage: bash tools/probe/tests/fake-device-test.sh [real nbt-aad] [real Releases.zip]
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROBE="$HERE/../nbt-probe.sh"
if ! command -v bwrap >/dev/null; then
  [[ -n "${REQUIRE_BWRAP:-}" ]] && { echo "FAIL: bwrap required (REQUIRE_BWRAP set) but not installed"; exit 1; }
  echo "SKIP: bwrap not installed"; exit 0
fi

W="$(mktemp -d "${TMPDIR:-/tmp}/nbtp-test.XXXXXX")"
trap 'rm -rf "$W"' EXIT
ROOT="$W/root"; BIN="$W/bin"
mkdir -p "$ROOT" "$BIN"

# ---- synthetic device tree --------------------------------------------------
P="$ROOT/opt/hmi/ID5/data/ro/Plugins"
mkdir -p "$ROOT"/{usr,proc,dev,tmp,net/hu-omap,fs/sda0/etc,fs/sda1,mnt,var/opt/aa,opt/aa/NbtAad.old,opt/sys/etc,fakebin} "$P/NbtAad" "$P/OtherPlugin"
for l in bin lib lib64 sbin; do [[ -L /$l ]] && ln -s "$(readlink /$l)" "$ROOT/$l"; done
if [[ -n "${1:-}" ]]; then cp "$1" "$ROOT/opt/aa/nbt-aad"; else
  printf '\x7fELF fake daemon\n  Build: v1.9.36-combo (%%s %%s)\n' >"$ROOT/opt/aa/nbt-aad"; fi
chmod 755 "$ROOT/opt/aa/nbt-aad"
printf '\x7fELF older daemon  Build: v1.9.30-old\n' >"$ROOT/opt/aa/nbt-aad.old"
printf 'NBT_ALT_WIFI=CARPLAY\nNBT_KEEP_PF=1\nNBT_WFD_PASS=SuperSecretPass1\nNBT_LOG_FILE=/mnt/umass01200t7/nbt-aad.log\n' >"$ROOT/opt/aa/nbt-aad.env"
printf 'pass in all\n' >"$ROOT/opt/aa/pf.bak"
printf 'pass in all\n# AA rules\n' >"$ROOT/fs/sda0/etc/pf.conf"
if [[ -n "${2:-}" ]]; then
  python3 -I -c 'import zipfile,sys,os
z=zipfile.ZipFile(sys.argv[1]); d=sys.argv[2]
for i in z.infolist():
  if i.is_dir(): continue
  n=os.path.basename(i.filename); open(os.path.join(d,n),"wb").write(z.read(i))' "$2" "$P/NbtAad"
else
  for f in libNbtAad.so NbtAad.manifest NbtAad.xml NbtAad_ALL_Texts.zip NbtAad_ALL_Images.zip; do
    printf 'fake %s rhmiapp-43-combo\n' "$f" >"$P/NbtAad/$f"; done
fi
printf 'old plugin\n' >"$ROOT/opt/aa/NbtAad.old/libNbtAad.so"
ln -s ../NbtAad/NbtAad.xml "$P/NbtAad/link-to-xml"
printf 'evil\n' >"$P/NbtAad/bad;name"
printf '1\n' >"$ROOT/var/opt/aa/bootguard"
printf "Alex's Pixel 8 PhoneOwnerName\n" >"$ROOT/var/opt/aa/spp-model"          # personal: must stay hash-only
printf 'peer\n' >"$ROOT/var/opt/aa/00-11-22-33-44-55.bin"                        # MAC in a file name
printf 'wifi=secret\n' >"$ROOT/var/opt/aa/iap2.cfg"                               # credential-like name: skipped
printf 'HU_SW=NBTevo_X18 FAKE\n' >"$ROOT/opt/sys/etc/nbt_version.txt"
mkdir -p "$W/shmem"
printf 'line\n  Build: v1.9.36-combo (Nov 8 2026)\nphone WBAJA11010B123456 secret\n' >"$W/shmem/nbt-aad.log"
printf 'create(name=NbtAad) rhmiapp-43-combo (x)\n' >"$W/shmem/nbt-aad-app.log"

cat >"$ROOT/fakebin/on" <<'EOF'
#!/bin/sh
[ "$1" = "-f" ] || { echo "on: fake supports only -f" >&2; exit 64; }
shift 2; exec "$@"
EOF
printf '#!/bin/sh\necho "     pid tid name\n       1   1 procnto\n   19320   1 /opt/aa/nbt-aad"\n' >"$ROOT/fakebin/pidin"
printf '#!/bin/sh\necho "usage: $1 [fake]"\n' >"$ROOT/fakebin/use"
cat >"$ROOT/fakebin/ls" <<'EOF'
#!/bin/sh
# FAKE_LS_8COL=1 simulates an ls -l without the group column.
if [ -n "$FAKE_LS_8COL" ] && [ "$1" = "-la" ]; then shift; exec /usr/bin/ls -lao "$@"; fi
exec /usr/bin/ls "$@"
EOF
chmod +x "$ROOT"/fakebin/*

tree_hash() { (cd "$ROOT" && find . -path ./proc -prune -o -path ./dev -prune -o -print0 | sort -z | xargs -0 stat -c '%n %s %a %Y %N' ; find . -path ./proc -prune -o -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum; }
BEFORE="$(tree_hash)"

# ---- fake ssh / ssh-keyscan -------------------------------------------------
ssh-keygen -q -t rsa -b 2048 -N '' -f "$W/hostkey" >/dev/null
ssh-keygen -q -t rsa -b 2048 -N '' -f "$W/otherkey" >/dev/null
cat >"$BIN/ssh-keyscan" <<EOF
#!/bin/sh
echo "[127.0.0.1]:2222 \$(cut -d' ' -f1,2 "$W/hostkey.pub")"
EOF
cat >"$BIN/ssh" <<EOF
#!/usr/bin/env bash
ROOT="$ROOT"; SHM="$W/shmem"; LOG="\$FAKE_LOG"; W="$W"
EOF
cat >>"$BIN/ssh" <<'EOF'
args=("$@"); pos=(); batch=0; verbose=0; ctl=""; master=0; kh=""; i=0; op=""
while (( i < ${#args[@]} )); do
  a="${args[i]}"
  case "$a" in
    -V) echo "OpenSSH_fake" >&2; exit 0 ;;
    -vv) verbose=1 ;;
    -p|-l|-i|-F|-S) i=$((i+2)); continue ;;
    -o) o="${args[i+1]}"
        case "$o" in BatchMode=yes) batch=1 ;; ControlPath=*) ctl="${o#ControlPath=}" ;;
                     ControlMaster=yes) master=1 ;; UserKnownHostsFile=*) kh="${o#UserKnownHostsFile=}" ;; esac
        i=$((i+2)); continue ;;
    -O) op="${args[i+1]}"; i=$((i+2)); continue ;;
    -*) ;;
    *) pos+=("$a") ;;
  esac
  i=$((i+1))
done
if [[ -n "$op" ]]; then
  echo "-O $op" >>"$LOG.ctl"
  case "$op" in check) [[ -S "$ctl" ]] && exit 0; exit 255 ;; exit) rm -f "$ctl"; exit 0 ;; esac
fi
if (( verbose )); then
  echo "debug1: Remote protocol version 2.0, remote software version OpenSSH_4.x-fake" >&2
  echo "debug2: peer server KEXINIT proposal" >&2
  echo "debug2: host key algorithms: ssh-rsa,ssh-dss" >&2
  echo "debug2: MACs ctos: hmac-sha1,hmac-md5" >&2
  exit 255
fi
if (( master )); then
  served="$W/hostkey.pub"; [[ -n "${FAKE_WRONG_KEY:-}" ]] && served="$W/otherkey.pub"
  grep -qF "$(cut -d' ' -f2 "$served")" "$kh" || { echo "Host key verification failed." >&2; exit 255; }
  python3 -I -c 'import socket,sys,os,time
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])
if os.fork(): sys.exit(0)
time.sleep(300)' "$ctl"; exit 0
fi
cmd="${pos[*]:1}"
if [[ ! -S "$ctl" ]]; then
  (( batch )) && { echo "Permission denied (BatchMode)" >&2; exit 255; }
  sleep 70; exit 255      # a non-BatchMode client would sit at a password prompt
fi
echo "$cmd" >>"$LOG"
n=$(wc -l <"$LOG")
if [[ -n "${FAKE_KILL_AFTER:-}" ]] && (( n >= FAKE_KILL_AFTER )); then rm -f "$ctl"; exit 255; fi
if [[ -n "${FAKE_HANG_CMD:-}" && "$cmd" == *"$FAKE_HANG_CMD"* ]]; then sleep 30; fi
exec bwrap --ro-bind "$ROOT" / --ro-bind /usr /usr --proc /proc --dev /dev \
  --ro-bind "$SHM" /dev/shmem --unshare-all --die-with-parent \
  --setenv PATH /fakebin:/usr/bin:/bin --setenv FAKE_LS_8COL "${FAKE_LS_8COL:-}" --chdir / /bin/sh -c "$cmd"
EOF
chmod +x "$BIN/ssh" "$BIN/ssh-keyscan"

# ---- helpers ----------------------------------------------------------------
fail=0
check() { if eval "$2"; then echo "ok   [$SC] $1"; else echo "FAIL [$SC] $1"; fail=1; fi; }
# run_scenario <name> [ENV=VAL...]: sets SC, OUT, R, PRC, PSECS, FAKE_LOG
run_scenario() {
  SC="$1"; shift
  OUT="$W/out-$SC"; mkdir -p "$OUT"
  FAKE_LOG="$W/calls-$SC.log"; : >"$FAKE_LOG"
  local t0=$SECONDS
  set +e
  (cd "$OUT" && printf 'PROBE\nyes\nfake-device test\nyes\n\n' | env PATH="$BIN:$PATH" FAKE_LOG="$FAKE_LOG" "$@" \
     bash "$PROBE" --host 127.0.0.1 --port 2222 >"$W/console-$SC.out" 2>&1)
  PRC=$?
  set -e
  PSECS=$((SECONDS - t0))
  R="$(echo "$OUT"/nbt-probe-*/report)"
}

# ---- scenario: main -----------------------------------------------------------
run_scenario main
check "probe exit 0" '[[ $PRC == 0 ]] || { tail -20 "$W/console-$SC.out"; false; }'
check "device tree unchanged (no writes)" '[[ "$BEFORE" == "$(tree_hash)" ]]'
check "report archive created" '[[ -s "$R/../report.tgz" ]]'
check "summary has >150 probes" '(( $(wc -l <"$R/summary.txt") > 150 ))'
check "no secret/personal data in report" '! grep -rqa -e SuperSecretPass1 -e WBAJA11010B123456 -e 00:11:22:33:44:55 -e 00-11-22-33-44-55 -e PhoneOwnerName -e "wifi=secret" "$R" && ! tar -xzOf "$R/../report.tgz" | grep -qa -e SuperSecretPass1 -e PhoneOwnerName'
check "CARPLAY preserved in redacted env" 'grep -q "NBT_ALT_WIFI=CARPLAY" "$R/text/opt-aa__nbt-aad.env"'
check "env secret redacted" 'grep -q "NBT_WFD_PASS=<REDACTED>" "$R/text/opt-aa__nbt-aad.env"'
check "allowlisted state file copied" '[[ -f "$R/text/var-opt-aa__bootguard" ]]'
check "non-allowlisted state hash-only" '[[ ! -e "$R/text/var-opt-aa__spp-model" ]] && grep -q "/var/opt/aa/spp-model" "$R/readback.tsv"'
check "credential-like name skipped, run continued" 'grep -q "SKIP credential path" "$R/readback-notes.txt" && ! grep -q iap2 "$FAKE_LOG" && [[ -s "$R/log-versions.txt" ]]'
real_sha="$(sha256sum "$ROOT/opt/aa/nbt-aad" | cut -d" " -f1)"
check "daemon readback hash matches" 'grep -q "^/opt/aa/nbt-aad	0	[0-9]*	$real_sha" "$R/readback.tsv"'
check "repeat readbacks match" '[[ $(grep -c "$real_sha" "$R/readback.tsv") -ge 3 ]]'
check "embedded build string extracted" 'grep -q "Build: v1.9.36-combo" "$R/readback.tsv"'
check "plugin files read back" '[[ $(grep -c "^/opt/hmi/ID5/data/ro/Plugins/NbtAad/" "$R/readback.tsv") -ge 5 ]]'
check "unsafe file name skipped, not recorded" 'grep -q "SKIP unsafe file name" "$R/readback-notes.txt" && ! grep -q "bad;name" "$R/readback-notes.txt" "$R/readback.tsv" "$R/exec-log.tsv" && ! grep -q "bad;name" "$FAKE_LOG"'
check "symlink noted, not followed" 'grep -q "symlink.*link-to-xml" "$R/readback-notes.txt"'
check "hu exit status 7 captured" '[[ $(cat "$R"/exec/*-hu-rc-sh7/rc) == 7 ]]'
check "split streams captured" 'grep -q to-stderr "$R"/exec/*-hu-split-streams/stderr && [[ $(cat "$R"/exec/*-hu-split-streams/rc) == 3 ]]'
check "quoting probe output" 'grep -q "\[d'"'"'e\]" "$R"/exec/*-hu-quoting/stdout'
check "missing digest tool recorded, not fatal" '[[ $(cat "$R"/exec/*-hu-digest-md5/rc) != 0 ]]'
check "log version lines only" 'grep -q "Build: v1.9.36" "$R/log-versions.txt" && ! grep -q "^line$" "$R/log-versions.txt"'
check "kexinit captured" 'grep -q "ssh-dss" "$R/ssh-kexinit.txt"'
check "no forbidden program reached device" '! grep -Eq "(^|[;&|] *|on -f [^ ]+ )(rm|mv|cp|kill|slay|chmod|mkdir|mount -|pfctl|/opt/aa/nbt-aad( |$))" "$FAKE_LOG"'
n_calls=$(wc -l <"$FAKE_LOG"); n_recs=$(find "$R/exec" -mindepth 1 -maxdepth 1 -type d | wc -l)
check "every remote call has a transcript record ($n_calls)" '[[ "$n_calls" == "$n_recs" ]] && [[ $(wc -l <"$R/exec-log.tsv") == "$n_recs" ]]'
check "every record complete" '! for d in "$R"/exec/*/; do for f in cmd rc ms started_utc policy stdout.sha256 stdout.bytes stderr.sha256 stderr; do [[ -f "$d$f" ]] || echo "missing $d$f"; done; done | grep -q .'
check "raw cmd order in private matches device order" 'diff "$FAKE_LOG" <(cat "$R"/../private/exec/*.cmd) >/dev/null'
check "binary/secret stdout not in report" '! ls "$R"/exec/*-readback/stdout "$R"/exec/*-log-*/stdout 2>/dev/null | grep -q .'
check "raw text stdout kept in private" '[[ -s $(ls "$R"/../private/exec/*-hu-uname.stdout) ]]'
check "raw daemon log not stored anywhere" '! grep -rqa "phone WBAJA" "$R/.."'
check "private dir mode 700" '[[ $(stat -c %a "$R/../private") == 700 ]]'
check "master closed at exit" 'grep -q -- "-O exit" "$FAKE_LOG.ctl"'

# ---- scenario: master-dies ----------------------------------------------------
run_scenario master-dies FAKE_KILL_AFTER=40
check "stops with code 3" '[[ $PRC == 3 ]]'
check "stops fast (${PSECS}s)" '(( PSECS < 60 ))'
check "partial report packaged" '[[ -s "$R/../report.tgz" ]] && grep -q "connection lost" "$R/notes.txt"'
check "no calls after loss" '[[ $(wc -l <"$FAKE_LOG") == 40 ]]'

# ---- scenario: hang -----------------------------------------------------------
run_scenario hang FAKE_HANG_CMD="pidin -p nbt-aad arg" NBT_PROBE_CMD_TIMEOUT=3
check "probe exit 0" '[[ $PRC == 0 ]]'
check "hung command recorded as timeout 124" '[[ $(cat "$R"/exec/*-hu-pidin-arg/rc) == 124 ]]'
check "later probes still ran" '[[ -s "$R/readback.tsv" ]]'

# ---- scenario: wrong-key ------------------------------------------------------
run_scenario wrong-key FAKE_WRONG_KEY=1
check "login refused (nonzero)" '[[ $PRC != 0 ]]'
check "zero remote commands executed" '[[ ! -s "$FAKE_LOG" ]]'
check "refusal evidence recorded" 'grep -q "Host key verification failed" "$R/ssh-login.stderr"'

# ---- scenario: ls-8col --------------------------------------------------------
run_scenario ls-8col FAKE_LS_8COL=1
check "probe exit 0" '[[ $PRC == 0 ]]'
check "unparsed ls lines reported" 'grep -q "UNPARSED ls line" "$R/readback-notes.txt"'
check "nothing guessed: no plugin readbacks" '! grep -q "^/opt/hmi/ID5/data/ro/Plugins/NbtAad/" "$R/readback.tsv"'

check "device tree still unchanged after all scenarios" '[[ "$BEFORE" == "$(tree_hash)" ]]'
(( fail )) && { echo "SOME CHECKS FAILED (work dir kept: $W)"; trap - EXIT; exit 1; }
echo "ALL CHECKS PASSED"
