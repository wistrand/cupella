#!/usr/bin/env bash
# Regression run after script changes: the fixtures, the native fixture, cite-check.py on
# every report, and the benchmark gate. Run it as `./cupella check`; it runs on the host
# and calls ./cupella for every step that reads sample data.
#
#   ./cupella check            everything; the gate needs bench/gate-baseline.txt
#   ./cupella check --no-gate  skip the gate (it rescans the benchmarks: minutes)
#
# Steps:
#   fixtures   fixtures/zipslip-test.sh, fixtures/injection-test.sh,
#              fixtures/manifest-tricks-test.sh, fixtures/md-view-test.sh,
#              fixtures/parquet-samples-test.sh
#   proposals  host/proposals-test.sh: ./cupella proposals and ./cupella workspaces on
#              throwaway workspaces (listing, decisions, refusals, --find)
#   try-proposal  host/try-proposal-test.sh: ./cupella try-proposal on a throwaway
#              workspace under work/_check/ (runs, read-only sample, lint, refusals)
#   export     host/export-test.sh: ./cupella export on a throwaway workspace (copies,
#              refusals, no overwrite)
#   harness    host/harness-test.py: the API harness's role policy and adapters, no
#              network, no key
#   native     builds scripts/fixtures/native-fixture.c with the host's clang and lld
#              (our own source, no APK data) as plain, APS2-packed, and RELR variants
#              into work/_check/native/, and checks native-summary.py --file,
#              native-disasm.py --jni, and fixtures/elf-headers-test.sh on each; skipped
#              when clang or ld.lld is missing
#   cite       ./cupella cite-check.py <name> for every reports/<name>.md with a work/<name>/
#   gate       ./cupella gate (rescans every benchmark sample: the longest step; output shown)
# Prints PASS, FAIL, or SKIP per step; full output in work/_check/. Exits 1 on any FAIL.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
cd "$root"
unset CUPELLA_WORKSPACE
gate=1
case "${1:-}" in
  --no-gate) gate=0 ;;
  "") ;;
  *) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
out="$root/work/_check"
# the proposals test leaves workspaces with read-only doc copies
[ ! -d "$out" ] || chmod -R u+w "$out"
rm -rf "$out"
mkdir -p "$out/native"
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
skip() { echo "SKIP  $1"; }

# fixtures: each prints PASS or FAIL per case; indented lines are detail
for t in zipslip-test.sh injection-test.sh manifest-tricks-test.sh md-view-test.sh parquet-samples-test.sh; do
  ./cupella "fixtures/$t" > "$out/$t.txt" 2>&1 || echo "FAIL: $t exited $?" >> "$out/$t.txt"
  bad=$(grep -v '^  ' "$out/$t.txt" | grep -v 'unzip is not used' | grep -c 'FAIL' || true)
  if [ "$bad" = 0 ] && grep -q 'PASS' "$out/$t.txt"; then pass "fixtures/$t"; else fail "fixtures/$t (work/_check/$t.txt)"; fi
done

# proposals: listing and decisions across workspaces (host side, no container)
host/proposals-test.sh "$out/proposals" > "$out/proposals.txt" 2>&1 || echo "FAIL: proposals-test.sh exited $?" >> "$out/proposals.txt"
if ! grep -q '^FAIL' "$out/proposals.txt" && grep -q '^PASS' "$out/proposals.txt"; then pass "proposals"
else fail "proposals (work/_check/proposals.txt)"; fi

# harness: policy and adapters of the API harness (host side, no container, no network)
python3 host/harness-test.py "$out/harness" > "$out/harness.txt" 2>&1 || echo "FAIL: harness-test.py exited $?" >> "$out/harness.txt"
if ! grep -q '^FAIL' "$out/harness.txt" && grep -q '^PASS' "$out/harness.txt"; then pass "harness"
else fail "harness (work/_check/harness.txt)"; fi

# try-proposal: host side, since the command starts its own container
host/try-proposal-test.sh "$out/try-proposal" > "$out/try-proposal.txt" 2>&1 || echo "FAIL: try-proposal-test.sh exited $?" >> "$out/try-proposal.txt"
if ! grep -q '^FAIL' "$out/try-proposal.txt" && grep -q '^PASS' "$out/try-proposal.txt"; then pass "try-proposal"
else fail "try-proposal (work/_check/try-proposal.txt)"; fi

# export: host side, since the command starts its own container
host/export-test.sh "$out/export" > "$out/export.txt" 2>&1 || echo "FAIL: export-test.sh exited $?" >> "$out/export.txt"
if ! grep -q '^FAIL' "$out/export.txt" && grep -q '^PASS' "$out/export.txt"; then pass "export"
else fail "export (work/_check/export.txt)"; fi

# native fixture: what each script must report about it (fixed strings)
summary_expect=(
  '**Code that runs at load, before any Java call** (1)'
  '- com.evil.app.Native: ping'
  '(3 in 1 tables)'
  '- network: connect, send, socket'
  '- process execution: system'
  '- dynamic loading: dlopen'
  '- memory protection: mprotect'
  '- debug, tracing: ptrace'
  'https://c2.example.invalid/upload'
)
disasm_expect=(
  'JNIEnv->RegisterNatives'
  '; import socket'
  '; "https://c2.example.invalid/upload"'
  '; "su -c id"'
)
if command -v clang > /dev/null && command -v ld.lld > /dev/null; then
  for v in plain:'' aps2:-Wl,--pack-dyn-relocs=android relr:-Wl,-z,pack-relative-relocs; do
    variant=${v%%:*}
    lib="work/_check/native/$variant/libfixture.so"
    mkdir -p "$(dirname "$lib")"
    # shellcheck disable=SC2086
    if ! clang --target=aarch64-linux-android24 -O1 -fPIC -shared -nostdlib -fuse-ld=lld -Wl,-z,undefs -s \
        ${v#*:} scripts/fixtures/native-fixture.c -o "$lib" > "$out/native/$variant.build.txt" 2>&1; then
      fail "native $variant: build (work/_check/native/$variant.build.txt)"
      continue
    fi
    ./cupella native-summary.py --file "$lib" > "$out/native/$variant.summary.txt" 2>&1 || true
    ./cupella native-disasm.py "$lib" --jni > "$out/native/$variant.disasm.txt" 2>&1 || true
    ./cupella fixtures/elf-headers-test.sh "$lib" > "$out/native/$variant.elf-headers.txt" 2>&1 || true
    missing=()
    for e in "${summary_expect[@]}"; do grep -q -F -e "$e" "$out/native/$variant.summary.txt" || missing+=("summary: $e"); done
    for e in "${disasm_expect[@]}"; do grep -q -F -e "$e" "$out/native/$variant.disasm.txt" || missing+=("disasm: $e"); done
    grep -q 'FAIL' "$out/native/$variant.elf-headers.txt" && missing+=("elf-headers-test.sh FAIL")
    [ "$(grep -c 'PASS' "$out/native/$variant.elf-headers.txt" || true)" -ge 3 ] || missing+=("elf-headers-test.sh: fewer than 3 PASS")
    if [ ${#missing[@]} = 0 ]; then pass "native $variant"; else
      fail "native $variant (work/_check/native/$variant.*.txt)"
      printf '        missing %s\n' "${missing[@]}"
    fi
  done
else
  skip "native fixture: clang and ld.lld are needed on the host"
fi

# citations of every report
: > "$out/cite.txt"
for r in reports/*.md; do
  [ -e "$r" ] || continue
  n=$(basename "$r" .md)
  if [ ! -d "work/$n" ]; then
    skip "cite $n (no work/$n/)"
    continue
  fi
  if ./cupella cite-check.py "$n" >> "$out/cite.txt" 2>&1; then pass "cite $n"; else fail "cite $n (work/_check/cite.txt)"; fi
done

if [ "$gate" = 1 ]; then
  if [ ! -f bench/gate-baseline.txt ]; then
    skip "gate: no bench/gate-baseline.txt (./cupella gate baseline on the unchanged scripts first)"
  # shown as it runs: the rescan of every benchmark sample takes a long time (pipefail
  # keeps the gate's exit status)
  elif ./cupella gate 2>&1 | tee "$out/gate.txt"; then
    pass "gate: $(grep '^PASS' "$out/gate.txt" | tail -1)"
  else
    fail "gate (work/_check/gate.txt)"
  fi
else
  skip "gate (--no-gate)"
fi

echo "== $fails failure(s); output in work/_check/"
[ "$fails" = 0 ]
