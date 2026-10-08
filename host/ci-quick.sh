#!/usr/bin/env bash
# The quick checks for CI (.github/workflows/ci.yml) and for a fast local run: everything
# that needs neither Docker nor the image. Synthetic data only: no APK, no benchmark
# file, no network, no key. `./cupella check` runs these and the container steps.
#
#   host/ci-quick.sh
#
# Steps:
#   syntax     bash -n on every shell script (tracked, or new and not ignored) and the
#              wrappers; python3 -m py_compile on every such Python file
#   harness    host/harness-test.py: role policy, path escapes and links on both stores
#              (the volume store's helper as a local process), adapters, repairs
#   proposals  host/proposals-test.sh: proposals, workspaces list, rm, --prune, new refusals
#   md-view    scripts/fixtures/md-view-test.sh: no control, escape, or bidi character
#              from a file reaches the terminal
#   parquet    scripts/fixtures/parquet-samples-test.sh: the Parquet reader and packer on
#              files written by a minimal writer (zstd cases skipped without the tool)
# The two fixtures run here on the host, which is safe because they make and read only
# their own synthetic files; on samples the scripts run only through ./cupella.
# Prints PASS, FAIL, or SKIP per step; output in work/_ci/. Exits 1 on any FAIL.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
cd "$root"
unset CUPELLA_WORKSPACE
out="$root/work/_ci"
[ ! -d "$out" ] || chmod -R u+w "$out"
rm -rf "$out"
mkdir -p "$out"
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }

# syntax: every script, so a broken edit fails here and not at a user's run
bad=0
: > "$out/syntax.txt"
while IFS= read -r f; do
  bash -n "$f" >> "$out/syntax.txt" 2>&1 || { echo "bash -n failed: $f" >> "$out/syntax.txt"; bad=1; }
done < <(git ls-files --cached --others --exclude-standard '*.sh'; printf '%s\n' cupella bench-setup)
pyc="$out/pycache"
while IFS= read -r f; do
  PYTHONPYCACHEPREFIX="$pyc" python3 -m py_compile "$f" >> "$out/syntax.txt" 2>&1 \
    || { echo "py_compile failed: $f" >> "$out/syntax.txt"; bad=1; }
done < <(git ls-files --cached --others --exclude-standard '*.py')
if [ "$bad" = 0 ]; then pass "syntax"; else fail "syntax (work/_ci/syntax.txt)"; fi

# a step that prints PASS/FAIL lines: passes when it printed a PASS and no FAIL
step() { # <name> <command...>
  local name=$1
  shift
  "$@" > "$out/$name.txt" 2>&1 || echo "FAIL: $name exited $?" >> "$out/$name.txt"
  if ! grep -E -q '(^FAIL|: FAIL$)' "$out/$name.txt" && grep -E -q '(^PASS|: PASS)' "$out/$name.txt"; then
    pass "$name$(grep -q 'SKIP' "$out/$name.txt" && echo " (some cases skipped: work/_ci/$name.txt)")"
  else
    fail "$name (work/_ci/$name.txt)"
  fi
}
step harness python3 host/harness-test.py "$out/harness"
step proposals host/proposals-test.sh "$out/proposals"
step md-view scripts/fixtures/md-view-test.sh
step parquet scripts/fixtures/parquet-samples-test.sh

[ ! -d "$out/proposals" ] || chmod -R u+w "$out/proposals"
echo "== $fails failure(s); output in work/_ci/"
[ "$fails" = 0 ]
