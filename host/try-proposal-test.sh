#!/usr/bin/env bash
# Checks ./cupella try-proposal on a throwaway workspace: a proposal tool runs offline
# with the sample read-only and writes only work/<name>/proposals/<slug>/; the lint
# rejects code that runs other programs; bad names and links are refused. Host side
# (try-proposal starts its own container), run by `./cupella check`. The sample is a
# directory of text files, not an APK: nothing from a real sample is involved.
#
# Usage: host/try-proposal-test.sh [work-dir]   default work/_check/try-proposal
# Prints PASS or FAIL per case.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
w=${1:-$root/work/_check/try-proposal}
rm -rf "$w"
mkdir -p "$w/work/fixture" "$w/proposals/good" "$w/proposals/bad" "$w/proposals/selfwrite"
w=$(cd "$w" && pwd)
cd "$w"
export CUPELLA_WORKSPACE="$w"
run() { "$root/cupella" try-proposal "$@" 2>&1; }

printf 'sample triage\nline two\n' > work/fixture/triage.txt
cat > proposals/good/tool.py <<'EOF'
import os, sys
sample = sys.argv[1]
with open(os.path.join(sample, "triage.txt")) as f:
  lines = sum(1 for _ in f)
with open("result.txt", "w") as f:
  f.write("lines=%d args=%s\n" % (lines, ",".join(sys.argv[2:])))
try:
  open(os.path.join(sample, "planted.txt"), "w").write("x")
  print("outside: written")
except OSError:
  print("outside: refused")
EOF
printf 'import subprocess\nsubprocess.run(["id"])\n' > proposals/bad/tool.py
cat > proposals/selfwrite/tool.py <<'EOF'
import os
try:
  open(os.path.abspath(__file__), "a").write("# changed\n")
  print("self: written")
except OSError:
  print("self: refused")
EOF

check() { # <name> <condition result 0/1> <detail>
  if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; echo "  $3"; fi
}

out=$(run good fixture a1 b2 || true)
r=1; grep -qx 'lines=2 args=a1,b2' work/fixture/proposals/good/result.txt 2> /dev/null && r=0
check "tool runs, reads the sample, gets its arguments" "$r" "$out"
r=1; grep -q 'outside: refused' <<< "$out" && [ ! -e work/fixture/planted.txt ] && r=0
check "sample directory is read-only to the tool" "$r" "$out"

before=$(sha256sum < proposals/selfwrite/tool.py)
out=$(run selfwrite fixture || true)
r=1; grep -q 'self: refused' <<< "$out" && [ "$(sha256sum < proposals/selfwrite/tool.py)" = "$before" ] && r=0
check "tool cannot change its own code" "$r" "$out"

r=0; out=$(run bad fixture) && r=1
grep -q 'agent code rejected' <<< "$out" || r=1
[ -z "$(ls -A work/fixture/proposals/bad 2> /dev/null)" ] || r=1
check "lint rejects a tool that runs a program" "$r" "$out"

r=0; out=$(run ../good fixture) && r=1
grep -q 'bad name' <<< "$out" || r=1
check "slug with a path is refused" "$r" "$out"

r=0; out=$(run good ../fixture) && r=1
grep -q 'bad name' <<< "$out" || r=1
check "sample name with a path is refused" "$r" "$out"

mkdir -p work/linked "$w/elsewhere"
cp work/fixture/triage.txt work/linked/
ln -s "$w/elsewhere" work/linked/proposals
r=0; out=$(run good linked) && r=1
grep -q 'is a link' <<< "$out" && [ -z "$(ls -A "$w/elsewhere")" ] || r=1
check "a link as the output directory is refused" "$r" "$out"
