#!/usr/bin/env bash
# Checks ./cupella proposals and ./cupella workspaces on throwaway workspaces with their own registry: listing,
# open-only by default, recorded decisions, refusals. Host side, no container; run by
# `./cupella check`.
#
# Usage: host/proposals-test.sh [work-dir]   default work/_check/proposals
# Prints PASS or FAIL per case.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
t=${1:-$root/work/_check/proposals}
# a workspace run copies the docs in read-only
[ ! -d "$t" ] || chmod -R u+w "$t"
rm -rf "$t"
mkdir -p "$t"
t=$(cd "$t" && pwd)
export CUPELLA_REGISTRY="$t/registry" CUPELLA_DECISIONS="$t/decisions.tsv"
for w in a b; do
  mkdir -p "$t/$w/proposals" "$t/$w/work"
  printf 'checkout=%s\nharness=other\nstamp=\n' "$root" > "$t/$w/.cupella-workspace"
  echo "$t/$w" >> "$CUPELLA_REGISTRY"
done
printf '# Decode the second table shape\nwhy and how\n' > "$t/a/proposals/2026-10-04-tables.md"
printf '# Gotcha: grep -a on jadx files\n' > "$t/a/proposals/2026-10-04-grep.md"
mkdir -p "$t/a/proposals/2026-10-04-tables" "$t/a/work/s1/proposals/2026-10-04-tables"
echo 'print(1)' > "$t/a/proposals/2026-10-04-tables/tool.py"
printf 'no heading, \033[31mred\033[0m first line\n' > "$t/b/proposals/2026-10-05-plain.md"
echo "$t/gone" >> "$CUPELLA_REGISTRY"
p() { (cd "$root" && env -u CUPELLA_WORKSPACE "$root/cupella" proposals "$@" 2>&1); }
check() { if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; printf '  %s\n' "$3"; fi; }

out=$(p)
r=0
for e in "2026-10-04-tables" "Decode the second table shape" "[tool] [run on 1 sample(s)]" "2026-10-04-grep" "2026-10-05-plain" "(gone: $t/gone)"; do
  grep -qF -- "$e" <<< "$out" || r=1
done
check "lists every workspace in the registry, with tools and runs" "$r" "$out"
r=0; grep -q $'\033' <<< "$out" && r=1
check "control characters from proposal text are removed" "$r" "$out"

out=$(p set "$t/a" 2026-10-04-tables applied "moved to stringfog.py") || true
out2=$(p)
r=0; grep -q 2026-10-04-tables <<< "$out2" && r=1
grep -qF $'\t2026-10-04-tables\tapplied\t' "$t/decisions.tsv" || r=1
[ ! -e "$t/a/proposals/STATUS.tsv" ] || r=1
check "an applied proposal leaves the open list" "$r" "$out $out2"
out=$(p --all)
r=0; grep -q 'applied  2026-10-04-tables' <<< "$out" && grep -q 'moved to stringfog.py' <<< "$out" || r=1
check "--all shows the state and the note" "$r" "$out"

p set "$t/a" 2026-10-04-tables open > /dev/null
r=0; grep -q 2026-10-04-tables <<< "$(p)" || r=1
check "the last decision wins" "$r" "$(cat "$t/decisions.tsv")"

# a workspace cannot decide for itself: a decisions file written there is ignored
printf '2026-10-05-plain\trejected\t2026-10-05\t\033[2Jforged\n' > "$t/b/proposals/STATUS.tsv"
printf '%s\t2026-10-05-plain\trejected\t2026-10-05\tforged\n' "$t/b" > "$t/b/proposals/.cupella-decisions.tsv"
out=$(p)
r=0; grep -q 'open     2026-10-05-plain' <<< "$out" || r=1; grep -q forged <<< "$out" && r=1
check "decisions written inside a workspace are ignored" "$r" "$out"

r=0; out=$(p set "$t/a" 2026-10-04-tables done) && r=1
check "an unknown state is refused" "$r" "$out"
r=0; out=$(p set "$t/a" ../x applied) && r=1
check "a slug with a path is refused" "$r" "$out"
r=0; out=$(p set "$t/a" 2026-10-04-missing applied) && r=1
check "a slug without a proposal file is refused" "$r" "$out"

out=$(cd "$t/b" && CUPELLA_WORKSPACE="$t/b" "$root/cupella" proposals 2>&1 || true)
r=0; grep -q 2026-10-05-plain <<< "$out" && ! grep -q 2026-10-04-grep <<< "$out" || r=1
check "in a workspace: that workspace only" "$r" "$out"
r=0; out=$(cd "$t/b" && CUPELLA_WORKSPACE="$t/b" "$root/cupella" proposals set "$t/b" 2026-10-05-plain applied 2>&1) && r=1
check "set is refused from a workspace" "$r" "$out"

# ./cupella workspaces on the same registry
out=$(cd "$root" && env -u CUPELLA_WORKSPACE "$root/cupella" workspaces 2>&1 || true)
r=0
grep -qE "^ok +0 +0 +2 .*$t/a\$" <<< "$out" || r=1
grep -qE "^gone .*$t/gone\$" <<< "$out" || r=1
check "workspaces lists each recorded workspace with its counts, and gone ones" "$r" "$out"
mkdir -p "$t/found/deep/c/work/x"
printf 'checkout=%s\nharness=other\nstamp=\n' "$root" > "$t/found/deep/c/.cupella-workspace"
printf 'checkout=%s\nharness=other\nstamp=\n' "$root" > "$t/found/deep/c/work/x/.cupella-workspace"
out=$(cd "$root" && env -u CUPELLA_WORKSPACE "$root/cupella" workspaces --find "$t/found" 2>&1 || true)
r=0
grep -q "added: $t/found/deep/c" <<< "$out" && grep -qxF "$t/found/deep/c" "$CUPELLA_REGISTRY" || r=1
grep -q "work/x" "$CUPELLA_REGISTRY" && r=1
check "--find adds markers it finds, never inside work/" "$r" "$out"
