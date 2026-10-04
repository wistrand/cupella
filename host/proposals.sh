#!/usr/bin/env bash
# Lists the proposals of Cupella workspaces and records whether each is open, applied, or
# rejected. Run as `./cupella proposals ...`; host side, it reads only proposals/ of each
# workspace (agent-written text, shown with control characters removed).
#
#   ./cupella proposals [--all] [workspace ...]
#       list proposals, open ones only unless --all. In the checkout: every workspace in
#       .cupella-workspaces (setup and each workspace run add themselves) plus the
#       checkout's own proposals/; in a workspace: that workspace only.
#   ./cupella proposals set <workspace> <slug> open|applied|rejected [note]
#       record a decision (checkout only). Appended to the checkout's
#       .cupella-decisions.tsv: workspace, slug, state, date, note; the last line for a
#       workspace and slug wins, earlier ones are history. Decisions are kept in the
#       checkout, never in a workspace, so an agent there cannot mark its own proposals.
#
# A proposal is proposals/<slug>.md, slug <YYYY-MM-DD>-<topic>, with an optional tool in
# proposals/<slug>/tool.py (./cupella try-proposal). Older proposals/<YYYY-MM-DD>.md files
# holding several entries are listed as one proposal each. A proposal with no decision
# is open.
set -euo pipefail

ws=${CUPELLA_WS:?run as ./cupella proposals}
root=${CUPELLA_ROOT:?run as ./cupella proposals}
# CUPELLA_REGISTRY, CUPELLA_DECISIONS: other files, for host/proposals-test.sh
registry=${CUPELLA_REGISTRY:-$root/.cupella-workspaces}
decisions=${CUPELLA_DECISIONS:-$root/.cupella-decisions.tsv}
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
clean() { LC_ALL=C tr -d '\000-\010\013-\037\177' | cut -c1-"${1:-100}"; }

state_of() { # <workspace> <slug>: state<TAB>date<TAB>note of the last decision, or open
  if [ -f "$decisions" ]; then
    awk -F'\t' -v w="$1" -v s="$2" '$1 == w && $2 == s { last = $3 "\t" $4 "\t" $5 }
      END { if (last) print last; else print "open\t-\t" }' "$decisions"
  else
    printf 'open\t-\t\n'
  fi
}

list_ws() { # <workspace> <all 0/1>: one block per workspace
  local w=$1 all=$2 p slug title st date note tool runs
  p="$w/proposals"
  [ -d "$p" ] || return 0
  local lines=()
  while IFS= read -r -d '' f; do
    slug=$(basename "$f" .md)
    [[ "$slug" =~ ^[A-Za-z0-9._-]+$ ]] || continue
    IFS=$'\t' read -r st date note < <(state_of "$w" "$slug")
    [ "$all" = 1 ] || [ "$st" = open ] || continue
    title=$(grep -m1 -E '^#+ ' "$f" 2> /dev/null | sed -E 's/^#+ +//' | clean 70)
    [ -n "$title" ] || title=$(grep -m1 -v '^[[:space:]]*$' "$f" 2> /dev/null | clean 70)
    tool=""; [ -f "$p/$slug/tool.py" ] && tool=" [tool]"
    runs=$(find "$w/work" -mindepth 3 -maxdepth 3 -path "*/proposals/$slug" -type d 2> /dev/null | wc -l)
    [ "$runs" = 0 ] || tool="$tool [run on $runs sample(s)]"
    lines+=("$(printf '  %-8s %-34s %s%s' "$st" "$slug" "$title" "$tool")")
    [ -z "$note" ] || lines+=("$(printf '           %s %s' "$date" "$note" | clean 110)")
  done < <(find "$p" -maxdepth 1 -type f -name '*.md' -print0 | sort -z)
  [ ${#lines[@]} = 0 ] && return 0
  echo "== $w"
  printf '%s\n' "${lines[@]}"
}

cmd=list
case "${1:-}" in
  set) cmd=set; shift ;;
  -h | --help | help) usage ;;
esac

if [ "$cmd" = set ]; then
  [ "$ws" = "$root" ] || { echo "proposals set runs in the checkout: a decision is the user's, not a workspace agent's" >&2; exit 1; }
  [ $# -ge 3 ] || usage
  w=$(cd "$1" 2> /dev/null && pwd -P) || { echo "no workspace $1" >&2; exit 1; }
  slug=$2 st=$3; shift 3
  note=$(printf '%s' "$*" | tr '\t\n' '  ' | clean 200)
  [[ "$slug" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad slug: $slug" >&2; exit 1; }
  case "$st" in open | applied | rejected) ;; *) echo "state must be open, applied, or rejected" >&2; exit 1 ;; esac
  [ -f "$w/proposals/$slug.md" ] || { echo "no proposals/$slug.md in $w" >&2; exit 1; }
  [[ "$w" != *$'\t'* && "$w" != *$'\n'* ]] || { echo "workspace path with a tab or newline" >&2; exit 1; }
  printf '%s\t%s\t%s\t%s\t%s\n' "$w" "$slug" "$st" "$(date +%F)" "$note" >> "$decisions"
  echo "$slug: $st"
  exit 0
fi

all=0
[ "${1:-}" = --all ] && { all=1; shift; }
targets=()
if [ $# -gt 0 ]; then
  for a in "$@"; do targets+=("$(cd "$a" && pwd -P)"); done
elif [ "$ws" != "$root" ]; then
  targets=("$(cd "$ws" && pwd -P)")
else
  targets=("$(cd "$root" && pwd -P)")
  if [ -f "$registry" ]; then
    while IFS= read -r w; do
      [ -n "$w" ] || continue
      if [ -f "$w/.cupella-workspace" ]; then targets+=("$(cd "$w" && pwd -P)"); else echo "(gone: $w)" >&2; fi
    done < <(sort -u "$registry")
  fi
fi
out=$(for w in "${targets[@]}"; do list_ws "$w" "$all"; done)
if [ -n "$out" ]; then echo "$out"
else
  # the checkout is searched too but is not a workspace: count it apart
  n=0; incl=""
  for w in "${targets[@]}"; do
    if [ "$w" = "$(cd "$root" && pwd -P)" ]; then incl="the checkout and "; else n=$((n + 1)); fi
  done
  echo "no $([ "$all" = 1 ] || echo 'open ')proposals in ${incl}$n workspace(s)"
fi
