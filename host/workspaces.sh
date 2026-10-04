#!/usr/bin/env bash
# Lists the workspaces made from this checkout. Run as `./cupella workspaces`; host side,
# no container. Reads only each workspace's marker and counts files in it.
#
#   ./cupella workspaces                  every workspace in .cupella-workspaces
#   ./cupella workspaces --find DIR ...   also search DIR (4 levels deep) for workspace
#                                         markers, and add what is found to the list
#
# Per workspace: the path, whether it still exists, the checkout it names when that is
# not this one, APKs in data/, reports, open proposals, and when its doc copies were
# last refreshed from the checkout. A workspace is added to the list by setup and by
# each ./cupella run in it; one made before the list existed appears after its next run,
# or through --find.
set -euo pipefail

ws=${CUPELLA_WS:?run as ./cupella workspaces}
root=${CUPELLA_ROOT:?run as ./cupella workspaces}
registry=${CUPELLA_REGISTRY:-$root/.cupella-workspaces}  # CUPELLA_REGISTRY: for tests
usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

found=()
while [ $# -gt 0 ]; do
  case $1 in
    --find)
      d=${2:?usage: ./cupella workspaces --find DIR}; shift 2
      [ -d "$d" ] || { echo "no directory $d" >&2; exit 1; }
      # workspaces hold samples and large work/ trees: never descend into those
      while IFS= read -r -d '' m; do
        found+=("$(cd "$(dirname "$m")" && pwd -P)")
      done < <(find "$d" -maxdepth 4 \( -name work -o -name data -o -name node_modules -o -name .git \) -prune \
                 -o -name .cupella-workspace -type f -print0 2> /dev/null)
      ;;
    -h | --help | help) usage ;;
    *) usage ;;
  esac
done
# ${a[@]+...}: bash before 4.4 (macOS has 3.2) calls an empty array unbound under set -u
for w in ${found[@]+"${found[@]}"}; do
  [ "$w" != "$(cd "$root" && pwd -P)" ] || continue
  grep -qxF -- "$w" "$registry" 2> /dev/null || { echo "$w" >> "$registry"; echo "added: $w"; }
done

[ -s "$registry" ] || { echo "no workspaces recorded (./cupella setup --workspace DIR makes one; --find DIR searches for older ones)"; exit 0; }
here=$(cd "$root" && pwd -P)
count() { { find "$@" 2> /dev/null || true; } | wc -l | tr -d ' '; }  # missing directory: 0; BSD wc pads
printf '%-6s %5s %7s %9s  %-10s  %s\n' state apks reports proposals refreshed path
while IFS= read -r w; do
  [ -n "$w" ] || continue
  if [ ! -f "$w/.cupella-workspace" ]; then
    printf '%-6s %5s %7s %9s  %-10s  %s\n' gone - - - - "$w"
    continue
  fi
  apks=$(count "$w/data" -type f -name '*.apk')
  reports=$(count "$w/reports" -maxdepth 1 -type f -name '*.md')
  open=$(CUPELLA_WS="$root" CUPELLA_ROOT="$root" "$root/host/proposals.sh" "$w" 2> /dev/null | grep -c '^  open ' || true)
  refreshed=$(date -r "$w/WORKSPACE.md" +%F 2> /dev/null || echo never)
  note=""
  c=$(sed -n 's/^checkout=//p' "$w/.cupella-workspace" 2> /dev/null | head -1)
  if [ -n "$c" ] && [ "$(cd "$c" 2> /dev/null && pwd -P || echo "$c")" != "$here" ]; then
    note="  (set up for the checkout $c)"
  fi
  printf '%-6s %5s %7s %9s  %-10s  %s%s\n' ok "$apks" "$reports" "$open" "$refreshed" "$w" "$note"
done < <(sort -u "$registry")
