#!/usr/bin/env bash
# Lists the workspaces made from this checkout. Run as `./cupella workspaces`; host side,
# no container. Reads only each workspace's marker and counts files in it.
#
#   ./cupella workspaces                  every workspace in .cupella-workspaces
#   ./cupella workspaces new DIR ...      a new workspace (handled by ./cupella: setup --workspace)
#   ./cupella workspaces --find DIR ...   also search DIR (4 levels deep) for workspace
#                                         markers, and add what is found to the list
#   ./cupella workspaces rm DIR [--yes]   delete a workspace: its Docker volumes (data/,
#                                         work/), the directory (reports/, proposals/,
#                                         exports/ with it), and its entry in the list;
#                                         shows what goes and asks for the directory's
#                                         name first (--yes: no question, for scripts)
#   ./cupella workspaces --prune          drop the entries whose directory is gone
#
# Per workspace: the path, whether it still exists, the checkout it names when that is
# not this one, APKs in data/ ("vol" when data/ is a Docker volume: ./cupella store ls
# in that workspace shows it), reports, open proposals, and when its doc copies were
# last refreshed from the checkout. A workspace is added to the list by setup and by
# each ./cupella run in it; one made before the list existed appears after its next run,
# or through --find.
set -euo pipefail

ws=${CUPELLA_WS:?run as ./cupella workspaces}
root=${CUPELLA_ROOT:?run as ./cupella workspaces}
registry=${CUPELLA_REGISTRY:-$root/.cupella-workspaces}  # CUPELLA_REGISTRY: for tests
usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
docker=${CUPELLA_DOCKER:-docker}

unregister() { # <path>: its line out of the list
  [ -f "$registry" ] || return 0
  { grep -vxF -- "$1" "$registry" || true; } > "$registry.tmp" && mv "$registry.tmp" "$registry"
}

if [ "${1:-}" = rm ]; then
  shift
  yes=0 dir=""
  for a in "$@"; do
    case $a in --yes) yes=1 ;; -*) usage ;; *) [ -z "$dir" ] && dir=$a || usage ;; esac
  done
  [ -n "$dir" ] || usage
  # the path as setup and the wrapper record it (cd && pwd, links kept)
  if [ -d "$dir" ]; then w=$(cd "$dir" && pwd); else w=${dir%/}; [[ $w == /* ]] || w="$PWD/$w"; fi
  [ "$w" != / ] && [ "$w" != "$HOME" ] || { echo "refusing to delete $w" >&2; exit 1; }
  if [ "$w" = "$(cd "$root" && pwd)" ] || { [ -d "$w" ] && [ "$(cd "$w" && pwd -P)" = "$(cd "$root" && pwd -P)" ]; }; then
    echo "$w is the checkout, not a workspace: nothing deleted" >&2; exit 1
  fi
  registered=no
  grep -qxF -- "$w" "$registry" 2> /dev/null && registered=yes
  wstore="" reports=0 props=0
  if [ -d "$w" ]; then
    # only a directory setup made: never an arbitrary one
    [ -f "$w/.cupella-workspace" ] && grep -q '^checkout=' "$w/.cupella-workspace" \
      || { echo "$w has no .cupella-workspace: not a Cupella workspace, nothing deleted" >&2; exit 1; }
    wstore=$(sed -n 's/^store=//p' "$w/.cupella-workspace")
    c=$(sed -n 's/^checkout=//p' "$w/.cupella-workspace" | head -1)
    [ "$c" = "$root" ] || echo "note: $w was set up for the checkout $c"
    # a missing directory counts 0 (find fails, and pipefail would end the script)
    reports=$({ find "$w/reports" -maxdepth 1 -type f -name '*.md' 2> /dev/null || true; } | wc -l | tr -d ' ')
    props=$({ find "$w/proposals" -maxdepth 1 -type f -name '*.md' 2> /dev/null || true; } | wc -l | tr -d ' ')
  elif [ "$registered" = no ]; then
    echo "$w: no such workspace (not a directory, not in the list)" >&2
  fi
  # its volumes: by the name setup gives them, and by the label setup puts on them
  # the path as given and resolved: a link in it gives another spelling, and another name
  paths=("$w")
  [ -d "$w" ] && [ "$(cd "$w" && pwd -P)" != "$w" ] && paths+=("$(cd "$w" && pwd -P)")
  vols=()
  if "$docker" info > /dev/null 2>&1; then
    while IFS= read -r v; do
      [ -n "$v" ] && [[ " ${vols[*]-} " != *" $v "* ]] && vols+=("$v")
    done < <({ for p in "${paths[@]}"; do
                 id=$(printf '%s' "$p" | sha256sum | cut -c1-12)
                 for v in "cupella-$id-data" "cupella-$id-work"; do "$docker" volume inspect "$v" > /dev/null 2>&1 && echo "$v"; done
                 "$docker" volume ls -q --filter "label=cupella.workspace=$p" 2> /dev/null
               done; } || true)
  elif [ "$wstore" = volume ]; then
    echo "Docker is not usable, and this workspace keeps data/ and work/ in volumes: nothing deleted" >&2; exit 1
  fi
  [ -d "$w" ] || [ "$registered" = yes ] || [ ${#vols[@]} -gt 0 ] || exit 1
  echo "workspace: $w"
  [ -d "$w" ] && echo "  directory, with $reports reports and $props proposals$([ -d "$w/exports" ] && echo ", exports/")" \
    || echo "  directory: already gone"
  echo "  volumes:   ${vols[*]:-none}"
  echo "  listed:    $registered"
  if [ "$yes" = 0 ]; then
    [ -t 0 ] || { echo "asks on a terminal; --yes deletes without asking" >&2; exit 1; }
    name=$(basename "$w")
    read -r -p "This cannot be undone. Type $name to delete it: " answer
    [ "$answer" = "$name" ] || { echo "not confirmed; nothing deleted"; exit 1; }
  fi
  if [ ${#vols[@]} -gt 0 ]; then
    "$docker" volume rm "${vols[@]}" > /dev/null \
      || { echo "could not delete the volumes (a container still using them? docker ps); nothing else deleted" >&2; exit 1; }
    echo "== deleted volumes ${vols[*]}"
  fi
  if [ -d "$w" ]; then
    # the doc copies are read-only
    chmod -R u+w "$w" && rm -rf -- "$w" || { echo "could not delete $w" >&2; exit 1; }
    echo "== deleted $w"
  fi
  if [ "$registered" = yes ]; then unregister "$w"; echo "== removed $w from the list"; fi
  exit 0
fi

if [ "${1:-}" = --prune ]; then
  [ -s "$registry" ] || { echo "no workspaces recorded"; exit 0; }
  n=0
  while IFS= read -r w; do
    [ -n "$w" ] && [ ! -f "$w/.cupella-workspace" ] || continue
    unregister "$w"; echo "dropped: $w"; n=$((n + 1))
  done < <(sort -u "$registry")
  echo "== $n gone workspace(s) dropped from the list (their volumes, if any: ./cupella store ls --all)"
  exit 0
fi

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

[ -s "$registry" ] || { echo "no workspaces recorded (./cupella workspaces new DIR makes one; --find DIR searches for older ones)"; exit 0; }
here=$(cd "$root" && pwd -P)
count() { { find "$@" 2> /dev/null || true; } | wc -l | tr -d ' '; }  # missing directory: 0; BSD wc pads
printf '%-6s %5s %7s %9s  %-10s  %s\n' state apks reports proposals refreshed path
while IFS= read -r w; do
  [ -n "$w" ] || continue
  if [ ! -f "$w/.cupella-workspace" ]; then
    printf '%-6s %5s %7s %9s  %-10s  %s\n' gone - - - - "$w"
    continue
  fi
  if grep -qx 'store=volume' "$w/.cupella-workspace" 2> /dev/null; then apks=vol
  else apks=$(count "$w/data" -type f -name '*.apk'); fi
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
