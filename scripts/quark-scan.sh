#!/usr/bin/env bash
# Runs Quark-Engine on APKs, for the benchmark comparison: the rule set pinned in the
# image (/opt/tools/quark-rules), JSON report to work/<name>/tools/quark.json and the
# summary table to quark.txt. APKs already scanned are skipped unless -f is given.
#
# Usage: ./cupella quark-scan.sh [-f] <data/...apk | list.txt> [...]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
: "${APK_TOOLS:?not in the analysis container: run this as ./cupella quark-scan.sh ...}"
rules="$APK_TOOLS/quark-rules/rules"
[ -d "$rules" ] || { echo "quark rules not in the image: ask the user to run ./cupella build" >&2; exit 1; }
force=0
[ "${1:-}" = "-f" ] && { force=1; shift; }
apks=()
for a in "$@"; do
  if [[ "$a" == *.txt ]]; then mapfile -t -O "${#apks[@]}" apks < <(grep -v '^$' "$root/$a"); else apks+=("$a"); fi
done
for a in "${apks[@]}"; do
  name=$(basename "$a" .apk)
  out="$root/work/$name/tools"
  [ "$force" = 0 ] && [ -s "$out/quark.json" ] && continue
  mkdir -p "$out"
  t0=$(date +%s)
  # HOME on tmpfs: quark writes its config there; -o writes the JSON report
  # cwd /tmp: quark writes a dated log file into the current directory
  if (cd /tmp && HOME=/tmp/home timeout --kill-after=30 "${APK_TOOL_TIMEOUT:-1800}" \
      quark -a "$root/$a" -r "$rules" -s -o "$out/quark.json") > "$out/quark.txt" 2>&1; then
    echo "quark: $name $(( $(date +%s) - t0 ))s"
  else
    echo "quark: $name FAILED (see work/$name/tools/quark.txt)"
  fi
done
