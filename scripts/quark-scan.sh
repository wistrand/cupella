#!/usr/bin/env bash
# Runs Quark-Engine on APKs: the rule set pinned in the image (/opt/tools/quark-rules),
# JSON report to work/<name>/tools/quark.json and the summary table to quark.txt.
# scan.sh runs it on each sample (-n); the benchmark comparison runs it on APK paths.
# A sample already scanned, or one whose last run failed (tools/quark.failed), is skipped
# unless -f is given: the result depends only on the APK and the pinned rules.
#
# Usage: ./cupella quark-scan.sh [-f] <data/...apk | list.txt> [...]
#        ./cupella quark-scan.sh [-f] -n <name> [...]   samples by name: work/<name>/repaired.apk
#                                                      when unpack.sh made one (Quark crashes
#                                                      on malformed ZIPs), else the input file
#                                                      named in triage.txt
# Environment: QUARK_TIMEOUT seconds per APK (default APK_TOOL_TIMEOUT, else 1800)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
: "${APK_TOOLS:?not in the analysis container: run this as ./cupella quark-scan.sh ...}"
rules="$APK_TOOLS/quark-rules/rules"
[ -d "$rules" ] || { echo "quark rules not in the image: ask the user to run ./cupella build" >&2; exit 1; }
force=0
[ "${1:-}" = "-f" ] && { force=1; shift; }
by_name=0
[ "${1:-}" = "-n" ] && { by_name=1; shift; }
names=() apks=()
if [ "$by_name" = 1 ]; then
  for n in "$@"; do
    w="$root/work/$n"
    a=""
    if [ -f "$w/repaired.apk" ]; then
      a="$w/repaired.apk"
    elif [ -f "$w/triage.txt" ]; then
      a=$(sed -n 's/^file: *//p' "$w/triage.txt" | head -n 1)
      a=${a/#\/repo\//$root/}
    fi
    if [ -z "$a" ] || [ ! -f "$a" ]; then
      echo "quark: $n: no APK found (work/$n/repaired.apk, or file: in triage.txt)"
      continue
    fi
    names+=("$n") apks+=("$a")
  done
else
  list=()
  for a in "$@"; do
    if [[ "$a" == *.txt ]]; then mapfile -t -O "${#list[@]}" list < <(grep -v '^$' "$root/$a"); else list+=("$a"); fi
  done
  for a in "${list[@]}"; do
    names+=("$(basename "$a" .apk)") apks+=("$root/$a")
  done
fi
for i in "${!names[@]}"; do
  name=${names[$i]} apk=${apks[$i]}
  out="$root/work/$name/tools"
  if [ "$force" = 0 ] && { [ -s "$out/quark.json" ] || [ -f "$out/quark.failed" ]; }; then
    continue
  fi
  mkdir -p "$out"
  rm -f "$out/quark.failed"
  t0=$(date +%s)
  # HOME on tmpfs: quark writes its config there; -o writes the JSON report
  # cwd /tmp: quark writes a dated log file into the current directory
  if (cd /tmp && HOME=/tmp/home timeout --kill-after=30 "${QUARK_TIMEOUT:-${APK_TOOL_TIMEOUT:-1800}}" \
      quark -a "$apk" -r "$rules" -s -o "$out/quark.json") > "$out/quark.txt" 2>&1 && [ -s "$out/quark.json" ]; then
    echo "quark: $name $(( $(date +%s) - t0 ))s"
  else
    rm -f "$out/quark.json"
    echo "exited after $(( $(date +%s) - t0 ))s; see quark.txt; -f retries" > "$out/quark.failed"
    echo "quark: $name FAILED (see work/$name/tools/quark.txt)"
  fi
done
