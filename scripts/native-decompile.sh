#!/usr/bin/env bash
# Decompile a native library to C with Ghidra (headless). Ghidra is part of the
# container image; run this through ./cupella. Static: the library is not executed.
#
# Usage: scripts/native-decompile.sh <lib.so> [function-name | 0xADDR ...]
#   With no functions, every function is decompiled (slow on large libraries).
#   Addresses are file virtual addresses as printed by native-disasm.py --list.
# Output: work/<name>/native/<abi>/<lib>.c for a library under raw/lib/<abi>/,
#   work/<name>/native/other/<file>.c for an ELF elsewhere under raw/, else next to the input.
set -euo pipefail

lib=${1:?usage: scripts/native-decompile.sh <lib.so> [function ...]}
shift
root=$(cd "$(dirname "$0")/.." && pwd)
tools=${APK_TOOLS:?not in the analysis container: run this as ./cupella native-decompile.sh ...}
headless="$tools/ghidra/support/analyzeHeadless"
[ -x "$headless" ] || { echo "Ghidra not found under $tools (image incomplete; ask the user to run ./cupella build)" >&2; exit 1; }
[ -f "$lib" ] || { echo "no such file: $lib" >&2; exit 1; }
lib=$(realpath "$lib")

# the sample dir is everything before the first /raw/; the ABI is the first component
# after raw/lib/ (a glob * also matches /, so nested paths need the split)
case "$lib" in
  "$root"/work/*/raw/*)
    name_dir=${lib%%/raw/*}
    rel=${lib#"$name_dir"/raw/}
    case "$rel" in
      lib/*/*)
        abi=${rel#lib/}
        abi=${abi%%/*}
        out_dir="$name_dir/native/$abi" ;;
      *)
        # an ELF outside lib/ (assets, res): keep raw/ pristine, write under native/other/
        out_dir="$name_dir/native/other" ;;
    esac ;;
  *) out_dir=$(dirname "$lib") ;;
esac
mkdir -p "$out_dir"
out="$out_dir/$(basename "$lib").c"
[ $# -gt 0 ] && out="$out_dir/$(basename "$lib").partial.c"

proj=$(mktemp -d)
trap 'rm -rf "$proj"' EXIT
log="$out_dir/$(basename "$lib").ghidra.log"

timeout --kill-after=30 "${APK_TOOL_TIMEOUT:-1800}" "$headless" "$proj" apk -import "$lib" \
  -scriptPath "$root/scripts/ghidra" \
  -postScript ExportDecompiled.java "$out" "$@" \
  -deleteProject > "$log" 2>&1 || { echo "Ghidra failed, see $log" >&2; tail -n 20 "$log" >&2; exit 1; }

python3 "$root/scripts/ghidra/postprocess.py" "$lib" "$out" || echo "postprocess failed; raw Ghidra output kept"
grep -a 'exported ' "$log" | sed 's/^INFO *//' | tail -n 1 || true
echo "wrote $out"
