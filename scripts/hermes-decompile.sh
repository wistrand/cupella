#!/usr/bin/env bash
# React Native apps: make the JavaScript bundle readable.
#
# The app's logic is in assets/index.android.bundle. It is either plain (minified)
# JavaScript or Hermes bytecode. For Hermes bytecode this runs hermes-dec to produce
# pseudo-JavaScript and a disassembly. unpack.sh calls this when a bundle is present.
# Static: the bundle is parsed, never executed.
#
# Usage: ./cupella hermes-decompile.sh <name>
# Output: work/<name>/hermes/  bundle.js (decompiled), bundle.hasm (disassembly),
#         header.txt (bytecode version and tables), SUMMARY.txt
set -euo pipefail

name=${1:?usage: ./cupella hermes-decompile.sh <name>}
root=$(cd "$(dirname "$0")/.." && pwd)
: "${APK_TOOLS:?not in the analysis container: run this as ./cupella hermes-decompile.sh ...}"
raw="$root/work/$name/raw"
out="$root/work/$name/hermes"

bundle=""
for c in "$raw/assets/index.android.bundle" "$raw"/assets/*.bundle "$raw"/assets/*.hbc; do
  [ -f "$c" ] && { bundle=$c; break; }
done
[ -n "$bundle" ] || { echo "no JavaScript bundle under work/$name/raw/assets: not a React Native app"; exit 0; }
mkdir -p "$out"
rel=${bundle#$root/}

# Hermes bytecode starts with the magic 0x1F1903C103BC1FC6 (little-endian on disk)
magic=$(head -c 8 "$bundle" | od -An -tx1 | tr -d ' \n')
{
  echo "# React Native bundle: $name"
  echo "bundle: $rel ($(stat -c %s "$bundle") bytes)"
} > "$out/SUMMARY.txt"

if [ "$magic" != "c61fbc03c103191f" ]; then
  {
    echo "format: not Hermes bytecode (magic $magic); plain or minified JavaScript"
    echo "read it directly: grep it for URLs, keys, and feature names. It is one long line"
    echo "when minified; search with grep -o and context patterns, do not open it whole."
  } >> "$out/SUMMARY.txt"
  cat "$out/SUMMARY.txt"
  exit 0
fi

echo "format: Hermes bytecode" >> "$out/SUMMARY.txt"
hbc-file-parser "$bundle" > "$out/header.txt" 2>&1 || echo "hbc-file-parser failed (see hermes/header.txt)" >> "$out/SUMMARY.txt"
grep -i -m 3 -E 'version|function ?count|string ?count' "$out/header.txt" >> "$out/SUMMARY.txt" 2>/dev/null || true
if timeout --kill-after=30 "${APK_TOOL_TIMEOUT:-1800}" hbc-decompiler "$bundle" "$out/bundle.js" > "$out/decompile.log" 2>&1; then
  echo "decompiled: work/$name/hermes/bundle.js ($(wc -l < "$out/bundle.js") lines)" >> "$out/SUMMARY.txt"
else
  echo "hbc-decompiler FAILED (see hermes/decompile.log): the bytecode version may be newer than hermes-dec supports" >> "$out/SUMMARY.txt"
fi
if timeout --kill-after=30 "${APK_TOOL_TIMEOUT:-1800}" hbc-disassembler "$bundle" "$out/bundle.hasm" > "$out/disasm.log" 2>&1; then
  echo "disassembly: work/$name/hermes/bundle.hasm ($(wc -l < "$out/bundle.hasm") lines)" >> "$out/SUMMARY.txt"
else
  echo "hbc-disassembler FAILED (see hermes/disasm.log)" >> "$out/SUMMARY.txt"
fi

# strings of interest straight from the string table, which survives any decompile failure
if [ -f "$out/bundle.hasm" ] || [ -f "$out/bundle.js" ]; then
  src="$out/bundle.js"; [ -f "$src" ] || src="$out/bundle.hasm"
  {
    echo
    echo "## URLs referenced"
    grep -a -o -E "(https?|wss?)://[^\"' )>\\\\]+" "$src" | sort -u \
      | grep -v -E 'reactnative\.dev|reactjs\.org|react\.dev|fb\.me|github\.com/facebook|w3\.org|mozilla\.org' | head -n 150 || true
    echo
    echo "## Native modules referenced (NativeModules.X / TurboModuleRegistry)"
    grep -a -o -E "(NativeModules\.[A-Za-z0-9_]+|getEnforcing\(['\"][A-Za-z0-9_]+|TurboModuleRegistry\.get\(['\"][A-Za-z0-9_]+)" "$src" \
      | sed -E "s/.*[.('\"]//" | sort | uniq -c | sort -rn | head -n 60 || true
  } >> "$out/SUMMARY.txt"
fi
cat "$out/SUMMARY.txt" | head -n 12
