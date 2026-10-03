#!/usr/bin/env bash
# Analyze a Flutter app's Dart AOT snapshot (libapp.so) with blutter. Output is
# annotated arm64 assembly per Dart library with function names and resolved object
# pool references, plus dumps of the object pool. Static: the app is not executed.
#
# Usage: ./cupella flutter-decompile.sh <name>
#
# blutter is compiled once per Dart version. ./cupella does that automatically when the
# build is missing (scripts/blutter-build.sh, in a separate networked container that
# cannot see data/ or work/), then runs this script offline. Builds are kept in
# cache/blutter/. Needs work/<name>/ from unpack.sh; unpack.sh output for a Flutter
# app triggers this script through ./cupella as well.
#
# Internal: `flutter-decompile.sh --need <name>` prints the Dart version and exits 3
# when a build is required, 0 when one exists.
# Output: work/<name>/dart/  asm/<package>/<file>.dart, pp.txt, objs.txt, INDEX.txt
set -euo pipefail

need=0
if [ "${1:-}" = "--need" ]; then need=1; shift; fi
name=${1:?usage: ./cupella flutter-decompile.sh <name>}
root=$(cd "$(dirname "$0")/.." && pwd)
tools=${APK_TOOLS:?not in the analysis container: run this as ./cupella flutter-decompile.sh ...}
bl=${APK_BLUTTER:?not in the analysis container: run this as ./cupella flutter-decompile.sh ...}
# cache/ is read-only here; blutter-build.sh (run by ./cupella in the builder container)
# seeds it from the pristine copy in the image
libdir="$root/work/$name/raw/lib/arm64-v8a"
out="$root/work/$name/dart"

[ -f "$libdir/libapp.so" ] || { echo "no arm64 libapp.so under work/$name (blutter supports arm64 only; run unpack.sh first)" >&2; exit 1; }
[ -f "$libdir/libflutter.so" ] || { echo "no libflutter.so next to libapp.so" >&2; exit 1; }

# Dart version from the engine, snapshot features from the app
ver=$(python3 - "$libdir/libflutter.so" <<'EOF'
import re, sys
m = re.search(rb"(\d+\.\d+\.\d+[\w.-]*) \((?:stable|beta|dev|main)\)", open(sys.argv[1], "rb").read())
print(m.group(1).decode() if m else "")
EOF
)
[ -n "$ver" ] || { echo "could not find the Dart version string in libflutter.so" >&2; exit 1; }
flags=$(python3 - "$libdir/libapp.so" <<'EOF'
import re, sys
m = re.search(rb"[0-9a-f]{32}((?:product|release|debug|profile)[ -~]{10,200})", open(sys.argv[1], "rb").read())
print(m.group(1).decode() if m else "")
EOF
)
case " $flags " in
  *" compressed-pointers "*) ;;
  *) echo "snapshot is not built with compressed pointers; the build shortcut used here does not cover that" >&2
     exit 1 ;;
esac

bin="$bl/bin/blutter_dartvm${ver}_android_arm64"
if [ "$need" = 1 ]; then
  echo "$ver"
  [ -x "$bin" ] && exit 0 || exit 3
fi

echo "Dart $ver; snapshot features: $flags"
if [ ! -x "$bin" ]; then
  echo "no blutter build for Dart $ver in cache/blutter/: run this through ./cupella, which builds it" >&2
  exit 2
fi
mkdir -p "$out"
timeout --kill-after=30 "${APK_TOOL_TIMEOUT:-1800}" "$bin" -i "$libdir/libapp.so" -o "$out"

# Frida is dynamic instrumentation; this workspace is static-only
rm -f "$out/blutter_frida.js"

if [ -f "$root/scripts/dart-index.py" ]; then
  python3 "$root/scripts/dart-index.py" "$name" > "$out/INDEX.txt" || echo "dart-index failed"
fi
echo "wrote work/$name/dart/ ($(find "$out/asm" -type f 2>/dev/null | wc -l) assembly files)"
