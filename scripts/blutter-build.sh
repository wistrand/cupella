#!/usr/bin/env bash
# Build blutter for one Dart version: fetches the Dart runtime sources at that
# version and compiles blutter against them, into cache/blutter/. Several minutes.
#
# ./cupella calls this automatically when flutter-decompile.sh needs a build that is not
# in the cache. It runs in a networked container that has no access to data/ or
# work/: the only input is the version string, which ./cupella validates first.
#
# Usage (normally not called by hand): ./cupella blutter-build.sh <dart-version>
set -euo pipefail

ver=${1:?usage: blutter-build.sh <dart-version>   e.g. 3.7.0}
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*$ ]] || { echo "not a Dart version: $ver" >&2; exit 1; }
tools=${APK_TOOLS:?not in the analysis container: run this as ./cupella blutter-build.sh ...}
bl=${APK_BLUTTER:?not in the analysis container: run this as ./cupella blutter-build.sh ...}

# first use: seed the writable cache from the pristine copy in the image
if [ ! -f "$bl/blutter.py" ]; then
  mkdir -p "$bl"
  cp -r "$tools/blutter-src/." "$bl/"
fi

if [ -x "$bl/bin/blutter_dartvm${ver}_android_arm64" ]; then
  echo "blutter for Dart $ver already built"
  exit 0
fi

echo "building blutter for Dart $ver (fetching Dart runtime sources, compiling)"
cd "$bl"
python3 - "$ver" <<'EOF'
import os
import sys

sys.path.insert(0, os.getcwd())
import blutter
from dartvm_fetch_build import DartLibInfo, fetch_and_build

info = DartLibInfo(sys.argv[1], "android", "arm64")
inp = blutter.BlutterInput("", info, "", True, False, False)
if not os.path.isfile(os.path.join(blutter.PKG_LIB_DIR, "lib" + info.lib_name + ".a")):
  fetch_and_build(info)
blutter.cmake_blutter(inp)
if not os.path.isfile(inp.blutter_file):
  sys.exit("build finished but %s is missing" % inp.blutter_file)
print("built " + inp.blutter_file)
EOF

# the Dart source checkout and intermediate build trees are not needed afterwards
rm -rf "$bl/dartsdk" "$bl/build"
