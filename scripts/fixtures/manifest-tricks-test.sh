#!/usr/bin/env bash
# Checks that a manifest hidden by ZIP and binary-XML tricks is still read: builds a
# synthetic APK (fixtures/manifest-tricks.py: the manifest stored with an unknown
# compression method and a false compressed size, an element without a name, attributes
# without their namespace, tag="" padding) in work/_manifest-fixture/, runs apkunzip.py,
# axml2xml.py, and manifest-summary.py on it, prints PASS or FAIL per trick, and removes
# the directory. A truncated manifest must make axml2xml.py fail, not print an empty
# document.
#
# Usage: ./cupella fixtures/manifest-tricks-test.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
w="$root/work/_manifest-fixture"
rm -rf "$w"
mkdir -p "$w"
check() { # <label> <0 when ok> [detail]
  if [ "$2" = 0 ]; then echo "$1: PASS"; else echo "$1: FAIL${3:+ ($3)}"; fi
}
size=$(python3 "$root/scripts/fixtures/manifest-tricks.py" "$w/tricks.apk")

# 1. ZIP: the entry is read as stored, at its uncompressed size
python3 "$root/scripts/apkunzip.py" "$w/tricks.apk" "$w/raw" --repair "$w/repaired.apk" > "$w/zip-anomalies.txt" 2>&1 || true
got=$(stat -c %s "$w/raw/AndroidManifest.xml" 2>/dev/null || echo 0)
check "apkunzip stored entry with a false compressed size" "$([ "$got" = "$size" ] && echo 0 || echo 1)" "$got of $size bytes"
check "apkunzip names the trick" "$(grep -q 'false compressed size' "$w/zip-anomalies.txt" && grep -q 'compression method 35868' "$w/zip-anomalies.txt" && echo 0 || echo 1)"
rep=$(python3 -c 'import sys, zipfile
print(len(zipfile.ZipFile(sys.argv[1]).read("AndroidManifest.xml")))' "$w/repaired.apk" 2>/dev/null || echo 0)
check "repaired copy holds the whole manifest" "$([ "$rep" = "$size" ] && echo 0 || echo 1)" "$rep of $size bytes"

# 2. binary XML: attributes by resource id, the nameless element kept
python3 "$root/scripts/axml2xml.py" "$w/raw/AndroidManifest.xml" > "$w/manifest.xml" 2> "$w/axml.err" || true
check "axml2xml attribute without namespace" "$(grep -q '<uses-permission android:name="android.permission.INTERNET"' "$w/manifest.xml" && grep -q 'android:exported="true"' "$w/manifest.xml" && echo 0 || echo 1)"
check "axml2xml element without a name" "$(grep -q '<_ android:name="com.example.fixture.PERM"' "$w/manifest.xml" && echo 0 || echo 1)"

# 3. a truncated manifest (what a tool that trusts the compressed size gets) is an error
head -c 100 "$w/raw/AndroidManifest.xml" > "$w/truncated.bin"
rc=0
python3 "$root/scripts/axml2xml.py" "$w/truncated.bin" > "$w/truncated.xml" 2>> "$w/axml.err" || rc=$?
check "axml2xml fails on a truncated manifest" "$([ "$rc" != 0 ] && ! grep -q '<manifest' "$w/truncated.xml" && echo 0 || echo 1)" "exit $rc"

# 4. the summary: permissions and components found, anomalies listed
python3 "$root/scripts/manifest-summary.py" _manifest-fixture > "$w/manifest-summary.txt" 2>&1 || true
check "manifest-summary reads the tampered manifest" "$(grep -q '^- android.permission.INTERNET' "$w/manifest-summary.txt" && grep -q 'activity com.example.fixture.Main \[explicit\]' "$w/manifest-summary.txt" && echo 0 || echo 1)"
check "manifest-summary lists the anomalies" "$(grep -q 'empty or invalid name: 1' "$w/manifest-summary.txt" && grep -q 'attribute tag="" on 7 elements' "$w/manifest-summary.txt" && echo 0 || echo 1)"

# 5. apktool writes a nameless element as "< attr=...>", which is not XML: still summarized
mkdir -p "$w/apktool"
sed -e 's/<_ /< /' -e 's#</_>#</ >#' "$w/manifest.xml" > "$w/apktool/AndroidManifest.xml"
python3 "$root/scripts/manifest-summary.py" _manifest-fixture > "$w/manifest-summary-apktool.txt" 2>&1 || true
check "manifest-summary reads apktool's invalid XML" "$(grep -q 'apktool/AndroidManifest.xml is not well-formed' "$w/manifest-summary-apktool.txt" && grep -q '^- android.permission.INTERNET' "$w/manifest-summary-apktool.txt" && echo 0 || echo 1)"
rm -rf "$w"
