#!/usr/bin/env bash
# Checks that the extraction steps keep archive entries inside their output directory:
# builds hostile ZIPs in /tmp (a ../ entry, an absolute path, a symlink entry followed by
# an entry written through it) and runs unzip and apkunzip.py on each. Nothing outside
# /tmp is touched except work/zipslip-fixture/, created and removed by the unpack.sh case;
# prints PASS or FAIL per tool and case.
#
# Usage: ./cupella fixtures/zipslip-test.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d /tmp/zipslip.XXXX)
python3 - "$t" <<'PY'
import sys, zipfile
t = sys.argv[1]
def mk(name, entries):
  with zipfile.ZipFile("%s/%s.zip" % (t, name), "w") as z:
    for n, data, link in entries:
      zi = zipfile.ZipInfo(n)
      if link:
        zi.create_system = 3
        zi.external_attr = (0o120777 << 16)
      z.writestr(zi, data)
mk("dotdot", [("AndroidManifest.xml", b"x", False), ("../escaped_dotdot", b"pwned", False)])
mk("absolute", [("AndroidManifest.xml", b"x", False), ("%s/escaped_abs" % t, b"pwned", False)])
mk("symlink", [("AndroidManifest.xml", b"x", False), ("lnk", t, True), ("lnk/escaped_link", b"pwned", False)])
mk("symlink_only", [("AndroidManifest.xml", b"x", False), ("lnk", "/etc/passwd", True)])
PY
for case in dotdot absolute symlink symlink_only; do
  for tool in unzip apkunzip; do
    out="$t/out-$tool-$case"; mkdir -p "$out/raw"
    if [ $tool = unzip ]; then
      unzip -q -o "$t/$case.zip" -d "$out/raw" > /dev/null 2>&1 < /dev/null || true
    else
      python3 "$root/scripts/apkunzip.py" "$t/$case.zip" "$out/raw" > /dev/null 2>&1 || true
    fi
    bad=""
    [ -e "$out/escaped_dotdot" ] && bad="$bad ../-entry"
    ls "$t"/escaped_abs >/dev/null 2>&1 && bad="$bad absolute"
    [ -e "$t/escaped_link" ] && bad="$bad via-symlink"
    [ -n "$(find "$out/raw" -type l 2>/dev/null)" ] && bad="$bad symlink-created"
    echo "$tool $case: ${bad:+FAIL:}${bad:-PASS}$([ $tool = unzip ] && echo ' (unzip is not used by unpack.sh)')"
    rm -f "$t"/escaped_*
  done
done
# decompression bombs, with small limits so the test is quick: one entry over the entry
# limit, many entries over the total limit, and an entry whose declared size lies
python3 - "$t" <<'PY'
import struct, sys, zipfile
t = sys.argv[1]
with zipfile.ZipFile("%s/bomb1.zip" % t, "w", zipfile.ZIP_DEFLATED) as z:
  z.writestr("AndroidManifest.xml", b"x")
  z.writestr("assets/big", b"\0" * (8 << 20))
with zipfile.ZipFile("%s/bomb2.zip" % t, "w", zipfile.ZIP_DEFLATED) as z:
  for i in range(10):
    z.writestr("assets/part%d" % i, b"\0" * (600 << 10))
with zipfile.ZipFile("%s/bomb3.zip" % t, "w", zipfile.ZIP_DEFLATED) as z:
  z.writestr("assets/liar", b"\0" * (8 << 20))
b = bytearray(open("%s/bomb3.zip" % t, "rb").read())
lo = b.find(b"PK\x03\x04"); cd = b.find(b"PK\x01\x02")
struct.pack_into("<I", b, lo + 22, 100); struct.pack_into("<I", b, cd + 24, 100)  # declare 100 bytes
open("%s/bomb3.zip" % t, "wb").write(b)
PY
for case in bomb1 bomb2 bomb3; do
  out="$t/out-$case"; mkdir -p "$out"
  res=$(APK_ENTRY_MAX=$((1 << 20)) APK_TOTAL_MAX=$((2 << 20)) python3 "$root/scripts/apkunzip.py" "$t/$case.zip" "$out" 2>&1 || true)
  size=$(du -sb "$out" | cut -f1)
  if [ "$size" -le $((2 << 20)) ] && grep -q 'size limit' <<< "$res"; then echo "apkunzip $case: PASS ($size bytes written)"
  else echo "apkunzip $case: FAIL ($size bytes written; $res)"; fi
done

# apktool and jadx write files named by the archive too (assets, unknown files, resources)
tools=${APK_TOOLS:-}
if [ -n "$tools" ]; then
  python3 - "$t" <<'PY'
import sys, zipfile
t = sys.argv[1]
with zipfile.ZipFile("%s/tool.apk" % t, "w") as z:
  z.writestr("AndroidManifest.xml", b"x")
  z.writestr("assets/../../escaped_tool_assets", b"pwned")
  z.writestr("unknown/../../../escaped_tool_unknown", b"pwned")
  z.writestr("res/../../../escaped_tool_res", b"pwned")
  z.writestr("%s/escaped_tool_abs" % t, b"pwned")
PY
  mkdir -p "$t/w"
  (cd "$t/w" && java -jar "$tools/apktool.jar" d -f -r -s -o "$t/w/apktool" "$t/tool.apk" > "$t/apktool.log" 2>&1) || true
  "$tools/jadx/bin/jadx" -d "$t/w/jadx" "$t/tool.apk" > "$t/jadx.log" 2>&1 || true
  for tool in apktool jadx; do
    esc=$(find "$t" -name 'escaped_tool_*' -not -path "$t/w/$tool/*" 2>/dev/null | grep -v "^$t/w/[a-z]*/" || true)
    lnk=$(find "$t/w/$tool" -type l 2>/dev/null || true)
    echo "$tool traversal: ${esc:+FAIL: $esc}${lnk:+ FAIL: symlink $lnk}${esc:-${lnk:-PASS}}"
    rm -f $esc
    if [ $tool = apktool ]; then echo "  apktool log: $(tail -2 "$t/apktool.log" | tr '\n' ' ' | cut -c1-160)"
    else echo "  jadx wrote: $(find "$t/w/jadx" -type f 2>/dev/null | sed "s|^$t/w/||" | head -6 | tr '\n' ' ')"; fi
    [ $tool = apktool ] && echo "  apktool wrote: $(find "$t/w/apktool" -type f 2>/dev/null | sed "s|^$t/w/||" | head -6 | tr '\n' ' ')"
  done
fi
# the whole unpack stage: a symlink entry must not survive in work/
if [ -n "$tools" ]; then
  cp "$t/symlink_only.zip" "$t/zipslip-fixture.apk"
  rc=0; "$root/scripts/unpack.sh" -f "$t/zipslip-fixture.apk" > "$t/unpack.log" 2>&1 || rc=$?
  [ "$rc" = 0 ] || { echo "unpack.sh exit $rc:"; tail -5 "$t/unpack.log"; }
  w="$root/work/zipslip-fixture"
  links=$(find "$w" -type l 2>/dev/null | wc -l)
  noted=$(grep -c 'symlink entries' "$w/triage.txt" 2>/dev/null || true)
  echo "unpack.sh symlink entry: $([ "$links" = 0 ] && [ "${noted:-0}" -gt 0 ] && echo PASS || echo "FAIL: $links links left, noted in triage: ${noted:-0}")"
  rm -rf "$w"
fi
rm -rf "$t"
