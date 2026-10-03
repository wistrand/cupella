#!/usr/bin/env bash
# Workflow stage 1 for one APK: identity, raw unpack, fallback decodes, apktool, jadx.
# Output goes to work/<name>/; summaries are written to work/<name>/triage.txt,
# manifest-summary.txt, and native-summary.txt.
# Steps whose output already exists are skipped; pass -f to redo everything.
#
# Usage: scripts/unpack.sh [-f] data/<name>.apk
set -euo pipefail

force=0
if [ "${1:-}" = "-f" ]; then force=1; shift; fi
apk=${1:?usage: scripts/unpack.sh [-f] data/<name>.apk}
[ -f "$apk" ] || { echo "no such file: $apk" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
tools=${APK_TOOLS:?not in the analysis container: run this as ./cupella unpack.sh ...}  # set by the image
apk=$(realpath "$apk")
name=$(basename "$apk" .apk)
out="$root/work/$name"
# -f keeps agent work, which no script regenerates: decrypt/ (decryptor, notes, outputs),
# progress/ (agent progress files), and scan-scope.txt (the agent's scope, reused by scan.sh)
prune() { # <sample dir>: remove everything but agent work
  find "$1" -mindepth 1 -maxdepth 1 ! -name decrypt ! -name progress ! -name scan-scope.txt -exec rm -rf {} +
}
if [ "$force" = 1 ] && [ -d "$out" ]; then
  prune "$out"
fi
mkdir -p "$out"
# Extraction writes no symlinks, but a tool might. A symlink under work/ could point a
# later reader (a container step, or the agent's file tools on the host) at files
# outside the sample, so every symlink is recorded and removed after each extraction
# step (scripts/fixtures/zipslip-test.sh; unzip would create them, apkunzip, apktool,
# and jadx create none).
# a tool that runs longer than this is stopped and named in the triage (hostile input
# can make a decompiler loop); APK_TOOL_TIMEOUT overrides it
tl=${APK_TOOL_TIMEOUT:-1800}
timed() { # <tool label> <command...>: run with the time limit, record a timeout
  local label=$1 rc=0
  shift
  timeout --kill-after=30 "$tl" "$@" || rc=$?
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    echo "$label: stopped after ${tl}s (time limit; output is partial)" >> "$out/timeouts.txt"
    echo "$label timed out after ${tl}s"
  fi
  return "$rc"
}
sweep_links() {
  local l
  while IFS= read -r -d '' l; do
    printf '%s -> %s\n' "${l#"$out"/}" "$(readlink "$l")" >> "$out/symlinks-removed.txt"
    rm -f "$l"
  done < <(find "$out" -type l -print0 2>/dev/null)
}

if [ ! -d "$out/raw" ]; then
  # apkunzip.py, not unzip: it reads entries as Android does (fake encryption flags,
  # unknown methods, shadowed names), measures the inflated size against limits
  # (decompression bombs), and writes regular files only (unzip recreates symlinks).
  # A clean copy for the other tools (repaired.apk) is kept only when it found anomalies.
  echo "== extract (apkunzip.py)"
  timed apkunzip python3 "$root/scripts/apkunzip.py" "$apk" "$out/raw" --repair "$out/repaired.apk" > "$out/zip-anomalies.txt" \
    || echo "apkunzip could not read every entry; see zip-anomalies.txt"
  grep -qx 'no ZIP anomalies' "$out/zip-anomalies.txt" && rm -f "$out/zip-anomalies.txt"
  sweep_links
fi
# tools that reject the original's ZIP tricks get the clean copy
apk_clean=$apk
[ -f "$out/repaired.apk" ] && apk_clean="$out/repaired.apk"

if [ ! -f "$out/manifest.xml" ]; then
  echo "== fallback manifest decode"
  python3 "$root/scripts/axml2xml.py" "$out/raw/AndroidManifest.xml" > "$out/manifest.xml" \
    || echo "axml2xml failed"
fi

if [ ! -d "$out/dex" ]; then
  echo "== dex class and string lists"
  mapfile -t dexes < <(find "$out/raw" -maxdepth 1 -type f -name 'classes*.dex' | sort -V)
  python3 "$root/scripts/dexlist.py" "$out/dex" "${dexes[@]}" || echo "dexlist failed"
fi

if [ ! -d "$out/apktool" ]; then
  if [ -f "$tools/apktool.jar" ]; then
    echo "== apktool"
    timed apktool java -jar "$tools/apktool.jar" d -f -o "$out/apktool" "$apk_clean" > "$out/apktool.log" 2>&1 \
      || echo "apktool failed (exit $?), see work/$name/apktool.log; consider -r"
  else
    echo "== apktool skipped: not found under $tools (image incomplete; ask the user to run ./cupella build)"
  fi
fi

if [ ! -d "$out/jadx" ]; then
  if [ -x "$tools/jadx/bin/jadx" ]; then
    echo "== jadx"
    rc=0
    # jadx reads the original: it copes with the ZIP tricks itself and needs the entries
    # that repaired.apk leaves out (shadowed names can be real resources). Only an APK
    # that hit the decompression limits goes to jadx as the repaired copy.
    jadx_in=$apk
    grep -q 'size limit' "$out/zip-anomalies.txt" 2>/dev/null && jadx_in=$apk_clean
    timed jadx "$tools/jadx/bin/jadx" --log-level ERROR -d "$out/jadx" "$jadx_in" > "$out/jadx.log" 2>&1 || rc=$?
    echo "jadx exit $rc (nonzero is normal when some methods fail)"
  else
    echo "== jadx skipped: not found under $tools (image incomplete; ask the user to run ./cupella build)"
  fi
fi

# code shipped in the clear besides classes*.dex (second stages, plugins), found by
# content. Each container becomes a sample of its own, work/<name>.emb<k>/, unpacked
# by this script, so scan.sh, structure leads, flows, and xref cover it. embedded.txt
# lists: child name, kind, size, path under raw/, and "disguised" when renamed.
# nesting is limited: an archive that contains itself would otherwise recurse forever
depth=$( (grep -o '\.\(emb\|dec\)[0-9]' <<< "$name" || true) | wc -l)
if [ "$depth" -ge 3 ] && [ ! -f "$out/embedded.txt" ]; then
  python3 "$root/scripts/embedded.py" "$name" > "$out/embedded.list" || true
  echo "nesting depth $depth: embedded containers listed in embedded.list, not unpacked" > "$out/embedded.txt"
fi
if [ ! -f "$out/embedded.txt" ]; then
  python3 "$root/scripts/embedded.py" "$name" > "$out/embedded.list" || echo "embedded.py failed"
  : > "$out/embedded.txt"
  k=0
  fflag=()
  [ "$force" = 1 ] && fflag=(-f)
  while IFS=$'\t' read -r kind size rel rest; do
    k=$((k + 1))
    [ "$k" -le 20 ] || { echo "more than 20 embedded containers; the rest are listed in embedded.list only"; break; }
    child="$name.emb$k"
    mkdir -p "$out/embedded"
    if [ "$kind" = dex ]; then
      # a bare dex: wrap it as classes.dex so the APK tools accept it
      python3 -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[2], "w") as z, open(sys.argv[1], "rb") as f:
  z.writestr(zipfile.ZipInfo("classes.dex", (1980, 1, 1, 0, 0, 0)), f.read())' \
        "$out/raw/$rel" "$out/embedded/$child.apk" < /dev/null || { echo "could not wrap $rel"; continue; }
    else
      cp "$out/raw/$rel" "$out/embedded/$child.apk"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$child" "$kind" "$size" "$rel" "$rest" >> "$out/embedded.txt"
    echo "== embedded $rel ($kind): unpacking as $child"
    # -f reaches the children too: their work/<child>/ lies outside $out
    "$root/scripts/unpack.sh" ${fflag[@]+"${fflag[@]}"} "$out/embedded/$child.apk" > "$out/embedded/$child.unpack.log" 2>&1 < /dev/null \
      || echo "unpack of embedded $rel failed, see embedded/$child.unpack.log"
  done < "$out/embedded.list"
fi
if [ "$force" = 1 ]; then
  # children from an earlier run that this run did not produce (numbered above the new
  # count, or skipped now) are stale: pruned like $out, removed when no agent work is left
  for d in "$root/work/$name".emb[0-9]*; do
    [ -d "$d" ] || continue
    c=$(basename "$d")
    [[ ${c#"$name".emb} =~ ^[0-9]+$ ]] || continue
    awk -F'\t' -v c="$c" '$1 == c { f = 1 } END { exit !f }' "$out/embedded.txt" 2>/dev/null && continue
    prune "$d"
    rmdir "$d" 2>/dev/null && echo "removed stale child work/$c" \
      || echo "stale child work/$c: kept only its agent work (decrypt/, progress/, scan-scope.txt)"
  done
fi

if [ ! -f "$out/apkid.txt" ]; then
  echo "== apkid"
  { echo "# APKiD: $name"
    echo "Compilers, packers, protectors, obfuscators, and anti-analysis techniques identified"
    echo "by signature. A match names a tool or technique; what it protects is for the agent to read."
    echo
    apkid -t 120 "$apk" 2>&1 | sed "s#$root/##" || echo "apkid failed"
  } > "$out/apkid.txt"
fi
python3 "$root/scripts/trackers.py" "$name" > "$out/trackers.txt" || echo "trackers failed"
sweep_links

{
  echo "# Triage: $name"
  echo
  echo "## Identity"
  echo "file:   $apk"
  echo "size:   $(stat -c %s "$apk")"
  echo "sha256: $(sha256sum "$apk" | cut -d' ' -f1)"
  [ -f "$out/manifest.xml" ] && sed -n 2p "$out/manifest.xml" | grep -o -E '(package|android:versionName|android:versionCode|android:compileSdkVersion)="[^"]*"' || true
  [ -f "$out/manifest.xml" ] && grep -o -E 'android:(min|target)SdkVersion="[^"]*"' "$out/manifest.xml" || true
  echo
  echo "## Signing"
  echo "-- v1 (JAR) signature"
  keytool -printcert -jarfile "$apk" 2>&1 | grep -E 'Owner|Issuer|Valid|SHA256|Signature algorithm|Public Key|Not a signed' || true
  grep -h 'X-Android-APK-Signed' "$out"/raw/META-INF/*.SF 2>/dev/null || true
  echo "-- APK Signing Block (extracted, not verified)"
  python3 "$root/scripts/apksigblock.py" "$apk" "$out/sig" || echo "apksigblock failed"
  for c in "$out"/sig/cert-*.der; do
    [ -f "$c" ] || continue
    echo "-- $(basename "$c")"
    keytool -printcert -file "$c" 2>&1 | grep -E 'Owner|Issuer|Valid|SHA256|Signature algorithm|Public Key' || true
  done
  echo "-- verification (scripts/apksig-verify.py: content digest and signature checked)"
  python3 "$root/scripts/apksig-verify.py" "$apk" 2>&1 | grep -E '=> |^v1|RESULT|FAIL' || true
  echo
  echo "## Top-level entries"
  ls -A "$out/raw" 2>/dev/null || echo "raw/ missing: extraction failed (see zip-anomalies.txt)"
  echo
  echo "## Dex"
  ls -l "$out"/raw/classes*.dex 2>/dev/null | awk '{print $5, $NF}' \
    || echo "no classes*.dex under raw/: apkunzip could not extract them (see zip-anomalies.txt); jadx may still have read them"
  [ -f "$out/dex/classes.txt" ] && echo "classes: $(wc -l < "$out/dex/classes.txt")"
  echo
  echo "## Manifest red flags"
  grep -q 'android.permission.INTERNET' "$out/manifest.xml" 2>/dev/null \
    && echo "INTERNET: requested" || echo "INTERNET: not requested (no network access)"
  grep -o -E 'android:(debuggable|testOnly|sharedUserId|usesCleartextTraffic)="[^"]*"' "$out/manifest.xml" 2>/dev/null || true
  for s in AccessibilityService NotificationListenerService DeviceAdminReceiver VpnService \
           InputMethod 'service.autofill' 'telecom.InCallService' 'SMS_DELIVER'; do
    grep -q "$s" "$out/manifest.xml" 2>/dev/null && echo "declares: $s"
  done
  echo
  echo "## Bundled schemas and configs in assets"
  find "$out/raw/assets" -type f \( -name '*.json' -o -name '*.properties' -o -name '*.xml' -o -name '*.db' -o -name '*.sqlite' -o -name '*.js' \) 2>/dev/null | sed "s#$out/raw/##" | head -40 || true
  echo
  if [ -s "$out/timeouts.txt" ]; then
    echo "## Tool time limits reached (output partial; name it under Analysis coverage)"
    cat "$out/timeouts.txt"
    echo
  fi
  if [ -s "$out/symlinks-removed.txt" ]; then
    echo "## Symlink entries in the archive (removed; an APK has no use for them: anti-analysis or an attack on the analyst)"
    cat "$out/symlinks-removed.txt"
    echo
  fi
  if [ -f "$out/zip-anomalies.txt" ]; then
    echo "## ZIP anomalies (raw/ as Android reads it; apktool read repaired.apk, jadx the original unless a size limit was hit)"
    echo "Deliberate ZIP malformation is an anti-analysis technique; name it in the report."
    cat "$out/zip-anomalies.txt"
    echo
  fi
  echo "## APKiD (details in apkid.txt)"
  grep -E '^\s*\|->' "$out/apkid.txt" 2>/dev/null | sed -E 's/^\s*\|-> *//' | sort | uniq -c | sort -rn | head -n 20 || true
  echo
  echo "## Trackers (details in trackers.txt)"
  grep -E '^NOTE' "$out/trackers.txt" 2>/dev/null || true
  sed -n '/^## Tracker SDK code present/,$p' "$out/trackers.txt" 2>/dev/null \
    | grep -E '^## |^- ' | cut -c1-150 || true
  echo
  echo "## Native libraries"
  find "$out/raw/lib" -name '*.so' 2>/dev/null | sed "s#$out/raw/##" | sort || true
  echo "(details in native-summary.txt)"
  echo
  echo "## Framework markers"
  for m in assets/flutter_assets assets/index.android.bundle assets/www assets/bin/Data \
           lib/arm64-v8a/libflutter.so lib/arm64-v8a/libil2cpp.so lib/arm64-v8a/libmonodroid.so \
           lib/arm64-v8a/libreactnativejni.so lib/arm64-v8a/libhermes.so; do
    [ -e "$out/raw/$m" ] && echo "found: $m"
  done
  echo "(none listed above means a plain dex app; for Flutter see flutter-summary.txt)"
  echo
  echo "## Embedded code found by content (each unpacked as work/<child>/; scan.sh scans them)"
  [ -s "$out/embedded.txt" ] && cat "$out/embedded.txt" || echo "none"
  echo
  echo "## Embedded archives and code outside classes*.dex, by file name"
  find "$out/raw" -type f \( -name '*.apk' -o -name '*.dex' -o -name '*.jar' -o -name '*.zip' \) \
    ! -path "$out/raw/classes*.dex" | sed "s#$out/raw/##" || true
  echo
  echo "## Packages by class count (top 40, three levels)"
  [ -f "$out/dex/classes.txt" ] && cut -f2 "$out/dex/classes.txt" \
    | awk -F. '{ if (NF>=4) print $1"."$2"."$3; else if (NF==3) print $1"."$2; else print $1 }' \
    | sort | uniq -c | sort -rn | head -40 || true
  echo
  echo "## Tool results"
  [ -f "$out/apktool/apktool.yml" ] && echo "apktool: decoded" || echo "apktool: no output"
  if [ -d "$out/jadx/sources" ]; then
    echo "jadx: $(find "$out/jadx/sources" -name '*.java' | wc -l) java files"
    grep -a -o 'finished with errors, count: [0-9]*' "$out/jadx.log" || true
  else
    echo "jadx: no output"
  fi
  [ -f "$tools/VERSIONS" ] && cat "$tools/VERSIONS"
  echo
  timeout 600 python3 "$root/scripts/class-coverage.py" "$name" 2>&1 || echo "class-coverage failed or timed out"
} > "$out/triage.txt" 2>&1

python3 "$root/scripts/manifest-summary.py" "$name" > "$out/manifest-summary.txt" \
  || echo "manifest-summary failed"
python3 "$root/scripts/native-summary.py" "$name" > "$out/native-summary.txt" \
  || echo "native-summary failed"
if [ -d "$out/raw/assets/flutter_assets" ] || ls "$out"/raw/lib/*/libapp.so > /dev/null 2>&1; then
  python3 "$root/scripts/flutter-summary.py" "$name" > "$out/flutter-summary.txt" \
    || echo "flutter-summary failed"
  echo "== Flutter app: wrote flutter-summary.txt and flutter-strings.txt (app logic is Dart, not in jadx/)"
fi

if ls "$out"/raw/assets/*.bundle "$out"/raw/assets/*.hbc > /dev/null 2>&1; then
  echo "== React Native bundle: running hermes-decompile.sh"
  "$root/scripts/hermes-decompile.sh" "$name" || echo "hermes-decompile failed"
fi
echo "== wrote work/$name/triage.txt, manifest-summary.txt, native-summary.txt, apkid.txt, trackers.txt"
echo "next: ./cupella scan.sh $name [source-subdir ...]"
