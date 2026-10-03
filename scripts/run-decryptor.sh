#!/usr/bin/env bash
# Run an agent-written static decryptor for one sample, then unpack what it produced.
#
# The agent reads the app's decryption routine and reimplements it in Python as
# work/<name>/decrypt/decrypt.py (standard library plus pycryptodome, imported as
# Cryptodome; openssl is also available). The reimplementation reads
# the encrypted data from work/<name>/raw/ and writes plaintext to
# work/<name>/decrypt/out/. Nothing from the APK is executed: only the agent's script,
# in the offline container.
#
# Afterwards, every dex file or dex-bearing archive in out/ is unpacked and scanned as
# a sample of its own, work/<name>.dec<k>/, like an embedded payload; out/ and the
# list in work/<name>/decrypt/outputs.txt are what the analysis reads next. Files under
# out/parts/ are listed but not unpacked: the pieces of an output the decryptor
# assembled (split APKs and the dex of a multidex app, rebuilt as one APK with its
# manifest). Children of an earlier run beyond this run's count are removed. When
# out/string-map.tsv exists (literal arguments of decoder calls -> plaintext), each
# child's jadx sources get annotated copies in jadx-strings/ (scripts/annotate-strings.py).
#
# Safety: scripts/decryptor-lint.py rejects decryptors that could run code or reach
# the network, and ./cupella executes the decryptor in a container where only
# work/<name>/decrypt/ is writable and other samples and data/ are not mounted.
#
# Usage: ./cupella run-decryptor.sh <name>
set -euo pipefail

phase=all
case "${1:-}" in --exec) phase=exec; shift ;; --unpack) phase=unpack; shift ;; esac
name=${1:?usage: ./cupella run-decryptor.sh <name>}
root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/work/$name/decrypt"
[ -f "$dir/decrypt.py" ] || { echo "no $dir/decrypt.py: write the decryptor first" >&2; exit 1; }

if [ "$phase" != unpack ]; then
  # the decryptor was written by an agent that read malware: check it, then run it
  # (./cupella gives this phase a container that can write only decrypt/)
  python3 -B "$root/scripts/decryptor-lint.py" "$dir" || exit 1
  mkdir -p "$dir/out"
  echo "== running work/$name/decrypt/decrypt.py"
  (cd "$dir" && timeout 600 python3 -B decrypt.py) || { echo "decrypt.py failed (exit $?)" >&2; exit 1; }
  [ "$phase" = exec ] && exit 0
fi

: > "$dir/outputs.txt"
k=0
while IFS= read -r -d '' f; do
  rel=${f#"$dir/out/"}
  kind=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import importlib.util as u
s = u.spec_from_file_location("e", sys.argv[1] + "/embedded.py"); m = u.module_from_spec(s); s.loader.exec_module(m)
print(m.kind_of(sys.argv[2]) or "")' "$root/scripts" "$f")
  size=$(stat -c %s "$f")
  if [ "${rel#parts/}" != "$rel" ]; then
    # pieces of an assembled output (split APKs, dex of a multidex app): recorded only
    printf '%s\tpart\t%s\t-\n' "$rel" "$size" >> "$dir/outputs.txt"
  elif [ -n "$kind" ]; then
    k=$((k + 1))
    child="$name.dec$k"
    if [ "$kind" = dex ]; then
      python3 -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[2], "w") as z, open(sys.argv[1], "rb") as f:
  z.writestr(zipfile.ZipInfo("classes.dex", (1980, 1, 1, 0, 0, 0)), f.read())' "$f" "$dir/$child.apk"
    else
      cp "$f" "$dir/$child.apk"
    fi
    printf '%s\t%s\t%s\t%s\n' "$rel" "$kind" "$size" "$child" >> "$dir/outputs.txt"
    echo "== $rel ($kind): unpacking as $child"
    # -f: a rerun of the decryptor may produce a different payload under the same name
    "$root/scripts/unpack.sh" -f "$dir/$child.apk" > "$dir/$child.unpack.log" 2>&1 || echo "unpack of $child failed, see $dir/$child.unpack.log"
    "$root/scripts/scan.sh" "$child" > "$dir/$child.scan.log" 2>&1 || echo "scan of $child failed, see $dir/$child.scan.log"
    if [ -f "$dir/out/string-map.tsv" ]; then
      maps=("work/$name/decrypt/out/string-map.tsv")
      [ -f "$root/work/$child/string-map.tsv" ] && maps+=("work/$child/string-map.tsv")
      python3 "$root/scripts/annotate-strings.py" "$child" "${maps[@]}" || echo "annotate-strings failed for $child"
    fi
  else
    printf '%s\tdata\t%s\t-\n' "$rel" "$size" >> "$dir/outputs.txt"
  fi
done < <(find "$dir/out" -type f -print0 | sort -z)
# children of an earlier run that this run no longer produces
for old in "$root/work/$name".dec*; do
  [ -d "$old" ] || continue
  j=${old##*.dec}
  case $j in ''|*[!0-9]*) continue ;; esac
  if [ "$j" -gt "$k" ]; then
    echo "== removing $(basename "$old"): left from an earlier run"
    rm -rf "$old" "$dir/$(basename "$old").apk" "$dir/$(basename "$old")".*.log
  fi
done
echo "== outputs (work/$name/decrypt/outputs.txt):"
cat "$dir/outputs.txt"
