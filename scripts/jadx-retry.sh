#!/usr/bin/env bash
# Re-decompile the classes whose methods jadx failed on, in jadx's "simple" mode
# (linear code with gotos instead of restored structure). A method that defeats
# structure recovery usually still comes out readable this way. The normal jadx
# output is left untouched; results go to work/<name>/jadx-retry/<class>/.
#
# Usage: ./cupella jadx-retry.sh <name> [class-prefix ...]
#   class-prefix  only retry classes starting with one of these (dotted, e.g. org.example).
#                 Default: every failed class. scan.sh calls this with its scopes.
# Writes work/<name>/jadx-retry/INDEX.txt: failed method -> file to read.
set -euo pipefail

name=${1:?usage: ./cupella jadx-retry.sh <name> [class-prefix ...]}
shift
root=$(cd "$(dirname "$0")/.." && pwd)
tools=${APK_TOOLS:?not in the analysis container: run this as ./cupella jadx-retry.sh ...}
out="$root/work/$name"
apk=$(find "$root/data" -name "$name.apk" -type f | head -n 1)  # data/ may have subdirectories
if [ -z "$apk" ] && [ -d "$root/work/_samples" ]; then
  # an APK that sample-archive.py took out of a sample archive
  apk=$(find "$root/work/_samples" -name "$name.apk" -type f | head -n 1)
fi
if [ -z "$apk" ] && [[ "$name" == *.emb* ]]; then
  # an embedded payload: unpack.sh keeps its copy in the parent's embedded/ directory
  apk=$(find "$root/work/${name%.emb*}/embedded" -name "$name.apk" -type f 2>/dev/null | head -n 1)
fi
if [ -z "$apk" ] && [[ "$name" == *.dec* ]]; then
  # a payload decrypted by run-decryptor.sh
  apk=$(find "$root/work/${name%.dec*}/decrypt" -name "$name.apk" -type f 2>/dev/null | head -n 1)
fi
[ -f "$out/jadx.log" ] || { echo "no work/$name/jadx.log: run unpack.sh first" >&2; exit 1; }
[ -n "$apk" ] || { echo "$name.apk not found under data/" >&2; exit 1; }
max=${JADX_RETRY_MAX:-40}

# failed methods from the log, mapped to their top-level class via the dex class list
python3 - "$out" "$@" > "$out/jadx-retry.todo" <<'EOF'
import os, re, sys
out, prefixes = sys.argv[1], sys.argv[2:]
classes = {}
with open(os.path.join(out, "dex", "classes.txt")) as f:
  for line in f:
    raw = line.rstrip("\n").split("\t")[-1]
    classes[raw.replace("$", ".")] = raw
todo = {}
with open(os.path.join(out, "jadx.log"), errors="replace") as f:
  for m in re.finditer(r"in method: ([^\s(]+)\(", f.read()):
    # the method name is after the last dot; it may itself contain '$' (Kotlin internal)
    cls = m.group(1).rsplit(".", 1)[0].replace("$", ".")
    raw = classes.get(cls)
    if raw is None:
      continue
    top = raw.split("$")[0]
    if prefixes and "." not in prefixes \
        and not any(top.startswith(p.replace("/", ".").rstrip(".")) for p in prefixes):
      continue
    todo.setdefault(top, set()).add("%s=%s" % (m.group(1), raw))
for top in sorted(todo):
  print("%s\t%s" % (top, ";".join(sorted(todo[top]))))
EOF

total=$(wc -l < "$out/jadx-retry.todo")
if [ "$total" = 0 ]; then
  rm -f "$out/jadx-retry.todo"
  echo "jadx-retry: no failed methods in scope"
  exit 0
fi
mkdir -p "$out/jadx-retry"
{
  echo "# jadx retry: $name"
  echo "Classes with methods jadx could not structure, re-decompiled in 'simple' mode"
  echo "(linear code with gotos). Read the method in the listed file; if it is still"
  echo "marked as failed there, use the smali under apktool/."
  echo
} > "$out/jadx-retry/INDEX.txt"

# decompile one class in simple mode into jadx-retry/<class>/ (kept from earlier runs); prints the file
retry_class() {
  local d="$out/jadx-retry/$1"
  if [ ! -d "$d" ]; then
    timeout --kill-after=10 300 "$tools/jadx/bin/jadx" --log-level ERROR -m simple --single-class "$1" \
      --single-class-output "$d" "$apk" > "$d.log" 2>&1 || true
  fi
  find "$d" -name '*.java' 2>/dev/null | head -n 1
}
safe_name() { [[ "$1" =~ ^[A-Za-z0-9_\$][A-Za-z0-9_\$.-]*$ ]] && [[ "$1" != *..* ]]; }

n=0
while IFS=$'\t' read -r cls methods; do
  # the class name becomes a directory name: never let one from the APK leave jadx-retry/
  if ! safe_name "$cls"; then
    echo "- $cls [skipped: unusual class name]" >> "$out/jadx-retry/INDEX.txt"
    continue
  fi
  n=$((n + 1))
  if [ "$n" -gt "$max" ]; then
    echo "- (stopped after $max classes; raise JADX_RETRY_MAX or pass a class-prefix)" >> "$out/jadx-retry/INDEX.txt"
    break
  fi
  top_file=$(retry_class "$cls")
  for pair in ${methods//;/ }; do
    m=${pair%%=*}
    raw=${pair#*=}
    short=${m##*.}
    file=$top_file
    # jadx writes some inner classes (Kotlin lambdas it does not inline) as files of their
    # own: the outer class's file then lacks the method, which is not the same as fixed
    if [ "$raw" != "$cls" ] && { [ -z "$file" ] || ! grep -qF -- "$raw" "$file"; } \
        && { [ -z "$file" ] || ! grep -qE "(class|interface|enum) ${raw##*\$}\b" "$file"; }; then
      file=""
      if safe_name "$raw"; then
        file=$(retry_class "$raw")
      fi
    fi
    state="not produced (./cupella dex-disasm.py $name '$raw')"
    if [ -n "$file" ]; then
      if grep -qF -e "Method not decompiled: $m(" -e "in method: $m(" "$file" \
        || { dump=$(grep -A3 -F -- "Method dump skipped" "$file" || true)
             [ -n "$dump" ] && grep -qwF -- "$short" <<< "$dump"; }; then
        state="STILL FAILED in simple mode (./cupella dex-disasm.py $name '$raw')"
      else
        state="ok"
      fi
    fi
    echo "- $m -> ${file#$root/} [$state]" >> "$out/jadx-retry/INDEX.txt"
  done
done < "$out/jadx-retry.todo"
rm -f "$out/jadx-retry.todo"
echo "jadx-retry: $total classes; see work/$name/jadx-retry/INDEX.txt"
