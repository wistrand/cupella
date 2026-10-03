#!/usr/bin/env bash
# Benchmark gate for proposed rule changes (scan patterns, scope, lead scripts).
# Run it as `./cupella gate`; it runs on the host and calls ./cupella for every step.
#
#   ./cupella gate baseline   rescan everything, run the scripted benchmarks, store the
#                             numbers in bench/gate-baseline.txt
#   ./cupella gate            rescan, rerun, and compare with the baseline: PASS when no
#                        coverage number dropped and no benign lead rate rose by more
#                        than one app (4 points of 25); FAIL lists what moved
#
# Benchmarks: Ghera pairs (fix-eval.py), MalEval behavior signals (bench-maleval.py),
# the analyzed apps' reports (lead-eval.py, cite-check.py). Datasets and procedure:
# agent_docs/benchmarks.md. Takes a few minutes; everything runs through ./cupella.
set -euo pipefail

# the checkout: this file is host/gate.sh in it; the benchmark data is the checkout's own
root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
cd "$root"
unset CUPELLA_WORKSPACE
mode=${1:-check}
out="$root/work/_gate"
mkdir -p "$out"
jobs=${GATE_JOBS:-4}

rescan() {
  # Ghera pairs, MalEval samples (scan.sh also rescans embedded payloads), analyzed apps
  ls -d work/*-Lean-benign work/*-Lean-secure 2>/dev/null | xargs -r -n1 basename > "$out/names.txt"
  if [ -d data/maleval ]; then
    find data/maleval -name '*.apk' -printf '%f\n' | sed 's/\.apk$//' >> "$out/names.txt"
  fi
  xargs -P "$jobs" -I{} sh -c './cupella scan.sh {} > /dev/null 2>&1 || ./cupella scan.sh {} > /dev/null 2>&1 || echo "scan failed: {}"' < "$out/names.txt"
  for r in reports/*.md; do
    n=$(basename "$r" .md)
    [ -d "work/$n" ] || continue
    if grep -q '^scope: \. ' "work/$n/scan.txt" 2>/dev/null; then
      ./cupella scan.sh "$n" . > /dev/null 2>&1 || ./cupella scan.sh "$n" . > /dev/null 2>&1 || echo "scan failed: $n"
    else
      ./cupella scan.sh "$n" > /dev/null 2>&1 || ./cupella scan.sh "$n" > /dev/null 2>&1 || echo "scan failed: $n"
    fi
  done
}

measure() { # writes metric<TAB>value lines
  ./cupella fix-eval.py --suffix -benign -secure > "$out/fix-eval.txt" 2>&1 || true
  ./cupella bench-maleval.py > "$out/bench-maleval.txt" 2>&1 || true
  : > "$out/lead-eval.txt"
  for r in reports/*.md; do
    n=$(basename "$r" .md)
    [ -d "work/$n" ] || continue
    { echo "## $n"; ./cupella lead-eval.py "$n" 2>&1 | grep 'covers' || true
      ./cupella cite-check.py "$n" 2>&1 | sed -n 2p || true; } >> "$out/lead-eval.txt"
  done
  python3 - "$out" <<'EOF'
import re, sys
out = sys.argv[1]
m = {}
t = open(out + "/fix-eval.txt").read()
for src, n in re.findall(r"^\s+(\S+\.txt|either source)\s+points at a changed method in (\d+)", t, re.M):
  m["ghera %s hits" % src] = int(n)
for n in re.findall(r"^\s+either source\s+(\d+)", t, re.M):
  m["ghera either source"] = int(n)
r = re.search(r"reflects the change in (\d+)", t)
if r: m["ghera manifest fixes reflected"] = int(r.group(1))
t = open(out + "/bench-maleval.txt").read()
for line in t.split("\n"):
  p = re.match(r"^(\S.{0,21}?)\s{2,}(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+) /\s+(\S+) /\s+(\S+) of", line)
  if p:
    b = p.group(1).strip()
    for k, v in (("code", 3), ("decl", 4), ("either", 5), ("flow", 6)):
      if p.group(v) not in ("-",):
        m["maleval %s %s" % (b, k)] = int(p.group(v).rstrip("%"))
    for k, v in (("benign code", 7), ("benign decl", 8), ("benign flow", 9)):
      if p.group(v) not in ("-",):
        m["maleval %s %s" % (b, k)] = int(p.group(v).rstrip("%"))
cur = None
for line in open(out + "/lead-eval.txt"):
  if line.startswith("## "):
    cur = line[3:].strip()
  r = re.match(r"^(\S.*?)\s+covers (\d+) of (\d+)", line)
  if r and cur:
    m["report %s %s covers" % (cur, r.group(1).strip())] = int(r.group(2))
  r = re.match(r"^\d+ citations checked and found; (\d+) problems", line)
  if r and cur:
    m["report %s citation problems" % cur] = -int(r.group(1))
with open(out + "/metrics.txt", "w") as f:
  for k in sorted(m):
    f.write("%s\t%d\n" % (k, m[k]))
EOF
}

echo "== rescanning (this takes a few minutes)"
rescan
echo "== measuring"
measure
if [ "$mode" = baseline ]; then
  mkdir -p bench
  cp "$out/metrics.txt" bench/gate-baseline.txt
  echo "baseline stored: bench/gate-baseline.txt ($(wc -l < bench/gate-baseline.txt) metrics)"
  exit 0
fi
[ -f bench/gate-baseline.txt ] || { echo "no baseline: run ./cupella gate baseline first" >&2; exit 2; }
python3 - bench/gate-baseline.txt "$out/metrics.txt" <<'EOF'
import sys
base = dict((l.split("\t")[0], int(l.split("\t")[1])) for l in open(sys.argv[1]) if "\t" in l)
cur = dict((l.split("\t")[0], int(l.split("\t")[1])) for l in open(sys.argv[2]) if "\t" in l)
fail, better = [], []
for k, b in sorted(base.items()):
  c = cur.get(k)
  if c is None:
    fail.append("%s: missing (was %d)" % (k, b)); continue
  if " benign " in k:
    if c > b + 4: fail.append("%s: %d -> %d (benign lead rate rose)" % (k, b, c))
    elif c < b: better.append("%s: %d -> %d" % (k, b, c))
  else:
    if c < b: fail.append("%s: %d -> %d" % (k, b, c))
    elif c > b: better.append("%s: %d -> %d" % (k, b, c))
for k in sorted(set(cur) - set(base)):
  better.append("%s: new metric %d" % (k, cur[k]))
print("improved:" if better else "improved: none")
for x in better: print("  " + x)
if fail:
  print("FAIL:")
  for x in fail: print("  " + x)
  sys.exit(1)
print("PASS (%d metrics, none worse)" % len(base))
EOF
