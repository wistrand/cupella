#!/usr/bin/env python3
"""Match a sample's strings against published family markers (scripts/family-markers.tsv).

Strings come from the dex string pool (dex/strings.txt), decrypted string calls
(jadx-strings/), and the decryption stage's string table (decrypt/out/strings.txt) of
the sample and, for a child sample work/<name>.dec<k>/ or .emb<k>/, of its parent. Each
match names the family, what matched, and the public source. A match is a lead to read
up on, not an attribution: markers can be shared by kits, leaks, and copies.

Usage: ./cupella family-markers.py <name>
Output: stdout (a section for scan.txt)
"""
import glob
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TABLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "family-markers.tsv")
ANN = re.compile(r'/\* = "((?:[^"\\]|\\.)*)"')


def strings(name):
  works = [os.path.join(ROOT, "work", name)]
  m = re.match(r"(.+)\.(?:dec|emb)\d+$", name)
  if m:
    works.append(os.path.join(ROOT, "work", m.group(1)))
  out = set()
  for w in works:
    p = os.path.join(w, "dex", "strings.txt")
    if os.path.isfile(p):
      with open(p, errors="replace") as f:
        out.update(l.rstrip("\n").split("\t", 1)[-1] for l in f)
    for p in glob.glob(os.path.join(w, "jadx-strings", "**", "*.java"), recursive=True):
      with open(p, errors="replace") as f:
        out.update(m.group(1).replace('\\"', '"') for m in ANN.finditer(f.read()))
    p = os.path.join(w, "decrypt", "out", "strings.txt")
    if os.path.isfile(p):
      with open(p, errors="replace") as f:
        out.update(l.rstrip("\n").split("\t", 1)[-1] for l in f if "\t" in l)
  return out


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  have = strings(sys.argv[1])
  text = "\n".join(have)
  hits = []
  with open(TABLE) as f:
    for line in f:
      if not line.strip() or line.startswith("#"):
        continue
      fam, kind, pat, mn, src = line.rstrip("\n").split("\t")
      if kind == "regex":
        m = re.search(pat, text)
        if m:
          hits.append((fam, "string %r" % m.group(0), src))
      elif kind == "strings":
        want = [w for w in pat.split(",") if w]
        got = [w for w in want if w in have]
        if len(got) >= int(mn):
          hits.append((fam, "%d of %d listed strings: %s" % (len(got), len(want), ", ".join(got)), src))
  print("\n## Known family markers (scripts/family-markers.tsv; leads to published reports, not attribution)")
  if not hits:
    print("(none of %d strings matched)" % len(have))
  for fam, what, src in hits:
    print("- %s: %s; source %s" % (fam, what, src))


if __name__ == "__main__":
  main()
