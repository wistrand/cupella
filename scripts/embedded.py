#!/usr/bin/env python3
"""Find code shipped inside an APK besides its own classes*.dex, by content, not name.

Second stages and plugin payloads are often stored in assets/ or res/raw/ under
misleading names (a dex archive called slogan.jpeg, MT_Bin, systemdata). Encrypted
payloads look like random data and are not code yet; this finds the ones stored in
the clear: dex files, and ZIP archives (apk, jar) that contain dex.

Usage: scripts/embedded.py <name>
  Prints one line per container: kind, size, path under work/<name>/raw/, and
  "disguised" when the extension does not say what it is. unpack.sh decompiles each
  into work/<name>/embedded/<path>/ and writes the list to embedded.txt.
"""
import os
import sys
import zipfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def kind_of(path):
  try:
    with open(path, "rb") as f:
      head = f.read(8)
  except OSError:
    return None
  if head[:4] == b"dex\n":
    return "dex"
  if head[:4] == b"PK\x03\x04":
    try:
      with zipfile.ZipFile(path) as z:
        if any(n.endswith(".dex") for n in z.namelist()):
          return "zip with dex"
    except (zipfile.BadZipFile, OSError, ValueError):
      return None
  return None


def find(work):
  raw = os.path.join(work, "raw")
  out = []
  for dp, dn, fn in os.walk(raw):
    dn.sort()
    for f in sorted(fn):
      p = os.path.join(dp, f)
      rel = os.path.relpath(p, raw)
      if "/" not in rel and rel.startswith("classes") and rel.endswith(".dex"):
        continue
      k = kind_of(p)
      if k:
        ext = os.path.splitext(f)[1].lower()
        disguised = not ((k == "dex" and ext in (".dex", ".odex")) or
                         (k != "dex" and ext in (".apk", ".jar", ".zip", ".aar")))
        out.append((rel, k, os.path.getsize(p), disguised))
  return out


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  for rel, k, size, disguised in find(os.path.join(ROOT, "work", sys.argv[1])):
    print("%s\t%d\t%s%s" % (k, size, rel, "\tdisguised" if disguised else ""))


if __name__ == "__main__":
  main()
