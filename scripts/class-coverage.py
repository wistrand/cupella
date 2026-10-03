#!/usr/bin/env python3
"""Which classes the decompiled tree is missing, which are defined twice, and which have
names built to break tools or mislead readers.

  missing    outer classes with methods in the dex files and no file in jadx/sources/ (jadx dropped
             them: a crash, a name the file system rejects, a timeout); checked against
             jadx's own notes, so renamed classes and classes it inlined as anonymous
             classes are not counted
  duplicates classes defined in more than one dex file; Android loads the one in the
             first file in order (classes.dex, classes2.dex, ...), and other tools may show
             another; the loaded copy is named
  names      class names over 200 characters (path limits make tools drop them) or with
             bidirectional-override or invisible characters (the shown name is not the
             real one)

Usage: ./cupella class-coverage.py <name>
Output: stdout (a section for triage.txt)
"""
import glob
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dex  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SHOW = 12
TRICKY = re.compile("[‪-‮⁦-⁩​-‏⁠﻿]")
# jadx notes a class it renamed ("renamed from") and a class it inlined into another as
# an anonymous class ("// from class:"); both count as produced
NOTES = re.compile(r"JADX INFO: renamed from: ([\w$.\-]+)|// from class: ([\w$.\-]+)")


def dex_order(path):
  m = re.match(r"classes(\d*)\.dex$", os.path.basename(path))
  return int(m.group(1) or 1) if m else 10 ** 6


def produced(src):
  """original dotted names of the outer classes jadx wrote"""
  names = set()
  for p in glob.glob(os.path.join(src, "**", "*.java"), recursive=True):
    rel = os.path.relpath(p, src)[:-5]
    parts = rel.split(os.sep)
    if parts[0] == "defpackage":
      parts = parts[1:]
    names.add(".".join(parts))
    names.add(".".join(re.sub(r"^p\d{3}", "", x) for x in parts))  # jadx's package renames
    try:
      with open(p, errors="replace") as f:
        text = f.read()
    except OSError:
      continue
    for a, b in NOTES.findall(text):
      names.add(a or b)
  return names


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  work = os.path.join(ROOT, "work", sys.argv[1])
  defs = {}  # dotted name -> [dex file, ...] in load order
  has_methods = set()
  for p in sorted(glob.glob(os.path.join(work, "raw", "classes*.dex")), key=dex_order):
    buf = open(p, "rb").read()
    if buf[:4] != b"dex\n":
      continue
    try:
      d = dex.Dex(buf)
      for desc, data, _s, _i in d.classes():
        if desc.startswith("L") and desc.endswith(";"):
          n = desc[1:-1].replace("/", ".")
          defs.setdefault(n, []).append(os.path.basename(p))
          if next(d.methods_of(data), None) is not None:
            has_methods.add(n)
    except (struct.error, IndexError, ValueError):
      continue
  print("## Class coverage (dex vs. jadx; scripts/class-coverage.py)")
  if not defs:
    print("no dex classes read")
    return
  dups = {n: f for n, f in defs.items() if len(f) > 1}
  long_names = [n for n in defs if len(n) > 200]
  tricky = [n for n in defs if TRICKY.search(n)]
  src = os.path.join(work, "jadx", "sources")
  missing = []
  if os.path.isdir(src):
    have = produced(src)
    # classes without methods (marker interfaces, R8 leftovers) are often not written and
    # hold nothing to read
    outer = {n for n in defs if "$" not in n.rsplit(".", 1)[-1] and n in has_methods}
    missing = sorted(n for n in outer if n not in have and n.rsplit(".", 1)[-1] not in have
                     and not re.match(r"R(\$|$)", n.rsplit(".", 1)[-1]))
    print("%d classes in %d dex files; %d outer classes with methods; %d have no file in jadx/sources/ (dropped, or renamed without a note)" % (
      len(defs), len({f for v in defs.values() for f in v}), len(outer), len(missing)))
    for n in missing[:SHOW]:
      print("- missing: %s%s" % (n, " (name %d chars)" % len(n) if len(n) > 200 else ""))
    if len(missing) > SHOW:
      print("- ... %d more; read them with ./cupella dex-disasm.py %s <Class>" % (len(missing) - SHOW, sys.argv[1]))
  else:
    print("%d classes; no jadx output to compare" % len(defs))
  if dups:
    print("%d classes defined in more than one dex file (Android loads the first; another tool may show a different copy):" % len(dups))
    for n, f in sorted(dups.items())[:SHOW]:
      print("- %s: %s (loaded: %s)" % (n, ", ".join(f), f[0]))
  if long_names:
    print("%d class names over 200 characters (file name limits make tools drop them), e.g. %s..." % (
      len(long_names), long_names[0][:80]))
  if tricky:
    print("%d class names with bidirectional-override or invisible characters (the displayed name is not the real one):" % len(tricky))
    for n in tricky[:SHOW]:
      print("- %r" % n)


if __name__ == "__main__":
  main()
