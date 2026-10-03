#!/usr/bin/env python3
"""Collect what a report cites into a bundle that can be read without the sample.

A report's claims cite paths under work/<name>/, which is not published. This writes
work/_evidence/<name>/ with, for every citation cite-check.py can resolve:

  excerpts   <path>.excerpt.txt for a file cited with lines: the cited lines (marked >)
             with a few lines around them, line numbers as in the original, ranges of
             one file merged
  functions  the same for a cited native function (FUN_..., jni_...) or Dart function
             (Class::name): its body from the decompiled output
  whole      a text file cited without lines (triage.txt, manifest-summary.txt, ...),
             copied whole when it is small enough
  INDEX.md   every citation in report order: report line, citation, where it is in the
             bundle, or why it is not (unresolved, binary, too large)

Only text is copied, never a dex, a native library, an APK, or another binary. The
excerpts are verbatim text from the sample: untrusted data, and they can hold secrets
or indicators that the report redacts. Review the bundle before publishing it.

Usage: ./cupella evidence-bundle.py <name> [--context N] [--max-kb N]
       --context  lines around each cited range (default 3)
       --max-kb   largest file copied whole (default 256)
Output: work/_evidence/<name>/ (replaced on each run); a summary on stdout.
"""
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TEXT_EXT = (".java", ".kt", ".xml", ".txt", ".c", ".dart", ".smali", ".json", ".js", ".html", ".properties",
            ".yml", ".yaml", ".cfg", ".md", ".tsv", ".log")


def is_text(path):
  with open(path, "rb") as f:
    head = f.read(4096)
  return b"\0" not in head


def main():
  args = sys.argv[1:]
  context, max_kb = 3, 256
  for flag in ("--context", "--max-kb"):
    if flag in args:
      i = args.index(flag)
      val = int(args[i + 1])
      del args[i:i + 2]
      if flag == "--context":
        context = val
      else:
        max_kb = val
  if len(args) != 1:
    sys.exit(__doc__)
  name = args[0]
  work = os.path.join(ROOT, "work", name)
  rpath = os.path.join(ROOT, "reports", name + ".md")
  if not os.path.exists(rpath):
    sys.exit("reports/%s.md not found" % name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found: rerun ./cupella unpack.sh first" % name)
  with open(rpath, errors="replace") as f:
    report = f.read()
  cc = units.load_script("cite-check.py")
  tree = cc.Tree(work)
  others = units.dart_units(work, name) + units.native_units(work)
  native = {}
  for u in others:
    if u.kind == "native":
      native.setdefault(u.name, []).append(u)
  dart = {u.id[5:]: u for u in others if u.kind == "dart"}

  dart_sources = set()
  fs = os.path.join(work, "flutter-summary.txt")
  if os.path.exists(fs):
    with open(fs, errors="replace") as f:
      dart_sources = set(re.findall(r"[\w$./-]+\.dart\b", f.read()))

  def lineno(pos):
    return report.count("\n", 0, pos) + 1

  def bundle_path(rel):
    """a path under work/<name>/ (children as ../<name>.dec1/...) -> its place in the bundle"""
    if rel.startswith("../"):
      top, _, rest = rel[3:].partition("/")
      short = top[len(name):] if top.startswith(name + ".") else top
      return os.path.join(short, rest)
    return rel

  wanted = {}   # rel -> [(first line, last line)] cited
  whole = {}    # rel -> report lines citing the file without lines
  index = []    # (report line, citation, [(rel, a, b)] or None, note)

  # files and lines, as cite-check.py reads them
  for span in re.finditer(r"`([^`\n]+)`", report):
    text = span.group(1)
    if "://" in text or text.startswith("/") or "*" in text:
      continue
    for m in cc.CITE.finditer(text):
      path, spec = m.group(1), m.group(2)
      if path.startswith("/") or "%" in path:
        continue
      rels = tree.resolve(path)
      ln = lineno(span.start())
      if not rels and path.endswith(".dart") and any(d == path or d.endswith("/" + path) for d in dart_sources):
        index.append((ln, path + spec, None, "a Dart source name from the snapshot (flutter-summary.txt); "
                      "blutter merges sources, so there is no file of that name"))
        continue
      if not rels:
        if "/" in path or spec or path.endswith((".java", ".c", ".dart", ".smali")):
          index.append((ln, path + spec, None, "unresolved: no such file under work/%s/" % name))
        continue
      if spec:
        rs = cc.ranges(spec)
        fits = [r for r in rels if all(1 <= a <= b <= len(tree.lines(r)) for a, b in rs)]
        if not fits:
          index.append((ln, path + spec, None, "unresolved: lines outside the file"))
          continue
        for r in fits:
          wanted.setdefault(r, []).extend(rs)
        index.append((ln, path + spec, [(r, a, b) for r in fits for a, b in rs], ""))
      else:
        for r in rels:
          whole.setdefault(r, []).append(ln)
        index.append((ln, path, [(r, 0, 0) for r in rels], ""))

  # native and Dart functions: their bodies
  for m in re.finditer(r"\b(FUN_[0-9a-f]{6,16}|jni_\w+|JNI_OnLoad)\b", report):
    us = native.get(m.group(1), [])
    if us:
      for u in us:
        wanted.setdefault(u.file, []).append((u.start, u.end))
      index.append((lineno(m.start()), m.group(1), [(u.file, u.start, u.end) for u in us], "native function"))
    else:
      index.append((lineno(m.start()), m.group(1), None, "unresolved: no such function in native/"))
  for span in re.finditer(r"`([^`\n]+)`", report):
    for q in re.findall(r"(?<![\w:])([A-Z][\w$]*::[A-Za-z_$][\w$<>]*)", span.group(1)):
      u = dart.get(q)
      if u and tree.lines(u.file):
        # blutter output: the function starts at its line; its body is that many lines long
        end = min(len(tree.lines(u.file)), u.start + max(len(u.lines), 1) - 1)
        wanted.setdefault(u.file, []).append((u.start, end))
        index.append((lineno(span.start()), q, [(u.file, u.start, end)], "Dart function"))

  out = os.path.join(ROOT, "work", "_evidence", name)
  shutil.rmtree(out, ignore_errors=True)
  os.makedirs(out)
  written, skipped = {}, {}

  # excerpts
  for rel, rs in sorted(wanted.items()):
    lines = tree.lines(rel)
    full = os.path.join(work, rel)
    if not lines or not is_text(full):
      skipped[rel] = "binary or unreadable"
      continue
    cited = set()
    for a, b in rs:
      cited.update(range(a, b + 1))
    show = set()
    for a, b in rs:
      show.update(range(max(1, a - context), min(len(lines), b + context) + 1))
    dest = os.path.join(out, bundle_path(rel) + ".excerpt.txt")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
      f.write("# %s\n# %d of %d lines; lines the report cites are marked >\n" % (
        os.path.normpath(os.path.join("work", name, rel)), len(show), len(lines)))
      prev = 0
      for n in sorted(show):
        if n != prev + 1:
          f.write("...\n")
        f.write("%s%6d  %s\n" % (">" if n in cited else " ", n, lines[n - 1]))
        prev = n
      if prev < len(lines):
        f.write("...\n")
    written[rel] = os.path.relpath(dest, out)

  # files cited without lines
  for rel in sorted(whole):
    if rel in written:
      continue
    full = os.path.join(work, rel)
    size = os.path.getsize(full)
    if not rel.endswith(TEXT_EXT) or not is_text(full):
      skipped[rel] = "binary: not copied"
    elif size > max_kb * 1024:
      skipped[rel] = "%d KB: larger than --max-kb %d, not copied" % (size // 1024, max_kb)
    else:
      dest = os.path.join(out, bundle_path(rel))
      os.makedirs(os.path.dirname(dest), exist_ok=True)
      shutil.copyfile(full, dest)
      written[rel] = os.path.relpath(dest, out)

  # index
  resolved = sum(1 for _l, _c, places, _n in index if places and any(r in written for r, _a, _b in places))
  with open(os.path.join(out, "INDEX.md"), "w") as f:
    f.write("# Evidence for reports/%s.md\n\n" % name)
    f.write("Made by `./cupella evidence-bundle.py %s` from `work/%s/`. Each row is a citation in the\n" % (name, name))
    f.write("report; the bundle file holds the cited lines (marked `>`) with %d lines around them, or the\n" % context)
    f.write("whole file when the report cites no line. Excerpts are verbatim text from the sample:\n")
    f.write("untrusted data. They can hold values the report redacts.\n\n")
    f.write("%d citations, %d in the bundle, %d not.\n\n" % (len(index), resolved, len(index) - resolved))
    f.write("| Report line | Citation | In the bundle |\n|---|---|---|\n")
    for ln, cite, places, note in index:
      if not places:
        where = note
      else:
        parts = []
        for r, a, b in dict.fromkeys(places):
          if r in written:
            parts.append("`%s`%s" % (written[r], " lines %d-%d" % (a, b) if a else ""))
          else:
            parts.append("not included (%s): `%s`" % (skipped.get(r, "not copied"), r))
        where = "; ".join(parts) + (" (%s)" % note if note else "")
      f.write("| %d | `%s` | %s |\n" % (ln, cite.replace("|", "\\|"), where.replace("|", "\\|")))
  size = sum(os.path.getsize(os.path.join(dp, fn)) for dp, _dn, fns in os.walk(out) for fn in fns)
  print("wrote work/_evidence/%s/: %d files, %d KB; %d citations, %d in the bundle, %d not" % (
    name, len(set(written.values())) + 1, size // 1024, len(index), resolved, len(index) - resolved))
  for r, why in sorted(skipped.items()):
    print("  not included: %s (%s)" % (r, why))
  for ln, cite, places, note in index:
    if not places and note.startswith("unresolved"):
      print("  report line %d: %s: %s" % (ln, cite, note))


if __name__ == "__main__":
  main()
