#!/usr/bin/env python3
"""Check that the evidence a report cites exists in work/<name>/.

Reads reports/<name>.md and checks, in backticked spans:

  files     a cited path (full or partial, e.g. `util/Foo.java`) names a file under
            work/<name>/; a partial path must match the end of exactly one or more
            real paths; a full `work/...` path into a child sample (work/<name>.dec1/)
            or a related sample must exist as given; `.dec1/...` and `.emb1/...` are
            short for work/<name>.dec1/... and work/<name>.emb1/...
  lines     `Foo.java:120-130` lies within the file (lines start at 1; a partial path
            that matches several files must fit all of them, or it is ambiguous)
  methods   `Cls.meth` (or `meth()`) directly followed by a line citation of Cls.java,
            as in "`Foo.bar` (`Foo.java:120`)": the cited line lies inside a method
            of that name
  quotes    "quoted text" directly followed by a line citation: the text occurs on
            the cited lines (give or take one line); up to 80 characters its first and
            last 40 must, beyond that all of it
  functions native (FUN_..., jni_..., JNI_OnLoad) and Dart (`Class::name`) function
            names exist in the decompiled output (a native name with no native/
            output is a problem)

Device paths (/data/..., /system/...), URLs, globs, and library names (.so) are not
checked. A .dart path that is not a file passes when flutter-summary.txt lists it as
that path or a path ending in /<cited> (blutter merges Dart sources into one file per
package); with a :line it is a problem, since the line cannot be checked.
A problem is a citation to fix or to explain; "ok" means the cited place exists, not
that it says what the report claims.

Usage: ./cupella cite-check.py <name>          needs reports/<name>.md
Exit status 1 when a problem was found.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
EXT = r"(?:java|kt|xml|txt|c|dart|smali|json|js|html|properties|yml|yaml|cfg|md|tsv|log)"
CITE = re.compile(r"(?<![\w/.:-])((?:[\w$.-]+/)*[\w$.-]+\." + EXT + r")((?::\d+(?:-\d+)?(?:,\s?\d+(?:-\d+)?)*)?)(?![\w/])")


class Tree:
  def __init__(self, work):
    self.work = work
    self.by_base = {}
    # the sample and its child samples (decrypted and embedded payloads, work/<name>.dec<k>/
    # and work/<name>.emb<k>/), whose files report short paths may cite
    parent = os.path.dirname(work)
    child = re.compile(re.escape(os.path.basename(work)) + r"(?:\.(?:dec|emb)\d+)+$")
    roots = [work] + sorted(os.path.join(parent, d) for d in os.listdir(parent)
                            if child.match(d) and os.path.isdir(os.path.join(parent, d)))
    for root in roots:
      for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if not d.startswith("."))
        for f in fn:
          rel = os.path.relpath(os.path.join(dp, f), work)
          self.by_base.setdefault(f, []).append(rel)
    self._lines = {}

  def resolve(self, cited):
    # `.dec2/...` and `.emb1/...` are short for work/<name>.dec2/... (a child sample)
    if re.match(r"\.(?:dec|emb)\d+/", cited):
      cited = "work/%s%s" % (os.path.basename(self.work), cited)
    # a full path into work/ (a child sample such as work/<name>.dec1/, or a related
    # sample): check it exists as given
    if cited.startswith("work/") and not cited.startswith("work/%s/" % os.path.basename(self.work)):
      full = os.path.join(os.path.dirname(self.work), cited[len("work/"):])
      return [os.path.relpath(full, self.work)] if os.path.isfile(full) else []
    c = cited
    for prefix in ("work/%s/" % os.path.basename(self.work), "./"):
      if c.startswith(prefix):
        c = c[len(prefix):]
    cands = self.by_base.get(os.path.basename(c), [])
    own = [r for r in cands if (r == c or r.endswith("/" + c)) and not r.startswith("..")]
    return own or [r for r in cands if r.endswith("/" + c) or r == c]

  def lines(self, rel):
    if rel not in self._lines and not os.path.isfile(os.path.join(self.work, rel)):
      return []
    if rel not in self._lines:
      with open(os.path.join(self.work, rel), errors="replace", newline="") as f:  # lines on \n only
        lines = f.read().split("\n")
      if lines and lines[-1] == "":
        lines.pop()  # the file ends with a newline: no line after it
      self._lines[rel] = lines
    return self._lines[rel]


def ranges(spec):
  return [(int(a), int(b or a)) for a, b in re.findall(r"(\d+)(?:-(\d+))?", spec)]


def norm(s):
  return re.sub(r"\s+", " ", s.replace("\\'", "'").replace('\\"', '"')).strip().lower()


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  work = os.path.join(ROOT, "work", name)
  rpath = os.path.join(ROOT, "reports", name + ".md")
  if not os.path.exists(rpath):
    sys.exit("reports/%s.md not found" % name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found: rerun ./cupella unpack.sh first" % name)
  with open(rpath, errors="replace") as f:
    report = f.read()
  tree = Tree(work)
  others = units.dart_units(work, name) + units.native_units(work)
  native_names = {u.name for u in others if u.kind == "native"}
  dart_quals = {u.id[5:] for u in others if u.kind == "dart"}
  has_native = any(u.kind == "native" for u in others)
  has_dart = any(u.kind == "dart" for u in others)

  dart_sources = set()
  fs = os.path.join(work, "flutter-summary.txt")
  if os.path.exists(fs):
    with open(fs, errors="replace") as f:
      dart_sources = set(re.findall(r"[\w$./-]+\.dart\b", f.read()))

  def dart_listed(path):
    return any(d == path or d.endswith("/" + path) for d in dart_sources)

  problems, ok = [], 0

  def lineno(pos):
    return report.count("\n", 0, pos) + 1

  def problem(pos, cite, msg):
    problems.append((lineno(pos), cite, msg))

  # files and lines
  for span in re.finditer(r"`([^`\n]+)`", report):
    text = span.group(1)
    if "://" in text or text.startswith("/") or "*" in text:
      continue
    for m in CITE.finditer(text):
      path, spec = m.group(1), m.group(2)
      if path.startswith("/") or "%" in path:
        continue
      rels = tree.resolve(path)
      if not rels and path.endswith(".dart") and dart_listed(path):
        if spec:  # the listing has names only; a line in it cannot be checked
          problem(span.start(), path + spec, "line unverifiable: Dart source is listed in "
                  "flutter-summary.txt but has no file under work/%s/; cite the blutter file" % name)
        else:
          ok += 1  # a Dart source file name from the snapshot; blutter merges files
        continue
      if not rels:
        # in renamed code a bare `g.c` is Class.method, not a C file: a call (`g.c(`), or the
        # method of a method citation (`g.c` (`pkg/g.java:133`))
        if "/" not in path and not spec and (text[m.end():m.end() + 1] == "(" or re.match(
            r"\s*\(`(?:[\w$.-]+/)*%s\.java:" % re.escape(path.rsplit(".", 1)[0]), report[span.end():])):
          continue
        if "/" in path or spec or path.endswith((".java", ".c", ".dart", ".smali")):
          problem(span.start(), path + spec, "no such file under work/%s/" % name)
        continue
      if spec:
        rs = ranges(spec)
        wrong = [(a, b) for a, b in rs if a < 1 or a > b]
        if wrong:
          problem(span.start(), path + spec, "invalid line range %d-%d" % wrong[0])
          continue
        fits = [r for r in rels if all(b <= len(tree.lines(r)) for _a, b in rs)]
        if not fits:
          bad = [(a, b) for a, b in rs if not any(b <= len(tree.lines(r)) for r in rels)] or rs
          problem(span.start(), path + spec, "line %d beyond end of file (%d lines)" % (
            bad[0][1], max(len(tree.lines(r)) for r in rels)))
          continue
        if len(fits) < len(rels):
          problem(span.start(), path + spec, "ambiguous: %d files match and the lines fit only "
                  "%s; cite a longer path" % (len(rels), ", ".join(fits[:3])))
          continue
      ok += 1

  # `Cls.meth` (`Cls.java:N`) and `meth()` (`.../Cls.java:N`)
  pat = re.compile(r"`(?:([A-Za-z_$][\w$]*)\.)?([A-Za-z_$][\w$]*)(?:\([^`]*\))?`\s*\(`((?:[\w$.-]+/)*([\w$]+)\.java):([\d,\s-]+)`")
  for m in pat.finditer(report):
    cls, meth, path, fcls, spec = m.groups()
    if cls and cls != fcls:
      continue
    if not cls and not m.group(0).split("`")[1].endswith(")"):
      continue
    rels = tree.resolve(path)
    if not rels:
      continue
    us = [u for r in rels if r.startswith("jadx/sources/") for u in units._java_file_units(
      os.path.join(work, r), r[len("jadx/sources/"):])]
    named = [u for u in us if u.name == meth]
    if not named:
      if us:
        problem(m.start(), m.group(0), "no method %s in %s" % (meth, path))
      continue
    for a, b in ranges(spec):
      if not any(u.start <= a and b <= u.end for u in named):
        inside = [u.name for u in us if u.start <= a <= u.end]
        problem(m.start(), m.group(0), "line %d is not inside %s%s" % (
          a, meth, " (it is in %s)" % inside[0] if inside else ""))
        break
    else:
      ok += 1

  # "quoted text" (`file:N`)
  for m in re.finditer(r"\"([^\"]{6,300})\"\s*\(`([^`]+?):([\d,\s-]+)`", report):
    quote, path, spec = m.groups()
    rels = tree.resolve(path)
    if not rels:
      continue
    q = norm(quote)
    heads = {q[:40], q[-40:]} if len(q) <= 80 else {q}
    found = False
    for r in rels:
      lines = tree.lines(r)
      for a, b in ranges(spec):
        chunk = norm(" ".join(lines[max(0, a - 2):b + 1]))
        if all(h in chunk or h.replace("'", "\\'") in chunk for h in heads):
          found = True
    if found:
      ok += 1
    else:
      problem(m.start(), '"%s" (%s:%s)' % (quote[:50], path, spec.strip()), "quoted text not on the cited lines")

  # native and Dart function names
  for m in re.finditer(r"\b(FUN_[0-9a-f]{6,16}|jni_\w+|JNI_OnLoad)\b", report):
    if not has_native:
      problem(m.start(), m.group(1), "cites native function but no native/ output in work/%s/" % name)
    elif m.group(1) in native_names:
      ok += 1
    else:
      problem(m.start(), m.group(1), "no such function in work/%s/native/" % name)
  for span in re.finditer(r"`([^`\n]+)`", report):
    for q in re.findall(r"(?<![\w:])([A-Z][\w$]*::[A-Za-z_$][\w$<>]*)", span.group(1)):
      if not has_dart:
        break
      if q in dart_quals:
        ok += 1
      elif not any(d.startswith(q.split("::")[0] + "::") for d in dart_quals):
        continue  # a class outside the app package (a library), not checked
      else:
        problem(span.start(), q, "no such Dart function in the app package")

  seen = set()
  print("# Citation check: reports/%s.md" % name)
  print("%d citations checked and found; %d problems" % (ok, len(problems)))
  for ln, cite, msg in sorted(problems):
    if (ln, cite) in seen:
      continue
    seen.add((ln, cite))
    print("report line %d: %s: %s" % (ln, cite, msg))
  sys.exit(1 if problems else 0)


if __name__ == "__main__":
  main()
