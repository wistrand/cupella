#!/usr/bin/env python3
"""Score the lead files of an analyzed APK against what its report concluded.

The report's Findings name the code they rest on (Java files and lines, methods,
native and Dart functions). Those functions are the answer key. For each lead
source (scan.txt, structure-leads.txt, flows.txt, quark-leads.txt, model-leads.txt) this script checks
which findings the source pointed at, and how far down its list the first pointer was.

  covered   a lead names a function cited by the finding (or, for a finding that
            cites only a file, any function in that file)
  rank      position of that first lead among the source's distinct functions (for
            structure-leads.txt the functions named in a line's call chains count too,
            right after the line's own function; a chain entry counts only when it
            names one file's function: Class.method that several files have does not)
  relevant  share of a source's distinct functions that the report cites anywhere

This measures lead sources against past analyses, so it is biased toward whatever
was found: a function the analyst never read cannot count. Use it to compare
sources and to check that a change to a lead script does not lose findings.

Usage: ./cupella lead-eval.py [-v] <name> [java-scope ...]     needs reports/<name>.md
       -v lists each finding's cited functions
Output: stdout (redirect to work/<name>/lead-eval.txt if wanted)
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCES = ("scan.txt", "structure-leads.txt", "flows.txt", "quark-leads.txt", "model-leads.txt")


class Index:
  """Functions of the decompiled output, loaded on demand per Java file."""

  def __init__(self, work, name, scopes):
    self.work = work
    self.base = os.path.join(work, "jadx", "sources")
    self.java = {}  # rel path under jadx/sources -> units
    self.by_base = {}
    if os.path.isdir(self.base):
      for dp, _dn, fn in os.walk(self.base):
        for f in fn:
          if f.endswith(".java"):
            rel = os.path.relpath(os.path.join(dp, f), self.base)
            self.by_base.setdefault(f, []).append(rel)
    self.other = units.dart_units(work, name) + units.native_units(work)
    self.scoped = units.java_units(work, scopes)
    for u in self.scoped:
      self.java.setdefault(u.file[len("jadx/sources/"):], []).append(u)

  def java_file(self, rel):
    if rel not in self.java:
      path = os.path.join(self.base, rel)
      self.java[rel] = units._java_file_units(path, rel) if os.path.exists(path) else []
    return self.java[rel]

  def resolve_file(self, cited):
    """A cited path (possibly partial, e.g. util/Foo.java) -> rel paths."""
    cited = cited.lstrip("./")
    if cited.startswith("jadx/sources/"):
      cited = cited[len("jadx/sources/"):]
    return [r for r in self.by_base.get(os.path.basename(cited), []) if r.endswith(cited)]

  def at_line(self, rel, line):
    for u in self.java_file(rel):
      if u.start <= line <= u.end:
        return u
    return None


def findings(report):
  m = re.search(r"^## Findings\s*$(.*?)(?=^## )", report, re.M | re.S)
  if not m:
    return []
  items = re.split(r"(?m)^(\d+)\. ", m.group(1))
  out = []
  for i in range(1, len(items), 2):
    body = items[i + 1]
    t = re.match(r"\*\*(.+?)\*\*", body, re.S)
    title = re.sub(r"\s+", " ", t.group(1) if t else body[:80])
    out.append((int(items[i]), title, body))
  return out


def targets(text, idx):
  """unit ids cited in text, and Java files cited without a line or method"""
  ids, files = set(), set()
  cited_files = []
  for m in re.finditer(r"([\w/$.-]+\.java)((?::\d+(?:-\d+)?(?:,\s?\d+(?:-\d+)?)*)?)", text):
    rels = idx.resolve_file(m.group(1))
    cited_files.extend(rels)
    if m.group(2):
      for a, b in re.findall(r"(\d+)(?:-(\d+))?", m.group(2)):
        for ln in range(int(a), int(b or a) + 1):
          for rel in rels:
            u = idx.at_line(rel, ln)
            if u:
              ids.add(u.id)
    else:
      files.update(rels)
  for span in re.findall(r"`([^`]+)`", text):
    for cls, meth in re.findall(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\b", span):
      for rel in idx.by_base.get(cls + ".java", []):
        hit = [u.id for u in idx.java_file(rel) if u.name == meth]
        if hit:
          ids.update(hit)
          files.discard(rel)
    bare = re.fullmatch(r"([a-z_$][\w$]*)(?:\([^)]*\))?", span.strip())
    if bare:
      meth = bare.group(1)
      hit = [u.id for rel in cited_files for u in idx.java_file(rel) if u.name == meth]
      if not hit:
        cand = [u.id for us in idx.java.values() for u in us if u.name == meth]
        hit = cand if 0 < len(cand) <= 3 else []
      ids.update(hit)
    for q in re.findall(r"([A-Za-z_$][\w$]*)?::([A-Za-z_$][\w$]*)", span):
      qual = "%s::%s" % q
      ids.update(u.id for u in idx.other if u.kind == "dart" and (u.id == "dart:" + qual or
                                                                   u.id.startswith("dart:" + qual + "@")))
  for nm in set(re.findall(r"\b(FUN_[0-9a-f]{6,16}|jni_\w+|JNI_OnLoad|init_\d+)\b", text)):
    ids.update(u.id for u in idx.other if u.kind == "native" and u.name == nm)
  return ids, files


def parse_leads(path, idx):
  """ordered distinct unit ids (or ('file', rel)) named by a lead file, and its lead-line count"""
  if not os.path.exists(path):
    return None, 0
  order, seen, lines = [], set(), 0
  scores = []
  native_by_name = {}
  for u in idx.other:
    if u.kind == "native":
      native_by_name.setdefault((os.path.basename(u.file), u.name), u.id)
  dart_by_where = {}
  for u in idx.other:
    if u.kind == "dart":
      dart_by_where[(u.file, u.start)] = u.id
  model = path.endswith("model-leads.txt")
  # chain entries of structure-leads.txt: Class.method, or pkg/Class.method where the
  # short name is in several files. Among the functions in scope, as structure-leads.py
  # sees them; a short name that several files have names none of them.
  java_by_short, java_by_path = {}, {}
  for u in idx.scoped:
    java_by_short.setdefault("%s.%s" % (u.cls, u.name), []).append(u)
    java_by_path.setdefault("%s.%s" % (u.file[len("jadx/sources/"):-5], u.name), []).append(u.id)
  java_by_short = {n: [u.id for u in us] for n, us in java_by_short.items() if len({u.file for u in us}) == 1}
  native_names = {}
  for u in idx.other:
    if u.kind == "native":
      native_names.setdefault(u.name, []).append(u.id)

  def chain(line):
    """functions named in 'via A > B' chains of structure-leads.txt"""
    out = []
    for part in re.findall(r" via ([^;]+)", line):
      for name in part.split(" > "):
        name = name.strip().lstrip("~")
        out.extend(java_by_path.get(name, []) or java_by_short.get(name, []) or native_names.get(name, []) or
                   [u.id for u in idx.other if u.kind == "dart" and u.id == "dart:" + name])
    return out

  with open(path, errors="replace") as f:
    for line in f:
      key = None
      m = re.match(r"^(?:- (?:(\d\.\d\d)  )?)?(?:\./)?(?:jadx/sources/)?([\w/$.-]+\.java):(\d+)", line)
      if m:
        u = idx.at_line(m.group(2), int(m.group(3)))
        key = u.id if u else ("file", m.group(2))
      else:
        m = re.match(r"^- (?:(\d\.\d\d)  )?(native/\S+) \((\w+) @ 0x", line)
        if m:
          key = native_by_name.get((os.path.basename(m.group(2)), m.group(3)))
        else:
          m = re.match(r"^- (?:(\d\.\d\d)  )?(dart/asm/\S+):(\d+) ", line)
          if m:
            key = dart_by_where.get((m.group(2), int(m.group(3))))
      if key is None:
        continue
      lines += 1
      if model:
        scores.append((-float(m.group(1)), lines, key))
      else:
        for k in [key] + chain(line):
          if k not in seen:
            seen.add(k)
            order.append(k)
  if model:
    for _s, _n, key in sorted(scores):
      if key not in seen:
        seen.add(key)
        order.append(key)
  return order, lines


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  args = sys.argv[1:]
  verbose = "-v" in args
  args = [a for a in args if a != "-v"]
  if not args:
    sys.exit(__doc__)
  name, scopes = args[0], args[1:]
  work = os.path.join(ROOT, "work", name)
  rpath = os.path.join(ROOT, "reports", name + ".md")
  if not os.path.exists(rpath):
    sys.exit("reports/%s.md not found" % name)
  with open(rpath, errors="replace") as f:
    report = f.read()
  if not scopes:
    scopes = units.load_script("scope.py").scopes(work)
  scopes = [s for s in scopes if os.path.isdir(os.path.join(work, "jadx", "sources", s))]
  idx = Index(work, name, scopes)

  all_ids, all_files = targets(report, idx)
  leads = {s: parse_leads(os.path.join(work, s), idx) for s in SOURCES}

  def covers(order, ids, files):
    if order is None:
      return None
    for i, key in enumerate(order):
      if isinstance(key, tuple):
        if key[1] in files or any(t.startswith("java:%s::" % key[1][:-5]) for t in ids):
          return i + 1
      elif key in ids or any(key.startswith("java:%s::" % f[:-5]) for f in files):
        return i + 1
    return None

  print("# Lead evaluation: %s" % name)
  print("answer key: functions cited in the Findings of reports/%s.md" % name)
  print()
  head = "%-4s %-58s %7s" % ("#", "finding", "targets") + "".join(" %10s" % s.split(".")[0][:10] for s in SOURCES)
  print(head)
  tot = {s: 0 for s in SOURCES}
  union = {"scan+structure": 0, "all": 0}
  counted = 0
  for num, title, body in findings(report):
    ids, files = targets(body, idx)
    if not ids and not files:
      print("%-4s %-58s %7s   (cites no function: config, resources, or prose)" % (num, title[:58], "-"))
      continue
    counted += 1
    row = "%-4s %-58s %7s" % (num, title[:58], "%d%s" % (len(ids), "+%df" % len(files) if files else ""))
    got = {}
    for s in SOURCES:
      r = covers(leads[s][0], ids, files)
      got[s] = r
      if r:
        tot[s] += 1
      row += " %10s" % ("n/a" if leads[s][0] is None else (r or "-"))
    if got["scan.txt"] or got["structure-leads.txt"]:
      union["scan+structure"] += 1
    if any(got.values()):
      union["all"] += 1
    print(row)
    if verbose:
      for t in sorted(ids):
        print("       %s" % t)
      for f in sorted(files):
        print("       file %s" % f)
  print()
  print("findings with cited code: %d" % counted)
  for s in SOURCES:
    order, lines = leads[s]
    if order is None:
      print("%-20s not present" % s)
      continue
    rel = sum(1 for k in order if (k in all_ids if not isinstance(k, tuple) else k[1] in all_files or
                                   any(t.startswith("java:%s::" % k[1][:-5]) for t in all_ids)))
    print("%-20s covers %d of %d; %d lead lines, %d distinct functions, %d of them cited in the report (%.0f%%)" % (
      s, tot[s], counted, lines, len(order), rel, 100.0 * rel / max(1, len(order))))
  print("%-20s covers %d of %d" % ("scan + structure", union["scan+structure"], counted))
  print("%-20s covers %d of %d" % ("any source", union["all"], counted))


if __name__ == "__main__":
  main()
