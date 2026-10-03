#!/usr/bin/env python3
"""Turn a Quark-Engine report into a lead file.

Reads work/<name>/tools/quark.json (written by quark-scan.sh) and writes
work/<name>/quark-leads.txt: one line per method that a Quark rule matched at 80% or
100% confidence (the levels where Quark names the calling method), mapped to its jadx
file and line. Methods in the scan scope come first, then library code; within each,
higher confidence and higher rule score first. Lower confidence levels name only API
use somewhere in the APK and are left out.

A Quark match is a lead like any other: the rule saw two API calls in one method (and,
at 100%, data passing between them). Read the code before reporting anything.

Line format (parsed by lead-eval.py and bench-quark-leads.py):
  - jadx/sources/<path>.java:<line>  <crime>  [<labels>]  (<confidence>, <rule>, app|library)
  - <Lclass; method>  <crime>  [<labels>]  (<confidence>, <rule>, not in jadx output)

Usage: ./cupella quark-leads.py <name> [java-scope ...]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def locations(crime):
  """(class descriptor, method name) pairs Quark names for a crime, deduplicated"""
  out = []
  for field in ("register", "sequence"):
    for entry in crime.get(field) or []:
      for where in entry:
        parts = where.split(" ")
        if len(parts) >= 2 and (parts[0], parts[1]) not in out:
          out.append((parts[0], parts[1]))
  return out


def java_location(work, cls, method, cache):
  """'Lpkg/Outer$Inner;' + method -> (rel path under jadx/sources, line) or None"""
  rel = cls[1:-1].split("$")[0] + ".java"
  if "/" not in rel:
    rel = "defpackage/" + rel  # jadx puts the unnamed package there
  path = os.path.join(work, "jadx", "sources", rel)
  if not os.path.exists(path):
    return None
  if rel not in cache:
    cache[rel] = units._java_file_units(path, rel)
  # the innermost class name, as jadx writes it (Outer$Inner -> Inner)
  short = cls[1:-1].split("/")[-1].split("$")[-1]
  for u in cache[rel]:
    if u.name == method and (u.inner or u.cls).replace("$", ".").split(".")[-1] == short:
      return rel, u.start
  for u in cache[rel]:
    if u.name == method:
      return rel, u.start
  return rel, 1


def scan_scope(work):
  """the scope scan.sh searched (its scope: line), else scope.py's default"""
  try:
    with open(os.path.join(work, "scan.txt"), errors="replace") as f:
      for line in f:
        if line.startswith("scope: "):
          return line[7:].split(" (under")[0].split()
  except OSError:
    pass
  return units.load_script("scope.py").scopes(work)


def build(name, scopes=None):
  """lead lines for a sample, or None when it has no quark.json"""
  work = os.path.join(ROOT, "work", name)
  qpath = os.path.join(work, "tools", "quark.json")
  if not os.path.exists(qpath):
    return None
  with open(qpath, errors="replace") as f:
    report = json.load(f)
  if scopes is None:
    scopes = scan_scope(work)
  scopes = [s.rstrip("/") + "/" for s in scopes if s not in (".", "")]
  rank = {"100%": 0, "80%": 1}
  rows, cache, seen = [], {}, set()
  for crime in report.get("crimes", []):
    conf = crime.get("confidence", "")
    if conf not in rank:
      continue
    labels = ",".join(crime.get("label", []))
    for cls, method in locations(crime):
      key = (cls, method, crime.get("rule"))
      if key in seen:
        continue
      seen.add(key)
      loc = java_location(work, cls, method, cache)
      if loc:
        rel, line = loc
        app = any(rel.startswith(s) for s in scopes) or not scopes
        where = "jadx/sources/%s:%d" % (rel, line)
        tail = "app" if app else "library"
      else:
        app, where, tail = False, "%s %s" % (cls, method), "not in jadx output"
      rows.append((0 if app else 1, rank[conf], -float(crime.get("score") or 0), where,
                   "- %s  %s  [%s]  (%s, %s, %s)" % (where, crime.get("crime", ""), labels, conf,
                                                    crime.get("rule", ""), tail)))
  rows.sort()
  return [r[4] for r in rows]


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name, scopes = sys.argv[1], sys.argv[2:] or None
  lines = build(name, scopes)
  if lines is None:
    sys.exit("no work/%s/tools/quark.json: run ./cupella quark-scan.sh on the APK first" % name)
  out = os.path.join(ROOT, "work", name, "quark-leads.txt")
  app = sum(1 for l in lines if l.endswith(", app)"))
  with open(out, "w") as f:
    f.write("# Quark leads: %s\n" % name)
    f.write("# rules matched at 80%%/100%% confidence, by calling method; %d lines, %d in app scope.\n"
            "# Leads, not findings: read the code behind each.\n\n" % (len(lines), app))
    f.write("\n".join(lines) + ("\n" if lines else ""))
  print("wrote work/%s/quark-leads.txt (%d lines, %d in app scope)" % (name, len(lines), app))


if __name__ == "__main__":
  main()
