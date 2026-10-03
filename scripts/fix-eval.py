#!/usr/bin/env python3
"""Score lead files on pairs of apps: a vulnerable version and its fixed version.

Benchmarks such as Ghera ship each vulnerability as a vulnerable app and a secure
app that differ only in the fix. The methods the fix changed are the answer key: a
useful lead points at them in the vulnerable app, and a discriminating lead is gone
from the same method in the fixed app. Manifest and resource-XML fixes are counted
separately: there the question is whether manifest-summary.txt changes with the fix.

For each pair and each lead source (scan.txt, structure-leads.txt, flows.txt):
  hit     a lead line names a changed method of the vulnerable app
  fixed   the same section still names that method in the fixed app (the lead does
          not tell the two apart)
and for manifest fixes:
  config  the fix changed AndroidManifest.xml (other than version, icon, label, theme)
          or res/xml/, and manifest-summary.txt differs between the two apps

Both apps must be unpacked and scanned (./cupella unpack.sh, ./cupella scan.sh).

Usage: ./cupella fix-eval.py <vulnerable> <fixed> [<vulnerable> <fixed> ...]
       ./cupella fix-eval.py --suffix <vuln-suffix> <fixed-suffix>   all pairs in work/,
                         e.g. --suffix -benign -secure for Ghera
Output: stdout
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCES = ("scan.txt", "structure-leads.txt", "flows.txt")


def scope_of(work):
  return units.load_script("scope.py").scopes(work)


def key_of(u):
  return (u.inner, u.bname, units._param_count(u.meta))


def body(u):
  return "\n".join(l.strip() for l in u.lines[1:])


def leads(work, us):
  """{source: set of (section, method key)}"""
  by_file = {}
  for u in us:
    by_file.setdefault(u.file[len("jadx/sources/"):], []).append(u)
  out = {}
  for src in SOURCES:
    path = os.path.join(work, src)
    hits = set()
    if os.path.exists(path):
      section = ""
      with open(path, errors="replace") as f:
        for line in f:
          if line.startswith("## "):
            section = re.sub(r"\s*\(\d+\)\s*$", "", line[3:].strip())
            continue
          m = re.match(r"^(?:- )?(?:\./)?(?:jadx/sources/)?([\w/$.-]+\.java):(\d+)", line)
          if not m:
            continue
          n = int(m.group(2))
          for u in by_file.get(m.group(1), ()):
            if u.start <= n <= u.end:
              hits.add((section, key_of(u)))
    out[src] = hits
  return out


def config_text(work):
  parts = []
  for rel in ("apktool/AndroidManifest.xml",):
    p = os.path.join(work, rel)
    if os.path.exists(p):
      with open(p, errors="replace") as f:
        parts.append(f.read())
  xml = os.path.join(work, "apktool", "res", "xml")
  if os.path.isdir(xml):
    for f in sorted(os.listdir(xml)):
      with open(os.path.join(xml, f), errors="replace") as fh:
        parts.append(f + "\n" + fh.read())
  # attributes that do not change behavior
  text = re.sub(r'android:(?:version\w*|icon|roundIcon|label|theme|logo)="[^"]*"', "", "\n".join(parts))
  return re.sub(r"[ \t]+", " ", text)


def summary_text(work):
  p = os.path.join(work, "manifest-summary.txt")
  if not os.path.exists(p):
    return ""
  with open(p, errors="replace") as f:
    return "\n".join(l for l in f.read().split("\n")[2:])


def evaluate(vname, fname):
  vw, fw = os.path.join(ROOT, "work", vname), os.path.join(ROOT, "work", fname)
  vu = units.java_units(vw, scope_of(vw))
  fu = units.java_units(fw, scope_of(fw))
  fixed_body = {}
  for u in fu:
    fixed_body.setdefault(key_of(u), set()).add(body(u))
  changed = {key_of(u) for u in vu if body(u) not in fixed_body.get(key_of(u), set())}
  config = config_text(vw) != config_text(fw)
  vl, fl = leads(vw, vu), leads(fw, fu)
  row = {"changed": len(changed), "config": config,
         "summary_differs": summary_text(vw) != summary_text(fw)}
  for src in SOURCES:
    hits = {(s, k) for s, k in vl[src] if k in changed}
    row[src] = (bool(hits), bool(hits and hits <= fl[src]), sorted({s for s, _k in hits}))
  return row


def main():
  args = sys.argv[1:]
  if not args:
    sys.exit(__doc__)
  pairs = []
  if args[0] == "--suffix":
    vs, fs = args[1], args[2]
    names = set(os.listdir(os.path.join(ROOT, "work")))
    pairs = sorted((n, n[:-len(vs)] + fs) for n in names if n.endswith(vs) and n[:-len(vs)] + fs in names)
  else:
    pairs = list(zip(args[0::2], args[1::2]))
  print("# Fix-pair evaluation: %d pairs" % len(pairs))
  print("hit: a lead names a method the fix changed; same: that lead is also in the fixed app;")
  print("config: the fix changed the manifest or res/xml; summary: manifest-summary.txt changed too")
  print()
  print("%-58s %4s %6s %7s  %-14s %-14s %-14s" % ("vulnerable app", "chg", "config", "summary", "scan", "structure", "flows"))
  tot = {"code": 0, "config": 0, "summary": 0}
  hit = {s: [0, 0] for s in SOURCES}
  either = 0
  for v, f in pairs:
    r = evaluate(v, f)
    cells = []
    for s in SOURCES:
      h, same, _secs = r[s]
      cells.append("-" if not h else "hit, same" if same else "hit")
    print("%-58s %4d %6s %7s  %-14s %-14s %-14s" % (v[:58], r["changed"], "yes" if r["config"] else "",
                                                    "yes" if r["summary_differs"] and r["config"] else "", *cells))
    if r["changed"]:
      tot["code"] += 1
      for s in SOURCES:
        if r[s][0]:
          hit[s][0] += 1
          if not r[s][1]:
            hit[s][1] += 1
      if any(r[s][0] for s in SOURCES):
        either += 1
    if r["config"]:
      tot["config"] += 1
      if r["summary_differs"]:
        tot["summary"] += 1
  print()
  print("pairs with code changes: %d" % tot["code"])
  for s in SOURCES:
    print("  %-20s points at a changed method in %d; of those, the lead is gone in the fixed app in %d" % (
      s, hit[s][0], hit[s][1]))
  print("  %-20s %d" % ("either source", either))
  print("pairs with manifest or res/xml changes: %d; manifest-summary.txt reflects the change in %d" % (
    tot["config"], tot["summary"]))


if __name__ == "__main__":
  main()
