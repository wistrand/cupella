#!/usr/bin/env python3
"""Quark Script queries over one APK: where a two-API behavior occurs, with its values.

Runs one Quark rule with Quark Script (the quark-engine in the image) and lists every
occurrence: the calling method mapped to its jadx file and line, the two API calls, the
argument values Quark resolves at the call sites, URLs among them, and whether each
string argument is hardcoded in the APK. This answers what xref.py and flows.py do
not: the actual values passed (a key handed to Cipher.init, the number given to
sendTextMessage, the URL opened).

The rule is a Quark rule id from the pinned rule set (00028 -> quark-rules/rules/00028.json)
or a rule JSON file under work/ in Quark's format (two APIs, each with class, method,
descriptor; see any file in the rule set). A rule file is data: it names APIs, it runs
nothing. An agent may write one to work/<name>/quark-rules/<what>.json.

Usage: ./cupella quark-query.py <name> <rule-id | work/.../rule.json> [--max N]
       ./cupella quark-query.py --api          list the installed Quark Script API
Output: stdout (redirect to work/<name>/quark-query-<what>.txt if wanted).
"""
import json
import os
import re
import sys

SELF = os.path.abspath(__file__)
ROOT = os.path.abspath(os.path.join(os.path.dirname(SELF), ".."))
QUARK_PY = "/opt/tools/quarkenv/bin/python"
RULES = os.path.join(os.environ.get("APK_TOOLS", "/opt/tools"), "quark-rules", "rules")

# quark writes a dated log file into the working directory and its config under HOME
os.chdir("/tmp")
os.environ.setdefault("HOME", "/tmp")
try:
  import quark.script as qs
except ImportError:
  if os.path.exists(QUARK_PY) and sys.executable != QUARK_PY:
    os.execv(QUARK_PY, [QUARK_PY, SELF] + sys.argv[1:])
  sys.exit("quark-engine not found: run this as ./cupella quark-query.py ...")

import inspect  # noqa: E402

sys.path.insert(0, os.path.dirname(SELF))
qleads = None  # quark-leads.py, loaded lazily (it imports units, which is stdlib-only)


def api():
  for n, o in sorted(vars(qs).items()):
    if n.startswith("_") or not callable(o) or getattr(o, "__module__", "").split(".")[0] != "quark":
      continue
    try:
      sig = str(inspect.signature(o))
    except (TypeError, ValueError):
      sig = "(...)"
    print("%s%s" % (n, sig))
    if inspect.isclass(o):
      for mn, mo in sorted(vars(o).items()):
        if not mn.startswith("_") and callable(mo):
          try:
            print("    .%s%s" % (mn, inspect.signature(mo)))
          except (TypeError, ValueError):
            print("    .%s(...)" % mn)


def apk_path(work):
  """the APK quark should read: repaired.apk when unpack.sh made one, else the input file"""
  rep = os.path.join(work, "repaired.apk")
  if os.path.exists(rep):
    return rep
  with open(os.path.join(work, "triage.txt"), errors="replace") as f:
    for line in f:
      if line.startswith("file:"):
        p = line.split(":", 1)[1].strip()
        return p.replace("/repo/", ROOT + "/", 1) if p.startswith("/repo/") else p
  return None


def rule_path(arg):
  if re.match(r"^\d{5}$", arg):
    return os.path.join(RULES, arg + ".json")
  p = os.path.abspath(os.path.join(ROOT, arg))
  if not p.startswith(os.path.join(ROOT, "work") + os.sep):
    sys.exit("a rule file must be under work/ (or give a rule id such as 00028)")
  return p


def short(text, n=160):
  text = str(text).replace("\n", "\\n")
  return text if len(text) <= n else text[:n] + "..."


def main():
  global qleads
  if "--api" in sys.argv:
    return api()
  args = sys.argv[1:]
  limit = 200
  if "--max" in args:
    i = args.index("--max")
    limit = int(args[i + 1])
    del args[i:i + 2]
  if len(args) != 2:
    sys.exit(__doc__)
  name, rarg = args
  work = os.path.join(ROOT, "work", name)
  apk = apk_path(work)
  if not apk or not os.path.exists(apk):
    sys.exit("no APK for %s: run ./cupella unpack.sh first" % name)
  rpath = rule_path(rarg)
  if not os.path.exists(rpath):
    sys.exit("rule not found: %s" % rarg)
  with open(rpath) as f:
    rule = json.load(f)
  import importlib.util
  spec = importlib.util.spec_from_file_location("quark_leads", os.path.join(os.path.dirname(SELF), "quark-leads.py"))
  qleads = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(qleads)

  result = qs.runQuarkAnalysis(apk, qs.Rule(rpath))
  occ = result.behaviorOccurList
  print("# Quark query: %s, rule %s (%s)" % (name, os.path.basename(rpath), short(rule.get("crime", ""), 80)))
  print("APK read: %s; occurrences: %d%s" % (os.path.relpath(apk, ROOT), len(occ),
                                             " (first %d shown)" % limit if len(occ) > limit else ""))
  print("Leads, not findings: read the code at each location.")
  print()
  cache = {}
  for b in occ[:limit]:
    caller = b.methodCaller
    cls, meth = caller.className, caller.methodName
    loc = qleads.java_location(work, cls, meth, cache)
    where = "jadx/sources/%s:%d" % loc if loc else "%s %s (not in jadx output)" % (cls, meth)
    print("- %s  %s.%s" % (where, cls.strip("L;").split("/")[-1], meth))
    print("    calls: %s.%s, then %s.%s" % (b.firstAPI.className, b.firstAPI.methodName,
                                          b.secondAPI.className, b.secondAPI.methodName))
    try:
      vals = b.getParamValues()
    except Exception as e:  # quark cannot resolve some register states
      vals, err = [], str(e)
      print("    values: not resolved (%s)" % short(err, 80))
    literals = []
    for v in vals:
      sv = str(v)
      print("    value: %s" % short(sv))
      # quark renders values as call expressions; the literal arguments sit innermost
      for lit in re.findall(r"\(([^(),;\[\]]{4,})\)", sv):
        if lit not in literals and not re.match(r"^L[\w/$]+$", lit):
          literals.append(lit)
    for lit in literals:
      try:
        hard = result.isHardcoded(lit)
      except Exception:
        hard = False
      print("    literal: %s%s" % (short(lit), "  [hardcoded in the APK]" if hard else ""))
    try:
      urls = b.hasUrl()
    except Exception:
      urls = []
    for u in urls:
      print("    url: %s" % short(u))


if __name__ == "__main__":
  main()
