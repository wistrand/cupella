#!/usr/bin/env python3
"""Would Quark-Engine leads add anything to the existing lead files? Measured on MalEval.

For each MalEval sample with a Quark report (work/<sha256>/tools/quark.json, from
quark-scan.sh), the Quark matches at 80%/100% confidence (quark-leads.py) are compared
with the existing scripted signals at two levels:

  per app        for each labeled behavior: does a Quark lead with a matching label
                 fire (anywhere, or in the app's scan scope), does bench-maleval.py's
                 code/decl/flow signal fire, and how often Quark fires alone. Benign
                 apps give the lead rate without the behavior.
  per function   the agent verdicts (work/_maleval-agent/verdicts/<sha>.json) cite
                 Java lines as evidence per behavior. For each cited function: does a
                 Quark lead name it, does scan.txt, structure-leads.txt, or flows.txt
                 name it, and how many only Quark names. Evidence in embedded payloads
                 (.emb<k>) is counted apart: Quark reads only the outer APK's dex.

The label map below (Quark labels to MalEval behavior classes) is a judgment made
before scoring; change it and rerun to see how much the result depends on it. The
function-level key is the agent's own evidence, so it favors what the agent read.

Usage: ./cupella bench-quark-leads.py [-v]      -v lists the functions only Quark named
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
qleads = units.load_script("quark-leads.py")
bmal = units.load_script("bench-maleval.py")
leval = units.load_script("lead-eval.py")

# Quark rule labels (and crime words) that speak to each behavior class
LABELS = {
  "Privacy Stealing": {"collection", "location", "calllog", "calendar", "camera", "record", "account",
                       "accounts", "contact", "privacy", "keylogging", "screen", "video"},
  "SMS/CALL": {"sms", "calllog", "phone"},
  "Premium Service": {"sms"},
  "Remote Control": {"command", "control", "socket", "relay"},
  "Abusing Accessibility": {"accessibility service"},
  "Bank Stealing": {"accessibility service", "keylogging", "screen"},
  "Ransom": {"lock", "admin"},
  "Privilege Escalation": {"admin", "exec", "permission"},
  "Stealthy Download": {"dexClassLoader", "so"},
  "Tricky Behavior": {"evasion", "icon-hide", "packer"},
  "Ads": set(),
}
CRIME_WORDS = {"Stealthy Download": ("install",)}

LINE = re.compile(r"^- jadx/sources/(\S+\.java):(\d+)  (.*?)  \[(.*?)\]  \((\d+%), (\S+), (app|library)\)")


def behaviors(labels, crime):
  out = {b for b, ls in LABELS.items() if ls & labels}
  out |= {b for b, ws in CRIME_WORDS.items() if any(w in crime.lower() for w in ws)}
  return out


def samples():
  path = os.path.join(ROOT, "work", "_tools", "maleval.txt")
  with open(path) as f:
    return [os.path.basename(l.strip())[:-4] for l in f if l.strip().endswith(".apk")]


def labels_by_sha():
  out = {}
  for fn, kind in (("archived_sample_info.json", "malware"), ("latest_sample_info.json", "malware"),
                   ("benign_sample_info.json", "benign")):
    with open(os.path.join(bmal.INFO, fn)) as f:
      for sha, meta in json.load(f).items():
        out[sha] = (kind, meta.get("behavior", []))
  return out


def main():
  verbose = "-v" in sys.argv
  labs = labels_by_sha()
  per_app, func = [], []
  quark_only_funcs = []
  for name in samples():
    if name not in labs:
      continue
    lines = qleads.build(name)
    if lines is None:
      continue
    kind, behs = labs[name]
    sig = bmal.signals_with_children(name) or {}
    q_any, q_app = set(), set()
    for l in lines:
      m = LINE.match(l)
      if not m:
        continue
      b = behaviors(set(m.group(4).split(",")), m.group(3))
      q_any |= b
      if m.group(7) == "app":
        q_app |= b
    per_app.append((name, kind, behs, sig, q_any, q_app))

    # function level, against the agent verdict's Java evidence in the outer APK
    vpath = os.path.join(ROOT, "work", "_maleval-agent", "verdicts", name + ".json")
    if kind != "malware" or not os.path.exists(vpath):
      continue
    with open(vpath) as f:
      verdict = json.load(f)
    work = os.path.join(ROOT, "work", name)
    scopes = [s for s in qleads.scan_scope(work) if os.path.isdir(os.path.join(work, "jadx", "sources", s))]
    idx = leval.Index(work, name, scopes)
    qunits = set()
    for l in lines:
      m = LINE.match(l)
      if m:
        u = idx.at_line(m.group(1), int(m.group(2)))
        if u:
          qunits.add(u.id)
    existing = set()
    for src in ("scan.txt", "structure-leads.txt", "flows.txt"):
      order, _n = leval.parse_leads(os.path.join(work, src), idx)
      existing |= {k for k in (order or []) if not isinstance(k, tuple)}
    for b in verdict.get("behaviors", []):
      ev = b.get("evidence", "")
      m = re.match(r"^work/([^/]+)/jadx/sources/(\S+\.java):(\d+)", ev)
      if not m:
        continue
      if m.group(1) != name:
        func.append((name, b.get("label"), "embedded", None, None))
        continue
      u = idx.at_line(m.group(2), int(m.group(3)))
      if not u:
        continue
      inq, inx = u.id in qunits, u.id in existing
      func.append((name, b.get("label"), "outer", inq, inx))
      if inq and not inx:
        quark_only_funcs.append((name[:16], b.get("label"), u.where))

  mal = [r for r in per_app if r[1] == "malware"]
  ben = [r for r in per_app if r[1] == "benign"]
  pct = lambda n, t: "%3d%%" % (100.0 * n / t) if t else "  - "
  print("# Quark leads on MalEval")
  print("samples with a Quark report: %d malware, %d benign" % (len(mal), len(ben)))
  print()
  print("## Per app: a lead toward each labeled behavior")
  print("%-22s %6s %9s %7s %9s %6s %8s   %s" % ("behavior", "labeled", "existing", "quark", "quark-app",
                                               "only", "app only", "benign: existing / quark / quark-app"))
  for beh in LABELS:
    lab = [r for r in mal if beh in r[2]]
    if not lab:
      continue
    ex = lambda r: bool(r[3].get(beh) and any(r[3][beh]))
    e = sum(1 for r in lab if ex(r))
    q = sum(1 for r in lab if beh in r[4])
    qa = sum(1 for r in lab if beh in r[5])
    qo = sum(1 for r in lab if beh in r[4] and not ex(r))
    qao = sum(1 for r in lab if beh in r[5] and not ex(r))
    be = sum(1 for r in ben if ex(r))
    bq = sum(1 for r in ben if beh in r[4])
    bqa = sum(1 for r in ben if beh in r[5])
    print("%-22s %6d %9s %7s %9s %6d %8d   %s / %s / %s of %d" % (
      beh, len(lab), pct(e, len(lab)), pct(q, len(lab)), pct(qa, len(lab)), qo, qao,
      pct(be, len(ben)), pct(bq, len(ben)), pct(bqa, len(ben)), len(ben)))
  print()
  print("## Per function: the agent verdicts' Java evidence")
  outer = [f for f in func if f[2] == "outer"]
  emb = [f for f in func if f[2] == "embedded"]
  print("cited functions in the outer APK: %d; in embedded payloads (Quark cannot see them): %d" % (len(outer), len(emb)))
  if outer:
    q = sum(1 for f in outer if f[3])
    x = sum(1 for f in outer if f[4])
    qo = sum(1 for f in outer if f[3] and not f[4])
    xo = sum(1 for f in outer if f[4] and not f[3])
    either = sum(1 for f in outer if f[3] or f[4])
    print("named by Quark leads: %d (%s)" % (q, pct(q, len(outer))))
    print("named by scan/structure/flows: %d (%s)" % (x, pct(x, len(outer))))
    print("named only by Quark: %d; only by the existing leads: %d; by either: %d (%s)" % (
      qo, xo, either, pct(either, len(outer))))
  if verbose and quark_only_funcs:
    print()
    print("## Functions only Quark named")
    for row in quark_only_funcs:
      print("%s  %-22s %s" % row)


if __name__ == "__main__":
  main()
