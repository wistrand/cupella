#!/usr/bin/env python3
"""Score agent reports on MalEval samples against the per-sample behavior labels.

Agents write work/_maleval-agent/verdicts/<sha256>.json with a verdict (malicious,
suspicious, benign) and the behaviors they claim from MalEval's eleven classes, each
with code evidence. This compares the claimed set with the labeled set:

  verdict    malware called malicious or suspicious; benign apps called benign
  behaviors  per class: labeled, claimed, both (true positives); recall and precision
  evidence   share of claimed behaviors whose evidence path exists under work/

Labels come from vendor reports, which describe a family and may name behaviors a
given sample lacks or hides (encrypted payloads); a claim missing from the labels is
not necessarily wrong. Read the per-sample lines before drawing conclusions.

Usage: ./cupella bench-maleval-agent.py [-v] [verdicts-dir] [sha256 ...]
  verdicts-dir: a name under work/_maleval-agent/ (default verdicts); sha256 values
  restrict scoring to those samples (to compare runs on a subset)
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(ROOT, "work", "_maleval-agent")
INFO = os.path.join(ROOT, "bench", "maleval", "info")
CLASSES = ["Privacy Stealing", "SMS/CALL", "Remote Control", "Bank Stealing", "Ransom", "Abusing Accessibility",
           "Privilege Escalation", "Stealthy Download", "Ads", "Premium Service", "Tricky Behavior"]


def main():
  args = [a for a in sys.argv[1:] if a != "-v"]
  verbose = "-v" in sys.argv
  vdir = args[0] if args and not all(c in "0123456789abcdef" for c in args[0]) else "verdicts"
  only = [a for a in args if len(a) == 64]
  labels = {}
  for f in ("archived", "latest", "benign"):
    for sha, m in json.load(open(os.path.join(INFO, "%s_sample_info.json" % f))).items():
      labels[sha] = (m.get("type") == "benign" or f == "benign", set(m.get("behavior", [])), m.get("family", "-"))
  sel = json.load(open(os.path.join(OUT, "selection.json")))
  stats = {c: [0, 0, 0] for c in CLASSES}  # labeled, claimed, both
  vrows, ev_ok, ev_all, missing = [], 0, 0, []
  for sha in sel["order"]:
    if only and sha not in only:
      continue
    p = os.path.join(OUT, vdir, sha + ".json")
    if not os.path.exists(p):
      missing.append(sha)
      continue
    v = json.load(open(p))
    benign, lab, fam = labels[sha]
    claimed = {b.get("label") for b in v.get("behaviors", []) if b.get("label") in CLASSES}
    for b in v.get("behaviors", []):
      m = re.match(r"(?:work/)?([^\s:,]+)", b.get("evidence", ""))
      if m:
        ev_all += 1
        path = m.group(1)
        if os.path.exists(os.path.join(ROOT, "work", path)) or os.path.exists(os.path.join(ROOT, path)):
          ev_ok += 1
    for c in CLASSES:
      stats[c][0] += c in lab
      stats[c][1] += c in claimed
      stats[c][2] += c in lab and c in claimed
    vrows.append((sha, fam, benign, v.get("verdict"), lab, claimed, v.get("unreadable", "")))
  mal = [r for r in vrows if not r[2]]
  ben = [r for r in vrows if r[2]]
  print("# MalEval agent reports: %d malware, %d benign scored; %d missing" % (len(mal), len(ben), len(missing)))
  print("malware called malicious or suspicious: %d of %d" % (sum(1 for r in mal if r[3] in ("malicious", "suspicious")), len(mal)))
  print("benign apps called benign: %d of %d (others: %s)" % (
    sum(1 for r in ben if r[3] == "benign"), len(ben), ", ".join("%s=%s" % (r[0][:8], r[3]) for r in ben if r[3] != "benign") or "none"))
  print("evidence paths that exist: %d of %d" % (ev_ok, ev_all))
  print()
  print("%-22s %7s %7s %5s %7s %9s" % ("behavior", "labeled", "claimed", "both", "recall", "precision"))
  tl = tc = tb = 0
  for c in CLASSES:
    l, cl, b = stats[c]
    tl, tc, tb = tl + l, tc + cl, tb + b
    print("%-22s %7d %7d %5d %7s %9s" % (c, l, cl, b, "%d%%" % (100 * b / l) if l else "-", "%d%%" % (100 * b / cl) if cl else "-"))
  print("%-22s %7d %7d %5d %7s %9s" % ("all", tl, tc, tb, "%d%%" % (100 * tb / tl) if tl else "-", "%d%%" % (100 * tb / tc) if tc else "-"))
  if verbose:
    print()
    for sha, fam, benign, verdict, lab, claimed, unread in vrows:
      print("%s %-12s %-10s missed: %s | extra: %s%s" % (
        sha[:10], fam[:12], verdict, ", ".join(sorted(lab - claimed)) or "-", ", ".join(sorted(claimed - lab)) or "-",
        " | unreadable: %s" % unread[:60] if unread else ""))


if __name__ == "__main__":
  main()
