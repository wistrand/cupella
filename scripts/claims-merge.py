#!/usr/bin/env python3
"""Merge verification verdicts into an analysis's claims.

The verifier (a reader agent, prompts/verify-report.md) cannot edit claims.jsonl; it
writes one file per claim, work/<name>/progress/verify-verdicts/<claim id>.json, a JSON
object:

  {"id": "F1", "result": "holds"|"overstated"|"wrong", "note": "<why, at most 500
   characters>", "refs": ["<path>:<line>", ...]}

One verdict per file means the verifier adds a verdict without resending the earlier
ones. The form before 2026-10-04, one object per line in
work/<name>/progress/verify-verdicts.jsonl, is still read (both may exist; an id in both
is a second verdict). refs are the lines the verifier read; required for "overstated" and
"wrong". This script
checks every verdict (known claim id, one verdict per id, the fields above) and writes each
verdict into that claim's "verdict" field, with "by": "verify". It changes nothing else:
a claim found wrong or overstated stays as it is until the main agent has checked the code
itself and edited the claim (and kept or replaced the verdict). The previous claims.jsonl
is kept as claims.jsonl.prev. Nothing is written when any verdict fails.

./cupella runs this in a container that sees only the verdicts (read-only) and
reports/<name>/. Then: ./cupella claims-check.py <name>, ./cupella report-build.py <name>.

Usage: ./cupella claims-merge.py <name>
"""
import json
import os
import re
import shutil
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
RESULTS = {"holds", "overstated", "wrong"}
FIELDS = {"id", "result", "note", "refs"}
REF = re.compile(r"^[\w./$+-]+:\d+(?:-\d+)?$")


def records(vdir, vpath):
  """[(where, text, id from the file name or None)] of the verdicts: the .json files of
  verify-verdicts/ in name order, then the lines of verify-verdicts.jsonl"""
  out = []
  if os.path.isdir(vdir):
    for f in sorted(os.listdir(vdir)):
      p = os.path.join(vdir, f)
      if not f.endswith(".json") or os.path.islink(p) or not os.path.isfile(p):
        continue
      with open(p, errors="replace") as fh:
        out.append(("verify-verdicts/%s" % f, fh.read(), f[:-5]))
  if os.path.isfile(vpath):
    with open(vpath, errors="replace") as fh:
      for n, line in enumerate(fh, 1):
        if line.strip():
          out.append(("verify-verdicts.jsonl:%d" % n, line, None))
  return out


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  cpath = os.path.join(ROOT, "reports", name, "claims.jsonl")
  vpath = os.path.join(ROOT, "work", name, "progress", "verify-verdicts.jsonl")
  vdir = os.path.join(ROOT, "work", name, "progress", "verify-verdicts")
  if not os.path.isfile(cpath):
    sys.exit("no reports/%s/claims.jsonl" % name)
  if not os.path.isfile(vpath) and not os.path.isdir(vdir):
    sys.exit("no work/%s/progress/verify-verdicts/ (or verify-verdicts.jsonl)" % name)
  with open(cpath) as f:
    lines = f.read().split("\n")
  claims = []
  for n, line in enumerate(lines, 1):
    if line.strip():
      try:
        claims.append(json.loads(line))
      except ValueError as e:
        sys.exit("claims.jsonl:%d: not JSON (%s); run ./cupella claims-check.py %s" % (n, e, name))
  ids = {c.get("id") for c in claims}
  verdicts, problems = {}, []
  for where, text, stem in records(vdir, vpath):
    try:
      v = json.loads(text)
    except ValueError as e:
      problems.append("%s: not JSON (%s)" % (where, e))
      continue
    if not isinstance(v, dict):
      problems.append("%s: not an object" % where)
      continue
    extra = set(v) - FIELDS
    if extra:
      problems.append("%s: unknown fields %s" % (where, ", ".join(sorted(extra))))
    cid = v.get("id")
    if stem is not None and cid != stem:
      problems.append("%s: id %r differs from the file name" % (where, cid))
    if cid not in ids:
      problems.append("%s: no claim %r" % (where, cid))
    elif cid in verdicts:
      problems.append("%s: second verdict for %s" % (where, cid))
    if v.get("result") not in RESULTS:
      problems.append("%s: result must be one of %s" % (where, ", ".join(sorted(RESULTS))))
    note = v.get("note", "")
    if not isinstance(note, str) or len(note) > 500:
      problems.append("%s: note must be a string of at most 500 characters" % where)
    refs = v.get("refs") or []
    if not isinstance(refs, list) or not all(isinstance(r, str) and REF.match(r) for r in refs):
      problems.append("%s: refs must be a list of <path>:<line>[-<line>]" % where)
    elif v.get("result") in ("overstated", "wrong") and not refs:
      problems.append("%s: a %s verdict needs refs" % (where, v.get("result")))
    verdicts[cid] = v
  if problems:
    print("\n".join(problems))
    sys.exit("not merged: fix the verdicts")
  shutil.copyfile(cpath, cpath + ".prev")
  with open(cpath, "w") as f:
    for c in claims:
      v = verdicts.get(c.get("id"))
      if v is not None:
        c["verdict"] = {"result": v["result"], "note": v.get("note", ""), "by": "verify", "refs": v.get("refs") or []}
      f.write(json.dumps(c, ensure_ascii=True) + "\n")
  counts = {r: sum(1 for v in verdicts.values() if v["result"] == r) for r in sorted(RESULTS)}
  missing = [c.get("id") for c in claims if c.get("status") != "rejected" and c.get("id") not in verdicts]
  print("merged %d verdicts into reports/%s/claims.jsonl (%s); previous copy: claims.jsonl.prev" % (
    len(verdicts), name, ", ".join("%s %d" % kv for kv in counts.items())))
  if missing:
    print("no verdict: %s" % ", ".join(missing))
  for cid, v in sorted(verdicts.items()):
    if v["result"] != "holds":
      print("%s %s: check the code yourself before editing the claim: %s" % (cid, v["result"], v.get("note", "")))


if __name__ == "__main__":
  main()
