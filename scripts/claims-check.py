#!/usr/bin/env python3
"""Check an analysis's claims: schema, evidence that resolves, quotes that match the code.

reports/<name>/claims.jsonl holds one JSON object per line, one per finding, written by
the agent (main agent or reader subagents). report-render.py prints them as the report's
Findings. A record:

  id          "F1", "F2", ...: unique; the order of lines is the order in the report
  status      "draft" (written, key steps not yet checked), "confirmed" (checked in the
              code by the main agent), "rejected" (kept for the record, not rendered)
  threat      heading the finding is grouped under ("NFC card relay"); "" for none
  title       one line, at most 120 characters
  claim       what the code does, at most 800 characters; no verdicts
  evidence    list, at least one item, each either
                {"ref": "<path>:<line>[-<line>]", "quote": "<text on those lines>"}
                  path relative to work/<name>/ (jadx/sources/...), to jadx/sources/, or
                  work/<child>/... for a child sample; quote optional for non-code files
                {"entry": "<Class.method>", "api": "<API label>"}
                  a row of facts.json behavior.entries (an entry point reaching an API)
  gate        what it depends on and whether that holds ("NFC requested")
  confidence  "confirmed", "likely", "lead", or "inert" (design-report.md labels)
  class       behavior class (malware), optional
  attack      list of MITRE ATT&CK Mobile IDs ("T1437.001"), optional
  inferred    list of statements that are inferences, optional
  author      "main" or the reader role that wrote it ("reader-c2")
  verdict     optional, from verification: {"result": "ok"|"wrong"|"overstated",
              "note": "...", "by": "verify"}

Checks: the schema; every ref names an existing file and lines inside it; every quote is
on the cited lines (whitespace ignored), else where it moved; every entry/api pair is in
work/<name>/facts.json. Exit status 1 when anything fails.

Usage: ./cupella claims-check.py <name>
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
STATUS = {"draft", "confirmed", "rejected"}
CONFIDENCE = {"confirmed", "likely", "lead", "inert"}
VERDICT = {"ok", "wrong", "overstated"}
FIELDS = {"id", "status", "threat", "title", "claim", "evidence", "gate", "confidence", "class",
          "attack", "inferred", "author", "verdict"}
REQUIRED = ("id", "status", "title", "claim", "evidence", "gate", "confidence")
REF = re.compile(r"^([\w./$+-]+):(\d+)(?:-(\d+))?$")
ATTACK = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def load(path):
  """([claims], [problems]) from a claims.jsonl, schema checked"""
  claims, problems, ids = [], [], set()
  if not os.path.isfile(path):
    return claims, problems
  with open(path, errors="replace") as f:
    for n, line in enumerate(f, 1):
      if not line.strip():
        continue
      where = "claims.jsonl:%d" % n
      try:
        c = json.loads(line)
      except ValueError as e:
        problems.append("%s: not JSON (%s)" % (where, e))
        continue
      if not isinstance(c, dict):
        problems.append("%s: not an object" % where)
        continue
      cid = c.get("id", "?")
      where = "%s %s" % (where, cid)
      for k in REQUIRED:
        if not c.get(k):
          problems.append("%s: missing %s" % (where, k))
      for k in c:
        if k not in FIELDS:
          problems.append("%s: unknown field %s" % (where, k))
      if not re.match(r"^F\d+$", str(cid)):
        problems.append("%s: id must be F<number>" % where)
      elif cid in ids:
        problems.append("%s: duplicate id" % where)
      ids.add(cid)
      if c.get("status") and c["status"] not in STATUS:
        problems.append("%s: status must be one of %s" % (where, ", ".join(sorted(STATUS))))
      if c.get("confidence") and c["confidence"] not in CONFIDENCE:
        problems.append("%s: confidence must be one of %s" % (where, ", ".join(sorted(CONFIDENCE))))
      for k, lim in (("title", 120), ("claim", 800), ("gate", 300)):
        if isinstance(c.get(k), str) and len(c[k]) > lim:
          problems.append("%s: %s longer than %d characters" % (where, k, lim))
        elif k in c and not isinstance(c[k], str):
          problems.append("%s: %s must be a string" % (where, k))
      for a in c.get("attack") or []:
        if not ATTACK.match(str(a)):
          problems.append("%s: attack id %r is not T<4 digits>[.<3 digits>]" % (where, a))
      if not isinstance(c.get("evidence", []), list):
        problems.append("%s: evidence must be a list" % where)
        c["evidence"] = []
      for e in c.get("evidence") or []:
        if not isinstance(e, dict) or not (("ref" in e) ^ ("entry" in e)):
          problems.append("%s: evidence item needs either ref or entry: %r" % (where, e))
        elif "ref" in e and not REF.match(str(e["ref"])):
          problems.append("%s: ref %r is not <path>:<line>[-<line>]" % (where, e["ref"]))
        elif "entry" in e and not e.get("api"):
          problems.append("%s: entry evidence needs api" % where)
      v = c.get("verdict")
      if v is not None and (not isinstance(v, dict) or v.get("result") not in VERDICT):
        problems.append("%s: verdict.result must be one of %s" % (where, ", ".join(sorted(VERDICT))))
      claims.append(c)
  return claims, problems


def resolve(name, path):
  """file path for a ref path, or None"""
  work = os.path.join(ROOT, "work", name)
  cands = [os.path.join(ROOT, path)] if path.startswith("work/") else [
    os.path.join(work, path), os.path.join(work, "jadx", "sources", path)]
  m = re.match(r"^\.((?:dec|emb)\d+(?:\.(?:dec|emb)\d+)*)/(.+)$", path)
  if m:
    child = os.path.join(ROOT, "work", "%s.%s" % (name, m.group(1)))
    cands = [os.path.join(child, m.group(2)), os.path.join(child, "jadx", "sources", m.group(2))]
  for c in cands:
    real = os.path.realpath(c)
    if os.path.isfile(c) and real.startswith(os.path.realpath(os.path.join(ROOT, "work")) + os.sep):
      return c
  return None


def norm(s):
  return re.sub(r"\s+", "", s)


def check_evidence(name, claims, facts):
  problems = []
  entries = {(e["func"], e["api"]) for e in ((facts or {}).get("behavior") or {}).get("entries", [])}
  for c in claims:
    if c.get("status") == "rejected":
      continue
    for e in c.get("evidence") or []:
      if not isinstance(e, dict):
        continue
      where = "%s %s" % (c.get("id"), e.get("ref") or e.get("entry"))
      if "entry" in e:
        if facts is None:
          problems.append("%s: no facts.json to check the entry against (run ./cupella facts.py)" % where)
        elif (e["entry"], e.get("api")) not in entries:
          problems.append("%s: no entry %s reaching %s in facts.json behavior.entries" % (where, e["entry"], e.get("api")))
        continue
      m = REF.match(str(e.get("ref", "")))
      if not m:
        continue
      path = resolve(name, m.group(1))
      if not path:
        problems.append("%s: no such file" % where)
        continue
      with open(path, errors="replace") as f:
        lines = f.read().split("\n")
      a = int(m.group(2))
      b = int(m.group(3) or a)
      if not 1 <= a <= b <= len(lines):
        problems.append("%s: lines outside the file (%d lines)" % (where, len(lines)))
        continue
      q = e.get("quote")
      if q and norm(q) not in norm("".join(lines[a - 1:b])):
        moved = [i + 1 for i, x in enumerate(lines) if norm(q) in norm(x)]
        problems.append("%s: quote not on the cited lines%s" % (
          where, "; found at line %s" % ", ".join(map(str, moved[:5])) if moved else "; not in the file"))
  return problems


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  path = os.path.join(ROOT, "reports", name, "claims.jsonl")
  if not os.path.isfile(path):
    sys.exit("no reports/%s/claims.jsonl" % name)
  claims, problems = load(path)
  fp = os.path.join(ROOT, "work", name, "facts.json")
  facts = None
  if os.path.isfile(fp):
    with open(fp) as f:
      facts = json.load(f)
  problems += check_evidence(name, claims, facts)
  n = {s: sum(1 for c in claims if c.get("status") == s) for s in sorted(STATUS)}
  print("# Claims check: reports/%s/claims.jsonl" % name)
  print("%d claims (%s); %d problems" % (len(claims), ", ".join("%s %d" % kv for kv in n.items()), len(problems)))
  for p in problems:
    print(p)
  sys.exit(1 if problems else 0)


if __name__ == "__main__":
  main()
