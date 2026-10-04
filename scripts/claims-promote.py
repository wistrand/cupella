#!/usr/bin/env python3
"""Promote a reader's draft claims into an analysis's claims.

A reader agent (prompts/read-area.md) cannot edit reports/; it writes its findings as
claim records to work/<name>/progress/<role>-claims.jsonl: the fields of claims-check.py,
with ids D1, D2, ... and status "draft". The main agent checks a draft's key steps in the
code, then promotes it: this script copies the named drafts into
reports/<name>/claims.jsonl with the next free ids (F<n>), status "confirmed" (or "draft"
with --draft, for one still to check), and "author" set to the role. It never changes a
claim already there. The previous claims.jsonl is kept as claims.jsonl.prev. Nothing is
written when a named draft is missing or fails the schema.

./cupella runs this in a container that sees only the draft file (read-only) and
reports/<name>/. Then: ./cupella claims-check.py <name>, ./cupella report-build.py <name>.

Usage: ./cupella claims-promote.py <name> <role> <D-id>... [--draft]
       ./cupella claims-promote.py <name> <role> --list     the drafts, one line each
"""
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def main():
  args = sys.argv[1:]
  as_draft, listing = "--draft" in args, "--list" in args
  args = [a for a in args if a not in ("--draft", "--list")]
  if len(args) < 2 or (len(args) < 3 and not listing):
    sys.exit(__doc__)
  name, role, want = args[0], args[1], args[2:]
  if not re.match(r"^[a-z0-9][a-z0-9-]{0,40}$", role):
    sys.exit("role must be lowercase letters, digits, and -")
  dpath = os.path.join(ROOT, "work", name, "progress", "%s-claims.jsonl" % role)
  cpath = os.path.join(ROOT, "reports", name, "claims.jsonl")
  if not os.path.isfile(dpath):
    sys.exit("no work/%s/progress/%s-claims.jsonl" % (name, role))
  drafts, problems = {}, []
  with open(dpath, errors="replace") as f:
    for n, line in enumerate(f, 1):
      if not line.strip():
        continue
      try:
        d = json.loads(line)
      except ValueError as e:
        problems.append("%s-claims.jsonl:%d: not JSON (%s)" % (role, n, e))
        continue
      if not isinstance(d, dict) or not re.match(r"^D\d+$", str(d.get("id", ""))):
        problems.append("%s-claims.jsonl:%d: id must be D<number>" % (role, n))
        continue
      if d["id"] in drafts:
        problems.append("%s-claims.jsonl:%d: duplicate id %s" % (role, n, d["id"]))
      drafts[d["id"]] = d
  if listing:
    for d in drafts.values():
      print("%s  %s  [%s]  %s" % (d["id"], d.get("confidence", "?"), d.get("threat", ""), str(d.get("title", ""))[:100]))
    for p in problems:
      print(p)
    return
  missing = [i for i in want if i not in drafts]
  if missing:
    problems.append("no draft %s in %s-claims.jsonl" % (", ".join(missing), role))
  existing = []
  if os.path.isfile(cpath):
    with open(cpath) as f:
      existing = [json.loads(x) for x in f if x.strip()]
  used = [int(c["id"][1:]) for c in existing if re.match(r"^F\d+$", str(c.get("id", "")))]
  nxt = max(used, default=0) + 1
  promoted = []
  for i in want:
    if i not in drafts:
      continue
    c = dict(drafts[i])
    c.pop("verdict", None)
    c["id"] = "F%d" % nxt
    nxt += 1
    c["status"] = "draft" if as_draft else "confirmed"
    c["author"] = "%s (%s)" % (role, i)
    promoted.append(c)
  # the schema of claims-check.py, on exactly what would be written
  cc = units.load_script("claims-check.py")
  tmp = os.path.join("/tmp", "claims-promote-check.jsonl")
  with open(tmp, "w") as f:
    for c in existing + promoted:
      f.write(json.dumps(c, ensure_ascii=True) + "\n")
  _claims, schema = cc.load(tmp)
  os.remove(tmp)
  # report a promoted draft by its draft id, not the F id it would get
  names = {c["id"]: c["author"].split("(")[1].rstrip(")") for c in promoted}
  for p in schema:
    m = re.match(r"^claims\.jsonl:\d+ (F\d+): (.*)$", p)
    problems.append("%s draft %s: %s" % (role, names[m.group(1)], m.group(2)) if m and m.group(1) in names else p)
  if problems:
    print("\n".join(problems))
    sys.exit("not promoted")
  if os.path.isfile(cpath):
    shutil.copyfile(cpath, cpath + ".prev")
  with open(cpath, "a") as f:
    for c in promoted:
      f.write(json.dumps(c, ensure_ascii=True) + "\n")
  for c in promoted:
    print("%s <- %s %s (%s)" % (c["id"], role, c["author"].split("(")[1].rstrip(")"), c["status"]))
  print("then: ./cupella claims-check.py %s; ./cupella report-build.py %s" % (name, name))


if __name__ == "__main__":
  main()
