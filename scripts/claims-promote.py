#!/usr/bin/env python3
"""Promote a reader's draft claims into an analysis's claims.

A reader agent (prompts/read-area.md) cannot edit reports/; it writes its findings as
claim records, one file each: work/<name>/progress/<role>-claims/D<n>.json, a JSON object
with the fields of claims-check.py, id D<n> as in the file name, and status "draft". One
record per file means a reader adds a claim without resending the earlier ones, and a
write that fails loses that claim only. The form before 2026-10-04, one object per line
in work/<name>/progress/<role>-claims.jsonl, is still read (both may exist; an id in both
is a problem). The main agent checks a draft's key steps in the code, then promotes it:
this script copies the named drafts into reports/<name>/claims.jsonl with the next free
ids (F<n>), status "confirmed" (or "draft" with --draft, for one still to check), and
"author" set to the role. It never changes a claim already there. The previous
claims.jsonl is kept as claims.jsonl.prev. Nothing is written when a named draft is
missing, is not JSON, or fails the schema; a broken draft that was not named, in a file of
its own, does not stop the others.

./cupella runs this in a container that sees only the drafts (read-only) and
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


def records(ddir, dpath, role):
  """[(where, text, id from the file name or None)] of the drafts: the files D<n>.json of
  <role>-claims/ in number order, then the lines of <role>-claims.jsonl"""
  out = []
  if os.path.isdir(ddir):
    names = [f for f in os.listdir(ddir) if re.match(r"^D\d+\.json$", f)]
    for f in sorted(names, key=lambda x: int(x[1:-5])):
      p = os.path.join(ddir, f)
      if os.path.islink(p) or not os.path.isfile(p):
        continue
      with open(p, errors="replace") as fh:
        out.append(("%s-claims/%s" % (role, f), fh.read(), f[:-5]))
  if os.path.isfile(dpath):
    with open(dpath, errors="replace") as fh:
      for n, line in enumerate(fh, 1):
        if line.strip():
          out.append(("%s-claims.jsonl:%d" % (role, n), line, None))
  return out


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
  ddir = os.path.join(ROOT, "work", name, "progress", "%s-claims" % role)
  cpath = os.path.join(ROOT, "reports", name, "claims.jsonl")
  if not os.path.isfile(dpath) and not os.path.isdir(ddir):
    sys.exit("no work/%s/progress/%s-claims/ (or %s-claims.jsonl)" % (name, role, role))
  # found: (draft id or None when the record does not say, problem); a problem with an id
  # stops only a promotion that names it
  drafts, found = {}, []
  for where, text, stem in records(ddir, dpath, role):
    try:
      d = json.loads(text)
    except ValueError as e:
      found.append((stem, "%s: not JSON (%s)" % (where, e)))
      continue
    if not isinstance(d, dict) or not re.match(r"^D\d+$", str(d.get("id", ""))):
      found.append((stem, "%s: id must be D<number>" % where))
      continue
    if stem and d["id"] != stem:
      found.append((stem, "%s: id %s differs from the file name" % (where, d["id"])))
      continue
    if d["id"] in drafts:
      found.append((d["id"], "%s: duplicate id %s" % (where, d["id"])))
    drafts[d["id"]] = d
  if listing:
    for d in drafts.values():
      print("%s  %s  [%s]  %s" % (d["id"], d.get("confidence", "?"), d.get("threat", ""), str(d.get("title", ""))[:100]))
    for _i, p in found:
      print(p)
    return
  problems = [p for i, p in found if i is None or i in want]
  missing = [i for i in want if i not in drafts and not any(j == i for j, _p in found)]
  if missing:
    problems.append("no draft %s in %s-claims/ or %s-claims.jsonl" % (", ".join(missing), role, role))
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
