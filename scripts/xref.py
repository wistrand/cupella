#!/usr/bin/env python3
"""Callers and callees of a function, from the same call graph as structure-leads.

Java calls come from the dex bytecode (exact, lambdas folded into their creator),
native calls from Ghidra output (direct calls and address-taken functions), Dart
calls from blutter's annotations. See units.py.

Usage: ./cupella xref.py <name> <query> [--depth N] [--scope path ...]
  query  Java: Class.method, Class (all its methods), or a jadx file path with line
           (util/Foo.java:120);
         native: FUN_00012eb4, jni_..., JNI_OnLoad;  Dart: Class::method
  --depth  levels of callers and callees to show (default 1, at most 3)
  --scope  Java scope under jadx/sources (default: scope.py)
Output: stdout. Callers marked <-, callees ->, external API calls (Java) as "calls".
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def short(u):
  if u.kind == "java":
    return "%s.%s" % (u.cls, u.name)
  return u.id.split(":", 1)[1] if u.kind == "dart" else u.name


def find(allu, q):
  m = re.match(r"^(?:jadx/sources/)?([\w/$.-]+\.java):(\d+)$", q)
  if m:
    line = int(m.group(2))
    return [u for u in allu if u.kind == "java" and u.file.endswith(m.group(1)) and u.start <= line <= u.end]
  if "::" in q:
    return [u for u in allu if u.kind == "dart" and (u.id == "dart:" + q or u.id.endswith(":" + q))]
  if re.match(r"^(FUN_[0-9a-f]+|jni_\w+|JNI_OnLoad|init_\d+|entry)$", q):
    return [u for u in allu if u.kind == "native" and u.name == q]
  if "." in q:
    cls, meth = q.rsplit(".", 1)
    return [u for u in allu if u.kind == "java" and u.cls == cls and u.name == meth]
  return [u for u in allu if u.kind == "java" and u.cls == q]


def main():
  args = sys.argv[1:]
  depth, scopes = 1, None
  if "--depth" in args:
    i = args.index("--depth")
    depth = max(1, min(3, int(args[i + 1])))
    del args[i:i + 2]
  if "--scope" in args:
    i = args.index("--scope")
    scopes = args[i + 1:]
    del args[i:]
  if len(args) < 2:
    sys.exit(__doc__)
  name, q = args[0], args[1]
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found" % name)
  scopes = scopes or units.load_script("scope.py").scopes(work)
  allu = units.java_units(work, scopes) + units.dart_units(work, name) + units.native_units(work)
  by_id, callers = units.callers_of(allu)
  hits = find(allu, q)
  if not hits:
    sys.exit("no function matches %s (Java scope: %s)" % (q, " ".join(scopes)))

  def tree(u, nxt, mark, level, seen):
    for cid in sorted(nxt(u), key=lambda c: by_id[c].where if c in by_id else c):
      if cid not in by_id:
        continue
      v = by_id[cid]
      print("%s%s %s  %s" % ("  " * level, mark, short(v), v.where))
      if level < depth and cid not in seen:
        seen.add(cid)
        tree(v, nxt, mark, level + 1, seen)

  for u in hits[:20]:
    print("%s  %s" % (short(u), u.where))
    tree(u, lambda x: callers.get(x.id, ()), "<-", 1, {u.id})
    tree(u, lambda x: x.calls | x.refs, "->", 1, {u.id})
    ext = sorted(u.ext)
    if ext:
      print("  calls: %s%s" % (", ".join(ext[:25]), " ... +%d" % (len(ext) - 25) if len(ext) > 25 else ""))
    print()
  if len(hits) > 20:
    print("... %d more matches" % (len(hits) - 20))


if __name__ == "__main__":
  main()
