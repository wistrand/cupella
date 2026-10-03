#!/usr/bin/env python3
"""Cross-check the Java call graph of units.py against androguard's cross-references.

units.py builds the call graph that structure-leads.py, flows.py, xref.py, and
behavior-map.py share: dex.py decodes each method's invokes, then units.py maps dex
methods to jadx functions, folds in methods jadx shows inline (lambdas, anonymous
classes, synthetic accessors), resolves virtual calls to overrides, and follows classes
a function creates or reads from a field. androguard (in the image with Quark) decodes
the same dex files independently. Two comparisons, for methods in the scan scope:

  invokes  dex.py's invoked methods per dex method vs. androguard's xref_to: a
           difference is a decoding error in one of them
  edges    units.py's function-to-function edges vs. androguard's direct calls lifted
           to the same functions, with the same folding through methods that have no
           jadx function. Edges only in units.py come from its heuristics and are
           grouped by which one plausibly made them:
             dispatch  the call names an overridden or interface method
             created   the target's class is created or read from a field
             other     neither: suspect
           Edges only in androguard are calls units.py lost.

A difference is a lead to check in the source, not a verdict on either tool.

Usage: ./cupella callgraph-check.py <name> [scope ...] [--show N]   (default scope: scan.txt's)
Output: work/<name>/callgraph-check.txt (counts and up to N examples per group, default 25)
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SELF = os.path.abspath(__file__)
VENV_PY = "/opt/tools/quarkenv/bin/python"  # androguard comes with Quark-Engine
FOLD_DEPTH = 4  # as units.py's expand()


def main():
  if os.path.exists(VENV_PY) and sys.executable != VENV_PY:
    os.execv(VENV_PY, [VENV_PY, SELF] + sys.argv[1:])
  args = sys.argv[1:]
  show = 25
  if "--show" in args:
    i = args.index("--show")
    show = int(args[i + 1])
    del args[i:i + 2]
  if not args:
    sys.exit(__doc__)
  name, scopes = args[0], args[1:]
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found" % name)
  sys.path.insert(0, os.path.dirname(SELF))
  import units
  if not scopes:
    scopes = units.load_script("quark-leads.py").scan_scope(work)
  scopes = [s for s in scopes if os.path.isdir(os.path.join(work, "jadx", "sources", s))]

  try:
    from loguru import logger
    logger.remove()  # androguard logs every class at debug level
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.dex import DEX
  except ImportError as ex:
    sys.exit("androguard not available (%s): it comes with Quark-Engine in the image" % ex)

  allu = units.java_units(work, scopes)
  if work not in units.DEX_INDEX:
    sys.exit("no dex call graph for %s (no raw/classes*.dex?)" % name)
  methods, _hier, units_for, _dispatch = units.DEX_INDEX[work]

  dx = Analysis()
  raw = os.path.join(work, "raw")
  dexes = sorted(f for f in os.listdir(raw) if re.match(r"classes\d*\.dex$", f))
  failed = []
  for f in dexes:
    try:
      with open(os.path.join(raw, f), "rb") as fh:
        dx.add(DEX(fh.read()))
    except Exception as ex:  # androguard raises many types on malformed dex
      failed.append("%s: %s" % (f, str(ex)[:120]))
  dx.create_xref()

  def key_of(ma):
    return "%s->%s%s" % (ma.class_name, ma.name, re.sub(r"\s+", "", str(ma.descriptor)))

  def norm(k):
    """androguard names an array's methods by the element type ([LFoo;->clone() as LFoo;)"""
    return k.lstrip("[")

  theirs = {}
  for ma in dx.get_methods():
    if ma.is_external():
      continue
    k = key_of(ma)
    if k in methods:
      theirs[k] = {norm(key_of(t)) for _c, t, _o in ma.get_xref_to()}

  # 1. invokes per dex method
  inv_diff = []
  compared = 0
  for k, m in methods.items():
    if not m.code or k not in theirs:
      continue
    compared += 1
    ours = {norm(t) for t in m.invokes}
    if ours != theirs[k]:
      inv_diff.append((k, sorted(ours - theirs[k]), sorted(theirs[k] - ours)))
  not_in_ag = sum(1 for k, m in methods.items() if m.code and k not in theirs)

  # 2. function edges, both folded through methods that have no jadx function
  def fold(start, nxt):
    found, seen, todo = set(), {start}, [(t, 1) for t in nxt(start)]
    while todo:
      t, depth = todo.pop()
      if t in seen:
        continue
      seen.add(t)
      us = units_for(t)
      if us:
        found.update(u.id for u in us)
      elif t in methods and depth <= FOLD_DEPTH:
        todo.extend((x, depth + 1) for x in nxt(t))
    return found

  by_id = {u.id: u for u in allu}
  keys_of = {}
  for k in methods:
    for u in units_for(k):
      keys_of.setdefault(u.id, []).append(k)
  ag_edges, our_edges = set(), set()
  for uid, ks in keys_of.items():
    for k in ks:
      for v in fold(k, lambda x: theirs.get(x, ())):
        if v != uid:
          ag_edges.add((uid, v))
    for v in by_id[uid].calls:
      if v in by_id:
        our_edges.add((uid, v))

  def sig(k):
    return k.split("->", 1)[1]

  def why(a, b):
    """which units.py heuristic plausibly made edge a -> b"""
    called = {sig(t) for k in keys_of.get(a, ()) for t in theirs.get(k, methods[k].invokes)}
    vk = keys_of.get(b, ())
    if any(sig(k) in called for k in vk):
      return "dispatch"
    vcls = {methods[k].cls for k in vk}
    seen = {methods[k].cls for k in keys_of.get(a, ())}
    for k in keys_of.get(a, ()):
      seen.update(methods[k].news)
      seen.update(getattr(methods[k], "fields", ()))
    return "created" if vcls & seen else "other"

  # classes with code and no jadx function: units.py folds all their methods into each
  # function that creates them or reads their static fields (meant for inlined lambdas)
  by_cls = {}
  for k, m in methods.items():
    by_cls.setdefault(m.cls, []).append(k)
  no_units = sorted(((c, len(ks), sum(1 for k in ks if methods[k].code)) for c, ks in by_cls.items()
                     if not any(units_for(k) for k in ks)), key=lambda x: -x[2])
  only_ours = sorted(our_edges - ag_edges)
  only_ag = sorted(ag_edges - our_edges)
  groups = {"dispatch": [], "created": [], "other": []}
  for a, b in only_ours:
    groups[why(a, b)].append((a, b))

  def where(uid):
    u = by_id[uid]
    return "%s.%s (%s)" % (u.cls, u.name, u.where)

  out = ["# Call graph check: %s" % name,
         "scope: %s" % " ".join(scopes),
         "androguard: %d dex files%s" % (len(dexes), "; failed: " + "; ".join(failed) if failed else ""),
         "",
         "## Invokes per dex method (dex.py vs. androguard)",
         "%d methods with code compared, %d differ; %d in-scope methods androguard did not list" % (
           compared, len(inv_diff), not_in_ag)]
  for k, mine, ag in inv_diff[:show]:
    out.append("- %s" % k)
    if mine:
      out.append("    dex.py only: %s" % ", ".join(mine[:5]))
    if ag:
      out.append("    androguard only: %s" % ", ".join(ag[:5]))
  both = len(our_edges & ag_edges)
  out += ["",
          "## Function edges (units.py vs. androguard direct calls, both folded)",
          "units.py %d, androguard %d, both %d; only units.py %d (dispatch %d, created %d, other %d); "
          "only androguard %d" % (len(our_edges), len(ag_edges), both, len(only_ours), len(groups["dispatch"]),
                                  len(groups["created"]), len(groups["other"]), len(only_ag))]
  for g, title in (("other", "Only units.py, no heuristic explains it (suspect)"),
                   ("created", "Only units.py, target class created or read from a field"),
                   ("dispatch", "Only units.py, override or interface dispatch")):
    out += ["", "### %s (%d)" % (title, len(groups[g]))]
    out += ["- %s -> %s" % (where(a), where(b)) for a, b in groups[g][:show]]
  out += ["", "## Classes with code but no jadx function (%d; units.py folds all their methods into "
          "functions that create them or read their static fields)" % len(no_units)]
  out += ["- %s  %d methods, %d with code" % x for x in no_units[:show]]
  out += ["", "### Only androguard: calls units.py lost (%d)" % len(only_ag)]
  out += ["- %s -> %s" % (where(a), where(b)) for a, b in only_ag[:show]]
  path = os.path.join(work, "callgraph-check.txt")
  with open(path, "w") as f:
    f.write("\n".join(out) + "\n")
  print("\n".join(out[:12]))
  print("wrote work/%s/callgraph-check.txt" % name)


if __name__ == "__main__":
  main()
