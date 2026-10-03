#!/usr/bin/env python3
"""Check the Java call graph of units.py against androguard's cross-references.

units.py builds the call graph that structure-leads.py, flows.py, xref.py, and
behavior-map.py share. dex.py decodes each method's invokes; units.py maps dex methods
to jadx functions and gives each function
  calls   what its own code calls: the method and the methods without a function of
          their own that it runs (lambdas, anonymous classes, synthetic methods: code
          jadx shows inline), with virtual calls resolved to the methods that can run
  far     functions reached only through code outside the scanned scope, with the
          number of method hops through that code
androguard (in the image with Quark) decodes the same dex files independently. Checks,
for methods in the dex index of the scope:

  invokes   dex.py's invoked methods per dex method vs. androguard's xref_to. A
            difference is a decoding error in one of them.
  mapping   every dex method with code in a class that has functions should have one
            function, or be of a kind jadx shows no function for; every function
            should have one dex method. Lists what does not fit.
  direct    androguard's calls of each function's own code (the same inline folding,
            no call resolution) must all be in calls: "lost" must be 0. Calls only
            units.py has are split by the rule that made them:
              resolved  the call names an inherited, abstract, or interface method
              created   the function creates the class (or reads it from a static
                        field) whose methods then run
  far       counts by hops; these have no reference, they are a bounded closure

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
NO_FUNCTION = (("<clinit>", "static initializer"), ("<init>", "constructor not shown"),
               ("values", "enum values"), ("valueOf", "enum valueOf"))


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

  units.OUT_DEPTH = 4  # count what lies further than the hops that leads use
  allu = units.java_units(work, scopes)
  if work not in units.DEX_INDEX:
    sys.exit("no dex call graph for %s (no raw/classes*.dex?)" % name)
  methods, _hier, units_for, _dispatch = units.DEX_INDEX[work]
  g = units.GRAPH[work]
  successors, outside, has_units, by_cls = g["successors"], g["outside"], g["has_units"], g["by_cls"]

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

  by_id = {u.id: u for u in allu}

  def where(uid):
    u = by_id[uid]
    return "%s.%s (%s)" % (u.cls, u.name, u.where)

  out = ["# Call graph check: %s" % name,
         "scope: %s" % " ".join(scopes),
         "androguard: %d dex files%s" % (len(dexes), "; failed: " + "; ".join(failed) if failed else "")]

  # 1. invokes per dex method
  inv_diff, compared = [], 0
  for k, m in methods.items():
    if not m.code or k not in theirs:
      continue
    compared += 1
    ours = {norm(t) for t in m.invokes}
    if ours != theirs[k]:
      inv_diff.append((k, sorted(ours - theirs[k]), sorted(theirs[k] - ours)))
  not_in_ag = sum(1 for k, m in methods.items() if m.code and k not in theirs)
  out += ["", "## Invokes per dex method (dex.py vs. androguard)",
          "%d methods with code compared, %d differ; %d methods androguard did not list" % (
            compared, len(inv_diff), not_in_ag)]
  for k, mine, ag in inv_diff[:show]:
    out.append("- %s" % k)
    if mine:
      out.append("    dex.py only: %s" % ", ".join(mine[:5]))
    if ag:
      out.append("    androguard only: %s" % ", ".join(ag[:5]))

  # 2. mapping between dex methods and jadx functions
  keys_of = {}
  for k in methods:
    for u in units_for(k):
      keys_of.setdefault(u.id, []).append(k)
  one = many = 0
  none, ambiguous = {}, []
  for cls, ks in by_cls.items():
    if not has_units[cls]:
      continue
    for k in ks:
      m = methods[k]
      if not m.code:
        continue
      us = units_for(k)
      if len(us) == 1:
        one += 1
      elif us:
        many += 1
        ambiguous.append(k)
      else:
        kind = "bridge" if m.flags & 0x40 else "synthetic" if m.flags & 0x1000 else \
            "lambda body" if "lambda$" in m.name else \
            next((label for prefix, label in NO_FUNCTION if m.name.startswith(prefix)), "other")
        none.setdefault(kind, []).append(k)
  orphans = sorted(u.id for u in allu if u.id not in keys_of)
  shared = sorted(uid for uid, ks in keys_of.items() if len(ks) > 1)
  n_none = sum(len(v) for v in none.values())
  out += ["", "## Mapping (dex methods with code, in classes that have functions)",
          "%d methods: one function %d, several functions %d, no function %d (%s)" % (
            one + many + n_none, one, many, n_none,
            ", ".join("%s %d" % (k, len(v)) for k, v in sorted(none.items(), key=lambda kv: -len(kv[1]))) or "none"),
          "%d functions: without a dex method %d, shared by several dex methods %d" % (
            len(allu), len(orphans), len(shared))]
  out += ["", "### Methods with several functions (%d)" % many]
  out += ["- %s: %s" % (k, "; ".join(u.where for u in units_for(k)[:4])) for k in ambiguous[:show]]
  out += ["", "### Methods with code and no function, kind 'other' (%d)" % len(none.get("other", ()))]
  out += ["- %s" % k for k in none.get("other", ())[:show]]
  # why a function has no dex method: its class, its name, or its parameters
  why = {}
  for uid in orphans:
    u = by_id[uid]
    cls = "L%s;" % u.inner.replace(".", "/")
    if cls not in by_cls:
      reason = "class not in the dex index"
    elif not any(methods[k].name in (u.bname, "<init>" if uid in g["ctors"] else u.bname) for k in by_cls[cls]):
      reason = "class has no method of that name"
    else:
      reason = "parameters do not match"
    why.setdefault(reason, []).append(uid)
  out += ["", "### Functions without a dex method (%d: %s)" % (
    len(orphans), ", ".join("%s %d" % (r, len(v)) for r, v in sorted(why.items())) or "none")]
  for reason, uids in sorted(why.items()):
    for uid in uids[:show]:
      u = by_id[uid]
      out.append("- [%s] %s  class %s, bytecode name %s: %s" % (reason, u.where, u.inner, u.bname, (u.meta or "")[:90]))
      if reason == "parameters do not match":
        want = "<init>" if uid in g["ctors"] else u.bname
        for k in by_cls["L%s;" % u.inner.replace(".", "/")]:
          if methods[k].name == want:
            out.append("    dex: %s  flags 0x%x%s" % (k.split("->", 1)[1], methods[k].flags,
                                                     "  -> " + units_for(k)[0].where if units_for(k) else ""))
  out += ["", "### Functions shared by several dex methods (%d)" % len(shared)]
  out += ["- %s: %s" % (by_id[uid].where, ", ".join(keys_of[uid][:4])) for uid in shared[:show]]

  # 3. direct calls: androguard's calls of each function's own code must be in calls
  def own_calls(key, nxt):
    """functions reached from method key through methods without a function that are not
    outside the scope (the function's own code), as units.py's expand() does"""
    found, seen, frontier = set(), {key}, [key]
    for _ in range(units.IN_DEPTH + 1):
      step = []
      for k in frontier:
        for t in nxt(k):
          us = units_for(t)
          if us:
            found.update(u.id for u in us)
          elif t not in seen and t in methods and not outside(methods[t].cls):
            seen.add(t)
            step.append(t)
      frontier = step
    return found

  ref, resolved, ours, far = set(), set(), set(), {}
  for uid, ks in keys_of.items():
    for k in ks:
      ref.update((uid, v) for v in own_calls(k, lambda x: theirs.get(x, ())) if v != uid)
      resolved.update((uid, v) for v in own_calls(k, lambda x: [t for t, via in successors(x) if via is None])
                      if v != uid)
    u = by_id[uid]
    ours.update((uid, v) for v in u.calls)
    for v, hop in u.far.items():
      far[(uid, v)] = hop
  lost = sorted(ref - ours)
  only_resolved = sorted((ours & resolved) - ref)
  only_created = sorted(ours - resolved - ref)
  out += ["", "## Direct calls (calls vs. androguard's calls of the function's own code)",
          "units.py %d, androguard %d, both %d; lost %d; only units.py %d (resolved %d, created %d)" % (
            len(ours), len(ref), len(ours & ref), len(lost), len(ours - ref), len(only_resolved), len(only_created))]
  for title, rows in (("Lost: androguard has the call, units.py does not", lost),
                      ("Only units.py, created class", only_created),
                      ("Only units.py, resolved call", only_resolved)):
    out += ["", "### %s (%d)" % (title, len(rows))]
    out += ["- %s -> %s" % (where(a), where(b)) for a, b in rows[:show]]

  # 4. calls through code outside the scope
  hops = {}
  for hop in far.values():
    hops[hop] = hops.get(hop, 0) + 1
  kinds = {"outside the scope": 0, "inline, no source file": 0, "inline, in a scanned file": 0}
  src = os.path.join(work, "jadx", "sources")
  for cls in by_cls:
    if has_units[cls]:
      continue
    if outside(cls):
      kinds["outside the scope"] += 1
    else:
      top = cls[1:-1].split("$")[0]
      rel = (top if "/" in top else "defpackage/" + top) + ".java"
      kinds["inline, in a scanned file" if os.path.isfile(os.path.join(src, rel)) else "inline, no source file"] += 1
  out += ["", "## Calls through code outside the scope (far; leads use up to %d hop%s)" % (
            units.FAR_HOPS, "" if units.FAR_HOPS == 1 else "s"),
          "%d edges; by hops: %s" % (len(far), ", ".join("%d: %d" % (h, hops[h]) for h in sorted(hops)) or "none"),
          "classes without functions: %s" % ", ".join("%s %d" % kv for kv in kinds.items())]
  out += ["- %s -> %s  (%d hops)" % (where(a), where(b), h) for (a, b), h in sorted(far.items())[:show]]

  path = os.path.join(work, "callgraph-check.txt")
  with open(path, "w") as f:
    f.write("\n".join(out) + "\n")
  print("\n".join(l for l in out if re.match(r"^(#|scope|androguard|\d|units\.py|classes)", l)))
  print("wrote work/%s/callgraph-check.txt" % name)


if __name__ == "__main__":
  main()
