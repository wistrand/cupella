#!/usr/bin/env python3
"""Behavior map of one function: how it is reached and what it reaches, as a Mermaid graph.

From the same call graph as structure-leads.py and xref.py: callers up to --up levels
(manifest component callbacks and native entry points marked as entry points), the
function itself, its direct callees, and deeper callees (to --down levels) that lead to a
capability (SMS, network, accessibility, ...; the capability labels of structure-leads.py),
with the capabilities as end nodes. Only functions in the scan scope appear. Writes work/<name>/maps/<function>.md: the Mermaid block to
paste under a report finding, then every node with its file and line for citations.

What the graph cannot show: calls through reflection, computed native pointers, and
dynamically loaded code. Names come from the APK and are untrusted: labels keep only
identifier characters.

Usage: ./cupella behavior-map.py <name> <Class.method | util/Foo.java:120> [--up N] [--down N] [--scope path ...]
       --up    caller levels (default 4, at most 6)      --down  callee levels (default 2, at most 4)
Output: work/<name>/maps/<Class.method>.md, and the same text on stdout.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sl = units.load_script("structure-leads.py")
xref = units.load_script("xref.py")
MAX_CALLERS = 10   # node budgets, so callers cannot crowd out what the function reaches
MAX_CALLEES = 12
FEW_CALLEES = 6    # at most this many direct callees: show them all
# component methods the system calls (structure-leads.py's wider on* pattern also catches app methods)
ENTRY = re.compile(r"^(onCreate|onStart|onResume|onNewIntent|onStartCommand|onBind|onHandleIntent|onReceive|"
                   r"onAccessibilityEvent|onNotificationPosted|onMessageReceived|onActivityResult|onDestroy|"
                   r"query|insert|update|delete|call|getType|openFile|doWork|handleMessage)$")


def label(text):
  """an APK-supplied name, reduced to characters that cannot break Mermaid or markdown"""
  return re.sub(r"[^A-Za-z0-9_.$:/ -]", "?", text)[:60]


def main():
  args = sys.argv[1:]
  up, down, scopes = 4, 2, None
  for flag, lim in (("--up", 6), ("--down", 4)):
    if flag in args:
      i = args.index(flag)
      val = max(0, min(lim, int(args[i + 1])))
      del args[i:i + 2]
      if flag == "--up":
        up = val
      else:
        down = val
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
  scopes = [s for s in scopes if os.path.isdir(os.path.join(work, "jadx", "sources", s))]
  allu = units.java_units(work, scopes) + units.dart_units(work, name) + units.native_units(work)
  hits = xref.find(allu, q)
  m = re.match(r"^(?:jadx/sources/)?([\w$.-]+)/[\w/$.-]+\.java:\d+$", q)
  if not hits and m and os.path.isdir(os.path.join(work, "jadx", "sources", m.group(1))):
    # a target outside the scan scope (R8 often moves app code): add its top package
    scopes = scopes + [m.group(1)]
    print("(target outside the scan scope: added %s/)" % m.group(1), file=sys.stderr)
    allu = units.java_units(work, scopes) + units.dart_units(work, name) + units.native_units(work)
    hits = xref.find(allu, q)
  by_id, callers = units.callers_of(allu, with_async=True)
  if not hits:
    sys.exit("no function matches %s (Java scope: %s)" % (q, " ".join(scopes)))
  if len(hits) > 1:
    sys.exit("%d functions match %s; give one as a file and line:\n%s" % (
      len(hits), q, "\n".join("  " + u.where for u in hits[:20])))
  target = hits[0]

  ns = units.load_script("native-summary.py")
  _pkg, comps = sl.manifest_components(work)
  caps_cache = {}

  def caps(u):
    if u.id not in caps_cache:
      caps_cache[u.id] = sl.strong(sl.own_caps(u, ns.STRING_CATEGORIES, ns.IMPORT_CATEGORIES))
    return caps_cache[u.id]

  def entry(u):
    if u.kind == "java":
      comp = u.file[len("jadx/sources/"):-5]
      if comp in comps and ENTRY.match(u.name):
        return "%s %s" % (comps[comp], u.name)
    elif u.kind == "native" and (u.name.startswith(("jni_", "Java_", "init_")) or u.name in ("JNI_OnLoad", "entry")):
      return "native entry"
    return None

  nodes, edges = {target.id: target}, set()
  # callers, breadth first, nearest levels first, capped
  frontier, n_callers, cut_up = [target], 0, False
  for _ in range(up):
    nxt = []
    for v in frontier:
      for cid in sorted(callers.get(v.id, ())):
        if cid not in by_id:
          continue
        if cid not in nodes and n_callers >= MAX_CALLERS:
          cut_up = True
          continue
        edges.add((cid, v.id))
        if cid not in nodes:
          n_callers += 1
          nodes[cid] = by_id[cid]
          if not entry(by_id[cid]):
            nxt.append(by_id[cid])
    frontier = nxt
  # callees that carry a capability, or lead to one within the remaining depth
  def leads_to_cap(u, depth, seen):
    if caps(u):
      return True
    if depth == 0:
      return False
    for cid in units.callees(u) | u.refs | u.async_:
      if cid in by_id and cid not in seen:
        seen.add(cid)
        if leads_to_cap(by_id[cid], depth - 1, seen):
          return True
    return False

  frontier, n_callees, reached = [target], 0, {target.id}
  few = len([c for c in units.callees(target) | target.refs | target.async_ if c in by_id]) <= FEW_CALLEES
  cut = False
  for level in range(down):
    nxt = []
    for v in frontier:
      for cid in sorted(units.callees(v) | v.refs | v.async_):
        if cid not in by_id:
          continue
        w = by_id[cid]
        # all direct callees when there are few; otherwise only those on a path to a capability
        if not (level == 0 and few) and not leads_to_cap(w, down - level - 1, {cid}):
          continue
        if n_callees >= MAX_CALLEES and cid not in nodes:
          cut = True
          continue
        n_callees += cid not in nodes
        reached.add(cid)
        edges.add((v.id, cid))
        if cid not in nodes:
          nodes[cid] = w
          nxt.append(w)
    frontier = nxt

  ids = {uid: "n%d" % i for i, uid in enumerate(nodes)}
  lines = ["```mermaid", "flowchart LR"]
  cap_nodes = {}
  for uid, u in nodes.items():
    text = "%s :%d" % (label(xref.short(u)), u.start)
    why = entry(u)
    if uid == target.id:
      lines.append('  %s[["%s"]]' % (ids[uid], text))
    elif why:
      lines.append('  %s(["%s<br/>%s"])' % (ids[uid], label(why), text))
    else:
      lines.append('  %s["%s"]' % (ids[uid], text))
  for a, b in sorted(edges):
    u = nodes[a]
    if b in u.calls | u.refs:
      lines.append("  %s --> %s" % (ids[a], ids[b]))
    elif b in u.far:
      lines.append("  %s -. outside .-> %s" % (ids[a], ids[b]))  # through a method outside the scope
    elif b in u.async_:
      lines.append("  %s -. later .-> %s" % (ids[a], ids[b]))  # handed to a thread or looper
    else:
      lines.append("  %s --> %s" % (ids[a], ids[b]))
  # capabilities as end nodes, for the target and its callees
  for uid in sorted(reached, key=lambda x: ids[x]):
    u = nodes[uid]
    for c in caps(u):
      if c not in cap_nodes:
        cap_nodes[c] = "c%d" % len(cap_nodes)
        lines.append('  %s(("%s"))' % (cap_nodes[c], label(c)))
      lines.append("  %s -.-> %s" % (ids[uid], cap_nodes[c]))
  lines.append("```")

  out = ["# Behavior map: %s" % label(xref.short(target)), ""]
  out.append("Callers up to %d levels (entry points rounded), direct callees, deeper callees on a path to a capability, up to %d levels." % (up, down))
  out.append("Calls through reflection, native pointers, or loaded code are not in the graph. A dotted")
  out.append("\"later\" edge is a Runnable or Handler held in a field or the object itself, handed to a")
  out.append("thread, executor, or looper by that function: check in the code that it is that object.")
  out.append("A dotted \"outside\" edge passes through one method outside the scanned scope (a class")
  out.append("created there, a callback): read that code before relying on the edge.")
  out.append("")
  out += lines
  out.append("")
  out.append("Nodes (cite these):")
  for uid, u in nodes.items():
    why = entry(u)
    cite = u.where.split(" ")[0] if u.kind == "java" else "%s` `%s" % (u.file, u.name)
    out.append("- `%s`%s%s" % (cite, "  (target)" if uid == target.id else "",
                                "  (entry point: %s)" % label(why) if why else ""))
  if cut or cut_up:
    out.append("")
    out.append("Cut at %d callers and %d callees; narrow with --up or --down." % (MAX_CALLERS, MAX_CALLEES))
  text = "\n".join(out) + "\n"
  mapdir = os.path.join(work, "maps")
  os.makedirs(mapdir, exist_ok=True)
  fn = re.sub(r"[^A-Za-z0-9_.$-]", "_", xref.short(target))[:120] + ".md"
  with open(os.path.join(mapdir, fn), "w") as f:
    f.write(text)
  sys.stdout.write(text)
  print("(written to work/%s/maps/%s)" % (name, fn))


if __name__ == "__main__":
  main()
