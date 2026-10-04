#!/usr/bin/env python3
"""Behavior facts: what the app's entry points reach, what gates it, what it exchanges.

A citable digest for the Findings section, from the same call graph as structure-leads.py.
Deterministic; every line names its path and line. Facts about the code, not findings:
a line here says that code exists and how the graph connects it, never what it means or
that it runs. Read the code behind each line before a finding rests on it.

Sections of work/<name>/behavior-facts.txt:
  components      each manifest component: kind, exported, launcher, intent actions,
                  and whether its class is in the dex (a missing launcher class means the
                  app cannot start as shipped; dex classes with the same simple name listed)
  entry points    manifest component callbacks, @JavascriptInterface methods, and
                  callbacks no scanned code calls (on* methods a library or the system
                  calls); for each, the APIs of the table below it reaches, one chain each
  unreached       functions that use a listed API but that no entry point reaches in the
                  call graph (dead code, or reached through reflection or a library)
  permission gates  per API the permission it needs and whether the manifest requests it
  messages        per function: JSON keys written and read, string literals compared
  webview         settings, JavaScript interface names, loadUrl and evaluateJavascript
                  arguments (script text shortened)

What the graph cannot show: reflection, native pointers, loaded code, and listeners a
library calls. Strings from the APK are untrusted: printed shortened, with characters
that could break markdown replaced.

Usage: ./cupella behavior-facts.py <name> [--depth N] [java-scope ...]
       --depth     call levels from an entry point (default 5, at most 8)
       java-scope  under jadx/sources (default: scope.py); scan.sh passes its scope
Output: work/<name>/behavior-facts.txt. facts.py calls compute() for the "behavior" part
of facts.json, which report-render.py turns into report tables.
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
A = "{http://schemas.android.com/apk/res/android}"
MAX_ITEMS = 40

# (label, pattern, permissions any one of which it needs or None). The pattern is matched on a
# function's own text and on the platform APIs its bytecode calls (units.py ext, written as
# "Class.method(" and "new Class(": this finds calls jadx shows in synthetic lambdas)
APIS = [
  ("NFC tag access", r"\bIsoDep\.get\(|\bNfcA\.get\(|\bNfcB\.get\(|\bMifareClassic\.get\(|\bNdef\.get\(", ["android.permission.NFC"]),
  ("NFC APDU exchange", r"\.transceive\(", ["android.permission.NFC"]),
  ("NFC dispatch", r"enableForegroundDispatch\(|enableReaderMode\(", ["android.permission.NFC"]),
  ("NFC card emulation", r"\bHostApduService\b|processCommandApdu\(|sendResponseApdu\(", ["android.permission.NFC"]),
  ("WebSocket", r"\bnewWebSocket\(|\bWebSocketClient\b", ["android.permission.INTERNET"]),
  ("WebSocket send", r"\b\w*[wW]eb[sS]ocket\w*\.send\(", ["android.permission.INTERNET"]),
  ("HTTP", r"\.newCall\(|openConnection\(|\bHttpURLConnection\b", ["android.permission.INTERNET"]),
  ("socket", r"\bnew (?:Socket|DatagramSocket|ServerSocket)\(", ["android.permission.INTERNET"]),
  ("WebView load", r"\.loadUrl\(|\.loadData(?:WithBaseURL)?\(|\.postUrl\(", ["android.permission.INTERNET"]),
  ("WebView JavaScript bridge", r"addJavascriptInterface\(", None),
  ("WebView script injection", r"evaluateJavascript\(", None),
  ("SMS send", r"\bsendTextMessage\(|\bsendMultipartTextMessage\(|\bsendDataMessage\(", ["android.permission.SEND_SMS"]),
  ("SMS read", r"content://sms|Telephony\.Sms\b", ["android.permission.READ_SMS"]),
  ("contacts", r"ContactsContract\b", ["android.permission.READ_CONTACTS"]),
  ("call log", r"\bCallLog\b", ["android.permission.READ_CALL_LOG"]),
  ("phone identifiers", r"TelephonyManager\.getDeviceId\(|\.getImei\(|\.getSubscriberId\(|\.getLine1Number\(|\.getSimSerialNumber\(",
   ["android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"]),
  ("location", r"getLastKnownLocation\(|requestLocationUpdates\(|getCurrentLocation\(|FusedLocationProviderClient",
   ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"]),
  ("camera", r"\bCamera\.open\(|CameraManager\b|openCamera\(", ["android.permission.CAMERA"]),
  ("microphone", r"\bAudioRecord\b|\bMediaRecorder\b", ["android.permission.RECORD_AUDIO"]),
  ("installed apps", r"getInstalledPackages\(|getInstalledApplications\(|queryIntentActivities\(", None),
  ("overlay window", r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT", ["android.permission.SYSTEM_ALERT_WINDOW"]),
  ("accessibility", r"getRootInActiveWindow\(|performGlobalAction\(|dispatchGesture\(|AccessibilityNodeInfo\.performAction\(|\bACTION_SET_TEXT\b", None),
  ("package install", r"\bPackageInstaller\b|application/vnd\.android\.package-archive", ["android.permission.REQUEST_INSTALL_PACKAGES"]),
  ("foreground service", r"startForeground\(|startForegroundService\(", ["android.permission.FOREGROUND_SERVICE"]),
  ("ANDROID_ID", r"\"android_id\"|Settings\.Secure\.ANDROID_ID", None),
  ("device model", r"\bBuild\.(?:MODEL|MANUFACTURER|FINGERPRINT|BRAND|DEVICE|PRODUCT)\b", None),
  ("clipboard", r"getPrimaryClip\(|setPrimaryClip\(", None),
  ("process", r"Runtime\.getRuntime\(\)\.exec|\bProcessBuilder\b", None),
  ("code loading", r"\bDexClassLoader\b|\bInMemoryDexClassLoader\b|System\.load(?:Library)?\(", None),
  ("crypto", r"Cipher\.getInstance\(|SecretKeySpec\b", None),
  ("Base64", r"\bBase64\.(?:decode|encode\w*)\(", None),
]
APIS = [(lab, re.compile(p), perms) for lab, p, perms in APIS]
COMPONENT_ENTRY = re.compile(r"^(onCreate|onStart|onResume|onNewIntent|onStartCommand|onBind|onHandleIntent|"
                             r"onReceive|onAccessibilityEvent|onServiceConnected|onNotificationPosted|"
                             r"onMessageReceived|onActivityResult|processCommandApdu|onTagDiscovered|"
                             r"query|insert|update|delete|call|getType|openFile|doWork|handleMessage)$")
CALLBACK = re.compile(r"^(?:on[A-Z]\w*|shouldOverrideUrlLoading|shouldInterceptRequest)$")
# an R8-merged lambda class: its run/accept/invoke switches on a field set by the constructor
MERGED = re.compile(r"^\s*switch \(this\.\w+\) \{")
JSON_PUT = re.compile(r"\.(?:put|putOpt|accumulate|addProperty)\(\"([^\"]{1,60})\"")
JSON_GET = re.compile(r"\.(?:get|opt|has|isNull|remove)(?:String|Int|Long|Boolean|Double|JSONObject|JSONArray)?\(\"([^\"]{1,60})\"")
COMPARED = re.compile(r"\"([^\"]{1,60})\"\.(?:equals|equalsIgnoreCase)\(|\.(?:equals|equalsIgnoreCase|startsWith|endsWith|contains)\(\"([^\"]{1,60})\"\)|case \"([^\"]{1,60})\":")
WV_SETTING = re.compile(r"getSettings\(\)\.(set\w+)\(([^)]{0,40})\)")
JS_IFACE = re.compile(r"addJavascriptInterface\((.{1,80}?),\s*\"([^\"]{1,40})\"\)")
# calls on a field whose declared type is the given one (obfuscated field names hide the type)
TYPED = [("WebSocket send", re.compile(r"(?:^|\.)WebSocket$"), "send")]
FIELD = re.compile(r"^\s*(?:(?:public|private|protected|static|final|volatile|transient)\s+)*([\w.$]+)(?:<[^>]*>)?\s+(\w+)\s*[;=]")
NET = {"WebSocket", "WebSocket send", "HTTP", "socket"}
FRAMEWORK_KEY = re.compile(r"^(?:android|androidx)[.:-]")
LOAD = re.compile(r"\.(loadUrl|evaluateJavascript|loadDataWithBaseURL|postUrl)\((.{0,200})")


def clean(text, n=80):
  """APK-supplied text, shortened, with characters that could break markdown or a terminal replaced"""
  text = re.sub(r"[^\x20-\x7e]", "?", text).replace("`", "'")
  return text if len(text) <= n else text[:n] + "..."


def parent_of(work):
  """work/<parent> of a child sample work/<parent>.dec<k> or .emb<k>, else None"""
  m = re.match(r"(.+)\.(?:dec|emb)\d+$", os.path.basename(work.rstrip("/")))
  return os.path.join(os.path.dirname(work.rstrip("/")), m.group(1)) if m else None


def manifest(work):
  """(package, [component dicts], manifest path, [requested permissions]); empty without one.
  A child sample has no manifest: it runs in its parent's process, under the parent's."""
  for rel in ("manifest.xml", "apktool/AndroidManifest.xml"):
    path = os.path.join(work, rel)
    if not os.path.isfile(path) or not os.path.getsize(path):
      continue
    try:
      root = ET.parse(path).getroot()
    except ET.ParseError:
      continue
    pkg = root.get("package", "")
    app = root.find("application")
    comps = []
    perms = [p.get(A + "name", "") for t in ("uses-permission", "uses-permission-sdk-23") for p in root.findall(t)]
    if app is None:
      return pkg, comps, rel, perms
    for kind in ("application", "activity", "activity-alias", "service", "receiver", "provider"):
      elems = [app] if kind == "application" else app.findall(kind)
      for e in elems:
        attr = "targetActivity" if kind == "activity-alias" else "name"
        name = e.get(A + attr)
        if not name:
          continue
        if name.startswith("."):
          name = pkg + name
        elif "." not in name:
          name = pkg + "." + name
        actions = [a.get(A + "name", "") for f in e.findall("intent-filter") for a in f.findall("action")]
        cats = [c.get(A + "name", "") for f in e.findall("intent-filter") for c in f.findall("category")]
        exp = e.get(A + "exported")
        comps.append({
          "kind": kind, "name": name, "actions": actions,
          "launcher": "android.intent.category.LAUNCHER" in cats,
          "exported": exp if exp is not None else ("implicit" if actions else "false"),
          "permission": e.get(A + "permission", ""),
        })
        if kind == "application":
          for key in ("appComponentFactory",):
            if e.get(A + key):
              comps.append({"kind": key, "name": e.get(A + key), "actions": [], "launcher": False,
                            "exported": "", "permission": ""})
    return pkg, comps, rel, perms
  parent = parent_of(work)
  if parent and os.path.isdir(parent):
    pkg, comps, rel, perms = manifest(parent)
    return pkg, comps, rel and "../%s/%s" % (os.path.basename(parent), rel), perms
  return "", [], None, []


def dex_classes(work):
  """{class name: sample it is in} for this sample, its parent, and the parent's other
  children (payloads found or decrypted run in the same process as the APK)"""
  base = work.rstrip("/")
  root = base
  while parent_of(root):
    root = parent_of(root)
  dirs = [root] + sorted(os.path.join(os.path.dirname(root), d) for d in os.listdir(os.path.dirname(root))
                         if re.match(re.escape(os.path.basename(root)) + r"(?:\.(?:dec|emb)\d+)+$", d))
  out = {}
  for d in [base] + [x for x in dirs if x != base]:
    path = os.path.join(d, "dex", "classes.txt")
    if os.path.isfile(path):
      with open(path, errors="replace") as f:
        for line in f:
          parts = line.rstrip("\n").split("\t")
          if len(parts) >= 2:
            out.setdefault(parts[1], os.path.basename(d))
  return out


FIELD_MEMO = {}


def field_types(work, u):
  """{field name: declared type} of the file a function is in"""
  if u.file not in FIELD_MEMO:
    types = {}
    try:
      with open(os.path.join(work, u.file), errors="replace") as f:
        for line in f:
          m = FIELD.match(line)
          if m and m.group(1) not in ("return", "throw", "new", "else"):
            types[m.group(2)] = m.group(1)
    except OSError:
      pass
    FIELD_MEMO[u.file] = types
  return FIELD_MEMO[u.file]


def ext_text(e):
  """a platform API from units.py ext (pkg.Class.method) as code text"""
  cls, meth = e.rsplit(".", 1)
  simple = cls.rsplit(".", 1)[-1].split("$")[-1]
  return "new %s(" % simple if meth == "<init>" else "%s.%s(" % (simple, meth)


def api_hits(work, u):
  """[(label, line number, how)] of the listed APIs a function uses, first line each;
  how is "" for its own text, "bytecode" for a call found only in its bytecode (a lambda
  body jadx shows elsewhere): the line is then the function's first"""
  out = {}
  types = field_types(work, u)
  for i, line in enumerate(u.lines):
    if line.lstrip().startswith(("//", "/*", "*")):
      continue
    for lab, pat, _perms in APIS:
      if lab not in out and pat.search(line):
        out[lab] = (u.start + i, "")
    for lab, tpat, meth in TYPED:
      if lab in out:
        continue
      for m in re.finditer(r"(?:this\.)?(\w+)\.%s\(" % meth, line):
        if tpat.search(types.get(m.group(1), "")):
          out[lab] = (u.start + i, "")
  for e in sorted(u.ext):
    t = ext_text(e)
    for lab, pat, _perms in APIS:
      if lab not in out and pat.search(t):
        out[lab] = (u.start, "bytecode")
  return sorted(((lab, ln, how) for lab, (ln, how) in out.items()), key=lambda x: x[1])


def short(u):
  return "%s.%s" % (u.cls, u.name)


def merged(u):
  return any(MERGED.match(x) for x in u.lines[1:4])


def cite(u, line=None):
  return "%s:%d" % (u.file[len("jadx/sources/"):], line or u.start)


def compute(name, scopes=None, depth=5):
  """(text of behavior-facts.txt, rep): rep holds the same facts as data, with units"""
  work = os.path.join(ROOT, "work", name)
  scopes = scopes or units.load_script("scope.py").scopes(work)
  scopes = [s for s in scopes if os.path.isdir(os.path.join(work, "jadx", "sources", s))]
  allu = [u for u in units.java_units(work, scopes) if u.kind == "java"]
  by_id, callers = units.callers_of(allu, with_async=True)
  _pkg, comps, mrel, requested = manifest(work)
  requested = set(requested)
  classes = dex_classes(work)
  hits = {u.id: api_hits(work, u) for u in allu}
  rep = {"comps": [], "entries": [], "gates": [], "messages": [], "unreached": [], "js": [], "wv": [],
         "requested": sorted(requested),
         "ifaces": [], "hits": hits, "missing_launcher": False}
  out = ["# Behavior facts: %s" % name, "",
         "Java scope: %s. Call levels from an entry point: %d." % (" ".join(scopes) or "(none)", depth),
         "Facts about the code, not findings: read the code behind each line. Paths are under",
         "jadx/sources/ unless shown otherwise. Calls through reflection, native code, loaded code,",
         "and listeners a library calls are not in the graph.", ""]

  # components
  out.append("## Components and the dex (%s; dex/classes.txt of this sample, its parent, and their children)" % (mrel or "no manifest"))
  simple = {}
  for c in classes:
    simple.setdefault(c.rsplit(".", 1)[-1], []).append(c)
  comp_classes = {}
  missing_launcher = False
  for c in comps:
    present = c["name"] in classes if classes else None
    where = classes.get(c["name"])
    status = ("in dex" if where == name else "in dex of %s" % where) if present else \
             ("NOT IN DEX" if present is False else "dex list missing")
    flags = [c["kind"], "exported=%s" % c["exported"] if c["exported"] else ""]
    if c["launcher"]:
      flags.append("LAUNCHER")
    if c["permission"]:
      flags.append("permission=%s" % c["permission"])
    line = "- %s  %s  [%s]" % (clean(c["name"], 120), status, ", ".join(f for f in flags if f))
    if c["actions"]:
      line += "  actions: %s" % ", ".join(clean(a, 60) for a in c["actions"][:6])
    out.append(line)
    rep["comps"].append(dict(c, status=status))
    same = []
    if present is False:
      same = [x for x in simple.get(c["name"].rsplit(".", 1)[-1], []) if x != c["name"]]
      if same:
        out.append("    dex classes with the same simple name: %s" % ", ".join(sorted(same)[:5]))
      if c["launcher"]:
        missing_launcher = True
    if c["kind"] in ("activity", "activity-alias", "service", "receiver", "provider", "application"):
      comp_classes[c["name"].replace(".", "/")] = c
      if present is False and len(same) == 1:
        # the code most likely meant as this component, for the entry points below
        comp_classes[same[0].replace(".", "/")] = dict(c, kind=c["kind"] + " (by simple name)")
  rep["missing_launcher"] = missing_launcher
  if missing_launcher:
    out.append("")
    out.append("A launcher activity's class is not in the dex: unless code loaded at runtime supplies it,")
    out.append("starting the app from the launcher fails with ClassNotFoundException.")
  if not comps:
    out.append("- none (no manifest)")
  out.append("")

  # entry points
  def entry_kind(u):
    comp = comp_classes.get(u.file[len("jadx/sources/"):-5])
    if comp and COMPONENT_ENTRY.match(u.name):
      return "%s callback" % comp["kind"]
    src = os.path.join(work, u.file)
    try:
      with open(src, errors="replace") as f:
        flines = f.read().split("\n")
      before = " ".join(flines[max(0, u.start - 4):u.start - 1])
    except OSError:
      before = ""
    if "@JavascriptInterface" in before:
      return "JavaScript interface"
    if CALLBACK.match(u.name) and not callers.get(u.id) and "@Override" in before:
      return "callback (no caller in scope)"
    return None

  entries = [(u, entry_kind(u)) for u in allu]
  entries = [(u, k) for u, k in entries if k]
  reached_any = set()
  out.append("## Entry points and the listed APIs they reach")
  out.append("Chain: each step a call in the graph; '~' a step through a method outside the scope, '=>'")
  out.append("a Runnable or Handler handed to a thread or looper, '*' a merged lambda class (one class")
  out.append("for several lambdas, switching on a constructor argument): a step into it from code that")
  out.append("did not create it with that case is often a false edge. Check each step in the code.")
  shown = 0
  order = {"JavaScript interface": 1, "callback (no caller in scope)": 2}
  for u, kind in sorted(entries, key=lambda x: (order.get(x[1], 0), x[0].where)):
    # breadth first: shortest chain to each API
    found, seen, frontier = {}, {u.id}, [(u, [(u, "")])]
    reached_any.add(u.id)
    for lab, line, how in hits[u.id]:
      found[lab] = ([(u, "")], line, how)
    for _ in range(depth):
      nxt = []
      for v, path in frontier:
        steps = [(c, "") for c in v.calls | v.refs] + [(c, "~") for c in units.callees(v) - v.calls] + \
                [(c, "=>") for c in v.async_ - v.calls - v.refs]
        for cid, mark in sorted(steps):
          if cid in seen or cid not in by_id:
            continue
          seen.add(cid)
          w = by_id[cid]
          reached_any.add(cid)
          p = path + [(w, mark)]
          for lab, line, how in hits[cid]:
            found.setdefault(lab, (p, line, how))
          nxt.append((w, p))
      frontier = nxt
    if not found:
      continue
    rep["entries"].append((u, kind, found))
    shown += 1
    if shown > MAX_ITEMS:
      continue
    out.append("")
    out.append("### %s  (%s)  %s" % (short(u), kind, cite(u)))
    for lab in sorted(found, key=lambda x: (len(found[x][0]), x)):
      path, line, how = found[lab]
      last = path[-1][0]
      chain = " > ".join("%s%s%s" % (m, short(x), "*" if merged(x) else "") for x, m in path[1:])
      out.append("- %s: %s%s%s" % (lab, cite(last, line), " (in its bytecode: a lambda or inlined call)" if how else "",
                                    "  via %s" % chain if chain else ""))
  if shown > MAX_ITEMS:
    out.append("")
    out.append("... %d more entry points" % (shown - MAX_ITEMS))
  if not shown:
    out.append("- none reach a listed API")
  out.append("")

  # unreached
  out.append("## Functions using a listed API that no entry point reaches (depth %d)" % depth)
  out.append("Dead code, code reached through reflection or a library listener, or deeper than the depth.")
  n = 0
  for u in sorted(allu, key=lambda x: x.where):
    if hits[u.id] and u.id not in reached_any:
      rep["unreached"].append(u)
      n += 1
      if n <= MAX_ITEMS:
        ncall = len(callers.get(u.id, ()))
        out.append("- %s  %s: %s  (callers in scope: %d)" % (short(u), cite(u), ", ".join(h[0] for h in hits[u.id]), ncall))
  if n > MAX_ITEMS:
    out.append("... %d more" % (n - MAX_ITEMS))
  if not n:
    out.append("- none")
  out.append("")

  # permission gates
  out.append("## Permission gates of the listed APIs (requested: %s)" % (mrel or "no manifest"))
  used = {}
  for u in allu:
    for lab, line, _how in hits[u.id]:
      used.setdefault(lab, []).append((u, line))
  any_gate = False
  for lab, _pat, perms in APIS:
    if lab not in used or not perms:
      continue
    any_gate = True
    ok = [p for p in perms if p in requested]
    state = "requested: %s" % ", ".join(ok) if ok else "NOT REQUESTED (%s): the API fails or is refused" % " or ".join(perms)
    where = ", ".join(cite(u, line) for u, line in used[lab][:4])
    more = " +%d" % (len(used[lab]) - 4) if len(used[lab]) > 4 else ""
    out.append("- %s: %s  at %s%s" % (lab, state, where, more))
    rep["gates"].append((lab, perms, bool(ok), [cite(u, line) for u, line in used[lab]]))
  if not any_gate:
    out.append("- none of the listed APIs that need a permission")
  out.append("")

  # messages
  out.append("## Messages: JSON keys written and read, literals compared (per function)")
  net_classes = {u.file for u in allu if any(h[0] in NET for h in hits[u.id])}
  n = 0
  for u in sorted(allu, key=lambda x: x.where):
    puts, gets, cmps = {}, {}, {}
    for i, line in enumerate(u.lines):
      for m in JSON_PUT.finditer(line):
        if not FRAMEWORK_KEY.match(m.group(1)):
          puts.setdefault(m.group(1), u.start + i)
      for m in JSON_GET.finditer(line):
        if not FRAMEWORK_KEY.match(m.group(1)):
          gets.setdefault(m.group(1), u.start + i)
      for m in COMPARED.finditer(line):
        cmps.setdefault(m.group(1) or m.group(2) or m.group(3), u.start + i)
    if not puts and not gets:
      continue
    if u.file in net_classes:
      rep["messages"].append((u, puts, gets, cmps))
    n += 1
    if n > MAX_ITEMS:
      continue
    out.append("- %s  %s" % (short(u), cite(u)))
    for title, d in (("writes", puts), ("reads", gets), ("compares", cmps)):
      if d:
        out.append("    %s: %s" % (title, ", ".join("%s :%d" % (clean(k, 40), v) for k, v in d.items())))
  if n > MAX_ITEMS:
    out.append("... %d more functions" % (n - MAX_ITEMS))
  if not n:
    out.append("- none in scope")
  out.append("")

  # webview
  out.append("## WebView")
  n = 0
  for u in sorted(allu, key=lambda x: x.where):
    rows = []
    for i, line in enumerate(u.lines):
      ln = u.start + i
      for m in WV_SETTING.finditer(line):
        rows.append("setting %s(%s) :%d" % (m.group(1), clean(m.group(2), 40), ln))
      for m in JS_IFACE.finditer(line):
        rows.append("JavaScript interface \"%s\" = %s :%d" % (clean(m.group(2), 40), clean(m.group(1), 40), ln))
        rep["ifaces"].append((m.group(2), cite(u, ln)))
      for m in LOAD.finditer(line):
        rows.append("%s(%s) :%d" % (m.group(1), clean(re.sub(r"\)\s*;?\s*$", "", m.group(2)), 70), ln))
    if not rows:
      continue
    rep["wv"].append((u, rows))
    n += 1
    if n > MAX_ITEMS:
      continue
    out.append("- %s  %s" % (short(u), cite(u)))
    out.extend("    " + r for r in rows[:12])
  js = [u for u, k in entries if k == "JavaScript interface"]
  rep["js"] = js
  if js:
    out.append("- methods the page can call (@JavascriptInterface): %s" % ", ".join(
      "%s (%s)" % (short(u), cite(u)) for u in js[:MAX_ITEMS]))
  if not n and not js:
    out.append("- none in scope")

  rep.update(scopes=scopes, depth=depth, manifest=mrel)
  return "\n".join(out) + "\n", rep


def main():
  args = sys.argv[1:]
  depth = 5
  if "--depth" in args:
    i = args.index("--depth")
    depth = max(1, min(8, int(args[i + 1])))
    del args[i:i + 2]
  if not args:
    sys.exit(__doc__)
  name, scopes = args[0], args[1:] or None
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found" % name)
  text, _rep = compute(name, scopes, depth)
  with open(os.path.join(work, "behavior-facts.txt"), "w") as f:
    f.write(text)
  print("wrote work/%s/behavior-facts.txt" % name)


if __name__ == "__main__":
  main()
