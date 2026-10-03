#!/usr/bin/env python3
"""Leads from the shape of the code: functions that tie behavior together.

Pattern searches (scan.sh) and the model (model-leads.py) find functions whose own
text gives them away. The functions that matter for understanding an app are often
the ones without telling text: the main loop, the command dispatcher, the handler
table, the method that starts the payload and reschedules itself. This script finds
them from the call graph and from control structure. Deterministic; no model.

Each function gets capabilities from its own text (Java and Dart: API names; native:
imported functions, system calls, JNI calls; all: strings by category). Through the
call graph (calls, plus address-taken functions in native code) each function also
reaches the capabilities of its callees, up to a few levels down.

Sections of work/<name>/structure-leads.txt:
  entry points    manifest components' methods, JNI and ELF entry points, and what
                  each reaches, with one call chain per capability
  coordinators    functions that reach several capabilities through different callees
  dispatch        switch statements and compare chains with many cases, and native
                  functions that take the address of many functions (handler tables)
  loops           endless loops and self-rescheduling tasks that reach capabilities
  decoders        XOR inside a loop with a repeating key, or in a function called from
                  several places: string and config decryptors, file masking, checksums
  combined        functions whose own text uses several capabilities
  capability map  Dart and native functions per capability (scan.sh covers Java only)

Every line is a lead, never a finding: read the code behind it.

Usage: ./cupella structure-leads.py <name> [java-scope ...]
       Default Java scope: scope.py (manifest package, packages of declared
       components, defpackage/).
Output: work/<name>/structure-leads.txt
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEPTH = 3
MAX_LINES = 25

JAVA_CAPS = [
  ("network", r"\b(?:Socket|ServerSocket|DatagramSocket|HttpURLConnection|HttpsURLConnection|URLConnection|"
              r"OkHttpClient|WebSocket)\b|openConnection\(|\.newCall\(|\bnew URL\("),
  ("process", r"\bProcessBuilder\b|Runtime\.getRuntime\(\)\.exec|\bProcess\b"),
  ("code loading", r"System\.load(?:Library)?\(|DexClassLoader|PathClassLoader|InMemoryDexClassLoader"),
  ("file permissions", r"setExecutable\(|\bchmod\b"),
  ("persistence", r"BOOT_COMPLETED|AlarmManager|JobScheduler|WorkManager|startForegroundService|startForeground\(|"
                  r"START_STICKY|START_REDELIVER_INTENT|IGNORE_BATTERY_OPTIMIZATIONS|WakeLock|setComponentEnabledSetting"),
  ("system settings", r"Settings\.(?:Secure|Global|System)\.put|enabled_accessibility_services|"
                      r"enabled_notification_listeners|DevicePolicyManager"),
  ("accessibility", r"AccessibilityNodeInfo|getRootInActiveWindow|performGlobalAction|dispatchGesture"),
  ("private data", r"ContactsContract|Telephony\.|SmsManager|CallLog|getLastKnownLocation|requestLocationUpdates|"
                   r"getDeviceId|getSubscriberId|getImei|ANDROID_ID|getInstalledPackages|getInstalledApplications|"
                   r"StatusBarNotification|ClipboardManager|getPrimaryClip"),
  ("overlay", r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|canDrawOverlays"),
  ("package install", r"PackageInstaller|application/vnd\.android\.package-archive"),
  ("webview bridge", r"addJavascriptInterface|evaluateJavascript"),
  ("crypto", r"Cipher\.getInstance|SecretKeySpec|MessageDigest\.getInstance|Mac\.getInstance"),
  ("reflection", r"Class\.forName|getDeclaredMethod|getDeclaredField"),
  ("storage", r"SharedPreferences|SQLiteDatabase|openFileOutput|FileOutputStream"),
]
DART_CAPS = [
  ("network", r"\[dart:io\] (?:Socket|RawSocket|HttpClient|WebSocket|SecureSocket|RawDatagramSocket|ServerSocket)|"
              r"\[package:[^\]]*(?:http|socket|dio|grpc|ping|scanner|lan_|generative_ai|api_client|_api/)|"
              r"\[package:[^\]]*/client\.dart\]"),
  ("process", r"\[dart:io\] Process::"),
  ("platform channel", r"(?:MethodChannel|EventChannel|BasicMessageChannel)::"),
  ("private data", r"\[package:(?:contacts\w*|geolocator\w*|location\w*|network_info\w*|device_info\w*|"
                   r"telephony\w*|flutter_contacts|sms\w*)/"),
  ("crypto", r"\[package:(?:crypto|encrypt|pointycastle|cryptography\w*)/"),
  ("file access", r"\[dart:io\] (?:File|Directory)::|_File::"),
  ("storage", r"\[package:(?:shared_preferences\w*|sqflite\w*|hive\w*|isar\w*|drift\w*)/"),
  ("code loading", r"DynamicLibrary::open|\[dart:ffi\]"),
]
NATIVE_IMPORT_CAPS = {
  "network": "network", "process execution": "process", "dynamic loading": "code loading",
  "memory protection": "memory protection", "debug, tracing": "debug, signals", "file access": "file access",
  "crypto": "crypto", "threads": "threads",
}
STRING_CAPS = {
  "URLs": "URL strings", "IPv4 addresses": "IP strings", "filesystem paths": "system path strings",
  "flooding, bot behavior": "bot-like strings", "root, hooking, emulator, debugger checks": "anti-analysis strings",
  "shell commands": "shell strings", "keys, certificates": "key strings",
  "format strings with shell or SQL shape": "shell or SQL format strings",
}
# not counted when ranking: common in ordinary code
WEAK = {"storage", "file access", "crypto", "reflection", "threads", "memory protection", "debug, signals",
        "system path strings", "shell or SQL format strings"}
JAVA_ENTRY = re.compile(r"^(on[A-Z]\w*|run|handleMessage|doWork|query|insert|update|delete|call|getType|openFile)$")
ANY_LOOP = re.compile(r"\bfor\s*\(|\bwhile\s*\(|\bdo\s*\{")
REPEAT_KEY = re.compile(r"\^\s*\(?\s*(?:\([\w ]+\)\s*)?\w+\[[^\]]*%[^\]]*\]|\[[^\]]*%[^\]]*\]\s*\)?\s*\^")
XOR = re.compile(r"[\w)\]]\s*\^=?\s*[\w(]")
LOOP = re.compile(r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)")
SCHEDULE = re.compile(r"postDelayed\(|postAtTime\(|sendEmptyMessageDelayed\(|sendMessageDelayed\(|"
                      r"\.schedule(?:AtFixedRate|WithFixedDelay)?\(|setRepeating\(|setExactAndAllowWhileIdle\(")
STRCMP = re.compile(r"\b(?:strn?cmp|strcasecmp|memcmp|strstr)\s*\(|\.equals\(\"|\.equalsIgnoreCase\(\"|"
                    r"\.startsWith\(\"|\.contains\(\"")
STR_LIT = re.compile(r'/\* -> "((?:[^"\\]|\\.)*)" \*/|"((?:[^"\\]|\\.){4,})"')


GATE = re.compile(r"getSimCountryIso\(|getNetworkCountryIso\(|getSimOperator(?:Name)?\(|getNetworkOperator(?:Name)?\(|"
                  r"Locale\.getDefault\(|getDefault\(\)\.getCountry|TimeZone\.getDefault\(|firstInstallTime|"
                  r"Build\.(?:FINGERPRINT|MODEL|MANUFACTURER|BRAND|PRODUCT|HARDWARE|DEVICE|BOARD|TAGS)\b|"
                  r"isDebuggerConnected\(|isUserAMonkey\(|isRunningInTestHarness\(|ro\.kernel\.qemu|goldfish|ranchu|"
                  r"/system/x?bin/su\b|DEVELOPMENT_SETTINGS_ENABLED|ADB_ENABLED|adb_enabled|getInstallerPackageName\(")


WEAK_GATE = re.compile(r"^(?:Locale\.getDefault|getDefault\(\)\.getCountry|firstInstallTime)$")


def strings_of(u):
  return [a or b for a, b in STR_LIT.findall(u.text)]


def own_caps(u, str_cats, imp_cats):
  caps = set()
  text = u.text
  if u.kind == "java":
    for label, pat in JAVA_CAPS:
      if re.search(pat, text):
        caps.add(label)
  elif u.kind == "dart":
    for e in u.ext:
      for label, pat in DART_CAPS:
        if re.search(pat, e):
          caps.add(label)
  else:
    for e in u.ext:
      for label, pat in imp_cats:
        if label in NATIVE_IMPORT_CAPS and (re.match(pat, e) or re.match(pat, e.lstrip("_"))):
          caps.add(NATIVE_IMPORT_CAPS[label])
    if "software_interrupt(" in text or re.search(r"\bsyscall\(", text):
      caps.add("system calls")
    if "/* JNIEnv->" in text:
      caps.add("JNI calls")
  for s in strings_of(u):
    for label, pat in str_cats:
      if label in STRING_CAPS and pat.search(s):
        caps.add(STRING_CAPS[label])
  return caps


def short(u):
  if u.kind == "java":
    return "%s.%s" % (u.cls, u.name)
  if u.kind == "dart":
    return u.id[5:]
  return u.name


def reach(u, by_id, caps, depth):
  """capability -> shortest call chain (list of units) from u to a function that has it"""
  found = {c: [u] for c in caps[u.id]}
  frontier, seen = [(u, [u])], {u.id}
  for _ in range(depth):
    nxt = []
    for v, path in frontier:
      for cid in sorted(v.calls | v.refs):
        if cid in seen or cid not in by_id:
          continue
        seen.add(cid)
        w = by_id[cid]
        p = path + [w]
        for c in caps[cid]:
          found.setdefault(c, p)
        nxt.append((w, p))
    frontier = nxt
  return found


def strong(cs):
  return sorted(c for c in cs if c not in WEAK)


def fmt_caps(found):
  parts = []
  for c in sorted(found, key=lambda c: (c in WEAK, c)):
    chain = found[c]
    parts.append(c if len(chain) == 1 else "%s via %s" % (c, " > ".join(short(x) for x in chain[1:])))
  return "; ".join(parts)


def manifest_components(work):
  path = os.path.join(work, "manifest.xml")
  if not os.path.exists(path):
    return "", {}
  with open(path, errors="replace") as f:
    text = f.read()
  m = re.search(r' package="([^"]+)"', text[:4000])
  pkg = m.group(1) if m else ""
  comps = {}
  for m in re.finditer(r"<(activity|activity-alias|service|receiver|provider)\b[^>]*?android:name=\"([^\"]+)\"", text):
    name = m.group(2)
    if name.startswith("."):
      name = pkg + name
    elif "." not in name:
      name = pkg + "." + name
    comps[name.replace(".", "/")] = m.group(1)
  return pkg, comps


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name, scopes = sys.argv[1], sys.argv[2:]
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found: run ./cupella unpack.sh first" % name)
  pkg, comps = manifest_components(work)
  if not scopes:
    scopes = units.load_script("scope.py").scopes(work)
  scopes = [s for s in scopes if os.path.isdir(os.path.join(work, "jadx", "sources", s))]

  ns = units.load_script("native-summary.py")
  str_cats = ns.STRING_CATEGORIES
  imp_cats = ns.IMPORT_CATEGORIES
  allu = units.java_units(work, scopes) + units.dart_units(work, name) + units.native_units(work)
  by_id, callers = units.callers_of(allu)
  caps = {u.id: own_caps(u, str_cats, imp_cats) for u in allu}
  reached = {u.id: reach(u, by_id, caps, DEPTH) for u in allu}

  out_lines = []

  def w(line=""):
    out_lines.append(line)
  kinds = {}
  for u in allu:
    kinds[u.kind] = kinds.get(u.kind, 0) + 1
  w("# Structure leads: %s" % name)
  w("Functions found from the call graph and control structure, not from their text.")
  w("Leads only: read the code behind each line. Capabilities come from API names, imports,")
  w("system calls, and strings; 'via' shows one call chain (up to %d calls deep) to a function" % DEPTH)
  w("that has the capability. Native calls through computed pointers are not followed.")
  w()
  w("functions: %s; java scopes: %s" % (", ".join("%s %d" % kv for kv in sorted(kinds.items())) or "none",
                                         ", ".join(scopes) or "none"))
  shown = set()

  # entry points
  entries = []
  for u in allu:
    if u.kind == "java":
      comp = u.file[len("jadx/sources/"):-5]
      if comp in comps and JAVA_ENTRY.match(u.name):
        entries.append((u, "%s %s" % (comps[comp], u.name)))
    elif u.kind == "native":
      if u.name.startswith(("jni_", "Java_", "init_")) or u.name in ("JNI_OnLoad", "entry", "main", "_start"):
        entries.append((u, "native entry"))
    elif u.kind == "dart" and u.id in ("dart:::main",):
      entries.append((u, "Dart main"))
  rows = []
  for u, why in entries:
    found = reach(u, by_id, caps, DEPTH + 1)
    if strong(found):
      rows.append((-len(strong(found)), u.where, u, why, found))
  rows.sort(key=lambda r: (r[0], r[1]))
  w()
  w("## Entry points and what they reach (%d)" % len(rows))
  w("Manifest components' callbacks, JNI and ELF entry points. Start reading here.")
  for _n, _wh, u, why, found in rows[:MAX_LINES * 2]:
    w("- %s  [%s]  %s" % (u.where, why, fmt_caps(found)))
    shown.add(u.id)
  if len(rows) > MAX_LINES * 2:
    w("- ... %d more" % (len(rows) - MAX_LINES * 2))

  # coordinators
  rows = []
  for u in allu:
    found = reached[u.id]
    s = strong(found)
    sources = {found[c][1].id for c in s if len(found[c]) > 1}
    if s and len(found) >= 3 and len(sources) >= 2 and u.id not in shown:
      rows.append((-len(s), -len(found), -len(sources), u.where, u, found))
  rows.sort(key=lambda r: r[:4])
  w()
  w("## Coordinators (%d)" % len(rows))
  w("Functions that reach three or more capabilities, one of them not a common one (storage,")
  w("files, crypto, reflection, threads), through two or more different callees: main loops,")
  w("command handlers, setup routines. Their own text often shows little.")
  for r in rows[:MAX_LINES]:
    w("- %s  %s" % (r[3], fmt_caps(r[5])))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))

  # environment gating: functions that read where and on what they run, and reach a
  # capability; malware activates only for chosen countries, operators, or real devices
  rows, weak_only = [], 0
  for u in allu:
    hits = sorted(set(m.group(0).rstrip("(") for m in GATE.finditer(u.text)))
    s = strong(reached[u.id])
    if hits and s:
      if all(WEAK_GATE.match(h) for h in hits):
        weak_only += 1  # locale and install time are mostly UI language and statistics
        continue
      rows.append((-len(hits), -len(s), u.where, u, hits))
  rows.sort(key=lambda r: r[:3])
  w()
  w("## Environment checks next to capabilities (%d)" % len(rows))
  w("Functions that read the country, operator, locale, time zone, install time, device model,")
  w("debugger, emulator, or root state and also reach a capability: the conditions under which")
  w("the app acts. Read the branch: what runs only when the check passes, and what it compares to.")
  for r in rows[:MAX_LINES]:
    found = reached[r[3].id]
    w("- %s  checks: %s  reaches: %s" % (r[2], ", ".join(r[4][:8]), fmt_caps({c: found[c] for c in strong(found)})))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))
  if weak_only:
    w("(%d more read only the locale or install time; listed only when a stronger check is present)" % weak_only)

  # dispatch
  rows = []
  for u in allu:
    text = u.text
    why = []
    cases = len(re.findall(r"^\s*case [^:]+:", text, re.M))
    if cases >= 6:
      why.append("switch with %d cases" % cases)
    cmps = len(STRCMP.findall(text))
    if cmps >= 5:
      why.append("%d string comparisons" % cmps)
    if len(u.refs) >= 4:
      names = sorted(by_id[r].name for r in u.refs)
      why.append("takes the address of %d functions (%s%s)" % (len(names), ", ".join(names[:6]),
                                                                ", ..." if len(names) > 6 else ""))
    if why:
      score = max(cases, cmps, 2 * len(u.refs))
      reach_s = strong(reached[u.id])
      rows.append((-len(reach_s), -score, u.where, u, why))
  rows.sort(key=lambda r: r[:3])
  w()
  w("## Dispatch and handler tables (%d)" % len(rows))
  w("Many-way branches and tables of function pointers: command dispatchers, protocol parsers,")
  w("registration of handlers. Ordered by the capabilities they reach, then by size.")
  for r in rows[:MAX_LINES]:
    found = reached[r[3].id]
    caps_s = fmt_caps({c: found[c] for c in strong(found)})
    w("- %s  %s%s" % (r[2], "; ".join(r[4]), "  reaches: " + caps_s if caps_s else ""))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))

  # loops and self-scheduling
  rows = []
  for u in allu:
    text = u.text
    why = None
    if LOOP.search(text) and len(u.calls) >= 2:
      why = "endless loop"
    elif u.kind == "java" and SCHEDULE.search(text) and (
        re.search(r"(?:postDelayed|schedule\w*|postAtTime)\(\s*this\b", text) or
        re.search(r"\bnew %s\(" % re.escape(u.cls), text)):
      why = "reschedules itself"
    elif u.kind == "dart" and any("Timer.periodic" in e or "Stream::periodic" in e for e in u.ext):
      why = "periodic timer"
    if why:
      s = strong(reached[u.id])
      if s:
        rows.append((-len(s), u.where, u, why))
  rows.sort(key=lambda r: r[:2])
  w()
  w("## Loops and repeating tasks (%d)" % len(rows))
  w("Endless loops with calls, and tasks that schedule themselves again, that reach a capability.")
  for r in rows[:MAX_LINES]:
    found = reached[r[2].id]
    w("- %s  %s; %s" % (r[1], r[3], fmt_caps({c: found[c] for c in strong(found)})))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))

  # decoders
  rows = []
  for u in allu:
    if u.name == "hashCode" or not ANY_LOOP.search(u.text):
      continue
    xors = len(XOR.findall(u.text))
    n_callers = len(callers.get(u.id, ()))
    repeating = bool(REPEAT_KEY.search(u.text))
    if xors and (n_callers >= 3 or repeating):
      rows.append((not repeating, -n_callers, xors, u.where, u))
  rows.sort(key=lambda r: r[:3])
  w()
  w("## Decoders and transforms (%d)" % len(rows))
  w("XOR inside a loop, with a repeating key (k[i % n]) or in a function called from three or")
  w("more places; repeating-key XOR first, then by number of callers:")
  w("string and configuration decryptors, file masking, checksums, hash and cipher code.")
  for r in rows[:MAX_LINES]:
    w("- %s  %scalled from %d functions, %d XOR operations" % (
      r[3], "" if r[0] else "XOR with a repeating key; ", -r[1], r[2]))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))

  # combined
  rows = []
  for u in allu:
    s = strong(caps[u.id])
    if len(s) >= 2 and len(caps[u.id]) >= 3:
      rows.append((-len(s), -len(caps[u.id]), u.where, u))
  rows.sort(key=lambda r: r[:3])
  w()
  w("## Functions combining capabilities in their own text (%d)" % len(rows))
  for r in rows[:MAX_LINES]:
    w("- %s  %s" % (r[2], ", ".join(sorted(caps[r[3].id]))))
  if len(rows) > MAX_LINES:
    w("- ... %d more" % (len(rows) - MAX_LINES))

  # capability map for code that scan.sh does not search
  bycap = {}
  for u in allu:
    if u.kind == "java":
      continue
    for c in caps[u.id]:
      if u.kind == "dart" or c not in WEAK:
        bycap.setdefault(c, []).append(u)
  w()
  w("## Capability map, Dart and native (%d capabilities)" % len(bycap))
  w("Functions whose own text has the capability, most callers first. scan.txt covers Java.")
  for c in sorted(bycap, key=lambda c: (c in WEAK, c)):
    us = sorted(bycap[c], key=lambda u: (-len(callers.get(u.id, ())), u.where))
    w()
    w("### %s (%d)" % (c, len(us)))
    for u in us[:15]:
      w("- %s" % u.where)
    if len(us) > 15:
      w("- ... %d more" % (len(us) - 15))

  out = os.path.join(work, "structure-leads.txt")
  with open(out, "w") as f:
    f.write("\n".join(out_lines) + "\n")
  print("wrote %s" % os.path.relpath(out, ROOT))


if __name__ == "__main__":
  main()
