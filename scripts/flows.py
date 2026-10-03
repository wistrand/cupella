#!/usr/bin/env python3
"""Data flows from source APIs to sink APIs in the app's Java code, from bytecode.

Pattern searches say an app reads contacts and that it sends HTTP requests; this
says whether the value read reaches the request. Like Quark-Engine's top stage
("APIs that handle the same register"), it follows values through the Dalvik
registers of a method:

  - a source call (TelephonyManager.getDeviceId, a content query, an intent extra,
    an asset or network stream, ...) taints its result; reading from a tainted
    stream taints the buffer read into, so asset -> decrypt -> file or class loader
    (a dropper) shows as a flow, marked when the data passed XOR or a cipher
  - taint moves through moves, array and field stores (fields are global: a value
    stored in one method and read in another stays tainted), string building and
    other library calls (a call with a tainted argument taints its result and its
    receiver: StringBuilder.append, Intent.putExtra, JSONObject.put)
  - a sink call (OutputStream.write, SmsManager.sendTextMessage, Log.d,
    SharedPreferences.Editor.putString, ...) with a tainted argument is a flow
  - calls into app methods use summaries: which parameters reach which sinks, which
    are stored into fields (how values reach coroutine and callback objects), and
    whether the method returns source data (three rounds, so a few levels compose)

Approximations: instructions are read in order, ignoring branches, so a register
keeps its taint until overwritten; exceptions, reflection, and native code are not
followed. Expect both misses and flows that cannot happen at run time. Every flow is
a lead: read the method.

Usage: ./cupella flows.py <name> [java-scope ...]      default scope: scope.py
Output: work/<name>/flows.txt (run by scan.sh)
"""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# (label, regex on "Lpkg/Cls;->name")
SOURCES = [
  ("device id", r"Landroid/telephony/TelephonyManager;->(getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|"
                r"getLine1Number|getSimOperator\w*|getNetworkOperator\w*)$|Landroid/net/wifi/WifiInfo;->(getMacAddress|getSSID|getBSSID)$|"
                r"AdvertisingIdClient\$Info;->getId$|Landroid/provider/Settings\$Secure;->getString$"),
  ("location", r"Landroid/location/Location;->(getLatitude|getLongitude)$|Landroid/location/LocationManager;->getLastKnownLocation$"),
  ("content query", r"Landroid/content/ContentResolver;->query$"),
  ("SMS received", r"Landroid/telephony/SmsMessage;->(getMessageBody|getDisplayMessageBody|getOriginatingAddress|getDisplayOriginatingAddress)$"),
  ("accounts", r"Landroid/accounts/AccountManager;->getAccounts\w*$"),
  ("installed apps", r"Landroid/content/pm/PackageManager;->(getInstalledPackages|getInstalledApplications)$"),
  ("clipboard", r"Landroid/content/ClipboardManager;->getPrimaryClip$"),
  ("screen text", r"Landroid/view/accessibility/(AccessibilityNodeInfo|AccessibilityEvent|AccessibilityRecord);->(getText|getContentDescription)$"),
  ("notification", r"Landroid/service/notification/StatusBarNotification;->getNotification$"),
  ("intent extra", r"Landroid/content/Intent;->(get\w*Extra|getExtras|getData|getDataString)$|Landroid/os/Bundle;->get\w*$"),
  ("bundled asset", r"Landroid/content/res/AssetManager;->(open|openFd|openNonAssetFd)$|"
                    r"Landroid/content/res/Resources;->(openRawResource\w*)$"),
  ("network input", r"Ljava/net/(URLConnection|HttpURLConnection|Socket);->getInputStream$|"
                    r"Ljavax/net/ssl/HttpsURLConnection;->getInputStream$|Ljava/net/URL;->openStream$"),
]
SINKS = [
  ("stream write (file or socket)", r"Ljava/io/OutputStream;->write$|"
                                    r"Ljava/io/(DataOutputStream|BufferedWriter|PrintWriter|OutputStreamWriter);->(write\w*|print\w*|append)$"),
  ("network", r"Ljava/net/(Socket|URL|HttpURLConnection|URLConnection);->|"
              r"Ljavax/net/ssl/HttpsURLConnection;->|Lokhttp3/(Request\$Builder;->(url|post|put|header|addHeader)|"
              r"RequestBody;->create|FormBody\$Builder;->add|HttpUrl\$Builder;->add\w*)$|"
              r"Ljava/net/DatagramPacket;-><init>$|Landroid/webkit/WebView;->(loadUrl|postUrl|loadData\w*)$"),
  ("SMS send", r"Landroid/telephony/SmsManager;->send\w*Message$"),
  ("log", r"Landroid/util/Log;->(d|e|i|v|w|wtf|println)$"),
  ("storage", r"Landroid/content/SharedPreferences\$Editor;->put\w*$|Ljava/io/FileOutputStream;->write$|"
              r"Landroid/database/sqlite/SQLiteDatabase;->(insert\w*|update\w*|replace\w*)$|"
              r"Landroidx/(room/EntityInsertionAdapter|room/EntityDeletionOrUpdateAdapter);->\w+$|"
              r"Landroidx/sqlite/db/SupportSQLiteStatement;->bind\w*$|Landroid/content/ContentResolver;->(insert|update)$"),
  ("SQL", r"Landroid/database/sqlite/SQLiteDatabase;->(rawQuery\w*|execSQL|compileStatement)$"),
  ("other apps", r"Landroid/content/(Context|ContextWrapper);->(sendBroadcast\w*|sendOrderedBroadcast\w*|startActivit\w*|startService)$|"
                 r"Landroid/app/Activity;->(startActivit\w*|setResult)$"),
  ("code", r"Ldalvik/system/(DexClassLoader|PathClassLoader|InMemoryDexClassLoader);-><init>$|Ljava/lang/Class;->forName$|"
           r"Ljava/lang/Runtime;->exec$|Ljava/lang/ProcessBuilder;-><init>$|"
           r"Landroid(x/fragment/app|/app)/Fragment;->instantiate$|Ljava/lang/ClassLoader;->loadClass$"),
  ("file path", r"Ljava/io/File;-><init>$|Ljava/io/(FileInputStream|FileOutputStream|FileReader|FileWriter);-><init>$"),
]
# source categories that may flow to these sinks without being worth a lead
QUIET = {("intent extra", "log"), ("intent extra", "storage"), ("bundled asset", "log"),
         ("bundled asset", "other apps"), ("network input", "log"), ("bundled asset", "file path"),
         ("network input", "other apps")}
# reading from a tainted stream or cursor fills the buffer argument
READ_INTO = re.compile(r"->(read\w*|copyStringToBuffer|getBytes)\(")

XOR_OPS = {0x97, 0xa2, 0xb7, 0xc2, 0xd7, 0xdf}
XFORM = ("xform",)  # marker: the data went through XOR or a cipher on the way
CIPHER = re.compile(r"^Ljavax/crypto/(Cipher|CipherInputStream|CipherOutputStream);->(doFinal|update|<init>)\(")
INVOKE_35C = set(range(0x6e, 0x73)) | {0xfc}
INVOKE_3RC = set(range(0x74, 0x79)) | {0xfd}
STATIC = {0x71, 0x77}


def classify(key, table):
  head = key.split("(", 1)[0]
  for label, pat in table:
    if re.search(pat, head):
      return label
  return None


class Analyzer:
  def __init__(self, methods, dispatch):
    self.methods, self.dispatch = methods, dispatch
    self.fields = {}       # field key -> taint labels
    self.summary = {}      # method key -> {param index: set of (sink, sink api, via)}
    self.returns = {}      # method key -> set of source labels returned
    self.param_fields = {}  # method key -> {param index: fields it is stored into}
    self.sink_cache, self.source_cache = {}, {}

  def sink(self, key):
    if key not in self.sink_cache:
      self.sink_cache[key] = classify(key, SINKS)
    return self.sink_cache[key]

  def source(self, key):
    if key not in self.source_cache:
      self.source_cache[key] = classify(key, SOURCES)
    return self.source_cache[key]

  def run(self, key, m, report):
    """One pass over a method. Taint labels: ("src", category, api) or ("param", i)."""
    d, b, off = m.dex, m.dex.buf, m.code_off
    nregs, nins = struct.unpack_from("<HH", b, off)
    (n,) = struct.unpack_from("<I", b, off + 12)
    base = off + 16
    taint = {}
    widths = [2 if p in ("J", "D") else 1 for p in m.params]
    reg = nregs - nins
    if nins > sum(widths):
      reg += 1  # this
    for i, w in enumerate(widths):
      taint[reg] = frozenset([("param", i)])
      reg += w
    pending, flows, ret, pf = frozenset(), [], set(), {}
    pc = 0

    def T(r):
      return taint.get(r, frozenset())

    def setr(r, t):
      if t:
        taint[r] = frozenset(t)
      else:
        taint.pop(r, None)

    while pc < n:
      unit = struct.unpack_from("<H", b, base + 2 * pc)[0]
      op = unit & 0xFF
      if op == 0 and unit != 0:
        if unit == 0x0100:
          pc += struct.unpack_from("<H", b, base + 2 * pc + 2)[0] * 2 + 4
        elif unit == 0x0200:
          pc += struct.unpack_from("<H", b, base + 2 * pc + 2)[0] * 4 + 2
        elif unit == 0x0300:
          w, size = struct.unpack_from("<HI", b, base + 2 * pc + 2)
          pc += (size * w + 1) // 2 + 4
        else:
          pc += 1
        continue
      a8, a4, b4 = unit >> 8, (unit >> 8) & 0xF, unit >> 12
      u1, u2 = struct.unpack_from("<HH", b, base + 2 * pc + 2) if base + 2 * pc + 6 <= len(b) else (0, 0)
      if op in INVOKE_35C or op in INVOKE_3RC:
        if op in INVOKE_35C:
          cnt = b4
          regs = [u2 & 0xF, (u2 >> 4) & 0xF, (u2 >> 8) & 0xF, (u2 >> 12) & 0xF, a4][:cnt]
        else:
          regs = list(range(u2, u2 + a8))
        target = d.method(u1)[4] if op not in (0xfc, 0xfd) else ""
        static = op in STATIC
        args = regs if static else regs[1:]
        at = frozenset().union(*[T(r) for r in args]) if args else frozenset()
        rt = T(regs[0]) if regs and not static else frozenset()
        snk = self.sink(target) if target else None
        if snk:
          # a sink receives tainted data through an argument, or through the
          # receiver for writers and builders that were filled earlier
          data = at | (rt if snk in ("network", "stream write (file or socket)") else frozenset())
          if data:
            flows.append((data, snk, target, None))
        res = set(at) | set(rt)
        app = [k for k in self.dispatch(target) if k in self.methods and self.methods[k].code] if target else []
        for k in app:
          # a tainted argument stored into a field by the callee (constructors of
          # coroutine and callback objects) taints that field everywhere
          for i, fs in self.param_fields.get(k, {}).items():
            if i < len(args):
              srcs = {x for x in T(args[i]) if x[0] == "src"}
              for f in fs:
                if srcs and not srcs <= self.fields.get(f, frozenset()):
                  self.fields[f] = frozenset(self.fields.get(f, frozenset()) | srcs)
          for i, sinks in self.summary.get(k, {}).items():
            if i < len(args):
              t = T(args[i])
              for s, api, _via in sinks:
                if t:
                  flows.append((t, s, api, k))
          res |= self.returns.get(k, set())
        if at and target and CIPHER.search(target):
          res.add(XFORM)
        if (at or rt) and any(XFORM in self.returns.get(k, set()) for k in app):
          res.add(XFORM)
        src = self.source(target) if target else None
        if src:
          res.add(("src", src, target))
        pending = frozenset(res)
        if at and not static and regs and not snk and not app:
          setr(regs[0], rt | at)  # builders, intents, collections take the value in
        if rt and not static and len(regs) > 1 and READ_INTO.search(target or ""):
          for r in regs[1:]:
            setr(r, T(r) | rt)  # in.read(buf): buf now holds the stream's data
      elif 0x0a <= op <= 0x0c:  # move-result
        setr(a8, pending)
      elif op in (0x01, 0x04, 0x07):  # move vA, vB
        setr(a4, T(b4))
      elif op in (0x02, 0x05, 0x08):
        setr(a8, T(u1))
      elif op in (0x03, 0x06, 0x09):
        setr(u1, T(u2))
      elif op == 0x0d or 0x12 <= op <= 0x1c or op == 0x22:  # move-exception, consts, new-instance
        setr(a4 if op == 0x12 else a8, None)
      elif op in (0x1f,):  # check-cast keeps the value
        pass
      elif op in (0x20, 0x23):  # instance-of, new-array
        setr(a4, None)
      elif op in (0x24, 0x25):  # filled-new-array: result via move-result
        regs = [u2 & 0xF, (u2 >> 4) & 0xF, (u2 >> 8) & 0xF, (u2 >> 12) & 0xF, a4][:b4] if op == 0x24 else list(range(u2, u2 + a8))
        pending = frozenset().union(*[T(r) for r in regs]) if regs else frozenset()
      elif 0x44 <= op <= 0x4a:  # aget vAA, vBB, vCC
        setr(a8, T(u1 & 0xFF))
      elif 0x4b <= op <= 0x51:  # aput
        arr = u1 & 0xFF
        setr(arr, T(arr) | T(a8))
      elif 0x52 <= op <= 0x58:  # iget vA, vB, field
        setr(a4, self.fields.get(d.field(u1), frozenset()))
      elif 0x59 <= op <= 0x5f:  # iput
        t = T(a4)
        if t:
          f = d.field(u1)
          self.fields[f] = frozenset(self.fields.get(f, frozenset()) | {x for x in t if x[0] == "src"})
          for x in t:
            if x[0] == "param":
              pf.setdefault(x[1], set()).add(f)
      elif 0x60 <= op <= 0x66:  # sget
        setr(a8, self.fields.get(d.field(u1), frozenset()))
      elif 0x67 <= op <= 0x6d:  # sput
        t = T(a8)
        if t:
          f = d.field(u1)
          self.fields[f] = frozenset(self.fields.get(f, frozenset()) | {x for x in t if x[0] == "src"})
          for x in t:
            if x[0] == "param":
              pf.setdefault(x[1], set()).add(f)
      elif op in (0x11, 0x0f, 0x10):  # return
        ret |= T(a8)
      elif 0x90 <= op <= 0xaf:  # binop vAA, vBB, vCC
        t = T(u1 & 0xFF) | T(u1 >> 8)
        setr(a8, t | {XFORM} if t and op in XOR_OPS else t)
      elif 0xb0 <= op <= 0xcf or 0x7b <= op <= 0x8f:  # binop/2addr, unop
        t = T(a4) | T(b4)
        setr(a4, t | {XFORM} if t and op in XOR_OPS else t)
      elif 0xd0 <= op <= 0xe2:
        t = T(b4) if op <= 0xd7 else T(u1 & 0xFF)
        setr(a4 if op <= 0xd7 else a8, t | {XFORM} if t and op in XOR_OPS else t)
      pc += WIDTH[op]

    # summaries for callers
    summ = {}
    for t, snk, api, via in flows:
      for lab in t:
        if lab[0] == "param":
          summ.setdefault(lab[1], set()).add((snk, api, via))
    self.summary[key] = summ
    self.param_fields[key] = pf
    self.returns[key] = {x for x in ret if x[0] == "src" or x == XFORM}
    if report is not None:
      for t, snk, api, via in flows:
        for lab in t:
          if lab[0] == "src" and (lab[1], snk) not in QUIET:
            report.add((key, lab[1], lab[2], snk, api, via, XFORM in t))


WIDTH = None


def api_name(key):
  cls, rest = key.split("->", 1)
  return "%s.%s" % (cls[1:-1].split("/")[-1], rest.split("(")[0])


def main():
  global WIDTH
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name, scopes = sys.argv[1], sys.argv[2:]
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found: run ./cupella unpack.sh first" % name)
  scopes = scopes or units.load_script("scope.py").scopes(work)
  WIDTH = units.load_script("dex.py").WIDTH
  us = units.java_units(work, scopes)
  out = os.path.join(work, "flows.txt")
  if work not in units.DEX_INDEX:
    with open(out, "w") as f:
      f.write("# Data flows: %s\nno dex files under raw/: nothing analyzed\n" % name)
    print("wrote %s (no dex)" % os.path.relpath(out, ROOT))
    return
  methods, _hier, units_for, dispatch = units.DEX_INDEX[work]
  an = Analyzer(methods, dispatch)
  keys = [k for k, m in methods.items() if m.code and m.dex is not None]
  report = set()
  for rnd in range(4):
    for k in keys:
      try:
        an.run(k, methods[k], report if rnd == 3 else None)
      except (struct.error, IndexError):
        pass
  # group by method where the flow happens; map to jadx locations. Methods of classes
  # jadx shows inline (anonymous classes, lambdas) count for the method creating them.
  creator = {}
  for k, m in methods.items():
    for t in m.news:
      creator.setdefault(t, k)

  def locate(key, depth=0):
    us_ = units_for(key)
    if us_ or depth > 4 or key not in methods:
      return us_
    c = creator.get(methods[key].cls)
    return locate(c, depth + 1) if c else []

  rows = {}
  for key, src, src_api, snk, api, via, xf in report:
    us_ = locate(key)
    where = us_[0].where if us_ else "%s (bytecode only: no jadx method found)" % api_name(key)
    rows.setdefault(snk, set()).add((where, src, api_name(src_api), api_name(api), api_name(via) if via else "", xf))
  with open(out, "w") as f:
    w = lambda s="": f.write(s + "\n")
    w("# Data flows: %s" % name)
    w("Values from a source API that reach a sink API, followed through registers, fields,")
    w("library calls, and app-method summaries in the bytecode. Branches are ignored, so a")
    w("flow may be impossible at run time; some flows are missed. Leads only: read the method.")
    w("[XOR or cipher on the way]: the value passed an XOR or javax.crypto.Cipher; for an asset")
    w("or download written to a file or class loader, that is the shape of a payload decryptor.")
    w("java scopes: %s; methods analyzed: %d" % (", ".join(scopes), len(keys)))
    order = [s for s, _p in SINKS]
    for snk in order:
      rs = sorted(rows.get(snk, ()))
      w()
      w("## to %s (%d)" % (snk, len(rs)))
      for where, src, sapi, kapi, via, xf in rs[:40]:
        w("- %s  %s (%s) -> %s%s%s" % (where, src, sapi, kapi, " via %s" % via if via else "",
                                       "  [XOR or cipher on the way]" if xf else ""))
      if len(rs) > 40:
        w("- ... %d more" % (len(rs) - 40))
  print("wrote %s (%d flows)" % (os.path.relpath(out, ROOT), sum(len(v) for v in rows.values())))


if __name__ == "__main__":
  main()
