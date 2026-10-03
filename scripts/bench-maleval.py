#!/usr/bin/env python3
"""Check the scripted outputs against MalEval's per-sample behavior labels.

MalEval (github.com/ZhengXR930/MalEval) labels each malware sample with behavior
classes taken from vendor reports (Remote Control, Privacy Stealing, SMS/CALL, ...);
its 25 benign apps have none. The labels are per app, not per function, so this
measures whether the scripted outputs give the agent a lead toward each labeled
behavior, not whether the lead is the right code.

For each behavior a sample is labeled with, two kinds of signal are checked:
  code   a matching section of scan.txt (app scope) or structure-leads.txt is non-empty
  decl   the manifest declares a matching permission or component, or trackers.txt and
         apkid.txt name a matching SDK or tool
  flow   flows.txt has a matching data flow (Privacy Stealing: personal data to the
         network, a stream, SMS, or another app; SMS/CALL: anything to an SMS send;
         Stealthy Download and Tricky Behavior: an asset or download written to a file,
         storage, or class loader after XOR or a cipher, the shape of a dropper)
Benign apps show how often the same signals fire without the behavior: a lead rate,
not a false-positive rate, since benign apps also read contacts or send SMS.

Signals of embedded payloads (work/<sha256>.emb<k>/, unpacked by unpack.sh) count for
the sample. Also reported per sample: Java classes in scan scope (zero means the app's code is
somewhere scan.sh did not look: a packer, a loader, or renamed packages).

Expects bench/maleval/info/*_sample_info.json and each APK unpacked and scanned under
work/<sha256>/.
Usage: ./cupella bench-maleval.py [-v]      -v lists each malware sample's misses
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
INFO = os.path.join(ROOT, "bench", "maleval", "info")

# behavior: scan.txt sections, structure-leads.txt capability words, permissions or
# manifest strings, tracker categories, APKiD lines
SIGNALS = {
  "Privacy Stealing": (["Identifiers", "Location", "Contacts, SMS, calls", "Camera, mic, sensors", "Installed apps",
                        "Accessibility reads", "Notification access", "Clipboard, screenshots"],
                       ["private data"],
                       ["READ_CONTACTS", "READ_SMS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_PHONE_STATE",
                        "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "GET_ACCOUNTS", "READ_PHONE_NUMBERS"], [], []),
  "SMS/CALL": (["Contacts, SMS, calls"], [],
               ["SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS", "CALL_PHONE", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
                "ANSWER_PHONE_CALLS", "RECEIVE_MMS"], [], []),
  "Premium Service": (["Contacts, SMS, calls"], [], ["SEND_SMS", "CALL_PHONE", "RECEIVE_SMS"], [], []),
  "Remote Control": (["Cleartext, sockets", "Data out", "Local servers, LAN"], ["network"],
                     ["com.google.firebase.MESSAGING_EVENT", "com.google.android.c2dm"], [], []),
  "Abusing Accessibility": (["Accessibility, overlay, admin", "Accessibility reads"], ["accessibility"],
                            ["BIND_ACCESSIBILITY_SERVICE"], [], []),
  "Bank Stealing": (["Accessibility, overlay, admin", "Accessibility reads"], ["overlay", "accessibility"],
                    ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"], [], []),
  "Ransom": (["Accessibility, overlay, admin", "Custom masking, weak crypto"], ["overlay"],
             ["BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW"], [], []),
  "Privilege Escalation": (["Dynamic code", "Anti-analysis"], ["process", "system settings"],
                           ["BIND_DEVICE_ADMIN", "WRITE_SECURE_SETTINGS", "WRITE_SETTINGS"], [], ["root", "su "]),
  "Stealthy Download": (["Package install", "Dynamic code"], ["code loading", "package install"],
                        ["REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DOWNLOAD_WITHOUT_NOTIFICATION"], [], []),
  "Ads": (["Ads"], [], [], ["Advertisement"], []),
  "Tricky Behavior": (["Component toggling", "Anti-analysis"], ["anti-analysis strings"], [], [],
                      ["packer", "protector", "obfuscator", "anti_vm", "anti_debug", "manipulator"]),
}


# behaviors a data flow (flows.txt) speaks to: source categories, sink sections
FLOWS = {
  "Privacy Stealing": ({"device id", "location", "content query", "SMS received", "accounts", "installed apps",
                        "clipboard", "screen text", "notification"},
                       {"network", "stream write (file or socket)", "SMS send", "other apps"}),
  "SMS/CALL": (None, {"SMS send"}),
  "Premium Service": (None, {"SMS send"}),
  "Bank Stealing": ({"screen text", "SMS received", "notification"}, {"network", "stream write (file or socket)", "SMS send"}),
  "Stealthy Download": ({"bundled asset", "network input"}, {"stream write (file or socket)", "code", "storage"}, True),
  "Tricky Behavior": ({"bundled asset", "network input"}, {"stream write (file or socket)", "code", "storage"}, True),
}


def flow_signal(work, beh):
  if beh not in FLOWS:
    return None
  text = read(os.path.join(work, "flows.txt")) or ""
  srcs, sinks = FLOWS[beh][:2]
  need_xform = len(FLOWS[beh]) > 2
  sec = None
  for line in text.split("\n"):
    if line.startswith("## to "):
      sec = re.sub(r" \(\d+\)$", "", line[6:])
    elif line.startswith("- ") and sec in sinks:
      m = re.search(r"  ([\w ]+) \(", line)
      if (srcs is None or (m and m.group(1) in srcs)) and (not need_xform or "XOR or cipher" in line):
        return True
  return False


def read(path):
  try:
    with open(path, errors="replace") as f:
      return f.read()
  except OSError:
    return None


def scan_sections(text):
  out, cur = {}, None
  for line in (text or "").split("\n"):
    if line.startswith("## "):
      cur = line[3:].strip()
      out[cur] = 0
    elif cur and line.strip() and not line.startswith("#"):
      out[cur] += 1
  return out


def signals(name):
  work = os.path.join(ROOT, "work", name)
  scan = read(os.path.join(work, "scan.txt"))
  if scan is None:
    return None
  secs = scan_sections(scan)
  struct = read(os.path.join(work, "structure-leads.txt")) or ""
  manifest = read(os.path.join(work, "manifest.xml")) or ""
  trackers = read(os.path.join(work, "trackers.txt")) or ""
  sdk = trackers.split("## Tracker domains")[0]
  apkid = read(os.path.join(work, "apkid.txt")) or ""
  scope = re.search(r"^scope: (.*?) \(under", scan, re.M)
  scope = scope.group(1).split() if scope else []
  nclasses = 0
  for s in scope:
    d = os.path.join(work, "jadx", "sources", s)
    for _dp, _dn, fn in os.walk(d):
      nclasses += sum(1 for f in fn if f.endswith(".java"))
  out = {"_classes": nclasses, "_packed": bool(re.search(r"\|-> (packer|protector)", apkid))}
  for beh, (sections, caps, decl, trk, kid) in SIGNALS.items():
    code = any(secs.get(s, 0) for s in sections) or any(
      re.search(r"(?m)^- .*\b%s\b" % re.escape(c), struct) for c in caps)
    dec = any(d in manifest for d in decl) or any("[%s" % t in sdk for t in trk) or any(
      re.search(r"\|-> .*%s" % re.escape(k), apkid) for k in kid)
    out[beh] = (code, dec, flow_signal(work, beh))
  return out


def signals_with_children(name, depth=0):
  """signals of a sample OR those of its embedded payloads (work/<name>.emb<k>/)"""
  s = signals(name)
  if s is None or depth > 1:
    return s
  emb = read(os.path.join(ROOT, "work", name, "embedded.txt")) or ""
  for line in emb.split("\n"):
    child = line.split("\t")[0].strip()
    if not child:
      continue
    c = signals_with_children(child, depth + 1)
    if c is None:
      continue
    for beh in SIGNALS:
      s[beh] = tuple(bool(a) or bool(b) for a, b in zip(s[beh], c[beh]))
  return s


def main():
  verbose = "-v" in sys.argv
  splits = [("archived_sample_info.json", "malware"), ("latest_sample_info.json", "malware"),
            ("benign_sample_info.json", "benign")]
  rows, missing = [], 0
  for fn, kind in splits:
    with open(os.path.join(INFO, fn)) as f:
      for sha, meta in json.load(f).items():
        s = signals_with_children(sha)
        if s is None:
          missing += 1
          continue
        rows.append((kind, sha, meta, s))
  mal = [r for r in rows if r[0] == "malware"]
  ben = [r for r in rows if r[0] == "benign"]
  print("# MalEval behavior signals")
  print("samples scanned: %d malware, %d benign; %d not yet unpacked and scanned" % (len(mal), len(ben), missing))
  empty = [r for r in mal if r[3]["_classes"] == 0]
  print("malware with no Java classes in scan scope: %d (%d of them flagged packed/protected by APKiD)" % (
    len(empty), sum(1 for r in empty if r[3]["_packed"])))
  print()
  print("%-22s %6s %7s %7s %7s %7s   %s" % ("behavior", "labeled", "code", "decl", "either", "flow",
                                         "benign: code / decl / flow"))
  for beh in SIGNALS:
    lab = [r for r in mal if beh in r[2].get("behavior", [])]
    if not lab:
      continue
    c = sum(1 for r in lab if r[3][beh][0])
    d = sum(1 for r in lab if r[3][beh][1])
    e = sum(1 for r in lab if r[3][beh][0] or r[3][beh][1])
    bc = sum(1 for r in ben if r[3][beh][0])
    bd = sum(1 for r in ben if r[3][beh][1])
    pct = lambda n, t: "%3d%%" % (100.0 * n / t) if t else "  - "
    if beh in FLOWS:
      fl = pct(sum(1 for r in lab if r[3][beh][2]), len(lab))
      bf = pct(sum(1 for r in ben if r[3][beh][2]), len(ben))
    else:
      fl = bf = "  - "
    print("%-22s %6d %7s %7s %7s %7s   %s / %s / %s of %d" % (beh, len(lab), pct(c, len(lab)), pct(d, len(lab)),
                                                            pct(e, len(lab)), fl, pct(bc, len(ben)),
                                                            pct(bd, len(ben)), bf, len(ben)))
  if verbose:
    print()
    for kind, sha, meta, s in mal:
      miss = [b for b in meta.get("behavior", []) if b in SIGNALS and not (s[b][0] or s[b][1])]
      if miss:
        print("%s %-12s %-14s classes %-5d %s  missed: %s" % (sha[:16], meta.get("family", "")[:12],
                                                             meta.get("type", "")[:14], s["_classes"],
                                                             "packed" if s["_packed"] else "      ", ", ".join(miss)))


if __name__ == "__main__":
  main()
