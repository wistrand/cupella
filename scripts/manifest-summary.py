#!/usr/bin/env python3
"""Summarize a decoded AndroidManifest.xml: permissions, application flags, every
component reachable from outside the app with its intent filters, intent-filter
priorities, and activity task attributes.

Reads the apktool manifest when present, else the fallback decode from axml2xml.py.
Requested permissions are grouped by who defines them (android_perms.py): platform,
the app itself, Google, other apps, or nobody (invented names, counted only).

Usage: scripts/manifest-summary.py <name> > work/<name>/manifest-summary.txt
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import android_perms  # noqa: E402

A = "{http://schemas.android.com/apk/res/android}"
APP_FLAGS = ["name", "debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig",
             "fullBackupContent", "dataExtractionRules", "requestLegacyExternalStorage",
             "extractNativeLibs", "testOnly", "sharedUserId"]
COMPONENTS = ["activity", "activity-alias", "service", "receiver", "provider"]


def attr(el, name, default=None):
  return el.get(A + name, default)


def filter_lines(f):
  parts = []
  for tag, key in (("action", "name"), ("category", "name")):
    vals = [attr(e, key, "?").replace("android.intent.", "") for e in f.findall(tag)]
    if vals:
      parts.append("%s: %s" % (tag, ", ".join(vals)))
  data = {}
  for d in f.findall("data"):
    for k in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"):
      if attr(d, k) is not None:
        data.setdefault(k, []).append(attr(d, k))
  for k, v in data.items():
    shown = v if len(v) <= 8 else v[:8] + ["... +%d more" % (len(v) - 8)]
    parts.append("%s: %s" % (k, ", ".join(shown)))
  if attr(f, "autoVerify") == "true":
    parts.append("autoVerify")
  if attr(f, "priority") is not None:
    parts.append("priority: %s" % attr(f, "priority"))
  return "; ".join(parts)


def main():
  name = sys.argv[1]
  root_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name)
  path = os.path.join(root_dir, "apktool", "AndroidManifest.xml")
  if not os.path.exists(path):
    path = os.path.join(root_dir, "manifest.xml")
  if not os.path.isfile(path) or not os.path.getsize(path):
    parent = re.match(r"(.+)\.(?:dec|emb)\d+$", name)
    print("No AndroidManifest.xml in this sample (dex only).")
    if parent:
      print("A child sample without a manifest runs inside its parent's process, with the parent's")
      print("permissions and native libraries: see work/%s/manifest-summary.txt." % parent.group(1))
    return
  m = ET.parse(path).getroot()
  app = m.find("application")
  sdk = m.find("uses-sdk")
  target = int(attr(sdk, "targetSdkVersion", "0")) if sdk is not None else 0

  print("# Manifest summary: %s" % name)
  print("source: %s" % os.path.relpath(path, os.path.join(root_dir, "..", "..")))
  print("package: %s" % m.get("package"))
  if not target:
    print("targetSdkVersion not in this manifest (apktool keeps it in apktool.yml)")

  # grouped by who defines the name; invented names (padding that grants nothing) are
  # counted, not listed, so the real permissions stay visible
  req = []
  for tag in ("uses-permission", "uses-permission-sdk-23"):
    for p in m.findall(tag):
      extra = " (maxSdk %s)" % attr(p, "maxSdkVersion") if attr(p, "maxSdkVersion") else ""
      extra += " [sdk-23 only]" if tag.endswith("23") else ""
      req.append((attr(p, "name") or "?", extra))
  kinds = android_perms.classify({n for n, _ in req}, {attr(p, "name") for p in m.findall("permission")}, m.get("package"))
  undefined = [n for n, _ in req if kinds[n] == "undefined"]
  print("\n## Permissions requested")
  print("%d requested: %s" % (len(req), ", ".join("%d %s" % (sum(1 for n, _ in req if kinds[n] == k), k)
                                                  for k in ("platform", "app", "google", "other", "undefined", "unknown")
                                                  if any(kinds[n] == k for n, _ in req))))
  seen = set()
  for n, extra in req:
    if kinds[n] != "undefined" and (n, extra) not in seen:
      seen.add((n, extra))
      print("- %s%s%s" % (n, extra, "" if kinds[n] in ("platform", "unknown") else "  [%s]" % kinds[n]))
  if undefined:
    print("Not defined by Android, Google, or this app (padding: grants nothing): %d, e.g. %s" % (
      len(undefined), ", ".join(sorted(set(undefined))[:6])))

  print("\n## Permissions declared")
  for p in m.findall("permission"):
    print("- %s protectionLevel=%s" % (attr(p, "name"), attr(p, "protectionLevel", "normal")))

  print("\n## Application flags")
  for k in APP_FLAGS:
    v = attr(app, k) if k != "sharedUserId" else attr(m, k)
    if v is not None:
      print("- %s = %s" % (k, v))

  print("\n## Components reachable from other apps")
  print("explicit = android:exported=\"true\"; implicit = has an intent filter and no")
  print("exported attribute (exported when targetSdkVersion < 31)\n")
  counts = {}
  for tag in COMPONENTS:
    for c in app.findall(tag):
      counts[tag] = counts.get(tag, 0) + 1
      exported, filters = attr(c, "exported"), c.findall("intent-filter")
      if exported == "true":
        how = "explicit"
      elif exported is None and filters:
        how = "implicit"
      else:
        continue
      flags = []
      if attr(c, "permission"):
        flags.append("permission=" + attr(c, "permission"))
      if attr(c, "enabled") == "false":
        flags.append("disabled")
      if tag == "provider":
        flags.append("authorities=" + attr(c, "authorities", "?"))
        for k in ("readPermission", "writePermission", "grantUriPermissions"):
          if attr(c, k):
            flags.append("%s=%s" % (k, attr(c, k)))
      if attr(c, "targetActivity"):
        flags.append("-> " + attr(c, "targetActivity"))
      print("- %s %s [%s]%s" % (tag, attr(c, "name"), how, " " + " ".join(flags) if flags else ""))
      for f in filters:
        print("    filter: %s" % filter_lines(f))

  print("\n## Intent filters with a priority, all components")
  print("A high priority lets a receiver see an ordered broadcast (SMS_RECEIVED) first and abort")
  print("it, or puts an activity first in the chooser.")
  for tag in COMPONENTS:
    for c in app.findall(tag):
      for f in c.findall("intent-filter"):
        if attr(f, "priority") is not None:
          print("- %s %s exported=%s: %s" % (tag, attr(c, "name"), attr(c, "exported", "unset"), filter_lines(f)))

  print("\n## Activity task attributes")
  print("taskAffinity and allowTaskReparenting decide which task an activity joins; a foreign")
  print("or empty affinity, reparenting, or singleTask/singleInstance enable task hijacking.")
  for tag in ("activity", "activity-alias"):
    for c in app.findall(tag):
      attrs = ["%s=%s" % (k, attr(c, k)) for k in ("taskAffinity", "allowTaskReparenting", "launchMode",
                                                  "excludeFromRecents", "documentLaunchMode")
               if attr(c, k) is not None and not (k == "launchMode" and attr(c, k) in ("0", "standard"))]
      if attrs:
        print("- %s %s" % (attr(c, "name"), " ".join(attrs)))
  if attr(app, "taskAffinity") is not None:
    print("- application taskAffinity=%s" % attr(app, "taskAffinity"))

  print("\n## Non-exported providers with grantUriPermissions")
  for c in app.findall("provider"):
    if attr(c, "exported") != "true" and attr(c, "grantUriPermissions") == "true":
      print("- %s authorities=%s" % (attr(c, "name"), attr(c, "authorities")))

  print("\n## Component totals")
  print(", ".join("%s: %d" % kv for kv in counts.items()))

  print("\n## meta-data (application level)")
  for md in app.findall("meta-data"):
    print("- %s = %s" % (attr(md, "name"), attr(md, "value", attr(md, "resource", ""))))

  q = m.find("queries")
  if q is not None:
    print("\n## queries")
    for e in q:
      label = attr(e, "name") or filter_lines(e)
      print("- %s %s" % (e.tag, label))


if __name__ == "__main__":
  main()
