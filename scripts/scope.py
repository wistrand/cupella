#!/usr/bin/env python3
"""The default source scope of an app: where its own code is under jadx/sources.

The manifest package alone misses much of it: malware and many apps declare
activities, services, and receivers in other packages (on MalEval, 153 of 230
malware samples), and R8 moves classes into the unnamed package (jadx: defpackage/).
The default scope is therefore:
  - the manifest package
  - the package of every component declared in the manifest, except known library
    packages (androidx, Google Play services, Kotlin, ...; not com.android.* in general,
    where malware likes to hide), tracker SDK packages named
    in trackers.txt, and one-segment packages such as "com" (a scope of all of com/)
  - defpackage/, when it exists
  - an R8-flattened package: one directory holding FLAT_MIN or more classes, most with
    names of three characters or fewer, outside the known libraries, whose code refers
    to the manifest package. R8 can merge app code and libraries into such a package
    under a generated name (verified: 1,444 classes including the app's config, string
    decoder, and DoS engine), and the rules above miss it.
Packages nested inside another chosen package are dropped. Directories that jadx did
not produce are skipped; when nothing remains the scope is "." (everything).

Used by scan.sh, structure-leads.py, model-leads.py, and lead-eval.py.
Usage: scripts/scope.py <name> [--why]   prints the scope, one path per line
  --why  adds the reason for each path after a tab
"""
import os
import glob
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LIBRARY = re.compile(r"^(android|androidx|com\.google|com\.android\.(?:billingclient|installreferrer|volley|vending)|kotlin|kotlinx|java|javax|dalvik|org\.jetbrains|"
                     r"com\.facebook|com\.squareup|okhttp3|okio|retrofit2|io\.flutter|io\.reactivex|"
                     r"com\.bumptech|com\.airbnb|org\.chromium|com\.huawei|com\.xiaomi|com\.unity3d|"
                     r"com\.applovin|com\.ironsource|com\.appsflyer|com\.adjust|io\.sentry|com\.journeyapps|"
                     r"org\.apache|com\.onesignal)(\.|$)")
FLAT_MIN = 300
SHORT = re.compile(r"^[A-Za-z_$][\w$]{0,2}\.java$")


def flattened(base, pkg, taken):
  """directories that look R8-flattened and refer to the manifest package"""
  out = []
  if not pkg:
    return out
  needle = pkg + "."
  for d, _dirs, fs in os.walk(base):
    java = [f for f in fs if f.endswith(".java")]
    if len(java) < FLAT_MIN or sum(1 for f in java if SHORT.match(f)) < 0.7 * len(java):
      continue
    rel = os.path.relpath(d, base)
    if rel == "." or rel == "defpackage" or LIBRARY.match(rel.replace("/", ".")):
      continue
    if any(rel == q or rel.startswith(q + "/") for q in taken):
      continue
    for f in java:
      with open(os.path.join(d, f), errors="replace") as fh:
        if needle in fh.read():
          out.append((rel, "R8-flattened: %d classes, refers to %s" % (len(java), pkg)))
          break
  return out


def scopes_why(work):
  """(paths, {path: reason})"""
  base = os.path.join(work, "jadx", "sources")
  try:
    with open(os.path.join(work, "manifest.xml"), errors="replace") as f:
      manifest = f.read()
  except OSError:
    manifest = ""
  m = re.search(r' package="([^"]+)"', manifest[:4000])
  pkg = m.group(1) if m else ""
  pkgs = [pkg] if pkg else []
  sdk = []
  try:
    with open(os.path.join(work, "trackers.txt"), errors="replace") as f:
      for line in f:
        if line.strip().startswith("signature:"):
          sdk += [s.strip().rstrip(".") for s in line.split(":", 1)[1].split("|") if s.strip()]
  except OSError:
    pass
  for m in re.finditer(r"<(?:activity|activity-alias|service|receiver|provider|application)\b[^>]*?"
                       r"android:name=\"([^\"]+)\"", manifest):
    name = m.group(1)
    if name.startswith("."):
      name = pkg + name
    elif "." not in name:
      name = pkg + "." + name
    p = name.rsplit(".", 1)[0] if "." in name else ""
    if p and "." in p and not LIBRARY.match(p) and not any(p == s or p.startswith(s + ".") for s in sdk):
      pkgs.append(p)
  paths, why = [], {}
  for p in sorted(set(pkgs), key=lambda x: (x.count("."), x)):
    path = p.replace(".", "/")
    if not os.path.isdir(os.path.join(base, path)):
      continue
    if any(path == q or path.startswith(q + "/") for q in paths):
      continue
    paths.append(path)
    why[path] = "manifest package" if p == pkg else "package of a declared component"
  if os.path.isdir(os.path.join(base, "defpackage")):
    paths.append("defpackage")
    why["defpackage"] = "R8 unnamed package"
  for path, reason in flattened(base, pkg, paths):
    paths.append(path)
    why[path] = reason
  if not paths:
    return ["."], {".": "no package found: everything"}
  return paths, why


def scopes(work):
  return scopes_why(work)[0]


if __name__ == "__main__":
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  paths, why = scopes_why(os.path.join(ROOT, "work", sys.argv[1]))
  print("\n".join("%s\t%s" % (p, why[p]) if "--why" in sys.argv else p for p in paths))
