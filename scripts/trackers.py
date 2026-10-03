#!/usr/bin/env python3
"""Match an unpacked APK against the Exodus Privacy tracker signature list.

Two kinds of signature, both from the list bundled in the image
($APK_TOOLS/exodus-trackers.json, fetched when the image was built):

  code     class-name patterns, matched against every class in the dex files
  network  domain patterns, matched against host names found in string constants of
           the dex files and, for Flutter apps, the Dart snapshot (hosts of URLs and
           bare domain names; library documentation links are left out)

A code match means the tracker's SDK classes are in the APK. It does not show the
SDK is initialized or what it sends: that is for the agent to read. A network-only
match is weaker: the domain appears as a string somewhere. No match is meaningful
only when library class names are intact; with R8 renaming of libraries, SDK classes
no longer carry their package names and code signatures cannot match.

Usage: scripts/trackers.py <name> > work/<name>/trackers.txt
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
URL_HOST = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
BARE_HOST = re.compile(r"^(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|ai|app|dev|cloud|info|biz|me|tv|ly|cn|ru|de|fr|uk|jp|in|br|eu|us)$")
# hosts that appear in library error messages and docs, not in app behavior
DOC_HOSTS = re.compile(r"^(?:issuetracker|developer|developers|source|support|play|g|goo)\.(?:google|android)\.com$|"
                       r"^(?:developer\.android\.com|goo\.gle|g\.co|schemas\.android\.com|www\.w3\.org|"
                       r"github\.com|youtrack\.jetbrains\.com|kotlinlang\.org|flutter\.dev|dart\.dev|pub\.dev)$")


def main():
  name = sys.argv[1]
  work = os.path.join(ROOT, "work", name)
  listing = os.path.join(os.environ.get("APK_TOOLS", ""), "exodus-trackers.json")
  print("# Trackers: %s" % name)
  if not os.path.exists(listing):
    print("tracker list not found at %s (image built without it?)" % listing)
    return
  with open(listing) as f:
    trackers = json.load(f)["trackers"]
  print("Exodus Privacy signature list: %d trackers (snapshot in the image; see ./cupella versions)" % len(trackers))

  classes = []
  cpath = os.path.join(work, "dex", "classes.txt")
  if os.path.exists(cpath):
    with open(cpath) as f:
      classes = [line.rstrip("\n").split("\t")[-1] for line in f]
  strings = set()  # host names, not whole strings: a domain pattern must hit a host
  for rel in (os.path.join("dex", "strings.txt"), "flutter-strings.txt"):
    p = os.path.join(work, rel)
    if os.path.exists(p):
      with open(p, errors="replace") as f:
        for line in f:
          s = line.rstrip("\n").split("\t")[-1]
          if "." not in s:
            continue
          for h in URL_HOST.findall(s):
            strings.add(h.lower())
          if len(s) < 80 and BARE_HOST.match(s):
            strings.add(s)
  strings = {h for h in strings if not DOC_HOSTS.match(h)}

  # how much of the dex keeps real package names: decides what "no match" is worth
  short = sum(1 for c in classes if len(c.split(".")[0]) <= 2)
  ratio = short / len(classes) if classes else 0
  print("classes: %d, of which %d (%.0f%%) are in one- or two-letter top-level packages" % (
    len(classes), short, 100 * ratio))
  if ratio > 0.3:
    print("NOTE: much of the code is renamed (R8). Code signatures cannot match renamed SDK")
    print("classes, so absence of code matches is weak evidence here. Network matches and")
    print("reading the code matter more.")

  blob = "\n".join(classes)
  sblob = "\n".join(sorted(strings))
  code_hits, net_hits = [], []
  for t in trackers.values():
    code, net = (t.get("code_signature") or "").strip(), (t.get("network_signature") or "").strip()
    matched_classes, matched_strings = [], []
    if code:
      try:
        rx = re.compile(code)
        matched_classes = [c for c in classes if rx.search(c)] if rx.search(blob) else []
      except re.error:
        pass
    if net:
      try:
        rx = re.compile(net)
        matched_strings = sorted({s for s in strings if rx.search(s)})[:6] if rx.search(sblob) else []
      except re.error:
        pass
    if matched_classes:
      code_hits.append((t, matched_classes, matched_strings))
    elif matched_strings:
      net_hits.append((t, matched_strings))

  def cats(t):
    c = t.get("categories") or []
    return ", ".join(c) if c else "uncategorized"

  print("\n## Tracker SDK code present (%d)" % len(code_hits))
  for t, cl, st in sorted(code_hits, key=lambda x: x[0]["name"].lower()):
    pkgs = sorted({".".join(c.split(".")[:4]) for c in cl})
    print("- %s [%s]: %d classes, e.g. %s" % (t["name"], cats(t), len(cl), ", ".join(pkgs[:3])))
    print("    signature: %s" % t["code_signature"][:120])
    if st:
      print("    its domains also appear in strings: %s" % ", ".join(st[:3]))
    if t.get("website"):
      print("    %s" % t["website"])
  if not code_hits:
    print("- none")

  print("\n## Tracker domains among host names in strings, no SDK classes matched (%d)" % len(net_hits))
  print("Weaker: a host name in a string. Some signatures are broad (Google Ads is any")
  print("*.google.com host). Find what uses the host before calling it a tracker.")
  by_hosts = {}
  for t, st in net_hits:
    by_hosts.setdefault(tuple(st[:3]), []).append(t["name"])
  for hosts, names in sorted(by_hosts.items()):
    names = sorted(names)
    print("- %s: matches %s%s" % (", ".join(hosts), ", ".join(names[:4]),
                                 " (+%d more signatures)" % (len(names) - 4) if len(names) > 4 else ""))
  if not net_hits:
    print("- none")


if __name__ == "__main__":
  main()
