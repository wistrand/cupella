#!/usr/bin/env python3
"""Compare two unpacked APKs, typically two versions of one app: what was added,
removed, or changed in identity, signing, permissions, components, libraries,
endpoints, trackers, and native code.

Works on the summaries the other scripts wrote, so both APKs must have been through
unpack.sh. Reports differences only; an empty section means no change. Every line is
a lead: read the code behind a change before reporting it.

Usage: scripts/apk-diff.py <old-name> <new-name> > work/<new-name>/diff-from-<old-name>.txt
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
URL = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>\\]{3,}")
NOISE_URL = re.compile(r"schemas\.android\.com|www\.w3\.org|xml\.org|apache\.org/licenses|xmlpull\.org|"
                       r"java\.sun\.com|ns\.adobe\.com|purl\.org|slf4j\.org|issuetracker\.google\.com|"
                       r"developer\.android\.com|goo\.gle|youtrack\.jetbrains|flutter\.dev|dart\.dev")


def read(name, rel):
  p = os.path.join(ROOT, "work", name, rel)
  if not os.path.exists(p):
    return None
  with open(p, errors="replace") as f:
    return f.read()


def sections(text):
  """Markdown-ish summary -> {heading: [lines]} keeping order within a section."""
  out, cur = {}, "(top)"
  for line in (text or "").split("\n"):
    if line.startswith(("## ", "### ")):
      cur = line.lstrip("# ").strip()
      cur = re.sub(r" \(\d+[^)]*\)$", "", cur)  # drop counts so headings compare
      out.setdefault(cur, [])
    elif line.strip():
      text = line.rstrip()
      out.setdefault(cur, []).append(text[2:] if text.startswith("- ") else text)
  return out


def show(title, removed, added, limit=60):
  removed, added = sorted(removed), sorted(added)
  if not removed and not added:
    return False
  print("\n### %s" % title)
  for x in removed[:limit]:
    print("- %s" % x[:200])
  if len(removed) > limit:
    print("- ... %d more removed" % (len(removed) - limit))
  for x in added[:limit]:
    print("+ %s" % x[:200])
  if len(added) > limit:
    print("+ ... %d more added" % (len(added) - limit))
  return True


def diff_summary(title, old, new, rel, skip=()):
  a, b = sections(read(old, rel)), sections(read(new, rel))
  if not a and not b:
    return
  print("\n## %s (%s)" % (title, rel))
  if not a or not b:
    print("only present for: %s" % (new if b else old))
    return
  changed = False
  for head in list(dict.fromkeys(list(a) + list(b))):
    if any(s in head for s in skip):
      continue
    la, lb = set(a.get(head, [])), set(b.get(head, []))
    changed |= show(head, la - lb, lb - la)
  if not changed:
    print("no differences")


def field(text, pattern):
  m = re.search(pattern, text or "", re.M)
  return m.group(1).strip() if m else None


def packages(name, depth=3):
  text = read(name, os.path.join("dex", "classes.txt"))
  out = {}
  for line in (text or "").split("\n"):
    cls = line.split("\t")[-1]
    if cls:
      key = ".".join(cls.split(".")[:depth]) if cls.count(".") >= depth else cls.rsplit(".", 1)[0]
      out[key] = out.get(key, 0) + 1
  return out


def urls(name):
  found = set()
  for rel in (os.path.join("dex", "strings.txt"), "flutter-strings.txt"):
    for u in URL.findall(read(name, rel) or ""):
      if not NOISE_URL.search(u):
        found.add(u.rstrip(".,);"))
  return found


def main():
  if len(sys.argv) != 3:
    sys.exit(__doc__)
  old, new = sys.argv[1], sys.argv[2]
  for n in (old, new):
    if not os.path.isdir(os.path.join(ROOT, "work", n, "raw")):
      sys.exit("work/%s/raw not found: run ./cupella unpack.sh data/%s.apk first" % (n, n))
  print("# APK diff: %s -> %s" % (old, new))
  print("'-' lines exist only in the old APK, '+' lines only in the new one.")

  ta, tb = read(old, "triage.txt") or "", read(new, "triage.txt") or ""
  print("\n## Identity and signing")
  for label, pat in (("package", r'^package="([^"]*)"'), ("versionName", r'versionName="([^"]*)"'),
                     ("versionCode", r'versionCode="([^"]*)"'), ("minSdk", r'minSdkVersion="([^"]*)"'),
                     ("targetSdk", r'targetSdkVersion="([^"]*)"'), ("size", r"^size:\s+(\d+)"),
                     ("verification", r"^RESULT: (.*)$")):
    va, vb = field(ta, pat), field(tb, pat)
    print("%-13s %s%s" % (label + ":", va, "" if va == vb else "  ->  %s" % vb))
  ca = set(re.findall(r"cert \d+ sha256 ([0-9a-f]{64})", ta)) | set(re.findall(r"certificate sha256 ([0-9a-f]{64})", ta))
  cb = set(re.findall(r"cert \d+ sha256 ([0-9a-f]{64})", tb)) | set(re.findall(r"certificate sha256 ([0-9a-f]{64})", tb))
  if ca == cb:
    print("signer:       same certificate(s) %s" % ", ".join(sorted(c[:16] + "..." for c in ca)))
  else:
    print("signer:       CHANGED. An update signed with a different key cannot install over")
    print("              the old app; treat the two as coming from different publishers until explained.")
    show("signing certificates (sha256)", ca - cb, cb - ca)
  if field(ta, r'^package="([^"]*)"') != field(tb, r'^package="([^"]*)"'):
    print("NOTE: different package names: these are two different apps, not two versions.")

  diff_summary("Manifest", old, new, "manifest-summary.txt", skip=("Component totals",))
  diff_summary("Trackers", old, new, "trackers.txt")
  diff_summary("APKiD", old, new, "apkid.txt")

  print("\n## Code packages (dex)")
  pa, pb = packages(old), packages(new)
  gone = {"%s (%d classes)" % (k, v) for k, v in pa.items() if k not in pb and v >= 3}
  came = {"%s (%d classes)" % (k, v) for k, v in pb.items() if k not in pa and v >= 3}
  if not show("packages removed / added (3+ classes)", gone, came):
    print("no package added or removed")
  grown = sorted(((pb[k] - pa[k], k) for k in pa if k in pb and abs(pb[k] - pa[k]) >= max(5, pa[k] // 4)),
                 reverse=True)
  if grown:
    print("\n### packages that changed size notably")
    for d, k in grown[:30]:
      print("  %+5d  %s (%d -> %d)" % (d, k, pa[k], pb[k]))
  print("\nclasses total: %d -> %d" % (sum(pa.values()), sum(pb.values())))

  print("\n## URLs in dex and Dart strings")
  ua, ub = urls(old), urls(new)
  if not show("URLs removed / added", ua - ub, ub - ua, 80):
    print("no differences")

  diff_summary("Native libraries", old, new, "native-summary.txt",
               skip=("Strings of interest",))
  diff_summary("Flutter", old, new, "flutter-summary.txt",
               skip=("Credential-related names", "Snapshot"))

  print("\n## What to do with this")
  print("New permissions, newly exported components, new packages, new URLs, new tracker")
  print("matches, and new sensitive native imports are where an update changes what the")
  print("app can do. Read the code behind each in the new APK (scan.sh, dart-index.py).")


if __name__ == "__main__":
  main()
