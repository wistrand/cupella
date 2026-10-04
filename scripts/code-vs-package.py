#!/usr/bin/env python3
"""What the code uses that the package does not provide: permissions the code names but
the manifest does not request, and native libraries the code loads but the APK does
not ship.

Code that checks for a permission the app never requests stays behind the check, and a
library that is not in the APK cannot be loaded, so the feature behind either does not
work as shipped (unless something delivers the library later). Malware built from a kit
often carries such features. Report them as present but inert, never as working.

Reads the scoped jadx sources and, when present, jadx-strings/ (decrypted string calls
annotated by annotate-strings.py), so permission and library names hidden by string
encryption count too. Sections are appended to scan.txt by scan.sh.

Usage: ./cupella code-vs-package.py <name> [scope ...]   (default scope: scope.py)
Output: stdout
"""
import glob
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import android_perms  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PERM = re.compile(r"android\.permission\.[A-Z][A-Z0-9_]+")
LOADLIB = re.compile(r'System\.loadLibrary\(\s*"([\w.+-]+)"')
SOFILE = re.compile(r"\blib[\w.+-]*?\.so\b")
SHOW = 3


def manifest_text(work):
  """the decoded manifest, or None when the sample has none (a dex-only child)"""
  for p in (os.path.join(work, "apktool", "AndroidManifest.xml"), os.path.join(work, "manifest.xml")):
    if os.path.isfile(p) and os.path.getsize(p):
      with open(p, errors="replace") as f:
        return f.read()
  return None


def manifest_permissions(text):
  return set(re.findall(r'<uses-permission(?:-sdk-23)?\b[^>]*?android:name="([^"]+)"', text or ""))


def host_chain(name):
  """the sample, then, while a sample has no manifest of its own, its parent (work/<parent>.dec<k>/
  and .emb<k>/ children): a dex-only child runs in its parent's process, with the parent's
  permissions and native libraries"""
  chain = [name]
  while manifest_text(os.path.join(ROOT, "work", chain[-1])) is None:
    m = re.match(r"(.+)\.(?:dec|emb)\d+$", chain[-1])
    if not m or not os.path.isdir(os.path.join(ROOT, "work", m.group(1))):
      break
    chain.append(m.group(1))
  return chain


def shipped_libraries(work):
  names = set()
  for d in ("lib", "assets"):
    for p in glob.glob(os.path.join(work, "raw", d, "**", "*.so"), recursive=True):
      names.add(os.path.basename(p))
  return names


def files(work, scopes):
  src = os.path.join(work, "jadx", "sources")
  ann = os.path.join(work, "jadx-strings")
  seen = set()
  inside = tuple("" if sc in (".", "") else sc.strip("/") + "/" for sc in scopes)
  if os.path.isdir(ann):  # annotated copies first: they hold the decrypted names
    for p in glob.glob(os.path.join(ann, "**", "*.java"), recursive=True):
      rel = os.path.relpath(p, ann)
      if not rel.startswith(inside):
        continue  # a library class with decoded strings: outside the scope, as its source is
      seen.add(rel)
      yield "jadx-strings/" + rel, p
  for sc in scopes:
    base = src if sc in (".", "") else os.path.join(src, sc)
    for p in glob.glob(os.path.join(base, "**", "*.java"), recursive=True):
      rel = os.path.relpath(p, src)
      if rel not in seen:
        seen.add(rel)
        yield "jadx/sources/" + rel, p


def main():
  args = sys.argv[1:]
  if not args:
    sys.exit(__doc__)
  name, scopes = args[0], args[1:]
  work = os.path.join(ROOT, "work", name)
  if not scopes:
    scopes = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "scope.py"), name],
                            capture_output=True, text=True).stdout.split()
  chain = host_chain(name)
  requested = manifest_permissions(manifest_text(os.path.join(ROOT, "work", chain[-1])))
  levels = android_perms.levels()
  shipped = set()
  for c in chain:
    shipped |= shipped_libraries(os.path.join(ROOT, "work", c))
  perms, libs = {}, {}
  for rel, p in files(work, scopes):
    with open(p, errors="replace") as f:
      for i, line in enumerate(f, 1):
        for m in set(PERM.findall(line)):
          perms.setdefault(m, []).append("%s:%d" % (rel, i))
        for m in LOADLIB.findall(line):
          libs.setdefault("lib%s.so" % m, []).append("%s:%d" % (rel, i))
        for m in set(SOFILE.findall(line)):
          libs.setdefault(m, []).append("%s:%d" % (rel, i))

  print("\n## Permissions the code names but the manifest does not request (features behind them fail)")
  print("Platform permissions only; signature-level ones no ordinary app can hold are marked. A name in")
  print("a list or table (describing other apps) is not a check: read the line.")
  if len(chain) > 1:
    print("This sample has no manifest of its own: it runs in the process of work/%s/, whose manifest" % chain[-1])
    print("and native libraries count here.")
  n = 0
  for perm in sorted(perms):
    if perm in requested or perm not in levels or perm.startswith("android.permission.BIND_"):
      continue
    lv = levels[perm]
    where = perms[perm]
    note = "" if android_perms.grantable(lv) else "  [%s: not grantable to apps]" % android_perms.describe(lv)
    print("- %s (%s)%s: %d place(s), e.g. %s" % (perm, android_perms.describe(lv), note, len(where), ", ".join(where[:SHOW])))
    n += 1
  if not n:
    print("(none)")

  print("\n## Native libraries the code names but the APK does not ship (raw/lib, raw/assets%s)"
        % ("; of %s too" % ", ".join("work/%s/" % c for c in chain[1:]) if len(chain) > 1 else ""))
  n = 0
  for lib in sorted(libs):
    if lib in shipped:
      continue
    where = libs[lib]
    print("- %s: %d place(s), e.g. %s" % (lib, len(where), ", ".join(where[:SHOW])))
    n += 1
  if not n:
    print("(none)")
  print("shipped: %s" % (", ".join(sorted(shipped)) or "no native libraries"))


if __name__ == "__main__":
  main()
