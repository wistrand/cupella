#!/usr/bin/env python3
"""Names of the permissions the Android platform defines, from apktool's framework.

A library module (standard library only). apktool ships the platform's framework
resources (framework-res, an APK inside apktool.jar); its AndroidManifest.xml declares
every platform permission. The list is read once and cached in
work/_reference/android-permissions.txt (cache/ is read-only in analysis containers).

  platform()          set of permission names ("android.permission.INTERNET", ...)
  levels()            {name: protection level} ("dangerous", "signature|privileged", ...)
  describe(level)     the level as text ("signature|appop")
  grantable(level)    False when only the system or platform-signed apps can hold it
  classify(names, own, package) {name: kind}: "platform", "app" (declared by the app
                      itself, in `own`), "google" (a known Google Play or Play Services name),
                      "other" (another app's namespace), "undefined" (an android.*,
                      com.google, com.android name, or one in the app's own `package`
                      namespace, that nothing defines: invented)

Usage (probe): ./cupella android_perms.py   prints the count and where the list came from
"""
import io
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import axml2xml  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CACHE = os.path.join(ROOT, "work", "_reference", "android-permissions.txt")
# real names outside the platform list that apps commonly request (Play Services, Play
# Store, launchers); everything else under these namespaces that is not here is invented
GOOGLE = {
  "com.google.android.c2dm.permission.RECEIVE", "com.google.android.c2dm.permission.SEND",
  "com.google.android.gms.permission.AD_ID", "com.google.android.gms.permission.ACTIVITY_RECOGNITION",
  "com.google.android.gms.permission.BIND_NETWORK_TASK_SERVICE",
  "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
  "com.android.vending.BILLING", "com.android.vending.CHECK_LICENSE",
  "com.google.android.providers.gsf.permission.READ_GSERVICES",
  "com.android.launcher.permission.INSTALL_SHORTCUT", "com.android.launcher.permission.UNINSTALL_SHORTCUT",
  "com.android.alarm.permission.SET_ALARM", "com.android.browser.permission.READ_HISTORY_BOOKMARKS",
  "com.android.voicemail.permission.ADD_VOICEMAIL",
}
RESERVED = re.compile(r"^(android\.|com\.android\.|com\.google\.android\.)")


def _from_jar():
  jar = os.path.join(os.environ.get("APK_TOOLS", "/opt/tools"), "apktool.jar")
  with zipfile.ZipFile(jar) as z:
    for name in z.namelist():
      if not name.endswith((".apk", ".jar")) or "framework" not in name.lower():
        continue
      inner = zipfile.ZipFile(io.BytesIO(z.read(name)))
      if "AndroidManifest.xml" not in inner.namelist():
        continue
      xml = axml2xml.decode(inner.read("AndroidManifest.xml"))
      names = {}
      for el in re.findall(r'<permission\s[^>]*>', xml):
        n = re.search(r'\bname="([^"]+)"', el)
        lv = re.search(r'protectionLevel="([^"]+)"', el)
        if n:
          names[n.group(1)] = lv.group(1) if lv else "normal"
      if len(names) > 100:
        return names, "%s!/%s" % (jar, name)
  return {}, jar


def levels():
  """{platform permission: protection level as the framework states it}"""
  if os.path.isfile(CACHE):
    with open(CACHE) as f:
      rows = [l.rstrip("\n").split("\t") for l in f if l.strip() and not l.startswith("#")]
    if rows and all(len(r) == 2 for r in rows):
      return {r[0]: r[1] for r in rows}
  names, src = _from_jar()
  if names:
    try:
      os.makedirs(os.path.dirname(CACHE), exist_ok=True)
      with open(CACHE, "w") as f:
        f.write("# platform permissions from %s\n" % src)
        f.write("".join("%s\t%s\n" % (n, names[n]) for n in sorted(names)))
    except OSError as e:
      print("android_perms: cannot write %s: %s" % (CACHE, e), file=sys.stderr)
  return names


def platform():
  return set(levels())


BASE = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"}


def describe(level):
  """protection level as text: the framework stores it as hex flags (0x9e2)"""
  try:
    v = int(level, 0)
  except ValueError:
    return level
  flags = [n for bit, n in ((0x10, "privileged"), (0x20, "development"), (0x40, "appop"),
                            (0x80, "pre23"), (0x100, "installer"), (0x400, "preinstalled"),
                            (0x1000, "instant")) if v & bit]
  return "|".join([BASE.get(v & 0xF, hex(v & 0xF))] + flags)


def grantable(level):
  """False for permissions only the system or platform-signed apps can hold; appop and
  development permissions are granted by the user or a shell even when signature"""
  d = describe(level).split("|")
  return d[0] in ("normal", "dangerous") or "appop" in d or "development" in d


def classify(names, own=(), package=None):
  plat, own = platform(), set(own)
  out = {}
  for n in names:
    if n in plat:
      out[n] = "platform"
    elif n in own:
      out[n] = "app"
    elif n in GOOGLE:
      out[n] = "google"
    elif package and n.startswith(package + "."):
      out[n] = "undefined"  # the app's own namespace, but the app does not declare it
    elif RESERVED.match(n) or not plat:
      out[n] = "undefined" if plat else "unknown"
    else:
      out[n] = "other"
  return out


if __name__ == "__main__":
  p = platform()
  print("%d platform permissions" % len(p))
  for n in sorted(p)[:5]:
    print(" ", n)
