#!/usr/bin/env python3
"""Build a synthetic APK with the manifest tricks that hide a manifest from tools.

For fixtures/manifest-tricks-test.sh. The file holds nothing but a binary manifest and
a text asset; it is not an installable app. The tricks, all tolerated by Android and
seen together in one dropper (2026-10-03):

  ZIP       AndroidManifest.xml stored with compression method 35868 and a compressed
            size of 100 in the local header and the central directory; the data is the
            whole file, at its uncompressed size
  elements  the <permission> element has an empty name
  attributes  android:name and android:exported carry no namespace, only their
            resource ids; every element has a tag="" attribute as padding

Usage: fixtures/manifest-tricks.py <out.apk>     prints the manifest's size in bytes
"""
import struct
import sys
import zlib

NO = 0xFFFFFFFF
ANDROID = "http://schemas.android.com/apk/res/android"
# attribute names first, in the order of the resource map
ATTRS = [("name", 0x01010003), ("exported", 0x01010010), ("debuggable", 0x0101000f),
         ("protectionLevel", 0x01010009), ("versionCode", 0x0101021b), ("tag", 0x010100d1)]


class Axml:
  def __init__(self):
    self.strings = [n for n, _ in ATTRS]
    self.body = b""

  def s(self, text):
    if text not in self.strings:
      self.strings.append(text)
    return self.strings.index(text)

  def chunk(self, ctype, payload):
    self.body += struct.pack("<HHIII", ctype, 16, 16 + len(payload), 1, NO) + payload

  def start(self, name, attrs, ns_attrs=True):
    """attrs: [(name, type, value)]; type 3 string, 0x12 boolean, 0x10 int. Attributes
    get the android namespace only when ns_attrs is set; all have their resource id
    through the resource map. A tag="" attribute is added to every element."""
    out = b""
    for aname, atype, val in attrs + [("tag", 3, "")]:
      known = aname in dict(ATTRS)
      ns = self.s(ANDROID) if known and (ns_attrs or aname == "tag") else NO
      raw = self.s(val) if atype == 3 else NO
      data = raw if atype == 3 else int(val)
      out += struct.pack("<IIIHBBI", ns, self.s(aname), raw, 8, 0, atype, data)
    n = len(attrs) + 1
    self.chunk(0x0102, struct.pack("<IIHHHHHH", NO, self.s(name), 20, 20, n, 0, 0, 0) + out)

  def end(self, name):
    self.chunk(0x0103, struct.pack("<II", NO, self.s(name)))

  def build(self):
    self.s("android")
    self.s(ANDROID)
    ns = struct.pack("<II", self.strings.index("android"), self.strings.index(ANDROID))
    body = struct.pack("<HHIII", 0x0100, 16, 24, 1, NO) + ns + self.body + struct.pack("<HHIII", 0x0101, 16, 24, 1, NO) + ns
    data, offsets = b"", []
    for text in self.strings:
      offsets.append(len(data))
      enc = text.encode("utf-16-le")
      data += struct.pack("<H", len(enc) // 2) + enc + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(offsets)
    pool = struct.pack("<HHIIIIII", 0x0001, 28, start + len(data), len(offsets), 0, 0, start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + data
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ATTRS)) + b"".join(struct.pack("<I", i) for _, i in ATTRS)
    rest = pool + resmap + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(rest)) + rest


def manifest():
  a = Axml()
  a.start("manifest", [("package", 3, "com.example.fixture"), ("versionCode", 0x10, 7)])
  a.start("uses-permission", [("name", 3, "android.permission.INTERNET")], ns_attrs=False)
  a.end("uses-permission")
  a.start("", [("name", 3, "com.example.fixture.PERM"), ("protectionLevel", 0x10, 2)])  # <permission>, nameless
  a.end("")
  a.start("application", [("debuggable", 0x12, 1)])
  a.start("activity", [("name", 3, "com.example.fixture.Main"), ("exported", 0x12, 1)], ns_attrs=False)
  a.start("intent-filter", [])
  a.start("action", [("name", 3, "android.intent.action.MAIN")])
  a.end("action")
  a.end("intent-filter")
  a.end("activity")
  a.end("application")
  a.end("manifest")
  return a.build()


def apk(path, axml):
  """a ZIP written by hand: zipfile would not write a false size or an unknown method"""
  entries = [("AndroidManifest.xml", axml, 35868, 100),
             ("assets/note.txt", b"fixture, not an app\n", 0, None)]
  out, central = b"", b""
  for name, data, method, false_size in entries:
    nm = name.encode()
    csize = false_size if false_size is not None else len(data)
    head = struct.pack("<HHHHHIIIHH", 20, 0, method, 0, 0x21, zlib.crc32(data), csize, len(data), len(nm), 0)
    central += b"PK\x01\x02" + struct.pack("<H", 20) + head + struct.pack("<HHHII", 0, 0, 0, 0, len(out)) + nm
    out += b"PK\x03\x04" + head + nm + data
  eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, len(entries), len(entries), len(central), len(out), 0)
  with open(path, "wb") as f:
    f.write(out + central + eocd)


if __name__ == "__main__":
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  m = manifest()
  apk(sys.argv[1], m)
  print(len(m))
