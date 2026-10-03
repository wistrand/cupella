#!/usr/bin/env python3
"""List defined classes and the string pool of dex files.

Works without jadx: gives class names and string
constants, no code. Strings are not attributed to classes.

Usage: scripts/dexlist.py <out-dir> work/<name>/raw/classes*.dex
Writes <out-dir>/classes.txt ("<dex>\t<class>") and <out-dir>/strings.txt ("<dex>\t<string>").
"""
import os
import struct
import sys


def uleb(buf, p):
  r = s = 0
  while True:
    b = buf[p]
    p += 1
    r |= (b & 0x7F) << s
    s += 7
    if not b & 0x80:
      return r, p


def dex_tables(buf):
  s_n, s_off = struct.unpack_from("<II", buf, 0x38)
  t_n, t_off = struct.unpack_from("<II", buf, 0x40)
  c_n, c_off = struct.unpack_from("<II", buf, 0x60)
  strings = []
  for i in range(s_n):
    (p,) = struct.unpack_from("<I", buf, s_off + 4 * i)
    _, p = uleb(buf, p)
    end = buf.index(b"\0", p)
    strings.append(buf[p:end].decode("utf-8", "replace"))  # MUTF-8, close enough
  types = [strings[struct.unpack_from("<I", buf, t_off + 4 * i)[0]] for i in range(t_n)]
  classes = [types[struct.unpack_from("<I", buf, c_off + 32 * i)[0]] for i in range(c_n)]
  return strings, classes


if __name__ == "__main__":
  out = sys.argv[1]
  os.makedirs(out, exist_ok=True)
  with open(os.path.join(out, "classes.txt"), "w") as fc, \
       open(os.path.join(out, "strings.txt"), "w") as fs:
    for path in sys.argv[2:]:
      with open(path, "rb") as f:
        strings, classes = dex_tables(f.read())
      name = os.path.basename(path)
      for c in classes:
        fc.write("%s\t%s\n" % (name, c[1:-1].replace("/", ".")))
      for s in strings:
        fs.write("%s\t%s\n" % (name, s.replace("\n", "\\n").replace("\r", "\\r")))
