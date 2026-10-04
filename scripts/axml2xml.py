#!/usr/bin/env python3
"""Decode Android binary XML (AndroidManifest.xml from an APK) to text XML.

Fallback for when apktool is unavailable or fails. Resource references are
printed as @0x7f...; they are not resolved against resources.arsc.

Usage: scripts/axml2xml.py work/<name>/raw/AndroidManifest.xml > work/<name>/manifest.xml
"""
import struct
import sys
from xml.sax.saxutils import escape, quoteattr

RES_STRING_POOL, RES_XML_RESOURCE_MAP = 0x0001, 0x0180
RES_XML_START_NS, RES_XML_END_NS = 0x0100, 0x0101
RES_XML_START_ELEM, RES_XML_END_ELEM, RES_XML_CDATA = 0x0102, 0x0103, 0x0104
UTF8_FLAG = 0x100
NO_ENTRY = 0xFFFFFFFF
# android: attribute resource ids (framework public.xml). The device identifies manifest
# attributes by these ids, not by the name strings, which tampered manifests disguise.
ATTR_NAMES = dict(enumerate([
  "theme", "label", "icon", "name", "manageSpaceActivity", "allowClearUserData", "permission",
  "readPermission", "writePermission", "protectionLevel", "permissionGroup", "sharedUserId", "hasCode",
  "persistent", "enabled", "debuggable", "exported", "process", "taskAffinity", "multiprocess",
  "finishOnTaskLaunch", "clearTaskOnLaunch", "stateNotNeeded", "excludeFromRecents", "authorities",
  "syncable", "initOrder", "grantUriPermissions", "priority", "launchMode"], start=0x01010000))
ATTR_NAMES.update({0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion",
                   0x0101021b: "versionCode", 0x0101021c: "versionName"})


def parse_string_pool(buf, off):
  _, hsize, _, count, _, flags, strings_start, _ = struct.unpack_from("<HHIIIIII", buf, off)
  utf8 = bool(flags & UTF8_FLAG)
  out = []
  count = min(count, max(0, (len(buf) - off - hsize) // 4))  # the offsets must be in the file
  for i in range(count):
    try:
      out.append(read_string(buf, off + strings_start + struct.unpack_from("<I", buf, off + hsize + 4 * i)[0], utf8))
    except (struct.error, IndexError):
      out.append("")  # offset past the end: an empty string, keeping later indices right
  return out


def read_string(buf, p, utf8):
  if p >= len(buf):
    raise IndexError("string offset past the end")
  if utf8:
    for _ in range(2):  # char length, then byte length; each 1 or 2 bytes
      n = buf[p]
      p += 1
      if n & 0x80:
        n = ((n & 0x7F) << 8) | buf[p]
        p += 1
    return buf[p:p + n].decode("utf-8", "replace")
  (n,) = struct.unpack_from("<H", buf, p)
  p += 2
  if n & 0x8000:
    (lo,) = struct.unpack_from("<H", buf, p)
    n = ((n & 0x7FFF) << 16) | lo
    p += 2
  return buf[p:p + 2 * n].decode("utf-16-le", "replace")


def xml_name(s):
  """s as a valid XML name: a pool string such as 'x android:exported="false" y' used as
  an element or attribute name would otherwise forge attributes in the text output"""
  out = "".join(c if (c.isascii() and (c.isalnum() or c in "._-")) or (not c.isascii() and c.isalpha())
                else "_" for c in s)
  if not out or not (out[0].isalpha() or out[0] == "_"):
    out = "_" + out
  return out


def attr_value(v):
  # newlines and tabs as references, so every element stays on one line for grep
  return quoteattr(v, {"\n": "&#10;", "\r": "&#13;", "\t": "&#9;"})


class Pool(list):
  """string pool that answers "" for out-of-range indices, as Android tolerates them"""

  def __getitem__(self, i):
    try:
      return list.__getitem__(self, i)
    except (IndexError, TypeError):
      return ""


def fmt_value(strings, raw, dtype, data):
  if dtype == 0x03 or (raw != NO_ENTRY and dtype == 0x03):
    return strings[data]
  if dtype == 0x01:
    return "@0x%08x" % data
  if dtype == 0x02:
    return "?0x%08x" % data
  if dtype == 0x12:
    return "true" if data else "false"
  if dtype == 0x10:
    return str(struct.unpack("<i", struct.pack("<I", data))[0])
  if dtype == 0x11:
    return "0x%x" % data
  if dtype == 0x04:
    return repr(struct.unpack("<f", struct.pack("<I", data))[0])
  if raw != NO_ENTRY:
    return strings[raw]
  return "type%#x:%#x" % (dtype, data)


def decode(buf):
  state = {"strings": Pool(), "resmap": [], "ns_prefix": {}, "pending_ns": []}
  lines, depth = ['<?xml version="1.0" encoding="utf-8"?>'], 0
  off = 8
  while off < len(buf):
    try:
      ctype, hsize, size = struct.unpack_from("<HHI", buf, off)
    except struct.error:
      lines.append("<!-- axml2xml: truncated chunk header at 0x%x; parsing stopped -->" % off)
      break
    if size == 0:
      break
    if hsize < 8 or size < hsize:
      lines.append("<!-- axml2xml: bad chunk sizes at 0x%x (header %d, size %d); parsing stopped -->" % (off, hsize, size))
      break
    if off + size > len(buf):
      lines.append("<!-- axml2xml: the chunk at 0x%x needs %d bytes and the file has %d left: truncated file -->"
                   % (off, size, len(buf) - off))
    try:
      depth = chunk(buf, off, ctype, hsize, size, lines, depth, state)
    except (struct.error, IndexError):
      lines.append("<!-- axml2xml: chunk 0x%04x at 0x%x runs past the data; parsing stopped -->" % (ctype, off))
      break
    off += size
  return "\n".join(lines) + "\n"


def chunk(buf, off, ctype, hsize, size, lines, depth, st):
  """one chunk: appends output lines, updates st, returns the new depth"""
  strings, resmap, ns_prefix = st["strings"], st["resmap"], st["ns_prefix"]
  if ctype == RES_STRING_POOL:
    st["strings"] = Pool(parse_string_pool(buf, off))
  elif ctype == RES_XML_RESOURCE_MAP:
    st["resmap"] = struct.unpack_from("<%dI" % ((size - hsize) // 4), buf, off + hsize)
  elif ctype == RES_XML_START_NS:
    prefix, uri = struct.unpack_from("<II", buf, off + hsize)
    ns_prefix[strings[uri]] = strings[prefix]
    st["pending_ns"].append((strings[prefix], strings[uri]))
  elif ctype == RES_XML_START_ELEM:
    # attributeStart and attributeSize come from the header: tampered manifests use
    # nonstandard values that Android honors and fixed-layout parsers misread
    _, name, a_start, a_size, attr_count = struct.unpack_from("<IIHHH", buf, off + hsize)
    a_size = a_size if a_size >= 20 else 20
    attrs = ['xmlns:%s=%s' % (xml_name(p), attr_value(u)) for p, u in st["pending_ns"]]
    st["pending_ns"] = []
    p = off + hsize + a_start
    for _ in range(attr_count):
      if p + 20 > len(buf):
        break
      a_ns, a_name, a_raw, _, _, a_type, a_data = struct.unpack_from("<IIIHBBI", buf, p)
      p += a_size
      n = xml_name(strings[a_name])
      if a_name < len(resmap) and resmap[a_name] in ATTR_NAMES:
        n = ATTR_NAMES[resmap[a_name]]  # the resource id decides, as on the device
      elif not strings[a_name] and a_name < len(resmap):
        n = "attr_0x%08x" % resmap[a_name]
      if a_name < len(resmap) and resmap[a_name] >> 24 == 0x01:
        # a framework attribute by its resource id: the device reads it as android:<name>
        # whatever the namespace field says (tampered manifests leave the namespace out)
        n = "android:%s" % n
      elif a_ns != NO_ENTRY:
        n = "%s:%s" % (xml_name(ns_prefix.get(strings[a_ns], strings[a_ns])), n)
      attrs.append("%s=%s" % (n, attr_value(fmt_value(strings, a_raw, a_type, a_data))))
    lines.append("%s<%s%s>" % ("  " * depth, xml_name(strings[name]), "".join(" " + a for a in attrs)))
    depth += 1
  elif ctype == RES_XML_CDATA:
    (text,) = struct.unpack_from("<I", buf, off + hsize)
    if strings[text].strip():
      lines.append("%s%s" % ("  " * depth, escape(strings[text].strip())))
  elif ctype == RES_XML_END_ELEM:
    _, name = struct.unpack_from("<II", buf, off + hsize)
    depth -= 1
    lines.append("%s</%s>" % ("  " * max(depth, 0), xml_name(strings[name])))
  return depth


if __name__ == "__main__":
  with open(sys.argv[1], "rb") as f:
    text = decode(f.read())
  sys.stdout.write(text)
  if not any(line.lstrip().startswith("<") and not line.lstrip().startswith(("<?", "<!--")) for line in text.split("\n")):
    # an empty document is not a manifest without content: say so, never look like success
    sys.exit("axml2xml: no element decoded from %s (truncated, or not binary XML)" % sys.argv[1])
