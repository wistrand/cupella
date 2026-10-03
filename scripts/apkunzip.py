#!/usr/bin/env python3
"""Extract an APK the way Android reads it, ignoring ZIP tricks that break tools.

Malware sets the "encrypted" flag on entries that are not encrypted, declares unknown
compression methods, adds bogus data, or adds entries such as "AndroidManifest.xml/x"
that turn a file's path into a directory on extraction, so that unzip asks for a
password, extractors lose the real file, and apktool aborts, while the device installs
the app fine. Android's reader ignores the
encryption flag and treats any method other than deflate as stored; this does the
same. Standard library only; reads the file, never runs anything from it.

Every entry is inflated under a size limit (APK_ENTRY_MAX, default 1 GiB; APK_TOTAL_MAX,
default 8 GiB for all entries), measured on the real data, so a decompression bomb cannot
fill the disk; entries over it are reported and skipped. Entries are written as regular
files only (never symlinks) and only inside <out-dir>.

Usage: scripts/apkunzip.py <apk> <out-dir> [--repair <clean.apk>]
  Extracts every entry to <out-dir> (skipping paths that would escape it) and prints
  one line per anomaly class with counts. Entries nested under a name that is also a
  file go to <out-dir>/_shadowing/ so the real file keeps its path. --repair also writes a copy with clean
  headers, for tools such as apktool, when any anomaly was found (removed otherwise).
Exit status 0 when every entry was read.
"""
import os
import struct
import sys
import zipfile
import zlib


# Decompression limits: an entry, and all entries together, may not inflate beyond these
# (a decompression bomb would otherwise fill the host disk under work/). The real
# inflated size is measured; declared sizes can lie.
ENTRY_MAX = int(os.environ.get("APK_ENTRY_MAX", 1 << 30))
TOTAL_MAX = int(os.environ.get("APK_TOTAL_MAX", 8 << 30))


class TooLarge(Exception):
  pass


def read_entry(z, fp, info, limit=ENTRY_MAX):
  """bytes of an entry, read from its local header, as Android would"""
  fp.seek(info.header_offset)
  hdr = fp.read(30)
  if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
    raise ValueError("bad local header")
  name_len, extra_len = struct.unpack("<HH", hdr[26:30])
  fp.seek(info.header_offset + 30 + name_len + extra_len)
  data = fp.read(info.compress_size)
  if info.compress_type == zipfile.ZIP_DEFLATED:
    d = zlib.decompressobj(-15)
    out = d.decompress(data, limit + 1)
    if len(out) > limit:
      raise TooLarge(info.filename)
    return out
  out = data[:info.file_size] if info.file_size <= len(data) else data
  if len(out) > limit:
    raise TooLarge(info.filename)
  return out


def main():
  args = sys.argv[1:]
  if len(args) < 2:
    sys.exit(__doc__)
  repair = None
  if "--repair" in args:
    i = args.index("--repair")
    repair = args[i + 1]
    args = args[:i] + args[i + 2:]
  apk, out = args[0], args[1]
  out_abs = os.path.abspath(out)
  z = zipfile.ZipFile(apk)
  anomalies, examples = {}, {}

  def note(kind, name=None):
    anomalies[kind] = anomalies.get(kind, 0) + 1
    if name is not None and len(examples.setdefault(kind, [])) < 5:
      examples[kind].append(repr(name)[1:-1][:120])

  failed = 0
  total = 0
  rz = zipfile.ZipFile(repair, "w") if repair else None
  seen = set()
  files = {i.filename for i in z.infolist() if not i.is_dir()}

  def shadowed(name):
    parts = name.split("/")
    return any("/".join(parts[:k]) in files for k in range(1, len(parts)))

  with open(apk, "rb") as fp:
    for info in z.infolist():
      if info.flag_bits & 0x1:
        note("entries with the encryption flag set (Android ignores it)", info.filename)
      if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        note("entries with compression method %d (Android reads them as stored)" % info.compress_type)
      if info.filename in seen:
        note("duplicate entry names (Android uses the first)", info.filename)
        continue
      seen.add(info.filename)
      if info.is_dir():
        continue
      if info.create_system == 3 and (info.external_attr >> 16) & 0o170000 == 0o120000:
        note("symlink entries (not extracted; an APK has no use for them: anti-analysis or an attack on the analyst)",
             info.filename)
        continue
      room = TOTAL_MAX - total
      try:
        data = read_entry(z, fp, info, min(ENTRY_MAX, room))
      except TooLarge:
        if room < ENTRY_MAX:
          note("extraction stopped at the total size limit (later entries not extracted; decompression bomb?)", info.filename)
          break
        note("entries over the size limit (not extracted, left out of the repaired copy; decompression bomb?)", info.filename)
        continue
      except (ValueError, zlib.error, OSError):
        note("entries that could not be read", info.filename)
        failed += 1
        continue
      total += len(data)
      if len(data) != info.file_size:
        note("entries whose declared size differs from the data", info.filename)
      rel = info.filename
      if shadowed(rel):
        note("entries nested under a name that is also a file (moved to _shadowing/; Android looks names up exactly)", info.filename)
        rel = "_shadowing/" + rel
      path = os.path.abspath(os.path.join(out, rel))
      if not path.startswith(out_abs + os.sep):
        note("entry paths escaping the archive (not extracted)", info.filename)
        continue
      os.makedirs(os.path.dirname(path), exist_ok=True)
      with open(path, "wb") as f:
        f.write(data)
      if rz and not rel.startswith("_shadowing/"):
        zi = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        rz.writestr(zi, data)
  if rz:
    rz.close()
    if not anomalies:
      os.remove(repair)  # nothing to repair: tools read the original
  for kind, n in sorted(anomalies.items()):
    print("%d %s" % (n, kind))
    for e in examples.get(kind, []):
      print("  e.g. %s" % e)
  if not anomalies:
    print("no ZIP anomalies")
  sys.exit(1 if failed else 0)


if __name__ == "__main__":
  main()
