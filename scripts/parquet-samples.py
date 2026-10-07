#!/usr/bin/env python3
"""List the APKs stored in a Parquet file and extract them to work/_samples/.

Sample datasets (Hugging Face and others) keep APKs as binary columns of Parquet
files, one APK per row, next to columns such as a hash, a file name, a package name, or
a label. This reads the file with a reader of its own (standard library only), finds
the values that are APKs (a ZIP with AndroidManifest.xml, raw or base64), and writes the
chosen ones to work/_samples/<name>.apk, from where unpack.sh takes them like any APK.
data/ is read-only and is never changed.

Names are guessed per row from the other columns, in this order: a file name ending in
.apk; a package name (with a version, when a version column has one); a hash column
whose value matches the APK's md5, sha1, or sha256; else the APK's sha256. The output
says which column a name came from. A hash column that does not match the bytes is
reported, not used.

Nothing is executed. Supported: flat and nested (struct) columns without lists;
BYTE_ARRAY, INT32, INT64, FIXED_LEN_BYTE_ARRAY values; PLAIN, dictionary, and DELTA
encodings; data pages v1 and v2; codecs none, snappy, gzip, LZ4_RAW, and zstd and
brotli where the image has their command-line tools. Encrypted files are refused.
Limits: APK_TOTAL_MAX bytes per value and per page (default 8 GiB, as apkunzip.py),
at most --max APKs extracted per run (default 20); files are written without following
links and never overwritten.

Usage: ./cupella parquet-samples.py data/<file>.parquet [--list] [--rows 0,3,10-12]
                                    [--column <name>] [--max N | --all]
  --list    only list: row, column, size, sha256, the guessed name and its source; when
            no APK is found, also what each column holds (type, codec, sizes, a guess
            at the format from the first bytes, the first 16 bytes in hex)
  --describe  --list, and the column description always
  --rows    rows to extract, 0-based over the whole file (default: every APK row)
  --column  the column holding the APKs (default: every column where one is found)
Output: one line per APK found, "extracted work/_samples/<name>.apk  sha256 <hash>" per
        APK written, and work/_samples/<file>.index.tsv: every APK row with its short
        column values (names, labels) for provenance.
"""
import base64
import binascii
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MAX_BYTES = int(os.environ.get("APK_TOTAL_MAX", 8 << 30))
KEEP = 512  # characters kept of a non-APK value, for names and the index


class Bad(Exception):
  pass


# ---- Thrift compact protocol (the Parquet footer and page headers) ----

class Thrift:
  def __init__(self, buf, pos=0, end=None):
    self.b, self.p, self.end = buf, pos, len(buf) if end is None else end

  def byte(self):
    if self.p >= self.end:
      raise Bad("thrift: truncated")
    v = self.b[self.p]
    self.p += 1
    return v

  def varint(self):
    shift = v = 0
    while True:
      c = self.byte()
      v |= (c & 0x7F) << shift
      if not c & 0x80:
        return v
      shift += 7
      if shift > 70:
        raise Bad("thrift: varint too long")

  def zigzag(self):
    v = self.varint()
    return (v >> 1) ^ -(v & 1)

  def binary(self):
    n = self.varint()
    if n > self.end - self.p:
      raise Bad("thrift: string past the end")
    v = bytes(self.b[self.p:self.p + n])
    self.p += n
    return v

  def value(self, t, depth):
    if depth > 32:
      raise Bad("thrift: nested too deep")
    if t in (1, 2):
      return t == 1
    if t == 3:
      return self.byte()
    if t in (4, 5, 6):
      return self.zigzag()
    if t == 7:
      self.p += 8
      return None
    if t == 8:
      return self.binary()
    if t in (9, 10):
      h = self.byte()
      n, et = h >> 4, h & 15
      if n == 15:
        n = self.varint()
      if n > self.end - self.p:
        raise Bad("thrift: list longer than the data")
      if et in (1, 2):
        return [self.byte() == 1 for _ in range(n)]
      return [self.value(et, depth + 1) for _ in range(n)]
    if t == 11:
      n = self.varint()
      if n == 0:
        return {}
      kv = self.byte()
      return {self.value(kv >> 4, depth + 1): self.value(kv & 15, depth + 1) for _ in range(n)}
    if t == 12:
      return self.struct(depth + 1)
    raise Bad(f"thrift: unknown type {t}")

  def struct(self, depth=0):
    out, last = {}, 0
    while True:
      h = self.byte()
      if h == 0:
        return out
      delta, t = h >> 4, h & 15
      fid = last + delta if delta else self.zigzag()
      out[fid] = self.value(t, depth)
      last = fid


# ---- decompression ----

def snappy(data, size):
  out, p = bytearray(), 0
  n = shift = 0
  while True:  # the uncompressed length
    c = data[p]
    p += 1
    n |= (c & 0x7F) << shift
    shift += 7
    if not c & 0x80:
      break
  if n > size or n > MAX_BYTES:
    raise Bad("snappy: declared size too large")
  while p < len(data):
    tag = data[p]
    p += 1
    kind = tag & 3
    if kind == 0:
      ln = (tag >> 2) + 1
      if ln > 60:
        k = ln - 60
        ln = int.from_bytes(data[p:p + k], "little") + 1
        p += k
      out += data[p:p + ln]
      p += ln
    else:
      if kind == 1:
        ln, off = ((tag >> 2) & 7) + 4, ((tag >> 5) << 8) | data[p]
        p += 1
      elif kind == 2:
        ln, off = (tag >> 2) + 1, int.from_bytes(data[p:p + 2], "little")
        p += 2
      else:
        ln, off = (tag >> 2) + 1, int.from_bytes(data[p:p + 4], "little")
        p += 4
      if off == 0 or off > len(out):
        raise Bad("snappy: bad copy offset")
      start = len(out) - off
      if off >= ln:
        out += out[start:start + ln]
      else:
        for i in range(ln):
          out.append(out[start + i])
    if len(out) > n:
      raise Bad("snappy: more output than declared")
  return bytes(out)


def lz4_raw(data, size):
  out, p = bytearray(), 0
  while p < len(data):
    tok = data[p]
    p += 1
    ln = tok >> 4
    if ln == 15:
      while True:
        c = data[p]
        p += 1
        ln += c
        if c != 255:
          break
    out += data[p:p + ln]
    p += ln
    if p >= len(data):
      break
    off = data[p] | data[p + 1] << 8
    p += 2
    ml = (tok & 15) + 4
    if ml == 19:
      while True:
        c = data[p]
        p += 1
        ml += c
        if c != 255:
          break
    if off == 0 or off > len(out):
      raise Bad("lz4: bad offset")
    start = len(out) - off
    for i in range(ml):
      out.append(out[start + i])
    if len(out) > size:
      raise Bad("lz4: more output than declared")
  return bytes(out)


def tool(name, args, data, size):
  exe = shutil.which(name)
  if not exe:
    raise Bad(f"{name}-compressed pages need the {name} tool in the image (Dockerfile; ./cupella build)")
  p = subprocess.run([exe] + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
  if p.returncode:
    raise Bad(f"{name}: {p.stderr.decode('utf-8', 'replace').strip()[:200]}")
  if len(p.stdout) > size:
    raise Bad(f"{name}: more output than declared")
  return p.stdout


def decompress(codec, data, size):
  if size > MAX_BYTES:
    raise Bad(f"page of {size} bytes is over the limit")
  if codec == 0:
    return bytes(data)
  if codec == 1:
    return snappy(data, size)
  if codec == 2:
    d = zlib.decompressobj(47)
    out = d.decompress(data, size + 1)
    if len(out) > size:
      raise Bad("gzip: more output than declared")
    return out
  if codec == 4:
    return tool("brotli", ["-dc"], data, size)
  if codec == 6:
    return tool("zstd", ["-dcq", "--no-progress"], data, size)
  if codec == 7:
    return lz4_raw(data, size)
  raise Bad({3: "LZO", 5: "LZ4 (Hadoop framing)"}.get(codec, f"codec {codec}") + " is not supported")


# ---- encodings ----

def hybrid(buf, pos, end, width, count):
  # RLE / bit-packed hybrid: count values of width bits
  out = []
  nbytes = (width + 7) // 8
  while len(out) < count and pos < end:
    t = Thrift(buf, pos, end)
    h = t.varint()
    pos = t.p
    if h & 1 == 0:
      v = int.from_bytes(buf[pos:pos + nbytes], "little")
      pos += nbytes
      out += [v] * min(h >> 1, count - len(out))
    else:
      groups = h >> 1
      ln = groups * width
      chunk = int.from_bytes(buf[pos:pos + ln], "little")
      pos += ln
      mask = (1 << width) - 1
      for i in range(groups * 8):
        if len(out) >= count:
          break
        out.append((chunk >> (i * width)) & mask if width else 0)
  if len(out) < count:
    out += [0] * (count - len(out))
  return out


def delta_packed(buf, pos, end):
  # DELTA_BINARY_PACKED -> (values, position after them)
  t = Thrift(buf, pos, end)
  block, mini, total = t.varint(), t.varint(), t.varint()
  first = t.zigzag()
  if total > 1 << 28 or (mini and block % mini) or (mini and (block // mini) % 8):
    raise Bad("delta: bad header")
  vals = [first] if total else []
  per = block // mini if mini else 0
  while len(vals) < total:
    mind = t.zigzag()
    widths = [t.byte() for _ in range(mini)]
    for w in widths:
      if len(vals) >= total:
        break
      ln = per * w // 8
      chunk = int.from_bytes(buf[t.p:t.p + ln], "little")
      t.p += ln
      mask = (1 << w) - 1
      for i in range(per):
        if len(vals) >= total:
          break
        vals.append(vals[-1] + mind + ((chunk >> (i * w)) & mask if w else 0))
  return vals, t.p


def plain(buf, pos, end, ptype, n, tlen):
  out = []
  for _ in range(n):
    if ptype == 6:
      if pos + 4 > end:
        raise Bad("plain: truncated")
      ln = struct.unpack_from("<I", buf, pos)[0]
      if ln > MAX_BYTES or pos + 4 + ln > end:
        raise Bad("plain: value past the page")
      out.append(bytes(buf[pos + 4:pos + 4 + ln]))
      pos += 4 + ln
    elif ptype == 7:
      out.append(bytes(buf[pos:pos + tlen]))
      pos += tlen
    elif ptype == 1:
      out.append(struct.unpack_from("<i", buf, pos)[0])
      pos += 4
    elif ptype == 2:
      out.append(struct.unpack_from("<q", buf, pos)[0])
      pos += 8
    else:
      raise Bad(f"type {ptype} not read")
  return out


def decode(buf, pos, end, enc, ptype, n, tlen, dictionary):
  if enc == 0:
    return plain(buf, pos, end, ptype, n, tlen)
  if enc in (2, 8):
    if dictionary is None:
      raise Bad("dictionary-encoded page without a dictionary")
    width = buf[pos]
    idx = hybrid(buf, pos + 1, end, width, n)
    if any(i >= len(dictionary) for i in idx):
      raise Bad("dictionary index out of range")
    return [dictionary[i] for i in idx]
  if enc == 5 and ptype in (1, 2):
    return delta_packed(buf, pos, end)[0][:n]
  if enc == 6 and ptype == 6:
    lens, p = delta_packed(buf, pos, end)
    out = []
    for ln in lens[:n]:
      if ln < 0 or p + ln > end:
        raise Bad("delta length: value past the page")
      out.append(bytes(buf[p:p + ln]))
      p += ln
    return out
  if enc == 7 and ptype in (6, 7):
    pre, p = delta_packed(buf, pos, end)
    lens, p = delta_packed(buf, p, end)
    out, prev = [], b""
    for a, ln in zip(pre[:n], lens[:n]):
      if ln < 0 or p + ln > end or a < 0 or a > len(prev):
        raise Bad("delta byte array: bad lengths")
      prev = prev[:a] + bytes(buf[p:p + ln])
      p += ln
      out.append(prev)
    return out
  raise Bad(f"encoding {enc} for type {ptype} is not supported")


# ---- the file ----

class Column:
  def __init__(self, path, ptype, tlen, max_def, max_rep):
    self.path, self.ptype, self.tlen, self.max_def, self.max_rep = path, ptype, tlen, max_def, max_rep
    self.name = ".".join(path)


def columns(schema):
  # the leaf columns, with their maximum definition and repetition levels
  out, i = [], 1

  def walk(prefix, d, r, count):
    nonlocal i
    for _ in range(count):
      if i >= len(schema):
        raise Bad("schema: fewer elements than declared")
      el = schema[i]
      i += 1
      rep = el.get(3, 0)
      nd, nr = d + (rep != 0), r + (rep == 2)
      name = el.get(4, b"?").decode("utf-8", "replace")
      if el.get(5):
        walk(prefix + [name], nd, nr, el[5])
      else:
        out.append(Column(prefix + [name], el.get(1), el.get(2, 0), nd, nr))
  walk([], 0, 0, schema[0].get(5, 0) if schema else 0)
  return out


def read_footer(f, size):
  if size < 12:
    raise Bad("too small for Parquet")
  f.seek(0)
  head = f.read(4)
  f.seek(size - 8)
  tail = f.read(8)
  if tail[4:] == b"PARE":
    raise Bad("encrypted Parquet (footer key needed): not supported")
  if head != b"PAR1" or tail[4:] != b"PAR1":
    raise Bad("not a Parquet file (no PAR1 magic)")
  n = struct.unpack("<I", tail[:4])[0]
  if n > size - 12:
    raise Bad("footer length past the file")
  f.seek(size - 8 - n)
  return Thrift(f.read(n)).struct()


def page_header(f, pos, end):
  # (header, position after it); headers are small, but a long statistics value can
  # make one larger than the first window
  win = 1 << 16
  while True:
    f.seek(pos)
    buf = f.read(min(win, end - pos))
    try:
      t = Thrift(buf)
      return t.struct(), pos + t.p
    except Bad:
      if len(buf) < win or win >= 1 << 26:
        raise
      win *= 4


def chunk_values(f, size, col, meta, pages=None):
  # every row's value of one column chunk, None for a null; read page by page
  codec = meta.get(4, 0)
  starts = [x for x in (meta.get(9), meta.get(11)) if isinstance(x, int) and x > 0]
  total = meta.get(7, 0)
  if not starts or min(starts) + total > size:
    raise Bad(f"{col.name}: column chunk past the file")
  pos = min(starts)
  end = pos + total
  dictionary, seen, want = None, 0, meta.get(5, 0)
  while pos < end and seen < want:
    ph, pos = page_header(f, pos, end)
    csize, usize = ph.get(3, 0), ph.get(2, 0)
    if csize < 0 or pos + csize > end or csize > MAX_BYTES:
      raise Bad(f"{col.name}: page past the chunk")
    f.seek(pos)
    raw = f.read(csize)
    pos += csize
    ptype = ph.get(1)
    if pages is not None:
      k = {0: "v1", 2: "dictionary", 3: "v2"}.get(ptype, f"type {ptype}")
      pages[k] = pages.get(k, 0) + 1
    if ptype == 2:
      dh = ph.get(7, {})
      page = decompress(codec, raw, usize)
      dictionary = plain(page, 0, len(page), col.ptype, dh.get(1, 0), col.tlen)
      continue
    if ptype == 0:
      dh = ph.get(5, {})
      n, enc = dh.get(1, 0), dh.get(2, 0)
      page = decompress(codec, raw, usize)
      p = 0
      if col.max_rep:
        raise Bad(f"{col.name}: repeated (list) columns are not supported")
      if col.max_def:
        ln = struct.unpack_from("<I", page, p)[0]
        defs = hybrid(page, p + 4, p + 4 + ln, col.max_def.bit_length(), n)
        p += 4 + ln
      else:
        defs = [0] * n
    elif ptype == 3:
      dh = ph.get(8, {})
      n, enc = dh.get(1, 0), dh.get(4, 0)
      dl, rl = dh.get(5, 0), dh.get(6, 0)
      if col.max_rep or rl:
        raise Bad(f"{col.name}: repeated (list) columns are not supported")
      levels = raw[:rl + dl]
      body = raw[rl + dl:]
      body = decompress(codec, body, usize - rl - dl) if dh.get(7, True) else bytes(body)
      defs = hybrid(levels, rl, rl + dl, col.max_def.bit_length(), n) if col.max_def else [0] * n
      page, p = body, 0
    else:
      continue
    present = sum(1 for d in defs if d == col.max_def)
    vals = decode(page, p, len(page), enc, col.ptype, present, col.tlen, dictionary)
    if len(vals) < present:
      # (raising StopIteration in a generator would become a RuntimeError)
      raise Bad(f"{col.name}: {len(vals)} values for {present} present rows")
    vals = iter(vals)
    for d in defs:
      yield next(vals) if d == col.max_def else None
    seen += n


# ---- APKs and names ----

def as_apk(v):
  # the APK bytes in a value (raw, or base64 text), else None
  if isinstance(v, bytes):
    if v[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in v:
      return v
    if v[:5] in (b"UEsDB", b"UEsFB") and len(v) > 100:
      try:
        b = base64.b64decode(v, validate=False)
      except (binascii.Error, ValueError):
        return None
      if b[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in b:
        return b
  return None


MAGIC = [(b"PK\x03\x04", "zip"), (b"dex\n", "dex"), (b"\x1f\x8b", "gzip"), (b"\x28\xb5\x2f\xfd", "zstd"),
         (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x7fELF", "elf"),
         (b"Rar!", "rar"), (b"\x04\x22\x4d\x18", "lz4 frame"), (b"\x03\x00\x08\x00", "binary xml"),
         (b"MZ", "windows pe (MZ)"), (b"\xca\xfe\xba\xbe", "mach-o fat or java class"),
         (b"\xcf\xfa\xed\xfe", "mach-o"), (b"%PDF", "pdf")]


def kind(v):
  # a guess at what a value is, from its first bytes
  if v is None:
    return "null"
  if not isinstance(v, bytes):
    return type(v).__name__
  for m, k in MAGIC:
    if v.startswith(m):
      return k
  head = v[:4096]
  if re.fullmatch(rb"[0-9a-fA-F\s]+", head) and len(v) >= 16:
    return "hex text"
  if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", head) and len(v) >= 64:
    return "base64 text"
  try:
    head.decode("utf-8")
    return "text"
  except UnicodeDecodeError:
    return "binary"


def short(v):
  if v is None:
    return ""
  if isinstance(v, bytes):
    try:
      s = v[:KEEP].decode("utf-8")
    except UnicodeDecodeError:
      return "<%d bytes>" % len(v)
    return s if s.isprintable() else "<%d bytes>" % len(v)
  return str(v)


def safe_name(s):
  s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._-")[:120]
  return s if s and s[0].isalnum() else ""


PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


def guess(row, apk_col, hashes):
  # (name, source) for one APK row; row: column name -> short value
  low = {k: (k.lower(), k.lower().rsplit(".", 1)[-1]) for k in row}
  # a sibling of the APK value in the same struct (Hugging Face stores files as {bytes, path})
  parent = apk_col.rsplit(".", 1)[0] if "." in apk_col else None
  for k, v in row.items():
    full, last = low[k]
    if k == apk_col or not v:
      continue
    base = v.replace("\\", "/").rsplit("/", 1)[-1]
    if base.lower().endswith(".apk") and (re.search(r"file|name|path|apk", last) or (parent and k.startswith(parent + "."))):
      n = safe_name(base[:-4])
      if n:
        return n, k
  pkg = ver = None
  for k, v in row.items():
    full, last = low[k]
    if not pkg and re.search(r"package|pkg|app_?id|bundle", last) and PKG.match(v or ""):
      pkg = (k, v)
    elif not ver and re.search(r"version", last) and re.fullmatch(r"[A-Za-z0-9._-]{1,40}", v or ""):
      ver = (k, v)
  if pkg:
    n = safe_name(pkg[1] + ("_" + ver[1] if ver else ""))
    if n:
      return n, pkg[0] + (" + " + ver[0] if ver else "")
  for k, v in row.items():
    vv = (v or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", vv) and vv in hashes.values():
      return vv, k + " (matches the APK)"
  return hashes["sha256"], "sha256 of the APK"


def mismatched(row, hashes):
  # hash-named columns whose hex value is none of the APK's hashes
  out = []
  for k, v in row.items():
    vv = (v or "").strip().lower()
    if re.search(r"sha|md5|hash", k.lower()) and re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", vv) \
       and vv not in hashes.values():
      out.append(k)
  return out


def parse_rows(spec):
  out = set()
  for part in spec.split(","):
    part = part.strip()
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
    if not m:
      raise SystemExit(f"bad --rows part {part!r}")
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    if b - a > 1000000:
      raise SystemExit("--rows range too large")
    out.update(range(a, b + 1))
  return out


def main():
  args = sys.argv[1:]
  if not args or args[0] in ("-h", "--help"):
    print(__doc__)
    return 0
  path, listing, rows_sel, only_col, limit, describe = args[0], False, None, None, 20, False
  i = 1
  while i < len(args):
    a = args[i]
    if a == "--list":
      listing = True
    elif a == "--rows" and i + 1 < len(args):
      rows_sel = parse_rows(args[i + 1])
      i += 1
    elif a == "--column" and i + 1 < len(args):
      only_col = args[i + 1]
      i += 1
    elif a == "--max" and i + 1 < len(args) and args[i + 1].isdigit():
      limit = int(args[i + 1])
      i += 1
    elif a == "--all":
      limit = None
    elif a == "--describe":
      listing = describe = True
    else:
      raise SystemExit(f"unknown argument {a!r} (see --help)")
    i += 1
  src = os.path.realpath(path)
  if not os.path.isfile(src):
    raise SystemExit(f"no file {path}")
  size = os.path.getsize(src)
  out_dir = os.path.join(ROOT, "work", "_samples")
  base = safe_name(os.path.basename(src).rsplit(".", 1)[0]) or "parquet"
  found, written, problems, stats = [], 0, [], {}
  with open(src, "rb") as f:
    try:
      fm = read_footer(f, size)
      cols = columns(fm.get(2) or [])
    except (Bad, IndexError, struct.error) as e:
      raise SystemExit(f"{path}: {e}")
    readable = [c for c in cols if c.ptype in (1, 2, 6, 7) and not c.max_rep]
    for c in cols:
      if c not in readable:
        problems.append(f"column {c.name}: not read (" + ("a list" if c.max_rep else f"type {c.ptype}") + ")")
    print(f"{path}: {fm.get(3, 0)} rows, {len(fm.get(4) or [])} row groups, columns: "
          + ", ".join(c.name for c in cols))
    first_row = 0
    for gi, rg in enumerate(fm.get(4) or []):
      chunks = {}
      for cc in rg.get(1) or []:
        md = cc.get(3) or {}
        chunks[".".join(x.decode("utf-8", "replace") for x in md.get(3, []))] = md
      nrows = rg.get(3, 0)
      # pass 1: every readable column; short values kept for names, APK rows hashed
      short_vals = {c.name: [""] * nrows for c in readable}
      for c in readable:
        st = stats.setdefault(c.name, {"values": 0, "nulls": 0, "min": None, "max": 0, "first": None, "kinds": {},
                                       "codec": None, "encodings": set(), "type": c.ptype})
      apk_rows = {}  # row in the group -> [(column, size, hashes)]
      for c in readable:
        md = chunks.get(c.name)
        if md is None:
          continue
        st = stats[c.name]
        st["codec"] = md.get(4, 0)
        st["encodings"].update(md.get(2) or [])
        try:
          for r, v in enumerate(chunk_values(f, size, c, md, st.setdefault("pages", {}))):
            if r >= nrows:
              break
            k = kind(v)
            st["kinds"][k] = st["kinds"].get(k, 0) + 1
            if v is None:
              st["nulls"] += 1
            else:
              st["values"] += 1
              ln = len(v) if isinstance(v, bytes) else len(str(v))
              st["min"] = ln if st["min"] is None else min(st["min"], ln)
              st["max"] = max(st["max"], ln)
              if st["first"] is None:
                st["first"] = v[:16].hex(" ") if isinstance(v, bytes) else str(v)[:40]
              if k in ("text", "int") and ln <= 80:
                t = short(v)
                st.setdefault("top", {})[t] = st.setdefault("top", {}).get(t, 0) + 1
            b = as_apk(v) if c.ptype in (6, 7) and (only_col in (None, c.name)) else None
            if b is not None:
              hashes = {"md5": hashlib.md5(b).hexdigest(), "sha1": hashlib.sha1(b).hexdigest(),
                        "sha256": hashlib.sha256(b).hexdigest()}
              apk_rows.setdefault(r, []).append((c.name, len(b), hashes))
              short_vals[c.name][r] = "<APK %d bytes>" % len(b)
            else:
              short_vals[c.name][r] = short(v)
        except (Bad, IndexError, struct.error, StopIteration) as e:
          problems.append(f"row group {gi}, column {c.name}: {e}")
      for r in sorted(apk_rows):
        row = {k: v[r] for k, v in short_vals.items()}
        for cname, sz, hashes in apk_rows[r]:
          name, source = guess(row, cname, hashes)
          found.append({"row": first_row + r, "group": gi, "grow": r, "column": cname, "size": sz,
                        "hashes": hashes, "name": name, "source": source, "row_values": row,
                        "mismatch": mismatched(row, hashes)})
      first_row += nrows
    # names unique within this run
    seen = {}
    for x in found:
      n = x["name"]
      seen[n] = seen.get(n, 0) + 1
      if seen[n] > 1:
        x["name"] = f"{n}-{seen[n]}"
    for x in found:
      print(f"row {x['row']}  {x['column']}  {x['size']} bytes  sha256 {x['hashes']['sha256']}  "
            f"name {x['name']} (from {x['source']})"
            + (f"  hash column does not match the bytes: {', '.join(x['mismatch'])}" if x["mismatch"] else ""))
    if not found:
      print("no APK found in any binary column")
    if listing and (not found or describe):
      # what each column holds, to see why nothing was found or what else is there
      cn = {0: "none", 1: "snappy", 2: "gzip", 3: "lzo", 4: "brotli", 5: "lz4", 6: "zstd", 7: "lz4_raw"}
      tn = {1: "int32", 2: "int64", 6: "byte_array", 7: "fixed_len_byte_array"}
      for c in cols:
        st = stats.get(c.name)
        if st is None:
          print(f"column {c.name}: not read")
          continue
        pg = ", ".join(f"{k} {n}" for k, n in sorted((st.get("pages") or {}).items()))
        print(f"column {c.name}: {tn.get(st['type'], st['type'])}, {'optional' if c.max_def else 'required'}, "
              f"pages {pg or 'none'}, codec {cn.get(st['codec'], st['codec'])}, "
              f"encodings {sorted(st['encodings'])}, {st['values']} values, {st['nulls']} nulls, "
              f"length {st['min']}-{st['max']}, kinds "
              + ", ".join(f"{k} {n}" for k, n in sorted(st["kinds"].items(), key=lambda x: -x[1]))
              + (f", first {st['first']}" if st["first"] is not None else ""))
        top = sorted((st.get("top") or {}).items(), key=lambda x: (-x[1], x[0]))
        if top and (len(top) < st["values"] or st["values"] < 10):
          print("  most common: " + ", ".join(f"{safe_name(t) or '?'} {n}" for t, n in top[:15])
                + (f" (+{len(top) - 15} more)" if len(top) > 15 else ""))
    if listing or not found:
      for p in problems:
        print(f"problem: {p}", file=sys.stderr)
      return 0 if found or not problems else 1
    chosen = [x for x in found if rows_sel is None or x["row"] in rows_sel]
    if limit is not None and len(chosen) > limit:
      print(f"{len(chosen)} APKs selected; extracting the first {limit} (--max N, --all, or --rows to choose)")
      chosen = chosen[:limit]
    os.makedirs(out_dir, exist_ok=True)
    if os.path.islink(out_dir):
      raise SystemExit("work/_samples is a link")
    # pass 2: the chosen values again, written as they come
    want = {}
    for x in chosen:
      want.setdefault((x["group"], x["column"]), {})[x["grow"]] = x
    for (gi, cname), byrow in sorted(want.items()):
      rg = fm[4][gi]
      md = next(cc.get(3) for cc in rg.get(1) or []
                if ".".join(x.decode("utf-8", "replace") for x in (cc.get(3) or {}).get(3, [])) == cname)
      c = next(c for c in readable if c.name == cname)
      left = len(byrow)
      try:
        for r, v in enumerate(chunk_values(f, size, c, md)):
          x = byrow.get(r)
          if x is None:
            continue
          left -= 1
          b = as_apk(v)
          if b is None or hashlib.sha256(b).hexdigest() != x["hashes"]["sha256"]:
            problems.append(f"row {x['row']}: changed between reads; not written")
            continue
          dst = os.path.join(out_dir, x["name"] + ".apk")
          try:
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
          except FileExistsError:
            problems.append(f"row {x['row']}: work/_samples/{x['name']}.apk exists; not overwritten")
            continue
          with os.fdopen(fd, "wb") as fh:
            fh.write(b)
          written += 1
          print(f"extracted work/_samples/{x['name']}.apk  sha256 {x['hashes']['sha256']}")
          if left == 0:
            break
      except (Bad, IndexError, struct.error) as e:
        problems.append(f"row group {gi}, column {cname}: {e} (second read)")
  # the index: every APK row found, with its short column values
  cols_out = sorted({k for x in found for k in x["row_values"]})
  idx = os.path.join(out_dir, f"{base}.index.tsv")
  lines = ["\t".join(["row", "name", "name_source", "sha256", "size", "column"] + cols_out)]
  for x in found:
    vals = [re.sub(r"[\t\r\n]+", " ", x["row_values"].get(k, ""))[:200] for k in cols_out]
    lines.append("\t".join([str(x["row"]), x["name"], x["source"], x["hashes"]["sha256"], str(x["size"]), x["column"]] + vals))
  try:
    fd = os.open(idx, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
      fh.write("\n".join(lines) + "\n")
    print(f"index: work/_samples/{base}.index.tsv")
  except OSError as e:
    problems.append(f"index not written: {e}")
  for p in problems:
    print(f"problem: {p}", file=sys.stderr)
  print(f"== {written} of {len(chosen)} written to work/_samples/; unpack each with ./cupella unpack.sh work/_samples/<name>.apk")
  return 0 if written == len(chosen) else 1


if __name__ == "__main__":
  sys.exit(main())
