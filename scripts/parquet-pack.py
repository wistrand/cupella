#!/usr/bin/env python3
"""Pack APKs into a Parquet file, one per row, the way sample datasets store them.

For testing parquet-samples.py on real APKs, and for handing a set of samples on in a
dataset's format. Copies bytes only: nothing in an APK is parsed or run. Writes
work/_parquet/<out>.parquet (never overwritten), one row group, one page per column.

Columns: file_name, sha256, size, and the APK as binary column "apk", or with --struct
as a Hugging Face style struct apk {bytes, path}. With --layout family instead: score
(int32), family (text), content (binary), all optional, score and family
dictionary-encoded, uncompressed by default, as in a malware dataset of that shape
(a label per sample, no names or hashes).

Usage: ./cupella parquet-pack.py <out> <apk>... [--codec none|gzip|snappy|zstd] [--struct] [--v2]
                                 [--layout family [--family LABEL] [--score N]]
  <out>    a file name: letters, digits, ._-  (.parquet is added)
  <apk>    paths under data/ or work/_samples/
  --codec  page compression (default snappy, as pyarrow writes; zstd needs the zstd tool)
  --struct the APK as apk.bytes with apk.path, instead of a flat binary column
  --v2     data pages v2 instead of v1
  --layout family  the score, family, content layout; --family (default benign) and
           --score (default 0) for every row
"""
import gzip
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
I32, I64, BIN, LIST, STRUCT, TRUE, FALSE = 5, 6, 8, 9, 12, 1, 2
CODECS = {"none": 0, "snappy": 1, "gzip": 2, "zstd": 6}


def varint(n):
  out = bytearray()
  while True:
    c = n & 0x7F
    n >>= 7
    out.append(c | (0x80 if n else 0))
    if not n:
      return bytes(out)


def zz(n):
  return varint((n << 1) ^ (n >> 63))


def tstruct(fields):
  # Thrift compact struct; fields: [(id, type, value)] in id order
  out, last = bytearray(), 0
  for fid, t, v in fields:
    if t == "bool":
      t = TRUE if v else FALSE
    out.append(((fid - last) << 4) | t)
    last = fid
    if t in (I32, I64):
      out += zz(v)
    elif t == BIN:
      out += varint(len(v)) + v
    elif t == STRUCT:
      out += tstruct(v)
    elif t == LIST:
      et, items = v
      out.append((len(items) << 4 | et) if len(items) < 15 else (0xF0 | et))
      if len(items) >= 15:
        out += varint(len(items))
      for it in items:
        out += zz(it) if et in (I32, I64) else (varint(len(it)) + it if et == BIN else tstruct(it))
  out.append(0)
  return bytes(out)


def rle(vals, width):
  out, i = bytearray(), 0
  while i < len(vals):
    j = i
    while j < len(vals) and vals[j] == vals[i]:
      j += 1
    out += varint((j - i) << 1) + vals[i].to_bytes(max(1, (width + 7) // 8), "little")
    i = j
  return bytes(out)


def snappy(data):
  # literal-only snappy: valid for every reader, no compression
  out = bytearray(varint(len(data)))
  for i in range(0, len(data), 1 << 16):
    ch = data[i:i + (1 << 16)]
    out += bytes([61 << 2]) + struct.pack("<H", len(ch) - 1) + ch
  return bytes(out)


def compress(codec, data):
  if codec == 0:
    return data
  if codec == 1:
    return snappy(data)
  if codec == 2:
    return gzip.compress(data, 6)
  exe = shutil.which("zstd")
  if not exe:
    sys.exit("--codec zstd needs the zstd tool in the image (./cupella build)")
  return subprocess.run([exe, "-q", "-c", "-3"], input=data, stdout=subprocess.PIPE, check=True).stdout


def page(values, defs, max_def, codec, v2, enc=0):
  lv = rle(defs, max_def.bit_length()) if max_def else b""
  if v2:
    comp = compress(codec, values)
    hdr = tstruct([(1, I32, 3), (2, I32, len(lv) + len(values)), (3, I32, len(lv) + len(comp)),
                   (8, STRUCT, [(1, I32, len(defs)), (2, I32, sum(1 for d in defs if d < max_def)),
                                (3, I32, len(defs)), (4, I32, enc), (5, I32, len(lv)), (6, I32, 0),
                                (7, "bool", codec != 0)])])
    return hdr + lv + comp, len(hdr) + len(lv) + len(values)
  raw = (struct.pack("<I", len(lv)) + lv if max_def else b"") + values
  comp = compress(codec, raw)
  hdr = tstruct([(1, I32, 0), (2, I32, len(raw)), (3, I32, len(comp)),
                 (5, STRUCT, [(1, I32, len(defs)), (2, I32, enc), (3, I32, 3), (4, I32, 3)])])
  return hdr + comp, len(hdr) + len(raw)


def dict_page(values_plain, n, codec):
  # compressed with the chunk's codec, like every other page of the chunk
  comp = compress(codec, values_plain)
  hdr = tstruct([(1, I32, 2), (2, I32, len(values_plain)), (3, I32, len(comp)),
                 (7, STRUCT, [(1, I32, n), (2, I32, 0)])])
  return hdr + comp, len(hdr) + len(values_plain)


def dict_indices(idx):
  width = max(1, (max(idx) if idx else 0).bit_length())
  return bytes([width]) + rle(idx, width)


def byte_array(vals):
  return b"".join(struct.pack("<I", len(v)) + v for v in vals)


def main():
  args = sys.argv[1:]
  if len(args) < 2 or args[0] in ("-h", "--help"):
    print(__doc__)
    return 0 if args and args[0] in ("-h", "--help") else 2
  codec, as_struct, v2, files, layout, family, score = None, False, False, [], None, "benign", 0
  out_name = args.pop(0)
  i = 0
  while i < len(args):
    a = args[i]
    if a == "--codec" and i + 1 < len(args) and args[i + 1] in CODECS:
      codec = CODECS[args[i + 1]]
      i += 1
    elif a == "--struct":
      as_struct = True
    elif a == "--v2":
      v2 = True
    elif a == "--layout" and i + 1 < len(args) and args[i + 1] == "family":
      layout = "family"
      i += 1
    elif a == "--family" and i + 1 < len(args):
      family = args[i + 1]
      i += 1
    elif a == "--score" and i + 1 < len(args) and re.fullmatch(r"-?\d+", args[i + 1]):
      score = int(args[i + 1])
      i += 1
    elif a.startswith("-"):
      sys.exit(f"unknown option {a!r} (see --help)")
    else:
      files.append(a)
    i += 1
  if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", out_name):
    sys.exit(f"bad output name {out_name!r}")
  out_name = re.sub(r"\.parquet$", "", out_name)
  allowed = [os.path.join(ROOT, "data"), os.path.join(ROOT, "work", "_samples")]
  apks = []
  for p in files:
    real = os.path.realpath(os.path.join(ROOT, p) if not os.path.isabs(p) else p)
    if not any(real.startswith(a + os.sep) for a in allowed) or not os.path.isfile(real):
      sys.exit(f"{p}: not a file under data/ or work/_samples/")
    with open(real, "rb") as f:
      b = f.read()
    apks.append((os.path.basename(real), b))
  n = len(apks)
  if codec is None:
    codec = CODECS["none"] if layout == "family" else CODECS["snappy"]
  names = [x[0].encode() for x in apks]
  shas = [hashlib.sha256(x[1]).hexdigest().encode() for x in apks]
  sizes = b"".join(struct.pack("<q", len(x[1])) for x in apks)
  datas = [x[1] for x in apks]
  OPT, REQ = 1, 0
  schema = [[(4, BIN, b"schema"), (5, I32, 4)],
            [(1, I32, 6), (3, I32, OPT), (4, BIN, b"file_name")],
            [(1, I32, 6), (3, I32, OPT), (4, BIN, b"sha256")],
            [(1, I32, 2), (3, I32, REQ), (4, BIN, b"size")]]
  cols = [(["file_name"], 6, byte_array(names), [1] * n, 1),
          (["sha256"], 6, byte_array(shas), [1] * n, 1),
          (["size"], 2, sizes, [0] * n, 0)]
  if as_struct:
    schema += [[(3, I32, OPT), (4, BIN, b"apk"), (5, I32, 2)],
               [(1, I32, 6), (3, I32, OPT), (4, BIN, b"bytes")],
               [(1, I32, 6), (3, I32, OPT), (4, BIN, b"path")]]
    cols += [(["apk", "bytes"], 6, byte_array(datas), [2] * n, 2),
             (["apk", "path"], 6, byte_array(names), [2] * n, 2)]
  else:
    schema.append([(1, I32, 6), (3, I32, OPT), (4, BIN, b"apk")])
    cols.append((["apk"], 6, byte_array(datas), [1] * n, 1))
  dicts = {}
  if layout == "family":
    schema = [[(4, BIN, b"schema"), (5, I32, 3)],
              [(1, I32, 1), (3, I32, OPT), (4, BIN, b"score")],
              [(1, I32, 6), (3, I32, OPT), (4, BIN, b"family")],
              [(1, I32, 6), (3, I32, OPT), (4, BIN, b"content")]]
    # score and family: one dictionary entry, every row index 0 (PLAIN_DICTIONARY)
    dicts = {"score": struct.pack("<i", score), "family": byte_array([family.encode()])}
    cols = [(["score"], 1, dict_indices([0] * n), [1] * n, 1),
            (["family"], 6, dict_indices([0] * n), [1] * n, 1),
            (["content"], 6, byte_array(datas), [1] * n, 1)]
  body, chunks = bytearray(b"PAR1"), []
  for pth, ptype, values, defs, max_def in cols:
    off = len(body)
    dp, dusize = dict_page(dicts[pth[0]], 1, codec) if pth[0] in dicts else (b"", 0)
    pg, usize = page(values, defs, max_def, codec, v2, enc=2 if dp else 0)
    body += dp + pg
    md = [(1, I32, ptype), (2, LIST, (I32, [2, 3, 4] if dp else [0, 3, 4])),
          (3, LIST, (BIN, [x.encode() for x in pth])), (4, I32, codec),
          (5, I64, n), (6, I64, usize + dusize), (7, I64, len(dp) + len(pg)), (9, I64, off + len(dp))]
    if dp:
      md.append((11, I64, off))
    chunks.append([(2, I64, off), (3, STRUCT, md)])
  fm = tstruct([(1, I32, 1), (2, LIST, (STRUCT, schema)), (3, I64, n),
                (4, LIST, (STRUCT, [[(1, LIST, (STRUCT, chunks)), (2, I64, len(body)), (3, I64, n)]])),
                (6, BIN, b"cupella parquet-pack.py")])
  body += fm + struct.pack("<I", len(fm)) + b"PAR1"
  out_dir = os.path.join(ROOT, "work", "_parquet")
  os.makedirs(out_dir, exist_ok=True)
  if os.path.islink(out_dir):
    sys.exit("work/_parquet is a link")
  dst = os.path.join(out_dir, out_name + ".parquet")
  try:
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
  except FileExistsError:
    sys.exit(f"work/_parquet/{out_name}.parquet exists; not overwritten")
  with os.fdopen(fd, "wb") as f:
    f.write(body)
  for (name, _), sha in zip(apks, shas):
    print(f"row  {name}  sha256 {sha.decode()}")
  shape = "score, family, content" if layout == "family" else ("struct apk" if as_struct else "flat apk")
  print(f"wrote work/_parquet/{out_name}.parquet ({len(body)} bytes, {n} rows, codec "
        f"{[k for k, v in CODECS.items() if v == codec][0]}, {shape}, page {'v2' if v2 else 'v1'})")
  return 0


if __name__ == "__main__":
  sys.exit(main())
