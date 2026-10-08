#!/usr/bin/env bash
# Checks parquet-samples.py on Parquet files written here by a minimal writer (the fake
# APKs are tiny ZIPs with an AndroidManifest.xml entry, nothing from a real sample):
#   f1: uncompressed, data page v1, a dictionary-encoded package column, the APK in a
#       Hugging Face style struct {bytes, path}, a null row, an md5 column
#   f2: snappy and gzip, data page v2, the APK as base64 text, a sha256 column that does
#       not match the bytes
# Names guessed from the path, the package and version, a matching hash, and the
# APK's sha256; extraction, --rows, --max, no overwrite, the index, a non-Parquet file;
# parquet-pack.py's files read back, in each codec and layout it writes.
# Prints PASS or FAIL per case and removes what it wrote.
#
# Usage: ./cupella fixtures/parquet-samples-test.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
w="$root/work/_parquet-fixture"
rm -rf "$w"
mkdir -p "$w"
cd "$root"
python3 - "$w" <<'PY'
import base64
import gzip
import hashlib
import io
import json
import struct
import sys
import zipfile

w = sys.argv[1]


def apk(tag):
  b = io.BytesIO()
  with zipfile.ZipFile(b, "w") as z:
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + tag.encode())
    z.writestr("classes.dex", b"dex\n035\x00" + tag.encode() * 50)
  return b.getvalue()


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


I32, I64, BIN, LIST, STRUCT, TRUE, FALSE = 5, 6, 8, 9, 12, 1, 2


def tstruct(fields):
  # fields: [(id, type, value)] in id order
  out, last = bytearray(), 0
  for fid, t, v in fields:
    if t == "bool":
      t, v = (TRUE if v else FALSE), None
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


def rle(vals, width=1):
  out = bytearray()
  i = 0
  while i < len(vals):
    j = i
    while j < len(vals) and vals[j] == vals[i]:
      j += 1
    out += varint((j - i) << 1) + vals[i].to_bytes((width + 7) // 8, "little")
    i = j
  return bytes(out)


def plain_bytes(vals):
  return b"".join(struct.pack("<I", len(v)) + v for v in vals)


def snappy(data):
  out = bytearray(varint(len(data)))
  for i in range(0, len(data), 60000):
    ch = data[i:i + 60000]
    out += bytes([61 << 2]) + struct.pack("<H", len(ch) - 1) + ch
  return bytes(out)


def write(path, schema, nrows, cols):
  # cols: [(path list, ptype, pages bytes, codec, encodings, num_values, usize, dict_offset_rel)]
  body = bytearray(b"PAR1")
  chunks = []
  for pth, ptype, pages, codec, encs, n, usize, has_dict in cols:
    off = len(body)
    body += pages
    md = [(1, I32, ptype), (2, LIST, (I32, encs)), (3, LIST, (BIN, [p.encode() for p in pth])), (4, I32, codec),
          (5, I64, n), (6, I64, usize), (7, I64, len(pages)), (9, I64, off + has_dict)]
    if has_dict:
      md.append((11, I64, off))
    chunks.append([(2, I64, off), (3, STRUCT, md)])
  fm = tstruct([(1, I32, 1), (2, LIST, (STRUCT, schema)), (3, I64, nrows),
                (4, LIST, (STRUCT, [[(1, LIST, (STRUCT, chunks)), (2, I64, len(body)), (3, I64, nrows)]]))])
  body += fm + struct.pack("<I", len(fm)) + b"PAR1"
  open(path, "wb").write(body)


def page_v1(values_bytes, defs, codec_fn=lambda b: b, max_def=1, enc=0):
  lv = rle(defs, max_def.bit_length()) if max_def else b""
  raw = (struct.pack("<I", len(lv)) + lv if max_def else b"") + values_bytes
  comp = codec_fn(raw)
  hdr = tstruct([(1, I32, 0), (2, I32, len(raw)), (3, I32, len(comp)),
                 (5, STRUCT, [(1, I32, len(defs)), (2, I32, enc), (3, I32, 3), (4, I32, 3)])])
  return hdr + comp, len(hdr) + len(raw)


def page_v2(values_bytes, defs, codec_fn, max_def=1):
  lv = rle(defs, max_def.bit_length())
  comp = codec_fn(values_bytes)
  hdr = tstruct([(1, I32, 3), (2, I32, len(lv) + len(values_bytes)), (3, I32, len(lv) + len(comp)),
                 (8, STRUCT, [(1, I32, len(defs)), (2, I32, defs.count(0)), (3, I32, len(defs)), (4, I32, 0),
                              (5, I32, len(lv)), (6, I32, 0), (7, "bool", True)])])
  return hdr + lv + comp, len(hdr) + len(lv) + len(values_bytes)


a1, a2, a3, a4, a5 = apk("one"), apk("two"), apk("three"), apk("four"), apk("five")
facts = {}
for k, a in (("a1", a1), ("a2", a2), ("a3", a3), ("a4", a4), ("a5", a5)):
  facts[k] = {"sha256": hashlib.sha256(a).hexdigest(), "md5": hashlib.md5(a).hexdigest()}

# f1: rows: a1 with path; a2 with package+version; a3 with only an md5; a null APK
OPT, REQ = 1, 0
schema = [[(4, BIN, b"schema"), (5, I32, 4)],
          [(1, I32, 6), (3, I32, OPT), (4, BIN, b"package_name")],
          [(1, I32, 6), (3, I32, OPT), (4, BIN, b"version")],
          [(1, I32, 6), (3, I32, OPT), (4, BIN, b"md5")],
          [(3, I32, OPT), (4, BIN, b"apk"), (5, I32, 2)],
          [(1, I32, 6), (3, I32, OPT), (4, BIN, b"bytes")],
          [(1, I32, 6), (3, I32, OPT), (4, BIN, b"path")]]
pk_dict = [b"org.cupellafixture.two", b"org.cupellafixture.other"]
dict_page_body = plain_bytes(pk_dict)
dhdr = tstruct([(1, I32, 2), (2, I32, len(dict_page_body)), (3, I32, len(dict_page_body)),
                (7, STRUCT, [(1, I32, 2), (2, I32, 0)])])
# package: row0 other, row1 two, row2 null, row3 other (dictionary indices)
idx = bytes([1]) + rle([1, 0, 1], 1)
pk_page, pk_us = page_v1(idx, [1, 1, 0, 1], enc=8)
pk_pages = dhdr + dict_page_body + pk_page
ver_page, ver_us = page_v1(plain_bytes([b"7"]), [0, 1, 0, 0])
md5_page, md5_us = page_v1(plain_bytes([facts["a3"]["md5"].encode()]), [0, 0, 1, 0])
# apk.bytes: def 2 = present, 0 = apk struct null
by_page, by_us = page_v1(plain_bytes([a1, a2, a3]), [2, 2, 2, 0], max_def=2)
pa_page, pa_us = page_v1(plain_bytes([b"some/dir/cupellafixture-one.apk"]), [2, 1, 1, 0], max_def=2)
write(f"{w}/f1.parquet", schema, 4, [
  (["package_name"], 6, pk_pages, 0, [0, 8], 4, len(dhdr) + len(dict_page_body) + pk_us, len(dhdr) + len(dict_page_body)),
  (["version"], 6, ver_page, 0, [0], 4, ver_us, 0),
  (["md5"], 6, md5_page, 0, [0], 4, md5_us, 0),
  (["apk", "bytes"], 6, by_page, 0, [0], 4, by_us, 0),
  (["apk", "path"], 6, pa_page, 0, [0], 4, pa_us, 0)])

# f2: base64 APKs (snappy, page v2), a sha256 column that does not match (gzip, v1)
schema2 = [[(4, BIN, b"schema"), (5, I32, 2)],
           [(1, I32, 6), (3, I32, OPT), (4, BIN, b"sha256")],
           [(1, I32, 6), (3, I32, OPT), (4, BIN, b"data")]]
sh_page, sh_us = page_v1(plain_bytes([b"0" * 64, facts["a5"]["sha256"].encode()]), [1, 1],
                         codec_fn=lambda b: gzip.compress(b))
da_page, da_us = page_v2(plain_bytes([base64.b64encode(a4), base64.b64encode(a5)]), [1, 1], snappy)
write(f"{w}/f2.parquet", schema2, 2, [(["sha256"], 6, sh_page, 2, [0], 2, sh_us, 0),
                                      (["data"], 6, da_page, 1, [0], 2, da_us, 0)])
open(f"{w}/not.parquet", "wb").write(b"PK\x03\x04 not parquet at all, long enough")
json.dump(facts, open(f"{w}/facts.json", "w"))
PY
s=work/_samples
run() { python3 scripts/parquet-samples.py "$@" 2>&1 || true; }
check() { if [ "$2" = 1 ]; then echo "$1: PASS"; else echo "$1: FAIL"; fi; }
yes() { "$@" > /dev/null 2>&1 && echo 1 || echo 0; }
f() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])' "$w/facts.json" "$1" "$2"; }
a3md5=$(f a3 md5); a4sha=$(f a4 sha256); a5sha=$(f a5 sha256); a1sha=$(f a1 sha256)

out=$(run "$w/f1.parquet" --list)
check "f1: three APKs found, the null row skipped" "$( [ "$(grep -c '^row ' <<< "$out")" = 3 ] && echo 1 || echo 0)"
check "f1: name from the struct's path" "$(yes grep -q 'name cupellafixture-one (from apk.path)' <<< "$out")"
check "f1: name from package and version (dictionary column)" "$(yes grep -q 'name org.cupellafixture.two_7 (from package_name + version)' <<< "$out")"
check "f1: name from a matching md5 column" "$(yes grep -q "name $a3md5 (from md5 (matches the APK))" <<< "$out")"
out=$(run "$w/f1.parquet" --describe)
check "f1: --describe names each column's contents" "$(yes grep -q 'column apk.bytes: byte_array, optional, pages v1 1, codec none.*kinds zip 3, null 1' <<< "$out")"
check "f1: --list writes nothing" "$( [ ! -e $s/cupellafixture-one.apk ] && echo 1 || echo 0)"
out=$(run "$w/f1.parquet" --rows 0)
check "f1: --rows extracts only that row" "$( [ -f $s/cupellafixture-one.apk ] && [ ! -e $s/org.cupellafixture.two_7.apk ] && echo 1 || echo 0)"
check "f1: the extracted APK is the row's bytes" "$( [ "$(sha256sum $s/cupellafixture-one.apk | cut -c1-64)" = "$a1sha" ] && echo 1 || echo 0)"
out=$(run "$w/f1.parquet" --max 1)
check "f1: --max limits the extraction" "$(yes grep -q '3 APKs selected; extracting the first 1' <<< "$out")"
check "f1: an existing file is not overwritten" "$(yes grep -q 'exists; not overwritten' <<< "$out")"
out=$(run "$w/f1.parquet")
check "f1: the rest extracted" "$( [ -f $s/org.cupellafixture.two_7.apk ] && [ -f "$s/$a3md5.apk" ] && echo 1 || echo 0)"
check "f1: index written" "$(yes grep -q 'org.cupellafixture.two_7' $s/f1.index.tsv)"
out=$(run "$w/f2.parquet")
check "f2: snappy, gzip, page v2, base64: both APKs" "$( [ "$(grep -c '^extracted ' <<< "$out")" = 2 ] && echo 1 || echo 0)"
check "f2: a mismatched hash column is reported and not used" "$(yes grep -q "sha256 $a4sha  name $a4sha (from sha256 of the APK)  hash column does not match the bytes: sha256" <<< "$out")"
check "f2: a matching sha256 column names the APK" "$(yes grep -q "name $a5sha (from sha256 (matches the APK))" <<< "$out")"
check "f2: the decoded base64 APK is written" "$( [ "$(sha256sum "$s/$a4sha.apk" | cut -c1-64)" = "$a4sha" ] && echo 1 || echo 0)"
out=$(run "$w/not.parquet")
check "a non-Parquet file is refused" "$(yes grep -q 'not a Parquet file' <<< "$out")"
# parquet-pack.py and back: a fake APK from work/_samples/, each codec and layout it writes
cp "$s/$a4sha.apk" "$s/cupellafixture-pack.apk"
# zstd only where the tool is (the image has it; a host run of this fixture may not)
have_zstd=0
command -v zstd > /dev/null && have_zstd=1
for opts in "--codec none" "--codec gzip --struct" "--codec snappy --v2" "--codec gzip --struct --v2" "--codec zstd"; do
  if [[ "$opts" == *zstd* && "$have_zstd" = 0 ]]; then echo "pack and read back ($opts): SKIP (no zstd)"; continue; fi
  tag=$(tr -c 'A-Za-z0-9\n' _ <<< "$opts")
  python3 scripts/parquet-pack.py "cupellafixture-$tag" work/_samples/cupellafixture-pack.apk $opts > /dev/null 2>&1 || true
  out=$(run "work/_parquet/cupellafixture-$tag.parquet" --list)
  check "pack and read back ($opts)" "$(yes grep -q "sha256 $a4sha  name cupellafixture-pack (from file_name" <<< "$out")"
  rm -f "work/_parquet/cupellafixture-$tag.parquet"
done
for c in gzip snappy zstd; do
  if [ "$c" = zstd ] && [ "$have_zstd" = 0 ]; then echo "pack --layout family --codec zstd: SKIP (no zstd)"; continue; fi
  python3 scripts/parquet-pack.py "cupellafixture-family-$c" work/_samples/cupellafixture-pack.apk --layout family --codec $c > /dev/null 2>&1 || true
  out=$(run "work/_parquet/cupellafixture-family-$c.parquet" --describe)
  check "pack --layout family --codec $c: the dictionary pages read back" "$(grep -q 'most common: benign 1' <<< "$out" && grep -q "sha256 $a4sha" <<< "$out" && ! grep -q problem <<< "$out" && echo 1 || echo 0)"
  rm -f "work/_parquet/cupellafixture-family-$c.parquet"
done
python3 scripts/parquet-pack.py cupellafixture-family work/_samples/cupellafixture-pack.apk --layout family --family testfam --score 3 > /dev/null 2>&1 || true
out=$(run work/_parquet/cupellafixture-family.parquet --describe)
check "pack --layout family: score, family, content, dictionary-encoded, read back" "$(grep -q "sha256 $a4sha  name $a4sha (from sha256 of the APK)" <<< "$out" \
  && grep -q 'column family: byte_array, optional, pages dictionary 1, v1 1, codec none, encodings \[2, 3, 4\]' <<< "$out" \
  && grep -q 'most common: testfam 1' <<< "$out" && grep -q 'column score: int32' <<< "$out" && echo 1 || echo 0)"
rm -f work/_parquet/cupellafixture-family.parquet
out=$(python3 scripts/parquet-pack.py cupellafixture-x /etc/passwd 2>&1 || true)
check "pack refuses a file outside data/ and work/_samples/" "$(yes grep -q 'not a file under data/ or work/_samples/' <<< "$out")"
rm -f "$s/cupellafixture-pack.apk"
rm -f "$s/cupellafixture-one.apk" "$s/org.cupellafixture.two_7.apk" "$s/$a3md5.apk" "$s/$a4sha.apk" "$s/$a5sha.apk" \
  "$s/f1.index.tsv" "$s/f2.index.tsv"
rm -rf "$w"
