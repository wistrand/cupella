#!/usr/bin/env python3
"""Decrypt payloads whose key is a constant in the APK, by trying and checking.

Packers and droppers ship their real code as an encrypted file in assets/ or res/, and
decrypt it at start with a common cipher and a key that is a constant in the stub. This
tries those ciphers with every constant the APK holds as a possible key, on every file
that looks encrypted, and keeps a result only when it is code:

  files    under raw/ with no known format and high entropy, and such members of ZIP
           archives found there; each as it is and, when it is a zlib or gzip stream,
           decompressed
  keys     dex string constants (as bytes, and Base64- or hex-decoded, and their MD5 and
           SHA-256), byte arrays from fill-array-data, printable strings of the native
           libraries, strings that stringfog.py decodes and that the decryption stage
           wrote (decrypt/out/); for XOR also the key that turns the first bytes into a
           dex or ZIP header
  ciphers  DES and 3DES (ECB, CBC), AES-128/192/256 (ECB, CBC; IV zero, the key, or the
           file's first block), RC4, repeating-key XOR, one-byte XOR and ADD
  check    the plaintext, after zlib, gzip, or ZIP layers, is a dex with a consistent
           header, a ZIP archive that opens and holds a dex, or an ELF file. Random
           output does not pass, so a wrong key cannot produce a result.

Nothing from the app is executed. A key derived at run time (from the package name, a
certificate, a server) or built by code is not found: that is the decryption stage's
work (prompts/decrypt.md).

Usage: ./cupella payload-decrypt.py <name>
Output: work/<name>/unlocked/<n>-<file>.<dex|apk|so> and work/<name>/unlocked.txt, one
        line per result: file, kind, size, source under raw/, layers, key (hex), key as
        text, where the key is in the APK, sha256 of the result. unpack.sh runs this and unpacks each dex or
        APK result as a child sample.
        work/<name>/encrypted-left.txt: the files that look encrypted and were not
        decrypted (source, size, entropy, layers removed): leads for the decryption stage.
"""
import base64
import binascii
import gzip
import hashlib
import io
import math
import os
import re
import shutil
import struct
import sys
import time
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dex  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MIN_SIZE = 512             # smaller files are not payloads
MAX_SIZE = 64 << 20        # per file read and per decompressed layer
MIN_ENTROPY = 7.0          # bits per byte over the first 64 KiB: compressed or encrypted
MAX_FILES = 60
MAX_KEYS = 400000
BUDGET = 300               # seconds for the key search
# formats that are what they say: not tried
KNOWN = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"ID3", b"\x00\x00\x01\x00", b"fLaC",
         b"\x03\x00\x08\x00", b"\x02\x00\x0c\x00", b"SQLite", b"%PDF", b"wOFF", b"wOF2", b"OTTO",
         b"\x00\x01\x00\x00", b"true", b"\x1aE\xdf\xa3", b"BM", b"\xfe\xed\xfe\xed", b"\xff\xfb", b"\xff\xf3",
         b"8BPS", b"II*\x00", b"MM\x00*", b"FWS", b"CWS", b"\xfd7zXZ", b"7z\xbc\xaf", b"Rar!", b"BZh",
         b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18")
DEX_MAGIC = re.compile(rb"^dex\n0[3-4][0-9]\0")
FIRST2 = {b"de", b"PK", b"\x7fE", b"\x1f\x8b", b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}


def entropy(data):
  if not data:
    return 0.0
  counts = [0] * 256
  for b in data:
    counts[b] += 1
  n = len(data)
  return -sum(c / n * math.log2(c / n) for c in counts if c)


def inflate(data, wbits=15):
  d = zlib.decompressobj(wbits)
  out = d.decompress(data, MAX_SIZE)
  if d.unconsumed_tail or not out:
    raise zlib.error("too large or empty")
  return out


def looks_zlib(b):
  return len(b) > 2 and b[0] & 0x0f == 8 and b[0] >> 4 <= 7 and (b[0] * 256 + b[1]) % 31 == 0


def code_parts(data, depth=0):
  """[(kind, bytes, layers)]: the code that data is after at most three wrapping layers.
  kind is dex, zip with dex, or elf; an archive of archives (split APKs) gives one part
  per member that is code, and then also its APKs without code (zip without dex: they
  hold the manifest). Empty when data is not code."""
  if DEX_MAGIC.match(data):
    if len(data) >= 0x70:
      size, hsize, endian = struct.unpack_from("<III", data, 0x20)
      if hsize == 0x70 and endian == 0x12345678 and 0x70 <= size <= len(data) + 16:
        return [("dex", data, [])]
    return []
  if data[:4] == b"\x7fELF" and len(data) > 64 and data[4] in (1, 2) and data[5] in (1, 2) and data[6] == 1:
    return [("elf", data, [])]
  if depth >= 3:
    return []
  if data[:4] == b"PK\x03\x04":
    out = []
    try:
      with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        dexes = [n for n in names if n.endswith(".dex")]
        if dexes and DEX_MAGIC.match(z.open(dexes[0]).read(8)):
          return [("zip with dex", data, [])]
        manifests = []
        for n in names[:16]:  # archives inside: a payload zipped once more, a set of split APKs
          if z.getinfo(n).file_size <= MAX_SIZE:
            member = z.read(n)
            parts = code_parts(member, depth + 1)
            out.extend((k, d, ["unzip %s" % n] + l) for k, d, l in parts)
            if not parts and member[:4] == b"PK\x03\x04":
              try:
                with zipfile.ZipFile(io.BytesIO(member)) as inner:
                  # the base APK, not a config split (whose manifest has a "split" attribute)
                  if "AndroidManifest.xml" in inner.namelist():
                    axml = inner.read("AndroidManifest.xml")
                    if b"\x05\x05split\x00" not in axml and "\x05split\x00".encode("utf-16-le") not in axml:
                      manifests.append(("zip without dex", member, ["unzip %s" % n]))
              except (zipfile.BadZipFile, OSError, ValueError, struct.error):
                pass
        if out:  # split APKs: the ones without code hold the app's manifest and resources
          out.extend(manifests)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, zlib.error, KeyError,
            struct.error):
      pass
    return out
  for name, cond, fn in (("inflate", looks_zlib(data), inflate),
                         ("gunzip", data[:3] == b"\x1f\x8b\x08", lambda d: inflate(d, 47))):
    if cond:
      try:
        return [(k, d, [name] + l) for k, d, l in code_parts(fn(data), depth + 1)]
      except (zlib.error, OSError, EOFError):
        return []
  return []


def dex_checksum_ok(data):
  """the adler32 in a dex header matches its content: the whole file decrypted right"""
  size = struct.unpack_from("<I", data, 0x20)[0]
  return size <= len(data) and zlib.adler32(data[12:size]) == struct.unpack_from("<I", data, 8)[0]


def unpad(data, block):
  n = data[-1] if data else 0
  return data[:-n] if 0 < n <= block and data.endswith(bytes([n]) * n) else data


def candidate_files(raw):
  """[(source, data, layers)]: files and ZIP members that may be encrypted payloads, each
  also decompressed when it is a zlib or gzip stream"""
  found = []

  def consider(source, data):
    if len(data) < MIN_SIZE or data.startswith(KNOWN) or DEX_MAGIC.match(data) or data[:4] == b"\x7fELF":
      return
    if data[:4] == b"PK\x03\x04":
      return
    variants = [(data, [])]
    for name, cond, fn in (("inflate", looks_zlib(data), inflate),
                           ("gunzip", data[:3] == b"\x1f\x8b\x08", lambda d: inflate(d, 47))):
      if cond:
        try:
          variants = [(fn(data), [name])]  # a valid stream: what is inside is the candidate
        except (zlib.error, OSError, EOFError):
          pass
    for d, layers in variants:
      # high entropy: encrypted or compressed; code under a compression layer only (a
      # deflated dex) is a result without a cipher
      if len(d) >= MIN_SIZE and (entropy(d[:65536]) >= MIN_ENTROPY or (layers and code_parts(d))):
        found.append((source, d, layers))

  skip = re.compile(r"^(classes\d*\.dex|AndroidManifest\.xml|resources\.arsc|META-INF/|lib/|kotlin/)")
  for dp, dn, fn in os.walk(raw):
    dn.sort()
    for f in sorted(fn):
      p = os.path.join(dp, f)
      rel = os.path.relpath(p, raw)
      if skip.match(rel) or os.path.islink(p):
        continue
      try:
        size = os.path.getsize(p)
        if size < MIN_SIZE or size > MAX_SIZE:
          continue
        with open(p, "rb") as fh:
          data = fh.read()
      except OSError:
        continue
      if data[:4] == b"PK\x03\x04":
        try:
          with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist()[:50]:
              if MIN_SIZE <= info.file_size <= MAX_SIZE:
                info.flag_bits &= ~1  # a set "encrypted" bit on plain entries is a known trick
                try:
                  consider("%s!%s" % (rel, info.filename), z.read(info))
                except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, OSError, ValueError,
                        struct.error):
                  pass
        except (zipfile.BadZipFile, OSError, ValueError, struct.error):
          pass
      else:
        consider(rel, data)
  found.sort(key=lambda x: (-len(x[1]), x[0]))
  return found[:MAX_FILES]


def native_strings(raw):
  out = {}
  lib = os.path.join(raw, "lib")
  if not os.path.isdir(lib):
    return out
  abis = sorted(os.listdir(lib), key=lambda a: (a != "arm64-v8a", a != "armeabi-v7a", a))
  for abi in abis[:1]:
    for f in sorted(os.listdir(os.path.join(lib, abi))):
      p = os.path.join(lib, abi, f)
      try:
        if os.path.getsize(p) > MAX_SIZE:
          continue
        with open(p, "rb") as fh:
          buf = fh.read()
      except OSError:
        continue
      for m in re.finditer(rb"[\x21-\x7e]{8,64}", buf):
        out.setdefault(m.group().decode("ascii"), "string in lib/%s/%s" % (abi, f))
        if len(out) > 100000:
          return out
  return out


def key_material(strings, arrays, natives):
  """{key bytes: where it comes from}: each constant as it is and in its usual encodings"""
  keys = {}

  def add(k, where):
    if k and len(k) <= 256 and k not in keys and len(keys) < MAX_KEYS:
      keys[k] = where

  for arr, where in arrays.items():
    add(arr, where)
  for source in (strings, natives):
    for s, where in source.items():
      try:
        b = s.encode("utf-8")
      except UnicodeEncodeError:
        continue
      add(b, where)
      if re.fullmatch(r"[A-Za-z0-9+/_-]{11,}={0,2}", s):
        try:
          add(base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)), where + ", Base64-decoded")
        except (binascii.Error, ValueError):
          pass
      if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        add(bytes.fromhex(s), where + ", hex-decoded")
  for k, where in list(keys.items()):
    if len(k) >= 6:
      add(hashlib.md5(k).digest(), where + ", MD5 of it")
      add(hashlib.sha256(k).digest(), where + ", SHA-256 of it")
  return keys


def xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def xor_repeat(data, key):
  rep = (key * (len(data) // len(key) + 1))[:len(data)]
  return (int.from_bytes(data, "big") ^ int.from_bytes(rep, "big")).to_bytes(len(data), "big")


def header_ok(p):
  """the first 0x70 bytes look like the start of a dex or of a ZIP local file header"""
  if DEX_MAGIC.match(p) and len(p) >= 0x70:
    size, hsize, endian = struct.unpack_from("<III", p, 0x20)
    return hsize == 0x70 and endian == 0x12345678
  if p[:4] == b"PK\x03\x04" and len(p) >= 30:
    nlen, xlen = struct.unpack_from("<HH", p, 26)
    return 0 < nlen < 200 and xlen < 200 and all(0x20 <= c < 0x7f for c in p[30:30 + min(nlen, 40)])
  return False


def search(files, keys, deadline):
  """[(file index, layers after the cipher, cipher name, key, final kind, final bytes)]"""
  from Cryptodome.Cipher import AES, ARC4, DES, DES3
  results, done = [], set()

  def accept(i, name, key, plain, where):
    if i in done:
      return
    parts = code_parts(plain)
    if parts:
      done.add(i)
      results.extend((i, layers, name, key, kind, data, where) for kind, data, layers in parts)

  # without a key: one-byte XOR and ADD, and XOR keys given away by the expected header
  for i, (_src, data, layers) in enumerate(files):
    head = data[:8]
    if layers:
      accept(i, "no cipher", b"", data, "")
    for k in range(1, 256):
      if bytes([head[0] ^ k, head[1] ^ k]) in FIRST2:
        accept(i, "XOR with one byte", bytes([k]), data.translate(bytes(b ^ k for b in range(256))),
               "found by trying all 255")
      if bytes([(head[0] - k) & 255, (head[1] - k) & 255]) in FIRST2:
        accept(i, "each byte minus a constant", bytes([k]), data.translate(bytes((b - k) & 255 for b in range(256))),
               "found by trying all 255")
    for magic in (b"dex\n035\0", b"dex\n036\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0",
                  b"PK\x03\x04\x14\x00\x00\x00", b"PK\x03\x04\x14\x00\x08\x00", b"PK\x03\x04\x0a\x00\x00\x00",
                  b"PK\x03\x04\x14\x00\x08\x08"):
      ks = xor(head, magic)
      for n in range(2, 9):
        if all(ks[j] == ks[j % n] for j in range(8)):
          key = ks[:n]
          if header_ok(xor_repeat(data[:0x70], key)):
            accept(i, "XOR with a repeating key", key, xor_repeat(data, key),
                   "the expected file header (known plaintext)")
          break

  heads = [d[:32].ljust(32, b"\0") for _s, d, _l in files]
  buf = b"".join(heads)

  def block_cipher(name, mod, key, bs, make, where):
    try:
      out = make(mod.MODE_ECB).decrypt(buf)
    except ValueError:
      return
    for i in range(len(files)):
      if i in done:
        continue
      p0, p1, c0 = out[32 * i:32 * i + bs], out[32 * i + bs:32 * i + 2 * bs], heads[i][:bs]
      data = files[i][1]
      whole = len(data) - len(data) % bs
      if p0[:2] in FIRST2:  # ECB, or CBC with a zero IV: the first block is the same
        full = make(mod.MODE_ECB).decrypt(data[:whole])
        accept(i, name + "-ECB", key, unpad(full, bs), where)
        if i not in done:
          accept(i, name + "-CBC, zero IV", key, unpad(mod.new(key, mod.MODE_CBC, bytes(bs)).decrypt(data[:whole]), bs),
                 where)
      if xor(p0, key)[:2] in FIRST2 and len(key) >= bs:
        accept(i, name + "-CBC, IV = key", key, unpad(mod.new(key, mod.MODE_CBC, key[:bs]).decrypt(data[:whole]), bs),
               where)
      if xor(p1, c0)[:2] in FIRST2 and whole > bs:
        accept(i, name + "-CBC, IV = the file's first block", key,
               unpad(mod.new(key, mod.MODE_CBC, c0).decrypt(data[bs:whole]), bs), where)

  n = 0
  for key, where in keys.items():
    n += 1
    if n % 2000 == 0 and (time.time() > deadline or len(done) == len(files)):
      break
    ln = len(key)
    if ln >= 4:
      k8 = (key + bytes(8))[:8]
      block_cipher("DES", DES, k8, 8, lambda mode, k=k8: DES.new(k, mode),
                   where + (", its first 8 bytes" if ln > 8 else ", zero-padded to 8 bytes" if ln < 8 else ""))
    if ln in (16, 24, 32):
      block_cipher("AES-%d" % (ln * 8), AES, key, 16, lambda mode, k=key: AES.new(k, mode), where)
    elif ln > 16:
      k16 = key[:16]
      block_cipher("AES-128", AES, k16, 16, lambda mode, k=k16: AES.new(k, mode), where + ", its first 16 bytes")
    if ln in (16, 24):
      try:
        k3 = DES3.adjust_key_parity(key)
        block_cipher("3DES", DES3, k3, 8, lambda mode, k=k3: DES3.new(k, mode), where)
      except ValueError:
        pass
    if ln >= 5:
      ks = ARC4.new(key).encrypt(bytes(8))
      for i in range(len(files)):
        if i in done:
          continue
        h = heads[i]
        if bytes([h[0] ^ ks[0], h[1] ^ ks[1]]) in FIRST2:
          accept(i, "RC4", key, ARC4.new(key).decrypt(files[i][1]), where)
        if ln <= 64 and bytes([h[0] ^ key[0], h[1] ^ key[1]]) in FIRST2:
          data = files[i][1]
          if header_ok(xor_repeat(data[:0x70], key)):
            accept(i, "XOR with a repeating key", key, xor_repeat(data, key), where)
  return results, n


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  work = os.path.join(ROOT, "work", name)
  raw = os.path.join(work, "raw")
  out = os.path.join(work, "unlocked")
  listing = os.path.join(work, "unlocked.txt")
  shutil.rmtree(out, ignore_errors=True)
  files = candidate_files(raw) if os.path.isdir(raw) else []
  if not files:
    open(listing, "w").close()
    open(os.path.join(work, "encrypted-left.txt"), "w").close()
    print("payload-decrypt: no file that looks encrypted")
    return
  strings, arrays = dex.constants(raw, 4, 512)
  # keys that are themselves hidden strings: what stringfog.py decodes, and what the
  # decryption stage wrote for this sample
  decoded = {}
  try:
    import stringfog
    for t in stringfog.decode(work)[1].values():
      if 4 <= len(t) <= 512:
        decoded.setdefault(t, "string decoded by stringfog.py")
    if os.path.isdir(os.path.join(work, "jadx", "sources")):
      for _rel, _line, _callee, t in stringfog.table_strings(work)[1]:
        if 4 <= len(t) <= 512:
          decoded.setdefault(t, "string decoded by stringfog.py (number table)")
  except Exception as ex:  # a decoder problem must not stop the payload search
    print("payload-decrypt: decoded strings not used (%s)" % str(ex)[:100])
  for rel, col in (("decrypt/out/strings.txt", 1), ("decrypt/out/string-map.tsv", -1)):
    try:
      with open(os.path.join(work, rel), errors="replace") as f:
        for line in f:
          cols = line.rstrip("\n").split("\t")
          if len(cols) >= 2 and 4 <= len(cols[col]) <= 512:
            decoded.setdefault(cols[col], "string decrypted by the decryption stage (%s)" % rel)
    except OSError:
      pass
  for t, where in decoded.items():
    strings.setdefault(t, where)
  keys = key_material(strings, arrays, native_strings(raw))
  t0 = time.time()
  results, tried = search(files, keys, t0 + BUDGET)
  os.makedirs(out, exist_ok=True)
  rows = []
  results.sort(key=lambda r: (files[r[0]][0], r[1]))
  for k, (i, after, cipher, key, kind, data, where) in enumerate(results, 1):
    source, _d, before = files[i]
    ext = {"dex": "dex", "zip with dex": "apk", "zip without dex": "apk", "elf": "so"}[kind]
    member = after[-1][6:] if after and after[-1].startswith("unzip ") else source
    fname = "%d-%s.%s" % (k, re.sub(r"[^A-Za-z0-9._-]", "_", re.split(r"[/!]", member)[-1])[:60], ext)
    with open(os.path.join(out, fname), "wb") as f:
      f.write(data)
    text = key.decode("ascii") if key and all(0x20 <= b < 0x7f for b in key) else ""
    if kind == "dex":
      kind = "dex" if dex_checksum_ok(data) else "dex, checksum does not match"
    rows.append((fname, kind, str(len(data)), source, " > ".join(before + [cipher] + after), key.hex(), text, where,
                 hashlib.sha256(data).hexdigest()))
  with open(listing, "w") as f:
    for r in rows:
      f.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in r) + "\n")
  solved = {r[0] for r in results}
  with open(os.path.join(work, "encrypted-left.txt"), "w") as f:
    for i, (source, data, layers) in enumerate(files):
      if i not in solved:
        f.write("%s\t%d\t%.2f\t%s\n" % (source, len(data), entropy(data[:65536]), " > ".join(layers)))
  solved = len(solved)
  print("payload-decrypt: %d files that look encrypted, %d keys tried in %ds, %d decrypted (%d results)%s" % (
    len(files), tried, time.time() - t0, solved, len(rows),
    "" if solved == len(files) else " (stopped at the time limit)" if tried < len(keys)
    else " (key limit %d reached)" % MAX_KEYS if len(keys) >= MAX_KEYS else ""))
  for r in rows:
    print("  %s <- %s: %s, key %s" % (r[0], r[3], r[4], r[6] or r[5]))


if __name__ == "__main__":
  main()
