#!/usr/bin/env python3
"""List a sample archive and extract the APK inside it to work/_samples/.

Malware repositories hand out samples as password-protected ZIP files (password
"infected" by convention), with ZipCrypto or WinZip AES encryption. data/ is read-only
and is never changed, so the APK goes to work/_samples/<member name>, from where
unpack.sh takes it like any APK.

Nothing is executed. Only members that are ZIP archives themselves (an APK is one) are
extracted, at most MAX_MEMBERS of them, each limited to APK_TOTAL_MAX bytes (default
8 GiB as in apkunzip.py) and written without following links; names are reduced to
their base name and safe characters.

Usage: ./cupella sample-archive.py data/<file>.zip [--password <text>] [--list]
       --password  default "infected"
       --list      only list the members
Output: one line per member (name, size, encryption), and for each extracted APK
        "extracted work/_samples/<name>.apk  sha256 <hash>".
"""
import hashlib
import hmac
import os
import re
import struct
import sys
import zipfile
import zlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MAX_MEMBERS = 8
MAX_BYTES = int(os.environ.get("APK_TOTAL_MAX", 8 << 30))


def aes_extra(info):
  """(strength, real compression method) of a WinZip AES member, or None"""
  extra, p = info.extra, 0
  while p + 4 <= len(extra):
    tag, size = struct.unpack_from("<HH", extra, p)
    if tag == 0x9901 and size >= 7:
      _ver, _vendor, strength, method = struct.unpack_from("<H2sBH", extra, p + 4)
      return strength, method
    p += 4 + size
  return None


def read_aes(fh, info, password, strength, method):
  """the plaintext of a WinZip AES member (AE-1, AE-2): PBKDF2-HMAC-SHA1 with 1000
  rounds, AES in counter mode with a little-endian counter from 1, HMAC-SHA1 check"""
  from Cryptodome.Cipher import AES
  from Cryptodome.Util import Counter
  klen = {1: 16, 2: 24, 3: 32}.get(strength)
  if klen is None:
    raise ValueError("unknown AES strength %d" % strength)
  fh.seek(info.header_offset)
  head = fh.read(30)
  if head[:4] != b"PK\x03\x04":
    raise ValueError("no local header")
  nlen, xlen = struct.unpack_from("<HH", head, 26)
  fh.seek(info.header_offset + 30 + nlen + xlen)
  if info.compress_size > MAX_BYTES:
    raise ValueError("member larger than the size limit")
  blob = fh.read(info.compress_size)
  slen = klen // 2
  salt, check, data, mac = blob[:slen], blob[slen:slen + 2], blob[slen + 2:-10], blob[-10:]
  keys = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * klen + 2)
  if keys[2 * klen:] != check:
    raise ValueError("wrong password")
  if not hmac.compare_digest(hmac.new(keys[klen:2 * klen], data, hashlib.sha1).digest()[:10], mac):
    raise ValueError("authentication code does not match")
  plain = AES.new(keys[:klen], AES.MODE_CTR, counter=Counter.new(128, initial_value=1, little_endian=True)).decrypt(data)
  if method == 0:
    return plain
  if method == 8:
    d = zlib.decompressobj(-15)
    out = d.decompress(plain, MAX_BYTES + 1)
    if len(out) > MAX_BYTES or d.unconsumed_tail:
      raise ValueError("member larger than the size limit")
    return out
  raise ValueError("compression method %d not supported" % method)


def main():
  args = sys.argv[1:]
  password, only_list = b"infected", False
  if "--list" in args:
    only_list = True
    args.remove("--list")
  if "--password" in args:
    i = args.index("--password")
    password = args[i + 1].encode("utf-8")
    del args[i:i + 2]
  if len(args) != 1:
    sys.exit(__doc__)
  path = os.path.join(ROOT, args[0])
  if not os.path.isfile(path):
    sys.exit("no such file: %s" % args[0])
  try:
    z = zipfile.ZipFile(path)
  except zipfile.BadZipFile as ex:
    sys.exit("not a ZIP archive: %s" % ex)
  infos = [i for i in z.infolist() if not i.is_dir()]
  if any(i.filename == "AndroidManifest.xml" for i in infos):
    sys.exit("%s is an APK itself: run ./cupella unpack.sh on it (rename it to .apk in data/ first, the user's step)" % args[0])
  out_dir = os.path.join(ROOT, "work", "_samples")
  done = 0
  written = set()
  with open(path, "rb") as fh:
    for info in infos[:200]:
      aes = aes_extra(info)
      enc = "AES-%d" % (aes[0] * 64 + 64) if aes else "ZipCrypto" if info.flag_bits & 1 else "not encrypted"
      print("%s\t%d bytes\t%s" % (re.sub(r"[^\x20-\x7e]", "?", info.filename), info.file_size, enc))
      if only_list or done >= MAX_MEMBERS:
        continue
      try:
        if aes:
          data = read_aes(fh, info, password, *aes)
        else:
          if info.file_size > MAX_BYTES:
            raise ValueError("member larger than the size limit")
          data = z.read(info, pwd=password if info.flag_bits & 1 else None)
      except (ValueError, RuntimeError, zipfile.BadZipFile, zlib.error, NotImplementedError, struct.error, OSError) as ex:
        print("  not extracted: %s" % str(ex)[:120])
        continue
      if data[:4] != b"PK\x03\x04":
        print("  not extracted: not a ZIP archive (an APK is one)")
        continue
      base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(info.filename.replace("\\", "/"))) or "sample"
      if not base.lower().endswith(".apk"):
        base += ".apk"
      os.makedirs(out_dir, exist_ok=True)
      # two members with one base name (in different folders of the archive) stay apart
      stem, k = base[:-4], 1
      while base in written:
        k += 1
        base = "%s-%d.apk" % (stem, k)
      written.add(base)
      dest = os.path.join(out_dir, base)
      if os.path.islink(dest):
        os.unlink(dest)
      with open(dest, "wb") as f:
        f.write(data)
      done += 1
      print("  extracted work/_samples/%s  sha256 %s" % (base, hashlib.sha256(data).hexdigest()))
  if not only_list and not done:
    sys.exit("nothing extracted")


if __name__ == "__main__":
  main()
