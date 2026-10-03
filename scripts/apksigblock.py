#!/usr/bin/env python3
"""List the APK Signing Block entries (v2/v3/v3.1) and extract signer certificates.

Extraction only: no signature is verified. Use it to identify the signer of an APK
that has no v1 (JAR) signature, where keytool reports "Not a signed jar file".

Usage: scripts/apksigblock.py <apk> [out-dir]
Prints one line per scheme and certificate (SHA-256 of the DER). With out-dir, writes
each certificate as <out-dir>/cert-<scheme>-<n>.der for `keytool -printcert -file`.
"""
import hashlib
import os
import struct
import sys

MAGIC = b"APK Sig Block 42"
SCHEMES = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
OTHER_IDS = {0x42726577: "padding", 0x6DFF800D: "source-stamp-v2", 0x2146444E: "google-play-frosting",
             0x504B4453: "dependency-info", 0x2B09189E: "source-stamp-v1"}


def find_eocd(buf):
  """offset of the ZIP end-of-central-directory record, or -1. As Android does: the last
  "PK\\x05\\x06" whose comment length reaches exactly the end of the file, so the same bytes
  inside the ZIP comment cannot pose as the record."""
  lo = max(0, len(buf) - 22 - 0xFFFF)
  end = len(buf) - 22 + 4  # a candidate needs its 22 bytes
  while end - 4 >= lo:
    p = buf.rfind(b"PK\x05\x06", lo, end)
    if p < 0:
      return -1
    (clen,) = struct.unpack_from("<H", buf, p + 20)
    if p + 22 + clen == len(buf):
      return p
    end = p + 3  # keep searching backwards
  return -1


def block_bounds(buf, eocd):
  """(block start, central directory offset) of the APK Signing Block, or None. The
  size in the footer must fit before the central directory and match the header copy."""
  (cd_off,) = struct.unpack_from("<I", buf, eocd + 16)
  if cd_off < 32 or cd_off > eocd or buf[cd_off - 16:cd_off] != MAGIC:
    return None
  (size,) = struct.unpack_from("<Q", buf, cd_off - 24)
  start = cd_off - size - 8
  if size < 24 or start < 0 or struct.unpack_from("<Q", buf, start)[0] != size:
    return None
  return start, cd_off


def find_block(buf):
  eocd = find_eocd(buf)
  if eocd < 0:
    return None
  b = block_bounds(buf, eocd)
  return None if b is None else buf[b[0] + 8:b[1] - 24]


def lp_items(buf):
  """Split a sequence of uint32-length-prefixed items."""
  p, out = 0, []
  while p + 4 <= len(buf):
    (n,) = struct.unpack_from("<I", buf, p)
    out.append(buf[p + 4:p + 4 + n])
    p += 4 + n
  return out


def lp(buf, p):
  (n,) = struct.unpack_from("<I", buf, p)
  return buf[p + 4:p + 4 + n], p + 4 + n


def signer_certs(value):
  certs = []
  signers, _ = lp(value, 0)
  for signer in lp_items(signers):
    signed_data, _ = lp(signer, 0)
    _digests, p = lp(signed_data, 0)
    cert_seq, _ = lp(signed_data, p)
    certs.extend(lp_items(cert_seq))
  return certs


def main():
  apk = sys.argv[1]
  out = sys.argv[2] if len(sys.argv) > 2 else None
  with open(apk, "rb") as f:
    buf = f.read()
  block = find_block(buf)
  if block is None:
    print("no APK Signing Block (v1-only or unsigned)")
    return
  p = 0
  while p + 12 <= len(block):
    n, ident = struct.unpack_from("<QI", block, p)
    value = block[p + 12:p + 8 + n]
    p += 8 + n
    if ident in SCHEMES:
      scheme = SCHEMES[ident]
      try:
        certs = signer_certs(value)
      except struct.error:
        print("%s: present, could not parse signers" % scheme)
        continue
      print("%s: %d certificate(s)" % (scheme, len(certs)))
      for i, der in enumerate(certs):
        print("  cert %d sha256 %s (%d bytes)" % (i, hashlib.sha256(der).hexdigest(), len(der)))
        if out:
          os.makedirs(out, exist_ok=True)
          with open(os.path.join(out, "cert-%s-%d.der" % (scheme, i)), "wb") as f:
            f.write(der)
    else:
      print("other entry: id 0x%08x (%s), %d bytes" % (ident, OTHER_IDS.get(ident, "unknown"), n - 4))


if __name__ == "__main__":
  main()
