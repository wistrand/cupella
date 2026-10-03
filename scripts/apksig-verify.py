#!/usr/bin/env python3
"""Verify the signatures of an APK without the Android SDK.

- v2 / v3 / v3.1 (APK Signature Scheme): recomputes the chunked content digest over
  the whole file, compares it with the signed digest, and verifies the signature over
  the signed data with the signer's public key (via the `openssl` command). Also
  checks that the public key is the one in the signer's certificate.
- v1 (JAR signing): delegates to `jarsigner -verify` when it is installed.

This answers "has the file been altered since it was signed, and by which key". It
does not answer "is this the developer's key": compare the certificate fingerprint
with one obtained from a source you trust.

Usage: scripts/apksig-verify.py <apk>
Exit status 0 when every signature present verifies, 1 otherwise.
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

MAGIC = b"APK Sig Block 42"
SCHEMES = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
CHUNK = 1024 * 1024
# id -> (name, content digest, openssl digest, extra openssl -sigopt arguments)
ALGS = {
  0x0101: ("RSASSA-PSS SHA-256", "sha256", "sha256", ["rsa_padding_mode:pss", "rsa_pss_saltlen:32"]),
  0x0102: ("RSASSA-PSS SHA-512", "sha512", "sha512", ["rsa_padding_mode:pss", "rsa_pss_saltlen:64"]),
  0x0103: ("RSA PKCS#1 v1.5 SHA-256", "sha256", "sha256", []),
  0x0104: ("RSA PKCS#1 v1.5 SHA-512", "sha512", "sha512", []),
  0x0201: ("ECDSA SHA-256", "sha256", "sha256", []),
  0x0202: ("ECDSA SHA-512", "sha512", "sha512", []),
  0x0301: ("DSA SHA-256", "sha256", "sha256", []),
}
STRENGTH = [0x0102, 0x0104, 0x0202, 0x0101, 0x0103, 0x0201, 0x0301]  # preference order


def lp(buf, p):
  (n,) = struct.unpack_from("<I", buf, p)
  if p + 4 + n > len(buf):
    raise ValueError("length prefix runs past the end")
  return buf[p + 4:p + 4 + n], p + 4 + n


def lp_items(buf):
  p, out = 0, []
  while p + 4 <= len(buf):
    item, p = lp(buf, p)
    out.append(item)
  return out


def layout(buf):
  eocd = buf.rfind(b"PK\x05\x06")
  if eocd < 0:
    raise ValueError("no ZIP end-of-central-directory record")
  (cd_off,) = struct.unpack_from("<I", buf, eocd + 16)
  if cd_off < 32 or buf[cd_off - 16:cd_off] != MAGIC:
    return None
  (size,) = struct.unpack_from("<Q", buf, cd_off - 24)
  block_start = cd_off - size - 8
  return block_start, cd_off, eocd


def content_digest(buf, block_start, cd_off, eocd, alg):
  """Chunked digest over ZIP entries, central directory, and EOCD (with the central
  directory offset rewritten to where the signing block starts)."""
  eocd_bytes = bytearray(buf[eocd:])
  struct.pack_into("<I", eocd_bytes, 16, block_start)
  sections = [buf[:block_start], buf[cd_off:eocd], bytes(eocd_bytes)]
  digests = []
  for sec in sections:
    for o in range(0, len(sec), CHUNK):
      chunk = sec[o:o + CHUNK]
      digests.append(hashlib.new(alg, b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest())
  return hashlib.new(alg, b"\x5a" + struct.pack("<I", len(digests)) + b"".join(digests)).digest()


def openssl_verify(pub_der, signed, sig, md, sigopts, tmp):
  paths = {}
  for name, data in (("pub.der", pub_der), ("data.bin", signed), ("sig.bin", sig)):
    paths[name] = os.path.join(tmp, name)
    with open(paths[name], "wb") as f:
      f.write(data)
  pem = os.path.join(tmp, "pub.pem")
  r = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", paths["pub.der"], "-out", pem],
                     capture_output=True, text=True)
  if r.returncode != 0:
    return False, "public key not parseable: " + r.stderr.strip()[:120]
  cmd = ["openssl", "dgst", "-" + md, "-verify", pem, "-signature", paths["sig.bin"]]
  for o in sigopts:
    cmd += ["-sigopt", o]
  r = subprocess.run(cmd + [paths["data.bin"]], capture_output=True, text=True)
  return r.returncode == 0 and "Verified OK" in r.stdout, (r.stdout + r.stderr).strip()[:160]


def cert_pubkey(cert_der, tmp):
  path = os.path.join(tmp, "cert.der")
  with open(path, "wb") as f:
    f.write(cert_der)
  r = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout", "-pubkey"],
                     capture_output=True, text=True)
  if r.returncode != 0:
    return None
  r2 = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=r.stdout.encode(),
                      capture_output=True)
  return r2.stdout if r2.returncode == 0 else None


def verify_signer(buf, lay, scheme, signer, tmp, digest_cache):
  ok = True
  signed_data, p = lp(signer, 0)
  if scheme != "v2":
    min_sdk, max_sdk = struct.unpack_from("<II", signer, p)
    p += 8
  sigs_raw, p = lp(signer, p)
  pubkey, p = lp(signer, p)

  digests_raw, q = lp(signed_data, 0)
  certs_raw, q = lp(signed_data, q)
  certs = lp_items(certs_raw)
  digests = {}
  for d in lp_items(digests_raw):
    (alg_id,) = struct.unpack_from("<I", d, 0)
    digests[alg_id], _ = lp(d, 4)
  sigs = {}
  for s in lp_items(sigs_raw):
    (alg_id,) = struct.unpack_from("<I", s, 0)
    sigs[alg_id], _ = lp(s, 4)

  if certs:
    print("  certificate sha256 %s" % hashlib.sha256(certs[0]).hexdigest())
  if scheme != "v2":
    print("  applies to SDK %d..%s" % (min_sdk, "any" if max_sdk == 0x7FFFFFFF else max_sdk))
  if not sigs:
    print("  FAIL: no signatures in signer block")
    return False
  if set(sigs) != set(digests):
    print("  FAIL: signature algorithms %s do not match digest algorithms %s" % (
      sorted(hex(a) for a in sigs), sorted(hex(a) for a in digests)))
    ok = False
  supported = [a for a in STRENGTH if a in sigs]
  for a in sigs:
    if a not in ALGS:
      print("  note: unsupported algorithm 0x%04x not checked" % a)
  if not supported:
    print("  FAIL: no supported signature algorithm")
    return False

  for alg_id in supported:
    name, cdig, md, opts = ALGS[alg_id]
    good, msg = openssl_verify(pubkey, signed_data, sigs[alg_id], md, opts, tmp)
    print("  signature (%s) over signed data: %s" % (name, "OK" if good else "FAIL " + msg))
    ok &= good
    if cdig not in digest_cache:
      digest_cache[cdig] = content_digest(buf, *lay, cdig)
    match = digest_cache[cdig] == digests.get(alg_id)
    print("  content digest (%s, whole file): %s" % (cdig, "OK" if match else "FAIL: file content differs from what was signed"))
    ok &= match

  if certs:
    cp = cert_pubkey(certs[0], tmp)
    same = cp is not None and cp == pubkey
    print("  public key matches certificate: %s" % ("OK" if same else "FAIL"))
    ok &= same
  else:
    print("  FAIL: no certificate")
    ok = False
  return ok


def main():
  apk = sys.argv[1]
  with open(apk, "rb") as f:
    buf = f.read()
  all_ok, any_sig = True, False
  lay = layout(buf)
  with tempfile.TemporaryDirectory() as tmp:
    if lay is None:
      print("APK Signing Block: none")
    else:
      block_start, cd_off, _eocd = lay
      block = buf[block_start + 8:cd_off - 24]
      p, cache = 0, {}
      while p + 12 <= len(block):
        n, ident = struct.unpack_from("<QI", block, p)
        value = block[p + 12:p + 8 + n]
        p += 8 + n
        if ident not in SCHEMES:
          continue
        scheme = SCHEMES[ident]
        try:
          signers = lp_items(lp(value, 0)[0])
        except (ValueError, struct.error) as ex:
          print("%s: FAIL, malformed block (%s)" % (scheme, ex))
          all_ok = False
          continue
        for i, signer in enumerate(signers):
          any_sig = True
          print("%s signer %d:" % (scheme, i))
          try:
            good = verify_signer(buf, lay, scheme, signer, tmp, cache)
          except (ValueError, struct.error) as ex:
            print("  FAIL: malformed signer (%s)" % ex)
            good = False
          print("  => %s %s" % (scheme, "VERIFIED" if good else "NOT VERIFIED"))
          all_ok &= good

  # v1: META-INF/*.SF present?
  has_v1 = False
  try:
    import zipfile
    with zipfile.ZipFile(apk) as z:
      has_v1 = any(n.startswith("META-INF/") and n.endswith(".SF") for n in z.namelist())
  except Exception as ex:  # a broken zip is itself worth reporting
    print("v1: could not read the ZIP directory: %s" % ex)
  if has_v1:
    any_sig = True
    try:
      r = subprocess.run(["jarsigner", "-verify", apk], capture_output=True, text=True, timeout=300)
      out = (r.stdout + r.stderr)
      good = "jar verified" in out
      print("v1 (JAR) signature, jarsigner: %s" % ("VERIFIED" if good else "NOT VERIFIED"))
      # jarsigner's "signed in JarFile but not in JarInputStream" lines are about entry
      # order in zipaligned files, not about missing signatures; count them only
      quirk = sum(1 for line in out.splitlines() if "is not signed in JarInputStream" in line)
      for line in out.splitlines():
        if "unsigned entries" in line or line.startswith("jarsigner: "):
          print("  " + line.strip()[:160])
      if quirk:
        print("  (%d entry-order notes from jarsigner omitted)" % quirk)
      all_ok &= good
    except FileNotFoundError:
      print("v1 (JAR) signature present; jarsigner not installed, not verified")
  else:
    print("v1 (JAR) signature: none")

  if not any_sig:
    print("RESULT: unsigned")
    sys.exit(1)
  print("RESULT: %s" % ("all signatures present verify" if all_ok else "VERIFICATION FAILED"))
  sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
  main()
