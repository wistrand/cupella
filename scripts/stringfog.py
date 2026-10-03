#!/usr/bin/env python3
"""Decode strings hidden by calls with constant arguments (StringFog and similar).

Many apps, malware in particular, replace each string literal with a call such as
decode("aj5A\\n", "B00nCJSjg9M=\\n") to a static (String, String) -> String method. This
finds such methods in the bytecode (called from MIN_CALLS or more places with two
const-string arguments), tries the common schemes on their arguments, and keeps a scheme
only when nearly all results are readable text:

  b64-xor   Base64-decode both, XOR the data with the key repeated (StringFog default)
  xor       XOR the characters of the first with the second, repeated

Nothing from the app is executed: the scheme is reimplemented here and checked by the
plausibility of its output. A method no scheme decodes is listed for the decryption
stage (agent). Results: work/<name>/string-map.tsv (the format annotate-strings.py
reads) and, through annotate-strings.py, work/<name>/jadx-strings/.

Usage: ./cupella stringfog.py <name>
Output: stdout (summary lines for scan.txt)
"""
import base64
import glob
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dex  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MIN_CALLS = 20
ACCEPT = 0.9
SIG = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"


def readable(t):
  if not t:
    return True
  good = sum(1 for c in t if c.isprintable() or c in "\n\t\r")
  return good >= 0.9 * len(t)


def b64(s):
  return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4), validate=False)


def scheme_b64_xor(s, k):
  d, key = b64(s), b64(k)
  if not key:
    raise ValueError("empty key")
  return bytes(c ^ key[i % len(key)] for i, c in enumerate(d)).decode("utf-8")


def scheme_xor(s, k):
  if not k:
    raise ValueError("empty key")
  return "".join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(s))


SCHEMES = [("b64-xor", scheme_b64_xor), ("xor", scheme_xor)]


# opcodes whose destination is a register pair (vA, vA+1)
WIDE_DST = ({0x04, 0x05, 0x06, 0x0b, 0x16, 0x17, 0x18, 0x19, 0x45, 0x53, 0x61, 0x7d, 0x80, 0x81, 0x83,
             0x86, 0x88, 0x89, 0x8b} | set(range(0x9b, 0xa6)) | set(range(0xab, 0xb0))
            | set(range(0xbb, 0xc6)) | set(range(0xcb, 0xd0)))
# after these the next instruction is reached only by a branch
ENDS = {0x0e, 0x0f, 0x10, 0x11, 0x27, 0x28, 0x29, 0x2a}


def written(op, unit, buf, at):
  """registers an instruction writes, by its Dalvik format (check-cast keeps the value)"""
  if op in (0x01, 0x04, 0x07, 0x12, 0x20, 0x21, 0x23) or 0x52 <= op <= 0x58 or 0x7b <= op <= 0x8f \
      or 0xb0 <= op <= 0xd7:
    a = (unit >> 8) & 0xF  # vA, 4 bits
  elif op in (0x02, 0x05, 0x08, 0x22, 0xfe, 0xff) or 0x0a <= op <= 0x0d or 0x13 <= op <= 0x1c \
      or 0x2d <= op <= 0x31 or 0x44 <= op <= 0x4a or 0x60 <= op <= 0x66 or 0x90 <= op <= 0xaf \
      or 0xd8 <= op <= 0xe2:
    a = unit >> 8  # vAA
  elif op in (0x03, 0x06, 0x09):
    a = struct.unpack_from("<H", buf, at + 2)[0]  # vAAAA
  else:
    return ()
  return (a, a + 1) if op in WIDE_DST else (a,)


def insns(buf, base, n):
  """(pc, unit, opcode) of each instruction, skipping switch and array payloads"""
  pc = 0
  while pc < n:
    unit = struct.unpack_from("<H", buf, base + 2 * pc)[0]
    op = unit & 0xFF
    if op == 0 and unit in (0x0100, 0x0200, 0x0300):
      if unit == 0x0100:
        pc += struct.unpack_from("<H", buf, base + 2 * pc + 2)[0] * 2 + 4
      elif unit == 0x0200:
        pc += struct.unpack_from("<H", buf, base + 2 * pc + 2)[0] * 4 + 2
      else:
        w, sz = struct.unpack_from("<HI", buf, base + 2 * pc + 2)
        pc += (sz * w + 1) // 2 + 4
      continue
    yield pc, unit, op
    pc += dex.WIDTH[op]


def branch_targets(buf, base, n):
  """pcs that goto, if-*, and switch instructions jump to"""
  out = set()
  try:
    for pc, unit, op in insns(buf, base, n):
      try:
        out |= _targets(buf, base, pc, unit, op)
      except struct.error:
        pass  # a branch or payload past the end
  except struct.error:
    pass  # truncated code: the targets found so far
  return out


def _targets(buf, base, pc, unit, op):
  at = base + 2 * pc
  if op == 0x28:
    return {pc + ((unit >> 8) ^ 0x80) - 0x80}
  if op == 0x29 or 0x32 <= op <= 0x3d:
    return {pc + struct.unpack_from("<h", buf, at + 2)[0]}
  if op == 0x2a:
    return {pc + struct.unpack_from("<i", buf, at + 2)[0]}
  if op in (0x2b, 0x2c):
    ppc = pc + struct.unpack_from("<i", buf, at + 2)[0]
    if ppc < 0:
      return set()
    pp = base + 2 * ppc
    ident, size = struct.unpack_from("<HH", buf, pp)
    if ident == 0x0100:
      return {pc + t for t in struct.unpack_from("<%di" % size, buf, pp + 8)}
    if ident == 0x0200:
      return {pc + t for t in struct.unpack_from("<%di" % size, buf, pp + 4 + 4 * size)}
  return set()


CONCAT_CALLS = ("Ljava/lang/StringBuilder;->", "Ljava/lang/String;->concat(", "Ljava/lang/String;->valueOf(")


def plain_concat(d, buf, base, n):
  """True when a method body only joins its arguments (R8-outlined `return a + b`):
  StringBuilder or String.concat calls, moves, and a return, nothing else"""
  for pc, unit, op in insns(buf, base, n):
    if op in (0x00, 0x07, 0x08, 0x0c, 0x11) or op == 0x22:  # nop, move-object, move-result-object, return-object, new-instance
      continue
    if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:  # invoke-*, invoke-*/range
      key = d.method(struct.unpack_from("<H", buf, base + 2 * pc + 2)[0])[4]
      if key.startswith(CONCAT_CALLS):
        continue
    return False
  return True


def calls(d, buf, concat):
  """{method_key: [(arg1, arg2), ...]} for static (String,String)String calls with constant args.
  A register keeps its const-string value until any instruction writes it; every value is
  dropped at branch targets, at move-exception, and after goto/return/throw, where it may
  come from another path. Keys of (String,String)String methods that only concatenate
  their arguments are added to `concat`."""
  out = {}
  for _cls, data, _s, _i in d.classes():
    for idx, code in d.methods_of(data):
      if not code:
        continue
      try:
        (n,) = struct.unpack_from("<I", buf, code + 12)
        base, regs = code + 16, {}
        mkey = d.method(idx)[4]
        if mkey.endswith(SIG) and plain_concat(d, buf, base, n):
          concat.add(mkey)
        targets = branch_targets(buf, base, n)
        for pc, unit, op in insns(buf, base, n):
          if pc in targets or op == 0x0d:  # join point or move-exception (handler entry)
            regs.clear()
          if op == 0x71 and unit >> 12 == 2:  # invoke-static with two arguments
            midx, rr = struct.unpack_from("<HH", buf, base + 2 * pc + 2)
            key = d.method(midx)[4]
            if key.endswith(SIG):
              a, b = rr & 0xF, (rr >> 4) & 0xF
              if a in regs and b in regs:
                out.setdefault(key, []).append((regs[a], regs[b]))
          for r in written(op, unit, buf, base + 2 * pc):
            regs.pop(r, None)
          if op == 0x1a:
            regs[unit >> 8] = d.string(struct.unpack_from("<H", buf, base + 2 * pc + 2)[0])
          elif op == 0x1b:
            regs[unit >> 8] = d.string(struct.unpack_from("<I", buf, base + 2 * pc + 2)[0])
          if op in ENDS:
            regs.clear()
      except (struct.error, IndexError, ValueError):
        continue
  return out


def tsv(t):
  return t.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  work = os.path.join(ROOT, "work", name)
  sites, concat = {}, set()
  for p in sorted(glob.glob(os.path.join(work, "raw", "classes*.dex"))):
    buf = open(p, "rb").read()
    try:
      d = dex.Dex(buf)
      if buf[:4] != b"dex\n":
        continue
      for k, v in calls(d, buf, concat).items():
        sites.setdefault(k, []).extend(v)
    except (struct.error, IndexError, ValueError):
      continue
  cands = {k: v for k, v in sites.items() if len(v) >= MIN_CALLS}
  print("\n## Encrypted strings decoded by script (stringfog.py; plaintext in jadx-strings/)")
  skipped = sorted(k for k in cands if k in concat)
  if skipped:
    print("(skipped, body only concatenates its arguments: %s)" % ", ".join(skipped))
  cands = {k: v for k, v in cands.items() if k not in concat}
  if not cands:
    print("(no decoder-like methods: no static (String,String)String method with %d+ constant-argument calls)" % MIN_CALLS)
    return
  rows, undecoded = {}, []
  for key, pairs in sorted(cands.items(), key=lambda kv: -len(kv[1])):
    uniq = sorted(set(pairs))
    best = None
    for sname, fn in SCHEMES:
      out, ok = {}, 0
      for s, k in uniq:
        try:
          t = fn(s, k)
        except (ValueError, UnicodeDecodeError):
          continue
        if readable(t):
          ok += 1
          out[(s, k)] = t
      if ok >= ACCEPT * len(uniq) and (best is None or ok > best[1]):
        best = (sname, ok, out)
    if best:
      rows.update(best[2])
      print("- %s: %d calls, %d distinct, scheme %s decoded %d" % (key, len(pairs), len(uniq), best[0], best[1]))
    else:
      undecoded.append(key)
      print("- %s: %d calls, no scheme gives readable text: a lead for the decryption stage" % (key, len(pairs)))
  if rows:
    mp = os.path.join(work, "string-map.tsv")
    with open(mp, "w") as f:
      for (s, k), t in sorted(rows.items()):
        f.write("%s\t%s\t%s\n" % (tsv(s), tsv(k), tsv(t)))
    import re
    import subprocess
    maps = []
    m = re.match(r"(.+)\.(?:dec|emb)\d+$", name)  # the decryption stage's map of the parent comes first
    if m and os.path.isfile(os.path.join(ROOT, "work", m.group(1), "decrypt", "out", "string-map.tsv")):
      maps.append(os.path.join("work", m.group(1), "decrypt", "out", "string-map.tsv"))
    maps.append(os.path.relpath(mp, ROOT))
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "annotate-strings.py"), name] + maps,
                       capture_output=True, text=True)
    print((r.stdout or r.stderr).strip())


if __name__ == "__main__":
  main()
