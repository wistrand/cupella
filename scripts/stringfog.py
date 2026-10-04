#!/usr/bin/env python3
"""Decode strings hidden by calls with constant arguments (StringFog and similar).

Many apps, malware in particular, replace each string literal with a call such as
decode("aj5A\\n", "B00nCJSjg9M=\\n") or d("801465EF...") to a static method that returns
the string. This finds such methods in the bytecode (static, one or two String
arguments, String result, called from MIN_CALLS or more places with constant arguments),
tries the common schemes on their arguments, and keeps a scheme only when nearly all
results are readable text:

  two arguments, one of them the key
    b64-xor            Base64-decode both, XOR the data with the key repeated (StringFog default)
    xor                XOR the characters of the first with the second, repeated
    hex|b64 > DES|AES|RC4   the ciphertext hex- or Base64-encoded, the other argument
                       the key (DES: its first 8 bytes; short keys zero-padded), ECB
  one argument, or a key that is not at the call
    b64, hex           only encoded
    hex|b64 > DES|AES|RC4   with the key found by trying the dex constants (strings and
                       byte arrays), kept only when the results read like names and
                       messages (XOR is not searched: a wrong key gives printable noise)
  any of the cipher schemes may be followed by a Base64 decode of the plaintext
  number tables (read from the jadx sources)
    decode(table, offset, length, key)   a per-class short[] constant; each character
                       is a table value XOR, minus, or plus the key (the "protected by
                       np" obfuscator and its relatives)

Nothing from the app is executed: each scheme is reimplemented here and checked by the
plausibility of its output. A method no scheme decodes is listed for the decryption
stage (agent). Results: work/<name>/string-map.tsv (the format annotate-strings.py
reads) and, through annotate-strings.py, work/<name>/jadx-strings/.

Usage: ./cupella stringfog.py <name>
Output: stdout (summary lines for scan.txt)
"""
import base64
import binascii
import glob
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dex  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MIN_CALLS = 20
ACCEPT = 0.9
SIG = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
SIG1 = "(Ljava/lang/String;)Ljava/lang/String;"
SEARCH_MAX = 6      # decoders whose key is searched among the constants, most called first
SEARCH_BUDGET = 120  # seconds for all key searches
HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")
B64 = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")


def readable(t):
  if not t:
    return True
  good = sum(1 for c in t if c.isprintable() or c in "\n\t\r")
  return good >= 0.9 * len(t)


def b64(s):
  return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4), validate=False)


def unhex(s):
  s = s.strip()
  if not HEX.match(s):
    raise ValueError("not hex")
  return bytes.fromhex(s)


def unb64(s):
  s = s.strip().replace("\n", "").replace("-", "+").replace("_", "/")
  if not B64.match(s) or len(s.rstrip("=")) % 4 == 1:
    raise ValueError("not Base64")
  return base64.b64decode(s + "=" * (-len(s) % 4))


ENCODINGS = (("hex", unhex), ("b64", unb64))


def scheme_b64_xor(s, k):
  d, key = b64(s), b64(k)
  if not key:
    raise ValueError("empty key")
  return bytes(c ^ key[i % len(key)] for i, c in enumerate(d)).decode("utf-8")


def scheme_xor(s, k):
  if not k:
    raise ValueError("empty key")
  return "".join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(s))


def dec_des(data, key):
  from Cryptodome.Cipher import DES
  if not data or len(data) % 8:
    raise ValueError("not DES blocks")
  return DES.new((key + bytes(8))[:8], DES.MODE_ECB).decrypt(data)


def dec_aes(data, key):
  from Cryptodome.Cipher import AES
  if not data or len(data) % 16:
    raise ValueError("not AES blocks")
  return AES.new(key if len(key) in (16, 24, 32) else (key + bytes(16))[:16], AES.MODE_ECB).decrypt(data)


def dec_rc4(data, key):
  from Cryptodome.Cipher import ARC4
  if not 1 <= len(key) <= 256:
    raise ValueError("no RC4 key")
  return ARC4.new(key).decrypt(data)


def dec_xor(data, key):
  if not key:
    raise ValueError("empty key")
  return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


CIPHERS = (("DES", dec_des, 8), ("AES", dec_aes, 16), ("RC4", dec_rc4, 0), ("XOR", dec_xor, 0))


def text_of(raw, block):
  """plaintext bytes as text: PKCS padding or zero padding removed for a block cipher"""
  if block and raw:
    n = raw[-1]
    raw = raw[:-n] if 0 < n <= block and raw.endswith(bytes([n]) * n) else raw.rstrip(b"\0")
  return raw.decode("utf-8")


def then_b64(fn):
  def g(args):
    return unb64(fn(args)).decode("utf-8")
  return g


def call_schemes():
  """[(name, fn(args) -> text)] for two-argument decoders whose key is at the call"""
  out = [("b64-xor", lambda a: scheme_b64_xor(a[0], a[1])), ("xor", lambda a: scheme_xor(a[0], a[1]))]
  for ct, key, order in ((0, 1, ""), (1, 0, ", key first")):
    for ename, enc in ENCODINGS:
      for cname, dec, bs in CIPHERS[:3]:
        fn = lambda a, enc=enc, dec=dec, bs=bs, ct=ct, key=key: text_of(dec(enc(a[ct]), a[key].encode("utf-8")), bs)
        out.append(("%s > %s > Base64%s" % (ename, cname, order), then_b64(fn)))
        out.append(("%s > %s%s" % (ename, cname, order), fn))
  return out


def looks_encoded(uniq, pos):
  """nearly all values of argument pos look like ciphertext: hex, or Base64 that is not
  a plain word (it has a digit, +, /, or = and is 12 or more characters long)"""
  n = 0
  for args in uniq:
    v = args[pos].strip()
    if HEX.match(v) and len(v) >= 16:
      n += 1
    elif len(v) >= 12 and B64.match(v.replace("\n", "")) and re.search(r"[0-9+/=]", v):
      n += 1
  return n >= ACCEPT * len(uniq)


def try_scheme(uniq, fn):
  out = {}
  for args in uniq:
    try:
      t = fn(args)
    except (ValueError, UnicodeDecodeError, binascii.Error):
      continue
    if readable(t):
      out[args] = t
  return out


def wordlike(texts):
  """the texts read like names, paths, and messages: mostly letters, digits, spaces, and
  the punctuation of identifiers and URLs. Printable is not enough when the key was
  searched: a wrong XOR-like key often gives printable noise."""
  total = sum(len(t) for t in texts)
  good = sum(1 for t in texts for c in t if c.isalnum() or c in " ._/:-")
  return total > 0 and good >= 0.85 * total


def textlike(chunk, single):
  """the first plaintext bytes of a string: printable ASCII; in a one-block ciphertext
  they may be followed by padding"""
  if single and chunk:
    n = chunk[-1]
    if 0 < n < len(chunk) and chunk.endswith(bytes([n]) * n):
      chunk = chunk[:-n]
    else:
      chunk = chunk.rstrip(b"\0")
  return bool(chunk) and all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in chunk)


def search_key(uniq, pos, keys, deadline):
  """(scheme name, key, {args: text}) for the decoder whose ciphertext is argument pos,
  with the key found among the constants, or None"""
  for ename, enc in ENCODINGS:
    datas = set()
    for args in uniq:
      try:
        datas.add(enc(args[pos]))
      except (ValueError, binascii.Error):
        pass
    if len(datas) < ACCEPT * len(uniq) or sum(map(len, datas)) < 8 * len(datas):
      continue
    sample = sorted(datas, key=lambda x: (-len(x), x))[:6]
    for cname, dec, bs in CIPHERS[:3]:  # not XOR: any key gives some output, most of it printable
      if bs and any(len(x) % bs for x in sample):
        continue
      width = bs or 8
      heads = [x[:width] for x in sample]
      single = [bool(bs) and len(x) == bs for x in sample]
      buf, tried = b"".join(heads), set()
      for n, (key, _where) in enumerate(keys.items()):
        if n % 5000 == 0 and time.time() > deadline:
          return None
        eff = (key + bytes(8))[:8] if cname == "DES" else key
        if eff in tried:
          continue
        tried.add(eff)
        try:
          if bs:
            plain = dec(buf, key)
            chunks = [plain[i * bs:(i + 1) * bs] for i in range(len(heads))]
          else:
            chunks = [dec(h, key) for h in heads]
        except ValueError:
          continue
        if not all(textlike(c, one) for c, one in zip(chunks, single)):
          continue
        fn = lambda a, enc=enc, dec=dec, bs=bs, key=key: text_of(dec(enc(a[pos]), key), bs)
        for name, f in (("%s > %s > Base64" % (ename, cname), then_b64(fn)), ("%s > %s" % (ename, cname), fn)):
          out = try_scheme(uniq, f)
          if len(out) >= ACCEPT * len(uniq) and wordlike(out.values()):
            return name, key, out
  return None


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
  """{method_key: [(arg1, arg2) or (arg1,), ...]} for static (String,String)String and
  (String)String calls with constant args.
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
          if op == 0x71 and unit >> 12 in (1, 2):  # invoke-static with one or two arguments
            midx, rr = struct.unpack_from("<HH", buf, base + 2 * pc + 2)
            key = d.method(midx)[4]
            a, b = rr & 0xF, (rr >> 4) & 0xF
            if unit >> 12 == 2 and key.endswith(SIG):
              if a in regs and b in regs:
                out.setdefault(key, []).append((regs[a], regs[b]))
            elif unit >> 12 == 1 and key.endswith(SIG1):
              if a in regs:
                out.setdefault(key, []).append((regs[a],))
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


def decode(work):
  """(summary lines, {args: plaintext}) for the sample in directory work"""
  raw = os.path.join(work, "raw")
  sites, concat = {}, set()
  for p in sorted(glob.glob(os.path.join(raw, "classes*.dex"))):
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
  lines, rows = [], {}
  if not cands:
    lines.append("(no decoder-like methods: no static (String)String or (String,String)String method with %d+ "
                 "constant-argument calls)" % MIN_CALLS)
    return lines, rows
  skipped = sorted(k for k in cands if k in concat)
  if skipped:
    lines.append("(skipped, body only concatenates its arguments: %s)" % ", ".join(skipped))
  cands = {k: v for k, v in cands.items() if k not in concat}
  schemes = call_schemes()
  open_ = []
  for key, pairs in sorted(cands.items(), key=lambda kv: -len(kv[1])):
    uniq = sorted(set(pairs))
    best = None
    if len(uniq[0]) == 2:
      for sname, fn in schemes:
        out = try_scheme(uniq, fn)
        if len(out) >= ACCEPT * len(uniq) and (best is None or len(out) > len(best[1])):
          best = (sname + ", key at the call", out)
    else:
      for sname, enc in ENCODINGS:
        out = try_scheme(uniq, lambda a, enc=enc: enc(a[0]).decode("utf-8"))
        if len(out) >= ACCEPT * len(uniq) and (best is None or len(out) > len(best[1])):
          best = (sname, out)
    if best:
      rows.update(best[1])
      lines.append("- %s: %d calls, %d distinct, scheme %s decoded %d" % (key, len(pairs), len(uniq), best[0], len(best[1])))
    elif len(uniq[0]) == 2 or looks_encoded(uniq, 0):
      # a one-argument method called with plain words is an ordinary helper, not a decoder
      open_.append((key, pairs, uniq))
  # decoders whose key is not at the call: try the dex constants as keys
  keys, deadline = None, time.time() + SEARCH_BUDGET
  for n, (key, pairs, uniq) in enumerate(open_):
    found = None
    if n < SEARCH_MAX and time.time() < deadline:
      if keys is None:
        strings, arrays = dex.constants(raw, 1, 64)
        keys = dict((a, w) for a, w in arrays.items())
        for st, w in strings.items():
          try:
            keys.setdefault(st.encode("utf-8"), w)
          except UnicodeEncodeError:
            pass
      for pos in range(len(uniq[0])):
        found = search_key(uniq, pos, keys, deadline)
        if found:
          break
    if found:
      sname, k, out = found
      rows.update(out)
      shown = '"%s"' % k.decode("ascii") if all(0x20 <= b < 0x7f for b in k) else "0x" + k.hex()
      lines.append("- %s: %d calls, %d distinct, scheme %s decoded %d, key %s (%s)" % (
        key, len(pairs), len(uniq), sname, len(out), shown, keys[k]))
    else:
      lines.append("- %s: %d calls, no scheme gives readable text: a lead for the decryption stage" % (key, len(pairs)))
  return lines, rows


TABLE = re.compile(r"\b(short|char|int|byte)\[\]\s+([\w$]+)\s*=\s*\{([^{}]*)\}\s*;")
TABLE_CALL = re.compile(r"\b([\w$]+(?:\.[\w$]+)*)\(\s*([\w$]+)\s*,\s*([-\w.$]+)\s*,\s*([-\w.$]+)\s*,\s*([-\w.$]+)\s*\)")
TABLE_OPS = (("xor", lambda v, k: v ^ k), ("minus", lambda v, k: v - k), ("plus", lambda v, k: v + k))
# the two argument layouts seen: (offset, length, key) and (start, end, key)
TABLE_SLICES = (("offset, length", lambda a, b: (a, b)), ("start, end", lambda a, b: (a, b - a)))


def table_strings(work):
  """Strings kept as slices of a number table, each character the table value XOR (or
  plus, or minus) the key. Two call shapes: decode(table, offset, length, key) with a
  per-class short[] (or char[], int[]) constant, and NAME(start, end, key) where a
  private method and its table share the name NAME. Read from the jadx sources, where the table is a literal and
  the call's numbers are literals or names of library constants (jadx substitutes those;
  they are looked up). Returns (summary lines, [(file, line, callee, text)]) and writes
  annotated copies to jadx-strings/ and the list to string-tables.tsv."""
  src = os.path.join(work, "jadx", "sources")
  out = os.path.join(work, "jadx-strings")
  # copies this function wrote in an earlier run are replaced; other files in jadx-strings/
  # (annotate-strings.py, the decryption stage, a fixture) are never removed here
  listing = os.path.join(out, "TABLES.txt")
  if os.path.isfile(listing):
    with open(listing, encoding="utf-8") as fh:
      for rel in fh.read().split("\n"):
        q = os.path.normpath(os.path.join(out, rel))
        if rel and q.startswith(out + os.sep) and q.endswith(".java") and os.path.isfile(q):
          os.remove(q)
    os.remove(listing)
  by_base, texts = {}, {}
  for dp, _dn, fn in os.walk(src):
    for f in fn:
      if f.endswith(".java"):
        by_base.setdefault(f[:-5], []).append(os.path.join(dp, f))

  def text_of_file(path):
    if path not in texts:
      with open(path, encoding="utf-8", errors="replace") as fh:
        texts[path] = fh.read()
    return texts[path]

  consts = {}

  def number(expr):
    """the int value of a literal or of a named constant (Outer.Inner.NAME), else None"""
    if re.fullmatch(r"-?\d+", expr):
      return int(expr)
    if re.fullmatch(r"-?0x[0-9a-fA-F]+", expr):
      return int(expr, 16)
    if expr not in consts:
      parts, vals = expr.split("."), set()
      for path in by_base.get(parts[0], ()) if len(parts) >= 2 else ():
        t, pos = text_of_file(path), 0
        for nested in parts[1:-1]:
          m = re.compile(r"\b(?:class|interface|enum)\s+%s\b" % re.escape(nested)).search(t, pos)
          pos = m.end() if m else len(t)
        m = re.compile(r"\b(?:int|short|char|byte|long)\s+%s\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*;"
                       % re.escape(parts[-1])).search(t, pos)
        if m:
          vals.add(int(m.group(1), 0))
      consts[expr] = vals.pop() if len(vals) == 1 else None
    return consts[expr]

  found = []  # (path, table values, match span and numbers)
  for paths in by_base.values():
    for path in paths:
      with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read()
      if "[] " not in head or " = {" not in head:
        continue
      tables = {}
      for m in TABLE.finditer(head):
        try:
          tables[m.group(2)] = [int(x, 0) for x in m.group(3).replace("\n", " ").split(",") if x.strip()]
        except ValueError:
          pass
      if not tables:
        continue
      texts[path] = head
      for m in TABLE_CALL.finditer(head):
        if m.group(2) in tables:
          nums = [number(m.group(i)) for i in (3, 4, 5)]
          found.append((path, tables[m.group(2)], m, nums, 0))
      # NAME(start, end, key): a method named like its table
      own = [t for t in tables if re.search(r"\bString\s+%s\s*\(\s*int\b" % re.escape(t), head)]
      if own:
        pat = re.compile(r"(?<![\w$.])(%s)\(\s*([-\w.$]+)\s*,\s*([-\w.$]+)\s*,\s*([-\w.$]+)\s*\)"
                         % "|".join(re.escape(t) for t in own))
        for m in pat.finditer(head):
          if re.match(r"int\b", m.group(2)):
            continue  # the method's own declaration
          nums = [number(m.group(i)) for i in (2, 3, 4)]
          found.append((path, tables[m.group(1)], m, nums, 1))
  if not found:
    return [], []

  def decode_with(op, table, nums, cut):
    if None in nums:
      return None
    off, ln = cut(nums[0], nums[1])
    key = nums[2]
    if off < 0 or ln < 0 or off + ln > len(table) or ln > 4096:
      return None
    try:
      # UTF-16 code units: pairs of surrogates (emoji) become one character
      units = b"".join(((op(table[off + i], key)) & 0xFFFF).to_bytes(2, "little") for i in range(ln))
      return units.decode("utf-16-le", "replace")
    except (ValueError, OverflowError):
      return None

  # one operation and one argument layout per call shape (the two shapes can be in one
  # app, with different layouts): the pair whose results read like text most often;
  # empty results do not count
  outs, notes = [None] * len(found), []
  for shape in (0, 1):
    idx = [i for i, f in enumerate(found) if f[4] == shape]
    if not idx:
      continue
    best = None
    for oname, op in TABLE_OPS:
      for cname, cut in TABLE_SLICES:
        res = [decode_with(op, found[i][1], found[i][3], cut) for i in idx]
        n = sum(1 for t in res if t and all(0x20 <= ord(c) < 0x7f or c in "\n\t\r" for c in t))
        if best is None or n > best[2]:
          best = ("%s; arguments %s, key" % (oname, cname), res, n)
    # most strings are ASCII; an app with much non-ASCII text still passes at 0.8
    if best[2] >= 0.8 * sum(1 for i in idx if None not in found[i][3]):
      for i, t in zip(idx, best[1]):
        outs[i] = t
      notes.append(best[0])
  oname = " / ".join(notes)
  if not notes:
    return ["- number-table decoders: %d calls, no operation gives readable text: a lead for the decryption "
            "stage" % len(found)], []
  rows, per_file = [], {}
  for (path, _table, m, nums, _shape), t in zip(found, outs):
    if t is not None:
      rel = os.path.relpath(path, src)
      line = texts[path].count("\n", 0, m.start()) + 1
      rows.append((rel, line, m.group(1), t))
      per_file.setdefault(path, []).append((m.end(), t))
  annotated = set()
  if os.path.isfile(os.path.join(out, "INDEX.txt")):
    with open(os.path.join(out, "INDEX.txt"), encoding="utf-8", errors="replace") as fh:
      annotated = {l.split(None, 1)[1].strip() for l in fh if re.match(r"\s*\d+\s+\S", l)}
  written = []
  for path, marks in per_file.items():
    rel = os.path.relpath(path, src)
    dest = os.path.join(out, rel)
    # a copy annotate-strings.py made holds other plaintexts already: it would shift the
    # positions, so the two kinds of annotation are not combined in one file. Any other
    # file there is a copy of an earlier run of this function and is rewritten.
    if rel in annotated:
      continue
    text, parts, last = texts[path], [], 0
    for end, t in sorted(marks):
      shown = t.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r").replace("*/", "*\\/")
      parts.append(text[last:end] + ' /* = "%s" */' % shown[:200])
      last = end
    parts.append(text[last:])
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
      fh.write("".join(parts))
    written.append(rel)
  if written:
    with open(listing, "w", encoding="utf-8") as fh:
      fh.write("\n".join(sorted(written)) + "\n")
  with open(os.path.join(work, "string-tables.tsv"), "w", encoding="utf-8") as fh:
    for rel, line, callee, t in sorted(rows):
      fh.write("%s:%d\t%s\t%s\n" % (rel, line, callee, tsv(t)))
  unresolved = sum(1 for t in outs if t is None)
  lines = ["- number-table decoders (each character is a table value %s): "
           "%d calls in %d files decoded%s; list in string-tables.tsv" % (
             oname, len(rows), len(per_file),
             ", %d not (a number that is not a literal or a known constant)" % unresolved if unresolved else "")]
  return lines, rows


def main():
  if len(sys.argv) != 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  work = os.path.join(ROOT, "work", name)
  lines, rows = decode(work)
  print("\n## Encrypted strings decoded by script (stringfog.py; plaintext in jadx-strings/)")
  print("\n".join(lines))
  if rows:
    mp = os.path.join(work, "string-map.tsv")
    with open(mp, "w") as f:
      for args, t in sorted(rows.items()):
        f.write("%s\t%s\n" % ("\t".join(tsv(a) for a in args), tsv(t)))
    import subprocess
    maps = []
    m = re.match(r"(.+)\.(?:dec|emb)\d+$", name)  # the decryption stage's map of the parent comes first
    if m and os.path.isfile(os.path.join(ROOT, "work", m.group(1), "decrypt", "out", "string-map.tsv")):
      maps.append(os.path.join("work", m.group(1), "decrypt", "out", "string-map.tsv"))
    maps.append(os.path.relpath(mp, ROOT))
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "annotate-strings.py"), name] + maps,
                       capture_output=True, text=True)
    print((r.stdout or r.stderr).strip())
  tlines, _trows = table_strings(work)
  if tlines:
    print("\n".join(tlines))


if __name__ == "__main__":
  main()
