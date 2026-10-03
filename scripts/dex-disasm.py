#!/usr/bin/env python3
"""Disassemble chosen dex methods by following control flow, for methods that jadx and
baksmali cannot read.

Packers put malformed data (a fill-array-data payload with an impossible element width
or size, stray opcodes) in code that is never executed. Linear decoders such as jadx
and baksmali read it as instructions and give up on the whole method or class. This
decodes from the method's entry and its exception handlers along branches, switches,
and fall-through only, so unreachable bytes are reported as a range and never decoded.
Operands are resolved: strings, types, fields, methods. Array payloads are printed as
hex, since keys and encrypted strings often sit there.

Usage: ./cupella dex-disasm.py <name|work/.../file.dex> <Class[.method]> [--list]
  <name>      the dex files work/<name>/raw/classes*.dex; or one dex file under work/
  Class       dotted (a.b.Cls) or descriptor (La/b/Cls;); .method selects one method
              by name (all overloads)
  --list      list the classes and methods instead (Class optional, as a prefix)
Output: stdout.
"""
import glob
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dex as dexmod  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ARRAY_MAX = 4096  # bytes of an array payload printed

# opcode -> (mnemonic, format, operand kind for the index: s=string t=type f=field m=method c=call site h=method handle p=proto)
OPS = {}


def _ops(start, names, fmt, kind=""):
  for i, n in enumerate(names):
    OPS[start + i] = (n, fmt, kind)


_ops(0x00, ["nop"], "10x")
_ops(0x01, ["move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16",
            "move-object", "move-object/from16", "move-object/16"], "")
for op, f in zip(range(0x01, 0x0a), ["12x", "22x", "32x"] * 3):
  OPS[op] = (OPS[op][0], f, "")
_ops(0x0a, ["move-result", "move-result-wide", "move-result-object", "move-exception"], "11x")
_ops(0x0e, ["return-void"], "10x")
_ops(0x0f, ["return", "return-wide", "return-object"], "11x")
_ops(0x12, ["const/4"], "11n")
OPS[0x13] = ("const/16", "21s", "")
OPS[0x14] = ("const", "31i", "")
OPS[0x15] = ("const/high16", "21h", "")
OPS[0x16] = ("const-wide/16", "21s", "")
OPS[0x17] = ("const-wide/32", "31i", "")
OPS[0x18] = ("const-wide", "51l", "")
OPS[0x19] = ("const-wide/high16", "21h", "")
OPS[0x1a] = ("const-string", "21c", "s")
OPS[0x1b] = ("const-string/jumbo", "31c", "s")
OPS[0x1c] = ("const-class", "21c", "t")
_ops(0x1d, ["monitor-enter", "monitor-exit"], "11x")
OPS[0x1f] = ("check-cast", "21c", "t")
OPS[0x20] = ("instance-of", "22c", "t")
OPS[0x21] = ("array-length", "12x", "")
OPS[0x22] = ("new-instance", "21c", "t")
OPS[0x23] = ("new-array", "22c", "t")
OPS[0x24] = ("filled-new-array", "35c", "t")
OPS[0x25] = ("filled-new-array/range", "3rc", "t")
OPS[0x26] = ("fill-array-data", "31t", "")
OPS[0x27] = ("throw", "11x", "")
OPS[0x28] = ("goto", "10t", "")
OPS[0x29] = ("goto/16", "20t", "")
OPS[0x2a] = ("goto/32", "30t", "")
OPS[0x2b] = ("packed-switch", "31t", "")
OPS[0x2c] = ("sparse-switch", "31t", "")
_ops(0x2d, ["cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"], "23x")
_ops(0x32, ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"], "22t")
_ops(0x38, ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"], "21t")
_SUF = ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"]
_ops(0x44, ["aget" + s for s in _SUF] + ["aput" + s for s in _SUF], "23x")
_ops(0x52, ["iget" + s for s in _SUF] + ["iput" + s for s in _SUF], "22c", "f")
_ops(0x60, ["sget" + s for s in _SUF] + ["sput" + s for s in _SUF], "21c", "f")
_INV = ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"]
_ops(0x6e, _INV, "35c", "m")
_ops(0x74, [n + "/range" for n in _INV], "3rc", "m")
_ops(0x7b, ["neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long",
            "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double",
            "float-to-int", "float-to-long", "float-to-double", "double-to-int", "double-to-long",
            "double-to-float", "int-to-byte", "int-to-char", "int-to-short"], "12x")
_BIN = ["add-%s", "sub-%s", "mul-%s", "div-%s", "rem-%s", "and-%s", "or-%s", "xor-%s", "shl-%s", "shr-%s", "ushr-%s"]
_BINOPS = [b % "int" for b in _BIN] + [b % "long" for b in _BIN] + [b % "float" for b in _BIN[:5]] + [b % "double" for b in _BIN[:5]]
_ops(0x90, _BINOPS, "23x")
_ops(0xb0, [b + "/2addr" for b in _BINOPS], "12x")
_ops(0xd0, ["add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16",
            "or-int/lit16", "xor-int/lit16"], "22s")
_ops(0xd8, ["add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8",
            "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8"], "22b")
OPS[0xfa] = ("invoke-polymorphic", "45cc", "m")
OPS[0xfb] = ("invoke-polymorphic/range", "4rcc", "m")
OPS[0xfc] = ("invoke-custom", "35c", "c")
OPS[0xfd] = ("invoke-custom/range", "3rc", "c")
OPS[0xfe] = ("const-method-handle", "21c", "h")
OPS[0xff] = ("const-method-type", "21c", "p")

WIDTH = {"10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1, "20t": 2, "22x": 2, "21t": 2, "21s": 2, "21h": 2,
         "21c": 2, "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2, "30t": 3, "32x": 3, "31i": 3, "31t": 3,
         "31c": 3, "35c": 3, "3rc": 3, "45cc": 4, "4rcc": 4, "51l": 5}
STOP = {0x0e, 0x0f, 0x10, 0x11, 0x27}  # return*, throw
GOTO = {0x28, 0x29, 0x2a}


def s16(v):
  return v - 0x10000 if v & 0x8000 else v


def s32(v):
  return v - 0x100000000 if v & 0x80000000 else v


def sleb(buf, p):
  r = s = 0
  while True:
    b = buf[p]
    p += 1
    r |= (b & 0x7F) << s
    s += 7
    if not b & 0x80:
      if b & 0x40:
        r -= 1 << s
      return r, p


class Code:
  def __init__(self, d, off):
    b = d.buf
    self.d = d
    self.regs, self.ins, _outs, self.tries, _dbg, self.n = struct.unpack_from("<HHHHII", b, off)
    self.base = off + 16
    self.handlers = []  # (start, end, [(type or None, addr)])
    if self.tries:
      t = self.base + 2 * self.n + (2 if self.n % 2 else 0)
      hl = t + 8 * self.tries
      for k in range(self.tries):
        start, cnt, hoff = struct.unpack_from("<IHH", b, t + 8 * k)
        p = hl + hoff
        size, p = sleb(b, p)
        hs = []
        for _ in range(abs(size)):
          ti, p = dexmod.uleb(b, p)
          addr, p = dexmod.uleb(b, p)
          hs.append((d.type(ti), addr))
        if size <= 0:
          addr, p = dexmod.uleb(b, p)
          hs.append((None, addr))
        self.handlers.append((start, start + cnt, hs))

  def u(self, pc):
    return struct.unpack_from("<H", self.d.buf, self.base + 2 * pc)[0]

  def index(self, kind, i):
    d = self.d
    try:
      if kind == "s":
        return repr(d.string(i))
      if kind == "t":
        return d.type(i)
      if kind == "f":
        return d.field(i)
      if kind == "m":
        return d.method(i)[4]
      return "%s@%d" % ({"c": "call_site", "h": "method_handle", "p": "proto"}[kind], i)
    except (struct.error, IndexError, ValueError):
      return "<bad index %d>" % i

  def insn(self, pc):
    """(text, width, successors, payload_pc) or None when the bytes are not an instruction"""
    unit = self.u(pc)
    op = unit & 0xFF
    if op not in OPS or (op == 0 and unit != 0):
      return None
    name, fmt, kind = OPS[op]
    w = WIDTH[fmt]
    if pc + w > self.n:
      return None
    a8, a4, b4 = unit >> 8, (unit >> 8) & 0xF, unit >> 12
    u1 = self.u(pc + 1) if w > 1 else 0
    u2 = self.u(pc + 2) if w > 2 else 0
    target = payload = None
    if fmt == "10x":
      ops = ""
    elif fmt == "12x":
      ops = "v%d, v%d" % (a4, b4)
    elif fmt == "11n":
      ops = "v%d, %d" % (a4, b4 - 16 if b4 & 8 else b4)
    elif fmt == "11x":
      ops = "v%d" % a8
    elif fmt == "10t":
      target = pc + (a8 - 256 if a8 & 0x80 else a8)
    elif fmt == "20t":
      target = pc + s16(u1)
    elif fmt == "30t":
      target = pc + s32(u1 | u2 << 16)
    elif fmt == "22x":
      ops = "v%d, v%d" % (a8, u1)
    elif fmt == "32x":
      ops = "v%d, v%d" % (u1, u2)
    elif fmt == "21t":
      target = pc + s16(u1)
      ops = "v%d" % a8
    elif fmt == "21s":
      ops = "v%d, %d" % (a8, s16(u1))
    elif fmt == "21h":
      ops = "v%d, 0x%x" % (a8, u1 << (48 if op == 0x19 else 16))
    elif fmt == "21c":
      ops = "v%d, %s" % (a8, self.index(kind, u1))
    elif fmt == "31c":
      ops = "v%d, %s" % (a8, self.index(kind, u1 | u2 << 16))
    elif fmt == "23x":
      ops = "v%d, v%d, v%d" % (a8, u1 & 0xFF, u1 >> 8)
    elif fmt == "22b":
      c = u1 >> 8
      ops = "v%d, v%d, %d" % (a8, u1 & 0xFF, c - 256 if c & 0x80 else c)
    elif fmt == "22t":
      target = pc + s16(u1)
      ops = "v%d, v%d" % (a4, b4)
    elif fmt == "22s":
      ops = "v%d, v%d, %d" % (a4, b4, s16(u1))
    elif fmt == "22c":
      ops = "v%d, v%d, %s" % (a4, b4, self.index(kind, u1))
    elif fmt == "31i":
      v = s32(u1 | u2 << 16)
      ops = "v%d, %d (0x%x)" % (a8, v, v & 0xFFFFFFFF)
    elif fmt == "31t":
      payload = pc + s32(u1 | u2 << 16)
      ops = "v%d" % a8
    elif fmt in ("35c", "45cc"):
      regs = [u2 & 0xF, (u2 >> 4) & 0xF, (u2 >> 8) & 0xF, u2 >> 12, a4][:b4]
      ops = "{%s}, %s" % (", ".join("v%d" % r for r in regs), self.index(kind, u1))
      if fmt == "45cc":
        ops += ", proto@%d" % self.u(pc + 3)
    elif fmt in ("3rc", "4rcc"):
      ops = "{v%d .. v%d}, %s" % (u2, u2 + a8 - 1, self.index(kind, u1)) if a8 else "{}, %s" % self.index(kind, u1)
    elif fmt == "51l":
      v = struct.unpack_from("<q", self.d.buf, self.base + 2 * pc + 2)[0]
      ops = "v%d, %d (0x%x)" % (a8, v, v & 0xFFFFFFFFFFFFFFFF)
    if target is not None:
      ops = (ops + ", " if fmt in ("21t", "22t") else "") + "L%04x" % target
    if payload is not None:
      ops += ", P%04x" % payload
    if op in STOP:
      succ = []
    elif op in GOTO:
      succ = [target]
    else:
      succ = [pc + w] + ([target] if target is not None else [])
    return "%-24s %s" % (name, ops), w, succ, payload

  def payload(self, pc, op):
    """(lines, width, extra successors) of the payload at pc for opcode op, or None"""
    if not 0 <= pc < self.n:
      return None
    ident = self.u(pc)
    b, at = self.d.buf, self.base + 2 * pc
    try:
      if op == 0x26 and ident == 0x0300:
        width, size = struct.unpack_from("<HI", b, at + 2)
        nbytes = width * size
        w = (nbytes + 1) // 2 + 4
        if width not in (1, 2, 4, 8) or pc + w > self.n:
          return ["array-data: element width %d, %d elements: malformed" % (width, size)], 4, []
        data = b[at + 8:at + 8 + min(nbytes, ARRAY_MAX)]
        out = ["array-data: element width %d, %d elements (%d bytes)" % (width, size, nbytes)]
        for k in range(0, len(data), 32):
          out.append("  " + data[k:k + 32].hex())
        if nbytes > ARRAY_MAX:
          out.append("  ... %d more bytes" % (nbytes - ARRAY_MAX))
        return out, w, []
      if op == 0x2b and ident == 0x0100:
        size, first = struct.unpack_from("<Hi", b, at + 2)
        tg = [struct.unpack_from("<i", b, at + 8 + 4 * k)[0] for k in range(size)]
        return ["packed-switch: %d -> %s" % (first + k, "L%04x" % t) for k, t in enumerate(tg)], size * 2 + 4, tg
      if op == 0x2c and ident == 0x0200:
        (size,) = struct.unpack_from("<H", b, at + 2)
        keys = [struct.unpack_from("<i", b, at + 4 + 4 * k)[0] for k in range(size)]
        tg = [struct.unpack_from("<i", b, at + 4 + 4 * size + 4 * k)[0] for k in range(size)]
        return ["sparse-switch: %d -> L%04x" % (k, t) for k, t in zip(keys, tg)], size * 4 + 2, tg
    except struct.error:
      pass
    return None


def disasm(d, cls, name, params, ret, off):
  c = Code(d, off)
  print("\n.method %s.%s(%s)%s  registers %d, ins %d, code units %d" % (cls, name, "".join(params), ret, c.regs, c.ins, c.n))
  for start, end, hs in c.handlers:
    print("  try %04x-%04x: %s" % (start, end, ", ".join("%s -> L%04x" % (t or "catch-all", a) for t, a in hs)))
  seen, data, labels, bad = {}, {}, set(), set()
  work = [0] + [a for _, _, hs in c.handlers for _, a in hs]
  labels.update(work[1:])
  while work:
    pc = work.pop()
    while 0 <= pc < c.n and pc not in seen and pc not in data:
      r = c.insn(pc)
      if r is None:
        bad.add(pc)
        break
      text, w, succ, ppc = r
      op = c.u(pc) & 0xFF
      if ppc is not None:
        pl = c.payload(ppc, op)
        if pl:
          lines, pw, tg = pl
          data[ppc] = (lines, pw)
          for t in tg:
            labels.add(pc + t)
            work.append(pc + t)
          if op != 0x26:
            text += "  ; " + ", ".join(l.split(": ", 1)[1] for l in lines[:12]) + (" ..." if len(lines) > 12 else "")
        else:
          text += "  ; payload unreadable"
      seen[pc] = (text, w)
      for s in succ[1:] if op not in GOTO else succ:
        labels.add(s)
      for s in succ[1:]:
        work.append(s)
      if op in STOP:
        break
      pc = succ[0] if op in GOTO else pc + w
  covered = set()
  for pc, (_, w) in seen.items():
    covered.update(range(pc, pc + w))
  for pc, (_, w) in data.items():
    covered.update(range(pc, pc + w))
  pc = 0
  while pc < c.n:
    if pc in seen:
      if pc in labels:
        print("L%04x:" % pc)
      text, w = seen[pc]
      print("  %04x  %s" % (pc, text))
      pc += w
    elif pc in data:
      lines, w = data[pc]
      print("P%04x:" % pc)
      for l in lines:
        print("        " + l)
      pc += w
    else:
      end = pc
      while end < c.n and end not in covered:
        end += 1
      print("  %04x  ; %d code units not reached from the entry or a handler (never executed; not decoded)%s" % (
        pc, end - pc, "; jumps into it were undecodable" if any(pc <= x < end for x in bad) else ""))
      pc = end


def main():
  args = [a for a in sys.argv[1:] if not a.startswith("--")]
  listing = "--list" in sys.argv
  if not args or (not listing and len(args) < 2):
    sys.exit(__doc__)
  src = args[0]
  if src.endswith(".dex"):
    paths = [os.path.join(ROOT, src)]
  else:
    paths = sorted(glob.glob(os.path.join(ROOT, "work", src, "raw", "classes*.dex")))
  if not paths:
    sys.exit("no dex files for %s" % src)
  query = args[1] if len(args) > 1 else ""
  dexes = [(path, dexmod.Dex(open(path, "rb").read())) for path in paths]
  names = {cls for _, d in dexes for cls, _, _, _ in d.classes()}
  want, mname = query, None
  if "->" in query:
    want, mname = query.split("->", 1)
  elif query and not query.startswith("L"):
    # a.b.Cls or a.b.Cls.method: the longest prefix that is a class wins
    want = "L" + query.replace(".", "/") + ";"
    if want not in names and "." in query and not listing:
      head, mname = query.rsplit(".", 1)
      want = "L" + head.replace(".", "/") + ";"
  found = False
  for path, d in dexes:
    for cls, data, _sup, _ifs in d.classes():
      if listing:
        if cls.startswith(want.rstrip(";")):
          print(cls, "(%s)" % os.path.relpath(path, ROOT))
          for idx, off in d.methods_of(data):
            c, n, p, r, _ = d.method(idx)
            print("  %s(%s)%s%s" % (n, "".join(p), r, "" if off else "  [no code]"))
        continue
      if cls != want:
        continue
      found = True
      print("# %s in %s" % (cls, os.path.relpath(path, ROOT)))
      for idx, off in d.methods_of(data):
        c, n, p, r, _ = d.method(idx)
        if mname and n != mname:
          continue
        if not off:
          print("\n.method %s.%s(%s)%s  [no code]" % (c, n, "".join(p), r))
          continue
        try:
          disasm(d, c, n, p, r, off)
        except (struct.error, IndexError) as e:
          print("  ; decoding stopped: %s" % e)
  if not listing and not found:
    sys.exit("class %s not found" % want)


if __name__ == "__main__":
  main()
