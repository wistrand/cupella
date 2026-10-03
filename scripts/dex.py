"""Read methods, their calls, and their string constants from dex bytecode.

A library module (standard library only), used by units.py for an exact Java call
graph: jadx output is text in which calls can only be guessed by name. Reads the
dex files under work/<name>/raw/ directly; decodes instructions only for classes
the caller asks for.

  load(paths, want)   want(class_descriptor) -> bool selects classes to decode.
                      Returns ({method_key: Method}, {class: (superclass, [interfaces])});
                      method_key is "Lpkg/Cls;->name(params)ret", as are the keys
                      in Method.invokes.
  Method fields: cls, name, params (list of type descriptors), ret, code (has a body;
  False for abstract and interface methods), dex and code_off (where the body is, for
  decoders such as flows.py), invokes (list of
  method keys, in order), strings (const-string values), news (types of new-instance,
  and classes whose static object field is read, which covers Kotlin's singleton
  lambdas and objects), new_consts ((class, [ints]) for the constant arguments of a
  constructor call: one of them is the case number of an R8-merged lambda class), cases ({case value: [method
  keys invoked in that case]} for the method's first switch, which in an R8-merged
  lambda class selects the lambda)

Instruction widths follow the Dalvik bytecode format table; switch and array
payloads are skipped by their own size headers. Odex-only opcodes are not handled.
"""
import struct

# width in 16-bit code units, by opcode
WIDTH = [1] * 256
for op, w in [(0x02, 2), (0x03, 3), (0x05, 2), (0x06, 3), (0x08, 2), (0x09, 3), (0x13, 2), (0x14, 3),
              (0x15, 2), (0x16, 2), (0x17, 3), (0x18, 5), (0x19, 2), (0x1a, 2), (0x1b, 3), (0x1c, 2),
              (0x1f, 2), (0x20, 2), (0x22, 2), (0x23, 2), (0x24, 3), (0x25, 3), (0x26, 3), (0x29, 2),
              (0x2a, 3), (0x2b, 3), (0x2c, 3), (0xfa, 4), (0xfb, 4), (0xfc, 3), (0xfd, 3), (0xfe, 2),
              (0xff, 2)]:
  WIDTH[op] = w
for lo, hi, w in [(0x2d, 0x31, 2), (0x32, 0x3d, 2), (0x44, 0x6d, 2), (0x6e, 0x72, 3), (0x74, 0x78, 3),
                  (0x90, 0xaf, 2), (0xd0, 0xe2, 2)]:
  for op in range(lo, hi + 1):
    WIDTH[op] = w
INVOKE = set(range(0x6e, 0x73)) | set(range(0x74, 0x79)) | {0xfa, 0xfb}


class Method:
  __slots__ = ("cls", "name", "params", "ret", "code", "invokes", "strings", "news", "dex", "code_off",
               "new_consts", "cases")

  def __init__(self, cls, name, params, ret):
    self.cls, self.name, self.params, self.ret, self.code = cls, name, params, ret, False
    self.dex, self.code_off = None, 0  # for decoders that need the instructions again
    self.invokes, self.strings, self.news = [], [], []
    self.new_consts, self.cases = [], {}


def uleb(buf, p):
  r = s = 0
  while True:
    b = buf[p]
    p += 1
    r |= (b & 0x7F) << s
    s += 7
    if not b & 0x80:
      return r, p


class Dex:
  def __init__(self, buf):
    self.buf = buf
    u = struct.unpack_from
    self.s_n, self.s_off = u("<II", buf, 0x38)
    self.t_n, self.t_off = u("<II", buf, 0x40)
    self.p_n, self.p_off = u("<II", buf, 0x48)
    self.f_n, self.f_off = u("<II", buf, 0x50)
    self.m_n, self.m_off = u("<II", buf, 0x58)
    self.c_n, self.c_off = u("<II", buf, 0x60)
    self._str, self._mkey = {}, {}

  def string(self, i):
    if i not in self._str:
      (p,) = struct.unpack_from("<I", self.buf, self.s_off + 4 * i)
      _, p = uleb(self.buf, p)
      end = self.buf.index(b"\0", p)
      self._str[i] = self.buf[p:end].decode("utf-8", "replace")  # MUTF-8, close enough
    return self._str[i]

  def type(self, i):
    return self.string(struct.unpack_from("<I", self.buf, self.t_off + 4 * i)[0])

  def proto(self, i):
    _shorty, ret, poff = struct.unpack_from("<III", self.buf, self.p_off + 12 * i)
    params = []
    if poff:
      (n,) = struct.unpack_from("<I", self.buf, poff)
      params = [self.type(struct.unpack_from("<H", self.buf, poff + 4 + 2 * k)[0]) for k in range(n)]
    return params, self.type(ret)

  def field(self, i):
    """field key, as Lpkg/Cls;->name:type"""
    c, t, n = struct.unpack_from("<HHI", self.buf, self.f_off + 8 * i)
    return "%s->%s:%s" % (self.type(c), self.string(n), self.type(t))

  def method(self, i):
    """(cls, name, params, ret, key)"""
    if i not in self._mkey:
      c, p, n = struct.unpack_from("<HHI", self.buf, self.m_off + 8 * i)
      params, ret = self.proto(p)
      cls, name = self.type(c), self.string(n)
      self._mkey[i] = (cls, name, params, ret, "%s->%s(%s)%s" % (cls, name, "".join(params), ret))
    return self._mkey[i]

  def classes(self):
    for k in range(self.c_n):
      cidx, _acc, sup, ifs, _src, _ann, data, _sv = struct.unpack_from("<8I", self.buf, self.c_off + 32 * k)
      yield self.type(cidx), data, sup, ifs

  def supers(self, sup, ifs):
    s = self.type(sup) if sup != 0xFFFFFFFF else None
    out = []
    if ifs:
      (n,) = struct.unpack_from("<I", self.buf, ifs)
      out = [self.type(struct.unpack_from("<H", self.buf, ifs + 4 + 2 * k)[0]) for k in range(n)]
    return s, out

  def methods_of(self, data):
    """(method_idx, code_off) of the methods in a class_data_item"""
    if not data:
      return
    b = self.buf
    sf, p = uleb(b, data)
    inf, p = uleb(b, p)
    dm, p = uleb(b, p)
    vm, p = uleb(b, p)
    for _ in range(sf + inf):
      _, p = uleb(b, p)
      _, p = uleb(b, p)
    for count in (dm, vm):
      idx = 0
      for _ in range(count):
        d, p = uleb(b, p)
        _, p = uleb(b, p)
        code, p = uleb(b, p)
        idx += d
        yield idx, code

  def decode(self, code, m):
    b = self.buf
    (n,) = struct.unpack_from("<I", b, code + 12)
    base = code + 16
    pc = 0
    consts = {}      # register -> int literal last loaded into it (straight-line approximation)
    invoke_at = {}   # pc -> invoked method key, for the case bodies below
    switch = None    # (pc, payload pc) of the first packed or sparse switch
    while pc < n:
      unit = struct.unpack_from("<H", b, base + 2 * pc)[0]
      op = unit & 0xFF
      if op == 0 and unit != 0:
        if unit == 0x0100:    # packed-switch payload
          size = struct.unpack_from("<H", b, base + 2 * pc + 2)[0]
          pc += size * 2 + 4
        elif unit == 0x0200:  # sparse-switch payload
          size = struct.unpack_from("<H", b, base + 2 * pc + 2)[0]
          pc += size * 4 + 2
        elif unit == 0x0300:  # fill-array-data payload
          width, size = struct.unpack_from("<HI", b, base + 2 * pc + 2)
          pc += (size * width + 1) // 2 + 4
        else:
          pc += 1
        continue
      if op in INVOKE:
        key = self.method(struct.unpack_from("<H", b, base + 2 * pc + 2)[0])[4]
        m.invokes.append(key)
        invoke_at[pc] = key
        if key.split("->", 1)[1].startswith("<init>("):
          # the constructor's argument registers (the first is the new object itself)
          if op == 0x70:
            argc = unit >> 12
            regs = struct.unpack_from("<H", b, base + 2 * pc + 4)[0]
            args = [regs & 0xF, (regs >> 4) & 0xF, (regs >> 8) & 0xF, (regs >> 12) & 0xF, (unit >> 8) & 0xF][1:argc]
          elif op == 0x76:
            first = struct.unpack_from("<H", b, base + 2 * pc + 4)[0]
            args = list(range(first + 1, first + (unit >> 8)))
          else:
            args = []
          vals = [consts[r] for r in args if r in consts]
          if vals:
            m.new_consts.append((key.split("->", 1)[0], vals))
      elif op == 0x12:  # const/4 vA, #+B
        lit = unit >> 12
        consts[(unit >> 8) & 0xF] = lit - 16 if lit & 8 else lit
      elif op == 0x13:  # const/16 vAA, #+BBBB
        consts[unit >> 8] = struct.unpack_from("<h", b, base + 2 * pc + 2)[0]
      elif op == 0x14:  # const vAA, #+BBBBBBBB
        consts[unit >> 8] = struct.unpack_from("<i", b, base + 2 * pc + 2)[0]
      elif op in (0x2b, 0x2c) and switch is None:
        switch = (pc, pc + struct.unpack_from("<i", b, base + 2 * pc + 2)[0])
      elif op == 0x1a:
        m.strings.append(self.string(struct.unpack_from("<H", b, base + 2 * pc + 2)[0]))
      elif op == 0x1b:
        m.strings.append(self.string(struct.unpack_from("<I", b, base + 2 * pc + 2)[0]))
      elif op == 0x22:
        m.news.append(self.type(struct.unpack_from("<H", b, base + 2 * pc + 2)[0]))
      elif op == 0x62:  # sget-object: the field's class
        fidx = struct.unpack_from("<H", b, base + 2 * pc + 2)[0]
        m.news.append(self.type(struct.unpack_from("<H", b, self.f_off + 8 * fidx)[0]))
      pc += WIDTH[op]
    if switch:
      m.cases = self._cases(b, base, n, switch, invoke_at)

  def _cases(self, b, base, n, switch, invoke_at):
    """{case value: [invoked method keys]} for one switch: each case body is read from its
    target until a return, throw, or goto (R8's merged lambdas are one call and a return)"""
    spc, ppc = switch
    if not 0 <= ppc < n:
      return {}
    ident, size = struct.unpack_from("<HH", b, base + 2 * ppc)
    if ident == 0x0100:
      first = struct.unpack_from("<i", b, base + 2 * ppc + 4)[0]
      keys = [first + i for i in range(size)]
      targets = struct.unpack_from("<%di" % size, b, base + 2 * ppc + 8)
    elif ident == 0x0200:
      keys = struct.unpack_from("<%di" % size, b, base + 2 * ppc + 4)
      targets = struct.unpack_from("<%di" % size, b, base + 2 * ppc + 4 + 4 * size)
    else:
      return {}
    out = {}
    for k, t in zip(keys, targets):
      pc, calls = spc + t, []
      while 0 <= pc < n:
        unit = struct.unpack_from("<H", b, base + 2 * pc)[0]
        op = unit & 0xFF
        if op == 0 and unit != 0:
          break  # ran into a payload
        if pc in invoke_at:
          calls.append(invoke_at[pc])
        if op in (0x0e, 0x0f, 0x10, 0x11, 0x27, 0x28, 0x29, 0x2a):
          break
        pc += WIDTH[op]
      out[k] = calls
    return out


def load(paths, want):
  out, hier = {}, {}
  for path in paths:
    with open(path, "rb") as f:
      buf = f.read()
    try:
      d = Dex(buf)
      ok = buf[:4] == b"dex\n" and all(o + 4 * k <= len(buf) for o, k in (
        (d.s_off, d.s_n), (d.t_off, d.t_n), (d.m_off, 2 * d.m_n), (d.c_off, 8 * d.c_n)))
    except struct.error:
      ok = False
    if not ok:
      continue  # not a dex, or a decoy with a broken header: nothing to read
    for cls, data, sup, ifs in d.classes():
      if not want(cls):
        continue
      hier[cls] = d.supers(sup, ifs)
      for idx, code in d.methods_of(data):
        c, name, params, ret, key = d.method(idx)
        m = Method(c, name, params, ret)
        m.code = bool(code)
        m.dex, m.code_off = d, code
        if code:
          try:
            d.decode(code, m)
          except (struct.error, IndexError):
            pass  # a malformed or unusual method: keep what was decoded
        out[key] = m
  return out, hier
