"""Minimal ELF reader for Android shared libraries. Standard library only.

Shared by native-summary.py and native-disasm.py. Reads headers, segments, sections,
the dynamic table, symbols, and relocations (REL/RELA, RELR, Android packed APS2), and
resolves pointers stored in data so JNI method tables can be found in stripped
libraries. Little-endian only (all Android ABIs).
"""
import collections
import math
import re
import struct

EM = {3: "x86", 40: "arm", 62: "x86_64", 183: "arm64"}
PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 0x6474E551, 0x6474E552
SHT_SYMTAB, SHT_DYNSYM, SHT_NOBITS = 2, 11, 8
(DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_STRSZ, DT_INIT,
 DT_SONAME, DT_RPATH, DT_REL, DT_RELSZ, DT_PLTREL, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW,
 DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_RELRSZ, DT_RELR) = (
   1, 2, 4, 5, 6, 7, 8, 10, 12, 14, 15, 17, 18, 20, 22, 23, 24, 25, 27, 29, 30, 35, 36)
DT_GNU_HASH, DT_FLAGS_1 = 0x6FFFFEF5, 0x6FFFFFFB
DT_ANDROID_REL, DT_ANDROID_RELSZ, DT_ANDROID_RELA, DT_ANDROID_RELASZ = (
  0x6000000F, 0x60000010, 0x60000011, 0x60000012)
DT_ANDROID_RELR, DT_ANDROID_RELRSZ = 0x6FFFE000, 0x6FFFE001
# relocation type numbers per machine: (relative, jump_slot, glob_dat, abs)
RELOC = {"arm64": (1027, 1026, 1025, 257), "x86_64": (8, 7, 6, 1), "arm": (23, 22, 21, 2),
         "x86": (8, 7, 6, 1)}

JNI_NAME = re.compile(r"^[A-Za-z_$<][\w$<>]*$")
JNI_SIG = re.compile(r"^!{0,2}\((\[*([ZBCSIJFD]|L[\w/$]+;))*\)\[*([ZBCSIJFDV]|L[\w/$]+;)$")


def jni_env_names():
  names = {4: "GetVersion", 5: "DefineClass", 6: "FindClass", 7: "FromReflectedMethod",
           8: "FromReflectedField", 9: "ToReflectedMethod", 10: "GetSuperclass",
           11: "IsAssignableFrom", 12: "ToReflectedField", 13: "Throw", 14: "ThrowNew",
           15: "ExceptionOccurred", 16: "ExceptionDescribe", 17: "ExceptionClear",
           18: "FatalError", 19: "PushLocalFrame", 20: "PopLocalFrame", 21: "NewGlobalRef",
           22: "DeleteGlobalRef", 23: "DeleteLocalRef", 24: "IsSameObject", 25: "NewLocalRef",
           26: "EnsureLocalCapacity", 27: "AllocObject", 28: "NewObject", 29: "NewObjectV",
           30: "NewObjectA", 31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID"}
  types = ["Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double"]
  i = 34
  for prefix in ("Call%sMethod", "CallNonvirtual%sMethod"):
    for t in types + ["Void"]:
      for suffix in ("", "V", "A"):
        names[i] = prefix % t + suffix
        i += 1
  names[i] = "GetFieldID"
  i += 1
  for prefix in ("Get%sField", "Set%sField"):
    for t in types:
      names[i] = prefix % t
      i += 1
  names[i] = "GetStaticMethodID"
  i += 1
  for t in types + ["Void"]:
    for suffix in ("", "V", "A"):
      names[i] = "CallStatic%sMethod%s" % (t, suffix)
      i += 1
  names[i] = "GetStaticFieldID"
  i += 1
  for prefix in ("GetStatic%sField", "SetStatic%sField"):
    for t in types:
      names[i] = prefix % t
      i += 1
  for n in ("NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF",
            "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
            "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement"):
    names[i] = n
    i += 1
  prims = types[1:]
  for prefix in ("New%sArray", "Get%sArrayElements", "Release%sArrayElements",
                 "Get%sArrayRegion", "Set%sArrayRegion"):
    for t in prims:
      names[i] = prefix % t
      i += 1
  for n in ("RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM",
            "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical",
            "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical",
            "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer",
            "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType"):
    names[i] = n
    i += 1
  return names


JNI_ENV = jni_env_names()
JAVA_VM = {3: "DestroyJavaVM", 4: "AttachCurrentThread", 5: "DetachCurrentThread", 6: "GetEnv",
           7: "AttachCurrentThreadAsDaemon"}
assert JNI_ENV[215] == "RegisterNatives" and JNI_ENV[167] == "NewStringUTF" and JNI_ENV[232] == "GetObjectRefType"


class Symbol:
  __slots__ = ("name", "value", "size", "type", "bind", "shndx")

  def __init__(self, name, value, size, info, shndx):
    self.name, self.value, self.size, self.shndx = name, value, size, shndx
    self.type, self.bind = info & 0xF, info >> 4

  @property
  def is_func(self):
    return self.type == 2

  @property
  def defined(self):
    return self.shndx != 0


class Elf:
  def __init__(self, path):
    self.path = path
    with open(path, "rb") as f:
      self.buf = f.read()
    b = self.buf
    if b[:4] != b"\x7fELF":
      raise ValueError("not an ELF file")
    if len(b) < 52:
      raise ValueError("truncated ELF header")
    if b[5] != 1:
      raise ValueError("big-endian ELF not supported")
    self.is64 = b[4] == 2
    self.word = 8 if self.is64 else 4
    # 32-bit ARM code pointers found in data (init_array, JNI tables): bit 0 set is Thumb.
    # The addresses returned are masked; the mode is kept here.
    self.thumb_ptrs, self.arm_ptrs = set(), set()
    # malformed input raises ValueError, never struct.error (callers catch ValueError)
    try:
      self.type, machine = struct.unpack_from("<HH", b, 16)
      self.machine = EM.get(machine, "em%d" % machine)
      if self.is64:
        (self.entry, phoff, shoff, _fl, _eh, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<QQQIHHHHHH", b, 24)
      else:
        (self.entry, phoff, shoff, _fl, _eh, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<IIIIHHHHHH", b, 24)
      self.segments = []  # (type, flags, offset, vaddr, filesz, memsz)
      for i in range(phnum):
        o = phoff + i * phentsize
        if self.is64:
          t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", b, o)
        else:
          t, off, va, _pa, fsz, msz, fl, _al = struct.unpack_from("<IIIIIIII", b, o)
        self.segments.append((t, fl, off, va, fsz, msz))
    except struct.error as ex:
      raise ValueError("truncated ELF or program headers: %s" % ex) from None
    self.sections = []  # dict(name, type, flags, addr, offset, size, link, entsize)
    self.sections_ok = False
    try:
      raw = []
      for i in range(shnum):
        o = shoff + i * shentsize
        if self.is64:
          n, t, fl, ad, off, sz, link, _info, _al, es = struct.unpack_from("<IIQQQQIIQQ", b, o)
        else:
          n, t, fl, ad, off, sz, link, _info, _al, es = struct.unpack_from("<IIIIIIIIII", b, o)
        raw.append([n, t, fl, ad, off, sz, link, es])
      if raw and shstrndx < len(raw):
        stoff = raw[shstrndx][4]
        for n, t, fl, ad, off, sz, link, es in raw:
          self.sections.append(dict(name=self._cstr_off(stoff + n), type=t, flags=fl, addr=ad,
                                    offset=off, size=sz, link=link, entsize=es))
        self.sections_ok = any(s["name"] == ".text" for s in self.sections)
    except (struct.error, IndexError):
      self.sections = []
    try:
      self._parse_dynamic()
      self._parse_symbols()
      self._parse_relocs()
    except struct.error as ex:
      raise ValueError("malformed ELF tables: %s" % ex) from None

  # --- address helpers
  def off(self, vaddr):
    for t, _fl, off, va, fsz, _msz in self.segments:
      if t == PT_LOAD and va <= vaddr < va + fsz:
        o = off + (vaddr - va)
        return o if o < len(self.buf) else None  # filesz may claim more than the file has
    return None

  def is_exec(self, vaddr):
    return any(t == PT_LOAD and fl & 1 and va <= vaddr < va + msz
               for t, fl, _o, va, _f, msz in self.segments)

  def is_code(self, vaddr):
    """True when vaddr is in an executable section (lld may put .rodata and .text in one
    R+X segment, so the segment flag alone would call strings code)."""
    if self.sections_ok:
      return any(s["flags"] & 4 and s["addr"] <= vaddr < s["addr"] + s["size"] for s in self.sections)
    return self.is_exec(vaddr)

  def _cstr_off(self, o, limit=4096):
    end = self.buf.find(b"\0", o, o + limit)
    if end < 0:
      return ""
    return self.buf[o:end].decode("utf-8", "replace")

  def cstr(self, vaddr, limit=4096):
    o = self.off(vaddr)
    return None if o is None else self._cstr_off(o, limit)

  def printable_cstr(self, vaddr, minlen=1, limit=300):
    o = self.off(vaddr)
    if o is None:
      return None
    end = self.buf.find(b"\0", o, o + limit)
    if end < 0 or end - o < minlen:
      return None
    raw = self.buf[o:end]
    if all(32 <= c < 127 or c in (9, 10, 13) for c in raw):
      return raw.decode("ascii")
    return None

  def read_word(self, vaddr):
    o = self.off(vaddr)
    if o is None or o + self.word > len(self.buf):
      return None
    return struct.unpack_from("<Q" if self.is64 else "<I", self.buf, o)[0]

  def ptr_at(self, vaddr):
    """Pointer value stored at vaddr after applying relative relocations."""
    if vaddr in self.rel_addend:
      return self.rel_addend[vaddr]
    return self.read_word(vaddr)

  def section(self, name):
    for s in self.sections:
      if s["name"] == name:
        return s
    return None

  # --- dynamic table
  def _parse_dynamic(self):
    self.dyn = []
    for t, _fl, off, _va, fsz, _msz in self.segments:
      if t == PT_DYNAMIC:
        step = 16 if self.is64 else 8
        for o in range(off, min(off + fsz, len(self.buf) - step + 1), step):
          tag, val = struct.unpack_from("<qQ" if self.is64 else "<iI", self.buf, o)
          if tag == 0:
            break
          self.dyn.append((tag, val))
    self.dynd = {}
    for tag, val in self.dyn:
      self.dynd.setdefault(tag, val)
    strtab = self.off(self.dynd.get(DT_STRTAB, 0)) if DT_STRTAB in self.dynd else None
    self._dynstr = strtab
    get = (lambda v: self._cstr_off(strtab + v)) if strtab is not None else (lambda v: "?")
    self.needed = [get(v) for t, v in self.dyn if t == DT_NEEDED]
    self.soname = get(self.dynd[DT_SONAME]) if DT_SONAME in self.dynd else None
    self.rpath = [get(v) for t, v in self.dyn if t in (DT_RPATH, DT_RUNPATH)]

  # --- symbols
  def _read_syms(self, off, count, stroff):
    out = []
    ent = 24 if self.is64 else 16
    for i in range(count):
      o = off + i * ent
      if o + ent > len(self.buf):
        break
      if self.is64:
        n, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.buf, o)
      else:
        n, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", self.buf, o)
      out.append(Symbol(self._cstr_off(stroff + n) if n else "", value, size, info, shndx))
    return out

  def _dynsym_count(self):
    ent = 24 if self.is64 else 16
    if DT_HASH in self.dynd:
      o = self.off(self.dynd[DT_HASH])
      if o is not None and o + 8 <= len(self.buf):
        return struct.unpack_from("<I", self.buf, o + 4)[0]
    if DT_GNU_HASH in self.dynd:
      n = self._gnu_hash_count()
      if n:
        return n
    sym, strt = self.dynd.get(DT_SYMTAB), self.dynd.get(DT_STRTAB)
    if sym is not None and strt is not None and strt > sym:
      return (strt - sym) // ent  # usual layout: .dynsym directly precedes .dynstr
    return 0

  def _gnu_hash_count(self):
    """number of dynamic symbols from DT_GNU_HASH: the highest bucket start, then its
    chain to the entry with the end bit (symbols below symoffset are not hashed)"""
    o = self.off(self.dynd[DT_GNU_HASH])
    if o is None:
      return 0
    try:
      nb, symoff, bloom, _shift = struct.unpack_from("<IIII", self.buf, o)
      bo = o + 16 + bloom * self.word
      buckets = struct.unpack_from("<%dI" % nb, self.buf, bo)
      last = max(buckets) if buckets else 0
      if last < symoff:
        return symoff
      co = bo + 4 * nb
      while not struct.unpack_from("<I", self.buf, co + 4 * (last - symoff))[0] & 1:
        last += 1
      return last + 1
    except struct.error:
      return 0

  def _parse_symbols(self):
    self.dynsyms, self.symtab = [], []
    ds = next((s for s in self.sections if s["type"] == SHT_DYNSYM), None)
    if ds and ds["link"] < len(self.sections):
      ent = 24 if self.is64 else 16
      self.dynsyms = self._read_syms(ds["offset"], ds["size"] // ent,
                                     self.sections[ds["link"]]["offset"])
    elif DT_SYMTAB in self.dynd and self._dynstr is not None:
      o = self.off(self.dynd[DT_SYMTAB])
      if o is not None:
        self.dynsyms = self._read_syms(o, self._dynsym_count(), self._dynstr)
    st = next((s for s in self.sections if s["type"] == SHT_SYMTAB), None)
    if st and st["link"] < len(self.sections):
      ent = 24 if self.is64 else 16
      self.symtab = self._read_syms(st["offset"], st["size"] // ent,
                                    self.sections[st["link"]]["offset"])
    self.stripped = not self.symtab
    self.exports = [s for s in self.dynsyms if s.defined and s.name and s.type in (1, 2, 10)]
    self.imports = [s for s in self.dynsyms if not s.defined and s.name]
    self.addr_names = {}
    for s in self.symtab + self.dynsyms:
      if s.defined and s.name and s.type == 2:
        self.addr_names.setdefault(s.value & ~1 if self.machine == "arm" else s.value, s.name)

  # --- relocations
  def _iter_plain(self, vaddr, size, rela):
    o = self.off(vaddr)
    if o is None:
      return
    if self.is64:
      ent, fmt = (24, "<QQq") if rela else (16, "<QQ")
    else:
      ent, fmt = (12, "<IIi") if rela else (8, "<II")
    for p in range(o, min(o + size, len(self.buf) - ent + 1), ent):
      vals = struct.unpack_from(fmt, self.buf, p)
      yield vals[0], vals[1], (vals[2] if rela else None)

  def _iter_aps2(self, vaddr, size, rela):
    o = self.off(vaddr)
    if o is None or self.buf[o:o + 4] != b"APS2":
      return
    pos = [o + 4]
    end = min(o + size, len(self.buf))

    def sleb():
      """next SLEB128; EOFError when the data ends before its last byte"""
      r = s = 0
      while pos[0] < end:
        byte = self.buf[pos[0]]
        pos[0] += 1
        r |= (byte & 0x7F) << s
        s += 7
        if not byte & 0x80:
          if byte & 0x40:
            r -= 1 << s
          return r
      raise EOFError

    mask = (1 << (64 if self.is64 else 32)) - 1
    try:
      count, offset, addend = sleb(), sleb(), 0
      # a group with delta and info shared needs no bytes per relocation, so the count is
      # the only bound: no real library has more relocations than words in the file
      count = min(count, len(self.buf) // self.word)
      done = 0
      while done < count and pos[0] < end:
        gsize, gflags = sleb(), sleb()
        by_info, by_delta, by_addend, has_addend = gflags & 1, gflags & 2, gflags & 4, gflags & 8
        gdelta = sleb() if by_delta else 0
        ginfo = sleb() if by_info else 0
        if has_addend and by_addend:
          addend += sleb()
        if not has_addend:
          addend = 0
        for _ in range(max(0, min(gsize, count - done))):
          offset += gdelta if by_delta else sleb()
          info = ginfo if by_info else sleb()
          if has_addend and not by_addend:
            addend += sleb()
          yield offset & mask, info & mask, (addend if rela else None)
          done += 1
    except EOFError:
      return

  def _iter_relr(self, vaddr, size):
    o = self.off(vaddr)
    if o is None:
      return
    w, bits = self.word, self.word * 8
    nxt = 0
    for p in range(o, min(o + size, len(self.buf) - w + 1), w):
      entry = struct.unpack_from("<Q" if self.is64 else "<I", self.buf, p)[0]
      if entry & 1 == 0:
        yield entry
        nxt = entry + w
      else:
        for i in range(1, bits):
          if entry >> i & 1:
            yield nxt + (i - 1) * w
        nxt += (bits - 1) * w

  def _parse_relocs(self):
    self.rel_addend = {}  # vaddr -> resolved pointer (relative relocs with explicit addend)
    self.relative_sites = set()
    self.got_syms = {}    # vaddr of GOT/data slot -> symbol name (glob_dat, jump_slot, abs)
    self.plt_relocs = []  # jump-slot relocs in table order: (slot vaddr, symbol name)
    self.packed_relocs = []
    rel_t, jmp_t, glob_t, abs_t = RELOC.get(self.machine, (None,) * 4)
    d = self.dynd

    def handle(offset, info, addend, into_plt=False):
      sym, typ = (info >> 32, info & 0xFFFFFFFF) if self.is64 else (info >> 8, info & 0xFF)
      if typ == rel_t:
        self.relative_sites.add(offset)
        if addend is not None:
          self.rel_addend[offset] = addend
      elif typ in (jmp_t, glob_t, abs_t) and sym < len(self.dynsyms):
        name = self.dynsyms[sym].name
        self.got_syms[offset] = name
        if into_plt or typ == jmp_t:
          self.plt_relocs.append((offset, name))

    if DT_RELA in d:
      for r in self._iter_plain(d[DT_RELA], d.get(DT_RELASZ, 0), True):
        handle(*r)
    if DT_REL in d:
      for r in self._iter_plain(d[DT_REL], d.get(DT_RELSZ, 0), False):
        handle(*r)
    if DT_ANDROID_RELA in d:
      self.packed_relocs.append("APS2 rela")
      for r in self._iter_aps2(d[DT_ANDROID_RELA], d.get(DT_ANDROID_RELASZ, 0), True):
        handle(*r)
    if DT_ANDROID_REL in d:
      self.packed_relocs.append("APS2 rel")
      for r in self._iter_aps2(d[DT_ANDROID_REL], d.get(DT_ANDROID_RELSZ, 0), False):
        handle(*r)
    for tag, sztag in ((DT_RELR, DT_RELRSZ), (DT_ANDROID_RELR, DT_ANDROID_RELRSZ)):
      if tag in d:
        self.packed_relocs.append("RELR")
        for site in self._iter_relr(d[tag], d.get(sztag, 0)):
          self.relative_sites.add(site)
    if DT_JMPREL in d:
      rela = d.get(DT_PLTREL, DT_RELA) == DT_RELA
      for r in self._iter_plain(d[DT_JMPREL], d.get(DT_PLTRELSZ, 0), rela):
        handle(*r, into_plt=True)

  def plt_map(self):
    """vaddr of each PLT stub -> imported symbol name. arm64 and x86_64 layouts."""
    out = {}
    names = [n for _slot, n in self.plt_relocs]
    plt = self.section(".plt")
    if plt and self.machine == "arm64":
      for i, n in enumerate(names):
        out[plt["addr"] + 32 + 16 * i] = n
    elif self.machine == "x86_64":
      sec = self.section(".plt.sec")
      if sec:
        for i, n in enumerate(names):
          out[sec["addr"] + 16 * i] = n
      elif plt:
        for i, n in enumerate(names):
          out[plt["addr"] + 16 + 16 * i] = n
    return out

  # --- derived facts
  def code_ptr(self, v):
    """a code pointer from data: on 32-bit ARM bit 0 is the Thumb bit; record the mode
    in thumb_ptrs / arm_ptrs and return the address without it"""
    if self.machine != "arm":
      return v
    if v & 1:
      self.thumb_ptrs.add(v & ~1)
      return v & ~1
    self.arm_ptrs.add(v)
    return v

  def init_functions(self, max_entries=4096):
    out = []
    if DT_INIT in self.dynd:
      out.append(self.code_ptr(self.dynd[DT_INIT]))
    if DT_INIT_ARRAY in self.dynd:
      base, size = self.dynd[DT_INIT_ARRAY], self.dynd.get(DT_INIT_ARRAYSZ, 0)
      size = min(size, len(self.buf), max_entries * self.word)  # the size is not checked by anyone
      for a in range(base, base + size, self.word):
        v = self.ptr_at(a)
        if v not in (None, 0, (1 << self.word * 8) - 1):
          out.append(self.code_ptr(v))
    return out

  def build_id(self):
    s = self.section(".note.gnu.build-id")
    if s and s["size"] >= 16 and s["offset"] + 12 <= len(self.buf):
      namesz, descsz = struct.unpack_from("<II", self.buf, s["offset"])
      start = s["offset"] + 12 + ((namesz + 3) & ~3)
      return self.buf[start:start + descsz].hex()
    return None

  def comment(self):
    s = self.section(".comment")
    if not s:
      return []
    raw = self.buf[s["offset"]:s["offset"] + s["size"]]
    return [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]

  def hardening(self):
    relro = any(t == PT_GNU_RELRO for t, *_ in self.segments)
    now = (DT_BIND_NOW in self.dynd or self.dynd.get(DT_FLAGS, 0) & 0x8
           or self.dynd.get(DT_FLAGS_1, 0) & 0x1)
    stack = next((fl for t, fl, *_ in self.segments if t == PT_GNU_STACK), None)
    imp = {s.name for s in self.imports}
    return {
      "relro": "full" if relro and now else "partial" if relro else "none",
      "nx_stack": stack is not None and not stack & 1,
      "stack_canary": "__stack_chk_fail" in imp or "__stack_chk_guard" in imp,
      "fortify": sorted(n for n in imp if n.endswith("_chk") and n != "__stack_chk_fail"),
      "textrel": DT_TEXTREL in self.dynd or bool(self.dynd.get(DT_FLAGS, 0) & 0x4),
      "rwx_segment": any(t == PT_LOAD and fl & 7 == 7 for t, fl, *_ in self.segments),
    }

  def jni_tables(self):
    """Find JNINativeMethod arrays {name, signature, fnPtr} in non-executable data."""
    w, tables, cur = self.word, [], []
    for t, fl, off, va, fsz, _msz in self.segments:
      if t != PT_LOAD or fl & 1:
        continue
      fsz = min(fsz, max(0, len(self.buf) - off))  # filesz may claim more than the file has
      a = (va + w - 1) & ~(w - 1)
      end = va + fsz - 3 * w
      while a <= end:
        entry = self._jni_entry(a)
        if entry:
          if any(entry[0] == row[1] and entry[1].lstrip("!") == row[2].lstrip("!") for row in cur):
            tables.append(cur)  # same method again: an adjacent table (e.g. per API level)
            cur = []
          cur.append((a,) + entry)
          a += 3 * w
          continue
        if cur:
          tables.append(cur)
          cur = []
        a += w
      if cur:
        tables.append(cur)
        cur = []
    return tables

  def _jni_entry(self, a):
    p0, p1, p2 = self.ptr_at(a), self.ptr_at(a + self.word), self.ptr_at(a + 2 * self.word)
    if not p0 or not p1 or not p2:
      return None
    fn = p2 & ~1 if self.machine == "arm" else p2  # Thumb bit: recorded by code_ptr below
    if not self.is_code(fn):
      return None
    o1 = self.off(p1)
    if o1 is None or self.buf[o1:o1 + 3].lstrip(b"!")[:1] != b"(":
      return None
    sig = self.cstr(p1, 512)
    if not sig or not JNI_SIG.match(sig):
      return None
    name = self.cstr(p0, 256)
    if not name or not JNI_NAME.match(name):
      return None
    return name, sig, self.code_ptr(p2)

  def strings(self, minlen=5):
    """Printable ASCII strings from non-executable file content, with file offsets."""
    spans = []
    if self.sections_ok:
      for s in self.sections:
        if s["type"] != SHT_NOBITS and not s["flags"] & 4 and s["size"] and s["name"] != ".comment":
          spans.append((s["offset"], s["offset"] + s["size"]))
    else:
      spans.append((0, len(self.buf)))
    pat = re.compile(rb"[\x20-\x7e\t]{%d,}" % minlen)
    seen, out = set(), []
    for a, b in spans:
      for m in pat.finditer(self.buf, a, b):
        s = m.group().decode("ascii")
        if s not in seen:
          seen.add(s)
          out.append(s)
    return out

  def entropy(self, offset, size):
    data = self.buf[offset:offset + size]
    if not data:
      return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())

  def exec_ranges(self):
    """(vaddr, file offset, size, label) of code to disassemble."""
    if self.sections_ok:
      return [(s["addr"], s["offset"], s["size"], s["name"]) for s in self.sections
              if s["flags"] & 4 and s["type"] != SHT_NOBITS and s["size"]]
    return [(va, off, fsz, "LOAD") for t, fl, off, va, fsz, _m in self.segments
            if t == PT_LOAD and fl & 1]
