#!/usr/bin/env python3
"""Disassemble functions of a native library with annotations an agent can read:
import names on calls, strings on address loads, JNIEnv function names on indirect
calls, and labels for JNI methods found in RegisterNatives tables.

Uses capstone's `cstool` for decoding. Annotations are arm64-only; other
architectures get labels and direct-call names only. Static: nothing is executed.
32-bit ARM: ARM or Thumb per function symbol; without one, the file's default from the
symbol majority, the ELF entry bit, or the share of code words with condition AL. Each
function header says which mode was used and why.

Usage:
  scripts/native-disasm.py <lib.so> --list                 functions known by name or table
  scripts/native-disasm.py <lib.so> <symbol|0xADDR> [...]  disassemble those functions
  scripts/native-disasm.py <lib.so> --jni                  JNI_OnLoad, init functions, all JNI methods
  scripts/native-disasm.py <lib.so> --all                  every executable section
  scripts/native-disasm.py <lib.so> --xref <string|import> functions referencing it (arm64)
Options: --max N  instruction cap per function without a known size (default 400)

<lib.so> is a path, e.g. work/<name>/raw/lib/arm64-v8a/libfoo.so
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import JAVA_VM, JNI_ENV, Elf  # noqa: E402

CSTOOL_MODE = {"arm64": "arm64", "x86_64": "x64", "x86": "x32", "arm": "arm"}
CHUNK = 24000  # bytes per cstool call; the hex argument must stay under the kernel's 128 KiB limit
MAX_FAILS = 32  # consecutive cstool calls that decode nothing before the rest is emitted raw


def cstool(mode, data, addr):
  """Decode bytes; returns [(addr, mnemonic, operands)]. Undecodable words become .word."""
  out = []
  pos = 0
  step = 4 if mode in ("arm64", "arm") else 2 if mode == "thumb" else 1
  fails = 0
  while pos < len(data):
    if fails >= MAX_FAILS:  # data, not code: one process per word would take hours
      for p in range(pos, len(data), step):
        raw = data[p:p + step]
        out.append((addr + p, ".byte" if step == 1 else ".word", raw.hex() if step == 1 else raw[::-1].hex()))
      break
    chunk = data[pos:pos + CHUNK]
    r = subprocess.run(["cstool", mode, chunk.hex(), "%x" % (addr + pos)],
                       capture_output=True, text=True)
    last_end = pos
    for line in r.stdout.split("\n"):
      m = re.match(r"^\s*([0-9a-f]+)\s+((?:[0-9a-f]{2} )+)\s*(\S+)\s*(.*)$", line)
      if not m:
        continue
      a = int(m.group(1), 16)
      size = len(m.group(2).split())
      out.append((a, m.group(3), m.group(4).strip()))
      last_end = a - addr + size
    if last_end >= pos + len(chunk):
      pos = last_end
      fails = 0
    elif last_end > pos and pos + len(chunk) < len(data) and pos + len(chunk) - last_end <= 16:
      # an instruction straddles the chunk boundary: decode again from where it starts
      pos = last_end
      fails = 0
    else:  # decoder stopped: emit raw bytes and resume after them
      raw = data[last_end:last_end + step]
      out.append((addr + last_end, ".byte" if step == 1 else ".word", raw.hex() if step == 1 else raw[::-1].hex()))
      fails = 0 if last_end > pos else fails + 1
      pos = last_end + step
  return out


class Disasm:
  def __init__(self, path):
    self.e = e = Elf(path)
    self.mode = CSTOOL_MODE.get(e.machine)
    if not self.mode:
      sys.exit("unsupported machine: %s" % e.machine)
    self.plt = e.plt_map()
    self.labels = dict(e.addr_names)
    self.sizes = {}
    for s in e.symtab + e.dynsyms:
      if s.defined and s.is_func and s.size:
        self.sizes[s.value & ~1 if e.machine == "arm" else s.value] = s.size
    # 32-bit ARM: a function symbol with bit 0 clear is ARM mode, set is Thumb. Pointers in
    # init_array and JNI tables carry the bit too (Elf.thumb_ptrs / arm_ptrs, added below);
    # other addresses get the file's default mode.
    funcs = [s.value for s in e.symtab + e.dynsyms if e.machine == "arm" and s.defined and s.is_func]
    self.arm_mode = {v for v in funcs if not v & 1}
    self.thumb_mode = {v & ~1 for v in funcs if v & 1}
    self.arm_default, self.arm_default_why = self._arm_default() if e.machine == "arm" else (None, None)
    self.jni = {}
    self.jni_table_at = {}
    for table in e.jni_tables():
      self.jni_table_at[table[0][0]] = "JNINativeMethod table: " + ", ".join(n for _a, n, _s, _f in table[:6]) + (
        ", ..." if len(table) > 6 else "")
      for _a, name, sig, fn in table:
        self.jni.setdefault(fn, "%s%s" % (name, sig))
    for i, a in enumerate(e.init_functions()):
      self.labels.setdefault(a, "init_%d" % i)
    for fn, desc in self.jni.items():
      self.labels.setdefault(fn, "jni_" + desc.split("(")[0])
    # after _arm_default, which counts symbols only; a symbol's mode wins over a pointer's
    for v in e.thumb_ptrs - self.arm_mode:
      self.thumb_mode.add(v)
    for v in e.arm_ptrs - self.thumb_mode:
      self.arm_mode.add(v)

  def _arm_default(self):
    """Mode for 32-bit ARM code without a function symbol: the majority of the function
    symbols; else the ELF entry point (bit 0 set is Thumb); else the share of aligned code
    words whose condition field is AL (0xE), which ARM-mode code has for most instructions
    and Thumb code has for few."""
    if self.arm_mode or self.thumb_mode:
      if len(self.arm_mode) > len(self.thumb_mode):
        return "arm", "%d of %d function symbols are ARM mode" % (len(self.arm_mode), len(self.arm_mode) + len(self.thumb_mode))
      return "thumb", "%d of %d function symbols are Thumb" % (len(self.thumb_mode), len(self.arm_mode) + len(self.thumb_mode))
    e = self.e
    if e.entry and e.is_exec(e.entry & ~1):
      return ("thumb", "ELF entry 0x%x has bit 0 set" % e.entry) if e.entry & 1 else (
        "arm", "ELF entry 0x%x has bit 0 clear" % e.entry)
    words = al = 0
    for va, _off, size, _label in e.exec_ranges():
      data = self.read(va & ~3, min(size, 1 << 20))
      for i in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[i:i + 4], "little")
        if w:
          words += 1
          al += (w >> 28) == 0xE
    if words and al * 2 > words:
      return "arm", "%d%% of code words have condition AL" % (100 * al // words)
    return "thumb", "no symbols or entry; %d%% of code words have condition AL" % (100 * al // words if words else 0)

  def mode_note(self, addr):
    if self.e.machine != "arm":
      return ""
    if addr in self.arm_mode or addr in self.thumb_mode:
      return ", %s mode from its symbol or a pointer to it" % self.mode_for(addr)
    return ", %s mode: %s" % (self.arm_default, self.arm_default_why)

  def mode_for(self, addr):
    if self.e.machine == "arm":
      if addr in self.arm_mode:
        return "arm"
      if addr in self.thumb_mode:
        return "thumb"
      return self.arm_default
    return self.mode

  def name_of(self, addr):
    if addr in self.plt:
      return "import " + self.plt[addr]
    if addr in self.jni:
      return "native " + self.jni[addr]
    return self.labels.get(addr)

  def read(self, vaddr, size):
    o = self.e.off(vaddr)
    return b"" if o is None else self.e.buf[o:o + size]

  def data_note(self, addr):
    """What an address in data refers to: string, import slot, or pointer target."""
    e = self.e
    if addr in self.jni_table_at:
      return self.jni_table_at[addr]
    if addr in e.got_syms:
      return "&" + e.got_syms[addr]
    s = e.printable_cstr(addr, minlen=1)
    if s is not None and not e.is_code(addr):
      return '"%s"' % s[:100].replace("\n", "\\n")
    p = e.ptr_at(addr) if addr % e.word == 0 else None
    if p:
      n = self.name_of(p)
      if n:
        return "-> " + n
      s = e.printable_cstr(p, minlen=2)
      if s is not None and not e.is_code(p):
        return '-> "%s"' % s[:100].replace("\n", "\\n")
    return None

  def function_bytes(self, addr, cap):
    size = self.sizes.get(addr)
    if size:
      return self.read(addr, size), True
    # unknown size: take up to the next known label or the cap
    nxt = min((a for a in list(self.labels) + list(self.plt) if a > addr), default=None)
    limit = cap * 4 if self.mode in ("arm64", "arm") else cap * 6
    if nxt is not None:
      limit = min(limit, nxt - addr)
    return self.read(addr, limit), False

  def annotate_arm64(self, insns):
    page, deref, envfn = {}, set(), {}
    lines = []
    for a, mn, ops in insns:
      note = None
      regs = re.findall(r"\b([xw]\d+|sp)\b", ops)
      dst = regs[0] if regs else None
      imm = re.findall(r"#(-?0x[0-9a-f]+|-?\d+)", ops)
      val = int(imm[-1], 0) if imm else None
      if mn in ("bl", "b") and val is not None:
        note = self.name_of(val)
      elif mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz"):
        pass
      elif mn == "adrp" and dst and val is not None:
        page[dst] = val
        deref.discard(dst)
        envfn.pop(dst, None)
        lines.append((a, mn, ops, None))
        continue
      elif mn == "adr" and dst and val is not None:
        note = self.data_note(val) or self.name_of(val)
      elif mn == "add" and len(regs) >= 2 and regs[1] in page and val is not None and "lsl" not in ops:
        target = page[regs[1]] + val
        note = self.data_note(target) or self.name_of(target) or "0x%x" % target
        page.pop(dst, None)
      elif mn in ("ldr", "ldrsw", "ldrb", "ldrh") and len(regs) >= 2:
        base = regs[1]
        off = val or 0
        if base in page and "[" in ops:
          target = page[base] + off
          note = self.data_note(target) or "[0x%x]" % target
        elif mn == "ldr" and "[" in ops and base in deref and off % 8 == 0:
          idx = off // 8
          if idx in JNI_ENV:
            envfn[dst] = JNI_ENV[idx] + (" (or JavaVM->%s)" % JAVA_VM[idx] if idx in JAVA_VM else "")
            lines.append((a, mn, ops, None))
            deref.discard(dst)
            page.pop(dst, None)
            continue
        if mn == "ldr" and "[" in ops and off == 0 and "!" not in ops and "]," not in ops:
          deref.add(dst)
          envfn.pop(dst, None)
          page.pop(dst, None)
          lines.append((a, mn, ops, note))
          continue
      elif mn in ("blr", "br") and dst in envfn:
        note = "JNIEnv->" + envfn[dst]
      if mn in ("bl", "blr"):
        # caller-saved registers are dead after a call
        for r in list(page):
          if r[0] == "x" and r[1:].isdigit() and int(r[1:]) <= 18:
            page.pop(r)
        deref = {r for r in deref if not (r[1:].isdigit() and int(r[1:]) <= 18)}
        envfn = {r: v for r, v in envfn.items() if not (r[1:].isdigit() and int(r[1:]) <= 18)}
      elif dst and mn not in ("str", "stp", "cmp", "tst", "cbz", "cbnz", "tbz", "tbnz", "b", "ret") \
          and not mn.startswith("b."):
        page.pop(dst, None)
        deref.discard(dst)
        envfn.pop(dst, None)
      lines.append((a, mn, ops, note))
    return lines

  def annotate_plain(self, insns):
    lines = []
    for a, mn, ops in insns:
      note = None
      if mn in ("call", "jmp", "bl", "blx", "b"):
        m = re.search(r"#?(0x[0-9a-f]+)$", ops)
        if m:
          note = self.name_of(int(m.group(1), 16))
      lines.append((a, mn, ops, note))
    return lines

  def render(self, addr, cap, out=sys.stdout):
    data, sized = self.function_bytes(addr, cap)
    if not data:
      out.write("; 0x%x: not in a loadable segment\n" % addr)
      return
    insns = cstool(self.mode_for(addr), data, addr)
    if not sized:
      # stop at the first return or tail call that is not jumped over
      targets = set()
      end = len(insns)
      for i, (a, mn, ops) in enumerate(insns):
        m = re.search(r"#(0x[0-9a-f]+)$", ops)
        if m and (mn.startswith("b.") or mn in ("b", "cbz", "cbnz", "tbz", "tbnz", "jmp")
                  or mn.startswith("j")):
          t = int(m.group(1), 16)
          if addr <= t < addr + len(data):
            targets.add(t)
        is_end = mn in ("ret", "retq", "br") or (mn == "bx" and ops == "lr") or (
          mn.startswith("pop") and "pc" in ops) or (mn in ("b", "jmp") and m and
                                                 not addr <= int(m.group(1), 16) < addr + len(data))
        if is_end and not any(t > a for t in targets):
          end = i + 1
          break
      insns = insns[:end]
    lines = self.annotate_arm64(insns) if self.mode == "arm64" else self.annotate_plain(insns)
    title = self.name_of(addr) or "sub_%x" % addr
    out.write("\n; ---- %s @ 0x%x (%d instructions%s%s)\n" % (
      title, addr, len(lines), "" if sized else ", end inferred", self.mode_note(addr)))
    local = {a for a, *_ in lines}
    for a, mn, ops, note in lines:
      if a != addr and a in self.labels:
        out.write("%s:\n" % self.labels[a])
      text = "  %6x  %-7s %s" % (a, mn, ops)
      if note:
        text = "%-52s ; %s" % (text, note)
      out.write(text + "\n")
    return local

  def resolve(self, token):
    if re.match(r"^0x[0-9a-fA-F]+$", token):
      return [int(token, 16)]
    hits = [a for a, n in self.labels.items() if n == token]
    if not hits:
      hits = [a for a, n in self.labels.items() if token in n]
    return sorted(hits)

  def listing(self):
    e = self.e
    print("; %s (%s)" % (os.path.basename(e.path), e.machine))
    rows = []
    for a, n in self.labels.items():
      kind = "jni" if a in self.jni else "init" if n.startswith("init_") else "sym"
      rows.append((a, kind, self.jni.get(a, n), self.sizes.get(a, 0)))
    for a, kind, n, size in sorted(rows):
      print("0x%-8x %-4s %5s  %s" % (a, kind, size or "?", n))
    names = sorted(set(self.plt.values()))
    print("; %d PLT imports (full list in native-summary.txt): %s%s" % (
      len(self.plt), ", ".join(names[:40]), ", ..." if len(names) > 40 else ""))
    for va, _off, size, label in e.exec_ranges():
      print("; code: %s 0x%x..0x%x (%d bytes)" % (label, va, va + size, size))

  def xref(self, needle, cap):
    """Scan all code for annotated references containing the needle. arm64 only."""
    if self.mode != "arm64":
      sys.exit("--xref needs arm64")
    starts = sorted(set(self.labels) | {va for va, *_ in self.e.exec_ranges()})
    for va, _off, size, label in self.e.exec_ranges():
      if label == ".plt":
        continue
      insns = cstool(self.mode, self.read(va, size), va)
      lines = self.annotate_arm64(insns)
      # function starts: known labels plus targets of bl inside this range
      fstarts = set(s for s in starts if va <= s < va + size)
      for a, mn, ops, _n in lines:
        if mn == "bl":
          m = re.search(r"#(0x[0-9a-f]+)$", ops)
          if m and va <= int(m.group(1), 16) < va + size:
            fstarts.add(int(m.group(1), 16))
      ordered = sorted(fstarts)
      import bisect
      for a, mn, ops, note in lines:
        if note and needle in note:
          i = bisect.bisect_right(ordered, a) - 1
          fn = ordered[i] if i >= 0 else va
          print("0x%x in %s (0x%x): %s %s ; %s" % (
            a, self.name_of(fn) or "sub_%x" % fn, fn, mn, ops, note))


def main():
  args = sys.argv[1:]
  if len(args) < 2 or args[0].startswith("-"):
    sys.exit(__doc__)
  cap = 400
  if "--max" in args:
    i = args.index("--max")
    cap = int(args[i + 1])
    del args[i:i + 2]
  d = Disasm(args[0])
  what = args[1:]
  if what[0] == "--list":
    d.listing()
  elif what[0] == "--xref":
    d.xref(what[1], cap)
  elif what[0] == "--all":
    for va, _off, size, label in d.e.exec_ranges():
      sys.stdout.write("\n; ==== %s%s\n" % (label, d.mode_note(va)))
      insns = cstool(d.mode_for(va), d.read(va, size), va)
      lines = d.annotate_arm64(insns) if d.mode == "arm64" else d.annotate_plain(insns)
      for a, mn, ops, note in lines:
        if a in d.labels or a in d.jni:
          sys.stdout.write("\n%s:\n" % (d.name_of(a)))
        text = "  %6x  %-7s %s" % (a, mn, ops)
        sys.stdout.write(("%-52s ; %s" % (text, note) if note else text) + "\n")
  elif what[0] == "--jni":
    addrs = [a for a, n in d.labels.items() if n == "JNI_OnLoad" or n.startswith(("init_", "Java_"))]
    addrs += list(d.jni)
    for a in sorted(set(addrs)):
      d.render(a, cap)
  else:
    for tok in what:
      hits = d.resolve(tok)
      if not hits:
        sys.stdout.write("; no function matching %s (try --list)\n" % tok)
      for a in hits:
        d.render(a, cap)


if __name__ == "__main__":
  main()
