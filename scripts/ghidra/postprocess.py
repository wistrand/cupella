#!/usr/bin/env python3
"""Make Ghidra's C output easier to read. Run by scripts/native-decompile.sh.

- names indirect calls through the JNI function table: (*env + 0x6b8) -> RegisterNatives
- renames FUN_<addr> to the JNI method registered at that address, and labels
  JNINativeMethod tables and init functions
- collapses runs of byte-wise zeroing into one line
- 32-bit code: annotates literal-pool words (DAT_<addr>) that point at strings or at
  the start of a decompiled function (function pointers: handler tables, callbacks)

Comments only add information; no code is removed except the collapsed zeroing runs.

Usage: scripts/ghidra/postprocess.py <lib.so> <file.c>     (rewrites file.c in place)
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from elf import JAVA_VM, JNI_ENV, Elf  # noqa: E402

ZERO = re.compile(r"^\s*\w+\[(?:0x[0-9a-f]+|\d+)\] = '\\0';\s*$")
TABLE_CALL = re.compile(r"\(\*\*\(code \*\*\)\(\*(\w+) \+ (0x[0-9a-f]+|\d+)\)\)")


def main():
  lib, cfile = sys.argv[1], sys.argv[2]
  e = Elf(lib)
  with open(cfile, encoding="utf-8") as f:
    text = f.read()
  m = re.search(r"^// Image base ([0-9a-fA-F]+)", text, re.M)
  base = int(m.group(1), 16) if m else 0

  names = {}
  for i, a in enumerate(e.init_functions()):
    names[a] = "init_%d" % i
  tables = e.jni_tables()
  for table in tables:
    for _a, name, _sig, fn in table:
      names.setdefault(fn, "jni_" + name)
  sigs = {fn: sig for table in tables for _a, _n, sig, fn in table}

  def rename(mo):
    addr = int(mo.group(1), 16) - base
    return names.get(addr, mo.group(0))

  text = re.sub(r"\bFUN_([0-9a-f]{8,16})\b", rename, text)
  for table in tables:
    label = "%08x" % (table[0][0] + base)
    text = re.sub(r"(\b\w+_%s\b)" % label,
                  r"\1 /* JNINativeMethod[%d]: %s */" % (
                    len(table), ", ".join(n for _a, n, _s, _f in table[:8])), text)

  def table_call(mo):
    idx, rem = divmod(int(mo.group(2), 0), e.word)
    if rem or idx not in JNI_ENV:
      return mo.group(0)
    alt = " or JavaVM->%s" % JAVA_VM[idx] if idx in JAVA_VM else ""
    return "%s /* JNIEnv->%s%s */" % (mo.group(0), JNI_ENV[idx], alt)

  text = TABLE_CALL.sub(table_call, text)

  # 32-bit ARM loads addresses from literal pools: Ghidra shows the pool word as
  # DAT_<addr>. When that word points at a printable string or at a function, say which.
  funcs = {}
  for mo in re.finditer(r"^// ---- (\w+) @ 0x([0-9a-f]+)", text, re.M):
    funcs[int(mo.group(2), 16) + base] = mo.group(1)

  def pool_string(mo):
    if "/* ->" in mo.group(0):
      return mo.group(0)
    target = e.read_word(int(mo.group(1), 16))
    if target is None:
      return mo.group(0)
    fn = funcs.get(target & ~1)
    if fn and e.is_code(target & ~1):
      return "%s /* -> &%s */" % (mo.group(0), fn)
    st = e.printable_cstr(target, minlen=3, limit=200)
    if st is None or e.is_code(target):
      return mo.group(0)
    return '%s /* -> "%s" */' % (mo.group(0), st[:90].replace("*/", "* /").replace("\n", "\\n"))

  if not e.is64:
    text = re.sub(r"\bDAT_([0-9a-f]{8})\b(?! /\* ->)", pool_string, text)

  out, run = [], []

  def flush():
    if len(run) >= 4:
      indent = re.match(r"^\s*", run[0]).group(0)
      out.append("%s/* %d byte-wise zero assignments collapsed (%s ... %s) */" % (
        indent, len(run), run[0].strip(), run[-1].strip()))
    else:
      out.extend(run)
    run.clear()

  for line in text.split("\n"):
    if ZERO.match(line):
      run.append(line)
      continue
    flush()
    mo = re.match(r"^// ---- (jni_\w+) @ 0x([0-9a-f]+)", line)
    if mo and int(mo.group(2), 16) in sigs:
      line += "   Java signature %s" % sigs[int(mo.group(2), 16)]
    out.append(line)
  flush()

  with open(cfile, "w", encoding="utf-8") as f:
    f.write("\n".join(out))


if __name__ == "__main__":
  main()
