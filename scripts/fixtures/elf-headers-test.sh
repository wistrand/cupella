#!/usr/bin/env bash
# Checks that the ELF reader (scripts/elf.py) gets the same facts from a library whose
# section headers are missing or garbage, as packers leave them (Android's loader reads
# only program headers). Copies the given libraries to /tmp, damages the copies three
# ways, and compares needed libraries, soname, exports, imports, relocations, JNI
# tables, and init functions with the intact copy. Prints PASS or FAIL per library and
# damage; touches nothing outside /tmp.
#
# Usage: ./cupella fixtures/elf-headers-test.sh <lib.so> [lib.so ...]   (paths under work/)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -gt 0 ] || { sed -n '2,10p' "$0"; exit 1; }
python3 - "$root" "$@" <<'PY'
import os, shutil, struct, sys, tempfile
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "scripts"))
import elf
t = tempfile.mkdtemp(prefix="elfhdr.")

def facts(e):
  return {
    "needed": sorted(e.needed), "soname": e.soname,
    "exports": sorted(s.name for s in e.exports), "imports": sorted(s.name for s in e.imports),
    "got": len(e.got_syms), "plt": len(e.plt_relocs), "relative": len(e.rel_addend),
    "jni": repr(sorted(map(repr, e.jni_tables()))), "init": repr(e.init_functions()),
  }

def damage(src, how):
  b = bytearray(open(src, "rb").read())
  is64 = b[4] == 2
  o_shoff, o_shnum, o_shstr = (40, 60, 62) if is64 else (32, 48, 50)
  shoff = struct.unpack_from("<Q" if is64 else "<I", b, o_shoff)[0]
  if how == "no-sections":
    struct.pack_into("<Q" if is64 else "<I", b, o_shoff, 0)
    struct.pack_into("<H", b, o_shnum, 0)
    struct.pack_into("<H", b, o_shstr, 0)
  elif how == "garbage-sections":
    for i in range(shoff, min(len(b), shoff + 64 * 40)):
      b[i] = (i * 151 + 17) & 0xFF
  elif how == "bad-shstrndx":
    struct.pack_into("<H", b, o_shstr, 0xFFF0)
  p = os.path.join(t, "%s.%s" % (os.path.basename(src), how))
  open(p, "wb").write(b)
  return p

bad = 0
for lib in sys.argv[2:]:
  src = os.path.join(root, lib) if not os.path.isabs(lib) else lib
  ref = facts(elf.Elf(src))
  for how in ("no-sections", "garbage-sections", "bad-shstrndx"):
    try:
      got = facts(elf.Elf(damage(src, how)))
      diff = [k for k in ref if ref[k] != got[k]]
    except Exception as ex:
      diff = ["crash: %s: %s" % (type(ex).__name__, ex)]
    print("%s %s: %s" % (os.path.basename(src), how, "PASS" if not diff else "FAIL: " + ", ".join(diff)))
    bad += bool(diff)
shutil.rmtree(t)
sys.exit(1 if bad else 0)
PY
