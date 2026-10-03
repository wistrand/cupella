#!/usr/bin/env python3
"""Index and condense blutter output (work/<name>/dart/asm) for a Flutter app.

blutter writes annotated arm64 assembly per Dart library: several lines per
instruction, tens of thousands of lines for an app. This script gives the map
(which function is where, what it calls, which strings it uses) and a condensed
listing of chosen functions that keeps the pseudo-code lines and drops the rest.

Usage:
  scripts/dart-index.py <name>                      index of the app's own package
  scripts/dart-index.py <name> --package <pkg>      index of another package
  scripts/dart-index.py <name> --func <pattern>     condensed body of matching functions
                                                    (substring of "Class::name"; app package
                                                    first, add --all to search every package)
  scripts/dart-index.py <name> --outline <pattern>  the same functions reduced to string
                                                    literals and calls outside dart:core
  scripts/dart-index.py <name> --callers <pattern>  functions calling a target whose
                                                    "[library] Class::name" matches the regex
  scripts/dart-index.py <name> --strings <regex>    functions loading a matching string literal
Options: --all  search all packages, not only the app's own
"""
import os
import re
import sys

FUNC_ADDR = re.compile(r"^\s+// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)")
PSEUDO = re.compile(r"^\s+// (0x[0-9a-f]+): (.*)$")
RAW = re.compile(r"^\s+//\s{3,}(0x[0-9a-f]+): (.*)$")
CLASS = re.compile(r"^(?:abstract |sealed |final |base |mixin )*(?:class|enum|mixin|extension) (\S+)")
CALL_TARGET = re.compile(r"; \[([^\]]+)\] (\S.*)$")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
BOILERPLATE = re.compile(
  r"^(EnterFrame|LeaveFrame|AllocStack\(|CheckStackOverflow|DecompressPointer |"
  r"r16 = Sentinel|ret$|SaveReg |RestoreReg |PushArgs|InitAsync\(\)$)")
STUB_CALL = re.compile(r"^r\d+ = (Allocate\w*|AllocateArray|Throw|ReThrow|StackOverflowSharedWith\w*|"
                       r"LateInitializationError\w*|RangeError\w*|NullCastError\w*|NullError\w*|"
                       r"ArrayWriteBarrier|WriteBarrier\w*|Await|ReturnAsync\w*|InitLateStaticField\w*|"
                       r"\w*TypeTest\w*|InstantiateType\w*|BoxInt64|BoxDouble|DefaultTypeTest)\(\)")
NOISE_LIB = re.compile(r"^(dart:|package:flutter/)")


class Func:
  __slots__ = ("lib", "file", "cls", "sig", "name", "addr", "size", "line", "calls", "strings", "body")

  def __init__(self, lib, file, cls, sig, line):
    self.lib, self.file, self.cls, self.sig, self.line = lib, file, cls, sig, line
    m = re.search(r"([\w$<>=\[\]+\-*/~&|^%!.]+)\s*\(", sig.replace("[closure] ", ""))
    self.name = m.group(1) if m else sig.strip()[:40]
    if "[closure]" in sig:
      self.name = "<closure> " + self.name.replace("closure>", "").strip()
    self.addr = self.size = 0
    self.calls, self.strings, self.body = [], [], []

  @property
  def qual(self):
    return "%s::%s" % (self.cls or "", self.name)


def parse_file(path, rel, keep_body):
  funcs, cls, lib, cur = [], "", "", None
  with open(path, encoding="utf-8", errors="replace") as f:
    for no, line in enumerate(f, 1):
      if no == 1:
        m = re.search(r"url: (\S+)", line)
        lib = m.group(1) if m else rel
        continue
      if line.startswith(("class ", "abstract ", "enum ", "mixin ", "sealed ", "final ", "base ", "extension ")):
        m = CLASS.match(line)
        cls = m.group(1) if m else ""
        if cls == "::":
          cls = ""
        cur = None
        continue
      if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith("{") \
          and not line.lstrip().startswith("//"):
        cur = Func(lib, rel, cls, line.strip()[:-1].strip(), no)
        funcs.append(cur)
        continue
      if cur is None:
        continue
      m = FUNC_ADDR.match(line)
      if m:
        cur.addr, cur.size = int(m.group(1), 16), int(m.group(2), 16)
        continue
      m = RAW.match(line)
      if m:
        t = CALL_TARGET.search(m.group(2))
        if t and re.match(r"bl?\s", m.group(2)):
          cur.calls.append((t.group(1), t.group(2)))
          if keep_body and cur.body:
            cur.body[-1] = (cur.body[-1][0], cur.body[-1][1] + "   ; [%s] %s" % (t.group(1), t.group(2)))
        continue
      m = PSEUDO.match(line)
      if m:
        text = m.group(2)
        for s in STRING.findall(text):
          cur.strings.append(s)
        if keep_body:
          cur.body.append((m.group(1), text))
  return funcs


def load(name, packages, keep_body=False):
  root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name, "dart", "asm")
  if not os.path.isdir(root):
    sys.exit("no blutter output: run scripts/flutter-decompile.sh %s (see agent_docs/runbook-flutter.md)" % name)
  all_pkgs = sorted(os.listdir(root))
  funcs = []
  for pkg in (all_pkgs if packages is None else packages):
    base = os.path.join(root, pkg)
    for dp, _dn, fn in os.walk(base):
      for f in sorted(fn):
        p = os.path.join(dp, f)
        funcs.extend(parse_file(p, os.path.relpath(p, root), keep_body))
  return funcs, all_pkgs, root


def app_package(name, all_pkgs):
  mf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name, "manifest.xml")
  if os.path.exists(mf):
    with open(mf) as f:
      m = re.search(r' package="([^"]+)"', f.read(4000))
    if m:
      for part in reversed(m.group(1).split(".")):
        if part in all_pkgs:
          return part
  return None


def pkg_of(lib):
  m = re.match(r"package:([^/]+)/", lib)
  return m.group(1) if m else lib.split(":")[0] + ":"


def index(name, funcs, all_pkgs, pkg, root):
  print("# Dart index: %s, package %s" % (name, pkg))
  print("From blutter output in work/%s/dart/asm. Addresses are in libapp.so." % name)
  print("Condensed body of a function: scripts/dart-index.py %s --func <Class::name>\n" % name)
  print("## All packages (%d)" % len(all_pkgs))
  print(", ".join(all_pkgs))

  by_file = {}
  for f in funcs:
    by_file.setdefault(f.file, []).append(f)
  print("\n## Files and classes")
  for file, fs in sorted(by_file.items()):
    classes = {}
    for f in fs:
      classes.setdefault(f.cls, []).append(f)
    print("- %s: %d functions in %d classes" % (file, len(fs), len(classes)))

  print("\n## Calls out of the package, by target package")
  print("Which app functions use which dependency. Flutter and dart: core omitted.")
  out = {}
  for f in funcs:
    for lib, target in f.calls:
      p = pkg_of(lib)
      if p == pkg or NOISE_LIB.match(lib):
        continue
      out.setdefault(p, {}).setdefault(f.qual, set()).add(target.split("(")[0])
  for p, callers in sorted(out.items()):
    print("\n### %s (%d calling functions)" % (p, len(callers)))
    for caller, targets in sorted(callers.items()):
      t = sorted(targets)
      print("- %s -> %s%s" % (caller, ", ".join(t[:6]), " ..." if len(t) > 6 else ""))

  print("\n## dart:io and dart:ffi use")
  for f in funcs:
    hits = sorted({t.split("(")[0] for lib, t in f.calls if lib in ("dart:io", "dart:ffi", "dart:_http")})
    if hits:
      print("- %s -> %s%s" % (f.qual, ", ".join(hits[:8]), " ..." if len(hits) > 8 else ""))

  print("\n## Functions")
  print("addr, size, asm line, then string literals the function loads.")
  for file, fs in sorted(by_file.items()):
    print("\n### %s" % file)
    last = None
    for f in fs:
      if f.cls != last:
        print("\nclass %s" % (f.cls or "(top level)"))
        last = f.cls
      strs = []
      for s in f.strings:
        if s not in strs and len(s) > 1:
          strs.append(s)
      tail = ""
      if strs:
        shown = ['"%s"' % s[:60] for s in strs[:8]]
        tail = "  " + " ".join(shown) + (" ..." if len(strs) > 8 else "")
      print("  0x%-7x %5d  L%-6d %s%s" % (f.addr, f.size, f.line, f.name[:60], tail))


CORE_CALL = re.compile(r"; \[dart:(core|_internal|_compact_hash|collection|typed_data|async)\]")


def outline(f):
  print("\n// ---- %s  [%s]  addr 0x%x size %d  (%s line %d)" % (
    f.qual, f.lib, f.addr, f.size, f.file, f.line))
  for addr, text in f.body:
    is_call = "   ; [" in text and not CORE_CALL.search(text)
    if is_call or STRING.search(text.split("   ; [")[0]):
      print("  %s  %s" % (addr[2:], text))


def condensed(f):
  print("\n// ---- %s  [%s]  addr 0x%x size %d  (%s line %d)" % (
    f.qual, f.lib, f.addr, f.size, f.file, f.line))
  print("// %s" % f.sig[:200])
  skipped = 0
  for addr, text in f.body:
    core = text.split("   ; [")[0]
    if BOILERPLATE.match(core) or STUB_CALL.match(core):
      skipped += 1
      continue
    print("  %s  %s" % (addr[2:], text))
  print("// (%d boilerplate lines omitted; full text in the asm file)" % skipped)


def main():
  args = sys.argv[1:]
  if not args or args[0].startswith("-"):
    sys.exit(__doc__)
  name = args[0]
  search_all = "--all" in args
  args = [a for a in args[1:] if a != "--all"]
  root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name, "dart", "asm")
  if not os.path.isdir(root):
    sys.exit("no blutter output: run scripts/flutter-decompile.sh %s (see agent_docs/runbook-flutter.md)" % name)
  all_pkgs = sorted(os.listdir(root))
  app = app_package(name, all_pkgs)

  mode = args[0] if args else "--index"
  if mode == "--package":
    pkg = args[1]
    funcs, _, _ = load(name, [pkg])
    index(name, funcs, all_pkgs, pkg, root)
    return
  if mode == "--index":
    if app is None:
      sys.exit("could not tell the app's own package; choose one with --package from: " + ", ".join(all_pkgs))
    funcs, _, _ = load(name, [app])
    index(name, funcs, all_pkgs, app, root)
    return

  pattern = args[1]
  scope = None if search_all or app is None else [app]
  if mode in ("--func", "--outline"):
    funcs, _, _ = load(name, scope, keep_body=True)
    hits = [f for f in funcs if pattern in f.qual]
    if not hits:
      print("no function matching %s%s" % (pattern, "" if search_all else " in the app package (try --all)"))
    for f in hits[:40]:
      (condensed if mode == "--func" else outline)(f)
    if len(hits) > 40:
      print("\n// %d more matches not shown; narrow the pattern" % (len(hits) - 40))
  elif mode == "--callers":
    rx = re.compile(pattern)
    funcs, _, _ = load(name, scope)
    for f in funcs:
      targets = sorted({"[%s] %s" % (lib, t.split("(")[0]) for lib, t in f.calls if rx.search("[%s] %s" % (lib, t))})
      if targets:
        print("%s  (%s L%d) -> %s" % (f.qual, f.file, f.line, "; ".join(targets[:5])))
  elif mode == "--strings":
    rx = re.compile(pattern)
    funcs, _, _ = load(name, scope)
    for f in funcs:
      strs = sorted({s for s in f.strings if rx.search(s)})
      if strs:
        print("%s  (%s L%d): %s" % (f.qual, f.file, f.line, " | ".join('"%s"' % s[:80] for s in strs[:6])))
  else:
    sys.exit(__doc__)


if __name__ == "__main__":
  main()
