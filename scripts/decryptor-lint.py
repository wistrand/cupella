#!/usr/bin/env python3
"""Reject agent-written decryptors that could run code or reach the network.

A decryptor (work/<name>/decrypt/decrypt.py) is written by an agent that has just read
malware, so it is checked before it runs: it must reimplement an algorithm, never
load, interpret, or execute anything. Parsed with ast; nothing is imported or run.

This is a filter, not a sandbox: it rejects the usual ways to run code, and the
container run-decryptor.sh uses (no network, only decrypt/ writable) is the boundary.

Allowed: a short list of standard-library modules for bytes, compression, hashes,
formats, and files (ALLOWED_MODULES), and pycryptodome (Cryptodome, as Debian installs
it). Anything else, including typing, dataclasses, functools, and pathlib, is rejected.
Rejected: subprocess and every other process, network, or loader module (ctypes,
importlib, pickle, marshal, ...); exec, eval, compile, __import__, getattr/setattr;
os.system/exec*/spawn*/popen/fork/kill; links, chmod, and copying file modes; any
dunder attribute or name other than __init__, __name__, __file__, __doc__ (no
__dict__, __class__, __builtins__, __subclasses__); operator (attrgetter and
methodcaller reach attributes without an attribute node); string.Formatter and
get_field (the same, through format fields); sys.path, sys.modules and
the import hooks; `from <module> import <banned name>`; aliasing sys; relative imports;
string literals that are paths under /proc/ or /dev/.

Known limits: a path assembled at run time ("/pr" + "oc/...") passes the string check,
and a static check cannot follow every way Python reaches an attribute. That is why
the container, not this lint, is the boundary.

Local helper modules next to decrypt.py may be imported. Every .py file under the
directory, in subdirectories too, is checked the same way; run-decryptor.sh then runs
read-only copies of the top-level ones, so the decryptor cannot rewrite a helper
before importing it.

Usage: scripts/decryptor-lint.py <decrypt-dir>     exit 1 with reasons when rejected
"""
import ast
import sys

# only what a decryptor needs: bytes, compression, hashes, formats, files. Each extra
# module is attack surface (typing, for one, evaluates annotation strings), so the list
# follows what decryptors import, not what might be handy.
ALLOWED_MODULES = {
  "base64", "binascii", "struct", "zlib", "gzip", "bz2", "lzma", "zipfile", "io", "os", "os.path", "sys",
  "re", "json", "hashlib", "hmac", "codecs", "string", "shutil", "collections", "itertools", "math", "array",
}
ALLOWED_ROOTS = {"Cryptodome"}
BANNED_NAMES = {"exec", "eval", "compile", "__import__", "globals", "locals", "vars", "breakpoint", "input",
                "getattr", "setattr", "delattr",
                # attribute access without an Attribute node (operator is not allowed either;
                # string stays for its constants, but Formatter.get_field returns attributes)
                "attrgetter", "methodcaller", "Formatter", "get_field"}
BANNED_ATTRS = {
  # processes
  "system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
  "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
  "posix_spawn", "posix_spawnp", "startfile", "fork", "forkpty", "kill", "killpg",
  # links and permissions (a link planted in decrypt/ would redirect later writes)
  "symlink", "symlink_to", "link", "link_to", "hardlink_to", "chmod", "lchmod", "chown", "lchown",
  "copymode", "copystat", "chroot",
  # the import machinery
  "modules", "meta_path", "path_hooks", "path_importer_cache",
  # attribute access through format fields (string.Formatter().get_field("0.system", ...))
  "Formatter", "get_field",
  # frames and code objects
  "_getframe", "f_globals", "f_locals", "f_builtins", "gi_frame", "cr_frame", "tb_frame", "mro",
}
ALLOWED_DUNDERS = {"__init__", "__name__", "__file__", "__doc__"}
NO_ALIAS = {"sys"}
BANNED_PATH_PARTS = ("/proc/", "/dev/")  # absolute paths only; notes may mention them


def dunder(s):
  return s.startswith("__") and s not in ALLOWED_DUNDERS


def check(tree, local=()):
  problems = []
  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for a in node.names:
        if a.name not in ALLOWED_MODULES and a.name.split(".")[0] not in ALLOWED_ROOTS and a.name not in local:
          problems.append("line %d: import %s" % (node.lineno, a.name))
        if a.asname and a.name in NO_ALIAS:
          problems.append("line %d: import %s as %s (aliasing %s)" % (node.lineno, a.name, a.asname, a.name))
    elif isinstance(node, ast.ImportFrom):
      mod = node.module or ""
      if node.level:
        problems.append("line %d: relative import" % node.lineno)
      elif mod not in ALLOWED_MODULES and mod.split(".")[0] not in ALLOWED_ROOTS and mod not in local:
        problems.append("line %d: from %s import" % (node.lineno, mod))
      for a in node.names:
        if a.name == "*" or a.name in BANNED_NAMES or a.name in BANNED_ATTRS or dunder(a.name) \
           or (mod == "sys" and a.name == "path"):
          problems.append("line %d: from %s import %s" % (node.lineno, mod, a.name))
    elif isinstance(node, ast.Name):
      if node.id in BANNED_NAMES or dunder(node.id):
        problems.append("line %d: %s" % (node.lineno, node.id))
    elif isinstance(node, ast.Attribute):
      if node.attr in BANNED_ATTRS or dunder(node.attr):
        problems.append("line %d: .%s" % (node.lineno, node.attr))
      elif node.attr == "path" and isinstance(node.value, ast.Name) and node.value.id == "sys":
        problems.append("line %d: sys.path" % node.lineno)
    elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
      v = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
      if v.lstrip().startswith(BANNED_PATH_PARTS):
        problems.append("line %d: string naming %s" % (node.lineno, v[:40]))
  return problems


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  import os
  d = sys.argv[1]
  files = []
  for dp, dn, fn in os.walk(d):
    dn[:] = sorted(dn)
    files += sorted(os.path.relpath(os.path.join(dp, f), d) for f in fn if f.endswith(".py"))
  local = {f[:-3] for f in files if os.sep not in f}
  problems = []
  for f in files:
    try:
      tree = ast.parse(open(os.path.join(d, f), encoding="utf-8", errors="replace").read())
    except SyntaxError as ex:
      problems.append("%s does not parse: %s" % (f, ex))
      continue
    problems += ["%s %s" % (f, p) for p in check(tree, local)]
  if problems:
    print("decryptor rejected:")
    for p in problems:
      print("  " + p)
    sys.exit(1)
  print("decryptor lint: ok")


if __name__ == "__main__":
  main()
