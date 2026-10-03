#!/usr/bin/env python3
"""Reject agent-written decryptors that could run code or reach the network.

A decryptor (work/<name>/decrypt/decrypt.py) is written by an agent that has just read
malware, so it is checked before it runs: it must reimplement an algorithm, never
load, interpret, or execute anything. Parsed with ast; nothing is imported or run.

Allowed: standard-library modules for bytes, math, files, and formats; pycryptodome
(Cryptodome, as Debian installs it; Crypto also accepted); subprocess only with a literal argument list starting with "openssl".
Rejected: exec, eval, compile, __import__, getattr on modules, importlib, ctypes,
network and process modules, os.system/exec*/spawn*/popen, pickle/marshal, and any
call through subprocess other than openssl.

Local helper modules next to decrypt.py may be imported; every .py file in that
directory is checked the same way.

Usage: scripts/decryptor-lint.py <decrypt-dir>     exit 1 with reasons when rejected
"""
import ast
import sys

ALLOWED_MODULES = {
  "base64", "binascii", "struct", "zlib", "gzip", "bz2", "lzma", "zipfile", "io", "os", "os.path", "sys",
  "re", "json", "hashlib", "hmac", "itertools", "functools", "collections", "math", "string", "codecs",
  "pathlib", "glob", "shutil", "typing", "dataclasses", "array", "textwrap", "subprocess", "xml",
  "xml.etree", "xml.etree.ElementTree", "html", "unicodedata", "operator", "enum", "secrets",
}
ALLOWED_ROOTS = {"Crypto", "Cryptodome"}
BANNED_NAMES = {"exec", "eval", "compile", "__import__", "globals", "locals", "vars", "breakpoint", "input"}
BANNED_ATTRS = {"system", "popen", "execv", "execve", "execvp", "execl", "execlp", "spawnv", "spawnl",
                "startfile", "fork", "forkpty", "kill", "symlink", "link", "chmod", "chown"}


def openssl_list(n):
  return isinstance(n, (ast.List, ast.Tuple)) and n.elts and isinstance(n.elts[0], ast.Constant) \
    and n.elts[0].value == "openssl"


def check(tree, local=()):
  problems = []
  # names only ever assigned a literal list that starts with "openssl"
  assigned = {}
  for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
      for t in node.targets:
        if isinstance(t, ast.Name):
          assigned.setdefault(t.id, []).append(openssl_list(node.value))
  openssl_names = {k for k, v in assigned.items() if all(v)}

  def is_openssl(n):
    if openssl_list(n):
      return True
    if isinstance(n, ast.Name):
      return n.id in openssl_names
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
      return is_openssl(n.left)
    return False

  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for a in node.names:
        if a.name not in ALLOWED_MODULES and a.name.split(".")[0] not in ALLOWED_ROOTS and a.name not in local:
          problems.append("line %d: import %s" % (node.lineno, a.name))
    elif isinstance(node, ast.ImportFrom):
      mod = node.module or ""
      if mod not in ALLOWED_MODULES and mod.split(".")[0] not in ALLOWED_ROOTS and mod not in local:
        problems.append("line %d: from %s import" % (node.lineno, mod))
    elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
      problems.append("line %d: %s" % (node.lineno, node.id))
    elif isinstance(node, ast.Attribute) and node.attr in BANNED_ATTRS:
      problems.append("line %d: .%s" % (node.lineno, node.attr))
    elif isinstance(node, ast.Call):
      f = node.func
      name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
      owner = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
      if owner == "subprocess" or name in ("run", "check_output", "check_call", "call", "Popen") and owner == "subprocess":
        args = node.args[0] if node.args else None
        if args is None or not is_openssl(args):
          problems.append("line %d: subprocess call that does not start with a literal \"openssl\"" % node.lineno)
        for kw in node.keywords:
          if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
            problems.append("line %d: subprocess with shell" % node.lineno)
      if name == "getattr" and node.args and isinstance(node.args[0], ast.Name):
        problems.append("line %d: getattr on a name (dynamic attribute access)" % node.lineno)
  return problems


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  import os
  d = sys.argv[1]
  files = sorted(f for f in os.listdir(d) if f.endswith(".py"))
  local = {f[:-3] for f in files}
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
