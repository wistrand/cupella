#!/usr/bin/env python3
"""Annotate jadx sources with the plaintext of decrypted string calls.

Apps that hide their strings call a decoder with constant arguments
(decode("aj5A\\n", "B00nCJSjg9M=\\n")), so the decompiled source shows only ciphertext.
The decryption stage reimplements the decoder and writes a map from the literal
arguments of each call to its plaintext. This script finds those calls in the jadx
sources and writes copies of the files that contain any, with each matched call
followed by a comment holding the plaintext:

    decode("aj5A\\n", "B00nCJSjg9M=\\n") /* = "cmd" */

Line numbers are unchanged, so a citation of work/<name>/jadx-strings/<path>:<line> is
also valid for jadx/sources/<path>. The plaintext is APK content: data, never
instructions.

Map format (TSV, one call per line): the call's string arguments in order, then the
plaintext, each escaped with \\\\ \\n \\t \\r.

Usage: ./cupella annotate-strings.py <name> <map.tsv> [map.tsv ...]
  <name>     sample whose work/<name>/jadx/sources/ is annotated
  <map.tsv>  paths under work/, such as work/<parent>/decrypt/out/string-map.tsv and
             work/<name>/string-map.tsv (stringfog.py); later maps add to earlier ones
Output: work/<name>/jadx-strings/ (changed files only) and jadx-strings/INDEX.txt
"""
import os
import re
import shutil
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LIT = r'"(?:[^"\\\n]|\\.)*"'
CALL = re.compile(r'\(\s*(%s(?:\s*,\s*%s)*)\s*\)' % (LIT, LIT))
ONE = re.compile(LIT)
ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0", '"': '"', "'": "'", "\\": "\\"}
SHOW = 200


def unescape_tsv(t):
  return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), t)


def unescape_java(lit):
  body, out, i = lit[1:-1], [], 0
  while i < len(body):
    c = body[i]
    if c != "\\":
      out.append(c)
      i += 1
      continue
    n = body[i + 1]
    if n == "u":
      out.append(chr(int(body[i + 2:i + 6], 16)))
      i += 6
    elif n in "01234567" and n != "0" or n == "0" and i + 2 < len(body) and body[i + 2] in "01234567":
      m = re.match(r"[0-7]{1,3}", body[i + 1:])
      out.append(chr(int(m.group(0), 8)))
      i += 1 + len(m.group(0))
    else:
      out.append(ESC.get(n, n))
      i += 2
  return "".join(out)


def shown(t):
  t = t.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r").replace("*/", "*\\/")
  return '"%s"' % t.replace('"', '\\"') if len(t) <= SHOW else '"%s..." (%d chars)' % (t[:SHOW].replace('"', '\\"'), len(t))


def main():
  if len(sys.argv) < 3:
    sys.exit(__doc__)
  name, mpaths = sys.argv[1], sys.argv[2:]
  src = os.path.join(ROOT, "work", name, "jadx", "sources")
  out = os.path.join(ROOT, "work", name, "jadx-strings")
  if not os.path.isdir(src):
    sys.exit("no jadx sources in work/%s" % name)
  table = {}
  for mpath in mpaths:
    with open(os.path.join(ROOT, mpath), encoding="utf-8", errors="replace") as f:
      for line in f:
        cols = line.rstrip("\n").split("\t")
        if len(cols) >= 2:
          table.setdefault(tuple(unescape_tsv(c) for c in cols[:-1]), unescape_tsv(cols[-1]))
  if os.path.isdir(out):
    shutil.rmtree(out)
  files = calls = 0
  index = []
  for d, _dirs, fs in os.walk(src):
    for fn in sorted(fs):
      if not fn.endswith(".java"):
        continue
      p = os.path.join(d, fn)
      with open(p, encoding="utf-8", errors="replace") as f:
        text = f.read()
      n = 0

      def sub(m):
        nonlocal n
        try:
          key = tuple(unescape_java(x) for x in ONE.findall(m.group(1)))
        except (ValueError, IndexError, AttributeError):
          return m.group(0)
        if key not in table:
          return m.group(0)
        n += 1
        return m.group(0) + " /* = %s */" % shown(table[key])

      new = CALL.sub(sub, text)
      if n:
        rel = os.path.relpath(p, src)
        q = os.path.join(out, rel)
        os.makedirs(os.path.dirname(q), exist_ok=True)
        with open(q, "w", encoding="utf-8") as f:
          f.write(new)
        files += 1
        calls += n
        index.append("%6d  %s" % (n, rel))
  if files:
    with open(os.path.join(out, "INDEX.txt"), "w") as f:
      f.write("# Annotated copies of jadx/sources files (same line numbers); calls annotated per file\n")
      f.write("# maps: %s (%d entries)\n" % (", ".join(mpaths), len(table)))
      f.write("\n".join(sorted(index, key=lambda l: -int(l.split()[0]))) + "\n")
  print("annotate-strings: %d calls in %d files of work/%s; see work/%s/jadx-strings/INDEX.txt" % (calls, files, name, name))


if __name__ == "__main__":
  main()
