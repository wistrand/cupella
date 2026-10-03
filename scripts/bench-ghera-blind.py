#!/usr/bin/env python3
"""Make blinded copies of the unpacked Ghera apps for an agent-verdict benchmark.

Ghera names each app after its vulnerability and its role (X-Lean-benign is the
vulnerable app, X-Lean-secure the fixed one), and the apps call themselves "Benign"
or "Secure" in resources and log tags. An agent asked to find vulnerabilities must
see neither. This copies work/<X>-benign/ and work/<X>-secure/ to work/gh-<random>/,
replaces the app name in every text file of the copy, and replaces the standalone
words Benign and Secure (not Settings.Secure, SecureRandom, or other identifiers)
with Appx; likewise "benign" anywhere, the "secure" package, Secure as a class-name
prefix (not SecureRandom and other APIs), and the benchmark's vulnerability name.
Directory names follow. Identifiers that describe behavior (insecureFactory) stay:
they are evidence a real analyst would see too. raw/ keeps the original binary files,
so agents must not run scripts on the copies; the scripted outputs are already there.

The key (which gh- id is which app) goes to work/_ghera-blind/key.json; agents that
analyze the copies must never read it.

Usage: ./cupella bench-ghera-blind.py [seed]
"""
import json
import os
import random
import re
import shutil
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORK = os.path.join(ROOT, "work")
TEXT = (".txt", ".xml", ".java", ".smali", ".yml", ".log", ".json", ".list", ".c", ".md", ".kt")
# role markers: any "benign" (a pure benchmark artifact), the word Secure or Secured,
# Secure as a class-name prefix (not real APIs), and the "secure" package name
ROLE = [
  (re.compile(r"(?i)benign"), "appx"),
  (re.compile(r"(?<![\w.$])Secured?(?![\w$])"), "Appx"),
  (re.compile(r"(?<![\w.$])Secure(?=[A-Z])(?!Random|ClassLoader|CacheResponse|Socket)"), "Appx"),
  (re.compile(r"(?<=[./])secure(?=[./;$\"]|$)"), "appx"),
  (re.compile(r"(?<=\.)Secure(?=Permission)"), "Appx"),
]


def main():
  seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
  rng = random.Random(seed)
  names = sorted(n for n in os.listdir(WORK) if n.endswith(("-Lean-benign", "-Lean-secure")))
  pairs = sorted({n.rsplit("-", 1)[0] for n in names if n.endswith("-benign") and n[:-7] + "-secure" in names})
  apps = [p + s for p in pairs for s in ("-benign", "-secure")]
  ids = rng.sample(range(16 ** 4, 16 ** 5), len(apps))
  key = {}
  out_dir = os.path.join(WORK, "_ghera-blind")
  os.makedirs(out_dir, exist_ok=True)
  for app, i in zip(apps, ids):
    bid = "gh-%05x" % i
    dst = os.path.join(WORK, bid)
    if os.path.exists(dst):
      shutil.rmtree(dst)
    shutil.copytree(os.path.join(WORK, app), dst, symlinks=True)
    pair = app.rsplit("-", 1)[0]
    stems = [pair, pair[:-5] if pair.endswith("-Lean") else pair]
    # directory names carry the package: edu/ksu/cs/benign, edu/ksu/cs/secure
    for dp, dn, _fn in os.walk(dst, topdown=False):
      if os.path.relpath(dp, dst).split(os.sep)[0] == "raw":
        continue
      for d in dn:
        nd = re.sub(r"(?i)benign", "appx", d)
        nd = "appx" if nd == "secure" else nd
        if nd != d and not os.path.exists(os.path.join(dp, nd)):
          os.rename(os.path.join(dp, d), os.path.join(dp, nd))
    for dp, _dn, fn in os.walk(dst):
      if os.path.relpath(dp, dst).split(os.sep)[0] == "raw":
        continue
      for f in fn:
        p = os.path.join(dp, f)
        if not f.endswith(TEXT) or os.path.islink(p):
          continue
        with open(p, encoding="utf-8", errors="surrogateescape") as fh:
          s = fh.read()
        t = s.replace(app, bid)
        for stem in stems:
          t = t.replace(stem, "Appx")
        for pat, rep in ROLE:
          t = pat.sub(rep, t)
        if t != s:
          with open(p, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(t)
    key[bid] = {"app": app, "pair": app.rsplit("-", 1)[0], "role": "vulnerable" if app.endswith("-benign") else "fixed"}
  with open(os.path.join(out_dir, "key.json"), "w") as f:
    json.dump(key, f, indent=1, sort_keys=True)
  print("%d pairs, %d blinded copies; key in work/_ghera-blind/key.json" % (len(pairs), len(key)))


if __name__ == "__main__":
  main()
