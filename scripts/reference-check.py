#!/usr/bin/env python3
"""Compare native libraries of an unpacked APK against public reference material.

Two checks, each run when it applies:

  flutter-engine  libflutter.so against the official engine artifact for the engine
                  commit embedded in it. Byte-identical means the stock engine.
  pub-sources     libraries whose build paths name a pub.dev package and version
                  (".pub-cache/hosted/pub.dev/<pkg>-<ver>/") against that package's
                  published sources: are the exported functions and the string
                  literals of the binary present in those sources? This shows
                  consistency with the sources, not a reproducible build.

NETWORK: this script downloads from a fixed list of public registries and nowhere
else: storage.googleapis.com/download.flutter.io and pub.dev/api/archives. Every
redirect is checked against the same list before it is followed, and so is the final
URL; a redirect anywhere else is refused and reported.
It sends only public identifiers taken from the binary (an engine commit hash, a
package name and version). It never contacts hosts named inside the APK. At most
MAX_LOOKUPS (50) downloads per run; a failed lookup is reported and the run goes on.
Downloads are cached in work/_reference/.

Usage: scripts/reference-check.py <name> [flutter-engine|pub-sources]
       (output is meant to be saved as work/<name>/reference-check.txt)
"""
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import Elf  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CACHE = os.path.join(ROOT, "work", "_reference")
ALLOWED = ("https://storage.googleapis.com/download.flutter.io/", "https://pub.dev/api/archives/")
ENGINE_ABI = {"arm64-v8a": "arm64_v8a", "armeabi-v7a": "armeabi_v7a", "x86_64": "x86_64", "x86": "x86"}
SRC_EXT = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".m", ".mm", ".S", ".s",
           ".rs", ".go", ".dart", ".cmake", ".txt", ".def")
REDIRECT_ALLOWED = ALLOWED  # a redirect elsewhere is refused and reported
MAX_DOWNLOAD = 400 * 1024 * 1024
MAX_LOOKUPS = 50
lookups = 0
PUB_PATH = re.compile(rb"\.pub-cache/hosted/pub\.dev/([A-Za-z0-9_]+)-(\d+\.\d+\.\d+[\w.+-]*)/")
SKIP_SYM = re.compile(r"^(std::|__|operator|typeinfo |vtable |VTT |guard variable|non-virtual thunk|"
                      r"virtual thunk|construction vtable|_Unwind|__cxa|__gnu|__aeabi|__emutls|"
                      r"_fini|_init|__bss|_edata|_end)")


class AllowListRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    if not newurl.startswith(REDIRECT_ALLOWED):
      raise ValueError("refusing redirect outside the allow-list: " + newurl)
    return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(AllowListRedirect)


def fetch(url, dest):
  """200 when dest holds the download, else a short reason (HTTP status, error, cap)."""
  global lookups
  if not url.startswith(ALLOWED):
    raise ValueError("refusing to fetch outside the allow-list: " + url)
  if os.path.exists(dest):
    return 200
  if lookups >= MAX_LOOKUPS:
    return "skipped: cap of %d lookups per run reached" % MAX_LOOKUPS
  lookups += 1
  os.makedirs(os.path.dirname(dest), exist_ok=True)
  req = urllib.request.Request(url, headers={"User-Agent": "cupella-reference-check"})
  try:
    with OPENER.open(req, timeout=120) as r:
      if not r.geturl().startswith(REDIRECT_ALLOWED):
        raise ValueError("final URL outside the allow-list: " + r.geturl())
      data = r.read(MAX_DOWNLOAD + 1)
      if len(data) > MAX_DOWNLOAD:
        raise ValueError("download larger than the cap")
      with open(dest + ".part", "wb") as f:
        f.write(data)
      os.replace(dest + ".part", dest)
      return r.status if r.status == 200 else "HTTP %s" % r.status
  except urllib.error.HTTPError as e:
    return "HTTP %s" % e.code
  except urllib.error.URLError as e:
    return "error: %s" % e.reason
  except (OSError, ValueError) as e:  # timeouts, resets, over-cap, refused redirect
    return "error: %s" % e


def sha256(path):
  h = hashlib.sha256()
  with open(path, "rb") as f:
    for block in iter(lambda: f.read(1 << 20), b""):
      h.update(block)
  return h.hexdigest()


def abis(name):
  lib = os.path.join(ROOT, "work", name, "raw", "lib")
  return {a: os.path.join(lib, a) for a in sorted(os.listdir(lib))} if os.path.isdir(lib) else {}


def check_flutter_engine(name):
  print("## Flutter engine")
  found = False
  for abi, d in abis(name).items():
    path = os.path.join(d, "libflutter.so")
    if not os.path.exists(path) or abi not in ENGINE_ABI:
      continue
    found = True
    with open(path, "rb") as f:
      buf = f.read()
    ours = hashlib.sha256(buf).hexdigest()
    hashes = sorted(set(m.decode() for m in re.findall(rb"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", buf)))
    print("- %s/libflutter.so: %d bytes, sha256 %s" % (abi, len(buf), ours))
    print("  commit-like hashes embedded: %s" % (", ".join(hashes) or "none"))
    matched = False
    for h in hashes:
      art = "%s_release" % ENGINE_ABI[abi]
      url = "https://storage.googleapis.com/download.flutter.io/io/flutter/%s/1.0.0-%s/%s-1.0.0-%s.jar" % (art, h, art, h)
      dest = os.path.join(CACHE, "flutter-engine", "%s-%s.jar" % (art, h))
      status = fetch(url, dest)
      if status != 200:
        print("  %s: no official release artifact (%s)" % (h, status))
        continue
      try:
        with zipfile.ZipFile(dest) as z:
          ref = z.read("lib/%s/libflutter.so" % abi)
      except (KeyError, zipfile.BadZipFile) as ex:
        print("  %s: artifact unreadable (%s)" % (h, ex))
        continue
      theirs = hashlib.sha256(ref).hexdigest()
      if theirs == ours:
        matched = True
        print("  %s: IDENTICAL to the official release engine for this commit" % h)
        print("    source: %s" % url)
      else:
        print("  %s: official artifact exists but DIFFERS (official %d bytes sha256 %s)" % (h, len(ref), theirs))
    if not matched:
      print("  => not shown to be a stock engine: a custom, patched, or non-release build, "
            "or a commit without a published artifact")
  if not found:
    print("- no libflutter.so: not a Flutter app")


def demangle(names):
  try:
    out = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True,
                         timeout=60).stdout.split("\n")
    return dict(zip(names, out))
  except (OSError, subprocess.SubprocessError):
    return {n: n for n in names}


def base_identifier(dem):
  """llama_context::graph_build(ggml_context*) -> graph_build; skip runtime symbols."""
  if SKIP_SYM.match(dem):
    return None
  name = dem.split("(")[0]
  for _ in range(6):  # drop template arguments, innermost first
    name = re.sub(r"<[^<>]*>", "", name)
  name = name.strip().split(" ")[-1]  # drop a leading return type
  if SKIP_SYM.match(name):
    return None
  last = name.split("::")[-1]
  if last.startswith("~"):
    last = last[1:]
  if not re.match(r"^[A-Za-z_]\w*$", last) or last.startswith("operator"):
    return None
  return last


FMT = re.compile(r"%[-+ #0-9.*]*(?:hh|h|ll|l|z|j|t|L)?[a-zA-Z]")
RUNTIME_STR = re.compile(r"DWARF|DW_EH_PE|DW_OP|\bCIE\b|\bFDE\b|libunwind|libc\+\+abi|terminat(e|ing)|unwind|"
                         r"_Unwind|personality|typeinfo|std::|basic_string|vector|out_of_range|bad_|"
                         r"__cxa|pure virtual|demangl|ios_base|locale|regex_error|"
                         r"The (state|future|associated)|recursive_|condition_variable|mutex|thread::")


SENSITIVE = re.compile(r"(?:https?|wss?|ftp)://|(?<![\w.])/(?:data|proc|system|sdcard|storage|dev)/|"
                       r"\b(?:sh|su|bash) -c\b|\bpm (?:install|uninstall|grant)\b|\bam start\b|"
                       r"\bchmod \d|\bcurl \b|\bwget \b|(?:\d{1,3}\.){3}\d{1,3}")


def normalize(text):
  return re.sub(r"\s+", " ", text)


def literal_in_sources(s, norm):
  """A binary string matches when every fragment between format specifiers appears in
  the sources. Sources are normalized: adjacent literals joined, whitespace collapsed,
  so wrapped literals, PRId64-style macros, and stringified assert expressions match."""
  frags = [normalize(f).strip() for f in FMT.split(s)]
  frags = [f for f in frags if len(f) >= 6]
  if not frags:
    return None  # nothing distinctive to test
  return all(f in norm for f in frags)


def load_corpus(src_root):
  texts, files = [], 0
  for dp, _dn, fn in os.walk(src_root):
    for f in fn:
      if f.endswith(SRC_EXT):
        try:
          with open(os.path.join(dp, f), encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read())
          files += 1
        except OSError:
          pass
  corpus = "\n".join(texts)
  return corpus, set(re.findall(r"[A-Za-z_]\w*", corpus)), files


def check_pub_sources(name):
  print("## Libraries built from pub.dev packages")
  all_abis = abis(name)
  abi = next((a for a in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86") if a in all_abis), None)
  if abi is None:
    print("- no native libraries")
    return
  by_pkg = {}
  for f in sorted(os.listdir(all_abis[abi])):
    path = os.path.join(all_abis[abi], f)
    with open(path, "rb") as fh:
      buf = fh.read()
    for pkg, ver in set(PUB_PATH.findall(buf)):
      by_pkg.setdefault((pkg.decode(), ver.decode()), []).append(path)
    roots = sorted(set(m.decode() for m in re.findall(rb"(/(?:home|Users|root|builds?|workspace|__w)/[\w.-]+)/", buf)))
    if roots:
      print("- %s: build paths under %s" % (f, ", ".join(roots[:4])))
  if not by_pkg:
    print("- no library carries a pub.dev build path (nothing to compare)")
    return

  for (pkg, ver), libs in sorted(by_pkg.items()):
    print("\n### %s %s" % (pkg, ver))
    url = "https://pub.dev/api/archives/%s-%s.tar.gz" % (pkg, ver)
    dest = os.path.join(CACHE, "pub", "%s-%s.tar.gz" % (pkg, ver))
    status = fetch(url, dest)
    if status != 200:
      print("- package archive not available (%s): %s" % (status, url))
      continue
    src = os.path.join(CACHE, "pub", "%s-%s" % (pkg, ver))
    if not os.path.isdir(src):
      with tarfile.open(dest) as t:
        t.extractall(src, filter="data")
    print("- published archive: %s (sha256 %s)" % (url, sha256(dest)))
    corpus, idents, nfiles = load_corpus(src)
    print("- %d source files in the package" % nfiles)
    prebuilt = [os.path.relpath(os.path.join(dp, f), src) for dp, _d, fn in os.walk(src) for f in fn
                if f.endswith((".so", ".a", ".dylib", ".dll", ".framework"))]
    print("- prebuilt binaries shipped in the package: %s" % (", ".join(prebuilt[:6]) if prebuilt else "none (built from source)"))
    joined = re.sub(r'"\s*(?:[A-Z][A-Z0-9_]*\s*)?"', "", corpus)  # "a" "b" and "a" PRId64 "b"
    norm = normalize(joined.replace('\\"', '"') + "\n" + corpus.replace('\\"', '"'))

    for path in libs:
      e = Elf(path)
      names = [s.name for s in e.exports if s.is_func]
      dem = demangle(names)
      project, missing = 0, []
      for n in names:
        ident = base_identifier(dem.get(n, n))
        if ident is None:
          continue
        project += 1
        if ident not in idents:
          missing.append(dem.get(n, n))
      print("\n- %s" % os.path.basename(path))
      print("  exported functions (excluding C++ runtime): %d; name found in package sources: %d (%.1f%%)" % (
        project, project - len(missing), 100.0 * (project - len(missing)) / project if project else 0))
      for m in missing[:12]:
        print("    not in sources: %s" % m[:140])
      if len(missing) > 12:
        print("    ... +%d more" % (len(missing) - 12))

      cands = sorted(x for x in e.strings(16) if " " in x.strip() and "/" not in x[:2]
                     and not x.startswith(("GCC:", "Android (", "clang version", "Linker:")))
      runtime = [x for x in cands if RUNTIME_STR.search(x)]
      cands = [x for x in cands if not RUNTIME_STR.search(x)]
      step = max(1, len(cands) // 1500)
      hit, miss = [], []
      for x in cands[::step]:
        r = literal_in_sources(x, norm)
        if r is True:
          hit.append(x)
        elif r is False:
          miss.append(x)
      tested = len(hit) + len(miss)
      print("  string literals tested: %d; found in package sources: %d (%.1f%%); %d C++ runtime strings set aside" % (
        tested, len(hit), 100.0 * len(hit) / tested if tested else 0, len(runtime)))
      flagged = [x for x in miss if SENSITIVE.search(x)]
      print("  unmatched literals that look like URLs, paths, or commands: %s" % (
        "none" if not flagged else len(flagged)))
      for m in flagged[:20]:
        print("    CHECK: %s" % m.strip()[:140])
      for m in [x for x in miss if x not in flagged][:10]:
        print("    not in sources: %s" % m.strip()[:120])
      if len(miss) > 10:
        print("    ... +%d more" % (len(miss) - 10))
  print("\nReading the numbers: near-complete name coverage and a high share of matching")
  print("literals mean the binary is consistent with these sources. Unmatched literals are")
  print("leads: read them. Text assembled by macros, data tables, and statically linked")
  print("runtime code account for ordinary misses; a URL, command, or path that is not in")
  print("the sources does not. None of this proves the binary was built from the sources")
  print("unmodified; that needs a reproducible build.")


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name = sys.argv[1]
  which = sys.argv[2] if len(sys.argv) > 2 else "all"
  if not os.path.isdir(os.path.join(ROOT, "work", name, "raw")):
    sys.exit("work/%s/raw not found: run scripts/unpack.sh first" % name)
  print("# Reference check: %s" % name)
  print("Compared against public registries only (see the script header for the allow-list).\n")
  if which in ("all", "flutter-engine"):
    check_flutter_engine(name)
    print()
  if which in ("all", "pub-sources"):
    check_pub_sources(name)
  print("\n%d network lookups (cap %d per run; cached downloads not counted)" % (lookups, MAX_LOOKUPS))


if __name__ == "__main__":
  main()
