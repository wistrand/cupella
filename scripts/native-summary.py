#!/usr/bin/env python3
"""Summarize the native libraries of an unpacked APK: what each library is, how Java
reaches it, what it imports, and what in it deserves a closer look.

Static only: nothing is loaded or executed. One ABI is analyzed in detail (arm64-v8a
when present); the others are compared against it for consistency.

Usage: scripts/native-summary.py <name> > work/<name>/native-summary.txt
       scripts/native-summary.py --file <path/to/lib.so>     (one library, no APK context)
"""
import hashlib
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import Elf  # noqa: E402

ABI_ORDER = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]

# Library file name -> what it is. Names only; the content is not fingerprinted.
KNOWN_LIBS = [
  (r"^libflutter\.so$", "Flutter engine. App logic is Dart AOT code in libapp.so"),
  (r"^libapp\.so$", "Flutter app code (Dart AOT snapshot). jadx shows only the host shell"),
  (r"^libil2cpp\.so$", "Unity IL2CPP: the game's C# compiled to native. Metadata in assets/bin/Data/Managed/Metadata/global-metadata.dat"),
  (r"^libunity\.so$", "Unity engine"),
  (r"^libmain\.so$", "often a Unity or game bootstrap; check exports"),
  (r"^libhermes.*\.so$", "Hermes JS engine (React Native). App logic is bytecode in assets/index.android.bundle"),
  (r"^libjsc\.so$|^libjscexecutor\.so$", "JavaScriptCore (React Native)"),
  (r"^libreact.*\.so$|^libfbjni\.so$|^libyoga\.so$|^libfolly.*\.so$", "React Native runtime"),
  (r"^libmonodroid\.so$|^libmonosgen.*\.so$|^libxamarin.*\.so$", "Xamarin/.NET runtime. App logic is .NET assemblies"),
  (r"^libc\+\+_shared\.so$", "LLVM C++ runtime, shared by other libraries"),
  (r"^libsqlcipher\.so$", "SQLCipher: encrypted SQLite. Look for where the key comes from"),
  (r"^libsqlite.*\.so$", "bundled SQLite"),
  (r"^libcrashlytics.*\.so$", "Firebase Crashlytics NDK"),
  (r"^libsentry.*\.so$", "Sentry NDK crash reporting"),
  (r"^libllama\.so$|^libllava.*\.so$|^libmtmd\.so$", "llama.cpp inference library (check for llama_* exports)"),
  (r"^libggml.*\.so$", "ggml tensor library used by llama.cpp/whisper.cpp (check for ggml_* exports)"),
  (r"^libwhisper\.so$", "whisper.cpp speech recognition"),
  (r"^libomp\.so$|^libgomp\.so$", "OpenMP runtime"),
  (r"^libonnxruntime.*\.so$", "ONNX Runtime"),
  (r"^libopencv.*\.so$", "OpenCV"),
  (r"^libffmpeg.*\.so$|^libav(codec|format|util|filter)\.so$|^libsw(scale|resample)\.so$", "FFmpeg"),
  (r"^libmpv\.so$|^libvlc.*\.so$", "media player engine"),
  (r"^libandroidx\.graphics\.path\.so$", "AndroidX graphics-path helper"),
  (r"^libdatastore_shared_counter\.so$", "AndroidX DataStore multi-process counter"),
  (r"^libimage_processing_util_jni\.so$|^libsurface_util_jni\.so$", "AndroidX CameraX"),
  (r"^libbarhopper.*\.so$|^libmlkit.*\.so$", "Google ML Kit"),
  (r"^libtensorflowlite.*\.so$|^libtflite.*\.so$", "TensorFlow Lite"),
  (r"^libcronet.*\.so$", "Cronet: Chromium network stack"),
  (r"^libconscrypt.*\.so$", "Conscrypt TLS provider"),
  (r"^libssl\.so$|^libcrypto\.so$", "bundled OpenSSL/BoringSSL"),
  (r"^libcurl\.so$", "bundled libcurl: native HTTP client"),
  (r"^librealm.*\.so$", "Realm database"),
  (r"^libmmkv\.so$", "Tencent MMKV key-value store"),
  (r"^libtoolChecker\.so$", "RootBeer root detection"),
  (r"^libjiagu.*\.so$|^libprotectClass.*\.so$", "360 Jiagu packer"),
  (r"^libshell.*\.so$|^libtup\.so$|^libexec.*\.so$", "Tencent Legu / generic packer stub"),
  (r"^libSecShell.*\.so$|^libsecexe\.so$|^libsecmain\.so$", "Bangcle/SecNeo packer"),
  (r"^libDexHelper.*\.so$|^libdexjni\.so$", "SecNeo/Ijiami packer"),
  (r"^libbaiduprotect.*\.so$", "Baidu packer"),
  (r"^libmobisec\.so$|^libsgmain.*\.so$|^libsgsecuritybody.*\.so$", "Alibaba security SDK / packer"),
  (r"^libnesec\.so$|^libnqshield\.so$", "NetEase / NQ Shield protector"),
  (r"^libdexprotector.*\.so$|^libdpboot\.so$", "DexProtector"),
  (r"^libarxan.*\.so$|^libcovault.*\.so$|^libappdome.*\.so$", "commercial app shielding"),
  (r"^libfrida.*\.so$|^libgadget\.so$", "Frida gadget: instrumentation embedded in the APK"),
  (r"^libsubstrate.*\.so$|^libxposed.*\.so$|^libsandhook.*\.so$|^libepic\.so$|^libwhale\.so$|^libdobby\.so$|^libshadowhook\.so$|^libbytehook\.so$", "inline/PLT hooking framework"),
]

# Imported function -> capability. A capability present in imports is a lead to read.
IMPORT_CATEGORIES = [
  ("network", r"^(socket|connect|bind|listen|accept4?|send(to|msg)?|recv(from|msg)?|getaddrinfo|gethostbyname.*|inet_.*|res_.*|android_getaddrinfofornetwork|curl_.*|SSL_.*|BIO_.*connect.*)$"),
  ("process execution", r"^(system|popen|exec[lv]p?e?|execvpe|fexecve|fork|vfork|posix_spawnp?|clone)$"),
  ("dynamic loading", r"^(dlopen|android_dlopen_ext|dlsym|dlvsym|dl_iterate_phdr|dladdr)$"),
  ("memory protection", r"^(mprotect|mmap|mmap64|mremap|memfd_create|__mmap2)$"),
  ("debug, tracing", r"^(ptrace|prctl|sigaction|signal|bsd_signal|inotify_.*|process_vm_(read|write)v|kill|tgkill|raise)$"),
  ("file access", r"^(open|open64|openat|fopen|fopen64|creat|unlink|rename|chmod|fchmod|stat|lstat|fstat|access|opendir|readdir|readlink|mkdir|ftruncate|__open_2|__openat_2)$"),
  ("system properties, environment", r"^(__system_property_(get|find|read|read_callback|foreach)|getenv|setenv|uname|getuid|geteuid|getpid|getppid|gettid|sysconf|getauxval)$"),
  ("crypto", r"^(EVP_.*|AES_.*|RSA_.*|SHA(1|256|512)_.*|MD5_.*|HMAC.*|RAND_.*|EC_.*|mbedtls_.*|crypto_.*|arc4random.*|getrandom|getentropy)$"),
  ("compression", r"^(inflate.*|deflate.*|uncompress|compress2?|LZ4_.*|ZSTD_.*|BZ2_.*|lzma_.*)$"),
  ("time, sleep", r"^(nanosleep|usleep|sleep|clock_gettime|gettimeofday|time)$"),
  ("threads", r"^(pthread_create|pthread_kill)$"),
  ("android framework", r"^(AAsset.*|ALooper.*|ANativeWindow.*|AConfiguration.*|ASensor.*|AInput.*|__android_log_.*|android_set_abort_message|AHardwareBuffer.*|ABinder.*|AIBinder.*)$"),
]

STRING_CATEGORIES = [
  ("URLs", re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>]{4,}")),
  ("IPv4 addresses", re.compile(r"(?<![\d./A-Za-z])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{2,5})?(?![\d.])")),
  ("filesystem paths", re.compile(r"^/(?:data|proc|sys|system|sdcard|storage|dev|vendor|sbin|apex|mnt)/[\w./%*-]+")),
  ("flooding, bot behavior", re.compile(
    r"^Mozilla/5\.0 |User-Agent: %s|%s %s HTTP/1\.[01]|^Cookie: %s|oom_score_adj|oom_adj|iptables |"
    r"/proc/net/tcp|/proc/%d/(exe|cmdline|comm)|eth_call|jsonrpc")),
  ("root, hooking, emulator, debugger checks", re.compile(
    r"\bfrida\b|frida[-_]|xposed|magisk|substrate|supersu|superuser|/su\b|busybox|TracerPid|/proc/self/(maps|status|task|fd)|"
    r"qemu|goldfish|ranchu|genymotion|nox|bluestacks|ro\.debuggable|ro\.secure|ro\.kernel\.qemu|"
    r"test-keys|gdbserver|lldb-server|android_server|linjector|zygisk|riru|lsposed|edxposed", re.I)),
  ("shell commands", re.compile(r"^(?:sh|su|/system/bin/sh) -c |\b(?:pm (?:install|uninstall|grant)|am (?:start|broadcast)|chmod [0-7]{3,4}|mount -o|setenforce|getprop |logcat )")),
  ("Java classes referenced (FindClass targets)", re.compile(r"^L?(?:[a-z][a-z0-9_]*/){2,}[A-Za-z_$][\w$]*;?$")),
  ("JNI method signatures", re.compile(r"^!{0,2}\((?:\[*(?:[ZBCSIJFD]|L[\w/$]+;))*\)\[*(?:[ZBCSIJFDV]|L[\w/$]+;)$")),
  ("build paths (who built it, from which package version)", re.compile(
    r"^(?:/(?:home|Users|root|builds?|workspace|__w|opt|mnt|var|tmp)/|[A-Z]:\\)[^\s]*\.(?:c|cc|cpp|cxx|h|hpp|rs|go|m|mm|S|kt|java)$|"
    r"\.pub-cache/hosted/|\.cargo/registry/|/go/pkg/mod/|/node_modules/|\.gradle/caches/")),
  ("keys, certificates", re.compile(r"-----BEGIN [A-Z ]+-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}")),
  ("embedded library banners", re.compile(
    r"OpenSSL \d|BoringSSL|libcurl/\d|SQLite format|sqlite3?[ _]version|zlib \d|inflate \d\.\d|deflate \d\.\d|"
    r"mbed TLS|wolfSSL|libpng|libjpeg|FFmpeg|Lua \d\.\d|Python \d\.\d|V8 |Dart VM|Unity|il2cpp|"
    r"clang version|GCC: \(|rustc|go\d\.\d+|Go build", re.I)),
  ("format strings with shell or SQL shape", re.compile(
    r"SELECT .+ FROM |INSERT (?:OR \w+ )?INTO |UPDATE \w+ SET |DELETE FROM |CREATE TABLE |%s[^%]{0,40}(?:&&|\|\|) *\w|^(?:/system/bin/)?\w+ -[a-zA-Z] .*%s")),
]

HIGH_ENTROPY = 7.2
SENSITIVE = {"network", "process execution", "dynamic loading", "debug, tracing", "memory protection"}


def demangle(names):
  if not names:
    return {}
  try:
    out = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True,
                         timeout=30).stdout.split("\n")
    return {n: d for n, d in zip(names, out) if d and d != n}
  except (OSError, subprocess.SubprocessError):
    return {}


def known(name):
  for pat, desc in KNOWN_LIBS:
    if re.search(pat, name):
      return desc
  return None


def jni_class(sym):
  """Java_com_example_Foo_bar -> (com.example.Foo, bar). Handles _1 escapes only."""
  body = sym[5:].split("__")[0]
  parts = re.split(r"_(?![0-9])", body)
  parts = [p.replace("_1", "_") for p in parts]
  if len(parts) < 2:
    return None, body
  return ".".join(parts[:-1]), parts[-1]


def limited(items, n):
  items = list(items)
  for it in items[:n]:
    yield it
  if len(items) > n:
    yield "... +%d more" % (len(items) - n)


SVC = {"arm64": (b"\x01\x00\x00\xd4", 4, "svc #0"), "arm": (b"\x00\x00\x00\xef", 4, "svc 0, ARM mode")}


def direct_syscalls(e):
  """(count, instruction) of aligned system call instructions in executable code, or None.
  arm64 and 32-bit ARM mode only; libc and the dynamic linker are expected to have them."""
  pat = SVC.get(e.machine)
  if not pat:
    return None
  insn, align, label = pat
  n = 0
  for _va, off, size, _l in e.exec_ranges():
    code = e.buf[off:off + size]
    i = code.find(insn)
    while i >= 0:
      if (off + i) % align == 0:
        n += 1
      i = code.find(insn, i + 1)
  return (n, label) if n else None


def describe(e, name, dex_classes, detail=True):
  buf = e.buf
  print("### %s" % name)
  desc = known(name)
  print("- identified by name: %s" % (desc or "not in the known-library table: treat as app-specific until shown otherwise"))
  print("- %s, %d bytes, sha256 %s" % (e.machine, len(buf), hashlib.sha256(buf).hexdigest()))
  bid = e.build_id()
  if bid:
    print("- build-id %s" % bid)
  for c in e.comment()[:3]:
    print("- toolchain: %s" % c)
  print("- soname %s; needs %s" % (e.soname, ", ".join(e.needed) or "nothing"))
  if e.rpath:
    print("- RPATH/RUNPATH: %s" % ", ".join(e.rpath))
  h = e.hardening()
  print("- hardening: RELRO %s, NX stack %s, stack canary %s, fortify %s%s%s" % (
    h["relro"], "yes" if h["nx_stack"] else "NO", "yes" if h["stack_canary"] else "no",
    "yes" if h["fortify"] else "no", ", TEXTREL" if h["textrel"] else "",
    ", RWX SEGMENT" if h["rwx_segment"] else ""))
  if e.type == 2:
    print("- an EXECUTABLE, not a shared library: something in the app runs it as a process "
          "(look for ProcessBuilder / Runtime.exec in scan.txt)")
  if not e.needed and not e.imports:
    print("- statically linked: no imports to read; behavior shows only in strings and code")
  print("- symbols: %s; %d exports, %d imports%s" % (
    "stripped (no .symtab)" if e.stripped else ".symtab present (%d symbols)" % len(e.symtab),
    len(e.exports), len(e.imports),
    "; packed relocations: " + ", ".join(e.packed_relocs) if e.packed_relocs else ""))
  if not detail:
    return

  flags = []
  if not e.sections_ok:
    flags.append("no usable section headers (stripped or deliberately removed: common for packers)")
  for va, off, size, label in e.exec_ranges():
    ent = e.entropy(off, size)
    if ent > HIGH_ENTROPY:
      flags.append("%s entropy %.2f over %d bytes: compressed or encrypted code" % (label, ent, size))
  if e.sections_ok:
    for s in e.sections:
      if s["type"] != 8 and s["size"] > 65536 and not s["flags"] & 4:
        ent = e.entropy(s["offset"], s["size"])
        if ent > HIGH_ENTROPY:
          flags.append("%s entropy %.2f over %d bytes: compressed or encrypted payload" % (
            s["name"], ent, s["size"]))
  svc = direct_syscalls(e)
  if svc:
    flags.append("%d direct system call instructions (%s): calls into the kernel that bypass libc, "
                 "so the imports understate what this library can do; read the code around them" % svc)
  if h["rwx_segment"]:
    flags.append("a loadable segment is writable and executable: self-modifying code is possible")
  if h["textrel"]:
    flags.append("text relocations: code is patched at load")
  if flags:
    print("\n**Structure flags**")
    for f in flags:
      print("- %s" % f)

  init = e.init_functions()
  print("\n**Code that runs at load, before any Java call** (%d)" % len(init))
  for a in init:
    print("- 0x%x %s" % (a, e.addr_names.get(a, "")))
  if any(s.name == "JNI_OnLoad" for s in e.exports):
    print("- JNI_OnLoad exported: runs on System.loadLibrary")

  java_exports = sorted(s.name for s in e.exports if s.name.startswith("Java_"))
  print("\n**JNI entry points by exported name** (%d)" % len(java_exports))
  by_class = {}
  for n in java_exports:
    cls, meth = jni_class(n)
    by_class.setdefault(cls, []).append(meth)
  for cls, meths in sorted(by_class.items(), key=lambda kv: str(kv[0])):
    note = ""
    if dex_classes is not None and cls is not None and cls not in dex_classes:
      note = "  [class not in dex: removed by R8 (library unused) or renamed]"
    print("- %s: %s%s" % (cls, ", ".join(limited(sorted(meths), 12)), note))

  tables = e.jni_tables()
  total = sum(len(t) for t in tables)
  print("\n**JNI methods registered by table (RegisterNatives)** (%d in %d tables)" % (total, len(tables)))
  for t in tables:
    print("- table at 0x%x" % t[0][0])
    for row in limited(["    %s %s -> 0x%x %s" % (n, sig, fn, e.addr_names.get(fn, ""))
                        for _a, n, sig, fn in t], 40):
      print(row)
  if not java_exports and not tables and any(s.name == "JNI_OnLoad" for s in e.exports):
    print("- JNI_OnLoad present but no table found: methods may be registered from a table "
          "built at runtime; disassemble JNI_OnLoad")

  other = sorted(s.name for s in e.exports if not s.name.startswith("Java_") and s.is_func)
  dm = demangle(other)
  print("\n**Other exported functions** (%d)" % len(other))
  for n in limited([dm.get(n, n) for n in other], 40):
    print("- %s" % n)

  imports = sorted({s.name for s in e.imports})
  print("\n**Imports by capability**")
  rest = set(imports)
  for label, pat in IMPORT_CATEGORIES:
    hit = [n for n in imports if re.match(pat, n)]
    rest -= set(hit)
    if hit:
      print("- %s: %s" % (label, ", ".join(limited(hit, 30))))
  if rest:
    dm = demangle(sorted(rest))
    print("- other (%d): %s" % (len(rest), ", ".join(limited([dm.get(n, n) for n in sorted(rest)], 40))))
  if not imports:
    print("- none: static binary, or imports resolved manually via dlsym or raw syscalls")

  strings = e.strings()
  print("\n**Strings of interest** (%d strings total)" % len(strings))
  for label, pat in STRING_CATEGORIES:
    hit = sorted({s.strip() for s in strings if pat.search(s)})
    if label.startswith("Java classes") and len(hit) > 400:
      continue  # C++ or Dart symbol soup, not FindClass targets
    if hit:
      print("- %s (%d):" % (label, len(hit)))
      if label.startswith("build paths"):
        # one line per directory, not per file
        dirs = {}
        for x in hit:
          dirs.setdefault(os.path.dirname(x), 0)
          dirs[os.path.dirname(x)] += 1
        hit = ["%s/  (%d files)" % (d, c) for d, c in sorted(dirs.items())]
      for s in limited([x[:160] for x in hit], 25):
        print("    %s" % s)
  print()


def load_calls(root_dir):
  """System.loadLibrary / System.load call sites in decompiled sources."""
  src = os.path.join(root_dir, "jadx", "sources")
  if not os.path.isdir(src):
    return None
  try:
    out = subprocess.run(
      ["grep", "-rn", "-E", "-e", r"System\.(loadLibrary|load)\(|Runtime\.getRuntime\(\)\.load(Library)?\(|ReLinker|SoLoader\.loadLibrary",
       "--", "."], cwd=src, capture_output=True, text=True, timeout=120).stdout
  except (OSError, subprocess.SubprocessError):
    return None
  return [line[:220] for line in out.split("\n") if line]


def main():
  if len(sys.argv) >= 3 and sys.argv[1] == "--file":
    describe(Elf(sys.argv[2]), os.path.basename(sys.argv[2]), None)
    return
  name = sys.argv[1]
  root_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name)
  lib_dir = os.path.join(root_dir, "raw", "lib")
  print("# Native summary: %s" % name)
  print("Static inspection only. Leads, not findings: read the code before reporting.\n")

  abis = {}
  if os.path.isdir(lib_dir):
    for abi in sorted(os.listdir(lib_dir)):
      files = sorted(f for f in os.listdir(os.path.join(lib_dir, abi)))
      if files:
        abis[abi] = files
  # ELF files hidden elsewhere in the APK (assets, res, root)
  stray = []
  raw = os.path.join(root_dir, "raw")
  for dp, _dn, fn in os.walk(raw):
    if dp.startswith(lib_dir):
      continue
    for f in fn:
      p = os.path.join(dp, f)
      try:
        with open(p, "rb") as fh:
          if fh.read(4) == b"\x7fELF":
            stray.append(os.path.relpath(p, raw))
      except OSError:
        pass

  if not abis and not stray:
    print("No native libraries in this APK.")
    return

  dex_classes = None
  cpath = os.path.join(root_dir, "dex", "classes.txt")
  if os.path.exists(cpath):
    with open(cpath) as f:
      dex_classes = {line.rstrip("\n").split("\t")[-1] for line in f}

  primary = next((a for a in ABI_ORDER if a in abis), next(iter(abis), None))
  print("## ABIs")
  for abi, files in abis.items():
    print("- %s: %d libraries%s" % (abi, len(files), "  (analyzed in detail)" if abi == primary else ""))
  if abis and "arm64-v8a" not in abis:
    print("- no arm64-v8a: disassembly annotations in native-disasm.py are arm64-only")

  if stray:
    print("\n## ELF files outside lib/ (not loadable by System.loadLibrary; loaded by path or dlopen)")
    for s in stray:
      print("- %s" % s)

  parsed = {}
  for abi, files in abis.items():
    for f in files:
      try:
        parsed[(abi, f)] = Elf(os.path.join(lib_dir, abi, f))
      except (ValueError, OSError, IndexError) as ex:
        parsed[(abi, f)] = ex

  print("\n## ABI consistency")
  names = sorted({f for files in abis.values() for f in files})
  clean = True
  for f in names:
    have = [a for a in abis if f in abis[a]]
    if len(have) != len(abis):
      clean = False
      print("- %s only in: %s" % (f, ", ".join(have)))
    sets = {}
    for a in have:
      e = parsed[(a, f)]
      if isinstance(e, Elf):
        sets[a] = (frozenset(s.name for s in e.exports if s.is_func),
                   frozenset(s.name for s in e.imports))
    if len(set(sets.values())) > 1 and primary in sets:
      for a, (ex, im) in sets.items():
        if a == primary:
          continue
        dex_, dim = ex ^ sets[primary][0], im ^ sets[primary][1]
        # only capability-relevant import differences count; libc helper sets vary per ABI
        dim = {n for n in dim if any(re.match(p, n) for lbl, p in IMPORT_CATEGORIES
                                     if lbl in SENSITIVE)}
        if dex_ or dim:
          clean = False
          print("- %s differs between %s and %s: exports %s; sensitive imports %s" % (
            f, primary, a, ", ".join(limited(sorted(dex_), 8)) or "same",
            ", ".join(limited(sorted(dim), 8)) or "same"))
  if clean:
    print("- same libraries, exported functions, and sensitive imports across all ABIs")

  calls = load_calls(root_dir)
  print("\n## Java load sites")
  if calls is None:
    print("- jadx output not available")
  elif not calls:
    print("- no System.loadLibrary/System.load call found in decompiled sources "
          "(loaded reflectively, by a library helper, or never)")
  else:
    for c in limited(calls, 40):
      print("- %s" % c)

  print("\n## Libraries (%s)\n" % primary)
  for f in abis.get(primary, []):
    e = parsed[(primary, f)]
    if isinstance(e, Elf):
      describe(e, f, dex_classes)
    else:
      print("### %s\n- not parseable as ELF: %s\n" % (f, e))
  for s in stray:
    try:
      describe(Elf(os.path.join(raw, s)), s, dex_classes)
    except (ValueError, OSError, IndexError) as ex:
      print("### %s\n- not parseable as ELF: %s\n" % (s, ex))


if __name__ == "__main__":
  main()
