# Runbook: native code

## Contents
- When this applies
- Step 1: read the native summary
- Step 2: decide what is worth reading
- Step 3: establish provenance
- Step 4: map the Java side
- Step 5: read code (disassembly)
- Step 6: decompile (optional, Ghidra)
- Executables, static binaries, and encrypted strings
- What to put in the report
- Limits
- Checking the scripts after a change

## When this applies

Any APK with files under `lib/`, or with ELF files elsewhere in the archive.
`scripts/unpack.sh` writes `work/<name>/native-summary.txt` for every APK; if it says
"No native libraries", skip this runbook. Everything here is static: never load or
run a library from an APK (`AGENTS.md` `Invariants`).

Native code matters because it is where an app can do things the Java-level scan
does not see: its own network stack, shell commands, anti-analysis checks, unpacking
of hidden code. An app whose Java side looks clean and whose native side is
unexamined has not been analyzed.

## Step 1: read the native summary

`native-summary.txt` (from `scripts/native-summary.py`) has, per APK:

| Section                     | What to take from it                                                    |
|-----------------------------|-------------------------------------------------------------------------|
| ABIs                        | which ABI was analyzed in detail (arm64-v8a when present)               |
| ELF files outside lib/      | native code hidden in `assets/` or elsewhere; loaded by path or `dlopen`, always worth reading |
| ABI consistency             | a library, export, or sensitive import present for only some ABIs       |
| Java load sites             | `System.loadLibrary` calls in decompiled sources                        |

and per library: identification by file name, hash, build id, toolchain, hardening,
structure flags (high entropy, missing section headers, RWX segments), code that runs
at load, JNI entry points (exported `Java_*` names and `RegisterNatives` tables found
in data), other exports, imports grouped by capability, and strings of interest.

The summary is produced without executing anything and without a disassembler. It
finds JNI method tables in stripped libraries by resolving relocations (plain, RELR,
and Android packed APS2).

## Step 2: decide what is worth reading

Sort libraries into three groups and say which is which in the report:

1. **Known runtime or framework** (AndroidX helpers, `libc++_shared.so`, engines such
   as Flutter, Unity, Hermes). Identification is by file name only, so check that the
   exports and imports fit the claimed identity. A "libc++_shared.so" that imports
   `socket` is not what its name says. Do not read their code unless that check fails.
2. **App logic compiled to native** (`libapp.so` for Flutter, `libil2cpp.so` for
   Unity, React Native bundles). The app's behavior lives here and the tools in this
   repo read it only at the level of strings, imports, and raw disassembly. State that
   limit plainly; see "Limits".
3. **App-specific libraries** (anything the known-library table does not match, and
   anything that fails the check in group 1). These get read, after Step 3 has shown what they
   were built from.

Within group 3, read in this order:

- Load-time code: init functions and `JNI_OnLoad`. They run before any Java call.
- JNI methods whose imports or strings touch a sensitive capability (network,
  process execution, dynamic loading, memory protection, tracing).
- Anything behind a structure flag. High entropy in code plus `mprotect`/`mmap` plus
  `dlopen` or few imports is the shape of a packer: the visible code is a loader and
  the real code is not statically visible.

## Step 3: establish provenance

Identification by file name and symbols says what a library claims to be. Two
stronger checks exist; use them before spending time reading code, and before
calling a library "stock" in a report.

- **Build paths.** `native-summary.txt` lists "build paths" found in each library:
  source paths left by the compiler. They show where it was built (`/home/runner/`
  is a GitHub Actions runner, `/Users/<name>/` a developer's Mac) and often from
  which package and version (`.pub-cache/hosted/pub.dev/<pkg>-<ver>/`,
  `.cargo/registry/`, `.gradle/caches/`). Paths are strings and can be forged, but
  they are a strong lead and frequently the only version information in the binary.
- **Reference comparison.**

  ```bash
  ./cupella reference-check.py <name> > work/<name>/reference-check.txt
  ```

  This uses the network (fixed allow-list of public registries; see the script
  header and `AGENTS.md` `Invariants`). It does two things:
  - `libflutter.so`: downloads the official engine artifact for each commit hash
    embedded in the library and compares SHA-256. "IDENTICAL" settles that the engine
    is stock. A difference or no artifact means a custom or non-release engine, which
    then has to be treated as app-specific code.
  - Libraries with a pub.dev build path: downloads that package version and reports
    how many exported functions exist by name in its sources and how many of the
    binary's string literals occur there, with unmatched literals that look like
    URLs, paths, or commands listed as `CHECK`.

Reading the source comparison:

- Name coverage near 100% and no `CHECK` lines: the binary is consistent with the
  published sources. Report it as that, with the package name, version, and archive
  hash. It is not proof of an unmodified build.
- Exported functions missing from the sources, or `CHECK` lines: code or strings that
  the published package does not explain. Read those functions (Step 5).
- Ordinary misses: data tables, regular expressions with escapes, C++ runtime
  messages (libunwind, libc++), text assembled by macros.
- "prebuilt binaries shipped in the package" means the source comparison says little:
  the binary may come from the package's own prebuilt file. Compare hashes instead.

In reports, call such a library "third-party" with its provenance, between "runtime"
and "app-specific".

## Step 4: map the Java side

Native methods are called from somewhere. For each JNI class in the summary:

- Find the declaring class in `jadx/sources/` (the `Native bridge` section of
  `scan.txt` lists `native` method declarations and load calls in scope; rerun
  `scan.sh` with `.` as scope if the class is in a library package).
- Find the callers of each `native` method, and what data they pass in and get back.
  The Java signature in the JNI table (`([B)I`) tells you the types crossing the
  boundary.
- "class not in dex" next to a `Java_*` export means R8 removed the class (the
  library is shipped but unused) or the class is loaded from elsewhere. Unused is the
  common case for AndroidX helpers.

## Step 5: read code (disassembly)

```bash
L=work/<name>/raw/lib/arm64-v8a/libfoo.so
./cupella native-disasm.py $L --list             # functions known by symbol or JNI table
./cupella native-disasm.py $L --jni              # init functions, JNI_OnLoad, all JNI methods
./cupella native-disasm.py $L upload 0x1a80      # by name (substring) or address
./cupella native-disasm.py $L --xref system      # which functions reference an import or string
./cupella native-disasm.py $L --all > work/<name>/native/libfoo.asm   # everything
```

Always use the arm64-v8a build when there is one: the annotations are arm64-only.
On arm64 each line may carry:

- `; import <name>` on calls into the PLT,
- `; "text"` where an address load resolves to a string,
- `; JNIEnv-><Function>` on indirect calls through the JNI function table,
- `; JNINativeMethod table: ...` where a method table is passed to `RegisterNatives`,
- `; native <name><signature>` on calls to a registered JNI method.

Reading approach: follow the calls. A JNI method that loads a URL string, calls
`socket`/`connect`/`send` or `system`, or passes a path to `dlopen` shows that in the
annotations without reading every instruction. Functions without symbols are named
`sub_<addr>`; give `0x<addr>` from a `bl` target to disassemble them. A function
whose size is unknown is cut at the first return ("end inferred"); raise `--max` if
it stops short.

## Step 6: decompile (optional, Ghidra)

For anything longer than a screen of assembly, C is faster to read:

```bash
./cupella native-decompile.sh $L upload 0x1a80   # selected functions -> native/<abi>/libfoo.so.partial.c
./cupella native-decompile.sh $L                 # everything -> native/<abi>/libfoo.so.c
```

Ghidra is part of the image. Two
functions of a small library take about 6 seconds; a whole large library takes
minutes, so name functions when you can. The Ghidra log is
`native/<abi>/<lib>.ghidra.log`.

`scripts/ghidra/postprocess.py` then annotates the C: indirect calls through the JNI
table get the function name as a comment (`/* JNIEnv->RegisterNatives */`),
`FUN_<addr>` becomes `jni_<method>` for registered methods with the Java signature
in the header line, method tables are labeled, runs of byte-wise zeroing are
collapsed, and in 32-bit code literal-pool words are annotated with the string or
function they point to (`DAT_00008edc /* -> &FUN_00009568 */`), which exposes handler
tables. Addresses in Ghidra names (`FUN_001019ec`, `DAT_00109fd0`) include the
image base printed at the top of the file; subtract it to get the address
`native-disasm.py` uses.

Decompiled C is a reconstruction, like jadx output. Cross-check anything a finding
depends on against the disassembly.

After decompiling, rerun `./cupella structure-leads.py <name>`: native functions then get
entry points, coordinators (a bot's main loop), dispatch and handler tables, endless
loops (attack routines), and decoders (string decryptors called from many places),
plus a per-capability map. `./cupella xref.py <name> FUN_...` lists a function's callers
and callees, including functions whose address it takes. On the DDoS-bot sample
these found the main function, the attack table, and the string decryptor that pattern
searches missed.

## Executables, static binaries, and encrypted strings

Worked example: [docs/examples/23282313-ddos-bot-loader.md](../docs/examples/23282313-ddos-bot-loader.md)
(a snapshot from 2026-10-03), a loader APK that copies a static 32-bit ARM DDoS bot
from `assets/` and runs it; the bot reads its C2 from ENS and SNS
name records and keeps 37 strings under a custom XOR stream cipher.

- **An ELF outside `lib/`**, especially an executable (the summary says "an
  EXECUTABLE, not a shared library"), is run as a process by Java code. Find the
  `ProcessBuilder` or `Runtime.exec` site in `scan.txt` ("Dynamic code"): it shows
  the file name it is copied to, its arguments, and what restarts it. That Java code
  is usually the whole app.
- **A statically linked binary has no imports.** The capability table is empty and
  says so. Everything comes from strings and code. `native-disasm.py` gives plain
  disassembly for 32-bit ARM (ARM or Thumb chosen per file, stated in each function
  header; check it when output looks like garbage); for reading, go straight to Ghidra: `./cupella native-decompile.sh
  work/<name>/raw/assets/<file>` writes `native/other/<file>.c` (about a minute for a
  500 KB binary, 1,400 functions).
- **Finding the functions that matter in stripped 32-bit ARM.** Strings are reached
  through literal pools, so Ghidra shows `DAT_<addr>` and not the text. The
  post-processor annotates each pool word that points at a string
  (`DAT_00011730 /* -> "\"result\":\"0x" */`). Grep the C for a telling string from
  the summary, take the function it is in, then grep for that function's callers.
  Most functions are C library and TLS code; follow the strings and the call chain
  from them up to the main function and ignore the rest.
- **Encrypted string tables.** Signs: few meaningful strings for what the binary
  evidently does, short garbage strings, and a setup function that registers many
  `(index, pointer, length)` entries, with get/unlock/lock helpers called around each
  use. Read the unlock function and its key setup, then have a decryption agent
  re-implement the cipher and decrypt every entry from the file bytes through
  `./cupella run-decryptor.sh` (agent-written code never touches sample bytes any other
  way); give it the table, key, and helper addresses, and ask it for plain data words
  (port tables, lists) in the same pass. Clean output for all entries confirms the
  cipher was read correctly. Then grep for the helper called with each index to see which
  function uses which string. Put the algorithm and the decrypted table in the
  report as an appendix: the script itself is specific to the sample and does not
  belong in `scripts/`.
- **Byte order of ports.** A port stored into a `sockaddr` is in network order.
  Check a known value before listing ports: the same table read with the wrong byte
  order gives 55 plausible but wrong numbers.
- **Never resolve or contact what you recover.** Names, addresses, and endpoints
  from a malicious sample go into the report as indicators. This includes lookups
  that look harmless, such as a public blockchain RPC call.

## What to put in the report

In "Native code" (see [design-report.md](design-report.md)): a table of libraries
with group (runtime, app logic, app-specific), what each is, and how that was
established; the JNI surface of app-specific libraries; and coverage (which
functions were read, by disassembly or decompilation, and which were not).

Findings from native code cite the library path, ABI, and function address, and quote
the annotated lines that carry the evidence (the call and the string), not whole
functions.

## Limits

State these under "Analysis coverage" when they apply:

- Strings and imports show capability, not behavior. A library that imports `socket`
  may never open one; read the callers.
- Strings can be encrypted or built at runtime, and functions can be reached through
  pointers the scripts do not follow. Absence in the summary is weak evidence.
- Raw syscalls (`svc` on arm64) bypass the import table. A library with few or no
  imports and `svc` instructions in its code is doing this; search the `--all`
  output for `svc`.
- IL2CPP (Unity) needs Il2CppDumper, which is not installed: report what strings and
  the bundled metadata show and say the logic was not read. Dart AOT (`libapp.so`)
  and Hermes bytecode have tools in the image: Flutter goes to
  [runbook-flutter.md](runbook-flutter.md), Hermes to the React Native section of
  [runbook-analysis.md](runbook-analysis.md).
- Packed or encrypted libraries cannot be analyzed statically past the loader.
- Annotations cover arm64. Other ABIs get plain disassembly with direct call names on
  x86 only.

## Checking the scripts after a change

`scripts/fixtures/native-fixture.c` is a small deliberately suspicious library with a
header comment giving the build command (clang with the aarch64 target and lld, no
NDK) and the expected output of `native-summary.py --file` and
`native-disasm.py --jni`. `./cupella check` builds it with each relocation packing variant
and checks that output; run it after changing `scripts/elf.py`.
