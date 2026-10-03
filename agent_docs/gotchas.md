# Gotchas and findings

Traps in APK formats and tooling. Entries marked (verified) were observed in this
workspace with jadx 1.5.6 and apktool 3.0.3; the rest are known behavior of the
formats and tools, not yet reproduced here. Confirm an unverified entry the first
time it matters, then mark it or fix it.

Sample names are anonymized: launcher A and launcher B are two third-party launcher
apps, the Flutter app is a third-party chat app, the video app is a third-party video
app, and malware is named by its public family (BTMOB, Octo).

## Contents
- Formats
- Signing
- apktool
- jadx
- Native code
- Shell and scripts
- Searching and reporting
- Findings

## Formats

- **Malware breaks ZIP readers on purpose (verified on MalEval).** Entries carry the
  "encrypted" flag without being encrypted (unzip asks for a password), or entries
  such as `AndroidManifest.xml/0M.xml` turn the manifest's path into a directory on
  extraction. Android ignores both. apktool fails with `NotAZipFileException`, jadx
  copes. `unpack.sh` falls back to `apkunzip.py` and runs apktool on `repaired.apk`.
- **Tampered binary manifests (verified).** Nonstandard attribute layouts and bad
  string indices crash fixed-layout parsers; the device identifies attributes by
  resource id. `axml2xml.py` honors the header's attribute layout and maps android:
  attributes by resource id.
- **Decoy dex files (verified).** Some samples ship a "dex" with a valid magic and a
  header whose offsets point gigabytes past its 1 KB end. `dex.py` skips dex files whose
  header tables do not fit, instead of crashing every bytecode script.
- **Payloads hide under misleading names (verified).** 56 dex files or dex-bearing
  archives in MalEval APKs, named `slogan.jpeg`, `MT_Bin`, `systemdata`. Match on
  content (`embedded.py`), never on extension.
- **`AndroidManifest.xml` inside the zip is binary XML (verified).** `unzip` output is
  not readable and grep for attribute values fails silently. Read the decoded copy
  from apktool or jadx, or the fallback from `scripts/axml2xml.py`.
- **Resource file names in the zip can be shortened (verified).** With resource path
  shortening, `raw/res/` holds files like `res/8G.xml` and `res/-5.xml`; the names
  carry no meaning. apktool restores real names from `resources.arsc`
  (`apktool/res/xml/network_security_config.xml`). Without apktool, decode all of
  `raw/res/*.xml` with `axml2xml.py` and find a file by its root element.
- **Element text matters in config XML (verified).** Network security config puts the
  domain names in text nodes, not attributes. A decoder that prints only attributes
  shows `domain-config` blocks with no domains.
- **Not every `.apk`-like file is a single APK.** `.xapk`, `.apks`, `.apkm` are zips
  holding a base APK plus splits. A lone `base.apk` from a split install lacks the
  native libraries and density/language resources, so "no native code" may be wrong.
  `triage.txt` has a "Split APK" section when the manifest requires splits
  (`requiredSplitTypes`, `isSplitRequired`, `com.android.vending.splits.required`); for a
  Flutter app it means the Dart code (`libapp.so`) is in the ABI split and not analyzable
  from the base (4 MalEval samples).
- **Code may be outside `classes*.dex`.** Flutter (`libapp.so`), React Native
  (`index.android.bundle`, often Hermes bytecode), Unity (IL2CPP in `libil2cpp.so`),
  Xamarin/.NET (assemblies blob). jadx then shows only the host shell; a clean-looking
  decompile says nothing about the app logic.
- **Packers hide the real dex.** A tiny dex with a custom `Application` class, large
  opaque files in `assets/` or `lib/`, and `DexClassLoader` use suggests the payload is
  decrypted at runtime. Static analysis of the visible dex then covers the loader only;
  state that in "Analysis coverage".
- **Zip timestamps are meaningless (verified).** Build tools zero them (one
  app store client's entries are all dated 1981). Do not infer build dates from them.
- **Zip tricks.** Malformed or deliberately odd zips (duplicate entry names, bogus
  compression methods, encrypted-flag bits) can make `unzip`, apktool, and Android
  disagree about contents. If tools disagree or error on the container itself, treat
  that as a finding.

## Signing

- **`keytool -printcert -jarfile` sees only the v1 (JAR) signature (verified).** An
  APK signed with v2/v3 only shows "Not a signed jar file" while being validly signed.
  `scripts/apksig-verify.py` verifies v2/v3 without the Android SDK, using `openssl`.
- **A verified signature is integrity, not identity (verified).** It shows the file
  is what the key holder signed. All four samples verify, including one signed with
  an eleven-week-old self-signed certificate naming only the app's own brand. Whose key it is
  needs a fingerprint from a trusted source.
- **`jarsigner -verify` prints hundreds of "signed in JarFile but is not signed in
  JarInputStream" lines for zipaligned APKs (verified).** They concern entry order,
  not missing signatures. `apksig-verify.py` counts them and prints only real
  warnings.
- **v2/v3 presence can be seen without verifying (verified).** The v1 `.SF` file
  carries `X-Android-APK-Signed: 2, 3`, and the file contains the magic
  `APK Sig Block 42`. `unpack.sh` reports both. Neither proves the signatures check
  out.
- **Apps with min SDK 24+ often have no v1 signature at all (verified).** `keytool`
  then prints "Not a signed jar file". Use `scripts/apksigblock.py` (run by
  `unpack.sh`) to get the signer certificate from the signing block.
- **A v1 signature block proves nothing alone** when the APK targets devices that
  require v2+. Do not write "signature valid"; write what was observed.
- **`keytool` flags old certificates as weak (verified).** A SHA1withRSA self-signed
  certificate is common on long-lived apps. For APK signing the identity is the key,
  not the certificate's self-signature. Report it, do not overstate it.
- **The debug certificate** has subject `CN=Android Debug, O=Android, C=US`. Worth a
  finding in anything presented as a release build.

## apktool

- **`apktool.yml` holds SDK versions and version name/code (verified).** apktool
  strips `uses-sdk` from the decoded manifest; `manifest-summary.py` cannot print the
  target SDK from it. The fallback `manifest.xml` keeps them.
- **apktool installs a framework file under `~/.local/share/apktool/` (verified).**
  A write outside the repo on first run; expected, and not controlled by `-o`.
- **apktool 3 has no `--help` on the subcommand (verified).** `apktool d --help`
  prints "Unrecognized option" followed by the usage text. The flags used by
  `unpack.sh` (`d -f -o`) are valid in 3.0.3.
- **Resource decode failures are common** on apps built with newer aapt2 features or
  with resource obfuscation. Read the manifest from the fallback decode or jadx output.
  No script reruns apktool with `-r` (smali only); if the smali is needed, ask the user
  to run it in `./cupella shell`. Never run apktool on the host.

## jadx

- **jadx output is not identical between runs (verified).** Two runs on the same APK
  gave the same file count and error count, but 11 of 5,390 files differed in small
  ways (a hoisted local, a `throws` clause, which pass failed on a hard method). The
  worker threads race. Line numbers cited in a report can shift by a few lines after
  a rerun with `-f`; cite the function as well as the line.
- **A nonzero error count and exit code are normal (verified).** On one app store client jadx
  exited 3 with 127 errors while producing 10,761 files. `unpack.sh` records the exit
  code and continues. Check that `sources/` is populated before treating it as a
  failure.
- **jadx's default log is a progress spinner (verified).** Redirected to a file it is
  one line of several hundred kilobytes of `INFO - progress` updates; never `tail` or
  `cat` it. `unpack.sh` runs with `--log-level ERROR`. To get the error count:
  `grep -a -o 'finished with errors, count: [0-9]*' jadx.log`.
- **One Java file per outer class (verified).** Inner classes and lambdas fold into
  the outer class's file, so file counts are far below class counts (one app: 1,487
  classes of its own in 480 files). Do not compare the two numbers.
- **Per-file warnings do not show in the error log (verified).** Search the sources
  for `JADX WARN`, `Code decompiled incorrectly`, `Method dump skipped`; `scan.sh`
  counts affected files in scope. Read flagged methods with suspicion or fall back to
  smali from apktool.
- **Decompiled Java is a reconstruction.** Control flow, types, and `try/catch` scope
  can be wrong, most often in exactly the obfuscated code that matters. For a finding
  that depends on precise logic, cross-check the smali.
- **Large APKs exhaust the default heap.** Symptoms: very slow, then
  `OutOfMemoryError`. No script sets the heap or thread count; ask the user to rerun
  jadx in `./cupella shell` with `JAVA_OPTS="-Xmx4g"` (jadx's launcher reads it) or
  `-j 2`. Never run jadx on the host.
- **Kotlin code decompiles with noise (verified)**: `Intrinsics.checkNotNull` calls,
  `@Metadata` annotations with long escaped strings (they match almost any grep, cut
  line length), `$default` bridge methods, coroutine state machines as `switch` blocks.
  These are compiler output, not obfuscation.
- **jadx renames classes, packages, and methods; the bytecode names differ
  (verified).** Kotlin lambda and coroutine classes (`Foo$onCreate$1`) become
  `AnonymousClass1`, invalid package names get a prefix (`a1` to `p001a1`), and
  mangled method names (`foo-abc123`) are renamed. jadx leaves `/* JADX INFO: renamed
  from: <original>, reason: ... */` before the declaration. Matching jadx output to
  dex, smali, or stack traces by name fails without it; `units.py` reads these
  comments. A call graph guessed from jadx text by simple names links unrelated
  same-named classes (launcher A: 12,600 of 14,400 text-guessed edges are absent from the
  bytecode graph of 2,900; the ones spot-checked were wrong).
- **Junk in dead code defeats jadx and baksmali together (verified).** A packer
  appends bytes after each method's last `return` that decode as a payload with an
  impossible size or element width. Both tools decode linearly, so jadx reports
  "Method load error ... newPosition < 0" for every method (simple mode too) and
  baksmali skips the class ("Invalid element width"). ART never executes those bytes.
  `./cupella dex-disasm.py` decodes along the control flow and reads them fine; the
  `flows.py` and `structure-leads.py` decoders also read past them.
- **Case-insensitive name clashes** from obfuscators (`a.java` and `A.java`) are not a
  problem on Linux but make output unusable if `work/` is copied to macOS or Windows.

## Native code

- **Capabilities of a static binary are invisible to the import table (verified).**
  The DDoS-bot sample's bot has no imports at all; its sockets, process
  killing, and TLS are all inside. "No sensitive imports" means nothing for a
  statically linked or packed binary. Check the "statically linked" line in the
  summary.
- **Version strings look like IP addresses (verified).** `Chrome/120.0.0.0` in user
  agent strings matched the IPv4 pattern. The pattern now requires valid octets and
  no preceding `/` or letter.
- **A `fork`/`exec` import is not always the app's doing (verified).** ggml's abort
  handler forks and tries to run `gdb` or `lldb` for a backtrace; every app bundling
  llama.cpp or whisper.cpp has it. `libflutter.so` imports `fork`/`execvp` and
  sockets for `dart:io`. Use `native-disasm.py --xref <import>` to find the caller
  and read it before reporting.
- **Libraries called through `dart:ffi` have no JNI surface (verified).** No `Java_*`
  exports, no `RegisterNatives` table, no `System.loadLibrary` site in Java. The
  absence does not mean the library is unused; look for the Dart `ffi` package and
  a binding package in `flutter-summary.txt`.
- **Substring patterns bite in string classification (verified).** "frida" matched
  "Friday" in llama.cpp's date strings. Patterns in `native-summary.py` need word
  boundaries; when a category has one odd hit, read the hit.
- **Build paths are the cheapest provenance (verified).** The Flutter app's inference libraries
  contain `/home/runner/.pub-cache/hosted/pub.dev/lcpp-0.2.5/...`: built on GitHub
  Actions from that pub.dev package version. Nothing else in the binaries carries a
  version. Read the "build paths" lines in `native-summary.txt` before trying to
  identify a library by its symbols.
- **"Identified by symbols" is not "stock" (verified).** Until
  `reference-check.py` showed the Flutter app's `libflutter.so` byte-identical to Google's
  artifact, calling it the Flutter engine rested on its name and exports. Say which
  kind of evidence a report has.
- **Demangled template functions start with their return type (verified).**
  `void std::__ndk1::vector<...>::__push_back_slow_path<...>(...)` begins with
  `void`, so a "starts with `std::`" filter misses it. Strip template arguments and
  the return type before classifying a symbol.
- **A library is identified by file name only (verified design limit).**
  `native-summary.py` matches names against a table. Renaming a library defeats it.
  Check that exports and imports fit the claimed identity before skipping a library.
- **Stripped libraries still expose their JNI methods (verified).** Methods registered
  with `RegisterNatives` have no `Java_*` symbol; the name, signature, and function
  pointer sit in a data table. `elf.py` finds these tables by resolving relocations,
  including RELR and Android packed (APS2) forms, where the pointers are not in the
  file bytes at the table's location.
- **JNI signatures can start with `!` (verified).** ART's fast-native convention
  prefixes the signature string (`!(J)I`). A detector that requires `(` first misses
  those entries and reports a short table; `elf.py` accepts the prefix. Adjacent
  tables are split only where a method name repeats (one table per API level in the
  AndroidX graphics library); two adjacent tables for different classes print as one.
  Count unique methods, and take the per-class split from the `RegisterNatives` calls
  in `JNI_OnLoad`.
- **lld can put `.rodata` and `.text` in one R+X segment (verified).** Segment flags
  then call strings "executable". `elf.py` `is_code` uses section flags when section
  headers exist.
- **JavaVM and JNIEnv tables overlap at low offsets (verified).** Offset `0x30` is
  `JavaVM->GetEnv` in `JNI_OnLoad` and `JNIEnv->FindClass` elsewhere. The disassembler
  prints both; the first indirect call in `JNI_OnLoad` is `GetEnv`.
- **32-bit ARM code is mostly Thumb (verified).** Decoding it as ARM gives plausible
  garbage. `native-disasm.py` follows each function symbol's mode bit and falls back to the
  file's default (see the next item); prefer the arm64 build regardless.
- **Stripped static ARM executables are often ARM mode, not Thumb (verified).** On the
  DDoS-bot sample (`assets/lol`, entry address even, no symbols) `native-disasm.py` used to
  decode ARM-mode code as Thumb. It now picks the mode from symbols, the entry bit, or a
  condition-field count, and prints its choice in each function header: check that line
  when the output looks like garbage. Ghidra's `@ 0x...` header comments in the C of such a
  binary are file offsets (image base 0x8000), not addresses.
- **A shipped library may be unused (verified).** Launcher A ships
  `libdatastore_shared_counter.so` while R8 removed the Java class that would load it.
  Check for a load site and for the declaring class before attributing the library's
  capabilities to the app.
- **`cstool` takes code as a hex argument.** One argument is limited to 128 KiB by
  the kernel, so `native-disasm.py` decodes in chunks; a chunk boundary inside an x86
  instruction can desynchronize a few instructions on `--all` for x86. Function-level
  disassembly is not affected.
- **High entropy alone is not packing.** Compressed assets embedded in `.rodata` and
  crypto tables raise entropy too. The packer shape is high-entropy code or payload,
  plus `mprotect`/`mmap` and `dlopen` or very few imports, plus a tiny dex.
- **Imports can be bypassed.** Raw syscalls (`svc #0`) and manual symbol lookup via
  `dlsym` leave no named import. An app-specific library with almost no imports is a
  reason to read more, not less.
- **Raw carriage returns shift line numbers (verified).** Ghidra string annotations in
  the DDoS-bot sample's `lol.c` carried raw `\r` from HTTP strings. Python's text mode
  counts a lone `\r` as a line break and grep does not, so native function lines in
  `xref.py` and `behavior-map.py` were 17 lines late by line 660. The scripts now read
  with `newline=""`, and `postprocess.py` escapes `\r`, `\n`, and `\t`. C files
  decompiled before 2026-10-03 still contain raw `\r`; `grep -c $'\r'` explains odd line
  counts in other tools.

## Shell and scripts

- **MobSF and Quark need help to run offline and read-only (verified).** MobSF writes
  migration files into its own code directory (run a copy on tmpfs) and downloads jadx
  on first use (`./cupella` gives it ours through `cache/`); Quark writes a dated log file
  into the current directory (run it from `/tmp`) and crashes on ZIPs with
  fake-encrypted entries. A search of `/` for MobSF's install path walked all of
  `work/`: never search the file system in a container that mounts `work/`.
- **Agents without a shell have no clock (verified).** Reader and scorer agents could
  not fill in "HH:MM" in progress files and wrote "--:--". Progress lines are numbered
  steps; the file's modification time shows when it last moved.

- **unzip recreates symlink entries and inflates without limit (verified).** An APK can
  carry a symlink entry, which `unzip` writes into `raw/`, where the agent's file tools on
  the host would follow it to a host file; and unzip inflates each stream to its end
  whatever size the entry declares, so a decompression bomb fills the disk under
  `work/`. `unpack.sh` therefore extracts with `apkunzip.py` only (no symlinks, measured
  size limits) and still removes any symlink a later tool creates. `../` and absolute
  entry names are rejected by every extractor (`./cupella fixtures/zipslip-test.sh`).
- **Shadowed ZIP entries can be real resources (verified).** In the Octo sample,
  `resources.arsc` points at entries named `resources.arsc/U2.xml` and
  `AndroidManifest.xml/sf.xml`: Android looks names up exactly, so they load fine.
  `repaired.apk` leaves such entries out (apktool fails on them), so jadx, which decodes
  them, must read the original APK; fed the repaired copy it lost every `res/xml` file.
- **A pipeline with grep in a `$(...)` aborts the script under pipefail when grep finds
  nothing (verified).** `depth=$(grep -o ... | wc -l)` killed `unpack.sh` for every
  sample whose name had no match; the fixture caught it. Wrap such greps in
  `(grep ... || true)`.
- **Without section headers, the dynamic symbol count must come from DT_GNU_HASH
  (verified).** Libraries with only a GNU hash table lost their imports in `elf.py` once
  the section headers were removed; `./cupella fixtures/elf-headers-test.sh <lib.so>` checks
  the fallback.

- **Subagents may not write files whose names look like reports (verified).** Claude
  Code refuses a subagent's Write to `report-verification.md` with "Subagents should
  return findings as text, not write report files", while `progress-test.md` in the same
  directory succeeds; the project's permission hook is never asked. Name subagent output
  files after their content (`verification.md`, `verdicts/<id>.json`), never `report*`.

- **Host tools on APK files are a sandbox escape route (verified, our own lapse).**
  During the benchmark work the main agent read raw asset bytes and opened embedded
  ZIPs with host Python, and a decryption agent ran host `readelf` and `cstool` on
  malware libraries. Parsing is not executing, but parser bugs in host tools run on the
  host. Use `./cupella` for anything that parses APK content; give agents that read APK
  content no general shell (`.claude/agents/`).

- **Scripts run in a container; paths and tools differ from the host.** Inside,
  the repo is `/repo`, tools are under `/opt/tools`, `HOME` is a tmpfs, and there is
  no network. A path outside `data/`, `work/`, `cache/`, `scripts/` does not exist
  there, and `scripts/` is read-only. A script that works on the host but fails under
  `./cupella` usually wrote somewhere else or called a program that is not in the
  `Dockerfile`.
- **The first Flutter app on a new Dart version takes minutes longer.** `./cupella`
  builds blutter for that version before the Dart step. It is not a hang; the
  message says "building". The result is cached in `cache/blutter/`.
- **The container runs in the C locale and UTC (verified).** Compared with a host run
  in a Swedish locale: certificate dates print in UTC, sort order differs, and apktool
  adds float comments to smali (`# 1.3f`) that the host run omitted. The container's
  output is the reference.
- **Ghidra starts slower in the container (verified).** About 20 seconds for one
  function against 6 on the host, because its settings directory is a fresh tmpfs on
  every run. Ask for several functions in one call.
- **`grep` differs between host and image.** The host has ugrep, the image GNU grep.
  Scripts use only options both accept (`-rn -E -e`, `-a -o`, `-F`, `-l`).

- **File names starting with `-` break commands (verified).** Shortened resource names
  include `-1.xml`, `-B.xml`. Always pass `--` before file arguments or prefix globs
  with `./`.
- **`grep` on this machine is ugrep (verified).** GNU-style flags used by the scripts
  work. An error like `invalid argument -m=l` came from a dash-leading file name in a
  glob (previous entry), not from ugrep itself.
- **`head` on search output hides hits (verified).** A hand-run grep capped with
  `head -20` dropped the one `HostnameVerifier` use in the app, and the first report
  draft said there was none. `scan.sh` caps per section too (`SCAN_MAX`); when a
  section is full, rerun that pattern alone without a cap before concluding.
- **The shell's working directory persists between agent commands.** After a `cd` into
  `work/`, relative paths to `scripts/` fail. Use absolute paths or `cd` to the repo
  root at the start of each command.

## Searching and reporting

- **R8 can move app code into one flattened library-looking package (verified).** In
  the second stage of the BTMOB sample, 1,444 renamed classes (libraries and app code: the
  string decoder, the config class, the DoS engine) sit in one package with a
  generated name, which `scope.py` leaves out as a non-manifest package. Check the
  triage's package table for a large package that is neither the manifest package nor
  a known library, and pass it to `scan.sh` explicitly.
- **A decrypted split APK scanned piece by piece has no manifest (verified).** Dex
  files decrypted from a split APK's base were each unpacked as a separate child: scope
  fell back to the whole tree, there were no entry points, and calls across dex files
  were lost. Have the decryptor reassemble the app as one APK (see
  `prompts/decrypt.md`, `out/parts/`).
- **An undecodable "string decoder" can be an R8-outlined concat (verified).** In launcher B,
  `scan.txt` listed `Lb/c0;->j(String,String)` (27 calls, "no scheme gives
  readable text") as a lead for the decryption stage. Its body is `return str + str2;`
  and its callers pass plain text. Open the decoder's body before starting a decryptor;
  a two-string static method with constant arguments is not enough.

- **R8-merged lambda classes create false call edges (verified; mostly fixed).** R8 folds
  many lambdas into one synthetic class whose methods `switch` on an int passed to the
  constructor, first or last (`new h(this, 6)`, `new o(12, x, this)`; launcher B's
  `rx/h` holds 29). `units.py` used to count every case as called by the creator, so
  `xref.py`, `structure-leads.py`, and `behavior-map.py` showed callees the code does not
  reach (an activity's `onCreate` "calling" a content provider's `call`). Since
  2026-10-03 `dex.py` records constant constructor arguments and the calls in each case,
  and `units.py` follows only the case whose label matches, using the switch on an int
  field of the class itself (the lambda number) when the method has one, else its first
  switch. A case body is read up to the next return, throw, or goto. Following it
  through gotos and branches instead was tried (2026-10-03) and reverted: launcher B's
  `NovaMobileActivity.onCreate` gained 16 callees, several wrong (Stripe activities'
  `finish`). So an odd edge can remain, and a case's calls after a branch can be
  missing; the methods of a merged class that have no switch count for every creator.
  Such a class usually lies outside the scope, so these edges are `far` edges
  (`~> outside` in `xref.py`). Check an edge in the source before relying on it in
  obfuscated code.
- **Ghidra literal-pool words used as offsets are not pointers (verified, fixed).** In
  32-bit position-independent code Ghidra shows `base + DAT_x`, where the pool word is an
  offset. `postprocess.py` annotated any pool word whose value equaled a function
  address (`/* -> &FUN_... */`), and `units.py` made each annotation a caller: in the
  DDoS-bot sample six functions "called" `FUN_00008b94` that way. Since 2026-10-03 a word
  used in addition or subtraction gets no annotation, and `units.py` ignores such
  annotations in older output.
- **A lead that names the right function can have the wrong reason (verified).** Before
  2026-10-03 the Java call graph folded every class without a jadx function into its
  creator, in an order-dependent walk, so launcher B's `NovaMobileActivity.onCreate` was
  listed as reaching accessibility "via NovaLauncher.q0" (it calls no such thing) and
  that line counted as covering the WebView finding. `lead-eval.py` scores a lead by
  the function it names, not by whether its chain is true. Read the chain's first call
  in the source before building on a structure lead.
- **Short names collide in obfuscated apps (verified, fixed).** `lead-eval.py` matched a
  chain entry such as `c.d` to every function named `c.d`; launcher B has 1,077 files
  named `c.java`, and one of its 12 findings was "covered" only that way, by a Stripe
  coroutine's chain. Since 2026-10-03 `structure-leads.txt` writes `pkg/Class.method`
  where several files in scope have that name, and `lead-eval.py` credits a chain entry
  only when it names one file's function. On that scoring the graph before and after
  the rebuild both cover 5 of launcher B's 12 findings.
- **The Java call graph has three kinds of edges (since 2026-10-03).** `calls`: what a
  function's own code calls, checked against androguard (`./cupella callgraph-check.py`:
  "lost" must be 0). `far`: reached through one method of a class whose source file is
  outside the scanned scope (shown as `~> outside` by `xref.py`, dotted in behavior
  maps): real for a listener class R8 moved to another package, noise for a library
  that calls back; a `~` before a chain entry in `structure-leads.txt` marks such a
  step. `async_`: a Runnable or Handler handed to a thread or looper. Leads
  use `calls` plus one outside hop (`FAR_HOPS`); two hops already link Stripe activities
  to launcher code (launcher B: 9,641 edges at one hop, 31,054 at two, 200,782 at four).
- **Brace counting and keyword checks in the jadx source parser (verified, fixed).**
  `units.py` lost functions and attributed others to the wrong class: a nested
  `/* data */ class` was not seen as a class, braces in string literals and comments
  shifted the nesting for the rest of the file, `synchronized` methods and methods whose
  return type starts like a keyword (`double`, a class named `if0`) were skipped, and
  local classes (`Outer$method$Name`) were looked up as `Outer$Name`. A function with the
  wrong class matches no dex method and has no call edges: 1,194 of launcher B's 13,091
  functions. `callgraph-check.py` lists functions without a dex method; that list
  should be empty.
- **A `defpackage` scope decodes every class (verified, kept on purpose).** In
  `units.py` a scope that includes `defpackage` adds the prefix `L`, which matches all
  classes, so the dex index covers library code too for those samples. Narrowing it to
  classes without a package lost real flows on MalEval (Bank Stealing 24 to 20, Privacy
  Stealing 34 to 31) and failed the gate, so it stays. In the call graph those classes
  are "outside the scope" (`far` edges); with any other scope, calls into classes
  outside it are opaque (`ext`).

- **Data flows stop at renamed libraries (verified).** `flows.py` recognizes sources
  and sinks by API name, so only framework calls (`android.*`, `java.*`) and libraries
  that kept their names count. In launcher A, Room and DataStore are R8-renamed, so the
  path from screen text to the session database ends at an unnamed library call and
  `flows.txt` is empty although finding 1 is exactly such a flow.
- **Malware code is usually outside the manifest package (verified).** 153 of 230
  MalEval malware samples declare components in other packages; with the manifest
  package as scope, code-level leads covered 45% of "Privacy Stealing" samples, with
  `scope.py` 76%. The remaining misses are mostly packed or loaded at run time.
- **The app's code is often in more than the manifest package (verified).** In one app
  store client the HTTP client and index verification live in sibling packages
  (`<vendor>.download`, `<vendor>.index`) outside the manifest package. A scan scoped to the manifest
  package showed an empty "TLS overrides" section while `ConnectionSpec` use sat one
  package over. Take the scope from the triage package table.
- **APKiD's anti-analysis hits are mostly library code (verified).** Every sample,
  including an app store client and a plain video player, shows `anti_vm : Build.FINGERPRINT
  check`. The Flutter app's long list of `Build.*` checks is the `device_info_plus` plugin. A hit
  says the check exists in the dex, not that the app evades analysis.
- **Tracker signatures match names, not behavior (verified).** An app store client matches ACRA,
  which it uses to offer emailing a crash report. Launcher A matches seven Facebook
  signatures through one string, `www.facebook.com`, an entry in its own list of
  sites to gate. And "Google Ads" in the Exodus list is any `*.google.com` host.
  Report what the code does with the SDK or host.
- **No tracker match under R8 renaming means little (verified).** The video app has 91%
  of its classes in one- or two-letter packages; an SDK's classes would not carry its
  package name there. `trackers.txt` prints a NOTE when that applies.
- **jadx's simple mode recovers most failed methods (verified).** Of 22 failed
  methods in the scanned scopes of the four samples, 21 were readable in simple mode, among them
  the two that the first reports had to leave unread (launcher A's polling loop,
  the video app's discovery routine). Read `jadx-retry/INDEX.txt` before falling back to
  smali.
- **Declared permissions can be noise in malware too (verified).** The bot loader
  declares location, phone state, and overlay permissions and uses none; one entry is
  not even a permission name. Report what the code uses, and note the unused ones as
  such.
- **An app with almost no code is a loader until shown otherwise (verified).** 75
  classes, three of them the app's, one asset: the asset is the program. Look at
  `assets/` and the "ELF files outside lib/" line before reading Java.
- **The local model flags text, not behavior (verified).** On the DDoS bot it ranked
  the flood builder, the lookup functions, the cipher, and the killer first and gave
  the main loop 0.02: that function is a loop of unnamed socket calls. On launcher A it
  flagged 30 "network" functions in an app with no network code (database
  coroutines). Network questions are now skipped when the manifest has no `INTERNET`
  permission; the general rule is that a score only chooses what to read.
- **Scoring everything is slow and adds noise (verified).** 1,402 functions of the
  bot sample would have taken about an hour, most of it on the embedded C library and
  wolfSSL. The filter in `model-leads.py` (functions around strings of interest)
  cut that to about 300, some 12 minutes.
- **Most hits are library code.** A grep over all of `sources/` for `http://` or
  `Cipher` returns mostly androidx, okhttp, bouncycastle, and XML namespace strings.
  Scope to the app's packages first.
- **A capability in the code is not a behavior by default (verified).** One app store client
  contains a metrics uploader and a persistent client id, both behind settings that
  default to off. Always find the gate and its default before describing what the app
  "does".
- **Counts written from memory drift (verified).** Two numbers in an early report
  draft were wrong until checked against script output. Take counts from
  `triage.txt` and `manifest-summary.txt`, not from recollection of a listing.
- **A preference's default is in the getter's fallback, not in XML, for DataStore
  apps (verified).** Compose apps have no `res/xml/preferences.xml`. Find the key in
  the DataStore wrapper class and read what it returns when the value is null
  (launcher A: retention falls back to `INDEFINITE`).
- **R8 renames libraries but often keeps the app's own package (verified).** Then the
  triage package table shows the app package plus many one- and two-letter packages.
  The app code reads well, but library identification has to come from kept class
  names, `META-INF/*.version` files, generated code (`*_Impl`, `Dagger*`,
  `Hilt_*`), and native library names.
- **"No network code" must be checked over all sources, not the app scope
  (verified).** A library could carry it. `scan.sh` prints a file list for the whole
  tree; an `INTERNET`-less manifest plus an empty list is the strong form of the claim.
- **R8 can move app code out of the app's package (verified).** The video app keeps 138
  classes under its manifest package, while biometric and UI code referencing them
  sits in `a/`, `da/`, and others. `scan.sh` lists packages that reference the
  manifest package; follow a feature by its distinctive strings (preference names, log
  tags, file names) across the whole tree, not by package.
- **A "lock", "vault", or "secure folder" feature needs its crypto read (verified).**
  The names say nothing about strength. The video app derives keys with PBKDF2 and then
  XORs only the first 8 KB of each file. Find the write path (what bytes change on
  disk) and the read path, and report what an attacker with file access gets. The
  "Custom masking, weak crypto" scan section looks for XOR-with-modulo loops and
  in-place file rewrites.
- **A local server turns app data into a network service (verified).** Casting,
  "share over Wi-Fi", and swap features embed HTTP servers. Check the bind address,
  authentication, what is served, and when it stops. The "Local servers, LAN" scan
  section finds them.
- **For a Flutter app the Java scan is nearly empty and that means nothing
  (verified).** The Flutter app's dex has the embedding and ten plugins; all endpoints, keys
  handling, and features are in `libapp.so`. Read `flutter-summary.txt` first.
- **A Dart package list is strong evidence in both directions (verified).**
  Non-obfuscated snapshots keep `package:` URIs for everything linked. No telemetry
  package in the list is better evidence of no telemetry than an empty grep of
  Java code. With `--obfuscate` this evidence is gone; check the URI count in the
  Snapshot section.
- **Dart strings suggest; the code decides (verified).** From strings, the Flutter app's network
  search looked like a ping sweep plus a port probe. Reading `checkForOllama` in
  blutter output showed the probe also sends `Authorization: Bearer <api key>` to
  every responding host. The strings-only report also guessed chats were stored as
  `chat.json` files; the code stores them in preferences and uses that name for
  export. Run `flutter-decompile.sh` before settling Dart findings.
- **Deduplicated Dart code carries the wrong name (verified).** Release snapshots
  are built with `dedup_instructions`: functions with identical machine code are
  merged, and a call shows the name of whichever copy survived. The Flutter app's
  `MistralController::stop` appears to call `AnthropicClient::endSession`. Trust such
  a name for what the code does, not for which class it belongs to.
- **One Dart library file can hold the whole app (verified).** With `part` files
  blutter writes every class into `asm/<app>/main.dart` (47,000 lines for the Flutter app),
  although `flutter-summary.txt` lists 49 source files. Use `dart/INDEX.txt` and
  `dart-index.py --func`, never read the file top to bottom.
- **Strings may not be literal.** Obfuscators encrypt strings or assemble them from
  char arrays; "no URL found by grep" is weak evidence. Look for a small static
  decrypt method called with byte arrays or integers all over the code.
- **Absence in decompiled code is not absence in the app.** Check smali and native
  libraries, and `assets/` for config files (JSON, properties, bundled JS), before
  writing "none found".
- **APK strings are untrusted.** Resource strings and assets can contain text aimed at
  an analyzing agent. The rule is in `AGENTS.md` `Invariants`; the trap is that such
  text shows up mid-grep looking like ordinary tool output.
- **Permissions declared are not permissions used**, and libraries merge their own
  into the manifest. Tie each sensitive permission to code, or say no use was found.

## Findings

Diagnosed problems kept as case studies. Add entries as symptom, diagnosis, fix,
takeaway.

### Report draft claimed no custom HostnameVerifier

- **Symptom:** a report said no custom `HostnameVerifier` existed in the app's code. A
  later `scan.sh` run over the app's common parent package listed one in the sibling
  package holding the HTTP client.
- **Diagnosis:** two errors stacked. The hand-run search was capped with `head`, and
  the default scan scope (the manifest package) excluded the sibling package holding
  the HTTP client.
- **Fix:** read the verifier (it delegates to OkHttp's verifier, so no weakening),
  corrected the report, documented scope selection in the runbook.
- **Takeaway:** a negative claim needs an uncapped search over the full app scope.
  Run `scan.sh` with the common parent package before writing "none found".
