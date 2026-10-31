# Gotchas

Traps in APK formats and tooling. Read **Core** before trusting a search, a decompile,
or writing that something is absent; read any other section when its trigger shows up.
Entries marked (verified) were observed in this workspace with jadx 1.5.6 and apktool
3.0.3; the rest are known behavior of the formats and tools. Confirm an unverified
entry the first time it matters, then mark it or fix it.

Keep this file to traps an analysis can still hit: when a script starts handling a
trap, delete the entry in the same change (the script's header can say what it
handles). Traps for changing scripts, the container, or the harness are in
[development.md](development.md).

Sample names are anonymized: launcher A and launcher B are two third-party launcher
apps, the Flutter app is a third-party chat app, the video app is a third-party video
app, and malware is named by its public family (BTMOB, Octo).

## Contents

- Core
- Malformed APK or manifest
- Triage lines and dates
- apktool failed or short resource names
- Signing
- jadx failures, large apps, Kotlin
- String decoders and the decryption stage
- R8 renaming
- Native code
- Claims that something is absent or impossible
- Feature checks

## Core

Read these before any search result, decompile, or claim that something is absent.

- **Capped or skipped searches hide hits (verified).** `head` on a grep and grep's
  binary detection drop hits silently. `scan.sh` greps with `-a` and ends a section that
  reached its cap (`SCAN_MAX`) with a `[capped: N of M hits shown]` line: treat such a
  section as a sample, not a list. A
  hand-run grep capped with `head -20` dropped the one `HostnameVerifier` in an app,
  and a report draft said there was none; the default scan scope (the manifest package)
  also missed the sibling package holding the HTTP client. Kotlin `@Metadata` strings
  and number tables put control characters in jadx files, so `grep` without `-a`
  treats a file as binary (a 208 KB file with 40 methods listed none). Before a
  negative claim: an uncapped `grep -a` over the full app scope, or `scan.sh` with the
  common parent package.
- **Absence in decompiled code is not absence in the app.** Check smali and native
  libraries, and `assets/` for config files (JSON, properties, bundled JS), before
  writing "none found".
- **Strings may not be literal.** Obfuscators encrypt strings or assemble them from
  char arrays; "no URL found by grep" is weak evidence. Look for a small static
  decrypt method called with byte arrays or integers all over the code.
- **Decompiled Java is a reconstruction (verified).** Control flow, types, and
  `try/catch` scope can be wrong, most often in the obfuscated code that matters, and
  jadx's per-file warnings are not in its error log: search for `JADX WARN`, `Code
  decompiled incorrectly`, `Method dump skipped` (`scan.sh` counts the files in scope).
  In Kotlin coroutine code jadx inverted a hash check with no warning (the smali has
  `if-eqz` to the throw), and in a block marked `JADX WARN: Code duplicated` it printed
  a flag test with the opposite sense. A check that reads backwards, or one in a
  flagged or duplicated block, is more likely a decompile error than a bug: read the
  branch in `apktool/smali*/` or `./cupella dex-disasm.py` before reporting it.
- **jadx output varies between runs (verified).** Two runs on one APK differed in 11 of
  5,390 files (worker threads race), so line numbers shift by a few lines after a rerun
  with `-f`: cite the function as well as the line.

## Malformed APK or manifest

Read when triage shows ZIP anomalies, `INTERNET: unknown`, or a `manifest-note.txt`; or the input is a `.xapk`, `.apks`, or split APK.

- **A stored ZIP entry with a false compressed size truncates the manifest (verified,
  fixed).** `AndroidManifest.xml` with a compression method that is neither 0 nor 8 and a
  compressed size smaller than the data: Android reads it as stored, at the uncompressed
  size. `apkunzip.py` trusted the compressed size until 2026-10-03 and wrote the first
  4,094 of 11,700 bytes; `axml2xml.py` then printed an empty document without an error,
  the triage said "INTERNET: not requested", `manifest-summary.txt` was empty, and the
  scan scope fell back to everything. Signs of a manifest that was not read: no
  `<manifest` in `manifest.xml`, a `manifest-note.txt`, "INTERNET: unknown" in the triage.
  Never conclude anything from an empty manifest: check that jadx or apktool decoded one.
  `./cupella fixtures/manifest-tricks-test.sh` builds a synthetic APK with this trick and the
  tampering below; `axml2xml.py` now exits with an error when it decodes no element.
- **Not every `.apk`-like file is a single APK.** `.xapk`, `.apks`, `.apkm` are zips
  holding a base APK plus splits. A lone `base.apk` from a split install lacks the
  native libraries and density/language resources, so "no native code" may be wrong.
  `triage.txt` has a "Split APK" section when the manifest requires splits
  (`requiredSplitTypes`, `isSplitRequired`, `com.android.vending.splits.required`); for a
  Flutter app it means the Dart code (`libapp.so`) is in the ABI split and not analyzable
  from the base (4 MalEval samples).

## Triage lines and dates

Read when citing a triage `declares:` line, or writing a build date or timeline.

- **"declares: AccessibilityService" in the triage is a text match (verified).** It also
  fires on a `<queries>` entry for that action, in an app that declares no such service.
  Read `manifest-summary.txt` for the components.
- **Zip timestamps are meaningless (verified).** Build tools zero them (one
  app store client's entries are all dated 1981). Do not infer build dates from them.

## apktool failed or short resource names

Read when triage says apktool produced no output, or `raw/res/` has shortened names.

- **Resource file names in the zip can be shortened (verified).** With resource path
  shortening, `raw/res/` holds files like `res/8G.xml` and `res/-5.xml`; the names
  carry no meaning. apktool restores real names from `resources.arsc`
  (`apktool/res/xml/network_security_config.xml`). Without apktool, decode all of
  `raw/res/*.xml` with `axml2xml.py` and find a file by its root element.
- **File names starting with `-` break commands (verified).** Shortened resource names
  include `-1.xml`, `-B.xml`. Always pass `--` before file arguments or prefix globs
  with `./`.

## Signing

Read when the triage Signing section shows a weak algorithm or a debug certificate.

- **`keytool` flags old certificates as weak (verified).** A SHA1withRSA self-signed
  certificate is common on long-lived apps. For APK signing the identity is the key,
  not the certificate's self-signature. Report it, do not overstate it.
- **The debug certificate** has subject `CN=Android Debug, O=Android, C=US`. Worth a
  finding in anything presented as a release build.

## jadx failures, large apps, Kotlin

Read when the jadx error count in triage is high, jadx ran out of memory, or the app is Kotlin.

- **One Java file per outer class (verified).** Inner classes and lambdas fold into
  the outer class's file, so file counts are far below class counts (one app: 1,487
  classes of its own in 480 files). Do not compare the two numbers.
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
  `AnonymousClass1`, invalid package names get a prefix (`a1` to `p001a1`; also
  ordinary names jadx treats as reserved: `me.nanoleaf` is written to `p258me/nanoleaf/`,
  so a search under `jadx/sources/me/` finds nothing), and
  mangled method names (`foo-abc123`) are renamed. jadx leaves `/* JADX INFO: renamed
  from: <original>, reason: ... */` before the declaration. Matching jadx output to
  dex, smali, or stack traces by name fails without it; `units.py` reads these
  comments. A call graph guessed from jadx text by simple names links unrelated
  same-named classes (launcher A: 12,600 of 14,400 text-guessed edges are absent from the
  bytecode graph of 2,900; the ones spot-checked were wrong).
- **Kotlin coroutine code hides the chain in suspend lambdas (verified, 2026-10-04).**
  The work of a suspend function is in `invokeSuspend` of a class jadx prints as
  `AnonymousClass1` or `C0805`; the outer method only creates it. A behavior map shows
  `create`, `invoke`, and `invokeSuspend` nodes under the outer class's name and may
  stop there. Read the `invokeSuspend` body, and when jadx failed on it, the
  `jadx-retry/` rendering or `./cupella dex-disasm.py <name> '<Outer$method$1>'`.

## String decoders and the decryption stage

Read when scan.txt lists a string decoder, or the decryption stage runs.

- **Number-table strings come in two call shapes (verified).** The "np" protector stores
  each string as a slice of a per-class `short[]` XORed with a key. One sample called a
  shared decoder, `decode(table, offset, length, key)`, from the app's classes and a
  private `NAME(start, end, key)` from library classes; the next used only the second,
  in every class of the APK (41,548 calls). `stringfog.py` decodes both and picks the
  argument layout per shape. A method jadx could not decompile keeps its strings hidden
  (the decoder reads the jadx text): read it in `jadx-retry/` or with `dex-disasm.py`.
- **A script-decrypted payload and an agent-decrypted one can be the same file.**
  `payload-decrypt.py` (since 2026-10-03) unpacks what it decrypts as `.emb<k>`; a sample
  analyzed before that has the same payload as `.dec<k>` from the decryption stage
  (Faketoken: identical sha256). Compare the `sha256:` lines of the children's
  `triage.txt` before analyzing both, and cite one.

## R8 renaming

Read when the triage package table shows the app package next to many one- and two-letter packages, or trackers.txt has matches.

- **R8 renames libraries but often keeps the app's own package (verified).** Then the
  triage package table shows the app package plus many one- and two-letter packages.
  The app code reads well, but library identification has to come from kept class
  names, `META-INF/*.version` files, generated code (`*_Impl`, `Dagger*`,
  `Hilt_*`), and native library names.
- **Tracker signatures match names, not behavior (verified).** An app store client matches ACRA,
  which it uses to offer emailing a crash report. Launcher A matches seven Facebook
  signatures through one string, `www.facebook.com`, an entry in its own list of
  sites to gate. And "Google Ads" in the Exodus list is any `*.google.com` host.
  Report what the code does with the SDK or host.

## Native code

Read when native-summary.txt lists app libraries ([runbook-native.md](runbook-native.md)).

- **A `fork`/`exec` import is not always the app's doing (verified).** ggml's abort
  handler forks and tries to run `gdb` or `lldb` for a backtrace; every app bundling
  llama.cpp or whisper.cpp has it. `libflutter.so` imports `fork`/`execvp` and
  sockets for `dart:io`. Use `native-disasm.py --xref <import>` to find the caller
  and read it before reporting.
- **JNI signatures can start with `!` (verified).** ART's fast-native convention
  prefixes the signature string (`!(J)I`). A detector that requires `(` first misses
  those entries and reports a short table; `elf.py` accepts the prefix. Adjacent
  tables are split only where a method name repeats (one table per API level in the
  AndroidX graphics library); two adjacent tables for different classes print as one.
  Count unique methods, and take the per-class split from the `RegisterNatives` calls
  in `JNI_OnLoad`.
- **JavaVM and JNIEnv tables overlap at low offsets (verified).** Offset `0x30` is
  `JavaVM->GetEnv` in `JNI_OnLoad` and `JNIEnv->FindClass` elsewhere. The disassembler
  prints both; the first indirect call in `JNI_OnLoad` is `GetEnv`.
- **Stripped static ARM executables are often ARM mode, not Thumb (verified).** On the
  DDoS-bot sample (`assets/lol`, entry address even, no symbols) `native-disasm.py` used to
  decode ARM-mode code as Thumb. It now picks the mode from symbols, the entry bit, or a
  condition-field count, and prints its choice in each function header: check that line
  when the output looks like garbage. Ghidra's `@ 0x...` header comments in the C of such a
  binary are file offsets (image base 0x8000), not addresses.
- **Ghidra starts slower in the container (verified).** About 20 seconds for one
  function against 6 on the host, because its settings directory is a fresh tmpfs on
  every run. Ask for several functions in one call.

## Claims that something is absent or impossible

Read when writing "no network code", "cannot be started", or another negative claim (with the Core entries).

- **"No network code" must be checked over all sources, not the app scope
  (verified).** A library could carry it. `scan.sh` prints a file list for the whole
  tree; an `INTERNET`-less manifest plus an empty list is the strong form of the claim.
- **An activity with MAIN and category INFO but no LAUNCHER has no icon and can still
  be started by name (verified, 2026-10-04).** `getLaunchIntentForPackage` looks for
  category INFO first. Droppers install payloads built this way and start them; do not
  write "no way to start it" from the missing LAUNCHER category.

## Feature checks

Read when the app has a lock or vault feature, a local server, or DataStore preferences.

- **A preference's default is in the getter's fallback, not in XML, for DataStore
  apps (verified).** Compose apps have no `res/xml/preferences.xml`. Find the key in
  the DataStore wrapper class and read what it returns when the value is null
  (launcher A: retention falls back to `INDEFINITE`).
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
