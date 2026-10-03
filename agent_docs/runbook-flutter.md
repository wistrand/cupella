# Runbook: Flutter apps

## Contents
- Recognizing one
- What each tool sees
- Step 1: read the Flutter summary
- Step 2: follow features through the strings
- Step 3: read the Dart code (blutter)
- Step 4: the Java side
- Step 5: native libraries
- Writing the report
- Limits

## Recognizing one

`triage.txt` shows `found: assets/flutter_assets` and `lib/<abi>/libflutter.so`, and
`unpack.sh` prints "Flutter app" and writes `flutter-summary.txt` and
`flutter-strings.txt`. A release build has `libapp.so`; a debug build has
`assets/flutter_assets/kernel_blob.bin` instead (Dart kernel, far easier to read; say
so in the report).

## What each tool sees

| Layer                          | Where it is                  | What reads it here                         |
|--------------------------------|------------------------------|--------------------------------------------|
| App logic (Dart)               | `lib/<abi>/libapp.so`        | strings: `scripts/flutter-summary.py`; code: blutter via `scripts/flutter-decompile.sh` |
| Flutter engine and Dart VM     | `lib/<abi>/libflutter.so`    | `native-summary.txt`; treat as runtime     |
| Plugins, Android half          | `classes.dex`                | jadx, `scan.sh` with scope `.`             |
| Plugins and app, Dart half     | `libapp.so`                  | same as app logic                          |
| Other native libraries         | `lib/<abi>/*.so`             | [runbook-native.md](runbook-native.md)     |
| Assets                         | `assets/flutter_assets/`     | read directly                              |

jadx output for a Flutter app is the embedding, AndroidX, and plugin glue. A clean
Java scan says nothing about the app. The package named in the manifest usually has
one class, `MainActivity`.

## Step 1: read the Flutter summary

`flutter-summary.txt` sections and what to take from each:

- **Snapshot**: Dart SDK version; the feature string (`product` means release). A low
  count of Dart library URIs means the build used `--obfuscate`: package and file
  names are then gone and Step 2 works much less well. Say which case applies.
- **Dart packages**: the linked pub packages with a note on the ones that grant a
  capability (HTTP clients, telemetry SDKs, storage, device info, network scanning,
  FFI). This is the Flutter equivalent of the third-party library table and the
  fastest way to see what the app can do. An absent package is decent evidence the
  capability is absent, because a Dart app has to link a package or write the code
  itself.
- **App source files**: file names under the app's own package. They outline the
  feature set (controllers, pages, managers).
- **URLs, API paths, platform channels**: every endpoint literal in the Dart code.
- **Key-shaped literals, credential-related names**: embedded secrets and the names
  around credential handling.
- **Bundled assets**: data files worth opening (`.json`, `.env`, `.db`).
- **Android side**: plugins registered in `GeneratedPluginRegistrant` and channel
  names in Java code.

## Step 2: follow features through the strings

`flutter-strings.txt` holds every string in the snapshot, sorted. Non-obfuscated Dart
keeps function and field names, so features can be traced by name:

```bash
grep -i -E 'ollama|scan|subnet' work/<name>/flutter-strings.txt
grep -E '^get:|^set:' work/<name>/flutter-strings.txt      # property names
```

For each capability package from Step 1, grep for how the app uses it: the app-level
function names near it, the preference keys, the user-visible messages (localized
text often states what a permission is for). Private Dart symbols carry a library
suffix (`_name@123456`); the same number groups symbols of one library.

This gives intent and wiring, not behavior. Conclusions from strings alone are
"likely" at most; Step 3 is how they become "confirmed".

## Step 3: read the Dart code (blutter)

`./cupella unpack.sh` runs this step automatically for a Flutter app with an arm64
`libapp.so`. To rerun it:

```bash
./cupella flutter-decompile.sh <name>     # writes work/<name>/dart/ and dart/INDEX.txt
```

blutter is compiled once per Dart version. When `cache/blutter/` has no build for the
app's version, `./cupella` builds one first: it prints "building (network, several
minutes ...)", fetches the Dart runtime sources, and compiles, in a container that
cannot see `data/` or `work/`. Wait for it; later apps on the same Dart version start
immediately. If the build fails (a Dart version newer than blutter supports is the
usual cause), say so in the report and continue with Steps 1 and 2. arm64 only.

Output in `work/<name>/dart/`:

| File                  | Content                                                              |
|-----------------------|----------------------------------------------------------------------|
| `asm/<package>/*.dart`| annotated assembly per Dart library: classes, named functions, each instruction with a pseudo-code line, call targets and string literals resolved |
| `pp.txt`, `objs.txt`  | object pool entries and dumped constant objects                      |
| `INDEX.txt`           | from `scripts/dart-index.py`: the map of the app's own package       |

An app that uses `part` files has all its classes in one library file
(`asm/<app>/main.dart`), tens of thousands of lines. Never read it whole. Work from
the index:

1. Read `INDEX.txt` down to "## Functions". "Calls out of the package, by target
   package" lists, for every dependency, which app functions call it and what they
   call. This is where a capability from Step 1 turns into specific functions:
   who calls the HTTP client, the preferences store, the network scanner, the file
   picker, `dart:io`.
2. For each function of interest:

   ```bash
   ./cupella dart-index.py <name> --outline <Class::name>   # strings and non-core calls only
   ./cupella dart-index.py <name> --func <Class::name>      # full condensed pseudo-code
   ./cupella dart-index.py <name> --callers '<regex>'       # who calls a target
   ./cupella dart-index.py <name> --strings '<regex>'       # who loads a string literal
   ```

   Add `--all` to search dependencies too. Start with `--outline`: the sequence of
   string literals and calls usually shows what a function does (URL pieces, header
   names, the client method). Use `--func` when order, conditions, or which field
   feeds which argument matters.
3. Reading the condensed listing:
   - `r0 = name()   ; [library] Class::name` is a call; arguments were set up in the
     preceding lines (`r1` is `this` or the first argument, then `r2`, `r3`; extra
     arguments go on the stack with `str`/`stp ... [SP]`).
   - `rN = "text"` loads a string literal. Strings assembled with `_interpolate`
     appear as an array filled with pieces, in order.
   - `LoadField: r2 = r1->field_37` reads an object field by offset. Find what the
     offset means from the class's setter or getter: `--func 'Class::name='` shows
     which `field_NN` the setter `set name=` stores.
   - `cmp w1, NULL` / `r16 = true; cmp` followed by a branch is a condition. A
     nullable bool compared with `true` means "off unless explicitly set".
   - `GDT[cid_x0 + N]()` is a virtual call through the dispatch table; the target is
     not named. The surrounding strings and the receiver's class usually identify it.
   - `async` functions are split at each `await`; closures appear as separate
     `<closure>` functions under the same class.
4. To settle a default, find every write to the field: `grep -n 'field_43'` in the
   asm file, then check which function each write is in (constructor, `fromMap`,
   setter, `clear`).

Cite Dart evidence as the `dart-index.py` command and the function address.

Structure leads cover Dart too: `structure-leads.txt` has a "Capability map, Dart
and native" section listing the app's Dart functions that use the network, storage,
files, platform channels, and other capabilities, most-called first. It is the
counterpart of `scan.txt` (Java only) and covered all four Dart findings of the Flutter app
report. `./cupella xref.py <name> Class::method` gives a Dart function's callers and
callees.

## Step 4: the Java side

Run `scripts/scan.sh <name> .` (the dex is small). Check:

- the manifest as for any app: permissions, exported components, intent filters;
- each registered plugin: a plugin is native capability the Dart code can call
  (file picker, device info, WebView, sharing). Unused dev plugins
  (`integration_test`) sometimes ship; note them;
- plugin activities and providers in the manifest.

## Step 5: native libraries

`libapp.so` and `libflutter.so` aside, treat the rest per
[runbook-native.md](runbook-native.md). Libraries without JNI entry points are called
from Dart through `dart:ffi` (look for the `ffi` package and a binding package in
Step 1), so there are no Java callers to map; their exports are the interface.
`libflutter.so` imports sockets, `fork`/`execvp`, and `dlopen` because the Dart
runtime implements `dart:io` there; that is normal and says nothing about the app.
Run `scripts/reference-check.py <name>`: it compares `libflutter.so` byte for byte
with the official engine artifact, and checks libraries built from pub.dev packages
against the package sources (see [runbook-native.md](runbook-native.md) "establish
provenance"). Only an "IDENTICAL" result justifies calling the engine stock.

## Writing the report

Follow [design-report.md](design-report.md), with these adjustments:

- State in the Summary and in "Analysis coverage" that the app logic is Dart AOT, and
  whether it was read through strings only or through blutter output, and which
  functions were read.
- "Third-party libraries" lists Dart packages first, then Android plugins.
- "Network" comes from the URL and API path sections, with the client package that
  implies each endpoint's purpose.
- Findings about Dart behavior are `likely` at most from strings alone, and
  `confirmed` when the function was read in blutter output.

## Limits

- blutter gives annotated assembly, not Dart source: no types on locals, fields as
  offsets, virtual calls unnamed. It is good for answering a specific question about
  a specific function and poor for skimming an app.
- blutter supports arm64 `libapp.so` only and may lag behind the newest Dart
  release; when it fails on a new version, fall back to Steps 1 and 2 and say so.
- `scripts/flutter-decompile.sh` passes the Dart version to blutter directly, which
  avoids blutter's dependency on the Python module `pyelftools`. Snapshots built
  without compressed pointers are not covered by that shortcut; the script says so.
- With `--obfuscate`, names are replaced by meaningless ones in both the strings and
  the blutter output; URLs and string literals remain, so `--strings` still works.
- If the project is open source, comparing against the source is a useful cross-check.
  Say that it shows the source, not this binary.
