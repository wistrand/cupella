# Developing Cupella

For changing Cupella itself: scripts, the container, the harness, and the docs. An
analysis does not need this file; the rules every session follows are in
[AGENTS.md](../AGENTS.md), analysis traps in [gotchas.md](gotchas.md). Before changing
scan patterns, scope, or lead scripts, also read [benchmarks.md](benchmarks.md) and
[workflow.md](workflow.md) "Improving the scripts".

## Contents

- Script conventions
- Feeding the scripts
- Documentation style
- Traps

## Script conventions

- Scripts: bash with `set -euo pipefail`, or Python 3 standard library only; 2-space
  indent; a usage header comment.
- A script that needs a new external program gets it added to `Dockerfile` in the same
  change, with a pinned version and checksum where it is downloaded.
- Scripts find external tools under `$APK_TOOLS` (set by the image), never by a
  hardcoded path. The scripts that call jadx, apktool, Ghidra, or blutter refuse to run
  when it is unset, that is, outside `./cupella`.
- Scripts stay APK-independent (`AGENTS.md` Invariants): never a package name, path, or
  expectation from one sample.
- After any script change run `./cupella check`; after changing scan, scope, or lead
  scripts, `./cupella gate baseline` before and `./cupella gate` after.
  `host/ci-quick.sh` runs the Docker-free part, as CI does.

## Feeding the scripts

The scripts improve only if sessions put back what they learn:

- A search you ran by hand and would run again: add a `scan` line to `scripts/scan.sh`.
- A fact you extracted by hand from the unpacked tree: add it to the triage section
  of `scripts/unpack.sh` or to `scripts/manifest-summary.py`.
- A new file format you had to decode: a new script, listed in the script table of
  [reference.md](reference.md).
- Keep additions APK-independent, rerun the script on a sample, and read its output
  before relying on it.
- After changing `scan.sh`, `scope.py`, `units.py`, `flows.py`, or the unpack steps,
  follow [workflow.md](workflow.md) "Improving the scripts" (gate, lead-eval).
- When reading finds something no lead pointed to, propose the pattern or check that
  would have, add it, and run the gate.

## Documentation style

- Markdown links for doc references you want an agent to follow, not backticks.
  Backticks are fine for source paths in tables and inline code. Align table columns.
- State each rule on its own line as always/never.
- Keep `AGENTS.md` the routing entry point; move detail into `agent_docs/`.
- A doc that only some analyses need starts with a "Read when" line naming a condition
  the agent can see in the script output or the request, and `AGENTS.md` or
  `workflow.md` routes to it. Keep the always-read set (`AGENTS.md`, `workflow.md`,
  `runbook-analysis.md`, `design-report.md`, the Core of `gotchas.md`) short.

## Traps

Delete an entry when the code no longer allows the mistake.

- **Printable output does not prove a key (verified).** Searching the dex constants for
  a string decoder's XOR key "found" keys on two samples whose output was printable noise
  (`tue^cb&~v<`): structured ciphertext XORed with an ASCII key is mostly printable.
  `stringfog.py` does not search XOR keys, and accepts a searched key only when the
  results read like names and messages. `payload-decrypt.py` has no such problem: a
  wrong key cannot produce a dex with a matching header or a ZIP that opens.
- **apktool 3 has no `--help` on the subcommand (verified).** `apktool d --help`
  prints "Unrecognized option" followed by the usage text. The flags used by
  `unpack.sh` (`d -f -o`) are valid in 3.0.3.
- **jadx renames package segments, so a package name is not a path under
  `jadx/sources/` (verified, 2026-10-31).** A segment that is not a valid Java name for
  jadx (`me`, `in`, `a1`) gets a numbered prefix: `me.nanoleaf.nanoleaf` is written to
  `p258me/nanoleaf/nanoleaf/`, with no "renamed from" comment on the classes. A script
  that turns a manifest package into a directory must follow the rename, or the whole
  app falls out of scope: `scope.py` (`jadx_dir`), `units.py` (strips `^p\d{3}` from
  path segments), and `class-coverage.py` do; copy one of them rather than
  `os.path.isdir(pkg.replace(".", "/"))`. Matching a manifest component to its code
  goes through a unit's `inner` (the binary class name), never the jadx file path
  (`behavior-facts.py`, `structure-leads.py`).
- **Case-insensitive name clashes** from obfuscators (`a.java` and `A.java`) are not a
  problem on Linux but make output unusable if `work/` is copied to macOS or Windows.
- **Substring patterns bite in string classification (verified).** "frida" matched
  "Friday" in llama.cpp's date strings. Patterns in `native-summary.py` need word
  boundaries; when a category has one odd hit, read the hit.
- **Demangled template functions start with their return type (verified).**
  `void std::__ndk1::vector<...>::__push_back_slow_path<...>(...)` begins with
  `void`, so a "starts with `std::`" filter misses it. Strip template arguments and
  the return type before classifying a symbol.
- **Never clear a directory that several scripts write (verified, 2026-10-04).**
  `jadx-strings/` holds copies from `stringfog.py`, `annotate-strings.py` (also run by
  the decryption stage), and test fixtures. A cleanup in `stringfog.py` that removed the
  whole directory deleted the others' files on every rescan; the injection fixture
  caught it. Remove only files the script lists as its own (`jadx-strings/TABLES.txt`).
- **MobSF and Quark need help to run offline and read-only (verified).** MobSF writes
  migration files into its own code directory (run a copy on tmpfs) and downloads jadx
  on first use (`./cupella` gives it ours through `cache/`); Quark writes a dated log file
  into the current directory (run it from `/tmp`) and crashes on ZIPs with
  fake-encrypted entries. A search of `/` for MobSF's install path walked all of
  `work/`: never search the file system in a container that mounts `work/`.
- **Agents without a shell have no clock (verified).** Reader and scorer agents could
  not fill in "HH:MM" in progress files and wrote "--:--". Progress lines are numbered
  steps; the file's modification time shows when it last moved.
- **A pipeline with grep in a `$(...)` aborts the script under pipefail when grep finds
  nothing (verified).** `depth=$(grep -o ... | wc -l)` killed `unpack.sh` for every
  sample whose name had no match; the fixture caught it. Wrap such greps in
  `(grep ... || true)`.
- **Without section headers, the dynamic symbol count must come from DT_GNU_HASH
  (verified).** Libraries with only a GNU hash table lost their imports in `elf.py` once
  the section headers were removed; `./cupella fixtures/elf-headers-test.sh <lib.so>` checks
  the fallback.
- **Scripts run in a container; paths and tools differ from the host.** Inside,
  the repo is `/repo`, tools are under `/opt/tools`, `HOME` is a tmpfs, and there is
  no network. A path outside `data/`, `work/`, `cache/`, `scripts/` does not exist
  there, and `scripts/` is read-only. A script that works on the host but fails under
  `./cupella` usually wrote somewhere else or called a program that is not in the
  `Dockerfile`.
- **The container runs in the C locale and UTC (verified).** Compared with a host run
  in a Swedish locale: certificate dates print in UTC, sort order differs, and apktool
  adds float comments to smali (`# 1.3f`) that the host run omitted. The container's
  output is the reference.
- **`grep` differs between host and image.** The host has ugrep, the image GNU grep.
  Scripts use only options both accept (`-rn -E -e`, `-a -o`, `-F`, `-l`).
- **`grep` on this machine is ugrep (verified).** GNU-style flags used by the scripts
  work. An error like `invalid argument -m=l` came from a dash-leading file name in a
  glob (previous entry), not from ugrep itself.
- **The shell's working directory persists between agent commands.** After a `cd` into
  `work/`, relative paths to `scripts/` fail. Use absolute paths or `cd` to the repo
  root at the start of each command.
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
- **Scoring everything is slow and adds noise (verified).** 1,402 functions of the
  bot sample would have taken about an hour, most of it on the embedded C library and
  wolfSSL. The filter in `model-leads.py` (functions around strings of interest)
  cut that to about 300, some 12 minutes.
