# Reference: scripts, commands, container

Lookup material for the tools. The order of work is in [workflow.md](workflow.md).

## Contents

- Repository layout
- Scripts
- Commands
- Container and network
- Third-party tools
- Local model (experimental, off by default)

## Repository layout

| Path                     | Role                                                                    |
|--------------------------|-------------------------------------------------------------------------|
| `data/`                  | input APKs, read-only (mounted read-only in the container); any subdirectories; benchmark APKs in `data/ghera/`, `data/maleval/` (live malware), `data/vulnapps/`; gitignored |
| `work/<name>/`           | derived output per APK, disposable, gitignored                          |
| `work/<name>.emb<k>/`, `work/<name>.dec<k>/` | child samples: payloads found by content or decrypted by script (`payload-decrypt.py`), and payloads decrypted by the decryption stage |
| `work/_*/`               | not samples: reference cache, gate metrics, agent benchmark runs, evidence bundles (`work/_evidence/<name>/`), APKs taken out of sample archives (`work/_samples/`) |
| `reports/<name>.md`      | the analysis report, the only authored output per sample                |
| `scripts/`               | everything that runs in the container (mounted read-only)               |
| `prompts/`               | prompt templates for subagent stages (`decrypt.md`, `verify-report.md`, `read-area.md`, `verify.md`); `prompts/bench/` for benchmarks |
| `AGENTS.md`              | the instructions for any coding agent; `CLAUDE.md` imports it for Claude Code |
| `roles/`                 | harness-neutral subagent roles: `reader` (no shell), `decryptor` (listed `./cupella` commands only) |
| `.claude/agents/`        | Claude Code agent types `apk-reader`, `apk-decryptor`, generated from `roles/` by `./cupella setup` |
| `cupella`                | wrapper: runs a script from `scripts/` in the container; also `setup` (first use, workspaces), `build`, `versions`, `shell`, `sync`, `gate`, `check`, `help` |
| `bench-setup`            | fetches the benchmark datasets, checked against `bench-sources/` (host side; downloads and extraction only) |
| `bench-sources/`         | source and hash of every benchmark file; never shown to analysis agents |
| `docs/`                  | the project web site (static, GitHub Pages: serve from `docs/`); not agent documentation, which is `agent_docs/` |
| `.claude/settings.json`  | project permission rules: `./cupella` allowed, host parsing tools and `adb` denied |
| `.cupella-workspace`     | marks a workspace made by `./cupella setup --workspace` and records the checkout path, the harness, and a stamp of the copied docs. A workspace has its own `data/`, `work/`, `reports/`, `proposals/`; read-only copies of `AGENTS.md`, `agent_docs/`, `prompts/`, `roles/`; `WORKSPACE.md`; a `cupella` wrapper; for Claude Code also `CLAUDE.md`, `.claude/settings.json`, and agent types. Every `./cupella` run there refreshes the copies when the checkout changed |
| `host/gate.sh`           | benchmark gate for rule changes, run as `./cupella gate baseline`, then `./cupella gate` |
| `host/check.sh`          | regression run after script changes, run as `./cupella check [--no-gate]`: fixtures, native fixture (built with the host's clang), `cite-check.py` on every report, gate |
| `Dockerfile`             | the analysis image; tool versions pinned here                           |
| `bench/`                 | benchmark metadata and answer keys; gitignored; never shown to analysis agents |
| `cache/`                 | blutter builds per Dart version; gitignored, safe to delete (costs a rebuild) |
| `agent_docs/`            | runbooks, workflow, report format, traps, benchmarks, further work      |

## Scripts

Pipeline (run by `unpack.sh` and `scan.sh` unless noted):

| Script                        | Role                                                                    |
|-------------------------------|-------------------------------------------------------------------------|
| `unpack.sh`                   | stage 1: identity, unpack, decode, decompile, embedded payloads, `triage.txt` |
| `scan.sh`                     | stage 2: pattern searches (`scan.txt`), structure leads, flows, jadx retry; the pattern table lives here |
| `apkunzip.py`                 | extracts every APK as Android reads it (fake encryption, shadowed entries), under decompression limits, without symlinks; writes `repaired.apk` when it finds anomalies |
| `class-coverage.py`           | classes jadx did not produce, classes defined in more than one dex, misleading or overlong class names; in `triage.txt` |
| `axml2xml.py`                 | binary XML to text, tolerant of tampered manifests; fallback when apktool fails |
| `dexlist.py`                  | class names and string pool from dex files, no decompiler needed        |
| `sample-archive.py`           | lists a password-protected sample archive (ZipCrypto or WinZip AES, password "infected" by default) and extracts the APK in it to `work/_samples/`; `data/` is not changed |
| `embedded.py`                 | finds dex and dex archives inside the APK by content                    |
| `payload-decrypt.py`          | decrypts payloads whose key is a constant in the APK: tries DES, 3DES, AES, RC4, and XOR with every dex string, byte array, and native string on files that look encrypted, and keeps results that are a dex, a ZIP with dex, or an ELF; `unlocked/`, `unlocked.txt` (cipher, key, where the key is), `encrypted-left.txt` (not decrypted); run by `unpack.sh`, which unpacks the results as `.emb<k>` |
| `manifest-summary.py`         | permissions, app flags, reachable components with filters, priorities, task attributes |
| `apksig-verify.py`            | verifies v2/v3 signatures (via `openssl`) and v1 (via `jarsigner`)      |
| `apksigblock.py`              | signer certificates from the v2/v3 signing block                        |
| `trackers.py`                 | Exodus Privacy tracker matches on classes and host names                |
| `native-summary.py`           | per-library facts: identity, JNI surface, imports by capability, strings |
| `hermes-decompile.sh`         | React Native: decompiles a Hermes bundle with hermes-dec                |
| `flutter-summary.py`          | Flutter: Dart packages, source files, URLs, channels from the AOT snapshot |
| `flutter-decompile.sh`        | Flutter: blutter output and `dart/INDEX.txt`                            |
| `scope.py`                    | default scan scope: manifest package, component packages, R8-flattened app packages, minus libraries; `--why` gives reasons |
| `stringfog.py`                | decodes string-decoder calls with constant arguments (one or two String arguments): Base64/hex with XOR, DES, AES, or RC4 and the key at the call, plain Base64 or hex, or a key searched among the dex constants; number-table strings (`decode(table, offset, length, key)` and per-class `NAME(start, end, key)`, read from the jadx sources, `string-tables.tsv`; its copies are listed in `jadx-strings/TABLES.txt` and replaced on a rescan, other files in `jadx-strings/` are left alone); `string-map.tsv`, `jadx-strings/`; `scan.sh` runs it, `payload-decrypt.py` uses its plaintexts as keys |
| `code-vs-package.py`          | permissions the code names but the manifest does not request; native libraries the code loads but the APK does not ship; run by `scan.sh` |
| `family-markers.py`           | matches strings against published family markers (`family-markers.tsv`, each row with its source); run by `scan.sh` |
| `jadx-retry.sh`               | re-decompiles failed methods in jadx's simple mode; an inner class jadx writes as its own file (a Kotlin lambda) is retried by itself |
| `structure-leads.py`          | leads from call graph and control structure: entry points, coordinators, dispatch, loops, decoders, capability map |
| `flows.py`                    | source-to-sink data flows in bytecode (`flows.txt`)                     |

On demand:

| Script                        | Role                                                                    |
|-------------------------------|-------------------------------------------------------------------------|
| `xref.py`                     | callers and callees of a Java, native, or Dart function; `~> outside` marks a callee reached through code outside the scan scope |
| `callgraph-check.py`          | checks the Java call graph against androguard: decoding, the mapping of dex methods to jadx functions, lost and added calls; `callgraph-check.txt` |
| `behavior-map.py`             | Mermaid call graph of one function (callers to entry points, callees to capabilities) for a report finding; `work/<name>/maps/` |
| `quark-query.py`              | runs one Quark rule with Quark Script: each occurrence with its jadx location, argument values at the call sites, and hardcoded literals |
| `annotate-strings.py`         | copies of jadx files with each decrypted string call followed by its plaintext (`jadx-strings/`); run by `run-decryptor.sh` when the decryptor writes `out/string-map.tsv` |
| `dex-disasm.py`               | bytecode listing of chosen methods by control flow; for methods jadx and baksmali reject (junk in dead code) |
| `native-disasm.py`            | annotated disassembly of chosen functions (arm64; 32-bit ARM/Thumb mode detected) |
| `native-decompile.sh`         | Ghidra headless decompile to C (postprocessed by `ghidra/postprocess.py`) |
| `dart-index.py`               | condensed listing of a Dart function from blutter output                |
| `apk-diff.py`                 | changes between two unpacked APKs                                       |
| `reference-check.py`          | compares native libraries with official builds and pub.dev sources (network) |
| `run-decryptor.sh`            | lints and runs an agent-written decryptor locked down, then unpacks and scans its outputs as `.dec<k>` (not `out/parts/`), annotates strings, removes stale children |
| `decryptor-lint.py`           | rejects decryptors that could run code or reach the network             |
| `cite-check.py`               | checks a report's citations against `work/`                             |
| `lead-eval.py`                | scores lead files against the functions a report's Findings cite        |
| `evidence-bundle.py`          | collects what a report cites into `work/_evidence/<name>/`: excerpts of the cited lines, cited native and Dart functions, small cited text files, and `INDEX.md`; text only |
| `quark-scan.sh`               | runs Quark-Engine on a sample (`-n <name>`: `repaired.apk` when present) or APK paths; result cached in `tools/quark.json` (`tools/quark.failed` after a failure; `-f` reruns); `scan.sh` runs it |
| `quark-leads.py`              | Quark-Engine matches (80%/100%, by calling method) as `quark-leads.txt`, app scope first; `scan.sh` runs it |
| `model-leads.py`              | experimental, off by default: local-model reading list (`model-leads.txt`) |
| `blutter-build.sh`            | builds blutter for one Dart version; called by `./cupella` when needed      |

Benchmarks ([benchmarks.md](benchmarks.md)): `fix-eval.py`, `bench-maleval.py`,
`bench-maleval-agent.py`, `bench-ghera-blind.py`, `bench-ghera-score.py`; tool
comparison: `bench-quark-leads.py` (Quark leads vs. the existing leads on MalEval), `mobsf-scan.py` (runs in
MobSF's own pinned image, offline; `./cupella` gives it our jadx through `cache/`),
`bench-tools.py` (APK lists, tool findings to verdicts).

Library modules: `units.py` (functions and call graphs of Java, Dart, native output),
`dex.py` (dex bytecode reader), `elf.py` (ELF reader), `android_perms.py` (platform
permissions and protection levels from apktool's framework), `llav_client.py` (model
client). `scripts/fixtures/` holds the source of a test library for the native scripts
and three checks: `zipslip-test.sh` (extraction stays inside the sample's directory,
decompression limits hold), `elf-headers-test.sh <lib.so ...>` (the ELF reader gives the
same facts without section headers), and `injection-test.sh` (the prompt-injection scan
sees every place text can hide). Run them with `./cupella fixtures/<name>`.

## Commands

```bash
./cupella build                                   # user runs this once, and after Dockerfile changes
./cupella versions                                # tool versions in the image
./cupella sync                                    # in a workspace: refresh the doc copies now
./cupella help                                    # commands and scripts
./cupella unpack.sh data/<path>/<name>.apk [-f]   # stage 1; skips steps already done, -f redoes them
./cupella scan.sh <name> [source-subdir ...]      # stage 2; an explicit scope is saved and reused; --default-scope resets
./cupella manifest-summary.py <name>              # rerun alone after a manifest re-decode
./cupella structure-leads.py <name> [scope ...]   # rerun after native-decompile.sh
./cupella flows.py <name> [scope ...]             # rerun alone after changing sources or sinks
./cupella xref.py <name> <Class.method|FUN_...|Class::method> [--depth N]
./cupella callgraph-check.py <name> [scope ...]   # after changing units.py or dex.py: "lost" and functions without a dex method must be 0
./cupella behavior-map.py <name> <Class.method|util/Foo.java:120> [--up N] [--down N]   # Mermaid map for a finding
./cupella quark-query.py <name> <rule-id|work/<name>/quark-rules/x.json>     # values passed at an API pair's call sites
./cupella dex-disasm.py <name> <Class[.method]>   # bytecode jadx failed on; --list to list classes
./cupella scope.py <name> --why                   # default scope with the reason for each path
./cupella stringfog.py <name>                     # decode constant-argument string calls (scan.sh runs it)
./cupella annotate-strings.py <name> <map.tsv>... # jadx-strings/ from string maps (run-decryptor.sh, stringfog.py run it)
./cupella code-vs-package.py <name> [scope ...]   # permissions and libraries the code needs but the APK lacks (scan.sh runs it)
./cupella family-markers.py <name>                # published family markers (scan.sh runs it)
./cupella class-coverage.py <name>                # classes jadx did not produce, duplicates, odd names (unpack.sh runs it)
./cupella fixtures/zipslip-test.sh                # extraction stays inside the sample; decompression limits hold
./cupella fixtures/injection-test.sh              # the injection scan sees every place text hides
./cupella fixtures/manifest-tricks-test.sh        # a manifest hidden by ZIP and binary-XML tricks is still read
./cupella fixtures/elf-headers-test.sh <lib.so>...# the ELF reader without section headers
./cupella native-disasm.py <lib.so> --jni         # annotated disassembly; see runbook-native
./cupella native-decompile.sh <lib.so> [fn]       # Ghidra C output
./cupella flutter-decompile.sh <name>             # unpack.sh runs it for Flutter apps
./cupella dart-index.py <name> --func <Class::name>
./cupella apk-diff.py <old> <new> > work/<new>/diff-from-<old>.txt
./cupella reference-check.py <name> > work/<name>/reference-check.txt   # NETWORK
./cupella run-decryptor.sh <name>                 # decryption stage
./cupella sample-archive.py data/<file>.zip        # a sample that came as a password-protected archive: APK to work/_samples/
./cupella cite-check.py <name>                    # before finishing a report
./cupella evidence-bundle.py <name>               # for a report to be published: the cited lines as work/_evidence/<name>/
./cupella lead-eval.py [-v] <name>                # lead files vs. the report's Findings
./cupella gate baseline; ./cupella gate           # rule loop
./cupella check [--no-gate]                       # regression run after script changes
./cupella model-leads.py <name> [java-scope ...]  # experimental, off by default; needs llav
./cupella --llav <script> [args]                  # any script that imports llav_client
```

Benchmark commands are in [benchmarks.md](benchmarks.md).

## Container and network

Every script runs in the image through `./cupella`: read-only root, all capabilities
dropped, the calling user's uid, `scripts/`, `data/`, and `cache/` read-only, `work/`
read-write. Limits against hostile input: memory 12 GiB (`APK_MEMORY`), 4,096
processes, 4 GiB per written file (`APK_FSIZE`), 30 minutes per tool run
(`APK_TOOL_TIMEOUT`; reached limits are listed in the triage), decompression 1 GiB per
entry and 8 GiB per APK (`APK_ENTRY_MAX`, `APK_TOTAL_MAX`), nesting of embedded or
decrypted payloads three levels deep. `cache/` holds blutter builds that later analyses execute, so only the
build container, which sees neither `data/` nor `work/`, writes it. Paths are relative to the repo root; absolute host paths do not
exist inside the container. Output redirection (`> work/...`) happens on the host.

Mount exceptions: `cite-check.py` and `lead-eval.py` also see `reports/`, and
`bench-*.py` see `bench/`, both read-only. `run-decryptor.sh` runs the decryptor with
only that sample's directories mounted, read-only except its `decrypt/`.

Everything runs with `--network none` except:

- `reference-check.py`: lookups in a fixed allow-list of public registries, sending
  only public identifiers.
- Building blutter for a Dart version that `cache/` does not have: automatic, in a
  container with `scripts/` and `cache/` but not `data/` or `work/`. It takes several
  minutes once per Dart version; let it finish.
- `--llav` (below).

## Third-party tools

Inside the image, pinned in `Dockerfile` (`./cupella versions` prints what was built):

| Tool                                         | Pinned as                                           | Used by                                                                          |
|----------------------------------------------|-----------------------------------------------------|----------------------------------------------------------------------------------|
| jadx                                         | version and sha256                                  | `unpack.sh` (Java decompilation), `jadx-retry.sh`, MobSF comparison              |
| apktool                                      | version and sha256                                  | `unpack.sh` (manifest, resources, smali)                                         |
| Ghidra                                       | version, date, and sha256                           | `native-decompile.sh`                                                            |
| blutter                                      | git commit                                          | `flutter-decompile.sh`; built per Dart version by `blutter-build.sh`             |
| APKiD                                        | version                                             | `unpack.sh` (`apkid.txt`: packers, protectors, obfuscators)                      |
| hermes-dec                                   | git commit                                          | `hermes-decompile.sh` (React Native Hermes bytecode)                             |
| Quark-Engine, quark-rules                    | version; rules at a git commit                      | `scan.sh` (`quark-scan.sh`, `quark-leads.py`), `quark-query.py`, tool comparison |
| androguard                                   | the version Quark-Engine pins                       | `callgraph-check.py` (reference for the call graph)                                    |
| Exodus Privacy tracker list                  | snapshot at build, checksum in `./cupella versions` | `unpack.sh` (`trackers.txt`)                                                     |
| capstone (`cstool`)                          | Debian package                                      | `native-disasm.py`; libcapstone also for the blutter build                       |
| binutils                                     | Debian package                                      | `scan.sh` (`strings` on `resources.arsc`)                                        |
| openssl                                      | Debian package                                      | `apksig-verify.py` (signature certificates)                                      |
| pycryptodome                                 | Debian package                                      | agent-written decryptors (the one crypto module `decryptor-lint.py` allows)      |
| OpenJDK 21                                   | Debian package                                      | runs jadx, apktool, Ghidra                                                       |
| cmake, ninja, g++, ICU, pyelftools, requests | Debian packages                                     | the blutter build and blutter itself, not Cupella's scripts                      |

Outside the image, all optional:

| Tool              | Where                           | Used by                                       |
|-------------------|---------------------------------|-----------------------------------------------|
| MobSF             | its own image, pinned by digest | `mobsf-scan.py` (benchmark comparison only)   |
| llav model server | the host or `LLAV_URL`          | `model-leads.py`, `--llav`                    |
| clang, ld.lld     | the host                        | `./cupella check` (builds the native fixture) |

Everything else (dex parsing, call graph, flows, pattern scans, string decoding, ZIP
extraction, ELF and binary-XML reading) is Cupella's own Python standard-library code in
`scripts/` (`dex.py`, `units.py`, `elf.py`, `apkunzip.py`, `axml2xml.py`, and the
scripts that use them).

## Local model (experimental, off by default)

Experimental and off by default: no script, scan, gate, or check runs it; it runs only
when invoked as below. It has added no coverage on any benchmark
([further-work.md](further-work.md)).

If a llav server runs on the host (`python3 -m llav --gguf <model> --host <gateway>
--port 8080`), `./cupella model-leads.py` and `./cupella --llav <script>` reach it as
`http://host.docker.internal:8080`. That container runs on the internal Docker network
`cupella-llav`: it reaches the host and has no route beyond it. `<gateway>` is that
network's gateway address, which `./cupella` prints when it cannot connect; a server bound
to `127.0.0.1` is not reachable from a container. Without a server the step is skipped
with a message; nothing else depends on it.

A remote llav server can be used by setting `LLAV_URL` (and `LLAV_API_KEY_FILE`) on the
host. That sends function text to the server and gives the container network access:
never do it for a sample unless the user asked for that server.

What the model step is good for: it flags functions whose purpose shows in their own
text, including renamed and stripped code; it misses functions whose meaning is in
their context (main loops, dispatch, thin wrappers); scores are nearly all 0 or 1. It
has not surfaced a finding that the scan, structure leads, flows, and reading missed.
Never cite a score.
