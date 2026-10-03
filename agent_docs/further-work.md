# Further work

What the analyzer cannot do yet, ordered by how much it would change results, with the
evidence behind each item. Numbers are from [benchmarks.md](benchmarks.md). Update this
file when an item is done or new evidence moves it.

## Contents

- Coverage gaps (largest effect)
- Detection gaps
- Measurement
- Tooling and operations
- Out of scope by design

## Coverage gaps (largest effect)

1. **Native decryption layers.** The agent decryption stage recovered all six
   encrypted MalEval samples at least in part and raised behavior recall on them from
   50% to 66%. What remains is native: Octo and Coper (same packer) decrypt their final
   dex inside `libcyqcXW.so` with a key derived at run time (`make_AES_key`, `get_salt`).
   Next steps: native-aware decryption prompts (Ghidra output of the unpack routine),
   and turning the recurring schemes (DES-ECB with a constant key between zlib layers,
   RC4 with a constant key, ZKM-style XOR string tables, AES-CBC with key and IV at the
   call site) into a script that recognizes and decrypts them without an agent. Done
   for constant-argument string decoders (`stringfog.py`: Base64+XOR and XOR, 5,032 of
   the agent's 5,030 strings on the BTMOB sample); the payload schemes remain.
2. **Flows through R8-renamed libraries.** `flows.py` finds sources and sinks by API
   name, so when Room, DataStore, or OkHttp are renamed the path ends at an unnamed
   call (launcher A's screen-text-to-database finding is invisible to it). Next step:
   identify renamed library classes by their string constants and class shapes against
   a small table of library signatures, and map them back to known sinks.
3. **Native code in flows and structure.** Native functions get call graphs and
   capabilities, but data flows stop at JNI. Next step: treat JNI calls with tainted
   arguments as leads into the native function, and add native sources and sinks
   (`send`, `write` on sockets, `system`) for dynamically linked libraries.
4. **Dart.** `units.py` builds Dart call graphs from blutter output, but there are no
   Dart flows, and Flutter apps split across config APKs lose `libapp.so` (one benign
   MalEval app). Next steps: Dart sources and sinks from blutter call annotations; a
   triage note when `libapp.so` is missing from the APK.

## Detection gaps

From the agent benchmarks; each is small and testable on the same samples.

- Hard-coded credentials and endpoints in resources and cloud configuration: scan
  sections added and gated ("Secrets in resources", "Cloud configuration"); confirm
  in the next vulnapp agent run that the OVAA `test_url` item is now found.
- Logic flaws a pattern cannot find (username enumeration, parameter manipulation,
  weak change-password flows in InsecureBankv2): runbook guidance on reading
  authentication flows end to end.
- Clipboard use (missed in InsecureBankv2 though `scan.sh` has a section): check why
  the lead was not followed.
- Over-claimed malware behaviors (Tricky Behavior and Privilege Escalation at 50%
  precision on MalEval): definitions tightened in the runbook and the prompt; rerun to
  confirm.
- Fixed-app reports on Ghera (8 in round 2): six of round 1's eleven were missed
  guards. Check the round-2 eight by hand and add any recurring guard to the checklist.
- Ghera misses that remain: certificate pinning absence, WebView HTTP auth reuse, and
  the five-pair set as a whole (2 of 5 after tuning).

## Agent stages

- Report verification has a prompt (`prompts/verify-report.md`) used twice: the Octo
  report (3 wrong, 4 overstated of 25 claims) and the BTMOB report (1 wrong, 10
  overstated of 56; most were features whose permission the manifest lacks, a check
  the analysis should make before writing: code that tests for a permission the app
  never requests does not run). Both times the Write tool refused the verifier's output
  file: Claude Code blocks subagent writes to files named like reports (see
  [gotchas.md](gotchas.md)); the output file is now `verification.md`. Run it on the other reports and on a
  benchmark slice to see whether it removes errors without removing true findings.
- The coverage critic (a fresh agent that lists checklist items, exported components,
  and lead sections the report did not examine) is not built yet; it targets the
  category misses seen on Ghera and the vulnerable apps.
- Large apps split by area across parallel reader agents with `prompts/read-area.md`:
  run on the BTMOB rerun (2026-10-03), six readers (dropper, C2, accessibility, pages,
  telephony, media), 136k to 265k tokens and 4 to 6 minutes each; a seventh area
  (startup and persistence) was read by the main agent after its prompt was stopped by
  the safety classifier. Spot checks of key claims held; the verifier then found 6
  overstated and 1 wrong of 47, mostly gates and counts. An earlier run used three
  readers.
- Child-sample gates: `scan.sh` on a `.dec<k>` child lists the parent's native library as
  not shipped, and a dex-only child has an empty `manifest-summary.txt`. The permission
  and native-library gates for a child should fall back to the parent's manifest and
  `raw/lib/` (seen on the BTMOB sample's `.dec1` child). Not done.
- Coordination for agent runs at scale. A full MalEval agent run (255 samples, each with
  reader, decryption, and verification agents, plus retries of stopped readers) is a
  work queue that prompts and progress files handle only because runs are small.
  Candidate: [Radia](https://radia.sh/) (open source, local; agents publish immutable
  records, workers claim them under grants, each handoff keeps author, grant lineage,
  and data provenance; TypeScript and Python SDKs, MCP). Assessed 2026-10-02 from its
  landing page only, not tried. It would not make `apk-decryptor`'s shell limit
  technical (grants govern which records a worker claims, not its commands), it adds a
  shared space that agents reading malware write to (treat as untrusted like any APK
  text), and it states it has no independent deployment history yet. Revisit when an
  agent benchmark runs at that scale.
- `family-markers.tsv` has rows for two families from two reports. It grows only from
  published reports; each analysis that identifies a family through outside sources
  should add its markers with the source.
- The `apk-reader` agent type ran the launcher B readers and two report
  verifiers on 2026-10-03 without needing a shell. The benchmark runs of 2026-10-02 used
  general-purpose agents with the same rules in their prompts; rerun one benchmark with
  the restricted types to confirm. `apk-decryptor` has not run as its own type yet.
- `stringfog.py` lists R8-outlined string concatenation helpers as undecodable decoders
  (launcher B: `b.c0.j`, body `return str + str2`). Skip methods whose body is a plain
  concatenation, then run the gate.
- Workspaces: the copy-and-refresh design (2026-10-03) was tested function by function
  and through the wrapper, not by a full `./cupella setup --workspace` on a fresh
  directory. Proposals in `proposals/` have no tooling yet; a command that lists them
  across workspaces would help the review in the checkout.
- Checkpoints and budget mode (`workflow.md`) are written from one Codex run that ran
  out of tokens; neither has been used end to end yet.
- The `decryptor` role's shell is limited by its instructions, not technically, in every
  harness so far. A per-agent command allow-list (from the role header) would make it
  technical where the harness supports one.
- Other harnesses (Codex CLI, Gemini CLI, Cursor) have setup notes in
  [harnesses.md](harnesses.md) but have not run an analysis. Run one sample and one
  benchmark slice through each before claiming support.

## Anti-analysis

- Direct system calls (`native-summary.py`): found in 32-bit ARM libraries of five
  samples; no arm64 library in the corpus has any, so the arm64 path has no positive
  test yet. Thumb-mode and x86 system calls are not counted.
- Environment checks (`structure-leads.py`): one real lead on the BTMOB sample; locale-only
  functions are counted, not listed. Check on MalEval families known for geofencing.
- Class coverage (`class-coverage.py`): jadx's notes explain most "missing" classes;
  the rest are real drops or renames jadx did not note (launcher A `v0.Z0`).
- Not covered: blutter's output file names come from Dart library paths in the
  snapshot and were not tested for traversal (inside the container they could reach
  only `work/`); resources.arsc tampering beyond what apktool reports; OLLVM-style
  control-flow flattening in native code (Ghidra output gets long; no summary flags it).

## Measurement

- **Human verification of scorers.** Every agent benchmark is scored by a model. Check a
  random sample of scorer decisions (20 or so) by hand and report the agreement.
- **Variance.** Rounds 1 and 2 on untouched Ghera pairs differed by about one pair.
  Run each agent benchmark twice before claiming an improvement of a few points.
- **A held-out set.** The checklist was written from Ghera's misses. Keep part of each
  benchmark out of tuning (for example half of MalEval's families) and report it
  separately.
- **Benign base rates.** 25 benign apps (MalEval) is small and some are thin (web
  wrappers, a Flutter app without its code). Add a larger benign set, such as popular
  open-source apps, for false-claim rates at report level.
- **Real apps at scale.** Ghera apps are tiny and the vulnerable apps are well known
  (possible recall from training). Real-world apps with published CVEs and fixed
  versions would test discovery in large codebases without that bias.
- **Full MalEval.** Agent reports exist for 25 of 255 samples; the scripted signals
  cover all 255.
- **Tool comparison on the same samples.** Done for MobSF and Quark-Engine (see
  [benchmarks.md](benchmarks.md), "Tool comparison"). Not yet on the vulnerable apps
  (InsecureBankv2 and others) or the full MalEval set.
- **Quark leads in the pipeline.** Measured as a lead source ([benchmarks.md](benchmarks.md),
  "Quark leads as a lead source"): 5 more of 60 cited functions, no benign hits in app
  scope. Next: have `scan.sh` run Quark (on `repaired.apk` when present, so malformed ZIPs
  do not crash it) and write `quark-leads.txt`, add it to `lead-eval.py`'s sources and
  the runbook's lead order, and keep it only on a gate PASS. Quark Script's CWE detectors
  were not tried; they target vulnerabilities, which the rule set does not, so Quark's 0
  on Ghera says nothing about them.
- **Quark Script detectors for Ghera's categories.** `quark-query.py` (2026-10-03) runs
  one rule and resolves argument values; it reproduced Quark's CWE-798 showcase on OVAA
  (hardcoded AES key in `WeakCrypto.encrypt`). Next: per-category detectors as scripts
  (hardcoded secrets, SQL built from input, exported components with sensitive actions,
  WebView JavaScript interfaces, logging of secrets), scored with `fix-eval.py` on Ghera's
  pairs, then measured as leads like `quark-leads.txt`.
- **Merged-lambda case selection** (done 2026-10-03, gate PASS, 100 metrics; launcher B
  structure leads 5,504 to 4,492 distinct functions, same findings covered). Left: use
  the switch on the discriminator field rather than a method's first switch, and follow
  case bodies by control flow instead of linearly ([gotchas.md](gotchas.md)).
- **Call graph cross-check.** androguard's bytecode cross-references (Apache-2.0; 4.1.4 on
  PyPI) are independent of `units.py`. Comparing edges on the benchmark samples would find
  false or missing edges systematically; pinned in the image, it could also serve agents
  as a query tool.
- **Behavior maps** (`behavior-map.py`, 2026-10-03) use the scan scope plus the target's
  top package; callers outside it (bundled library code such as an embedded HTTP server) end the
  chain early. Not yet used in a report.

## Tooling and operations

- The model step (`model-leads.py`) adds ranking but no coverage on every benchmark so
  far. Keep it optional; spend no more on it unless a benchmark shows a gap it fills.
  A larger instruction-tuned model, not a code-specialized one, is the variant worth
  trying if it is revisited.
- React Native: `hermes-decompile.sh` has run only on a synthetic bundle; validate on
  a real Hermes app.
- iOS is not supported.
- The repository is not under version control yet. `.gitignore` covers `data/` (live
  malware), `work/`, `cache/`, and `bench/`.
- `scripts/` is flat: pipeline scripts, library modules (`units.py`, `dex.py`,
  `elf.py`, `llav_client.py`), and benchmark scripts side by side. Splitting it needs
  `./cupella`, the `PYTHONPATH` of the container, and the mount cases in `cupella` changed
  together.
- Project permission rules (`.claude/settings.json`): `./cupella` is allowed;
  `adb` and host parsing tools (`readelf`, `objdump`, `strings`, `cstool`, `unzip`,
  `file`, `jadx`, `apktool`) are denied for every session in the project, the user's
  own commands through Claude Code included. `apk-decryptor`'s shell is still limited
  by its instructions beyond that.
- Distribution: clone the repository, `./cupella setup`; workspaces keep cases out of the
  checkout. Not done: a prebuilt image in a registry (would remove the long first build;
  publishing is the maintainer's call), a thin Claude Code plugin as a launcher.
- `bench-setup`'s MalEval part has not run end to end (the data was fetched by hand
  before the script existed); Ghera and the vulnerable apps were checked against the
  files already present.
- A regression run: the native fixture, `cite-check.py` on all reports, and the
  scripted benchmarks, as one command to run after script changes.

## Out of scope by design

- Dynamic analysis (running the app, an emulator, Frida). Some listed vulnerabilities
  need it (runtime manipulation, values in memory, keyboard cache); the invariants
  allow it only when the user asks in that session.
- Contacting anything an APK names, including through public lookup services.
- Verdicts and severity scores on the report's own authority (see
  [design-report.md](design-report.md)).
