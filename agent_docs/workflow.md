# Workflow: from a request to a finished report

The order of work for a request about an APK, which stages are required, when to
start subagents, and the checks before saying a report is done. How to read each
script's output is in [runbook-analysis.md](runbook-analysis.md); the report format is
in [design-report.md](design-report.md).

## Contents

- Request types
- Samples and names
- Stages
- Checkpoints
- Budget mode
- Subagent stages
- Finishing checklist
- Reruns and updates
- Improving the scripts

## Request types

| Request                                   | Stages                                              | Output |
|-------------------------------------------|-----------------------------------------------------|--------|
| "What is this app", "who signed it"       | 1                                                   | answer in the reply, citing `triage.txt` |
| Permissions, exported components          | 1, read `manifest-summary.txt` and the manifest      | answer in the reply |
| Endpoints, SDKs, trackers                 | 1, 2, the network and telemetry sections of the leads | answer in the reply, or a report if asked |
| "Analyze X" (full analysis)               | 1 to 5, 7, 8                                        | `reports/<name>.md` |
| "Analyze X on a budget", or a harness with a small token limit | see "Budget mode" | `reports/<name>.md`, marked as a budget run |
| Security review                           | full analysis plus the Vulnerability checklist ([runbook-analysis.md](runbook-analysis.md)), verification required | `reports/<name>.md` |
| Malware: what does it do                  | full analysis plus "Malware samples" ([runbook-analysis.md](runbook-analysis.md)), decryption when code is hidden, verification required | `reports/<name>.md` |
| Compare two versions                      | 1 on both, then `./cupella apk-diff.py <old> <new> > work/<new>/diff-from-<old>.txt`; read the code behind each change | answer, or a section in the newer report |

A question about one fact needs no report. Write a report when the user asks for an
analysis, or when the answer needs more than a few cited lines.

## Samples and names

- Input APKs live in `data/`, in any subdirectory (`data/malware/` for live samples).
  In a workspace (`.cupella-workspace` present) `data/`, `work/`, and `reports/` are the
  workspace's own, the docs are read-only copies at the same paths, and `./cupella` runs
  the checkout (`WORKSPACE.md`).
  The user puts them there; never move, rename, or delete anything in `data/`.
- A sample that came as a password-protected archive (`data/<sha256>.zip` from a malware
  repository) is taken out with `./cupella sample-archive.py data/<file>.zip`; the APK
  lands in `work/_samples/<name>.apk`, and `unpack.sh` takes that path. Never extract it
  with host tools, and never write to `data/`.
- `<name>` is the APK filename without `.apk`. Every stage keys on it: `work/<name>/`,
  `reports/<name>.md`. `./cupella run-decryptor.sh` accepts only names made of letters,
  digits, `.`, `_`, and `-`; ask the user to rename a file before staging it if needed.
- Child samples get their own work directories and are analyzed as part of the parent:
  `work/<name>.emb<k>/` for code found inside the APK by content (`unpack.sh`), and
  `work/<name>.dec<k>/` for decrypted payloads (`run-decryptor.sh`). Cite their paths
  in full. A child that is itself a known sample (identical SHA-256) is a finding;
  report the link.
- `work/_*/` directories are not samples: `_reference` (download cache of
  `reference-check.py`), `_gate` (gate metrics), `_tools` (sample lists for the
  tool comparison), `_previous` (agent work moved aside by `run-decryptor.sh` when a
  child number now holds a different payload), and the agent benchmark runs
  (`_ghera-blind*`, `_maleval-agent`, `_vulnapps`).

## Stages

1. **Unpack.** `./cupella unpack.sh data/<path>/<name>.apk`. Read `triage.txt` in full and
   settle app type, own packages, obfuscation, packing, and signing before going on.
   The anti-analysis sections (ZIP anomalies, symlink entries, tool time limits, class
   coverage) say what the tools could not see; carry them into "Analysis coverage".
   Flutter and React Native switch the code reading to
   [runbook-flutter.md](runbook-flutter.md) or the React Native section of the runbook.
2. **Scan.** `./cupella scan.sh <name>`. Check the `scope:` and `scope source:` lines of
   `scan.txt` against the triage's package table; rerun with an explicit parent when
   the app's code is elsewhere (the scope is then kept for later scans). Embedded
   children are scanned too. String decoders that `stringfog.py` can decode are decoded
   here; read such code in `jadx-strings/`.
3. **Read the leads.** In order: injection section of `scan.txt` (anything there is a
   finding), "Known family markers", entry points and environment checks in
   `structure-leads.txt`, `flows.txt`, `behavior-facts.txt`, `scan.txt` section by section, then the app-scope
   lines of `quark-leads.txt` that no other source named. Read the code
   behind every lead you report. Use `./cupella xref.py` for callers and callees, and
   `./cupella dex-disasm.py` where jadx failed. Before reporting a feature, check its gate:
   the "Permissions the code names but the manifest does not request" and "Native
   libraries ... not ship" sections, and the defaults of operator options.
4. **Native code.** When `native-summary.txt` lists anything beyond known runtime
   libraries, follow [runbook-native.md](runbook-native.md), then rerun
   `./cupella structure-leads.py <name>` so the Ghidra output joins the call graph.
5. **Decryption.** Payloads whose key is a constant in the APK are already decrypted
   (`triage.txt` "Encrypted payloads decrypted by script"; their children are
   `work/<name>.emb<k>/`). When code or strings are still encrypted (see "Malware
   samples" in the runbook for the signs; `triage.txt` "Files that look encrypted and
   were not decrypted"), run the decryption subagent below. After it,
   repeat stages 3 and 4 on each new `work/<name>.dec<k>/`, which
   `run-decryptor.sh` has already unpacked and scanned. Repeat for each further layer.
6. **Experimental, off by default: model reading list.** Never run it unless the user
   asks for it: `./cupella model-leads.py <name>`. See
   [reference.md](reference.md) "Local model".
7. **Write the report** in the format of [design-report.md](design-report.md), filling
   the skeleton written after stage 1 (see "Checkpoints"). Outside
   research (web searches on the hash, package names, distinctive strings) only when
   the user asks for it: it is the one exception to "never look up identifiers from a
   sample", search identifiers only, never contact infrastructure, and put the results
   in "Outside references".
8. **Finish** with the checklist below.

Stages 1 and 2 always come first and always through the scripts; never retype their
steps by hand. Stages 4 to 6 are conditional; when one is skipped for a reason other
than "not needed", name it under "Analysis coverage".

## Checkpoints

A session can end at any point (token limit, rate limit, crash). Work only in the
agent's context is then lost. In every mode:

- A new analysis is a rendered report ([design-report.md](design-report.md) "Rendered
  reports"): `./cupella unpack.sh` creates `reports/<name>/` (a stub `notes.md`, an empty
  `claims.jsonl`) when no report exists, and `./cupella scan.sh` builds
  `reports/<name>.json` and `reports/<name>.md` from `facts.json`. Every generated section
  is filled from then on; Summary and Findings read "not reached" until written. Never
  delete `reports/<name>/`.
- One claim appended to `reports/<name>/claims.jsonl` is the checkpoint for a finding,
  written when its code is read and its gate checked (`likely` if a step is still open).
  Prose goes into `notes.md` one section at a time, indicators the facts cannot hold into
  `indicators.jsonl`. A write that is interrupted (session end, safety classifier,
  malformed tool call) then loses only that piece, and `progress/main.md` names where to
  resume. Rebuild with `./cupella report-build.py <name>` whenever it helps to see the report.
- For a malicious or suspected sample, findings come from a reader subagent (`reader`
  role, `prompts/read-area.md`) that writes draft claims, one file each, to
  `work/<name>/progress/<role>-claims/D<n>.json`. The main agent checks each draft's key
  steps in the code and promotes it with `./cupella claims-promote.py <name> <role> D<n>`
  (`--list` shows the drafts). A main agent describing malware behavior at length can be
  stopped by the model provider's safety classifier, and everything in that response is
  lost; short claims and promotion keep that text out of the main agent's responses.
- Finish with `./cupella claims-check.py <name>`, `./cupella report-build.py <name>`,
  `./cupella cite-check.py <name>`.
- Hand-written reports (a `reports/<name>.md` without `reports/<name>/`, from before
  rendering): fill one section or one finding per write, as soon as it is settled; never
  delete a section, leave it "not reached".
- When a write is stopped by the safety classifier, never retry it in that session,
  reworded or through a subagent. Note the stop in `progress/main.md` and tell the user;
  a fresh session resumes from there ([harnesses.md](harnesses.md)).
- Append one line per step to `work/<name>/progress/main.md` ("<step number> <what was
  done or found, next step>"), as subagents do.
- Write what reading found to `work/<name>/progress/main-findings.md` as soon as each
  behavior is confirmed, one entry per behavior: what it does, where (`path:line` for
  each step of the chain), its gate and whether it passes, and the confidence label.
  Also record settled facts the report needs that are not findings (endpoints, the
  scope, a tool failure). A step line in `progress/main.md` names the classes read;
  the entry holds the content. A session that ends between reading and writing then
  loses nothing: the report is written from this file, not by reading again.
- A request to resume names a sample, often by a hash or name prefix: look for
  `work/<prefix>*/progress/main.md` (and in a workspace, its own `work/`). Never search
  session transcripts for it.
- A new session continuing the work reads `progress/main.md`, `progress/main-findings.md`,
  readers' `progress/*-claims/` (and `*-claims.jsonl`, `*-findings.md` from before), the sources in
  `reports/<name>/`, and the partial report first, then goes on from the first section
  still "not reached". Re-read code only to check an entry, not
  to rebuild it. This is the one case
  where reading an earlier report of the same sample is allowed: it is this analysis's
  own unfinished output.
- When stopped short, say so in the report's Summary and "Analysis coverage", and leave
  the unreached sections as "not reached" rather than deleting them.

## Budget mode

For a request made "on a budget", or a harness whose token limit is small (Codex on a
Plus plan ran out mid-analysis). The scripts cost no tokens; reading does. Cost per
stage, from Claude Code runs on 2026-10-03:

| Stage                                  | Tokens              | Time        |
|----------------------------------------|---------------------|-------------|
| One reader agent (one area, ~30 files) | 100k to 265k        | 4 to 7 min  |
| Verification (one report)              | 125k to 280k        | 3 to 10 min |
| Six parallel readers on a large app    | 950k to 1.13M total | 7 min wall  |
| Decryption of a native string table    | about 90k           | 4 min       |

Changes from a full analysis:

- No reader subagents. Read in the order of stage 3, settle the strongest leads, and
  stop when further reading is unlikely to change the findings; list the rest under
  "Open questions".
- Search with a few lines of context (`rg -n -C3` scoped to a package) and read a cited
  range, never a whole file; never `sed -n '1,260p'` a class to find one method.
- Verification checks Findings only (give the verifier that scope in the prompt), or is
  skipped and named under "Analysis coverage". Security reviews and malware keep full
  verification; say so to the user before starting if the budget cannot cover it.
- Decryption runs only when the user asks, or when the app's behavior cannot be
  described at all without it.
- The report's first line under Summary says it was a budget run and what that left out.

Checkpoints matter most here: write each section as it settles, so running out leaves
a usable partial report.

## Subagent stages

Agents that read APK content are started fresh (never as forks) with the role and
prompt below. Roles are in `roles/` (what the agent may read, write, and run, and its
rules); prompt templates in `prompts/`; fill in the placeholders. How the harness in
use starts a role is in [harnesses.md](harnesses.md) (Claude Code: agent types
`apk-reader` and `apk-decryptor`, generated from the roles).

| Stage        | Role        | Prompt                       | When                                    |
|--------------|-------------|------------------------------|-----------------------------------------|
| Decryption   | `decryptor` | `prompts/decrypt.md`         | code, payload, or strings encrypted; one agent per layer |
| Verification | `reader`    | `prompts/verify-report.md`   | required for security reviews and malware; recommended for every full report |
| Reading      | `reader`    | `prompts/read-area.md`       | large apps: one agent per area, in parallel; malware: Findings and Indicators ("Checkpoints"); check their key claims in the code |
| Benchmarks   | `reader`    | `prompts/bench/*.md`         | only for benchmark runs ([benchmarks.md](benchmarks.md)) |

- When the harness cannot restrict a subagent's tools as the role says, the role's
  rules go into the prompt and the report says the restriction was by instruction only.
- Decryption agents may run only `./cupella run-decryptor.sh <name>`,
  `./cupella dex-disasm.py`, and the native scripts. Their output is `work/<name>/decrypt/` (`decrypt.py`, `NOTES.md`,
  `out/`, `outputs.txt`, and `PROGRESS.md`, written as the agent goes: read it when
  the user asks for status). With string obfuscation, read the child's code in
  `jadx-strings/` (same line numbers as `jadx/sources/`, plaintext in comments) and the children it unpacks. Read `NOTES.md` before citing a
  key or algorithm, and check that each child in `outputs.txt` decompiled.
- Name subagent output files after their content, never `report*`: Claude Code, for one, refuses
  a subagent's write to a file named like a report ([gotchas.md](gotchas.md)).
- Reader output is `work/<name>/progress/<role>-claims/D<n>.json`, one draft claim per
  file, which the main agent promotes with `./cupella claims-promote.py`;
  the final message is one line. Agent output is one record per write: a reader has no
  append, so a growing file would be resent whole for each record, and one failed write
  would block the rest. A reader that summarizes malware behavior in its final
  message can be stopped by a safety classifier while writing it, and the summary is
  lost ([harnesses.md](harnesses.md)).
- Verification output is `work/<name>/verification.md` (for a rendered report written
  once at the end, for a hand-written one section by section), or
  the agent's final message when it cannot write. For a rendered report also
  `work/<name>/progress/verify-verdicts/<id>.json`, one verdict file per claim, which
  `./cupella claims-merge.py <name>` merges into `reports/<name>/claims.jsonl`. Fix every "wrong" and "overstated" item after
  checking it against the code yourself; the verifier can be wrong too. One data point
  for cost: verifying the Octo report took about 150k tokens and 3 minutes and found 3
  wrong and 4 overstated claims out of 25.
- The main agent writes `work/<name>/progress/main.md` as it works (see
  "Checkpoints").
- Every subagent writes a progress file as it works: decryption agents
  `work/<name>/decrypt/PROGRESS.md`, other agents on a sample
  `work/<name>/progress/<role>.md` (role such as `verify`, `reader-c2`), benchmark
  agents the path named in their `prompts/bench/` prompt (under the run's
  `work/_*/progress/`). Name the file in the prompt. When the
  user asks for status, read these files; never read an agent's transcript.
- Run independent subagents in parallel (decryption of separate layers cannot be, as
  each needs the previous layer's output).

## Finishing checklist

Before telling the user a report is done:

- `./cupella cite-check.py <name>` lists no problems.
- Verification ran (where required) and its corrections are applied; cite-check rerun
  after the edits.
- Every count in the report checked against the script output or by counting in the
  source.
- "Analysis coverage" names every tool failure, partial decompile, tool time limit,
  class jadx did not produce, skipped stage, and payload that stayed encrypted.
- Every feature claimed as a capability passes its gate: its permission is requested,
  its native library ships, its operator option is on by default or the report says
  it is off. Otherwise it is reported as present but inert.
- Every finding that rests on a call chain across several functions has a behavior map
  (`./cupella behavior-map.py`, [design-report.md](design-report.md) "Behavior maps"), with
  each edge checked in the code: false edges removed, edges the graph cannot follow
  (Handler posts, threads, function pointers) added and marked as read.
- Inferred claims are marked as inferred; open questions are listed.
- No section still reads "not reached", unless the run was stopped short or was a
  budget run and the Summary says so.
- Traps that cost time are in [gotchas.md](gotchas.md), and ad hoc extractions that
  proved useful are in a script (see "Improving the scripts"); in a workspace, both are
  in `proposals/<YYYY-MM-DD>-<topic>.md` instead, one file per proposal.

The reply to the user gives the report path, a few lines of what the app does, what
could not be read, and the verification result. Do not repeat the report.

## Reruns and updates

- `unpack.sh` skips steps already done; `-f` redoes them (after a script change or a
  new tool version) and keeps `decrypt/`, `progress/`, and `scan-scope.txt`. `scan.sh` always rewrites its outputs.
- Never rerun `unpack.sh -f` or `scan.sh` on benchmark samples while `./cupella gate` runs: it
  measures the files you are rewriting (a FAIL on 2026-10-02 came from exactly that).
- Rerunning an analysis updates `reports/<name>.md` in place, but the analysis itself
  is done fresh, without reading the old report (`AGENTS.md` Invariants). Then compare:
  a finding the old report has and the new run lacks is rechecked in the code before it
  is dropped or restored. Recheck citations (line numbers move when jadx changes) and
  rerun cite-check.
- `work/` can be deleted at any time and regenerated, except agent outputs:
  `work/<name>/decrypt/`, `work/<name>/progress/`, and `work/_*/` benchmark runs need
  agent time to recreate. `unpack.sh -f` keeps these and `scan-scope.txt` (a scan scope
  given by hand).

## Improving the scripts

When the user asks to improve the analyzer, or when an analysis needed a step no
script covers:

1. Add the step to the matching script (`scan.sh` patterns, `unpack.sh` triage,
   `manifest-summary.py`, the lead scripts), APK-independent.
2. Rerun it on the sample and read the output.
3. After changing `units.py` or `dex.py`, run `./cupella callgraph-check.py <name>` on a
   small and a large analyzed sample: "lost" calls and functions without a dex method
   must stay 0.
   For changes to `scan.sh`, `scope.py`, `units.py`, `flows.py`, `structure-leads.py`,
   or the unpack steps: `./cupella gate baseline` on the unchanged scripts first, then `./cupella gate`;
   keep the change only on PASS.
4. Check that past reports' findings are still pointed at: `./cupella lead-eval.py <name>`.
5. After changes to extraction, `unpack.sh`, `elf.py`, or the injection scan, run
   `./cupella check` (the fixtures, including the manifest tricks, `proposals`, and `try-proposal`, the native fixture, and
   `cite-check.py` on every report, then the gate), and re-unpack one benign and one malformed sample with `-f`:
   a change in what jadx reads moved the Octo report's citations once.
6. The gate measures leads, not every section: a new informational section (a triage
   check, a summary) passes with "improved: none". Run it over the whole corpus and read
   its hits before trusting it; the first class-coverage count flagged 178 samples,
   most of them from blinded benchmark copies and classes jadx inlines.
7. Rows in `scripts/family-markers.tsv` come only from published reports, each with its
   source.
8. Update [further-work.md](further-work.md) when an item there is done, and
   [benchmarks.md](benchmarks.md) when an agent benchmark is rerun.

In a workspace the scripts cannot be changed. Write the change as a proposal, one file
each: `proposals/<slug>.md`, slug `<YYYY-MM-DD>-<topic>`, starting with a `# title`
line. When it is an extraction, write it as `proposals/<slug>/tool.py` too (same slug)
and run it with `./cupella try-proposal <slug> <name>`:
it is linted like a decryptor and runs offline with the sample read-only, writing only
`work/<name>/proposals/<slug>/`. Its output may be cited in the report like script
output; say in "Method changes" that it comes from a proposal, not from `scripts/`. The
user moves an accepted tool into `scripts/` in the checkout and runs the gate there.

In the checkout, `./cupella proposals` lists the open proposals of every workspace made
from it (`--all` adds applied and rejected ones), and
`./cupella proposals set <workspace> <slug> applied|rejected|open [note]` records a
decision in the checkout's `.cupella-decisions.tsv`, where a workspace agent cannot
write it. Only the user, or an agent in the checkout on the user's word, records
decisions.
