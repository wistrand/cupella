# Cupella

Static analysis of Android APKs with a coding agent.
Project site: [wistrand.github.io/cupella](https://wistrand.github.io/cupella/).

Put an APK in `data/` and ask the agent to analyze it. The report lands in `reports/`:
what the app is, what it requests, its libraries and endpoints, how it is signed, and
what looks odd. Every claim cites a file and line. Nothing from the APK is executed or
installed.

Scripts do the extraction. The agent reads the code behind what the scripts found and
writes the report. When an analysis needs a step no script covers, that step becomes a
script, and changes to the scan and lead scripts must pass a benchmark gate before they
stay. An agent working on a sample never edits the scripts: it writes a proposal, and
you apply it or not.

Only the front end and the benchmarks are specific to APKs.

## Requirements

- Docker, runnable by the current user. Linux (x86_64), or macOS on Apple Silicon with
  Docker Desktop.
- A coding agent that reads `AGENTS.md` and runs shell commands, started in this
  directory. Claude Code ran the benchmarks and the subagent stages; `./cupella setup`
  generates agent types for it. Codex and Antigravity have also run analyses. Other
  harnesses: `agent_docs/harnesses.md`.
- About 3 GB for the image. `work/` needs more: a large app unpacks to a few GB.
- Python 3 on the host (standard library only), for the gate, `./cupella check`, and
  the benchmarks. Analyzing samples does not need it.

## Quick start

```bash
git clone <this repository> cupella && cd cupella
./cupella setup   # checks Docker, builds the image once, self-test
cp ~/Downloads/some.apk data/
claude            # or your coding agent, started in the checkout
```

Then ask, for example:

- "analyze data/some.apk"
- "analyze data/some.apk on a budget": fewer subagents and a shorter check, for small
  token limits. The report says what was left out.
- "which network endpoints does data/some.apk talk to?"
- "compare the permissions of data/a.apk and data/b.apk"

`./cupella help` lists the commands and scripts.

## Workspaces

To keep cases out of the checkout, make a workspace and work there:

```bash
./cupella setup --workspace ~/cases/acme  # own data/, work/, reports/; read-only copies of the docs
cd ~/cases/acme && claude                 # or your coding agent
```

A workspace has read-only copies of the agent docs and a `./cupella` wrapper that runs
the checkout. Nothing else in the checkout is reachable from it.

| Task | How |
|------|-----|
| Update | `git pull` in the checkout. The next `./cupella` run in a workspace refreshes its copies; `./cupella sync` does it now and restores copies edited by hand. |
| Move the checkout | Rerun `<checkout>/cupella setup --workspace <dir>`. |
| Improvements | The agent writes proposals to the workspace's `proposals/` and can try a proposed extraction on the sample with `./cupella try-proposal <slug> <name>` (linted and offline, like a decryptor). You apply them in the checkout, where `./cupella gate` runs. To share them, fork. |
| Review proposals | `./cupella proposals` in the checkout lists the open ones across workspaces; `./cupella proposals set <workspace> <slug> applied` (or `rejected`) records the decision. |
| List workspaces | `./cupella workspaces` in the checkout, with sample, report, and open-proposal counts. An older workspace shows up after its next `./cupella` run, or with `./cupella workspaces --find <dir>`. |
| Git | Setup writes a `.gitignore` once, if none exists: `reports/` and `proposals/` are tracked; samples, `work/`, and generated files never are. |
| Delete | The doc copies are read-only: `chmod -R u+w <dir> && rm -rf <dir>`. |

## Layout

| Path             | Contents                                                          |
|------------------|-------------------------------------------------------------------|
| `data/`          | APKs to analyze (benchmark sets in subdirectories)                |
| `reports/`       | one report per APK                                                |
| `work/`          | unpacked and decompiled output, safe to delete                    |
| `cache/`         | build cache for the Dart analysis tool                            |
| `scripts/`       | unpack, scan, lead, and benchmark scripts                         |
| `prompts/`       | prompt templates for subagent stages and benchmarks               |
| `roles/`         | subagent roles: what each may read, write, and run                |
| `host/`          | host-side helpers run by `./cupella` (benchmark gate, regression check) |
| `bench/`         | benchmark data, fetched by `./bench-setup` (not in the repository) |
| `bench-sources/` | where each benchmark file comes from, and its hash                |
| `agent_docs/`    | runbooks, report format, traps, benchmarks, further work          |
| `docs/`          | project site; `docs/examples/` has an example report              |

## Scripts

The scripts also run without the agent:

```bash
./cupella unpack.sh data/some.apk     # unpack, decode, decompile, verify signatures; writes work/some/triage.txt
./cupella scan.sh some                # pattern searches; writes work/some/scan.txt
./cupella native-disasm.py work/some/raw/lib/arm64-v8a/libfoo.so --jni   # annotated native disassembly
./cupella apk-diff.py <old> <new>     # compare two versions of an app
./cupella lead-eval.py <name>         # which leads pointed at a finished report's findings
```

Unpacking also summarizes native libraries (`native-summary.txt`), identifies trackers
and packers (`trackers.txt`, `apkid.txt`), and makes the compiled Dart or JavaScript of
Flutter and React Native apps readable.

Experimental and off by default: a local model served by
[llav](https://wistrand.github.io/llav/) can rank functions into a reading list
(`./cupella model-leads.py <name>`). No script runs it unless you do. It has not found
anything the rest missed.

The image has jadx, apktool, Ghidra, blutter, APKiD, hermes-dec, and Quark-Engine (with
androguard) at pinned versions; full list in
[agent_docs/reference.md](agent_docs/reference.md#third-party-tools).

## Safety

The agent runs on the host. The APK is parsed only inside the container: no network, no
capabilities, read-only root, and only `work/` writable. Nothing from an APK is
executed, installed, or loaded, and no address found in one is contacted.

Two steps use the network, and say so:

- `./cupella reference-check.py`, which compares libraries against official builds.
- The build of the Dart analysis tool, the first time a Flutter app with a new Dart
  version comes in. It runs automatically, takes several minutes, and its container
  cannot see the APK.

Archive entries cannot land outside the sample's directory: `../` and absolute names
are rejected, and symlink entries are removed after extraction. The build cache that
later runs execute is read-only to every container that sees an APK.
`./cupella fixtures/zipslip-test.sh` checks the extraction side.

Some steps need code the agent writes, such as reimplementing a payload's decryption.
That code runs in a container with no network that can write only that sample's
`decrypt/` directory. Before it runs, a lint rejects exec, eval, dynamic imports,
subprocess, network modules, and any module outside the standard library's byte, file,
and format modules and pycryptodome. The lint is a best-effort filter, not a sandbox.

Subagents that read APK content get no shell (role `reader`), or a shell meant for
`./cupella run-decryptor.sh`, `./cupella dex-disasm.py`, and the native scripts only
(role `decryptor`). Claude Code enforces the tool lists of both roles. It does not
restrict which commands the decryptor's shell runs, and no other harness does either, so
that list holds by instruction only. The host rules in `.claude/settings.json` (allow
`./cupella`, deny `adb`, `readelf`, `unzip`, and other parsing tools) are prefix
matches: a full path or `bash -c` gets around them. Text in an APK that addresses the
agent is reported as a finding and never followed.

For live malware:

- Keep samples under `data/malware/` (gitignored with the rest of `data/`).
- Keep the file names as they are (letters, digits, `.`, `_`, `-`).
- Expect reports to contain keys, command names, and indicators in clear text.
- The agent reads text from the sample on the host, so run the harness session in a VM
  or under a dedicated user account.

## How it works

The scripts do the repeatable part: unpacking, decoding the manifest and resources,
decompiling, summarizing permissions, exported components and native libraries, a fixed
set of pattern searches, and finding functions by their place in the call graph (entry
points and what they reach, dispatch tables, loops, decoders). Malformed APKs (fake ZIP
encryption, tampered manifests) are read the way Android reads them. Payloads hidden in
assets under misleading names are found by content and analyzed as samples of their own.

The agent reads the code behind each lead, works out what it does and whether it is on
by default, and decrypts hidden payloads when it has to. It writes the report with
evidence for every claim. A fresh agent then tries to refute each claim, and the
citations are checked mechanically. The order of work is in `agent_docs/workflow.md`.

Reports go to `reports/`, which is not in the repository. One example:
[docs/examples/23282313-ddos-bot-loader.md](docs/examples/23282313-ddos-bot-loader.md)
([rendered](https://wistrand.github.io/cupella/report.html?f=23282313-ddos-bot-loader.md)),
a loader APK around a native DDoS bot that finds its server through blockchain name
records. Snapshot from 2026-10-03; the signer's name is redacted.

## Results

Agent runs on public benchmarks, static only, scored by a separate model:

| Benchmark | Result |
|-----------|--------|
| Ghera, 59 vulnerable/fixed app pairs, blind, with verification | 55 of 59 vulnerabilities found; 6 fixed apps also flagged |
| InsecureBankv2, OVAA, InsecureShop, AndroGoat | 85 of 89 listed vulnerabilities found |
| MalEval, 20 malware families and 5 benign apps | 19 of 20 malware and 5 of 5 benign classified right; behaviors 65% recall, 70% precision |
| MalEval, the 6 samples with encrypted code, after static decryption | behaviors 50% -> 66% recall, 68% -> 74% precision |

On the same apps, scored the same way:

| Tool | Ghera | MalEval behavior recall |
|------|-------|-------------------------|
| Cupella | 55 of 59, 6 fixed apps flagged | 65% |
| MobSF 4.5.3 | 20 of 59, 6 fixed apps flagged | 19% |
| Quark-Engine 26.9.1 | not scored: malware-behavior rules only | 26%; crashed on 2 of 25 samples (ZIP entries marked encrypted) |

MobSF and Quark-Engine take seconds per app and need no model. The agent takes minutes,
and a full analysis of a real app takes hundreds of thousands to over a million tokens.
In Claude Code runs on 2026-10-03, subagents used about 0.3M tokens on a small bot
loader and about 1.4M on a two-stage banking RAT (six readers, a verifier). The main
agent's own use is not counted. Per-stage costs: `agent_docs/workflow.md`.

Caveats:

- The vulnerability checklist was written from Ghera's own misses, so the Ghera result
  is optimistic. A held-out set is open work.
- The vulnerable apps are well known; some recall may come from training.
- Every agent benchmark is scored by a model, not a person, and most ran once or twice.
- What is still missed is mostly code behind native decryption layers.

Details and how to rerun: `agent_docs/benchmarks.md`. Known gaps and next steps:
`agent_docs/further-work.md`.

## License

Apache License 2.0, see `LICENSE`. The tools the image downloads (jadx, apktool, Ghidra,
blutter, APKiD, Quark-Engine, and others pinned in `Dockerfile`), the benchmark data
fetched by `./bench-setup`, and the samples you analyze keep their own licenses.
