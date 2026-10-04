# Benchmarks

Public benchmarks for checking the analyzer, and the numbers to compare against after
a change. Two kinds: scripted benchmarks measure leads (does a script point the agent
at the right code); agent benchmarks measure what an agent reports after reading.

## Contents

- Datasets
- Rerunning
- Rerunning the agent benchmarks
- Current numbers
- Tool comparison
- Quark leads as a lead source
- What the numbers do not say

## Datasets

| Dataset | Where | Answer key | Script |
|---------|-------|------------|--------|
| Ghera: 60 small app pairs (59 scored in every result below; why one is left out is not recorded), each a known vulnerability, as a vulnerable ("benign") and a fixed ("secure") build | `data/ghera/`, READMEs in `bench/ghera/`; APKs from Bitbucket `secure-it-i/android-app-vulnerability-benchmarks` (the GitHub fork has no LFS content) | the methods the fix changed; manifest or res/xml changes | `fix-eval.py` |
| MalEval: 230 malware (MalRadar and newer) and 25 benign apps | `data/maleval/{malradar,new,benign}/`, labels in `bench/maleval/info/`, vendor-report annotations in `bench/maleval/reports/`; Hugging Face `Xinzxr/MalEval`, revision `a5bd8d8` | per-sample behavior labels (Remote Control, Privacy Stealing, SMS/CALL, ...), no function-level labels | `bench-maleval.py` |
| Deliberately vulnerable apps: InsecureBankv2, OVAA, InsecureShop, AndroGoat | `data/vulnapps/` from each project's GitHub releases; READMEs at the same release tag in `bench/vulnapps/` | the vulnerability list in each README, taken by the scorer (`work/_vulnapps/key-<app>.txt`) | agent scoring, `prompts/bench/vulnapp-*.md` |
| The five analyzed apps | `data/`, `reports/` | functions cited in each report's Findings | `lead-eval.py` |

MalEval APKs are live malware. The invariants apply: static analysis only, never
contact anything they name.

## Rerunning

The data comes from `./bench-setup` (in the checkout): it fetches each dataset from
its source and checks it against the hashes in `bench-sources/`. Then unpack and scan every app once (`./cupella unpack.sh`,
`./cupella scan.sh`), and record the gate baseline (`./cupella gate baseline`). Baselines
recorded before 2026-10-03 named report metrics by the first 24 characters of the
report name; record a new one before the next `./cupella gate`. The current baseline
(2026-10-04) has 121 metrics: Ghera, MalEval, and lead coverage of 10 reports.

After changing `scan.sh`, `scope.py`, `structure-leads.py`, `units.py`, or the unpack
steps, rescan and rerun:

```bash
for d in work/*-benign work/*-secure; do ./cupella scan.sh "$(basename "$d")"; done
./cupella fix-eval.py --suffix -benign -secure
# MalEval: rescan each work/<sha256>/ (four in parallel takes about 5 minutes); scan.sh
# also rescans the sample's embedded payloads work/<sha256>.emb<k>/
./cupella bench-maleval.py -v
for n in <name> ...; do ./cupella lead-eval.py "$n"; done
```

Keep a change only if it loses nothing here and the benign lead rates in
`bench-maleval.py` do not jump.

## Rerunning the agent benchmarks

These cost agent time (about 12 analysis agents and 4 scorers for Ghera, 9 for the
MalEval slice, 8 for the vulnerable apps); run them after changing the runbook's
guidance, not after every script change. Prompts are in `prompts/bench/` (analysis and scoring) and `prompts/` (verification, decryption).
`maleval-analyze.md` and `vulnapp-analyze.md` carry refinements added after the runs
reported below (behavior definitions, `strings.xml` and Firebase secrets,
authentication logic), so a rerun measures them too.

- Always use fresh agents with the `reader` role (see [harnesses.md](harnesses.md)), never forks: a fork sees this conversation
  and the keys.
- Never put both apps of a Ghera pair in one batch, and never let analysis agents read
  `work/_ghera-blind/key.json`, `bench/`, or `data/`.
- Ghera: `./cupella bench-ghera-blind.py <seed>` makes blinded copies under new ids and the
  key; the main agent then writes `work/_ghera-blind/batches.json` from `key.json`
  (a JSON list of lists of sample ids, no pair in one list); one agent per batch with `ghera-analyze.md`; then `./cupella bench-ghera-score.py packets <seed>`, four scorers
  with `ghera-score.md`, and `./cupella bench-ghera-score.py tally`. Move the previous
  `work/_ghera-blind/` aside first to keep it for comparison.
- MalEval slice: the selection is `work/_maleval-agent/selection.json` (20 malware from
  20 families, 5 benign); agents with `maleval-analyze.md`, about three apps each; score
  with `./cupella bench-maleval-agent.py -v`.
- Vulnerable apps: `./cupella unpack.sh` and `./cupella scan.sh` on each, one agent per app with
  `vulnapp-analyze.md`, one scorer per app with `vulnapp-score.md`.

## Current numbers

As of 2026-10-02, after the default scope (`scope.py`), embedded payloads unpacked as
samples, the SQL-concatenation, WebView-callback, and Ads patterns, and `flows.py` with
asset and network-input sources.

Ghera (`fix-eval.py`, 59 pairs):

- 52 pairs change code. `scan.txt` points at a changed method in 47 (with
  `structure-leads.txt` and `flows.txt`, 49); in 19 of those
  the lead is gone in the fixed app (the rest flag the API in both versions, and the
  difference is in arguments or checks the agent must read).
- Misses: FragmentInjection (an intent extra names the fragment class),
  OutdatedLibrary, UnhandledException (a missing null check), WebView geolocation
  without a prompt. These need reading, not patterns.
- 29 pairs change the manifest or res/xml; `manifest-summary.txt` reflects all 29.
- `structure-leads.txt` points at a changed method in 14: the apps are too small for
  structure to matter.

Ghera, agent verdicts (blind, 2026-10-02): the agent, given only the scripted
outputs and decompiled code of each app under a random id, listed the vulnerabilities
it found; a separate blind scorer decided per pair whether each of the two unlabeled
verdicts reported the benchmark's vulnerability (`bench-ghera-blind.py`,
`bench-ghera-score.py`; result in `work/_ghera-blind/tally.txt`).

- 54 of 59 vulnerable apps: reported (TP). 5 missed: EnforceCallingOrSelfPermission,
  OrderedBroadcast, TaskAffinityAndReparenting, UnpinnedCertificates, WebViewProceed.
- 11 of 59 fixed apps: the same vulnerability reported too. Two checked by hand:
  ClipboardUse is a real false positive (the fix disables copying on the field), and
  UnhandledException's fix only checks that extras exist, so a crash on a missing extra
  may remain. The other nine are not checked.
- Informedness (TPR - FPR): 0.73.
- Round 2, after adding the runbook's "Vulnerability checklist" (written from these
  misses and fixed-app reports) and its scan patterns, fresh blind copies and agents:
  55 of 59 reported, 8 of 59 fixed apps also reported, informedness 0.80. On the 44
  pairs the checklist was not written from: 44 -> 43 reported, 0 -> 1 fixed-app
  reports, i.e. run-to-run noise of about one pair. On the tuned pairs: the five misses
  went 0 -> 2, the eleven fixed-app reports 11 -> 7. Results in
  `work/_ghera-blind/tally.txt` (round 1 in `work/_ghera-blind-run1/`).
- For comparison, the 14 free tools in Ranganath and Mitra (2019) on 42 Ghera
  vulnerabilities: no tool detected more than 15, all together 30. Their Ghera
  version, tool-output scoring by the authors, and our model-based scorer differ, so
  compare the order of magnitude, not the numbers.
- Blinding limits: app names, role words, and vulnerability names were replaced in the
  copies; two analysis agents reported glob slips that listed other directories' names;
  one fixed app keeps a UI string ("Your data is in secure hands").

Deliberately vulnerable apps (agent verdicts, 2026-10-02): InsecureBankv2, OVAA,
InsecureShop, AndroGoat from their GitHub releases (`data/vulnapps/`), answer keys
from their READMEs. One agent per app wrote a vulnerability list; a separate agent
scored each listed item found, missed, or not statically checkable. The keys used on
2026-10-02 were extracted once from the READMEs and are no longer in the repository; the scorer
now takes the list from the README at the release tag itself and writes it to
`work/_vulnapps/key-<app>.txt`, so a rerun may list slightly different items. Results in `work/_vulnapps/tally.txt`.

| App | Listed | Found | Missed | Needs a running app | Extra, unverified |
|-----|--------|-------|--------|---------------------|-------------------|
| InsecureBankv2 | 25 | 19 | 3 | 3 | 2 |
| OVAA | 18 | 17 | 1 | 0 | 6 |
| InsecureShop | 19 | 19 | 0 | 0 | 7 |
| AndroGoat | 33 | 30 | 1 | 2 | 5 |

85 of 90 statically checkable items found (94%; 85 of 89 after removing AndroGoat's
Firebase item, which the APK does not contain). Misses: clipboard use, parameter
manipulation, username enumeration (InsecureBankv2), hard-coded dev credentials in
`strings.xml` (OVAA), Firebase misconfiguration (AndroGoat). Caveat: these apps are
well known and their package names cannot be hidden, so the model may recall their
vulnerabilities from training; the scorer is a model too.

MalEval, agent reports (2026-10-02): 20 malware from 20 families and 5 benign apps,
one report per app with a verdict and behaviors from MalEval's eleven classes, each
with code evidence; scored by `bench-maleval-agent.py` (`work/_maleval-agent/score.txt`).

- Verdict: 19 of 20 malware called malicious (Haken, an ad-fraud plugin family, was
  called benign); 5 of 5 benign apps called benign.
- Behaviors: recall 65%, precision 70% against the labels (56 of 86 labeled behaviors
  claimed; 80 claimed). Remote Control and Ransom precision 100%; Tricky Behavior and
  Privilege Escalation over-claimed (52%, 50% precision).
- Every one of the 83 evidence paths exists (paths are counted per citation, not per
  behavior, so this count differs from the 80 behaviors claimed).
- Most misses are code the agent could not read and said so: payloads encrypted in
  assets (Faketoken, Octo, Coper, ZNIU), encrypted string tables (Rotexy, DoubleLocker),
  unanalyzed native libraries. Labels describe the family from vendor reports, so some
  "misses" may be behaviors this sample does not carry.

Agent stages added after these runs (2026-10-02):

- Verification (`prompts/verify.md`) on Ghera round 2: fresh agents tried
  to refute each reported item against the code; 22 of 374 items refuted, 43
  downgraded to likely. Rescored blind (`work/_ghera-blind/tally-verified.txt`): 55 of
  59 still found (no loss), fixed-app reports 8 -> 6, informedness 0.80 -> 0.83.
- Decryption (`prompts/decrypt.md`, `./cupella run-decryptor.sh`) on the six
  MalEval samples whose code or strings were encrypted: Faketoken (RC4 payload and
  strings), Rotexy (AES-256-CBC string table, 427 strings), DoubleLocker (XOR string
  tables, 521 strings), ZNIU (five DES/AES/arithmetic payloads), Coper and Octo (DES
  payload layers; a native RC4 layer decrypted, a third layer not). Re-analysis with
  the decrypted outputs (`work/_maleval-agent/score-dec.txt`), same labels: behavior
  recall 50% -> 66%, precision 68% -> 74% on those six; Faketoken 0 -> 5 of 5 labeled
  behaviors. Octo and Coper stay blocked at the native third layer.
- Payload decryption by script (`payload-decrypt.py`, 2026-10-03), no agent: 29 of 230
  malware samples have a payload it decrypts (AES-128-ECB with a Base64 key 14, RC4 with
  a string or byte-array key 10, a byte offset 10, zlib only 3, DES between zlib layers
  2, DES with a key that `stringfog.py` decodes first 26 in 14 samples; some samples
  have several), 0 of 25 benign apps; 67 samples keep files that look
  encrypted. With the decrypted children scanned, the scripted behavior signals rose:
  Bank Stealing code 68 to 75 and flow 24 to 37, Privacy Stealing code 76 to 83,
  SMS/CALL code 60 to 68, Premium Service code 7 to 14 (percent of labeled samples;
  benign rates unchanged). The agent benchmark was not rerun.
- Rule loop (`./cupella gate`): two agent-proposed rules from the vulnerable-app misses,
  "Secrets in resources" and "Cloud configuration", and a prompt-injection section,
  each passed the gate (82 metrics, none worse). AndroGoat's "Misconfigured Firebase
  DB" is not in its v2.0.1 APK (no Firebase reference in code, resources, or dex
  strings): that miss is an answer-key error, so the vulnerable-app result is 85 of 89.

MalEval (`bench-maleval.py`): share of labeled malware with a lead, and in brackets
the share of the 25 benign apps where the same code signal fires.

| Behavior | Labeled | Code lead | Code or declaration | Data flow | Benign, code | Benign, flow |
|----------|---------|-----------|---------------------|-----------|--------------|--------------|
| Remote Control | 203 | 86% | 89% | - | 16% | - |
| Privacy Stealing | 176 | 76% | 99% | 34% | 32% | 0% |
| Tricky Behavior | 115 | 66% | 85% | 7% (dropper) | 4% | 0% |
| SMS/CALL | 108 | 60% | 87% | 28% | 0% | 0% |
| Privilege Escalation | 87 | 67% | 87% | - | 12% | - |
| Stealthy Download | 81 | 61% | 69% | 4% (dropper) | 4% | 0% |
| Abusing Accessibility | 58 | 70% | 86% | - | 16% | - |
| Bank Stealing | 58 | 68% | 98% | 24% | 16% | 0% |
| Ads | 55 | 61% | 67% | - | 0% | - |
| Ransom | 47 | 57% | 74% | - | 0% | - |
| Premium Service | 14 | 7% | 35% | 0% | 0% | 0% |

Signals of embedded payloads (`work/<sha256>.emb<k>/`) count for their sample. "Dropper"
flows are an asset or download written to a file, storage, or class loader after XOR or
a cipher; a plain copy (one benign app copies a bundled database) does not count.

Before `scope.py` (manifest package only) the code-lead column was 27% to 51%. Of the
53 SMS/CALL samples without a code lead at that point, 33 showed a hidden payload:
embedded code (14, now decompiled), a dex loader (11), high-entropy assets (6), or a
packer flagged by APKiD (2).

The five analyzed apps (`lead-eval.py`): scan plus structure leads cover every
finding that cites code; the model (`model-leads.txt`) covers none they miss but
often ranks a finding earlier. `flows.txt` covers none of their findings: launcher A's
screen-text-to-database flow runs through R8-renamed libraries (see gotchas).

## Tool comparison (2026-10-03)

MobSF 4.5.3 (official image, pinned by digest) and Quark-Engine 26.9.1 (rules
80c902f) on the same apps, offline, scored by the same procedure as the agent:
`./cupella quark-scan.sh` and `./cupella mobsf-scan.py` over `work/_tools/ghera.txt` and
`maleval.txt` (from `./cupella bench-tools.py lists`), then `./cupella bench-tools.py ghera|maleval
<tool>`. On Ghera every finding a tool reports counts as reported (MobSF: all severities
except secure/good; Quark: rules matched at 100%), and the blind scorer agents judged
the packets (`bench-ghera-score.py packets 11 <tool>-verdicts <tool>-score`). On
MalEval, classifier agents (`prompts/bench/tool-maleval-classify.md`) mapped each tool's
findings to the behavior classes without seeing the labels.

| | Ghera found (of 59) | fixed apps flagged | informedness | MalEval malware flagged | benign right | behavior recall | precision |
|---|---|---|---|---|---|---|---|
| this project (agent, verified) | 55 | 6 | 0.83 | 19 of 20 | 5 of 5 | 65% | 70% |
| MobSF 4.5.3 | 20 | 6 | 0.24 | 18 of 20 | 5 of 5 | 19% | 60% |
| Quark-Engine 26.9.1 | 0 (out of scope) | 1 | -0.02 (out of scope) | 18 of 20 | 4 of 5 | 26% | 56% |

- MobSF's 20 come from its code and manifest rules (ECB, trust-all certificates,
  exported components, WebView settings); it reports 7.6 findings per app and flagged 6
  fixed apps as well.
- Quark scores malicious behavior, not vulnerabilities: Ghera is outside its purpose.
  On MalEval it finds data theft (Privacy Stealing 64% recall) but no Remote Control,
  Bank Stealing, Ransom, Ads, or Privilege Escalation, which depend on what the code
  does as a whole. It crashed on the two samples with fake-encrypted ZIP entries
  (Python's zipfile refuses them); they count as reporting nothing.
- MobSF on MalEval rarely names behaviors (19% recall): its findings are weaknesses
  and permissions, not what the app does.
- The MalEval verdicts of both tools pass through a model (the classifier), which may
  read more or less into a finding than an analyst would; the Ghera scoring does the
  same for all three. 25 MalEval samples is a small slice.
- Cost per app: Quark about 2 s, MobSF about 5 s (Ghera) to 25 s (MalEval); the agent
  minutes and tens of thousands of tokens or more.

## Quark leads as a lead source (2026-10-03)

Would Quark-Engine's rule matches add to the scripted leads? `./cupella quark-leads.py <name>`
turns the comparison run's `tools/quark.json` into `quark-leads.txt` (matches at 80% and
100% confidence, which name the calling method; app scope first), and
`./cupella bench-quark-leads.py [-v]` scores them on the MalEval slice: 18 malware and 5
benign apps with a Quark report (the 2 fake-encrypted samples crashed Quark). The map
from Quark labels to behavior classes is at the top of the script, written before
scoring.

Per app, a lead toward each labeled behavior ("existing": `bench-maleval.py`'s code,
decl, or flow signal; "quark-app": a Quark lead in the app's scan scope):

| Behavior | Labeled | Existing | Quark anywhere | Quark-app | Quark-app only | Benign: existing / Quark anywhere / Quark-app |
|----------|---------|----------|----------------|-----------|----------------|-----------------------------------------------|
| Privacy Stealing | 12 | 100% | 83% | 66% | 0 | 40% / 100% / 0% |
| SMS/CALL | 8 | 75% | 87% | 50% | 0 | 0% / 20% / 0% |
| Premium Service | 1 | 0% | 100% | 0% | 0 | 0% / 20% / 0% |
| Remote Control | 14 | 85% | 92% | 85% | 1 | 0% / 80% / 0% |
| Abusing Accessibility | 4 | 100% | 50% | 25% | 0 | 0% / 0% / 0% |
| Bank Stealing | 5 | 80% | 60% | 20% | 0 | 0% / 80% / 0% |
| Ransom | 5 | 80% | 40% | 40% | 0 | 0% / 0% / 0% |
| Privilege Escalation | 6 | 100% | 16% | 16% | 0 | 0% / 0% / 0% |
| Stealthy Download | 7 | 85% | 100% | 57% | 0 | 0% / 40% / 0% |
| Tricky Behavior | 8 | 87% | 62% | 37% | 0 | 40% / 40% / 0% |
| Ads | 6 | 66% | 0% | 0% | 0 | 20% / 0% / 0% |

Per function, against the Java lines the agent verdicts cite as evidence (60 functions
in the outer APKs; 7 more in embedded payloads, which Quark does not read): the existing
lead files name 38 (63%), Quark leads 23 (38%), only Quark 5, only the existing leads
20, either 43 (71%).

- Quark anywhere in the APK fires on most benign apps (library code); restricted to the
  app's scan scope it fired on none of the 5 benign apps for any behavior.
- At the app level it adds one behavior signal; at the function level it adds 5 of 60
  cited functions (63% to 71%). The function key is the agent's own evidence, found from
  the existing leads, so it favors them.
- 18 samples is a small slice; the result is a signal, not a proof.
- In the pipeline since 2026-10-03 (`scan.sh`). On the 9 analyzed apps' reports
  (`lead-eval.py`), `quark-leads.txt` covers 0 to 8 findings per app; launcher B's
  "any source" coverage rose from 8 to 10 of 12 findings, the other apps' did not change.

## What the numbers do not say

- Every agent benchmark is scored by a model, not a person, and has run once or twice;
  differences of one or two items are within run-to-run noise.
- The Ghera checklist was written from Ghera's own misses, so the Ghera result is
  optimistic; the untouched pairs are the fair measure of it. A held-out set is open
  work ([further-work.md](further-work.md), "Measurement").
- Cost: minutes per app for the agent, and hundreds of thousands to over a million
  tokens for a full analysis of a real app (subagents on 2026-10-03: about 0.3M on a
  small bot loader, about 1.4M on a two-stage banking RAT; one reader agent on one area: 100k to 265k tokens;
  verification of one report: 125k to 280k; budget table in [workflow.md](workflow.md)),
  against seconds for the scanners.
- The vulnerable apps are public and well known; their package names cannot be
  hidden, so part of the result may be recall from training.
- MalEval labels are per app. A code lead for "SMS/CALL" means some SMS API use in
  scope, not that the lead is the malicious code.
- The benign column is a lead rate, not a false-positive rate: benign apps read
  contacts and open sockets too. Leads are for reading, never verdicts.
- Ghera apps are tiny; any API-level pattern lands in the changed method. Real apps
  bury the same code among hundreds of methods.
- `lead-eval.py` is biased toward what the analyst found, since the answer key is
  the report.
