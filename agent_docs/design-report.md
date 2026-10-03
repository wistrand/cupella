# Design: analysis report

## Contents
- Purpose
- Structure
- Behavior maps
- Evidence rules
- Confidence labels
- What stays out

## Purpose

`reports/<name>.md` is the product of an analysis: a reader who never opens `work/`
should learn what the APK is and what in it deserves attention, and be able to check
each claim. The structure is fixed so reports for different APKs can be compared
section by section.

## Structure

Use these sections in this order. Keep a section even when it is empty and write
"none found" plus what was searched, so absence is distinguishable from not checked.

```markdown
# <app label> (<package>) <versionName>

## Summary
Three to six sentences: what the app is, how it is built (native, Flutter, ...),
and the findings that matter most.

## Identity
| Field | Value |   file, sha256, size, package, versionName/Code, min/target SDK
When the report speaks for a family or the sample was chosen from several, one line on
why this sample (for example: its behaviors cover the family's documented profile most
fully; the newest; the only one that decompiles).

## Signing
Certificate subject, validity, SHA-256 fingerprint, signature schemes present, and the
result of scripts/apksig-verify.py. Say what verification does and does not establish.

## Analysis coverage
Tool versions (from the end of triage.txt, or ./cupella versions), which stages ran, jadx error count,
anything that failed or was skipped. Framework note if app logic is outside the dex.
Agent setup: the harness and its version (Claude Code, Codex CLI, ...), the model and
reasoning setting of the main agent and of each subagent stage, how many subagents ran
in which roles, and token use per stage where the harness reports it. Give exact model
IDs only as the harness or system prompt states them; write "not known" for anything
the agent cannot see, never a guess. Mark a budget run here too.

## Permissions
| Permission | Used by (code reference) | Notes |

## Components
Exported activities, services, receivers, providers; deep links; guarding permissions.

## Network
Hosts and endpoints, cleartext use, network security config, TLS overrides, pinning.

## Third-party libraries
| Library | Package prefix | Purpose | Notes |
Tracker signature matches (trackers.txt) with what each match turned out to be.

## Data handling
Storage, identifiers collected, crypto use, hardcoded secrets.

## Native code
ABIs; a table of libraries with group (runtime, app logic, third-party, app-specific),
provenance (build paths, reference-check result) and how
each was identified; JNI surface of app-specific libraries; which functions were
read and how (disassembly, decompilation), which were not.

## Findings
Numbered, most significant first. Each: what, where (evidence), why it matters,
confidence. For a malicious or suspected sample, also name its behavior class and the
MITRE ATT&CK Mobile technique IDs that fit (see runbook-analysis "Malware samples"),
and group the findings under the threats they serve (for example "Credential theft",
"SMS interception", "Payload download"), each threat with its findings beneath it.
For security weaknesses, mark each as a vulnerability (exploitable as described) or a
configuration issue. A finding that rests on a call chain across several functions gets
a behavior map (below).

## Indicators
Only for samples that are malicious or suspected: hashes, signer fingerprint, package
and file names, hosts, names, ports, keys, log lines. A table, values exact.

## Open questions
What could not be determined statically, and what would resolve it.

## Method changes
Scan patterns, script additions, or Quark-style rules this analysis added or proposed
(in a workspace: the `proposals/` file), each with what it detects, the sample and code
that showed the need, and the `./cupella gate` result or "not yet gated". "None" when
the run added nothing.

## Outside references
Only when the user asked for outside research (web searches on identifiers). What was
searched, on what date, what was found, with links. Context, never evidence: each
claim that matches a public report names the code that matches it.
```

## Behavior maps

A behavior map is a small call graph that shows how a finding's behavior is reached:
the entry point, the functions in between, and the APIs that do the work. Generate it
with `./cupella behavior-map.py <name> <Class.method>` and paste the Mermaid block it
writes under the finding, followed by the evidence citations as usual. Use one for each
finding whose claim depends on a chain (a receiver that leads to an upload, a command
handler that reaches SMS sending), not for single-function findings. The map shows
what the call graph contains; reflection, native calls, and dynamically loaded code do
not appear in it, so say when the chain was completed by reading. In R8-obfuscated code
check each edge in the source before using a map: merged lambda classes create false
edges ([gotchas.md](gotchas.md)).

## Evidence rules

- Every factual claim cites where it was seen: a path relative to `work/<name>/`
  (`jadx/sources/org/example/Net.java:42`, `apktool/AndroidManifest.xml`), or the
  command that produced it.
- Quote short fragments (a URL, a manifest attribute, one or two lines of code).
  Never paste whole methods; the path is the reference.
- Redact live-looking secrets to the first and last four characters. The report may
  be shared; the full value stays findable through the cited path.
- For obfuscated code, cite the obfuscated name as it appears. Do not report
  `--deobf` generated names as real ones.
- State counts with their scope: "14 hosts in the app's own packages, library code
  not searched".
- Cite code in a child sample with its path: the full `work/<name>.dec2/...` or the
  short `.dec2/...`. Code read in `jadx-strings/` may be cited there (the plaintext is
  next to each call) or under `jadx/sources/`: the line numbers are the same.
- Write citations in the forms `./cupella cite-check.py <name>` can verify: paths in
  backticks (`util/Foo.java:120-130`), "`Foo.bar` (`util/Foo.java:120`)" for a method
  and its lines, a quote directly followed by its citation, native and Dart function
  names as they appear in the decompiled output.

## Confidence labels

Findings carry one label:

| Label       | Meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| `confirmed` | read the code or config and it does what the finding says               |
| `likely`    | consistent indicators, but a step is inferred (obfuscation, reflection) |
| `lead`      | a search hit or name match not followed up; say why not                 |

A feature whose code exists but cannot run as shipped is neither: the permission it
checks for is not requested, the native library it loads is not in the APK, or the
operator option that enables it is off by default. Say "present but inert" (or "off by
default, enabled by command") and name the gate with its evidence; `scan.txt` lists
missing permissions and libraries. On the BTMOB report, most claims the verifier
found overstated were of this kind.

Static analysis cannot show that code is reached at runtime. A `confirmed` finding
says the code exists and what it does, not that it runs. Phrase accordingly: "contains
code that uploads X", not "uploads X", unless the call path from an entry point was
traced.

## What stays out

- Severity scores. Explain why something matters instead; scoring schemes need a
  threat model the report does not have.
- Generic advice ("consider enabling pinning"). The report describes the APK.
- Library internals, unless a finding depends on them.
- Verdicts such as "malware" or "safe" on the report's own authority. Describe the
  behavior and let the reader decide. When a sample was provided as malware, say so
  in the first line and describe what it does; naming a family is a claim about
  lineage that needs the structural evidence stated (a version string in the code, a
  match in `scan.txt` "Known family markers", the outside report's details compared
  with the code).
