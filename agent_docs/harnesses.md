# Harnesses

Cupella is a set of scripts, a container, docs, and prompts; the coding agent that
reads the docs and runs `./cupella` is interchangeable. This file says what a harness has
to provide and how each known one provides it. Claude Code ran all benchmarks and the
subagent stages. Codex and Antigravity have run analyses successfully. The notes for
the other harnesses are untested.

## Contents

- What a harness must provide
- Claude Code
- Other harnesses (Codex CLI, Antigravity, Gemini CLI, Cursor, others)
- Known harness-specific behavior

## What a harness must provide

| Need | Why | Without it |
|------|-----|------------|
| Read `AGENTS.md` at session start | the instructions, invariants, and doc routes | tell the agent to read `AGENTS.md` first |
| Run shell commands (`./cupella`) | every script runs through `./cupella` in the container | Cupella cannot run |
| Start fresh subagents with their own instructions | decryption, verification, area readers, benchmarks: a second context that has not seen the analysis | run the stage as a new session with the role and the prompt (below); slower, same result |
| Restrict a subagent's tools (no shell for `reader`, listed commands for `decryptor`) | agents reading malware-derived text get no general shell | the restriction is by instruction only; say so in the report's coverage |
| Deny host tools on sample files | invariant: parse samples only inside the container | by instruction only |

Roles are defined once in `roles/` (see [../roles/README.md](../roles/README.md)): a
header with what the role may read, write, and run, and the rule text. Prompts for each
stage are in `prompts/`. A harness runs a stage by starting an agent with the role's
rule text followed by the stage prompt, and enforcing the role's header where it can.

## Claude Code

- `CLAUDE.md` imports `AGENTS.md` (`@AGENTS.md`); a workspace's generated `CLAUDE.md`
  imports its copy of `AGENTS.md` and `WORKSPACE.md`. The workspace's
  `.claude/settings.json` and agent types are generated too and refreshed with the docs;
  user permission rules go in `.claude/settings.local.json`.
- `./cupella setup` (with `--harness claude`, the default when `claude` is installed)
  generates the agent types `apk-reader` and `apk-decryptor` in `.claude/agents/` from
  `roles/`, with the tool lists the role headers allow (reader: Read, Grep, Glob, Write;
  decryptor: the same plus Bash). They load when a session starts; a session started
  before they existed uses a general-purpose agent with the role text in its prompt.
- `.claude/settings.json` allows `./cupella` and denies `adb` and host parsing
  tools for every session in the project.
- Subagents run in the background and report back; progress files in
  `work/<name>/progress/` show where they are.

## Other harnesses

Codex CLI (in a workspace, without subagent stages) and Antigravity have run analyses
successfully; the others are untested. The steps follow each harness's documented
conventions as of 2026-10; check them against its current docs.

- **Codex CLI** reads `AGENTS.md` itself. It has no subagent type definitions: run a
  stage as a separate `codex exec` session whose prompt is the role text
  (`roles/<role>.md`, body) followed by the stage prompt (`prompts/<stage>.md`, filled
  in). Its sandbox blocks the Docker socket (see "Known harness-specific behavior"):
  set the approval mode to "Ask for approval" and approve commands that start with
  `./cupella` to run outside the sandbox; never give the session full access instead. A
  reader session needs no shell beyond reading files, so run it with the strictest
  sandbox that still lets it write its output and progress files, and never approve
  `./cupella` there.
- **Gemini CLI** reads `GEMINI.md` by default; set `"contextFileName": "AGENTS.md"` in
  `.gemini/settings.json` (in the checkout or workspace). Stages run as separate
  sessions as for Codex.
- **Cursor, GitHub Copilot agent mode, and others that read `AGENTS.md`**: the
  instructions load; stages run as new chats or tasks with the role text and the
  stage prompt.
- **Harnesses without instruction-file support**: start each session with "Read
  AGENTS.md and follow it".

`./cupella setup --harness other` (the default when `claude` is not installed) makes the
workspace files every harness needs (the doc copies, `WORKSPACE.md`, the `cupella` wrapper, the
marker) and none of the Claude files. Because the workspace holds copies, not a link, a
harness sandbox limited to the workspace (Codex `workspace-write`) can read every doc the
agent needs; proposals go to the workspace's `proposals/`, inside the sandbox, and
`./cupella try-proposal` runs a proposed tool from there.

## Known harness-specific behavior

- Codex CLI's `workspace-write` sandbox blocks `/var/run/docker.sock` even when the
  user is in the `docker` group, so `./cupella` fails inside it (verified 2026-10).
  Commands it runs inherit the sandbox, and a session started with escalation
  disabled cannot ask to leave it. Switch the approval mode with `/permissions` to "Ask
  for approval", then approve the `./cupella` prefix once ("always run commands that
  start with ./cupella"). Only `./cupella` leaves the sandbox; the scripts it runs stay in
  Cupella's own container.

- Claude Code refuses a subagent's write to a file named like a report
  ("Subagents should return findings as text, not write report files"); subagent output
  files are named after their content (`verification.md`, `verdicts/<id>.json`).
- Agents without a shell have no clock: progress lines are numbered steps, not times.
- A safety classifier can stop a subagent reading malware code partway; split reading
  into small areas (`prompts/read-area.md`) so a stopped agent loses little.
- The same classifier has stopped the main agent while it wrote reader prompts, and a
  reader assigned to a DDoS bot's attack routines before it read anything (2026-10-03).
  Keep prompts short and neutral (paths, function names, questions; no paraphrase of
  what the malware does), never resend a stopped prompt reworded, and report the area
  as not read or read it at the capability level from strings and structure leads.
- The classifier has also stopped readers at the very end, while they wrote their final
  summary of a banking trojan's SMS and command code (two of four readers, 2026-10-04):
  the reading was done and only the summary was lost. Readers now write each finding
  to `work/<name>/progress/<role>-findings.md` as they confirm it and end with a
  one-line message (`prompts/read-area.md`).
- It has stopped the main agent writing a report in large pieces (table below).
  Nothing from a stopped response is kept. The main agent now writes one section per
  write and takes the Findings and Indicators of malware from a reader's findings file
  ([workflow.md](workflow.md) "Checkpoints").
- Stops so far, by model and stage (one or two events each, different samples: a hint,
  not a measurement):

  | Model | Stage | Outcome |
  |-------|-------|---------|
  | Claude Fable 5.1 (main agent) | report writing, two malware samples (a dropper, an SMS stealer; 2026-10-03/04) | finished, not stopped |
  | `claude-opus-4-8` (reader subagents) | final summaries of an SMS stealer's areas (2026-10-04) | 2 of 4 stopped |
  | Claude Opus 5.5 (main agent) | first write of the report on an NFC card-relay app (2026-10-04) | stopped; no file written |
  | Claude Opus 5.5 (main agent) | same sample, second session: one Edit holding eight sections (2026-10-04) | stopped; skeleton kept, edit not applied |

- When the report stage is stopped, never retry the stopped content in that session,
  reworded or through a subagent. Write the stop into `progress/main.md` and tell the
  user. The user can finish the analysis in a fresh session, with another model
  selected if they choose (Claude Code: `/model`); that session resumes from
  `progress/main.md` and the script output ([workflow.md](workflow.md) "Checkpoints")
  and writes the report itself. A subagent cannot take over the report anyway: Claude
  Code refuses a subagent's write to a file named like a report.
