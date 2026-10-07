# A Cupella harness on any model API

Status (2026-10-05): built in `harness/`, run as `./cupella agent`. Done: the `chat` and
`messages` adapters with streaming, the tools and role policy, parallel subagents,
refusal records, usage and cost, fallback, cost and context limits. Smoke-tested on
OpenRouter with `deepseek/deepseek-v4.1-flash` and `anthropic/claude-sonnet-5.5`: a
one-fact question on F-Droid, `run`, a denied `data/` read, and a reader subagent whose
write outside its list was refused. Not built: the `responses` and `prompt` adapters,
`./cupella setup --harness api`, `--resume` from a context-limit stop without the user.
Not yet run: a full analysis, a decryptor subagent, a local server, the `messages`
adapter against the live API, and `host/harness-test.py`. The rest of this file is the
design; where the code differs, the code and "Files and commands" are current.

A small agent loop of our own that calls a
model through a completion or response API (OpenRouter, a vendor's own API, or a local
server) and gives it only the tools Cupella needs. What a harness must provide is in
[harnesses.md](harnesses.md); this file says how ours would provide it, what it gains
over Claude Code and Codex, and the steps to build and measure it. Statements about the
APIs are from their documentation as of 2026-10; check them against the current docs
before building.

## Contents

- Why
- What it is
- Backends
- Tools and roles
- Models per role
- Writing code
- The loop
- Repairs
- Safety
- Files and commands
- Milestones
- Open questions

## Why

- Role limits become technical. Claude Code enforces a role's tool list but not which
  commands the decryptor's shell runs; no harness does ([harnesses.md](harnesses.md)).
  Ours has no shell at all: it runs a fixed set of `./cupella` commands per role.
- Any model with tool calling can run a stage, on any API that serves it, chosen per
  role (a strong model for the main agent and verification, a cheaper one for area
  readers), so models can be compared on the benchmarks with everything else fixed.
- A local server keeps sample-derived text on the machine, which no current harness
  offers.
- Exact model IDs and token use per stage come from the API, so a report's "Agent
  setup" no longer says "not known".
- A refusal or content filter is a recorded event with a known model, the exact
  request, and the text produced before the stop, not a lost response.

What it costs: we maintain the loop, the API adapters, context handling, and retries
ourselves, and models other than Claude have not run a Cupella analysis yet.

## What it is

A host-side Python program, standard library only (like the other host scripts), that:

1. builds the system prompt from `AGENTS.md` (plus `WORKSPACE.md` in a workspace) and
   all of `agent_docs/workflow.md` for the main agent (a model that read the workflow
   itself stopped at line 240 and skipped the native stage, 2026-10-05), or from `roles/<role>.md` plus the filled stage prompt for a
   subagent ([harnesses.md](harnesses.md) "What a harness must provide");
2. sends the conversation and the tool list to the backend configured for that stage;
3. executes the tool calls the model returns, under that role's policy, and sends back
   the results;
4. repeats until the model answers without a tool call, a turn or token limit is
   reached, or the stage is stopped.

It runs on the host because it calls `./cupella`, which needs Docker. It never parses a
sample: it reads the text the scripts wrote under `work/`, like the Read tool does.

## Backends

The loop works on one internal form (messages, tool calls, tool results, usage, stop
reason). A backend adapter turns it into one API's request and back. Planned adapters:

| Adapter | API | Serves |
|---------|-----|--------|
| `chat` | OpenAI-style chat completions (`/v1/chat/completions`, `tools`, `tool_calls`) | OpenRouter, OpenAI, most hosted vendors, and local servers: vLLM, llama.cpp `llama-server`, Ollama, LM Studio |
| `responses` | OpenAI-style Responses API (`/v1/responses`, function calls as output items) | OpenAI, and servers that copy it |
| `messages` | Anthropic Messages API (`/v1/messages`, `tool_use` and `tool_result` blocks) | Anthropic directly |
| `prompt` | plain completion: tool calls written as JSON blocks in the text and parsed by the harness | a model or server with no tool calling at all |

- `chat` comes first: it covers the most servers. The others follow in milestone 4.
- The adapter maps stop reasons to one set: done, tool calls, length, filtered
  (`content_filter`, Anthropic's `refusal`), error.
- Usage and price: every adapter reads input, output, and cached token counts where the
  API reports them. Price comes from the API where it says (OpenRouter), else from a
  per-model price in the configuration, else is reported as unknown.
- Model facts (tool calling, context length): read from a models endpoint where one
  exists (OpenRouter's model list), else taken from the configuration. A model whose
  facts are unknown and not configured is refused.
- `prompt` is the fallback for models without native tool calls. Expect it to be the
  least reliable; it exists so a local base or instruct model can at least run the
  reader stages, and milestone 5 says whether it is good enough.

## Tools and roles

| Tool | What it does | main | reader | decryptor |
|------|--------------|------|--------|-----------|
| `read_file(path, offset, limit)` | text of a file, numbered lines, capped size | yes | yes | yes |
| `grep(pattern, path, glob)` | Python `re` over text files under one directory, capped hits | yes | yes | yes |
| `list_dir(path, glob)` | names under a directory | yes | yes | yes |
| `write_file(path, content)` | create or replace one file | report sources, progress; in the checkout `scripts/`, `host/`, docs; in a workspace `proposals/` | its progress and claim files | under `work/<name>/decrypt/` |
| `edit_file(path, old, new)` | replace one exact, unique string in a file | same paths as `write_file` | no | under `work/<name>/decrypt/` |
| `append_file(path, text)` | append to a progress file | yes | yes | yes |
| `run(script, args)` | runs `./cupella <script> <args>` as an argument list, no shell | any `./cupella` script or command (`check`, `gate`, `try-proposal`) | none | `run-decryptor.sh`, `dex-disasm.py`, `native-summary.py`, `native-disasm.py`, `native-decompile.sh` |
| `spawn(stage, vars, extra, model)` | fills `prompts/<stage>.md` with `vars`, runs a subagent with the stage's role and files, returns its final message | yes | no | no |

- Paths are resolved (`realpath`) and checked against the role's allow-list after
  resolution, so `..` and symlinks cannot leave it. A subagent reads the `samples` the
  main agent names (with their `.emb`/`.dec` children) plus `read` paths under them or
  their `reports/` entry; a reader writes only its `write` list, under its samples; a
  decryptor writes only `work/<name>/decrypt/` and runs the commands in the `shell:`
  line of `roles/decryptor.md`, with path and sample arguments checked.
- Always denied, every role: `data/` (samples are binary; scripts read them),
  `bench/`, `bench-sources/`, `work/_ghera-blind*/key.json`, `reports/_archive/`,
  `work/_previous/`, and any earlier report of the sample under analysis. The answer-key
  and earlier-report invariants in `AGENTS.md` become checks, not instructions.
- `run` checks the script name against the role's list and each argument against a
  pattern (no `;`, `|`, `` ` ``, `$(`, no leading `-` where the script takes a path).
  There is no shell to escape into.
- `run`'s `stdout_to` writes a new file under `work/<name>/` only: it never replaces an
  existing one, so a script's output (`scan.txt`, `facts.json`) cannot be overwritten
  through it. `reports/<name>/costs.jsonl` is written by the harness alone (`DENY_WRITE`).
- A subagent's samples are its sample's directory and its child samples' as they exist
  when it starts, each by exact name; a path repair never moves a path to another sample.
- `run("md-view.py", [path])` is for the user: the harness shows the rendering on its
  own terminal (colored, paged with `less -R`) and returns only a note to the model, so
  it cannot be used to read a report written before the session. Such files are listed
  by `list_dir`, marked as not readable, so that the agent does not take them for
  missing.
- `append_file` exists because the reader prompts work around its absence (one claim
  per file, [harnesses.md](harnesses.md)); keep the one-file-per-claim layout anyway, so
  prompts stay the same across harnesses.
- `spawn` fills the stage's template itself (`read-area`, `verify-report`, `decrypt`):
  the main agent passes the placeholder values and optional `extra` notes, and the
  harness sets the role, samples, and output files from the stage (`STAGES` in
  `harness/agent.py`). A main agent that wrote the prompts itself shortened them to a
  fifth and dropped the claim and verdict schemas, so the reader's claims could not be
  promoted and the verdicts could not be merged (2026-10-06). A missing value is an
  error that quotes the template's header. A stage without a template takes `role` and
  `prompt` as before.
- `spawn` runs subagents in threads, so independent readers run in parallel. Each
  writes the progress file its prompt names, as now.

## Models per role

Every stage runs on the model and backend its configuration names, so a run can mix a
strong hosted model for the main agent with a cheaper or local one for readers, or put
the verifier on a different model from the readers it checks.

```json
{
  "backends": {
    "openrouter": {"api": "chat", "base_url": "https://openrouter.ai/api/v1",
                   "key_env": "OPENROUTER_API_KEY", "provider": {"data_collection": "deny"}},
    "anthropic":  {"api": "messages", "base_url": "https://api.anthropic.com/v1",
                   "key_env": "ANTHROPIC_API_KEY"},
    "local":      {"api": "chat", "base_url": "http://127.0.0.1:8000/v1",
                   "models": {"<local model>": {"context": 131072, "tools": true, "usd_per_mtok": [0, 0]}}}
  },
  "default":   {"backend": "anthropic", "model": "<model>", "max_tokens": 16000},
  "roles": {
    "main":      {"backend": "anthropic", "model": "<model>"},
    "reader":    {"backend": "openrouter", "model": "<cheaper model>",
                  "fallback": [{"backend": "local", "model": "<local model>"}]},
    "decryptor": {"backend": "anthropic", "model": "<model>"}
  },
  "stages": {
    "verify-report": {"backend": "openrouter", "model": "<a model other than the readers'>"},
    "bench":         {"backend": "openrouter", "model": "<the model under test>"}
  },
  "spawn_allowed": ["anthropic:<model>", "openrouter:<cheaper model>", "local:<local model>"],
  "max_usd_per_stage": 5
}
```

- **Keys.** A role (`main`, `reader`, `decryptor`) sets the backend and model for every
  stage of that role; a stage, named after its prompt (`read-area`, `verify-report`,
  `decrypt`, `bench`), overrides its role. Verification is a reader stage, so it needs
  its own `stages` entry to differ from the area readers.
- **Order.** `--role-model` or `--stage-model` on the command line
  (`reader=local:<model>`), then the stage entry, then the role entry, then `default`.
  The backend and model that ran are recorded either way.
- **The main agent's choice.** `spawn(role, prompt, model)` may name a model, but only
  one in `spawn_allowed`; anything else is refused and the configured model is used.
  The main agent cannot raise its own cost or send a stage to a backend the user did
  not list.
- **Fallback** is for availability only: HTTP 5xx after the retries, a refused
  connection, or no provider serving the model. A filtered stop or a refusal does not
  fall back automatically; resending stopped content to another model is the user's
  decision, as in [harnesses.md](harnesses.md).
- **Checks at start.** For each configured model the harness confirms tool calling
  (or the `prompt` adapter) and a context length above a minimum per role (readers and
  the decryptor read large decompiled files; set the minimum from milestone 3), and
  refuses to start otherwise.
- **Limits per model:** `max_tokens` per response and `max_usd_per_stage`, from the
  reported or configured prices. A stage that reaches its cap stops and writes that to
  its progress file, like a session that ran out of context.
- **Caching** is per model and backend, so a stage on another model starts with a cold
  cache. Readers do not share a prefix with the main agent anyway.
- **Recorded:** backend, model, provider (where the API names one), and tokens per
  stage in `harness-usage.tsv`, and in the report's "Agent setup".

Whether a verifier on a different model finds more wrong claims than one on the same
model is a hypothesis: Ghera with verification (milestone 5) can measure it.

## Writing code

Cupella's code work runs through paths that already exist; the harness only has to
give the right role write access to them and nothing more.

| Work | Who | Where the code goes | How it runs |
|------|-----|---------------------|-------------|
| A decryptor for one sample | `decryptor` subagent | `work/<name>/decrypt/decrypt.py` | `./cupella run-decryptor.sh <name>`: linted, offline, writes only `decrypt/` |
| A repair or extraction in a workspace (a ZIP trick `apkunzip.py` does not handle, a new string scheme) | main agent | `proposals/<slug>/tool.py` | `./cupella try-proposal <slug> <name>`: linted, offline, sample read-only |
| The same as a script change, in the checkout | main agent | `scripts/` (`apkunzip.py`, `stringfog.py`, ...) | the scripts in the container; then `./cupella check` and `./cupella gate` |

- `edit_file` is needed for script changes: `apkunzip.py` and `scan.sh` are too large to
  resend whole for a three-line change, and a whole-file rewrite by a model is where
  unrelated lines get lost.
- Agent-written code never runs on the host and never touches sample bytes outside
  those two containers, as now (`AGENTS.md` Invariants). The harness adds no code
  runner of its own.
- Whether a given model writes a correct decryptor is a model question, not a harness
  one. Claude reimplemented AES, RC4, and XOR layers from decompiled Java and Ghidra C
  in one to a few iterations (the decryption stage on MalEval; a dex2c dropper's AES
  payload on 2026-10-04 in about 50k tokens). Other models are untested: the
  decryptor stage belongs in milestone 5.

## The loop

- **Tool results are capped** (for example 20,000 characters). A truncated result says
  so and how to read further (`offset`). Every result from `work/` is wrapped as data
  (`<tool_result path=...>`), never merged into the system text.
- **Context limit.** When a session nears the model's context length, it stops and a
  new session starts that resumes from `progress/main.md`, the claim files, and the
  report sources, the path [workflow.md](workflow.md) "Checkpoints" already describes.
  No summarizing by the model: the progress files are the summary.
- **Retries** with backoff on HTTP 429 and 5xx; a backend failure after the retries
  ends the stage (or falls back, "Models per role") and is written to the progress file.
- **Refusals and filters.** A filtered stop, or a refusal with no tool call, is logged
  with backend, model, provider, and stage in the progress file, and the stage is not
  retried with the same content ([harnesses.md](harnesses.md) stop table rules). The
  user may rerun it with another model.
- **Refusal records.** Each stop is saved to `work/_stops/<time>-<request id>/`: the
  exact request sent (no key), the raw response or stream including any text produced
  before the stop, the response headers, and the stage, role, and model. Written
  before the stage ends; agents never read it. Claude Code keeps only the request id
  and category, in a transcript it deletes after 30 days.
- **Cost in the report.** At the end of a session the harness appends a summary (tokens
  and cost per role, stage, and model) to `reports/<name>/costs.jsonl` for every report
  the main agent wrote or built, and rebuilds the report, which shows it as "Appendix:
  Cost" (design-report.md).
- **Accounting.** The usage of every response (input, output, cache reads and writes,
  cost) and the model and provider the API reports go to
  `work/_harness/<session>/usage.tsv`, one row per response; the main agent is told the
  path and cites it in "Agent setup". Cost comes from the API (OpenRouter) or from the
  configured or listed price.
- **Prompt caching** matters for cost: a long analysis resends a large prefix each turn.
  Use each API's caching (explicit `cache_control` breakpoints on Anthropic's API and
  through OpenRouter for Anthropic models, automatic prefix caching on OpenAI and on
  vLLM or llama.cpp with it enabled), and keep the system prompt and tool list stable
  within a session.
- **Provider routing.** A role's `params` go into every request body, e.g. OpenRouter's
  `provider` object: `{"order": ["openai/flex", "openai"], "allow_fallbacks": true,
  "data_collection": "deny"}` sends Sol to OpenAI's flex tier (half the standard price,
  2026-10-07) and falls back to the standard tier, keeping one provider so the prompt
  cache stays warm. A role's `params` replace the backend's keys of the same name, and
  are dropped when the command line or a spawn swaps in another model.
- **Reasoning effort.** `"reasoning": "low"` (or `"minimal"`, `"medium"`, `"high"`) on a
  role or stage becomes OpenRouter's `reasoning.effort`, OpenAI's `reasoning_effort`, or
  Anthropic's `output_config.effort`. Most main-agent turns only pick the next tool
  call; keep more effort for the stages that judge (verification, the report). Not set
  in the example: models differ in which values they accept.
- **Cache lifetime.** Anthropic's cache entries last 5 minutes. The main agent often
  waits longer than that for its readers, and its next request then writes its whole
  prefix again. `"cache_ttl": "1h"` on a role or stage asks for the 1-hour cache (a
  write costs 2x input instead of 1.25x; a read 0.1x either way); the example sets it
  for `main`. Readers send requests seconds apart and keep the 5-minute default.
  OpenAI and other providers that cache automatically ignore it.
- **Transcripts** go to `work/_harness/<session>/` for debugging, one JSON line per
  request and response, appended as they happen. Agents never read them
  ([workflow.md](workflow.md) "Subagent stages").

## Repairs

Easy mistakes in a tool call are repaired, not refused (`harness/repair.py`), and every
repair heads the tool result (`[harness repaired: ...]`) and goes to `events.log`:
Claude Code tool names (`Read`, `Bash` with a `./cupella` command), argument names and
types (`file_path`, `"5"` for a number, a string for a list), tool-call JSON that does
not parse (unless the response was cut off), a guessed sample file (`data/x.apk` found
as `data/malware/X.apk`), a sample name prefix, a near-miss path, a bare `stdout_to`
name (put in `work/<name>/`), reading a directory (listed instead), an invalid regular
expression (searched as text), an `edit_file` string that differs only in whitespace,
and code fences around JSON written to a `.json` or `.jsonl` file (which is also
parsed, with bad lines reported). A missing file's error names the closest existing
names. A repaired path goes through the same policy checks. An unexpected error in a
tool or a subagent becomes an error result, logged with its traceback, and never ends
the session. An agent that makes the same tool call three times in a row is told the
result will not change and to try something else; on the eighth (`max_repeats`) it is
stopped. A decryptor once sent the same `grep` 12 times in a row (2026-10-06).

## Safety

- **Data leaves the machine** on every hosted backend. Every file the agent reads,
  including decompiled malware and strings from the sample, goes to that API and, for
  a router like OpenRouter, to the provider it picks. That is true of Claude Code and
  Codex too, but here the user picks. Default to providers that do not retain or train
  on prompts (OpenRouter: `data_collection: "deny"`); say in the report which backends
  and providers were used. A local backend keeps it on the machine.
- **API keys** come from the environment variable each backend names (`key_env`), are
  never written to a log or transcript, and are removed from the environment of every
  `./cupella` call.
- **Network:** the harness process talks only to the `base_url` of each configured
  backend. No tool fetches anything. The only `./cupella` script with network access
  the agent can run is `reference-check.py`, main role only, as now. A local backend
  listens on loopback; it is the user's server and outside Cupella's container.
- **Injection:** tool results are data to the model, and nothing the model says can
  widen a policy. A model that asks for a tool outside its role gets an error result,
  which the harness also logs.
- **Live malware:** the same advice as for any harness applies: run the harness in a VM
  or under a dedicated user (`README.md` "Safety").

## Files and commands

```
harness/
  agent.py              the loop, retries, fallback, limits, accounting, refusal records, CLI
  backends.py           adapters: chat, messages (streaming)
  tools.py              tool implementations
  policy.py             per-role path and command policy; deny list for every role
  repair.py             repairs of easy mistakes in tool calls ("Repairs")
  store.py              file access for tools and logs: host directories, or data/ and
                        work/ in Docker volumes through store_helper.py (store-volumes.md)
  store_helper.py       the volume store's helper, in a container (./cupella store-serve)
  models.example.json   backends, model per role and stage, limits; copy to models.json
host/harness-test.py    policy and adapter checks: path escape, symlink, denied paths,
                        role limits, command arguments, recorded streams per adapter;
                        the policy and tool cases on both stores
```

- Configuration: `harness/models.json` (copied from the example; gitignored), or
  `harness.json` in a workspace, or `--config`. Keys stay in the environment variable
  each backend names (`key_env`), or in a file (`key_file`, e.g. a Hugging Face token),
  and are removed from every `./cupella` call.
- `./cupella agent "<request>"` starts a main session, answers, and exits. `--chat`
  (`-i`) keeps it open for follow-ups on a terminal, in the same context: the only way
  to ask about a report afterwards, since a later session cannot read it. `--model`,
  `--role-model reader=<backend>:<id>`, `--stage-model verify-report=<backend>:<id>`,
  and `--max-usd` override the configuration.
- `./cupella agent --resume <name>` starts a session that resumes an unfinished analysis.
- `./cupella agent --check` resolves every role's model and checks tool support and
  context length (from OpenRouter's model list or the configuration).
- Per session, `work/_harness/<session>/`: `config.json` (no keys), `events.log`,
  `usage.tsv`, and per agent `transcript.jsonl` (appended message by message) and `runs/`
  (full `./cupella` output). Per stop, `work/_stops/<time>-<request id>/`: `request.json`,
  `stream.txt`, `headers.json`, `event.json`. Agents never read either, except the main
  agent's `usage.tsv`. In a volume workspace both are in the work volume, not on the host
  ([store-volumes.md](store-volumes.md)).
- `./cupella check` runs `host/harness-test.py`: no network, no key.
- `./cupella model-compare <name> <spec>...` (`host/model-compare.py`) runs the same
  analysis once per model (`MAIN` or `MAIN+READER`), each from the scripts' output
  alone: the sample's agent outputs are moved aside first and back at the end. Per run:
  finished or stopped, cost, turns, subagent stages, native tool runs and reads,
  `claims-check` and `cite-check` results, verifier verdicts, repairs, denials, stops,
  in `work/_bench-models/<run>/summary.md`. Each run's `work/` outputs are kept in
  `work/_bench-models/<run>/<model>/`, its report files in
  `reports/_archive/model-compare/<run>/<model>/` (both denied to agents), so it works
  in a volume workspace too. Judging the findings is the user's.

## Milestones

1. **One session, main role, `chat` adapter.** (Done on a hosted backend, 2026-10-05;
   local server not run.) Loop, the read/grep/list/write/append
   tools, `run` with the main allow-list, usage logging. Done when it runs `unpack.sh`
   and `scan.sh` and answers a one-fact question ("who signed it") on a benign sample,
   once on a hosted backend and once on a local server.
2. **Policy tests** in `./cupella check` (written, not yet run): escapes through `..`, symlinks in `work/`,
   denied paths, argument patterns, a reader calling `run`.
3. **Subagents.** (Built; one reader smoke-tested.) `spawn`, roles, parallel readers, claim files, verification. Done
   when it produces a full rendered report on a benign app that passes `cite-check`
   and `claims-check`, and a decryptor subagent decrypts a MalEval sample whose payload
   the Claude Code decryption stage already opened (same `outputs.txt`).
3b. **Code work.** `edit_file`, the checkout and workspace write paths, `check` and
   `gate` through `run`. Done when a workspace session writes a proposal tool that
   `try-proposal` runs on a sample, and a checkout session makes a script change that
   passes `./cupella check` and the gate.
4. **Long runs and the other adapters.** Context-limit restart from the checkpoints,
   retries, fallback, filter handling, cost cap; the `messages`, `responses`, and
   `prompt` adapters. Done when an analysis interrupted on purpose finishes from
   `progress/main.md`, and the one-fact question passes on each adapter.
5. **Measure.** Ghera blind and the MalEval slice with `prompts/bench/`, first with a
   Claude model through this harness (to separate harness effects from model effects),
   then with one or two other hosted models and one local model. Record in
   [benchmarks.md](benchmarks.md) and add a section to [harnesses.md](harnesses.md).

Each milestone ends with a run on a real sample; a milestone that does not reach its
"done when" is the next one's first task.

## Open questions

- Which non-Claude models follow the invariants over a long run (no earlier reports,
  one claim per file, no verdicts) is unknown; milestone 5 answers it.
- Whether any local model is good enough for more than reader stages, and how much
  context a local server can hold for the decompiled files a reader opens.
- Cost per full analysis without caching could be several times the Claude Code
  figures in [workflow.md](workflow.md) "Budget mode"; measure it in milestone 3.
- Whether the `prompt` adapter is worth keeping once milestone 5 has run.
- Whether the harness should also run benchmark agents (`bench-*.py` start them today
  through the harness the user runs); probably yes, after milestone 5.
