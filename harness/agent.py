#!/usr/bin/env python3
# The Cupella harness: an agent loop on any model API, with the tools Cupella needs and
# each role's paths and commands enforced in code (agent_docs/harness-api.md). Host
# side, standard library only. Run as `./cupella agent`.
#
#   ./cupella agent "<request>"                 a main session in the checkout or workspace:
#                                               answers and exits
#   ./cupella agent --resume <name>             resume an unfinished analysis of <name>
#   ./cupella agent --chat "<request>"          then asks for follow-ups in the same session
#                                               (-i; on a terminal only)
#   ./cupella agent --check                     check the configured backends and models
#
#   --model B:M                 the main agent's backend and model
#   --role-model reader=B:M     a role's (repeatable)
#   --stage-model verify-report=B:M   a stage's (repeatable)
#   --max-usd N                 cost cap per stage
#   --config FILE               default: harness.json in the workspace, else harness/models.json
#
# Writes work/_harness/<session>/: transcript.jsonl per agent, runs/ (full ./cupella
# output), usage.tsv (tokens and cost per response), events.log. A response stopped by
# the provider (refusal, content filter) is saved to work/_stops/<time>-<request id>/:
# the request body as sent, every streamed line, the response headers, and event.json.
# All of these hold sample-derived text: they are written through the workspace's store
# (harness/store.py), so in volume mode they stay in the work volume.
import argparse
import concurrent.futures
import datetime
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backends  # noqa: E402
import repair  # noqa: E402
import policy as pol  # noqa: E402
import store as stores  # noqa: E402
from tools import ROLE_TOOLS, TOOL_SPECS, Tools, ToolError  # noqa: E402

KEY_ENVS = {"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"}
DEFAULT_MIN_CONTEXT = {"main": 100000, "reader": 64000, "decryptor": 64000}


def now():
  return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_spec(s):
  b, sep, m = s.partition(":")
  if not sep or not b or not m:
    raise SystemExit(f"bad model spec {s!r}: use <backend>:<model>")
  return b, m


class Harness:
  def __init__(self, ws, root, cfg, args):
    self.ws, self.root, self.cfg, self.args = os.path.realpath(ws), root, cfg, args
    # the wrapper by the path the user's ./cupella gave (CUPELLA_WS), not the resolved one:
    # a workspace's volumes are named from that path, and a link in it changes the name
    self.cupella = os.path.join(ws, "cupella") if os.path.exists(os.path.join(ws, "cupella")) \
      else os.path.join(root, "cupella")
    keys = KEY_ENVS | {b.get("key_env") for b in cfg["backends"].values() if b.get("key_env")}
    self.clean_env = {k: v for k, v in os.environ.items() if k not in keys and k != "CUPELLA_WORKSPACE"}
    self.session = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(2)
    self.store = stores.make(self.ws, self.cupella, self.clean_env)
    self.dir = f"work/_harness/{self.session}"  # relative to the workspace, in the store
    self.opened = False
    self.lock = threading.Lock()
    self.stop_event = threading.Event()
    self.backends, self.facts, self.or_models = {}, {}, None
    self.n_agents = 0
    self.started = time.time()
    self.total_usd = 0.0
    self.rows = []            # one per response: for the report's cost appendix
    self.report_names = set()  # reports/<name>/ this session wrote or built

  def open_session(self):
    # the session directory: not made for --check
    self.store.write_text(f"{self.dir}/usage.tsv", "time\tagent\trole\tstage\tbackend\tmodel\tprovider\tinput\t"
                          "cache_read\tcache_write\toutput\tusd\tstop\n")
    cfg_safe = {k: v for k, v in self.cfg.items() if k != "backends"}
    cfg_safe["backends"] = {n: {k: v for k, v in b.items() if k != "key"} for n, b in self.cfg["backends"].items()}
    self.store.write_text(f"{self.dir}/config.json", json.dumps(
      {"session": self.session, "args": vars(self.args), "config": cfg_safe, "store": self.store.mode}, indent=2))
    self.opened = True

  def log(self, msg, quiet=False):
    line = f"{now()} {msg}"
    with self.lock:
      if self.opened:
        self.store.append_text(f"{self.dir}/events.log", line + "\n")
      if not quiet:
        print(f"{time.strftime('%H:%M:%SZ', time.gmtime())} [harness] {msg}", file=sys.stderr, flush=True)

  def backend(self, name):
    if name not in self.backends:
      bc = self.cfg["backends"].get(name)
      if bc is None:
        raise SystemExit(f"no backend {name!r} in the configuration")
      key = None
      if bc.get("key_env"):
        key = os.environ.get(bc["key_env"])
        if not key:
          raise SystemExit(f"backend {name}: {bc['key_env']} is not set")
      elif bc.get("key_file"):
        # a token kept in a file (never logged; ./cupella calls never see it)
        try:
          key = open(os.path.expanduser(bc["key_file"])).read().strip()
        except OSError as e:
          raise SystemExit(f"backend {name}: key_file {bc['key_file']}: {e.strerror}")
      self.backends[name] = backends.make(name, bc, key)
    return self.backends[name]

  def spec(self, role, stage=None, override=None):
    # order: command line, stage entry, role entry, default
    c = dict(self.cfg.get("default", {}))
    c.update(self.cfg.get("roles", {}).get(role, {}))
    if stage:
      c.update(self.cfg.get("stages", {}).get(stage, {}))
    for key, table in (("role", self.args.role_model), ("stage", self.args.stage_model)):
      for item in table or []:
        k, _, v = item.partition("=")
        if (key == "role" and k == role) or (key == "stage" and k == stage):
          c["backend"], c["model"] = parse_spec(v)
          c.pop("fallback", None)
    if role == "main" and self.args.model:
      c["backend"], c["model"] = parse_spec(self.args.model)
      c.pop("fallback", None)
    if override:
      c["backend"], c["model"] = parse_spec(override)
      c.pop("fallback", None)
    # params configured for one model (provider routing, say) do not follow a model
    # swapped in from the command line or a spawn
    configured = dict(self.cfg.get("default", {}), **self.cfg.get("roles", {}).get(role, {}),
                      **(self.cfg.get("stages", {}).get(stage, {}) if stage else {}))
    if (c.get("backend"), c.get("model")) != (configured.get("backend"), configured.get("model")):
      c.pop("params", None)
    if not c.get("backend") or not c.get("model"):
      raise SystemExit(f"no backend and model configured for role {role}" + (f", stage {stage}" if stage else ""))
    return c

  def model_facts(self, backend_name, model):
    k = (backend_name, model)
    if k in self.facts:
      return self.facts[k]
    bc = self.cfg["backends"][backend_name]
    f = dict(bc.get("model_defaults", {}))
    f.update(bc.get("models", {}).get(model, {}))
    if ("context" not in f or "tools" not in f) and "openrouter.ai" in bc["base_url"]:
      if self.or_models is None:
        try:
          self.or_models = {m["id"]: m for m in self.backend(backend_name).get_json("/models").get("data", [])}
        except Exception as e:  # noqa: BLE001
          self.log(f"{backend_name}: model list unavailable: {e}")
          self.or_models = {}
      m = self.or_models.get(model)
      if m:
        f.setdefault("context", m.get("context_length"))
        f.setdefault("tools", "tools" in (m.get("supported_parameters") or []))
        p = m.get("pricing") or {}
        try:
          f.setdefault("usd_per_mtok", [float(p.get("prompt", 0)) * 1e6, float(p.get("completion", 0)) * 1e6])
          if p.get("input_cache_read"):
            f.setdefault("usd_per_mtok_cache_read", float(p["input_cache_read"]) * 1e6)
        except (TypeError, ValueError):
          pass
    self.facts[k] = f
    return f

  def check_model(self, role, c):
    f = self.model_facts(c["backend"], c["model"])
    if not f.get("context") or "tools" not in f:
      raise SystemExit(f"{c['backend']}:{c['model']}: context length and tool support unknown; "
                       f"add them under backends.{c['backend']}.models in the configuration")
    if not f["tools"]:
      raise SystemExit(f"{c['backend']}:{c['model']}: no tool calling (the prompt adapter is not built)")
    need = self.cfg.get("min_context", {}).get(role, DEFAULT_MIN_CONTEXT.get(role, 64000))
    if f["context"] < need:
      raise SystemExit(f"{c['backend']}:{c['model']}: context {f['context']} below the {role} minimum {need}")
    return f

  def price(self, facts, u, ttl=None):
    if u.get("cost") is not None:
      return float(u["cost"])
    p = facts.get("usd_per_mtok")
    if not p:
      return None
    cr = facts.get("usd_per_mtok_cache_read", p[0] * facts.get("cache_read_mult", 0.1))
    # a cache write costs 1.25x input for the 5-minute cache, 2x for the 1-hour one (Anthropic)
    cw = p[0] * (facts.get("cache_write_mult_1h", 2.0) if ttl == "1h" else facts.get("cache_write_mult", 1.25))
    return (u["input"] * p[0] + u["cache_read"] * cr + u["cache_write"] * cw + u["output"] * p[1]) / 1e6

  def usage_row(self, agent, r, usd):
    u = r.usage
    row = [now(), agent.label, agent.role, agent.stage, agent.backend.name, r.model or agent.model,
           str(r.provider or ""), u["input"], u["cache_read"], u["cache_write"], u["output"],
           "" if usd is None else f"{usd:.4f}", r.stop]
    with self.lock:
      self.rows.append({"role": agent.role, "stage": agent.stage, "model": r.model or agent.model,
                        "provider": str(r.provider or ""), "usage": dict(u), "usd": usd})
      self.total_usd += usd or 0
      self.store.append_text(f"{self.dir}/usage.tsv", "\t".join(str(x) for x in row) + "\n")

  def save_stop(self, agent, r, why, error=None):
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rid = re.sub(r"[^A-Za-z0-9_-]", "", str(r.request_id or agent.label))[:48]
    d = f"work/_stops/{t}-{rid}"
    self.store.write_text(f"{d}/request.json", json.dumps(r.request, indent=1))
    self.store.write_text(f"{d}/stream.txt", "\n".join(r.lines) + "\n")
    self.store.write_text(f"{d}/headers.json", json.dumps(r.headers, indent=2))
    ev = {"time": now(), "why": why, "session": self.session, "agent": agent.label, "role": agent.role,
          "stage": agent.stage, "backend": agent.backend.name, "api": agent.backend.api,
          "model_requested": agent.model, "model": r.model, "provider": r.provider,
          "request_id": r.request_id, "stop": r.stop, "stop_raw": r.stop_raw, "stop_details": r.stop_details,
          "error": error, "usage": r.usage, "text_before_stop": r.text, "refusal_text": r.refusal,
          "tool_calls_before_stop": [{"name": c["name"], "raw_args": c["raw_args"]} for c in r.tool_calls],
          "turn": agent.turns, "transcript": agent.tpath}
    self.store.write_text(f"{d}/event.json", json.dumps(ev, indent=2))
    return d


def write_costs(h):
  # one line per session in reports/<name>/costs.jsonl for each report the session wrote
  # or built, then a rebuild so the report's "Appendix: Cost" includes this session
  if not h.rows or not h.report_names:
    return
  agg = {}
  for r in h.rows:
    k = (r["role"], r["stage"], r["model"], r["provider"])
    a = agg.setdefault(k, {"role": k[0], "stage": k[1], "model": k[2], "provider": k[3], "responses": 0,
                           "input": 0, "cache_read": 0, "cache_write": 0, "output": 0, "usd": 0.0})
    a["responses"] += 1
    for f in ("input", "cache_read", "cache_write", "output"):
      a[f] += r["usage"].get(f) or 0
    a["usd"] = None if a["usd"] is None or r["usd"] is None else a["usd"] + r["usd"]
  for a in agg.values():
    if a["usd"] is not None:
      a["usd"] = round(a["usd"], 4)
  rec = {"session": h.session, "ended": now(), "harness": "cupella agent", "agents": list(agg.values())}
  for name in sorted(h.report_names):
    d = os.path.join(h.ws, "reports", name)
    if not os.path.isdir(d) or os.path.islink(d):
      continue
    with open(os.path.join(d, "costs.jsonl"), "a") as f:
      f.write(json.dumps(rec) + "\n")
    h.log(f"cost of this session added to reports/{name}/costs.jsonl")
    if os.path.exists(os.path.join(h.ws, "reports", name + ".json")):
      r = subprocess.run([h.cupella, "report-build.py", name], cwd=h.ws, env=h.clean_env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
      h.log(f"rebuilt reports/{name}.md with the cost appendix" if r.returncode == 0 else
            f"rebuilding reports/{name}.md failed: {r.stdout.decode('utf-8', 'replace').strip()[-200:]}")


def tool_list(role):
  return [(n, TOOL_SPECS[n]) for n in ROLE_TOOLS[role]]


def looks_like_refusal(e):
  return bool(re.search(r"refus|content.?filter|usage polic|safety|moderation|flagged", e.body or str(e), re.I))


class Agent:
  def __init__(self, h, role, stage, policy, system, override=None, parent=None):
    self.h, self.role, self.stage, self.policy, self.system = h, role, stage or role, policy, system
    with h.lock:
      h.n_agents += 1
      n = h.n_agents
    self.label = "main" if role == "main" and parent is None else f"{self.stage}-{n}"
    self.spec = h.spec(role, stage, override)
    self.chain = [(self.spec["backend"], self.spec["model"])] + [parse_spec(x) if isinstance(x, str) else
                                                                 (x["backend"], x["model"]) for x in self.spec.get("fallback", [])]
    self.use(0)
    self.max_tokens = self.spec.get("max_tokens", 16000)
    self.params = dict(self.spec.get("params", {}))
    if self.spec.get("reasoning"):
      # one setting for every adapter: OpenRouter's reasoning object, OpenAI's
      # reasoning_effort, Anthropic's output_config effort
      e = self.spec["reasoning"]
      if self.backend.api == "messages":
        self.params.setdefault("output_config", {"effort": e})
      elif "openrouter.ai" in self.backend.base:
        self.params.setdefault("reasoning", {"effort": e})
      else:
        self.params.setdefault("reasoning_effort", e)
    self.cap_usd = h.args.max_usd if h.args.max_usd is not None else h.cfg.get("max_usd_per_stage")
    self.usd = 0.0
    self.turns = 0
    self.max_turns = h.cfg.get("max_turns", {}).get(role, 400 if role == "main" else 150)
    self.messages = []
    self.adir = f"{h.dir}/{self.label}"
    self.tpath = f"{self.adir}/transcript.jsonl"
    self.tools = Tools(h, policy, self.adir)
    self.warned_context = False
    self.raised = set()
    self.last_call, self.repeats = None, 0
    self.record({"kind": "start", "role": role, "stage": self.stage, "backend": self.backend.name,
                 "model": self.model, "policy": policy.describe(), "system": system})

  def use(self, i):
    self.ci = i
    b, m = self.chain[i]
    self.backend, self.model = self.h.backend(b), m
    self.facts = self.h.check_model(self.role, {"backend": b, "model": m})

  def record(self, obj):
    obj = {"t": now(), **obj}
    self.h.store.append_text(self.tpath, json.dumps(obj, ensure_ascii=False) + "\n")

  def add(self, msg):
    self.messages.append(msg)
    self.record({"kind": "message", **{k: v for k, v in msg.items() if k != "raw"},
                 **({"raw": msg["raw"]} if msg.get("raw") else {})})

  def call(self):
    while True:
      try:
        return backends.complete_with_retries(
          self.backend, self.model, self.system, self.messages, tool_list(self.role), self.max_tokens, self.params,
          retries=self.h.cfg.get("retries", 5), log=lambda m: self.h.log(f"{self.label}: {m}"), stop_event=self.h.stop_event,
          cache_ttl=self.spec.get("cache_ttl"), on_wait=self.waiting)
      except backends.BackendError as e:
        r = e.response or backends.Response()
        if e.status and not e.retryable and looks_like_refusal(e):
          r.stop = "filtered"
          rec = self.h.save_stop(self, r, "HTTP error that names a refusal or filter", str(e))
          self.h.log(f"{self.label}: request refused by {self.backend.name}:{self.model}: {e}; saved {rec}")
          return r, rec
        avail = e.retryable or e.status is None
        if avail and self.ci + 1 < len(self.chain):
          self.h.log(f"{self.label}: {self.backend.name}:{self.model} unavailable ({e}); falling back")
          self.use(self.ci + 1)
          continue
        r.stop = "error"
        rec = self.h.save_stop(self, r, "backend error", str(e)) if r.request else None
        self.h.log(f"{self.label}: backend error on {self.backend.name}:{self.model}: {e}" + (f"; saved {rec}" if rec else ""))
        return r, rec

  def waiting(self, secs):
    def say(s):
      self.h.log(f"{self.label}: waiting for {self.backend.name}:{self.model}, {s} s without output "
                 f"(keep-alives only; gives up at {self.backend.idle} s)")
    return say(secs)

  def run(self, prompt):
    self.add({"role": "user", "text": prompt})
    nudged_length = False
    while not self.h.stop_event.is_set():
      if self.turns >= self.max_turns:
        return self.finish(f"stopped: turn limit {self.max_turns} reached")
      self.turns += 1
      out = self.call()
      r, rec = out if isinstance(out, tuple) else (out, None)
      usd = self.h.price(self.facts, r.usage, self.spec.get("cache_ttl")) if r.request else None
      self.usd += usd or 0
      if r.request:
        self.h.usage_row(self, r, usd)
      self.record({"kind": "response", "model": r.model, "provider": r.provider, "request_id": r.request_id,
                   "stop": r.stop, "stop_raw": r.stop_raw, "stop_details": r.stop_details, "usage": r.usage, "usd": usd})
      if r.stop == "filtered":
        if rec is None:
          rec = self.h.save_stop(self, r, "stopped by the provider (refusal or content filter)")
        self.h.log(f"{self.label}: response stopped by {self.backend.name}:{r.model or self.model} "
                   f"({r.stop_raw}{', ' + json.dumps(r.stop_details) if r.stop_details else ''}); saved {rec}")
        return self.finish(f"STOPPED by the model provider ({r.stop_raw}); record {rec}. "
                           "Never resend the stopped content, reworded or not.", stopped=True)
      if r.stop == "error":
        if rec is None and r.request:
          rec = self.h.save_stop(self, r, "response the adapter could not map (stop_raw " + repr(r.stop_raw) + ")")
          self.h.log(f"{self.label}: unusable response from {self.backend.name}:{self.model}; saved {rec}")
        return self.finish(f"stopped: backend error" + (f"; record {rec}" if rec else ""))
      self.add({"role": "assistant", "text": r.text, "tool_calls": r.tool_calls, "raw": r.raw, "api": self.backend.api})
      if r.text and self.role == "main":
        print(r.text, flush=True)
      if not r.tool_calls:
        failed = self.unresolved_failures()
        if failed:
          self.add({"role": "user", "text": "[harness] Not finished: the latest run of these commands failed and was "
                    "not followed by a successful one:\n" + failed + "\nFix the cause and rerun them, or state in your "
                    "answer that the step failed and what is missing because of it."})
          continue
        if r.stop == "length" and not nudged_length:
          nudged_length = True
          self.add({"role": "user", "text": "[harness] Your response hit the output limit. Continue where it was cut off, in smaller pieces."})
          continue
        return self.finish(r.text)
      sig = json.dumps([(c["name"], c["args"]) for c in r.tool_calls], sort_keys=True, default=str)
      self.repeats = self.repeats + 1 if sig == self.last_call else 1
      self.last_call = sig
      if self.repeats >= self.h.cfg.get("max_repeats", 8):
        self.h.log(f"{self.label}: the same tool call {self.repeats} times in a row; stopped")
        return self.finish(f"stopped: repeated the same tool call {self.repeats} times in a row "
                           "(a loop); its progress file shows where it was")
      results = self.execute(r.tool_calls, truncated=(r.stop == "length"))
      if self.repeats >= 3:
        results[-1]["content"] = (f"[harness] You have made this exact call {self.repeats} times in a row and the "
                                  "result does not change. Do something else: read the surrounding lines with "
                                  "read_file and an offset, search for a different name, or write down what you "
                                  "have in your progress file and finish.\n\n" + results[-1]["content"])
        self.h.log(f"{self.label}: same tool call {self.repeats} times in a row; told it to change approach")
      note = self.limits_note(r)
      if note:
        results[-1]["content"] += "\n\n" + note
      self.add({"role": "tool", "results": results})
      if self.cap_usd is not None and self.usd >= self.cap_usd:
        return self.finish(f"stopped: cost cap {self.cap_usd} USD reached ({self.usd:.2f})")
      ctx = self.facts["context"]
      used = r.usage["input"] + r.usage["cache_read"] + r.usage["cache_write"] + r.usage["output"]
      if used > 0.95 * ctx:
        return self.finish(f"stopped: context nearly full ({used} of {ctx} tokens); resume in a new session "
                           "from the progress files (workflow.md Checkpoints)")
    return self.finish("stopped by the user")

  def unresolved_failures(self):
    # each failure is raised once: a model that answers again after the note may finish
    out = []
    for s, (code, last, args) in self.tools.last_exit.items():
      if code and (s, tuple(args)) not in self.raised:
        self.raised.add((s, tuple(args)))
        out.append(f"- ./cupella {s} {' '.join(args)}: exit {code}: {last[:300]}")
    return "\n".join(out)

  def limits_note(self, r):
    used = r.usage["input"] + r.usage["cache_read"] + r.usage["cache_write"] + r.usage["output"]
    if not self.warned_context and used > 0.8 * self.facts["context"]:
      self.warned_context = True
      return ("[harness] The context is 80% full. Write your current state to your progress file now; "
              "the session stops at 95% and a new one resumes from the progress files.")
    return None

  def finish(self, text, stopped=False):
    self.record({"kind": "finish", "text": text, "usd": self.usd, "turns": self.turns, "stopped": stopped})
    if self.role != "main":
      self.h.log(f"{self.label}: finished after {self.turns} turns, {self.usd:.2f} USD", quiet=True)
    return text

  def execute(self, calls, truncated=False):
    results = [None] * len(calls)
    spawns = []
    for i, c in enumerate(calls):
      if c["args"] is None and not truncated:
        fixed = repair.repair_json(c.get("raw_args"))
        if fixed is not None:
          # the repaired form is what the history replays to the API
          c["args"], c["raw_args"] = fixed, json.dumps(fixed)
          for m in reversed(self.messages):
            if m["role"] == "assistant":
              for b in m.get("raw") or []:
                if b.get("type") == "tool_use" and b.get("id") == c["id"]:
                  b["input"] = fixed
              break
          c["repaired"] = "arguments were not valid JSON; parsed them leniently"
      if c["args"] is None:
        why = ("the response was cut off at the output limit, so this call is incomplete; write smaller pieces"
               if truncated else "arguments are not valid JSON: send them again as one JSON object")
        results[i] = {"id": c["id"], "content": f"error: {why}", "is_error": True}
      elif c["name"] == "spawn" and self.role == "main":
        spawns.append(i)
      else:
        results[i] = self.run_tool(c)
    if spawns:
      ex = concurrent.futures.ThreadPoolExecutor(max_workers=self.h.cfg.get("max_parallel", 4))
      try:
        futs = {ex.submit(self.spawn, calls[i]["args"]): i for i in spawns}
        for fu in concurrent.futures.as_completed(futs):
          i = futs[fu]
          try:
            results[i] = {"id": calls[i]["id"], "content": fu.result(), "is_error": False}
          except (ToolError, pol.PolicyError, SystemExit) as e:
            results[i] = {"id": calls[i]["id"], "content": f"error: {e}", "is_error": True}
          except Exception as e:  # noqa: BLE001 - a subagent's crash must not end the session
            self.h.log(f"{self.label}: subagent crashed: {e!r}\n{traceback.format_exc()}", quiet=True)
            results[i] = {"id": calls[i]["id"], "content": f"error: the subagent failed in the harness ({e!r}); "
                          "its progress and claim files show what it did", "is_error": True}
      finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

  def run_tool(self, c):
    t0 = time.time()
    if c["name"] == "run" and isinstance(c.get("args"), dict):
      # a script can take minutes (unpack.sh, native-decompile.sh): say so when it starts
      a = c["args"]
      self.h.log(f"{self.label}: running ./cupella {a.get('script', '?')} {' '.join(map(str, a.get('args') or []))}"[:300],
                 quiet=self.role != "main")
    notes = [c["repaired"]] if c.get("repaired") else []
    try:
      out, err = self.tools.call(c["name"], c["args"], notes), False
    except ToolError as e:
      out, err = f"error: {e}", True
      if notes:
        out = "[harness repaired: " + "; ".join(notes) + "]\n" + out
      if str(e).startswith("denied"):
        self.h.log(f"{self.label}: {c['name']} denied: {e}", quiet=self.role != "main")
    except Exception as e:  # noqa: BLE001 - a harness bug must not end the session
      self.h.log(f"{self.label}: harness error in {c['name']}: {e!r}\n{traceback.format_exc()}", quiet=True)
      out, err = f"error: the harness failed on this call ({e!r}); try another way", True
    if notes:
      self.h.log(f"{self.label}: repaired {c['name']}: {'; '.join(notes)}")
    summary = {k: (v if not isinstance(v, str) or len(v) < 200 else f"<{len(v)} chars>") for k, v in (c["args"] or {}).items()}
    self.h.log(f"{self.label}: {c['name']} {json.dumps(summary)[:300]} ({time.time() - t0:.1f} s{', error' if err else ''})")
    return {"id": c["id"], "content": out, "is_error": err}

  def spawn(self, a):
    stage = (a.get("stage") or "").strip()
    prompt, role, samples, read, write = fill_stage(self.h.ws, stage, a)
    p = pol.sub_policy(self.h.ws, self.h.root, role, samples, read, write, store=self.h.store)
    p.since, p.resume = self.h.started, self.h.args.resume
    override = a.get("model")
    if override and override not in self.h.cfg.get("spawn_allowed", []):
      self.h.log(f"{self.label}: spawn model {override} not in spawn_allowed; using the configured one")
      override = None
    tools_line = ", ".join(ROLE_TOOLS[role])
    system = (pol.role_body(self.h.root, role) + "\n\n## Harness\n\n"
              f"Your tools: {tools_line}. Where the instructions say Read, Grep, Glob, Write, use read_file, grep, "
              "list_dir, write_file; append_file adds a line to a progress file; `./cupella <script> <args>` is "
              "run(script, args). Paths are relative to the repository root. The harness enforces these limits; "
              "a denied call returns an error.\n" + p.describe())
    sub = Agent(self.h, role, stage, p, system, override, parent=self)
    self.h.log(f"{self.label}: spawned {sub.label} ({role}, {sub.backend.name}:{sub.model}, samples {', '.join(p.samples)})")
    text = sub.run(prompt)
    self.h.log(f"{self.label}: {sub.label} returned ({len(text)} chars, {sub.usd:.2f} USD)")
    return f"[{sub.label}, {role}, {sub.backend.name}:{sub.model}, {sub.turns} turns]\n" + text[:8000]


# Stages whose prompt template the harness fills itself, with the role, samples, and
# files each gets. The main agent passes the placeholder values; it cannot shorten the
# template (a model that paraphrased them dropped the claim and verdict schemas).
STAGES = {
  "read-area": {"role": "reader", "samples": ["{NAME}", "{REPORT}"], "read": [],
                "write": ["work/{REPORT}/progress/{ROLE}.md", "work/{REPORT}/progress/{ROLE}-claims/"]},
  "verify-report": {"role": "reader", "samples": ["{NAME}"], "read": ["reports/{NAME}.md", "reports/{NAME}/"],
                    "write": ["work/{NAME}/progress/verify.md", "work/{NAME}/progress/verify-verdicts/",
                              "work/{NAME}/verification.md"]},
  "decrypt": {"role": "decryptor", "samples": ["{APP}"], "read": [], "write": []},
}
PLACEHOLDER = re.compile(r"\{([A-Z][A-Z_]*)\}")


def fill_stage(ws, stage, a):
  # -> (prompt, role, samples, read, write) for a spawn call
  path = os.path.join(ws, "prompts", f"{stage}.md")
  if not re.fullmatch(r"[a-z0-9-]+", stage or "") or not os.path.isfile(path):
    if not a.get("prompt") or not a.get("role"):
      raise ToolError(f"stage {stage!r} has no template in prompts/ (templates: "
                      f"{', '.join(sorted(STAGES))}); for another stage give role and prompt")
    return a["prompt"], a["role"], a.get("samples") or [], a.get("read") or [], a.get("write") or []
  text = open(path, encoding="utf-8").read()
  m = re.match(r"\s*<!--(.*?)-->\s*", text, re.S)
  guide, body = (m.group(1).strip(), text[m.end():]) if m else ("", text)
  vals = {str(k).strip("{} ").upper(): str(v) for k, v in (a.get("vars") or {}).items()}
  st = STAGES.get(stage, {})
  if "REPORT" in PLACEHOLDER.findall(body) and "REPORT" not in vals and "NAME" in vals:
    vals["REPORT"] = vals["NAME"]
  need = sorted(set(PLACEHOLDER.findall(body)) | {x for t in st.get("samples", []) + st.get("write", [])
                                                 for x in PLACEHOLDER.findall(t)})
  missing = [n for n in need if not vals.get(n)]
  if missing:
    raise ToolError(f"stage {stage} needs vars {', '.join(missing)} (all: {', '.join(need)}). "
                    f"From the template's header: {guide}")
  for n in ("NAME", "REPORT", "APP"):
    if n in vals and not pol.sample_ok(vals[n]):
      raise ToolError(f"{n} {vals[n]!r} is not a sample name")
  if "ROLE" in vals and not re.fullmatch(r"[a-z0-9-]+", vals["ROLE"]):
    raise ToolError(f"ROLE {vals['ROLE']!r}: a short slug such as reader-c2")
  fill = lambda t: PLACEHOLDER.sub(lambda mm: vals.get(mm.group(1), mm.group(0)), t)  # noqa: E731
  prompt = fill(body).strip()
  if a.get("extra"):
    prompt += "\n\nNotes from the main agent:\n" + str(a["extra"]).strip()
  role = st.get("role") or a.get("role") or "reader"
  samples = list(dict.fromkeys([fill(s) for s in st.get("samples", [])] + list(a.get("samples") or [])))
  read = [fill(x) for x in st.get("read", [])] + list(a.get("read") or [])
  write = [fill(x) for x in st.get("write", [])] + list(a.get("write") or [])
  return prompt, role, samples, read, write


def main_system(h):
  parts = [open(os.path.join(h.ws, "AGENTS.md"), encoding="utf-8").read()]
  if os.path.exists(os.path.join(h.ws, "WORKSPACE.md")):
    parts.append(open(os.path.join(h.ws, "WORKSPACE.md"), encoding="utf-8").read())
  # the stage order and finishing checklist, in full: a model that reads the file
  # itself may stop partway and skip stages
  parts.append("# agent_docs/workflow.md (loaded in full; do not read it again)\n\n"
               + open(os.path.join(h.ws, "agent_docs", "workflow.md"), encoding="utf-8").read())
  p = pol.main_policy(h.ws, h.root, h.store)
  p.since, p.resume = h.started, h.args.resume
  models = {r: f"{h.spec(r)['backend']}:{h.spec(r)['model']}" for r in ("main", "reader", "decryptor")}
  parts.append(
    "## Harness\n\nThis session runs in the Cupella API harness (agent_docs/harness-api.md), not Claude Code.\n"
    "- Tools: read_file, grep, list_dir, write_file, edit_file, append_file, run, spawn. Where the docs say Read, "
    "Grep, Glob, Write, Edit, use those. There is no shell: `./cupella <script> <args>` is run(script, args); "
    "for `> file`, pass stdout_to.\n"
    "- Subagent stages: spawn(stage, vars, extra). The harness fills prompts/<stage>.md with vars (the template's "
    "placeholders without braces, e.g. {\"NAME\": ..., \"ROLE\": \"reader-c2\", \"AREA\": ..., \"STARTS\": ...}) and "
    "gives the agent its role, samples, and output files; never retell a template. extra adds notes. Several spawn "
    "calls in one response run in parallel.\n"
    "- To show the user a markdown file (a report, \"show the report\"), run(\"md-view.py\", [\"reports/<name>.md\"]): "
    "the harness renders it on the user's terminal and does not return it to you. Reports written before this "
    "session are listed but not readable; md-view.py still shows them to the user.\n"
    "- A response stopped by the provider ends that agent; the harness saves it under work/_stops/ (never read "
    "there) and tells you. Never resend the stopped content.\n"
    f"- Session {h.session}. Tokens and cost per response: work/_harness/{h.session}/usage.tsv; cite it in the "
    f"report's \"Agent setup\". Models: " + ", ".join(f"{k} {v}" for k, v in models.items()) + ".\n"
    + p.describe())
  return "\n\n".join(parts), p


def load_config(ws, root, path):
  for c in ([path] if path else [os.path.join(ws, "harness.json"), os.path.join(root, "harness", "models.json")]):
    if c and os.path.exists(c):
      with open(c) as f:
        return json.load(f), c
  raise SystemExit("no harness configuration: copy harness/models.example.json to harness/models.json "
                   "(or harness.json in a workspace) and edit it")


def main():
  ap = argparse.ArgumentParser(prog="./cupella agent", description="Cupella agent harness on a model API")
  ap.add_argument("request", nargs="*")
  ap.add_argument("--resume", metavar="NAME")
  ap.add_argument("--chat", "-i", action="store_true", help="ask for follow-ups in the same session")
  ap.add_argument("--once", action="store_true", help=argparse.SUPPRESS)  # the default now; kept for scripts
  ap.add_argument("--check", action="store_true")
  ap.add_argument("--model")
  ap.add_argument("--role-model", action="append")
  ap.add_argument("--stage-model", action="append")
  ap.add_argument("--max-usd", type=float)
  ap.add_argument("--config")
  args = ap.parse_args()
  ws = os.environ.get("CUPELLA_WS") or sys.exit("run as ./cupella agent")
  root = os.environ.get("CUPELLA_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  cfg, cpath = load_config(ws, root, args.config)
  h = Harness(ws, root, cfg, args)
  if args.check:
    for role in ("main", "reader", "decryptor"):
      c = h.spec(role)
      f = h.check_model(role, c)
      print(f"{role}: {c['backend']}:{c['model']} context {f['context']} tools {f['tools']} price {f.get('usd_per_mtok', 'unknown')}")
    for st in cfg.get("stages", {}):
      c = h.spec("reader" if st != "decrypt" else "decryptor", st)
      print(f"stage {st}: {c['backend']}:{c['model']}")
    h.store.close()
    return
  if args.resume:
    if not pol.sample_ok(args.resume):
      sys.exit(f"bad name {args.resume!r}")
    request = (f"Resume the unfinished analysis of {args.resume}: read work/{args.resume}/progress/main.md and "
               "the other checkpoint files (agent_docs/workflow.md \"Checkpoints\") and continue from there.")
  else:
    request = " ".join(args.request).strip()
  if not request:
    ap.error("give a request, --resume NAME, or --check")
  h.open_session()
  system, p = main_system(h)
  h.log(f"session {h.session}, config {os.path.relpath(cpath, ws) if cpath.startswith(ws) else cpath}, "
        f"transcripts in {h.dir}/" + (" (in the work volume)" if h.store.mode == "volume" else ""))
  agent = Agent(h, "main", None, p, system)
  h.log(f"main: {agent.backend.name}:{agent.model}")
  failed = False
  try:
    text = agent.run(request)
    while True:
      if text.startswith(("stopped", "STOPPED")):
        print(f"{time.strftime('%H:%M:%SZ', time.gmtime())} [harness] {text}", file=sys.stderr)
      if not args.chat or args.once or not sys.stdin.isatty():
        if not args.chat and h.report_names and sys.stdin.isatty():
          h.log("a later session cannot read this report (earlier files are not read); to ask about it, "
                "run the analysis with --chat, which keeps the session open for follow-ups")
        break
      try:
        # --chat: the session stays open for follow-ups in the same context
        more = input("\nFollow-up (Enter or Ctrl-D to end the session): ").strip()
      except EOFError:
        print()
        break
      if not more:
        break
      text = agent.run(more)
  except Exception as e:  # noqa: BLE001 - keep what was written, say how to go on
    h.log(f"harness error: {e!r}\n{traceback.format_exc()}")
    h.log("the session's files are kept; continue with ./cupella agent --resume <name>")
    failed = True
  except KeyboardInterrupt:
    h.stop_event.set()
    h.log(f"interrupted by the user; {h.total_usd:.2f} USD so far; resume with ./cupella agent --resume <name>")
    try:
      write_costs(h)
    except Exception as e:  # noqa: BLE001
      h.log(f"cost record failed: {e!r}")
    where_reports(h)
    os._exit(130)  # subagent threads may be blocked in a request
  try:
    write_costs(h)
  except Exception as e:  # noqa: BLE001
    h.log(f"cost record failed: {e!r}")
  h.log(f"done: main {agent.turns} turns, {h.total_usd:.2f} USD for all agents; usage per response in "
        f"{h.dir}/usage.tsv")
  where_reports(h)
  h.store.close()
  if failed:
    sys.exit(1)


def where_reports(h):
  # the reports this session wrote, as host paths; in volume mode also how to reach the
  # work/ files they cite, which are not on the host
  shown = [n for n in sorted(h.report_names) if os.path.isfile(os.path.join(h.ws, "reports", n + ".md"))]
  for n in shown:
    h.log(f"report: {os.path.join(h.ws, 'reports', n + '.md')}"
          + (f" (data: reports/{n}.json, sources: reports/{n}/)" if os.path.isdir(os.path.join(h.ws, "reports", n)) else "")
          + f"; to read it: cd {h.ws} && ./cupella md-view.py reports/{n}.md")
  if shown and h.store.mode == "volume":
    h.log(f"the work/ paths the report cites are in the work volume, not on the host: copy them out with "
          f"`cd {h.ws} && ./cupella export {shown[0]} work/{shown[0]}/triage.txt ...` (to exports/{shown[0]}/), "
          f"or look with ./cupella shell")


if __name__ == "__main__":
  main()
