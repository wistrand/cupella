# Backend adapters for the Cupella harness. The loop works on one internal form; an
# adapter turns it into one API's request and parses that API's streamed response.
#
# Internal messages:
#   {"role": "user", "text": str}
#   {"role": "assistant", "text": str, "tool_calls": [{"id", "name", "args", "raw_args"}],
#    "raw": <the API's own assistant content, replayed to the same API>, "api": str}
#   {"role": "tool", "results": [{"id", "content", "is_error"}]}
#
# Every response is streamed, and every streamed line is kept with the request body and
# the response headers, so a stopped response can be saved with the text produced
# before the stop (agent.py writes it to work/_stops/).
import json
import socket
import time
import urllib.error
import urllib.request

RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class BackendError(Exception):
  def __init__(self, msg, retryable=False, status=None, body=""):
    super().__init__(msg)
    self.retryable, self.status, self.body = retryable, status, body
    self.response = None


class Response:
  def __init__(self):
    self.text = ""
    self.refusal = ""
    self.tool_calls = []
    self.raw = None
    self.stop = "error"        # done, tool_calls, length, filtered, error
    self.stop_raw = None       # the API's own stop reason
    self.stop_details = None
    self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost": None}
    self.model = None
    self.provider = None
    self.request_id = None
    self.request = None        # the request body as sent
    self.headers = {}
    self.lines = []            # every streamed line
    self.on_wait = None        # called once a minute while only keep-alives arrive


def sse(resp, lines, idle=180, deadline=1800, on_wait=None):
  # idle: seconds without a data line (keep-alive comments do not count); deadline: for
  # the whole response. Either raises a retryable error instead of waiting forever.
  event, data = None, []
  t0 = last = time.time()
  said = 0
  for raw in resp:
    line = raw.decode("utf-8", "replace").rstrip("\r\n")
    lines.append(line)
    t = time.time()
    if line and not line.startswith(":"):
      last, said = t, 0
    elif on_wait and int(t - last) // 60 > said:
      said = int(t - last) // 60
      on_wait(int(t - last))
    if t - last > idle:
      raise BackendError(f"no data from the backend for {idle} s (keep-alives only)", True)
    if t - t0 > deadline:
      raise BackendError(f"response took longer than {deadline} s", True)
    if line == "":
      if data:
        yield event, "\n".join(data)
      event, data = None, []
    elif line.startswith(":"):
      continue
    elif line.startswith("event:"):
      event = line[6:].strip()
    elif line.startswith("data:"):
      data.append(line[5:].lstrip())
  if data:
    yield event, "\n".join(data)


class Backend:
  api = None

  def __init__(self, name, cfg, key):
    self.name, self.cfg, self.key = name, cfg, key
    self.base = cfg["base_url"].rstrip("/")
    self.idle = cfg.get("idle_timeout", 180)          # no data line, keep-alives aside
    self.timeout = cfg.get("timeout", self.idle)      # socket read timeout: no bytes at all
    self.deadline = cfg.get("response_timeout", 1800)

  def post(self, path, body, headers, r):
    r.request = body
    req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", "accept": "text/event-stream", **headers})
    try:
      resp = urllib.request.urlopen(req, timeout=self.timeout)
    except urllib.error.HTTPError as e:
      text = e.read().decode("utf-8", "replace")[:20000]
      r.headers = {k.lower(): v for k, v in e.headers.items() if k.lower() != "set-cookie"}
      r.lines = text.splitlines()
      raise BackendError(f"HTTP {e.code}: {text[:500]}", e.code in RETRY_STATUS, e.code, text)
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
      raise BackendError(f"connection failed: {e}", True)
    r.headers = {k.lower(): v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
    return resp

  def complete(self, model, system, messages, tools, max_tokens, params, cache_ttl=None, on_wait=None):
    r = Response()
    r.on_wait = on_wait
    self.eph = {"type": "ephemeral", **({"ttl": cache_ttl} if cache_ttl else {})}
    try:
      return self._complete(r, model, system, messages, tools, max_tokens, params)
    except BackendError as e:
      e.response = r
      raise
    except (OSError, ValueError) as e:  # a stream cut off midway
      err = BackendError(f"stream failed: {e}", True)
      err.response = r
      raise err

  def get_json(self, path):
    req = urllib.request.Request(self.base + path, headers=self.auth())
    with urllib.request.urlopen(req, timeout=60) as resp:
      return json.load(resp)


def tool_args(raw):
  try:
    v = json.loads(raw or "{}")
    return v if isinstance(v, dict) else None
  except ValueError:
    return None


class ChatBackend(Backend):
  # OpenAI-style chat completions: OpenRouter, OpenAI, vLLM, llama.cpp, Ollama, LM Studio
  api = "chat"

  def auth(self):
    return {"authorization": f"Bearer {self.key}"} if self.key else {}

  def build(self, model, system, messages, tools, max_tokens, params):
    cache = self.cfg.get("cache_control", False)
    eph = getattr(self, "eph", {"type": "ephemeral"})
    msgs = [{"role": "system", "content": [{"type": "text", "text": system, "cache_control": eph}] if cache else system}]
    for m in messages:
      if m["role"] == "user":
        msgs.append({"role": "user", "content": m["text"]})
      elif m["role"] == "assistant":
        a = {"role": "assistant", "content": m.get("text") or None}
        if m.get("tool_calls"):
          a["tool_calls"] = [{"id": c["id"], "type": "function", "function": {
            "name": c["name"], "arguments": c["raw_args"] if tool_args(c.get("raw_args")) is not None
            else json.dumps(c.get("args") or {})}} for c in m["tool_calls"]]
        msgs.append(a)
      else:
        for t in m["results"]:
          msgs.append({"role": "tool", "tool_call_id": t["id"], "content": t["content"]})
    if cache and msgs[-1]["role"] in ("user", "tool") and isinstance(msgs[-1]["content"], str):
      msgs[-1] = dict(msgs[-1], content=[{"type": "text", "text": msgs[-1]["content"], "cache_control": eph}])
    body = {"model": model, "messages": msgs, "stream": True, "stream_options": {"include_usage": True},
            self.cfg.get("max_tokens_param", "max_tokens"): max_tokens}
    if tools:
      body["tools"] = [{"type": "function", "function": {"name": n, **s}} for n, s in tools]
    body.update(self.cfg.get("params", {}))
    body.update(params)
    return body

  def _complete(self, r, model, system, messages, tools, max_tokens, params):
    resp = self.post("/chat/completions", self.build(model, system, messages, tools, max_tokens, params), self.auth(), r)
    calls, finish = {}, None
    r.request_id = r.headers.get("x-request-id") or r.headers.get("x-generation-id")
    with resp:
      for _, data in sse(resp, r.lines, self.idle, self.deadline, r.on_wait):
        if data == "[DONE]":
          break
        try:
          o = json.loads(data)
        except ValueError:
          continue
        if o.get("error"):
          e = o["error"]
          msg = e.get("message", str(e)) if isinstance(e, dict) else str(e)
          code = e.get("code") if isinstance(e, dict) else None
          raise BackendError(f"stream error: {msg}", code in RETRY_STATUS or code in (None, "server_error"), code, data)
        r.model = o.get("model") or r.model
        r.provider = o.get("provider") or r.provider
        r.request_id = r.request_id or o.get("id")
        for ch in o.get("choices") or []:
          d = ch.get("delta") or {}
          r.text += d.get("content") or ""
          r.refusal += d.get("refusal") or ""
          for tc in d.get("tool_calls") or []:
            c = calls.setdefault(tc.get("index", 0), {"id": None, "name": "", "raw_args": ""})
            c["id"] = tc.get("id") or c["id"]
            f = tc.get("function") or {}
            c["name"] += f.get("name") or ""
            c["raw_args"] += f.get("arguments") or ""
          finish = ch.get("finish_reason") or finish
          if ch.get("native_finish_reason") in ("refusal", "content_filter", "SAFETY"):
            r.stop_details = {"native_finish_reason": ch["native_finish_reason"]}
        u = o.get("usage")
        if u:
          det = u.get("prompt_tokens_details") or {}
          cached, written = det.get("cached_tokens") or 0, det.get("cache_write_tokens") or 0
          r.usage.update(input=(u.get("prompt_tokens") or 0) - cached - written, output=u.get("completion_tokens") or 0,
                         cache_read=cached, cache_write=written, cost=u.get("cost"))
    r.tool_calls = [{"id": c["id"] or f"call_{i}", "name": c["name"], "raw_args": c["raw_args"],
                     "args": tool_args(c["raw_args"])} for i, c in sorted(calls.items())]
    r.stop_raw = finish
    if finish == "error" or (finish is None and not r.text and not calls and not r.refusal):
      # an upstream failure reported inside a 200 stream (OpenRouter: finish_reason
      # "error", no tokens): transient, so retried like an HTTP 5xx
      raise BackendError(f"backend reported finish_reason {finish!r} with no output", True)
    if finish == "content_filter" or r.stop_details or (r.refusal and not r.tool_calls):
      r.stop = "filtered"
    elif finish == "length":
      r.stop = "length"
    elif r.tool_calls:
      r.stop = "tool_calls"
    elif finish in ("stop", "end_turn", None) and (r.text or finish):
      r.stop = "done"
    else:
      r.stop = "error"
    r.raw = None
    return r


class MessagesBackend(Backend):
  # Anthropic Messages API
  api = "messages"

  def auth(self):
    return {"x-api-key": self.key or "", "anthropic-version": self.cfg.get("version", "2023-06-01")}

  def build(self, model, system, messages, tools, max_tokens, params):
    eph = getattr(self, "eph", {"type": "ephemeral"})
    msgs = []
    for m in messages:
      if m["role"] == "user":
        role, content = "user", [{"type": "text", "text": m["text"]}]
      elif m["role"] == "assistant":
        role = "assistant"
        if m.get("api") == self.api and m.get("raw"):
          content = m["raw"]
        else:
          content = ([{"type": "text", "text": m["text"]}] if m.get("text") else []) + [
            {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"] or {}} for c in m.get("tool_calls", [])]
      else:
        role, content = "user", [{"type": "tool_result", "tool_use_id": t["id"], "content": t["content"],
                                  "is_error": bool(t.get("is_error"))} for t in m["results"]]
      if msgs and msgs[-1]["role"] == role:
        msgs[-1]["content"] = msgs[-1]["content"] + content
      else:
        msgs.append({"role": role, "content": list(content)})
    if msgs and msgs[-1]["content"]:
      last = msgs[-1]["content"]
      msgs[-1] = {"role": msgs[-1]["role"], "content": last[:-1] + [dict(last[-1], cache_control=eph)]}
    body = {"model": model, "max_tokens": max_tokens, "stream": True,
            "system": [{"type": "text", "text": system, "cache_control": eph}], "messages": msgs}
    if tools:
      body["tools"] = [{"name": n, "description": s["description"], "input_schema": s["parameters"]} for n, s in tools]
    body.update(self.cfg.get("params", {}))
    body.update(params)
    return body

  def _complete(self, r, model, system, messages, tools, max_tokens, params):
    resp = self.post("/messages", self.build(model, system, messages, tools, max_tokens, params), self.auth(), r)
    r.request_id = r.headers.get("request-id")
    blocks, partial = {}, {}
    with resp:
      for ev, data in sse(resp, r.lines, self.idle, self.deadline, r.on_wait):
        try:
          o = json.loads(data)
        except ValueError:
          continue
        t = o.get("type") or ev
        if t == "message_start":
          m = o.get("message") or {}
          r.model, r.request_id = m.get("model"), r.request_id or m.get("id")
          u = m.get("usage") or {}
          r.usage.update(input=u.get("input_tokens") or 0, cache_read=u.get("cache_read_input_tokens") or 0,
                         cache_write=u.get("cache_creation_input_tokens") or 0, output=u.get("output_tokens") or 0)
        elif t == "content_block_start":
          blocks[o["index"]] = dict(o.get("content_block") or {})
        elif t == "content_block_delta":
          b, d = blocks.setdefault(o["index"], {"type": "text", "text": ""}), o.get("delta") or {}
          dt = d.get("type")
          if dt == "text_delta":
            b["text"] = b.get("text", "") + d.get("text", "")
          elif dt == "input_json_delta":
            partial[o["index"]] = partial.get(o["index"], "") + d.get("partial_json", "")
          elif dt == "thinking_delta":
            b["thinking"] = b.get("thinking", "") + d.get("thinking", "")
          elif dt == "signature_delta":
            b["signature"] = d.get("signature")
        elif t == "content_block_stop":
          i = o["index"]
          if blocks.get(i, {}).get("type") == "tool_use":
            blocks[i]["_raw"] = partial.get(i, "")
        elif t == "message_delta":
          d = o.get("delta") or {}
          r.stop_raw = d.get("stop_reason") or r.stop_raw
          r.stop_details = d.get("stop_details") or r.stop_details
          if (o.get("usage") or {}).get("output_tokens") is not None:
            r.usage["output"] = o["usage"]["output_tokens"]
        elif t == "error":
          e = o.get("error") or {}
          retry = e.get("type") in ("overloaded_error", "api_error", "rate_limit_error")
          raise BackendError(f"stream error: {e.get('type')}: {e.get('message')}", retry, e.get("type"), data)
    raw = []
    for i in sorted(blocks):
      b = blocks[i]
      if b.get("type") == "tool_use":
        rawargs = b.pop("_raw", partial.get(i, ""))
        b["input"] = tool_args(rawargs) if rawargs else (b.get("input") or {})
        r.tool_calls.append({"id": b.get("id"), "name": b.get("name"), "raw_args": rawargs, "args": b["input"]})
        if b["input"] is None:
          b["input"] = {}
      elif b.get("type") == "text":
        r.text += b.get("text", "")
      raw.append(b)
    r.raw = raw
    r.stop = {"end_turn": "done", "stop_sequence": "done", "tool_use": "tool_calls", "max_tokens": "length",
              "refusal": "filtered", "pause_turn": "done"}.get(r.stop_raw, "error")
    if r.stop == "done" and r.tool_calls:
      r.stop = "tool_calls"
    return r


ADAPTERS = {"chat": ChatBackend, "messages": MessagesBackend}


def make(name, cfg, key):
  api = cfg.get("api", "chat")
  if api not in ADAPTERS:
    raise BackendError(f"backend {name}: api {api!r} is not built yet (chat, messages)")
  return ADAPTERS[api](name, cfg, key)


def complete_with_retries(backend, *args, retries=5, log=None, stop_event=None, cache_ttl=None, on_wait=None):
  delay = 2
  for attempt in range(retries + 1):
    try:
      return backend.complete(*args, cache_ttl=cache_ttl, on_wait=on_wait)
    except BackendError as e:
      if not e.retryable or attempt == retries or (stop_event and stop_event.is_set()):
        raise
      if log:
        log(f"{backend.name}: {e}; retry {attempt + 1}/{retries} in {delay} s")
      time.sleep(delay)
      delay = min(delay * 2, 60)
