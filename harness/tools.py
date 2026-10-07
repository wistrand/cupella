# Tool implementations for the Cupella harness. Every tool goes through the agent's
# Policy; a denied call returns an error result to the model and is logged. There is
# no shell: `run` executes ./cupella with an argument list. Files are reached through
# the policy's store (harness/store.py), so the tools work the same on host directories
# and on Docker volumes.
import fnmatch
import inspect
import json
import re
import shutil
import subprocess
import sys
import time

import repair
from policy import DENY_WRITE, PolicyError, matches

TOOL_SPECS = {
  "read_file": {
    "description": "Read a text file. Returns numbered lines. Use offset and limit for large files.",
    "parameters": {"type": "object", "properties": {
      "path": {"type": "string", "description": "path relative to the working directory"},
      "offset": {"type": "integer", "description": "first line, 1-based"},
      "limit": {"type": "integer", "description": "number of lines (default 2000)"}},
      "required": ["path"]}},
  "grep": {
    "description": "Search text files under one directory (or one file) with a Python regular expression. Returns path:line: text.",
    "parameters": {"type": "object", "properties": {
      "pattern": {"type": "string"},
      "path": {"type": "string", "description": "directory or file to search; keep it narrow"},
      "glob": {"type": "string", "description": "only files whose name (or relative path, if it holds '/') matches, e.g. *.java"},
      "ignore_case": {"type": "boolean"},
      "max_hits": {"type": "integer", "description": "default 200"}},
      "required": ["pattern", "path"]}},
  "list_dir": {
    "description": "List names in a directory (directories end in /), or the paths matching a glob below it (** for any depth).",
    "parameters": {"type": "object", "properties": {
      "path": {"type": "string"}, "glob": {"type": "string"}}, "required": ["path"]}},
  "write_file": {
    "description": "Create or replace one file.",
    "parameters": {"type": "object", "properties": {
      "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
  "edit_file": {
    "description": "Replace one exact string in a file. old must occur exactly once unless replace_all is true.",
    "parameters": {"type": "object", "properties": {
      "path": {"type": "string"}, "old": {"type": "string"}, "new": {"type": "string"},
      "replace_all": {"type": "boolean"}}, "required": ["path", "old", "new"]}},
  "append_file": {
    "description": "Append text to a file (a progress file, one line per step). A newline is added if missing.",
    "parameters": {"type": "object", "properties": {
      "path": {"type": "string"}, "text": {"type": "string"}}, "required": ["path", "text"]}},
  "run": {
    "description": "Run `./cupella <script> <args...>`: a Cupella script or command, as an argument list, no shell.",
    "parameters": {"type": "object", "properties": {
      "script": {"type": "string", "description": "e.g. unpack.sh, scan.sh, cite-check.py, check"},
      "args": {"type": "array", "items": {"type": "string"}},
      "stdout_to": {"type": "string", "description": "rarely needed: only for large output to keep as a file under work/<name>/ (apk-diff.py); normally omit it and read the output in the result"}},
      "required": ["script"]}},
  "spawn": {
    "description": ("Start a subagent for a stage in a fresh context; returns its final message. The harness fills "
                    "prompts/<stage>.md with vars and sets the role, samples, and output files. Several spawn calls "
                    "in one response run in parallel."),
    "parameters": {"type": "object", "properties": {
      "stage": {"type": "string", "description": "read-area, verify-report, or decrypt"},
      "vars": {"type": "object", "description": "the template's placeholders without braces: read-area NAME, REPORT, ROLE, AREA, STARTS; verify-report NAME; decrypt APP"},
      "extra": {"type": "string", "description": "optional notes appended to the filled template"},
      "samples": {"type": "array", "items": {"type": "string"}, "description": "optional: more samples the agent may read"},
      "read": {"type": "array", "items": {"type": "string"}, "description": "optional: more read paths under work/<sample> or reports/<sample>"},
      "write": {"type": "array", "items": {"type": "string"}, "description": "optional: more files a reader may write"},
      "role": {"type": "string", "enum": ["reader", "decryptor"], "description": "only for a stage without a template"},
      "prompt": {"type": "string", "description": "only for a stage without a template"},
      "model": {"type": "string", "description": "optional backend:model, only one the configuration allows"}},
      "required": ["stage"]}},
}

ROLE_TOOLS = {
  "main": ["read_file", "grep", "list_dir", "write_file", "edit_file", "append_file", "run", "spawn"],
  "reader": ["read_file", "grep", "list_dir", "write_file", "append_file"],
  "decryptor": ["read_file", "grep", "list_dir", "write_file", "edit_file", "append_file", "run"],
}


class ToolError(Exception):
  pass


EARLIER = ("  [written before this session: not readable (AGENTS.md Invariants); "
           "run md-view.py on it to show it to the user]")


class Tools:
  def __init__(self, h, policy, sess_dir):
    self.h = h  # the Harness: configuration, cupella path, clean environment
    self.p = policy
    self.st = policy.store
    self.sess_dir = sess_dir  # relative to the workspace: work/_harness/<session>/<agent>
    self.cap = h.cfg.get("tool_result_chars", 30000)
    self.n_runs = 0
    self.last_exit = {}  # script -> (exit code, last output line) of its latest run

  def call(self, name, args, notes=None):
    # notes collects the repairs made to this call; they head the result
    notes = [] if notes is None else notes
    valid = ROLE_TOOLS[self.p.role]
    name, args = repair.normalize(name, args, valid + ["bash"], notes)
    if name == "bash":
      a = repair.bash_to_run(args.get("command", ""), notes) if "run" in valid else None
      if a is None:
        raise ToolError("there is no shell. Use read_file, grep, list_dir, and the write tools"
                        + (", and run(script, args) for ./cupella" if "run" in valid else ""))
      name, args = "run", a
    if name not in valid:
      raise ToolError(f"tool {name} is not available to the {self.p.role} role (tools: {', '.join(valid)})")
    fn = getattr(self, "t_" + name)
    params = inspect.signature(fn).parameters
    for k in [k for k in args if k not in params]:
      notes.append(f"argument {k} ignored (not a parameter of {name})")
      args.pop(k)
    missing = [k for k, p in params.items() if p.default is inspect.Parameter.empty and k not in args]
    if missing:
      raise ToolError(f"{name} needs {', '.join(missing)}")
    if "path" in args:
      args["path"] = repair.fix_path(self.st, args["path"], name in ("read_file", "grep", "list_dir", "edit_file"), notes)
    if name == "run":
      args["args"] = repair.fix_run_args(self.st, args.get("script", ""), list(args.get("args") or []), notes)
      if "stdout_to" in args:
        args["stdout_to"] = repair.fix_stdout_to(self.st, args["stdout_to"], args["args"], notes)
    try:
      out = fn(**args)
    except PolicyError as e:
      raise ToolError(f"denied: {e}")
    except FileNotFoundError:
      raise ToolError(repair.missing_hint(self.st, args.get("path") or "?"))
    except OSError as e:
      raise ToolError(f"{e.strerror or e}: {args.get('path', '')}")
    if notes:
      out = "[harness repaired: " + "; ".join(notes) + "]\n" + out
    return out

  def capped(self, text, how):
    if len(text) <= self.cap:
      return text
    return text[:self.cap] + f"\n[truncated at {self.cap} of {len(text)} characters; {how}]"

  def t_read_file(self, path, offset=1, limit=2000):
    rel = self.p.check_read(path)
    kind = self.st.stat(rel)["type"]
    if kind == "-":
      raise ToolError(repair.missing_hint(self.st, rel))
    if kind == "d":
      return f"[harness: {rel} is a directory; listing it]\n" + self.t_list_dir(path)
    if kind != "f":
      raise ToolError(f"{rel} is not a regular file")
    offset, limit = max(1, int(offset or 1)), max(1, int(limit or 2000))
    r = self.st.read_lines(rel, offset, limit)
    if r["binary"]:
      raise ToolError(f"{rel} is binary: read it through a ./cupella script's text output")
    out, total = [f"{i:6}\t{line}" for i, line in enumerate(r["lines"], offset)], r["total"]
    body = "\n".join(out) if out else f"(no lines at offset {offset}; the file has {total})"
    if offset + limit <= total:
      body += f"\n[lines {offset}-{offset + limit - 1} of {total}; read on with offset]"
    return f'<tool_result path="{rel}">\n' + self.capped(body, "read on with offset and a smaller limit") + "\n</tool_result>"

  def t_grep(self, pattern, path, glob=None, ignore_case=False, max_hits=200):
    rel = self.p.check_read(path)
    note = ""
    kind = self.st.stat(rel)["type"]
    if kind == "-":
      raise ToolError(repair.missing_hint(self.st, rel))
    try:
      re.compile(pattern)
    except re.error as e:
      pattern = re.escape(pattern)
      note = f"[harness: not a valid regular expression ({e}); searched for the literal text]\n"
    max_hits = min(int(max_hits or 200), 2000)
    if kind == "f":
      files = [rel]
    else:
      # the policy decides per file; the store lists and searches
      files = [f for f, size, link in self.st.walk(rel)
               if not link and self.p.can_read(f)
               and (not glob or fnmatch.fnmatchcase(f if "/" in glob else f.rsplit("/", 1)[-1], glob))]
    found, timed_out = self.st.grep(files, pattern, bool(ignore_case), max_hits, 120, 20 << 20)
    hits = [f"{f}:{i}: {text}" for f, i, text in found]
    tail = ""
    if len(hits) >= max_hits:
      tail = f"\n[stopped at {max_hits} hits: narrow the path or pattern]"
    elif timed_out:
      tail = "\n[stopped after 120 s: narrow the path]"
    body = "\n".join(hits) or "no matches"
    return note + f'<tool_result path="{rel}">\n' + self.capped(body + tail, "narrow the search") + "\n</tool_result>"

  def t_list_dir(self, path, glob=None):
    rel = self.p.check_list(path)
    if not self.st.isdir(rel):
      raise ToolError(f"{rel} is not a directory")
    if glob:
      out = []
      if ".." in glob.split("/") or glob.startswith("/"):
        raise ToolError("the glob must stay below the directory")
      for qrel, is_dir in self.st.glob(rel, glob, 20000):
        if qrel != "." and self.p.can_list(qrel):
          out.append(qrel + ("/" if is_dir else ""))
        elif qrel != "." and self.p.listed_earlier(qrel):
          out.append(qrel + EARLIER)
        if len(out) >= 2000:
          out.append("[stopped at 2000 entries]")
          break
    else:
      out = []
      for n, is_dir in self.st.listdir(rel):
        q = f"{rel}/{n}" if rel != "." else n
        if self.p.can_list(q):
          out.append(n + ("/" if is_dir else ""))
        elif self.p.listed_earlier(q):
          out.append(n + EARLIER)
    return self.capped("\n".join(out) or "(empty)", "use a glob")

  def note_report(self, rel):
    # a report this session writes: its cost goes into the report's appendix
    m = re.match(r"reports/([^/_][^/]*?)(?:\.md|\.json)?(?:/|$)", rel)
    if m and self.p.role == "main":
      with self.h.lock:
        self.h.report_names.add(m.group(1))

  def t_write_file(self, path, content):
    rel = self.p.check_write(path)
    self.note_report(rel)
    if not isinstance(content, str):
      content = json.dumps(content, indent=2) if rel.endswith(".json") else str(content)
    warn, notes = "", []
    if rel.endswith((".json", ".jsonl")):
      content, bad = repair.check_json_text(rel, content, notes)
      if bad:
        warn = "\nwarning: not valid JSON, fix and rewrite: " + "; ".join(bad[:10])
    self.st.write_text(rel, content)
    head = "[harness repaired: " + "; ".join(notes) + "]\n" if notes else ""
    return f"{head}wrote {rel} ({len(content)} characters){warn}"

  def t_edit_file(self, path, old, new, replace_all=False):
    rel = self.p.check_write(path)
    self.note_report(rel)
    text = self.st.read_text(rel)
    if not isinstance(old, str) or not isinstance(new, str):
      # a JSON object given for a line of a .jsonl file: match it in the file's own spacing
      forms = [(lambda v, s=s: json.dumps(v, ensure_ascii=False, separators=s)) for s in (None, (",", ":"))]
      pick = next((f for f in forms if isinstance(old, str) or f(old) in text), forms[0])
      old = old if isinstance(old, str) else pick(old)
      new = new if isinstance(new, str) else pick(new)
    n = text.count(old)
    if old and n == 0:
      m = repair.fuzzy_edit(text, old)
      if m:
        self.st.write_text(rel, text[:m.start()] + new + text[m.end():])
        return f"[harness: old string matched once with different whitespace; replaced that]\nedited {rel} (1 replacement)"
    if not old or n == 0:
      raise ToolError(f"old string not found in {rel}; read the lines again and copy them exactly")
    if n > 1 and not replace_all:
      raise ToolError(f"old string occurs {n} times in {rel}: give more context or replace_all")
    self.st.write_text(rel, text.replace(old, new) if replace_all else text.replace(old, new, 1))
    return f"edited {rel} ({n if replace_all else 1} replacement{'s' if replace_all and n > 1 else ''})"

  def t_append_file(self, path, text):
    rel = self.p.check_write(path)
    self.st.append_text(rel, text if text.endswith("\n") else text + "\n")
    return f"appended to {rel}"

  def show_md(self, args):
    # md-view.py is for the user: its rendering goes to the user's terminal (paged when it
    # is one), never to the model, so it cannot be used to read an earlier report either
    self.n_runs += 1
    log = f"{self.sess_dir}/runs/{self.n_runs:03d}-md-view.py.txt"
    env = dict(self.h.clean_env)
    tty = sys.stdout.isatty()
    if tty:
      env.update(CUPELLA_MDVIEW_TTY="1", COLUMNS=str(shutil.get_terminal_size().columns))
    try:
      r = subprocess.run([self.h.cupella, "md-view.py"] + args, cwd=self.p.ws, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    except subprocess.TimeoutExpired:
      raise ToolError("./cupella md-view.py timed out")
    err = "\n".join(x for x in r.stderr.decode("utf-8", "replace").splitlines() if not x.startswith("== workspace"))
    self.st.write_text(log, f"$ ./cupella md-view.py {' '.join(args)}\n{err}\n[exit {r.returncode}; output shown to the user]\n")
    self.last_exit["md-view.py"] = (r.returncode, err.strip().splitlines()[-1] if err.strip() else "", args)
    if r.returncode:
      return f"FAILED: exit {r.returncode}\n{err}"
    n = r.stdout.count(b"\n")
    with self.h.lock:
      sys.stdout.flush()
      if tty and shutil.which("less"):
        # the output holds only md-view.py's own colors: control characters from the file
        # are already shown as <U+XXXX>
        subprocess.run(["less", "-R", "-F", "-X"], input=r.stdout)
      else:
        sys.stdout.buffer.write(r.stdout)
        sys.stdout.flush()
    return (f"exit 0\n[harness: the rendered file ({n} lines) was shown to the user on their terminal. "
            "It is not given to you: do not repeat or summarize it; say it was shown, or answer what the user asked about it "
            "from files you may read.]")

  def t_run(self, script, args=None, stdout_to=None):
    args = list(args or [])
    self.p.check_run(script, args)
    if script == "md-view.py":
      return self.show_md(args)
    if script in ("report-build.py", "claims-promote.py", "claims-merge.py") and args and "/" not in args[0]:
      self.note_report("reports/" + args[0] + "/")
    out_path = None
    if stdout_to:
      out_path = orel = self.p.resolve(stdout_to)
      if not any(matches(orel, p) for p in self.p.stdout_to) or orel.startswith("work/_") \
         or any(matches(orel, p) for p in DENY_WRITE):
        raise ToolError(f"stdout_to {orel}: not allowed")
      if self.st.lexists(orel) or self.p.store.is_link(stdout_to):
        # script outputs (scan.txt, facts.json) are the scripts' own: never replaced from here
        raise ToolError(f"stdout_to {orel}: exists; stdout_to writes a new file only (choose another name)")
    self.n_runs += 1
    log = f"{self.sess_dir}/runs/{self.n_runs:03d}-{re.sub(r'[^A-Za-z0-9._-]', '_', script)}.txt"
    t0 = time.time()
    try:
      r = subprocess.run([self.h.cupella, script] + args, cwd=self.p.ws, env=self.h.clean_env,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT if not out_path else subprocess.PIPE,
                         timeout=self.h.cfg.get("run_timeout", 3600))
    except subprocess.TimeoutExpired:
      raise ToolError(f"./cupella {script} timed out")
    out = r.stdout.decode("utf-8", "replace")
    err = (r.stderr or b"").decode("utf-8", "replace") if out_path else ""
    self.st.write_text(log, f"$ ./cupella {script} {' '.join(args)}\n{err}{out if not out_path else ''}\n[exit {r.returncode}]\n")
    if out_path:
      self.st.write_text(out_path, out)
      out = err + f"[standard output, {len(out)} characters, written to {stdout_to}]"
    lines = [x for x in (err + out).splitlines() if x.strip()]
    self.last_exit[script] = (r.returncode, lines[-1] if lines else "", args)
    head = (f"FAILED: exit {r.returncode} after {time.time() - t0:.0f} s. Read the output; the step did not complete.\n"
            if r.returncode else f"exit 0 after {time.time() - t0:.0f} s\n")
    if len(out) > self.cap:
      keep = self.cap // 4
      out = out[:keep] + f"\n[... {len(out) - self.cap} characters omitted ...]\n" + out[-(self.cap - keep):]
    return head + out
