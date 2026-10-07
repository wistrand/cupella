# Repairs for the easy mistakes a model makes in tool calls: Claude Code tool names,
# arguments of the wrong type or under another name, malformed JSON, a guessed path or
# sample name, a bare file name for stdout_to. Every repair is reported back to the model
# in the tool result and logged; nothing is repaired silently, and nothing widens a
# role's policy (repaired paths go through the same checks).
import ast
import difflib
import json
import re
import shlex

from store import HostStore

# Claude Code and other harnesses' tool names, which the docs mention
ALIASES = {
  "read": "read_file", "cat": "read_file", "view": "read_file", "open_file": "read_file",
  "grep": "grep", "search": "grep", "rg": "grep",
  "glob": "list_dir", "ls": "list_dir", "list": "list_dir", "list_files": "list_dir",
  "write": "write_file", "create_file": "write_file",
  "edit": "edit_file", "str_replace": "edit_file", "replace": "edit_file",
  "append": "append_file",
  "bash": "bash", "shell": "bash", "run_command": "bash", "exec": "bash",
  "task": "spawn", "agent": "spawn",
}
ARG_ALIASES = {
  "file_path": "path", "filepath": "path", "file": "path", "filename": "path", "dir": "path",
  "directory": "path", "old_string": "old", "new_string": "new", "old_str": "old", "new_str": "new",
  "text": None, "contents": "content", "data": "content", "regex": "pattern", "query": "pattern",
  "include": "glob", "command_args": "args", "arguments": "args", "cmd": "command",
}
INT_ARGS = {"offset", "limit", "max_hits"}
BOOL_ARGS = {"ignore_case", "replace_all"}
LIST_ARGS = {"args", "samples", "read", "write"}


def normalize(name, args, valid, notes):
  # tool name: exact, else case-insensitive, else an alias
  if name not in valid:
    low = (name or "").lower()
    cand = next((v for v in valid if v.lower() == low), None) or ALIASES.get(low)
    if cand:
      notes.append(f"tool {name} taken as {cand}")
      name = cand
  if not isinstance(args, dict):
    args = {}
  out = {}
  for k, v in args.items():
    k2 = k
    if k not in ("text",) and k in ARG_ALIASES and ARG_ALIASES[k]:
      k2 = ARG_ALIASES[k]
    if k == "text" and name == "write_file":
      k2 = "content"
    if k == "pattern" and name == "list_dir":
      k2 = "glob"
    if k2 != k:
      notes.append(f"argument {k} taken as {k2}")
    out[k2] = v
  for k in list(out):
    v = out[k]
    if k in INT_ARGS and isinstance(v, str) and v.strip().lstrip("-").isdigit():
      out[k] = int(v)
      notes.append(f"{k} {v!r} taken as a number")
    elif k in BOOL_ARGS and isinstance(v, str):
      out[k] = v.strip().lower() in ("true", "1", "yes")
      notes.append(f"{k} {v!r} taken as {out[k]}")
    elif k in LIST_ARGS and isinstance(v, str):
      try:
        out[k] = shlex.split(v)
      except ValueError:
        out[k] = v.split()
      notes.append(f"{k} given as a string, split into {out[k]}")
    elif isinstance(v, str) and k in ("path", "stdout_to", "script"):
      s = v.strip().strip("'\"`")
      if s.startswith("./") and k != "script":
        s = s[2:]
      if k == "script":
        s = re.sub(r"^(\./)?cupella\s+", "", s)
      if s != v:
        notes.append(f"{k} {v!r} taken as {s!r}")
      out[k] = s
  return name, out


def bash_to_run(command, notes):
  # a shell command that is a ./cupella call becomes run(); anything else is refused
  try:
    words = shlex.split(command or "")
  except ValueError:
    return None
  stdout_to = None
  if ">" in words:
    i = words.index(">")
    stdout_to = words[i + 1] if i + 1 < len(words) else None
    words = words[:i]
  if len(words) < 2 or words[0] not in ("./cupella", "cupella") or any(w in ("|", "&&", ";", "||") for w in words):
    return None
  notes.append(f"shell command taken as run({words[1]!r}, {words[2:]})")
  a = {"script": words[1], "args": words[2:]}
  if stdout_to:
    a["stdout_to"] = stdout_to
  return a


def repair_json(raw):
  # a tool call's argument text that does not parse: code fences, trailing text,
  # Python literals, missing closing braces
  if not raw:
    return {}
  s = raw.strip()
  s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s)
  for cand in (s, s[:s.rfind("}") + 1] if "}" in s else s):
    try:
      v = json.loads(cand)
      if isinstance(v, dict):
        return v
    except ValueError:
      pass
  try:
    v = ast.literal_eval(s)
    if isinstance(v, dict):
      return v
  except (ValueError, SyntaxError):
    pass
  for tail in ("}", "\"}", "\"]}", "]}", "}}"):
    try:
      v = json.loads(s + tail)
      if isinstance(v, dict):
        return v
    except ValueError:
      pass
  return None


def store_of(ws):
  # the functions below take the workspace's store (harness/store.py), or a host path
  return HostStore(ws) if isinstance(ws, str) else ws


def work_dirs(ws):
  try:
    return [n for n, _ in store_of(ws).listdir("work")]
  except OSError:
    return []


def sample_prefix(ws, name):
  # a unique sample directory that starts with name (case-insensitive); children
  # (.emb, .dec) only when name asks for them
  if not name or name.startswith(("_", "-", ".")) or len(name) < 4:
    return None
  low = name.lower()
  c = [d for d in work_dirs(ws) if d.lower().startswith(low) and not d.startswith("_")
       and (".emb" in name or ".dec" in name or not re.search(r"\.(emb|dec)\d+$", d))]
  if len(c) == 1:
    return c[0]
  exact = [d for d in c if d.lower() == low]
  return exact[0] if len(exact) == 1 else None


def fix_path(ws, path, must_exist, notes):
  # work/<prefix>/... -> the unique sample directory; a case or near-miss in one name
  # component -> the existing one, when unique
  if not isinstance(path, str) or not path:
    return path
  st = store_of(ws)
  p = path.replace("\\", "/")
  if p.startswith(st.ws + "/"):
    p = p[len(st.ws) + 1:]
  p = re.sub(r"/{2,}", "/", p).rstrip("/") or "."
  if p.startswith("/") or ".." in p.split("/"):
    return p  # resolution and the policy deal with it
  if st.exists(p):
    if p != path:
      notes.append(f"path {path!r} taken as {p!r}")
    return p
  parts = p.split("/")
  if len(parts) >= 2 and parts[0] == "work" and not st.exists(f"work/{parts[1]}"):
    s = sample_prefix(st, parts[1])
    if s:
      parts[1] = s
  # repair one component at a time from the top while the parent exists
  for i in range(len(parts)):
    parent = "/".join(parts[:i]) or "."
    if not st.isdir(parent):
      break
    if st.exists("/".join(parts[:i + 1])):
      continue
    if i == len(parts) - 1 and not must_exist:
      break
    if i == 1 and parts[0] == "work":
      # the sample directory: only the unique-prefix repair above, never a near miss,
      # which would read or write another sample's files
      break
    names = [n for n, _ in st.listdir(parent)]
    ci = [n for n in names if n.lower() == parts[i].lower()]
    if len(ci) == 1:
      parts[i] = ci[0]
      continue
    close = difflib.get_close_matches(parts[i], names, n=2, cutoff=0.85)
    if len(close) == 1:
      parts[i] = close[0]
      continue
    break
  q = "/".join(parts)
  if q != p and (st.exists(q) or not must_exist):
    notes.append(f"path {path!r} does not exist; taken as {q!r}")
    return q
  return p


def missing_hint(ws, path):
  # for a path that does not exist: the nearest existing directory and the closest names
  st = store_of(ws)
  if path.startswith("/") or ".." in path.split("/"):
    return f"{path} does not exist"
  parts = path.split("/")
  for i in range(len(parts) - 1, -1, -1):
    d = "/".join(parts[:i]) or "."
    if st.isdir(d):
      try:
        names = [n for n, _ in st.listdir(d)]
      except OSError:
        return f"{path} does not exist"
      close = difflib.get_close_matches(parts[i] if i < len(parts) else "", names, n=5, cutoff=0.5)
      where = "/".join(parts[:i]) or "."
      shown = ", ".join(close) if close else ", ".join(names[:20]) + (" ..." if len(names) > 20 else "")
      return f"{path} does not exist; {where}/ has: {shown}"
  return f"{path} does not exist"


def find_sample_file(ws, path, notes):
  # a ./cupella argument under data/ or work/_samples/ that does not exist: the unique
  # file with that name, or whose name starts with it, anywhere under data/ or work/_samples/
  st = store_of(ws)
  if path.startswith("/") or ".." in path.split("/") or st.exists(path):
    return path
  base = path.rsplit("/", 1)[-1].lower()
  stem = re.sub(r"\.(apk|zip|xapk|apks|parquet)$", "", base)
  if len(stem) < 4:
    return path
  hits = []
  for top in ("data", "work/_samples"):
    if not st.isdir(top):
      continue
    for f, _, link in st.walk(top):
      nl = f.rsplit("/", 1)[-1].lower()
      if not link and (nl == base or (nl.startswith(stem) and re.search(r"\.(apk|zip|xapk|apks|parquet)$", nl))
                       or re.sub(r"[^a-z0-9]", "", nl).startswith(re.sub(r"[^a-z0-9]", "", stem))):
        hits.append(f)
  apks = [h for h in hits if h.lower().endswith(".apk")] if path.lower().endswith(".apk") else hits
  if len(apks) > 1:  # the same APK in data/ and taken out of an archive: data/ wins
    apks = [h for h in apks if h.startswith("data/")] or apks
  pick = apks if len(apks) == 1 else hits if len(hits) == 1 else []
  if pick:
    notes.append(f"{path!r} does not exist; taken as {pick[0]!r}")
    return pick[0]
  return path


def fix_run_args(ws, script, args, notes):
  # unpack.sh takes -f only as its first argument
  if script == "unpack.sh" and "-f" in args[1:]:
    args = ["-f"] + [a for a in args if a != "-f"]
    notes.append("unpack.sh takes -f first: moved it")
  st = store_of(ws)
  out = []
  for i, a in enumerate(args):
    if not isinstance(a, str):
      a = str(a)
    b = a.strip()
    if b.startswith("./"):
      b = b[2:]
    if b.startswith(("data/", "work/_samples/")):
      b = find_sample_file(st, b, notes)
    elif b.startswith("work/") and not st.exists(b):
      b = fix_path(st, b, True, notes)
    elif "/" not in b and not b.startswith("-") and script != "unpack.sh" and b not in (".", "..") \
         and not st.isdir(f"work/{b}") and i == next(
           (j for j, x in enumerate(args) if not str(x).startswith("-")), -1):
      s = sample_prefix(st, b)
      if s:
        notes.append(f"sample {b!r} taken as {s!r}")
        b = s
    out.append(b)
  return out


def sample_of(ws, args):
  st = store_of(ws)
  for a in args:
    if "/" not in a and a not in (".", "..", "") and not a.startswith("_") and st.isdir(f"work/{a}"):
      return a
    m = re.match(r"(?:data|work/_samples)/(?:.*/)?([^/]+)\.apk$", a)
    if m:
      return m.group(1)
    m = re.match(r"work/([^/_][^/]*)/", a)
    if m:
      return m.group(1)
  return None


def fix_stdout_to(ws, stdout_to, args, notes):
  # a bare file name, or a path outside work/<sample>/: put it in the sample's directory
  if not stdout_to:
    return None
  p = stdout_to[2:] if stdout_to.startswith("./") else stdout_to
  if re.match(r"work/[^/_][^/]*/", p):
    return p
  s = sample_of(ws, args)
  if not s:
    notes.append(f"stdout_to {stdout_to!r} is not under work/<name>/ and no sample was named: output returned instead")
    return None
  name = p.split("/")[-1] or "output.txt"
  if p.startswith(s + "/"):
    name = p[len(s) + 1:]
  q = f"work/{s}/{name}"
  notes.append(f"stdout_to {stdout_to!r} taken as {q!r}")
  return q


def fuzzy_edit(text, old):
  # old that matches once when runs of whitespace are compared loosely
  words = old.split()
  if not words:
    return None
  rx = re.compile(r"\s+".join(re.escape(w) for w in words))
  m = list(rx.finditer(text))
  return m[0] if len(m) == 1 else None


def check_json_text(path, content, notes):
  # for .json and .jsonl writes: strip code fences; report lines that do not parse
  s = content
  if s.lstrip().startswith("```"):
    s = re.sub(r"^\s*```(?:jsonl?|json)?\s*\n|\n?\s*```\s*$", "", s)
    notes.append("removed the code fence around the JSON")
  bad = []
  if path.endswith(".jsonl"):
    for i, line in enumerate(s.splitlines(), 1):
      if line.strip():
        try:
          json.loads(line)
        except ValueError as e:
          bad.append(f"line {i}: {e}")
  else:
    try:
      json.loads(s)
    except ValueError as e:
      bad.append(str(e))
  return s, bad
