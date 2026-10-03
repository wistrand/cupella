#!/usr/bin/env python3
"""Rank decompiled functions with a local model (llav) to produce a reading list.

Each selected function is sent as text to a local llav server with a fixed set of
yes/no questions; the answers are probabilities. Output is a list of functions per
question, for the agent to read. A score is a lead of the weakest kind: the model
sees one function at a time, misses behavior that spans functions, and is sometimes
confidently wrong. Nothing here is evidence.

What is scored (a filter, because scoring everything is slow and mostly noise):
  Java    methods in the given scopes of jadx output, minus generated code, UI
          builders, and trivial methods
  Dart    functions of the app's own package in blutter output that have string
          literals or calls outside dart:core
  native  functions in Ghidra output (work/<name>/native/**/*.c) that reference a
          string of interest, their callers two levels up, and the direct callees of
          all of those. Library code without such strings is not scored.
Questions about network use are dropped when the manifest has no INTERNET permission.

Needs a llav server running on the host (default http://127.0.0.1:8080, or LLAV_URL).
./cupella executes this on an internal Docker network that reaches only the host, with
LLAV_URL=http://host.docker.internal:8080 (scripts/llav_client.py). The server must
listen on that network's gateway address or 0.0.0.0, not only 127.0.0.1.

Usage: ./cupella model-leads.py <name> [java-scope ...]      e.g. ./cupella model-leads.py app org/example
       MODEL_LEADS_MAX (default 600 units)
Output: work/<name>/model-leads.txt, scores cached in work/<name>/model-leads.jsonl
"""
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import llav_client  # noqa: E402
import units  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
MAX_UNITS = int(os.environ.get("MODEL_LEADS_MAX", "600"))
MAX_CHARS = 3500

QUESTIONS = {
  "network": "Does this code open a network connection, send an HTTP request, or listen on a network port?",
  "command_server": "Does this code find or contact a remote server in order to receive commands or configuration?",
  "system_settings": "Does this code write Android system settings (Settings.Secure, Settings.Global, Settings.System) "
                     "or switch on an accessibility service, notification listener, or device admin?",
  "persistence": "Does this code make the program start or restart by itself, for example after boot, after being "
                 "stopped, or by re-enabling itself?",
  "credentials": "Does this code store, send, or compare a password, API key, access token, or encryption key?",
  "masking": "Does this code encrypt, decrypt, XOR-mask, or otherwise scramble data or files?",
  "private_data": "Does this code read the user's browsing URLs, notification contents, contacts, messages, "
                  "location, or screen contents?",
  "process": "Does this code execute a shell command or another program, or kill a process?",
  "flood": "Does this code send repeated requests or packets to a target in order to overload it?",
}
NEEDS_INTERNET = ("network", "command_server", "flood")



def java_leads(work, scopes):
  out = []
  for u in units.java_units(work, scopes):
    ui = "Composer " in u.meta or "Composer," in u.meta  # Compose UI builders
    trivial = len(u.lines) < 6 or re.match(r"^(get|set|is)[A-Z]\w*$", u.name) and len(u.lines) < 9
    if not ui and not trivial:
      out.append((u.id, u.where, u.text[:MAX_CHARS]))
  return out


def dart_leads(work, name):
  di = None
  out = []
  for u in units.dart_units(work, name):
    f = u.meta
    if "/locale/" in f.file or "/l10n/" in f.file or f.size < 80:
      continue
    di = di or units.load_script("dart-index.py")
    lines = ["// Dart function %s (pseudo-code: string literals, calls, field stores, branches)" % f.qual]
    informative = 0
    for _addr, text in f.body:
      core = text.split("   ; [")[0]
      if di.BOILERPLATE.match(core) or di.STUB_CALL.match(core):
        continue
      call = "   ; [" in text
      has_str = bool(di.STRING.search(core))
      if call and not di.CORE_CALL.search(text) or has_str:
        informative += 1
      if call or has_str or "StoreField" in core or core.startswith(("cmp", "b.")):
        lines.append(text[:160])
    if informative:
      out.append((u.id, u.where, "\n".join(lines)[:MAX_CHARS]))
  return out


def native_leads(work):
  ns = units.load_script("native-summary.py")
  wanted = ("URLs", "IPv4 addresses", "filesystem paths", "flooding, bot behavior", "shell commands",
            "root, hooking, emulator, debugger checks", "keys, certificates", "format strings with shell or SQL shape")
  patterns = [pat for label, pat in ns.STRING_CATEGORIES if label in wanted]
  allu = units.native_units(work)
  by_id, callers = units.callers_of(allu)
  seeds = set()
  for u in allu:
    strs = re.findall(r'/\* -> "((?:[^"\\]|\\.)*)" \*/', u.text) + re.findall(r'(?<!-> )"((?:[^"\\]|\\.){4,})"', u.text)
    if any(p.search(s) for s in strs for p in patterns):
      seeds.add(u.id)
  calls = {u.id: u.calls for u in allu}
  level1 = {c for s in seeds for c in callers.get(s, ())}
  level2 = {c for s in level1 for c in callers.get(s, ())}
  chosen = seeds | level1 | level2
  # what the string-bearing and the orchestrating functions call directly
  chosen |= {c for n in seeds | level1 | level2 for c in calls.get(n, ())}
  out = []
  for u in sorted((by_id[i] for i in chosen), key=lambda x: (x.file, x.addr)):
    if len(u.lines) >= 6:
      role = "has strings of interest" if u.id in seeds else "calls or is called by such a function"
      out.append((u.id, "%s, %s)" % (u.where[:-1], role), u.text[:MAX_CHARS]))
  return out


def ask(state, questions):
  return {k: v["noul"] for k, v in llav_client.ask(state, questions).items()}


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name, scopes = sys.argv[1], sys.argv[2:]
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found: run ./cupella unpack.sh first" % name)
  try:
    model = llav_client.model_id()
  except llav_client.LlavError as ex:
    sys.exit("%s. This step is optional: start a llav server on the host "
             "(python3 -m llav --gguf <model> --port 8080) and rerun." % ex)

  manifest = ""
  mpath = os.path.join(work, "manifest.xml")
  if os.path.exists(mpath):
    with open(mpath, errors="replace") as f:
      manifest = f.read()
  if not scopes:
    scopes = units.load_script("scope.py").scopes(work)
  internet = "android.permission.INTERNET" in manifest
  questions = {k: {"type": "noul", "instructions": v} for k, v in QUESTIONS.items()
               if internet or k not in NEEDS_INTERNET}
  qhash = hashlib.sha256(json.dumps(questions, sort_keys=True).encode()).hexdigest()[:12]

  selected = java_leads(work, scopes) + dart_leads(work, name) + native_leads(work)
  total = len(selected)
  truncated = total > MAX_UNITS
  selected = selected[:MAX_UNITS]

  cache_path = os.path.join(work, "model-leads.jsonl")
  cache = {}
  if os.path.exists(cache_path):
    with open(cache_path) as f:
      for line in f:
        try:
          row = json.loads(line)
          cache[row["key"]] = row["scores"]
        except (ValueError, KeyError):
          pass
  t0, fresh, errors, scores = time.time(), 0, 0, {}
  with open(cache_path, "a") as f:
    for i, (uid, _where, body) in enumerate(selected):
      key = hashlib.sha256((qhash + model + body).encode()).hexdigest()[:24]
      if key not in cache:
        try:
          cache[key] = ask(body, questions)
          f.write(json.dumps({"key": key, "id": uid, "scores": cache[key]}) + "\n")
          f.flush()
          fresh += 1
        except (llav_client.LlavError, KeyError, TypeError):
          errors += 1
          continue
        if fresh % 50 == 0:
          print("  %d/%d scored (%.0f s)" % (i + 1, len(selected), time.time() - t0), file=sys.stderr)
      scores[uid] = cache[key]

  out = os.path.join(work, "model-leads.txt")
  with open(out, "w") as f:
    w = lambda s="": f.write(s + "\n")
    w("# Model leads: %s" % name)
    w("Functions ranked by a local model (%s via llav) on fixed yes/no questions." % model)
    w("WEAKEST KIND OF LEAD. The model reads one function at a time: it misses behavior")
    w("that spans functions and is sometimes confidently wrong. Read the code; cite the code.")
    w("A function's absence here means nothing.")
    w()
    kinds = {}
    for uid, _w, _b in selected:
      kinds[uid.split(":")[0]] = kinds.get(uid.split(":")[0], 0) + 1
    w("scored: %d functions (%s)%s; %d newly scored in %.0f s; %d request errors" % (
      len(scores), ", ".join("%s %d" % kv for kv in sorted(kinds.items())),
      " of %d selected, cap MODEL_LEADS_MAX" % total if truncated else "", fresh, time.time() - t0, errors))
    w("java scopes: %s" % ", ".join(scopes))
    if not internet:
      w("manifest has no INTERNET permission: the network, command_server, and flood questions were not asked")
    where = {uid: wh for uid, wh, _b in selected}
    for q, text in QUESTIONS.items():
      if q not in questions:
        continue
      hits = sorted(((s[q], uid) for uid, s in scores.items() if s.get(q, 0) >= 0.5), reverse=True)
      w()
      w("## %s (%d of %d)" % (q, len(hits), len(scores)))
      w(text)
      if len(hits) > 0.25 * max(1, len(scores)) and len(hits) > 40:
        w("NOTE: more than a quarter of the functions are flagged; treat this list as noise unless")
        w("something else points at this behavior.")
      for sc, uid in hits[:60]:
        w("- %.2f  %s" % (sc, where[uid]))
      if len(hits) > 60:
        w("- ... %d more" % (len(hits) - 60))
    w()
    w("## Read next")
    w("For each flagged function, read its callers and callees: the functions that tie")
    w("behavior together (main loops, dispatch tables, thin wrappers) usually score low.")
  print("wrote %s (%d functions, %d newly scored, %.0f s)" % (os.path.relpath(out, ROOT), len(scores), fresh, time.time() - t0))


if __name__ == "__main__":
  main()
