#!/usr/bin/env python3
# Runs the same analysis through the API harness once per model and tabulates what each
# run did. Run as `./cupella model-compare`; host side, it starts `./cupella agent` per
# model and calls ./cupella for the checks.
#
#   ./cupella model-compare <name> <spec> [<spec> ...] [--max-usd N] [--request TEXT]
#
#   <name>  the sample (work/<name>/ or an APK under data/; the agent unpacks it with -f)
#   <spec>  MAIN or MAIN+READER, each <backend>:<model>; READER also runs the decryptor
#           (default: MAIN). Example: openrouter:google/gemini-3.8-flash+openrouter:deepseek/deepseek-v4.1-flash
#   --max-usd N     cost cap per stage, passed to the agent (default 3)
#   --request TEXT  the request, {name} replaced (default: a fresh full analysis)
#
# Before the first run, the sample's agent outputs (reports/<name>.md, .json, and
# reports/<name>/; work/<name>/progress/, decrypt/, verification.md; work/<name>.dec*/)
# are moved aside to <run>/_before/, so each model starts from the scripts' output alone;
# after each run its outputs are moved to <run>/<model>/; at the end the _before state is
# moved back. <run> is work/_bench-models/<run>/ for the work/ outputs and the summary,
# and reports/_archive/model-compare/<run>/ for the report files: each move is a rename
# on one side, so it works the same when work/ is a Docker volume (the workspace's store,
# harness/store.py). Nothing is deleted; <run>/moved.json lists what was moved aside.
#
# Per model: finished or stopped, cost, turns, subagent stages, native tool runs and
# reads of decompiled native code, claims-check and cite-check results, verifier verdict
# counts, repairs, denials, provider stops. Written to summary.tsv and summary.md in
# work/_bench-models/<run>/ and printed. Judging the findings stays with the user.
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

ws = os.environ.get("CUPELLA_WS") or sys.exit("run as ./cupella model-compare")
root = os.environ.get("CUPELLA_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cupella = os.path.join(ws, "cupella") if os.path.exists(os.path.join(ws, "cupella")) else os.path.join(root, "cupella")
sys.path.insert(0, os.path.join(root, "harness"))
import store as stores  # noqa: E402

st = None  # the workspace's store, set in main()
DEFAULT_REQUEST = ("analyze {name} fresh: unpack with -f, then the full workflow "
                   "(native code, readers, verification), and write the rendered report")


def slug(spec):
  return re.sub(r"[^A-Za-z0-9._-]+", "_", spec)[:80]


def outputs(name):
  # the sample's agent outputs, as paths relative to the workspace
  cands = [f"reports/{name}.md", f"reports/{name}.json", f"reports/{name}",
           f"work/{name}/progress", f"work/{name}/decrypt", f"work/{name}/verification.md"]
  try:
    cands += [f"work/{n}" for n, _ in st.listdir("work") if re.fullmatch(re.escape(name) + r"\.dec\d+", n)]
  except OSError:
    pass
  return [c for c in cands if st.lexists(c)]


def place(run, sub, rel):
  # where an output is kept aside: the same side (host or volume) as the output itself
  if rel.startswith("reports/"):
    return f"reports/_archive/model-compare/{run}/{sub}/{rel}"
  return f"work/_bench-models/{run}/{sub}/{rel}"


def move_out(name, run, sub):
  moved = []
  for rel in outputs(name):
    st.move(rel, place(run, sub, rel))
    moved.append(rel)
  return moved


def move_back(run, moved):
  for rel in moved:
    if st.lexists(rel):
      print(f"  not restored, exists: {rel}", file=sys.stderr)
      continue
    try:
      st.move(place(run, "_before", rel), rel)
    except OSError as e:
      print(f"  not restored: {rel}: {e}", file=sys.stderr)


def cup(*args):
  r = subprocess.run([cupella, *args], cwd=ws, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, timeout=900)
  return r.returncode, r.stdout.decode("utf-8", "replace")


def claims_and_cite(name, m):
  code, out = cup("claims-check.py", name)
  mm = re.search(r"\(confirmed (\d+), draft (\d+), rejected (\d+)\).*?(\d+) problems?", out)
  m["claims"] = (f"{mm.group(1)} confirmed, {mm.group(2)} draft, {mm.group(3)} rejected, {mm.group(4)} problems" if mm
                 else (out.strip().splitlines() or ["no output"])[-1][:80]) + ("" if code == 0 else f" (exit {code})")
  code, out = cup("cite-check.py", name)
  mm = re.search(r"(\d+) citations checked.*?(\d+) problems?", out)
  m["cite"] = (f"{mm.group(1)} cited, {mm.group(2)} problems" if mm else (out.strip().splitlines() or ["no output"])[-1][:80])


def metrics(name, session, log_text):
  m = {"session": session or "", "finished": "no", "usd": 0.0, "turns_main": 0, "responses": 0,
       "stages": "", "native_runs": 0, "native_reads": 0, "claims": "", "cite": "", "verdicts": "",
       "repairs": 0, "denied": 0, "harness_errors": 0, "stops": 0, "models": ""}
  sdir = f"work/_harness/{session}" if session and re.fullmatch(r"[A-Za-z0-9T-]+", session) else None
  if sdir and st.isdir(sdir):
    models = set()
    rows = [line.split("\t") for line in st.read_text(f"{sdir}/usage.tsv").splitlines()][1:]
    for r in rows:
      m["responses"] += 1
      m["usd"] += float(r[11] or 0)
      m["turns_main"] += r[1] == "main"
      models.add(f"{r[2]}={r[5]}")
    m["models"] = ", ".join(sorted(models))
    stages = {}
    ev = st.read_text(f"{sdir}/events.log") if st.isfile(f"{sdir}/events.log") else ""
    for lab in re.findall(r"spawned (\S+) \(", ev):
      stage = re.sub(r"-\d+$", "", lab)
      stages[stage] = stages.get(stage, 0) + 1
    m["stages"] = " ".join(f"{k}x{v}" for k, v in sorted(stages.items()))
    m["native_runs"] = len(re.findall(r': run \{"script": "native-(?:decompile|disasm|summary)', ev))
    m["native_reads"] = len(re.findall(r': (?:read_file|grep) \{"path": "work/[^"]*/native/', ev))
    m["repairs"] = ev.count(": repaired ")
    m["denied"] = len(re.findall(r" denied: ", ev))
    m["harness_errors"] = ev.count("harness error")
    m["stops"] = len(re.findall(r"response stopped by|request refused by", ev))
    m["finished"] = "yes" if re.search(r"\] done: main|\bdone: main", ev) and "interrupted" not in ev else "no"
    # the main agent's own end: a cost cap, turn limit, or context stop is not a finish
    try:
      for line in st.read_text(f"{sdir}/main/transcript.jsonl").splitlines():
        r = json.loads(line)
        if r.get("kind") == "finish" and str(r.get("text", "")).startswith("stopped"):
          m["finished"] = "no: " + r["text"][9:70]
    except (OSError, ValueError):
      pass
    if "STOPPED by the model provider" in log_text or m["stops"]:
      m["finished"] = "stopped by provider"
  if not os.path.exists(os.path.join(ws, "reports", name, "claims.jsonl")):  # reports/ is on the host
    m["claims"], m["cite"] = "no report", "no report"
  else:
    claims_and_cite(name, m)
  vdir = f"work/{name}/progress/verify-verdicts"
  if st.isdir(vdir):
    res = {}
    for f in [f"{vdir}/{n}" for n, d in st.listdir(vdir) if not d and n.endswith(".json")]:
      try:
        r = json.loads(st.read_text(f)).get("result", "?")
      except (OSError, ValueError, AttributeError):
        r = "unreadable"
      res[r] = res.get(r, 0) + 1
    m["verdicts"] = " ".join(f"{k} {v}" for k, v in sorted(res.items())) or "none (json)"
  else:
    m["verdicts"] = "none"
  m["usd"] = round(m["usd"], 3)
  return m


def main():
  ap = argparse.ArgumentParser(prog="./cupella model-compare")
  ap.add_argument("name")
  ap.add_argument("specs", nargs="+")
  ap.add_argument("--max-usd", type=float, default=3)
  ap.add_argument("--request", default=DEFAULT_REQUEST)
  a = ap.parse_args()
  if not re.fullmatch(r"[A-Za-z0-9][^/\x00-\x1f]*", a.name) or ".." in a.name:
    sys.exit(f"bad name {a.name!r}")
  for s in a.specs:
    for part in s.split("+"):
      if ":" not in part:
        sys.exit(f"bad spec {s!r}: <backend>:<model>[+<backend>:<model>]")
  global st
  st = stores.make(ws, cupella, dict(os.environ))
  run = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + slug(a.name)[:24]
  base = f"work/_bench-models/{run}"
  if st.lexists(base):
    sys.exit(f"{base} exists")
  st.mkdir(base)
  before = move_out(a.name, run, "_before")
  st.write_text(f"{base}/moved.json", json.dumps({"moved": before, "kept_in": {
    "work": f"work/_bench-models/{run}/_before/", "reports": f"reports/_archive/model-compare/{run}/_before/"}}, indent=2))
  print(f"== results in {base}/ (report files in reports/_archive/model-compare/{run}/); "
        f"moved aside first: {', '.join(before) or 'nothing'}")
  rows = []
  try:
    for spec in a.specs:
      main_spec, _, reader = spec.partition("+")
      reader = reader or main_spec
      out_dir = f"{base}/{slug(spec)}"
      st.mkdir(out_dir)
      cmd = [cupella, "agent", "--once", "--max-usd", str(a.max_usd), "--model", main_spec,
             "--role-model", f"reader={reader}", "--role-model", f"decryptor={reader}",
             a.request.replace("{name}", a.name)]
      print(f"\n== {spec}")
      log = []
      p = subprocess.Popen(cmd, cwd=ws, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      try:
        for raw in p.stdout:
          line = raw.decode("utf-8", "replace")
          sys.stdout.write(line)
          sys.stdout.flush()
          log.append(line)
        p.wait()
      except KeyboardInterrupt:
        p.terminate()
        p.wait()
        log.append("[model-compare] interrupted\n")
        print("\n== interrupted; checks and moves still run")
      text = "".join(log)
      st.write_text(f"{out_dir}/agent.log", text)
      ms = re.search(r"\[harness\] session (\S+),", text)
      m = metrics(a.name, ms.group(1).rstrip(",") if ms else None, text)
      m = {"spec": spec, **m}
      rows.append(m)
      st.write_text(f"{out_dir}/metrics.json", json.dumps(m, indent=2))
      move_out(a.name, run, slug(spec))
      print(f"== {spec}: {m['finished']}, {m['usd']} USD, claims {m['claims']}, stages {m['stages'] or 'none'}, "
            f"native runs {m['native_runs']}, native reads {m['native_reads']}")
  finally:
    move_back(run, before)
    write_summary(base, a, rows)
    st.close()


def write_summary(base, a, rows):
  if not rows:
    return
  cols = list(rows[0].keys())
  st.write_text(f"{base}/summary.tsv", "\t".join(cols) + "\n"
                + "".join("\t".join(str(r[c]) for c in cols) + "\n" for r in rows))
  show = ["spec", "finished", "usd", "turns_main", "stages", "native_runs", "native_reads",
          "claims", "cite", "verdicts", "repairs", "denied", "stops"]
  lines = [f"# Model comparison: {a.name}", "", f"Request: {a.request.replace('{name}', a.name)}", "",
           "| " + " | ".join(show) + " |", "|" + "|".join("---" for _ in show) + "|"]
  lines += ["| " + " | ".join(str(r[c]).replace("|", "/") for c in show) + " |" for r in rows]
  lines += ["", "Per model: agent.log, metrics.json, and the run's work/ outputs in its directory; its report "
            f"files in reports/_archive/model-compare/{base.rsplit('/', 1)[-1]}/<model>/."]
  st.write_text(f"{base}/summary.md", "\n".join(lines) + "\n")
  print("\n" + "\n".join(lines))


main()
