# Checks the API harness without network or keys: the role policy (escapes through ..,
# symlinks, denied paths, write limits, command allow-lists and arguments) on a
# throwaway workspace, on both stores (host directories, and the volume store with its
# helper run locally on a scratch directory in place of the container), and each
# adapter's request and parsing of recorded streams. Run by ./cupella check; prints PASS
# or FAIL per case.
#
#   host/harness-test.py <scratch dir>
import argparse
import io
import json
import os
import shutil
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "harness"))
import backends  # noqa: E402
import repair  # noqa: E402
import policy as pol  # noqa: E402
import store as stores  # noqa: E402
from tools import Tools, ToolError  # noqa: E402

scratch = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "work", "_check", "harness"))
shutil.rmtree(scratch, ignore_errors=True)
fails = 0


def check(name, ok):
  global fails
  print(("PASS  " if ok else "FAIL  ") + name)
  fails += 0 if ok else 1


def denied(fn, *a):
  try:
    fn(*a)
    return False
  except (pol.PolicyError, ToolError):
    return True


def refused(fn, *a):
  # a store that refuses the path itself (below the policy)
  try:
    fn(*a)
    return False
  except stores.StoreError:
    return True


class FakeH:
  import threading
  lock = threading.Lock()
  report_names = set()
  cfg = {"tool_result_chars": 30000}
  cupella = "/bin/false"
  clean_env = {}


def build(ws, vol):
  # the test tree; data/ and work/ go to vol when given (the volume store's areas)
  def top(rel):
    return os.path.join(vol if vol and rel.split("/")[0] in stores.AREAS else ws, rel)
  for d in ("data", "work/app/jadx", "work/app.dec1", "work/app.decoy", "work/other", "work/_harness/s1", "work/_stops/x",
            "reports", "bench", "scripts"):
    os.makedirs(top(d), exist_ok=True)
  for f, text in {"work/app/triage.txt": "signer: CN=test\n", "work/other/triage.txt": "x\n",
                  "data/app.apk": "PK", "bench/key.json": "{}", "work/_harness/s1/usage.tsv": "t\n",
                  "work/_stops/x/event.json": "{}", "scripts/scan.sh": "", "reports/app.md": "# r\n",
                  "exports/app/work/app/triage.txt": "signer: CN=test\n"}.items():
    os.makedirs(os.path.dirname(top(f)), exist_ok=True)
    with open(top(f), "w") as fh:
      fh.write(text)
  os.symlink("../../data", top("work/app/link"))
  os.symlink("/etc", top("work/app/etc"))
  return top


def suite(tag, ws, st, top):
  def check_(name, ok):
    check(f"{tag}: {name}", ok)
  # main role
  m = pol.Policy(ws, "main", ["/"], ["reports/", "work/*/progress/"], {"scan.sh"} | pol.CUPELLA_COMMANDS, store=st)
  check_("main reads work/", not denied(m.check_read, "work/app/triage.txt"))
  check_("main denied data/", denied(m.check_read, "data/app.apk"))
  check_("main denied bench/", denied(m.check_read, "bench/key.json"))
  check_("main denied ../ escape", denied(m.check_read, "work/../../outside"))
  check_("main denied absolute outside", denied(m.check_read, "/etc/passwd"))
  check_("main lists data/ names", not denied(m.check_list, "data"))
  check_("reader cannot list data/", denied(pol.sub_policy(ws, root, "reader", ["app"], [], ["work/app/p.md"], store=st).check_list, "data"))
  check_("main denied symlink into data/", denied(m.check_read, "work/app/link/app.apk"))
  check_("main denied symlink out of workspace", denied(m.check_read, "work/app/etc/passwd"))
  check_("main denied work/_stops/", denied(m.check_read, "work/_stops/x/event.json"))
  check_("main reads usage.tsv", not denied(m.check_read, "work/_harness/s1/usage.tsv"))
  check_("main writes reports/", not denied(m.check_write, "reports/app/notes.md"))
  check_("main writes progress", not denied(m.check_write, "work/app/progress/main.md"))
  check_("main denied writing work/app/scan.txt", denied(m.check_write, "work/app/scan.txt"))
  check_("main denied writing harness/", denied(m.check_write, "harness/policy.py"))
  check_("main runs scan.sh", not denied(m.check_run, "scan.sh", ["app"]))
  check_("main denied setup", denied(m.check_run, "setup", []))
  check_("main denied proposals set", denied(m.check_run, "proposals", ["set", "w", "s", "applied"]))
  check_("main denied workspaces rm and --prune", denied(m.check_run, "workspaces", ["rm", "/tmp/x", "--yes"])
         and denied(m.check_run, "workspaces", ["--prune"]) and denied(m.check_run, "workspaces", ["new", "/tmp/x"])
         and not denied(m.check_run, "workspaces", []))

  # files from before the session: denied, except for the sample being resumed
  import time as _t
  os.makedirs(top("work/app/progress"), exist_ok=True)
  for f in ("reports/app.md", "work/app/progress/main.md"):
    with open(top(f), "w") as fh:
      fh.write("old\n")
    os.utime(top(f), (_t.time() - 100, _t.time() - 100))
  m.since = _t.time() - 10
  check_("main denied an earlier report", denied(m.check_read, "reports/app.md"))
  check_("main denied earlier progress", denied(m.check_read, "work/app/progress/main.md"))
  m.resume = "app"
  check_("main reads them when resuming that sample", not denied(m.check_read, "work/app/progress/main.md"))
  m.resume = None
  tm = Tools(FakeH(), m, "work/_harness/t/earlier")
  check_("an earlier report is listed, marked", "app.md  [written before this session" in tm.call("list_dir", {"path": "reports"}))
  check_("an earlier report is listed by a glob, marked",
         "reports/app.md  [written before" in tm.call("list_dir", {"path": "reports", "glob": "*.md"}))
  check_("an earlier report stays unreadable", denied(tm.call, "read_file", {"path": "reports/app.md"}))
  m.since = None

  # reader
  r = pol.sub_policy(ws, root, "reader", ["app"], [], ["work/app/progress/r1.md", "work/app/progress/r1-claims/*.json"], store=st)
  check_("reader reads its sample", not denied(r.check_read, "work/app/triage.txt"))
  check_("reader reads child sample", not denied(r.check_read, "work/app.dec1"))
  check_("reader denied other sample", denied(r.check_read, "work/other/triage.txt"))
  check_("reader denied reports/ unless given", denied(r.check_read, "reports/app.md"))
  check_("reader writes its progress", not denied(r.check_write, "work/app/progress/r1.md"))
  check_("reader writes a claim", not denied(r.check_write, "work/app/progress/r1-claims/D1.json"))
  check_("reader denied other files", denied(r.check_write, "work/app/progress/main.md"))
  check_("reader has no commands", denied(r.check_run, "scan.sh", ["app"]))
  check_("reader spawn refuses write outside its sample",
        denied(pol.sub_policy, ws, root, "reader", ["app"], [], ["work/other/x.md"]))
  check_("reader spawn refuses read of all of work/", denied(pol.sub_policy, ws, root, "reader", ["app"], ["work/"], ["work/app/p.md"]))
  check_("reader spawn refuses bad sample", denied(pol.sub_policy, ws, root, "reader", ["../x"], [], ["work/app/p.md"]))
  v = pol.sub_policy(ws, root, "reader", ["app"], ["reports/app.md"], ["work/app/progress/v.md"], store=st)
  check_("verifier reads the report it was given", not denied(v.check_read, "reports/app.md"))

  # decryptor
  d = pol.sub_policy(ws, root, "decryptor", ["app"], store=st)
  check_("decryptor commands from roles/decryptor.md", "run-decryptor.sh" in d.commands and "scan.sh" not in d.commands)
  check_("decryptor writes decrypt/", not denied(d.check_write, "work/app/decrypt/decrypt.py"))
  check_("decryptor denied writing elsewhere", denied(d.check_write, "work/app/progress/x.md"))
  check_("decryptor runs its sample", not denied(d.check_run, "run-decryptor.sh", ["app"]))
  check_("decryptor denied other sample", denied(d.check_run, "run-decryptor.sh", ["other"]))
  check_("decryptor denied path outside", denied(d.check_run, "native-disasm.py", ["work/other/triage.txt"]))
  check_("decryptor denied unlisted command", denied(d.check_run, "unpack.sh", ["data/app.apk"]))

  # tools on the reader policy
  t = Tools(FakeH(), r, "work/_harness/t/sess")
  check_("read_file numbered", "1\tsigner" in t.call("read_file", {"path": "work/app/triage.txt"}))
  check_("grep finds", "triage.txt:1:" in t.call("grep", {"pattern": "CN=", "path": "work/app"}))
  check_("grep denied through a link into data/", denied(t.call, "grep", {"pattern": ".", "path": "work/app/link"}))
  check_("list_dir glob cannot climb", denied(t.call, "list_dir", {"path": "work/app", "glob": "../*"}))
  check_("reader has no run tool", denied(t.call, "run", {"script": "scan.sh"}))
  check_("reader has no edit tool", denied(t.call, "edit_file", {"path": "work/app/progress/r1.md", "old": "a", "new": "b"}))


  # repairs: each is reported in notes, and repaired paths still pass the policy
  os.makedirs(top("data/malware"), exist_ok=True)
  with open(top("data/malware/Some-App.apk"), "w") as fh:
    fh.write("PK")
  n = []
  check_("repair: data path found in a subdirectory, case-insensitive",
        repair.fix_run_args(st, "unpack.sh", ["-f", "data/some-app.apk"], n) == ["-f", "data/malware/Some-App.apk"] and n)
  check_("repair: unpack.sh -f moved first", repair.fix_run_args(st, "unpack.sh", ["data/malware/Some-App.apk", "-f"], [])[0] == "-f")
  check_("repair: sample prefix", repair.fix_run_args(st, "scan.sh", ["oth"], []) == ["oth"]
        and repair.fix_run_args(st, "scan.sh", ["othe"], []) == ["other"])
  check_("repair: bare stdout_to goes to the sample", repair.fix_stdout_to(st, "x.txt", ["app"], []) == "work/app/x.txt")
  check_("repair: stdout_to without a sample is dropped", repair.fix_stdout_to(st, "x.txt", ["--help"], []) is None)
  check_("repair: path with a sample prefix and wrong case",
        repair.fix_path(st, "work/ap/TRIAGE.txt", True, []) in ("work/app/triage.txt", "work/ap/TRIAGE.txt"))
  check_("repair: missing file names the closest", "triage.txt" in repair.missing_hint(st, "work/app/triage.tx"))
  check_("repair: Claude Code names", repair.normalize("Read", {"file_path": "./work/app/triage.txt", "limit": "5"},
        ["read_file"], [])[1] == {"path": "work/app/triage.txt", "limit": 5})
  check_("repair: shell ./cupella call becomes run", repair.bash_to_run("./cupella scan.sh app > work/app/o.txt", [])
        == {"script": "scan.sh", "args": ["app"], "stdout_to": "work/app/o.txt"})
  check_("repair: shell pipeline refused", repair.bash_to_run("cat x | sh", []) is None)
  check_("repair: JSON with a missing brace", repair.repair_json('{"path": "a", "limit": 3') == {"path": "a", "limit": 3})
  check_("repair: JSON in a fence, Python quotes", repair.repair_json("```json\n{'path': 'a'}\n```") == {"path": "a"})
  check_("repair: whitespace-loose edit", repair.fuzzy_edit("a  b\n c", "a b c") is not None)
  check_("repair: fenced JSONL and a bad line", repair.check_json_text("x.jsonl", "```jsonl\n{\"a\": 1}\n{bad}\n```", [])[1][0].startswith("line 2"))
  tr = Tools(FakeH(), r, "work/_harness/t/sess2")
  check_("repair: reader tool call with a repaired path stays inside its policy",
        denied(tr.call, "read_file", {"path": "work/othe/triage.txt"}))
  check_("repair: reading a directory lists it", "triage.txt" in tr.call("read_file", {"path": "work/app"}))

  # the user's commands and copies stay the user's
  check_("main denied exports/", denied(m.check_read, "exports/app/work/app/triage.txt"))
  check_("main policy cannot run export-files.py", "export-files.py" not in pol.main_policy(ws, root, st).commands)
  check_("main denied writing a report's costs.jsonl", denied(pol.main_policy(ws, root, st).check_write, "reports/app/costs.jsonl"))

  # review fixes (2026-10-07)
  rs = pol.sub_policy(ws, root, "reader", ["app"], [], ["work/app/progress/r9.md"], store=st)
  check_("reader scope: a child sample by its exact name, not a sample that starts with it",
         not denied(rs.check_read, "work/app.dec1") and denied(rs.check_read, "work/app.decoy"))
  check_("reader scope: glob characters in a sample name are literal", pol.esc("a*?[") == "a[*][?][[]")
  check_("repair: no near-miss move to another sample", repair.fix_path(st, "work/othet/triage.txt", True, []) == "work/othet/triage.txt")
  tmain = Tools(FakeH(), pol.main_policy(ws, root, st), "work/_harness/t/main")
  try:
    tmain.call("run", {"script": "scan.sh", "args": ["app"], "stdout_to": "work/app/triage.txt"})
    so = ""
  except ToolError as e:
    so = str(e)
  check_("stdout_to never replaces an existing file", "exists; stdout_to writes a new file only" in so)
  check_("list_dir glob from the root reaches work/", "work/app/triage.txt" in tmain.call("list_dir", {"path": ".", "glob": "work/*/triage.txt"}))
  check_("list_dir ** from the root reaches work/", "work/app/triage.txt" in tmain.call("list_dir", {"path": ".", "glob": "**/triage.txt"}))
  check_("main policy cannot run store, export, store-serve",
         all(denied(pol.main_policy(ws, root, st).check_run, c, []) for c in ("store", "export", "store-serve")))

  # moves (model-compare): a rename on one side, never over an existing file
  st.move("work/app.dec1", "work/_bench-models/r/_before/work/app.dec1")
  check_("move within work/", st.lexists("work/_bench-models/r/_before/work/app.dec1") and not st.lexists("work/app.dec1"))
  st.move("work/_bench-models/r/_before/work/app.dec1", "work/app.dec1")
  check_("move back", st.isdir("work/app.dec1"))
  check_("move refuses an existing target", refused(st.move, "work/app/triage.txt", "work/other/triage.txt"))
  st.move("reports/app.md", "reports/_archive/model-compare/r/_before/reports/app.md")
  check_("move within reports/", st.lexists("reports/_archive/model-compare/r/_before/reports/app.md"))
  st.move("reports/_archive/model-compare/r/_before/reports/app.md", "reports/app.md")


# host store: everything under ws
ws = os.path.join(scratch, "ws")
suite("host", ws, stores.HostStore(ws), build(ws, None))

# volume store: data/ and work/ under vol, reached through the helper (run here as a
# local process with vol as its root, where ./cupella store-serve runs it in a container
# with the volumes at /repo); the rest of the workspace under vws
vws, vol = os.path.join(scratch, "vws"), os.path.join(scratch, "vol")
vtop = build(vws, vol)
vst = stores.VolumeStore(vws, [sys.executable, "-I", os.path.join(root, "harness", "store_helper.py"), vol])
try:
  suite("volume", vws, vst, vtop)
  vm = pol.Policy(vws, "main", ["/"], ["reports/", "work/*/progress/"], {"scan.sh"}, store=vst)
  check("volume: .. out of work/ continues on the host", vst.resolve("work/../reports/app.md") == "reports/app.md")
  check("volume: .. above the volume is outside", vst.resolve("work/../../x") is None)
  check("volume: absolute path of the workspace", vst.resolve(os.path.join(vws, "work", "app")) == "work/app")
  check("volume: link into data/ resolves inside the volume", vst.resolve("work/app/link/app.apk") == "data/app.apk")
  check("volume: link to / is outside", vst.resolve("work/app/etc/passwd") is None)
  os.symlink("../work/app", os.path.join(vws, "reports", "w"))
  check("volume: a host link into work/ resolves in the volume", vst.resolve("reports/w/triage.txt") == "work/app/triage.txt")
  os.makedirs(os.path.join(vol, "work/app/progress"), exist_ok=True)
  os.symlink("../../other", os.path.join(vol, "work/app/progress/lnk"))
  check("volume: writing through a linked directory is resolved to its target and denied",
        denied(pol.sub_policy(vws, root, "reader", ["app"], [], ["work/app/progress/"], store=vst).check_write,
               "work/app/progress/lnk/x.md"))
  check("volume: the helper refuses a write below a link", refused(vst.write_text, "work/app/progress/lnk/x.md", "x"))
  check("volume: the helper refuses an unresolved read", refused(vst.read_lines, "work/app/link/app.apk", 1, 10))
  check("volume: the helper refuses writes to data/", refused(vst.write_text, "data/new.apk", "x"))
  check("volume: a file that is a link is not written", denied(vm.check_write, "work/app/progress/lnk"))
  check("volume: no move between the host and the volume", refused(vst.move, "reports/app.md", "work/app/r.md"))
  check("volume: the helper refuses a move out of work/", refused(vst.move, "data/app.apk", "data/x.apk"))
  tv = Tools(FakeH(), vm, "work/_harness/t/main")
  tv.call("write_file", {"path": "work/app/progress/main2.md", "content": "a\n"})
  tv.call("append_file", {"path": "work/app/progress/main2.md", "text": "b"})
  tv.call("edit_file", {"path": "work/app/progress/main2.md", "old": "b", "new": "c"})
  check("volume: write, append, edit land in the volume",
        open(os.path.join(vol, "work/app/progress/main2.md")).read() == "a\nc\n")
  check("volume: list_dir of the root shows data/ and work/",
        {"data/", "work/", "reports/"} <= set(tv.call("list_dir", {"path": "."}).splitlines()))
  check("volume: list_dir glob in the volume", "work/app/triage.txt" in tv.call("list_dir", {"path": "work", "glob": "*/triage.txt"}))
  check("volume: grep over the workspace root skips denied paths",
        "work/app/triage.txt:1:" in tv.call("grep", {"pattern": "CN=|PK", "path": "."})
        and "data/" not in tv.call("grep", {"pattern": "CN=|PK", "path": "."}))

  # the harness's own files (transcripts, usage, events) go into the volume
  import agent as ag  # noqa: E402
  hargs = argparse.Namespace(role_model=None, stage_model=None, model=None, max_usd=None, resume=None)
  h = ag.Harness(vws, root, {"backends": {}}, hargs)
  h.store = vst
  h.dir = "work/_harness/t/sess"
  h.open_session()
  h.log("test line", quiet=True)
  check("volume: session files in the volume",
        all(os.path.isfile(os.path.join(vol, h.dir, f)) for f in ("usage.tsv", "config.json", "events.log")))
  check("volume: nothing of data/ or work/ on the host",
        not any(os.path.lexists(os.path.join(vws, a)) for a in stores.AREAS))
finally:
  vst.close()

# md-view.py: its output goes to the user's terminal, not to the model
fake = os.path.join(scratch, "fake-cupella")
with open(fake, "w") as fh:
  fh.write('#!/bin/sh\necho "RENDERED $2"\n')
os.chmod(fake, 0o755)


class FakeMdH(FakeH):
  cupella = fake


class Capture:
  def __init__(self):
    self.buffer = io.BytesIO()

  def write(self, s):
    self.buffer.write(s.encode())

  def flush(self):
    pass

  def isatty(self):
    return False


tmd = Tools(FakeMdH(), pol.Policy(ws, "main", ["/"], [], {"md-view.py"}), "work/_harness/t/md")
cap, real = Capture(), sys.stdout
sys.stdout = cap
try:
  res = tmd.call("run", {"script": "md-view.py", "args": ["reports/app.md"]})
finally:
  sys.stdout = real
check("md-view: the rendering goes to the user, not to the model",
      b"RENDERED reports/app.md" in cap.buffer.getvalue() and "RENDERED" not in res and "shown to the user" in res)

# spawn fills the stage templates
import agent as ag  # noqa: E402
os.makedirs(os.path.join(ws, "prompts"), exist_ok=True)
for st in ("read-area", "verify-report"):
  shutil.copy(os.path.join(root, "prompts", f"{st}.md"), os.path.join(ws, "prompts"))
pr, role_, sm, rd, wr = ag.fill_stage(ws, "read-area", {"vars": {"NAME": "app", "ROLE": "reader-x", "AREA": "a", "STARTS": "s"}})
check("spawn: read-area filled in full", not ag.PLACEHOLDER.findall(pr) and len(pr) > 3000 and role_ == "reader")
check("spawn: read-area files from the stage", wr == ["work/app/progress/reader-x.md", "work/app/progress/reader-x-claims/"])
check("spawn: verify-report reads the report", ag.fill_stage(ws, "verify-report", {"vars": {"NAME": "app"}})[3][0] == "reports/app.md")
check("spawn: missing vars refused", denied(ag.fill_stage, ws, "read-area", {"vars": {"NAME": "app"}}))
check("spawn: bad ROLE refused", denied(ag.fill_stage, ws, "read-area", {"vars": {"NAME": "app", "ROLE": "../x", "AREA": "a", "STARTS": "s"}}))

# adapters on recorded streams
class FakeResp(io.BytesIO):
  headers = {"x-request-id": "req1", "request-id": "req2"}


def run_adapter(cls, cfg, stream):
  b = cls("t", {"base_url": "http://x", **cfg}, "k")
  sent = {}

  def post(path, body, headers, r):
    sent.update(path=path, body=body, headers=headers)
    r.request = body
    r.headers = dict(FakeResp.headers)
    return FakeResp(stream.encode())
  b.post = post
  msgs = [{"role": "user", "text": "hi"},
          {"role": "assistant", "text": "", "tool_calls": [{"id": "c1", "name": "read_file", "args": {"path": "a"}, "raw_args": '{"path":"a"}'}]},
          {"role": "tool", "results": [{"id": "c1", "content": "x", "is_error": False}]}]
  return b.complete("m", "sys", msgs, [("read_file", {"description": "d", "parameters": {"type": "object"}})], 100, {}), sent


chat_stream = "".join(f"data: {json.dumps(o)}\n\n" for o in [
  {"model": "m1", "provider": "P", "choices": [{"delta": {"content": "Hel"}}]},
  {"choices": [{"delta": {"content": "lo", "tool_calls": [{"index": 0, "id": "c2", "function": {"name": "grep", "arguments": "{\"pat"}}]}}]},
  {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "tern\":\"x\",\"path\":\"w\"}"}}]}, "finish_reason": "tool_calls"}]},
  {"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 7, "prompt_tokens_details": {"cached_tokens": 60}, "cost": 0.01}},
]) + "data: [DONE]\n\n"
resp, sent = run_adapter(backends.ChatBackend, {}, chat_stream)
check("chat request maps tool results", any(x.get("role") == "tool" and x.get("tool_call_id") == "c1" for x in sent["body"]["messages"]))
check("chat parses text and tool call", resp.text == "Hello" and resp.tool_calls[0]["args"] == {"pattern": "x", "path": "w"})
check("chat stop and usage", resp.stop == "tool_calls" and resp.usage["cache_read"] == 60 and resp.usage["input"] == 40)
check("chat keeps stream lines", any("Hel" in x for x in resp.lines) and resp.provider == "P")

filt = "".join(f"data: {json.dumps(o)}\n\n" for o in [
  {"model": "m1", "choices": [{"delta": {"content": "partial"}}]},
  {"choices": [{"delta": {}, "finish_reason": "content_filter"}]}])
resp, _ = run_adapter(backends.ChatBackend, {}, filt)
check("chat content_filter is filtered, text kept", resp.stop == "filtered" and resp.text == "partial")

msg_stream = "".join(f"event: {o['type']}\ndata: {json.dumps(o)}\n\n" for o in [
  {"type": "message_start", "message": {"id": "msg1", "model": "claude-x", "usage": {"input_tokens": 5, "cache_read_input_tokens": 50, "output_tokens": 1}}},
  {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
  {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Partial answer"}},
  {"type": "content_block_stop", "index": 0},
  {"type": "message_delta", "delta": {"stop_reason": "refusal", "stop_details": {"type": "refusal", "category": "cyber"}}, "usage": {"output_tokens": 42}},
  {"type": "message_stop"}])
resp, sent = run_adapter(backends.MessagesBackend, {}, msg_stream)
check("messages request: tool_result block, cache_control on last",
      sent["body"]["messages"][-1]["content"][-1].get("cache_control") == {"type": "ephemeral"}
      and sent["body"]["messages"][-1]["content"][0]["type"] == "tool_result")
check("messages refusal is filtered with details and partial text",
      resp.stop == "filtered" and resp.stop_details["category"] == "cyber" and resp.text == "Partial answer"
      and resp.usage["output"] == 42 and resp.request_id == "req2")

tool_stream = "".join(f"event: {o['type']}\ndata: {json.dumps(o)}\n\n" for o in [
  {"type": "message_start", "message": {"id": "msg2", "model": "claude-x", "usage": {"input_tokens": 5}}},
  {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tu1", "name": "read_file", "input": {}}},
  {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\": \"wo"}},
  {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "rk/a\"}"}},
  {"type": "content_block_stop", "index": 0},
  {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}}])
resp, _ = run_adapter(backends.MessagesBackend, {}, tool_stream)
check("messages tool_use parsed", resp.stop == "tool_calls" and resp.tool_calls[0]["args"] == {"path": "work/a"}
      and resp.raw[0]["input"] == {"path": "work/a"})

sys.exit(1 if fails else 0)
