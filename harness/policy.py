# Per-role path and command policy for the Cupella harness (agent_docs/harness-api.md).
# Every path a tool touches is resolved (realpath, by the workspace's store: the host,
# or the helper for data/ and work/ in volume mode) and checked against the role's
# allow-list after resolution, so ".." and symlinks cannot leave it. The deny list
# applies to every role and wins over every allow rule.
import fnmatch
import os
import re

from store import HostStore, StoreError

# never read, any role: samples are binary (scripts read them), answer keys, earlier
# reports and analyses, harness transcripts and refusal records, example reports, the
# user's copies out of work/ (./cupella export)
DENY_READ = [
  "data/", "bench/", "bench-sources/", "cache/", ".git/", "exports/",
  "work/_ghera-blind*/key.json", "work/_ghera-blind*/score-key.json", "work/_vulnapps/key-*",
  "reports/_archive/", "work/_previous/", "work/_stops/", "work/_harness/", "work/_bench-models/",
  "docs/examples/",
  "harness/models.json", "harness.json", ".claude/settings.local.json",
]
# never written, any role, on top of DENY_READ: the harness and the wrapper that
# enforce the policy, the agent configuration, version control
DENY_WRITE = DENY_READ + ["harness/", "cupella", ".claude/", ".cupella-workspace",
                          ".cupella-workspaces", ".cupella-decisions.tsv", "Dockerfile",
                          # the harness's own record of each session's cost (write_costs)
                          "reports/*/costs.jsonl"]
# readable although under a denied directory: the usage table the main agent cites in
# the report's "Agent setup"
ALLOW_READ_EXCEPT = ["work/_harness/*/usage.tsv"]

# ./cupella commands that are not scripts, and those the main agent may run; never
# import, export, store, store-serve, setup, shell (the user's), nor the script behind export
CUPELLA_COMMANDS = {"check", "gate", "try-proposal", "proposals", "workspaces", "versions", "help", "sync"}
USER_SCRIPTS = {"export-files.py"}
SAMPLE_RE = re.compile(r"^[A-Za-z0-9][^/\x00-\x1f]*$")


class PolicyError(Exception):
  pass


def matches(rel, pat):
  # "dir/" matches the directory and everything under it; anything else is an fnmatch
  # glob over the whole relative path. Patterns may hold globs in directory names.
  if pat == "/":
    return True
  if pat.endswith("/"):
    base, parts = pat[:-1], rel.split("/")
    return any(fnmatch.fnmatchcase("/".join(parts[:i]), base) for i in range(1, len(parts) + 1))
  return fnmatch.fnmatchcase(rel, pat)


def esc(name):
  # a sample name used inside a pattern: [, *, and ? are glob syntax
  return "".join(f"[{c}]" if c in "[*?" else c for c in name)


def sample_ok(name):
  return bool(SAMPLE_RE.match(name)) and ".." not in name


CHILD = r"(\.(emb|dec)\d+)+"


def sample_scope(name, store=None):
  # the sample's directory and its child samples' (<name>.emb<k>, <name>.dec<k>, nested)
  # as they exist now, each by its exact name: a glob such as <name>.dec* would also match
  # another sample that merely starts with it
  out = [f"work/{esc(name)}/"]
  if store is not None:
    try:
      kids = [n for n, d in store.listdir("work") if d and re.fullmatch(re.escape(name) + CHILD, n)]
    except OSError:
      kids = []
    out += [f"work/{esc(k)}/" for k in kids]
  return out


def role_commands(root, role):
  # the commands a role may run, from the "shell:" line of roles/<role>.md
  try:
    text = open(os.path.join(root, "roles", f"{role}.md"), encoding="utf-8").read()
  except OSError:
    return set()
  head = text.split("---")[1] if text.startswith("---") else ""
  for line in head.splitlines():
    k, _, v = line.partition(":")
    if k.strip() == "shell":
      return {m.group(1) for m in re.finditer(r"\./cupella\s+(\S+?)(?:,|\s|$)", v)}
  return set()


def role_body(root, role):
  text = open(os.path.join(root, "roles", f"{role}.md"), encoding="utf-8").read()
  if text.startswith("---"):
    text = text.split("---", 2)[2]
  return text.strip()


class Policy:
  def __init__(self, ws, role, read, write, commands=(), samples=(), stdout_to=(), store=None):
    self.ws = os.path.realpath(ws)
    self.store = store or HostStore(self.ws)
    self.role = role
    self.read = list(read)      # patterns; ["/"] is everything not denied
    self.write = list(write)
    self.commands = set(commands)
    self.samples = list(samples)
    self.stdout_to = list(stdout_to)
    # earlier analyses are not read (AGENTS.md): report sources and progress files last
    # written before the session started are denied, except for the sample a session
    # was started to resume (--resume)
    self.since = None
    self.resume = None

  def resolve(self, path):
    # -> the resolved path relative to the workspace
    if not isinstance(path, str) or not path or "\x00" in path:
      raise PolicyError("no path given")
    try:
      rel = self.store.resolve(path)
    except StoreError as e:
      raise PolicyError(f"{path}: could not be resolved ({e})")
    if rel is None:
      raise PolicyError(f"{path}: outside the working directory")
    return rel

  def earlier(self, rel):
    if self.since is None or not (matches(rel, "reports/") or matches(rel, "work/*/progress/")):
      return False
    parts = rel.split("/")
    if self.resume and len(parts) > 1 and re.sub(r"(\.(emb|dec)\d+)+$|\.(md|json)$", "", parts[1]) == self.resume:
      return False
    st = self.store.stat(rel)
    return st["type"] == "f" and st["mtime"] < self.since

  def can_read(self, rel, earlier=True):
    # earlier=False: whether rel would be readable if it were not from before the session
    if any(matches(rel, p) for p in ALLOW_READ_EXCEPT) and self.role == "main":
      return True
    if any(matches(rel, p) for p in DENY_READ) or (earlier and self.earlier(rel)):
      return False
    return any(matches(rel, p) for p in self.read)

  def listed_earlier(self, rel):
    # an earlier report or progress file: its name is listed, marked, so that the agent
    # does not conclude it is missing; its content stays unreadable
    return self.earlier(rel) and self.can_read(rel, earlier=False)

  def can_write(self, rel):
    if any(matches(rel, p) for p in DENY_WRITE):
      return False
    return any(matches(rel, p) for p in self.write)

  def can_list(self, rel):
    # the main agent may see the names in data/ (to pass a sample path to unpack.sh),
    # never read the files
    return self.can_read(rel) or (self.role == "main" and (rel == "data" or matches(rel, "data/")))

  def check_list(self, path):
    rel = self.resolve(path)
    if not self.can_list(rel):
      raise PolicyError(f"{rel}: not readable for the {self.role} role")
    return rel

  def check_read(self, path):
    rel = self.resolve(path)
    if self.earlier(rel):
      raise PolicyError(f"{rel}: written before this session; earlier analyses are not read (AGENTS.md "
                        "Invariants). To continue an unfinished analysis, start with --resume <name>")
    if not self.can_read(rel):
      raise PolicyError(f"{rel}: not readable for the {self.role} role")
    return rel

  def check_write(self, path):
    if isinstance(path, str) and path and self.store.is_link(path):
      raise PolicyError(f"{path}: is a link")
    rel = self.resolve(path)
    if not self.can_write(rel):
      raise PolicyError(f"{rel}: not writable for the {self.role} role; this agent may write: "
                        + (", ".join(self.write) or "nothing"))
    return rel

  def check_run(self, script, args):
    if script not in self.commands:
      if script in ("grep", "cat", "ls", "find", "head", "tail", "sed", "rg"):
        raise PolicyError(f"{script} is not a Cupella script: use the read_file, grep, and list_dir tools")
      allowed = ("a script in scripts/ or " + ", ".join(sorted(CUPELLA_COMMANDS)) if self.role == "main"
                 else ", ".join(sorted(self.commands)) or "none")
      raise PolicyError(f"./cupella {script}: not allowed for the {self.role} role (allowed: {allowed})")
    for a in args:
      if not isinstance(a, str) or any(c in a for c in "\x00\n\r"):
        raise PolicyError(f"bad argument {a!r}")
    if self.role == "main":
      if script in ("proposals",) and args[:1] == ["set"]:
        raise PolicyError("./cupella proposals set records the user's decisions: not for agents")
      if script == "workspaces" and args[:1] in (["rm"], ["--prune"], ["new"]):
        raise PolicyError("./cupella workspaces new, rm, and --prune make and delete workspaces: the user's, not for agents")
      return
    # a subagent: every path argument inside its read scope, every sample name its own
    own = set(self.samples)
    for a in args:
      if "/" in a:
        rel = self.resolve(a)
        if not self.can_read(rel):
          raise PolicyError(f"argument {a}: outside this agent's samples")
      elif sample_ok(a) and self.store.isdir(f"work/{a}"):
        base = re.sub(r"(\.(emb|dec)\d+)+$", "", a)
        if a not in own and base not in own:
          raise PolicyError(f"argument {a}: not this agent's sample")
    if script == "run-decryptor.sh" and args[:1] != self.samples[:1]:
      raise PolicyError(f"./cupella run-decryptor.sh takes this agent's sample: {self.samples[0]}")

  def describe(self):
    r = "everything except " + ", ".join(DENY_READ) if self.read == ["/"] else ", ".join(self.read)
    w = ", ".join(self.write) or "nothing"
    c = ", ".join(f"./cupella {x}" for x in sorted(self.commands)) or "none"
    lst = ("\nList: also the names in data/ (list_dir data, with a glob such as **/*.apk), to pick a sample "
           "for unpack.sh; never its contents" if self.role == "main" else "")
    return f"Read: {r}\nWrite: {w}{lst}\nCommands (run tool): {c}"


def is_workspace(ws, root):
  return os.path.realpath(ws) != os.path.realpath(root) or os.path.exists(os.path.join(ws, ".cupella-workspace"))


def main_policy(ws, root, store=None):
  scripts = {f for f in os.listdir(os.path.join(root, "scripts")) if f.endswith((".sh", ".py"))} - USER_SCRIPTS
  write = ["reports/", "work/*/progress/", "proposals/"]
  if not is_workspace(ws, root):
    write += ["scripts/", "host/", "agent_docs/", "prompts/", "roles/", "docs/", "AGENTS.md", "README.md"]
  return Policy(ws, "main", ["/"], write, scripts | CUPELLA_COMMANDS, stdout_to=["work/*/"], store=store)


def sub_policy(ws, root, role, samples, read=(), write=(), store=None):
  if role not in ("reader", "decryptor"):
    raise PolicyError(f"unknown role {role!r}: reader or decryptor")
  samples = [s for s in samples if s]
  if not samples:
    raise PolicyError("spawn needs the sample(s) the agent reads")
  for s in samples:
    if not sample_ok(s) or s.startswith("_"):
      raise PolicyError(f"bad sample name {s!r}")
  if store is None:
    store = HostStore(os.path.realpath(ws))
  rd = [p for s in samples for p in sample_scope(s, store)]
  bases = {re.sub(r"(\.(emb|dec)\d+)+$", "", s) for s in samples}
  for p in read:
    if not (p.startswith("work/") or p.startswith("reports/")) or p.rstrip("/*") in ("work", "reports"):
      raise PolicyError(f"read {p}: a subagent reads under work/<sample>/ or reports/<sample>")
    top = p.split("/")[1]
    if re.sub(r"(\.(emb|dec)\d+)+(\.md)?$|\.md$", "", top) not in bases | set(samples):
      raise PolicyError(f"read {p}: not one of this agent's samples")
    rd.append(p)
  if role == "decryptor":
    if len(samples) != 1:
      raise PolicyError("a decryptor works on exactly one sample")
    wr = [f"work/{esc(samples[0])}/decrypt/"]
    cmds = role_commands(root, "decryptor")
  else:
    wr = []
    for p in write:
      parts = p.split("/")
      if len(parts) < 3 or parts[0] != "work":
        raise PolicyError(f"write {p}: a reader writes files under work/<sample>/")
      if re.sub(r"(\.(emb|dec)\d+)+$", "", parts[1]) not in bases | set(samples):
        raise PolicyError(f"write {p}: not one of this agent's samples")
      wr.append(p)
    if not wr:
      raise PolicyError("a reader needs the files it writes (its progress file at least)")
    cmds = set()
  return Policy(ws, role, rd, wr, cmds, samples=samples, store=store)
