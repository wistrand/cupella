# File access of the Cupella harness (agent_docs/store-volumes.md). Every tool and the
# harness's own logs go through a Store with paths relative to the workspace:
#   HostStore    the workspace's directories on the host (the default)
#   VolumeStore  a workspace made with `./cupella setup --store volume`: data/ and work/
#                are Docker volumes, reached through helper containers
#                (harness/store_helper.py, `./cupella store-serve`); everything else
#                (reports/, docs, prompts, proposals/) is on the host
# The policy (harness/policy.py) stays on the host: a store only resolves paths and does
# I/O on paths the policy has passed.
import fnmatch
import json
import os
import pathlib
import re
import subprocess
import tempfile
import threading
import time

AREAS = ("data", "work")


class StoreError(OSError):
  pass


class Refused(StoreError):
  # the helper refused the path (outside the store, or not resolved)
  pass


def area_of(rel):
  return rel.split("/")[0] in AREAS


def store_mode(ws):
  try:
    with open(os.path.join(ws, ".cupella-workspace"), encoding="utf-8") as f:
      for line in f:
        if line.startswith("store="):
          return line.strip().partition("=")[2] or "host"
  except OSError:
    pass
  return "host"


def make(ws, cupella, env):
  if store_mode(ws) == "volume":
    return VolumeStore(ws, [cupella, "store-serve"], env)
  return HostStore(ws)


class HostStore:
  # the host file system under ws
  def __init__(self, ws):
    self.ws = os.path.realpath(ws)
    self.mode = "host"

  def p(self, rel):
    return self.ws if rel in (".", "") else os.path.join(self.ws, rel)

  def to_rel(self, a):
    return "." if a == self.ws else os.path.relpath(a, self.ws).replace(os.sep, "/")

  def resolve(self, path):
    # -> the resolved path relative to ws, or None when it leaves ws
    a = os.path.realpath(path if os.path.isabs(path) else os.path.join(self.ws, path))
    if a != self.ws and not a.startswith(self.ws + os.sep):
      return None
    return self.to_rel(a)

  def is_link(self, path):
    return os.path.islink(path if os.path.isabs(path) else os.path.join(self.ws, path))

  def stat(self, rel):
    try:
      s = os.stat(self.p(rel))
    except OSError:
      return {"type": "-", "size": 0, "mtime": 0}
    t = "d" if os.path.isdir(self.p(rel)) else "f" if os.path.isfile(self.p(rel)) else "o"
    return {"type": t, "size": s.st_size, "mtime": s.st_mtime}

  def exists(self, rel):
    return self.stat(rel)["type"] != "-"

  def isdir(self, rel):
    return self.stat(rel)["type"] == "d"

  def isfile(self, rel):
    return self.stat(rel)["type"] == "f"

  def listdir(self, rel):
    a = self.p(rel)
    return [(n, os.path.isdir(os.path.join(a, n))) for n in sorted(os.listdir(a))]

  def glob(self, rel, pattern, limit=2000):
    out = []
    for q in pathlib.Path(self.p(rel)).glob(pattern):
      qa = os.path.realpath(q)
      if qa != self.ws and not qa.startswith(self.ws + os.sep):
        continue
      out.append((self.to_rel(qa), q.is_dir()))
      if len(out) >= limit:
        break
    return out

  def walk(self, rel):
    # files below a directory, sorted, links not followed: (rel, size, is_link)
    out = []
    for d, dirs, names in os.walk(self.p(rel)):
      dirs.sort()
      for n in sorted(names):
        f = os.path.join(d, n)
        link = os.path.islink(f)
        try:
          size = 0 if link else os.path.getsize(f)
        except OSError:
          continue
        out.append((self.to_rel(f), size, link))
    return out

  def is_binary(self, rel):
    with open(self.p(rel), "rb") as f:
      return b"\x00" in f.read(8192)

  def read_lines(self, rel, offset, limit, maxline=2000):
    if self.is_binary(rel):
      return {"binary": True}
    lines, total = [], 0
    with open(self.p(rel), encoding="utf-8", errors="replace") as f:
      for i, line in enumerate(f, 1):
        total = i
        if offset <= i < offset + limit:
          line = line.rstrip("\n")
          if len(line) > maxline:
            line = line[:maxline] + " [line truncated]"
          lines.append(line)
    return {"binary": False, "lines": lines, "total": total}

  def read_text(self, rel):
    with open(self.p(rel), encoding="utf-8") as f:
      return f.read()

  def grep(self, files, pattern, ignore_case=False, max_hits=200, seconds=120, max_size=20 << 20):
    rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    hits, deadline, timed_out = [], time.time() + seconds, False
    for rel in files:
      if len(hits) >= max_hits:
        break
      if time.time() > deadline:
        timed_out = True
        break
      a = self.p(rel)
      if os.path.islink(a) or not os.path.isfile(a) or os.path.getsize(a) > max_size or self.is_binary(rel):
        continue
      with open(a, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
          if rx.search(line):
            hits.append((rel, i, line.rstrip()[:300]))
            if len(hits) >= max_hits:
              break
    return hits, timed_out

  def write_text(self, rel, text, append=False):
    a = self.p(rel)
    os.makedirs(os.path.dirname(a), exist_ok=True)
    with open(a, "a" if append else "w", encoding="utf-8") as f:
      f.write(text)

  def append_text(self, rel, text):
    self.write_text(rel, text, append=True)

  def mkdir(self, rel):
    os.makedirs(self.p(rel), exist_ok=True)

  def lexists(self, rel):
    return os.path.lexists(self.p(rel))

  def move(self, src, dst):
    # rename; the target must not exist
    if os.path.lexists(self.p(dst)):
      raise StoreError(f"{dst}: exists")
    os.makedirs(os.path.dirname(self.p(dst)), exist_ok=True)
    os.rename(self.p(src), self.p(dst))

  def close(self):
    pass


class Helper:
  # one helper process: a container running store_helper.py, one request at a time
  def __init__(self, cmd, env, cwd):
    self.err = tempfile.TemporaryFile()
    # a session of its own: Ctrl-C in the harness must not end the helper before the
    # harness has written its last records
    self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                 env=env, cwd=cwd, start_new_session=True)
    if self.call({"op": "ping"}) != "pong":
      raise StoreError("the store helper did not answer")

  def stderr_tail(self):
    self.err.seek(0)
    return self.err.read().decode("utf-8", "replace").strip()[-500:]

  def call(self, req):
    try:
      self.proc.stdin.write((json.dumps(req) + "\n").encode())
      self.proc.stdin.flush()
      line = self.proc.stdout.readline()
    except (BrokenPipeError, OSError):
      line = b""
    if not line:
      self.close()
      raise StoreError(f"the store helper ended: {self.stderr_tail() or 'no output'}")
    r = json.loads(line)
    if "error" in r:
      if r.get("errno") == "ENOENT":
        raise FileNotFoundError(2, r["error"])
      raise (Refused if r.get("errno") == "EREFUSED" else StoreError)(r["error"])
    return r["ok"]

  def alive(self):
    return self.proc.poll() is None

  def close(self):
    try:
      self.proc.stdin.close()
    except OSError:
      pass
    try:
      self.proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
      self.proc.kill()


class VolumeStore:
  # data/ and work/ through helpers (a small pool, so parallel subagents do not wait on
  # each other's grep); every other path on the host
  def __init__(self, ws, cmd, env=None, max_helpers=6):
    self.ws = os.path.realpath(ws)
    self.mode = "volume"
    self.host = HostStore(self.ws)
    self.cmd, self.env, self.max = list(cmd), env, max_helpers
    self.idle, self.n = [], 0
    self.cv = threading.Condition()
    self.closed = False
    self.put(self.start())  # fail at once when the helper cannot start

  def start(self):
    with self.cv:
      self.n += 1
    try:
      return Helper(self.cmd, self.env, self.ws)
    except Exception:
      with self.cv:
        self.n -= 1
        self.cv.notify()
      raise

  def put(self, h):
    with self.cv:
      if h.alive() and not self.closed:
        self.idle.append(h)
      else:
        self.n -= 1
        h.close()
      self.cv.notify()

  def call(self, op, **kw):
    with self.cv:
      while not self.idle and self.n >= self.max:
        self.cv.wait()
      h = self.idle.pop() if self.idle else None
    if h is None:
      h = self.start()
    try:
      return h.call({"op": op, **kw})
    finally:
      self.put(h)

  def rel_of(self, path):
    if not isinstance(path, str) or not path or "\x00" in path:
      return None
    if os.path.isabs(path):
      if path == self.ws:
        return "."
      if not path.startswith(self.ws + "/"):
        return None
      path = path[len(self.ws) + 1:]
    # "." and empty components change nothing; ".." is left for resolution
    return "/".join(c for c in path.split("/") if c not in ("", ".")) or "."

  def resolve(self, path):
    rel = self.rel_of(path)
    if rel is None:
      return None
    if area_of(rel):
      try:
        r = self.call("resolve", path=rel)
      except Refused:
        return None
      if r is None or area_of(r):
        return r
      # left the volume through ".." or a link: the rest is a host path
      r = self.host.resolve(r)
      return None if r is None or area_of(r) else r
    r = self.host.resolve(rel)
    if r is not None and area_of(r):
      # "x/../work/..." or a host link into work/: resolve that in the volume, once
      try:
        r = self.call("resolve", path=r)
      except Refused:
        return None
      return r if r is not None and area_of(r) else None
    return r

  def is_link(self, path):
    rel = self.rel_of(path)
    if rel is None:
      return False
    if area_of(rel):
      try:
        return self.call("stat", rel=rel, follow=False)["type"] == "l"
      except StoreError:
        return False
    return self.host.is_link(rel)

  def stat(self, rel):
    if not area_of(rel):
      return self.host.stat(rel)
    try:
      return self.call("stat", rel=rel)
    except StoreError:
      return {"type": "-", "size": 0, "mtime": 0}

  def exists(self, rel):
    return self.stat(rel)["type"] != "-"

  def isdir(self, rel):
    return self.stat(rel)["type"] == "d"

  def isfile(self, rel):
    return self.stat(rel)["type"] == "f"

  def listdir(self, rel):
    if rel in (".", ""):
      # the workspace root: the host's entries plus the two volume areas
      names = {n: d for n, d in self.host.listdir(".") if n not in AREAS}
      names.update({a: True for a in AREAS})
      return sorted(names.items())
    if not area_of(rel):
      return self.host.listdir(rel)
    return [tuple(x) for x in self.call("list", rel=rel)]

  def glob(self, rel, pattern, limit=2000):
    if area_of(rel):
      return [tuple(x) for x in self.call("glob", rel=rel, pattern=pattern, limit=limit)]
    out = [x for x in self.host.glob(rel, pattern, limit) if not area_of(x[0])]
    if rel in (".", ""):
      # from the workspace root: the pattern's first component may name data/ or work/
      first, _, rest = pattern.partition("/")
      for a in AREAS:
        if first == "**":
          out.append((a, True))
          out += [tuple(x) for x in self.call("glob", rel=a, pattern=pattern, limit=limit)]
        elif fnmatch.fnmatchcase(a, first):
          if rest:
            out += [tuple(x) for x in self.call("glob", rel=a, pattern=rest, limit=limit)]
          else:
            out.append((a, True))
    return out[:limit]

  def walk(self, rel):
    if rel in (".", ""):
      out = [x for x in self.host.walk(".") if not area_of(x[0])]
      for a in AREAS:
        out += self.walk(a)
      return sorted(out)
    if not area_of(rel):
      return self.host.walk(rel)
    return [tuple(x) for x in self.call("walk", rel=rel)]

  def is_binary(self, rel):
    return self.call("binary", rel=rel) if area_of(rel) else self.host.is_binary(rel)

  def read_lines(self, rel, offset, limit, maxline=2000):
    if not area_of(rel):
      return self.host.read_lines(rel, offset, limit, maxline)
    return self.call("read", rel=rel, offset=offset, limit=limit, maxline=maxline)

  def read_text(self, rel):
    return self.call("text", rel=rel) if area_of(rel) else self.host.read_text(rel)

  def grep(self, files, pattern, ignore_case=False, max_hits=200, seconds=120, max_size=20 << 20):
    vol = [f for f in files if area_of(f)]
    t0 = time.time()
    hits, timed_out = self.host.grep([f for f in files if not area_of(f)], pattern, ignore_case,
                                     max_hits, seconds, max_size)
    if vol and len(hits) < max_hits:
      r = self.call("grep", files=vol, pattern=pattern, ignore_case=ignore_case, max_hits=max_hits - len(hits),
                    seconds=max(1, seconds - (time.time() - t0)), max_size=max_size)
      hits += [tuple(h) for h in r["hits"]]
      timed_out = timed_out or r["timeout"]
    order = {f: i for i, f in enumerate(files)}
    hits.sort(key=lambda h: (order.get(h[0], 0), h[1]))
    return hits, timed_out

  def write_text(self, rel, text, append=False):
    if not area_of(rel):
      return self.host.write_text(rel, text, append)
    self.call("write", rel=rel, text=text, append=append)

  def append_text(self, rel, text):
    self.write_text(rel, text, append=True)

  def mkdir(self, rel):
    if not area_of(rel):
      return self.host.mkdir(rel)
    self.call("mkdir", rel=rel)

  def lexists(self, rel):
    if not area_of(rel):
      return self.host.lexists(rel)
    try:
      return self.call("stat", rel=rel, follow=False)["type"] != "-"
    except StoreError:
      return False

  def move(self, src, dst):
    # a rename on one side only: within the volume (work/) or within the host
    if area_of(src) != area_of(dst):
      raise StoreError(f"{src} -> {dst}: a move between the host and the volume")
    if not area_of(src):
      return self.host.move(src, dst)
    self.call("move", src=src, dst=dst)

  def close(self):
    with self.cv:
      self.closed = True
      hs, self.idle = self.idle, []
    for h in hs:
      h.close()
