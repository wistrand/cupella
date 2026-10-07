#!/usr/bin/env python3
# The store helper of the API harness in volume mode (agent_docs/store-volumes.md): runs
# in a container that sees the workspace's data/ (read-only) and work/ (read-write) under
# ROOT, and answers one JSON request per line on stdin with one JSON line on stdout. It
# does resolution and file I/O only; the harness on the host keeps the policy and asks
# only for paths it has checked. Started by `./cupella store-serve` (harness/store.py).
#
#   store_helper.py ROOT          ROOT is /repo in the container
#
# Request: {"op": <name>, ...}. Response: {"ok": <result>} or {"error": <text>, "errno": <name>}.
# Every path is relative to ROOT. Paths for I/O must be in data/ or work/ and already
# resolved: one that resolves elsewhere now (a link swapped in since) is refused.
import errno
import json
import os
import pathlib
import re
import stat as st
import sys
import time

AREAS = ("data", "work")
MAX_TEXT = 64 << 20


class Refused(Exception):
  pass


def main():
  root = os.path.realpath(sys.argv[1] if len(sys.argv) > 1 else "/repo")

  def joined(rel):
    # ROOT/rel without following links; never above ROOT
    if not isinstance(rel, str) or not rel or "\x00" in rel or rel.startswith("/"):
      raise Refused("bad path")
    p = os.path.normpath(os.path.join(root, rel))
    if p != root and not p.startswith(root + os.sep):
      raise Refused("outside the store")
    return p

  def to_rel(p):
    return "." if p == root else os.path.relpath(p, root).replace(os.sep, "/")

  def exact(rel, area=AREAS):
    # a resolved path in data/ or work/ that still resolves to itself
    p = joined(rel)
    if to_rel(p).split("/")[0] not in area:
      raise Refused(f"{rel}: not in {' or '.join(area)}/")
    if os.path.realpath(p) != p:
      raise Refused(f"{rel}: resolves elsewhere now (a link); resolve it again")
    return p

  def kind(p, follow):
    try:
      s = os.stat(p) if follow else os.lstat(p)
    except OSError:
      return "-", 0, 0
    k = "l" if st.S_ISLNK(s.st_mode) else "d" if st.S_ISDIR(s.st_mode) else "f" if st.S_ISREG(s.st_mode) else "o"
    return k, s.st_size, s.st_mtime

  def is_binary(p):
    if not os.path.isfile(p):
      raise Refused(f"{to_rel(p)}: not a regular file")
    with open(p, "rb") as f:
      return b"\x00" in f.read(8192)

  def op_resolve(path):
    p = os.path.realpath(joined(path))
    return to_rel(p) if p == root or p.startswith(root + os.sep) else None

  def op_stat(rel, follow=True):
    k, size, mtime = kind(joined(rel), follow)
    return {"type": k, "size": size, "mtime": mtime}

  def op_list(rel):
    p = exact(rel)
    return [[n, os.path.isdir(os.path.join(p, n))] for n in sorted(os.listdir(p))]

  def op_glob(rel, pattern, limit=2000):
    p = exact(rel)
    if pattern.startswith("/") or ".." in pattern.split("/"):
      raise Refused("the glob must stay below the directory")
    out = []
    for q in pathlib.Path(p).glob(pattern):
      qa = os.path.realpath(q)
      if qa != root and not qa.startswith(root + os.sep):
        continue
      out.append([to_rel(qa), q.is_dir()])
      if len(out) >= limit:
        break
    return out

  def op_walk(rel, limit=500000):
    # files below a directory, sorted, links not followed: [rel, size, is_link]
    p = exact(rel)
    out = []
    for d, dirs, names in os.walk(p):
      dirs.sort()
      for n in sorted(names):
        f = os.path.join(d, n)
        link = os.path.islink(f)
        try:
          size = 0 if link else os.path.getsize(f)
        except OSError:
          continue
        out.append([to_rel(f), size, link])
        if len(out) >= limit:
          return out
    return out

  def op_read(rel, offset=1, limit=2000, maxline=2000):
    p = exact(rel)
    if is_binary(p):
      return {"binary": True}
    lines, total = [], 0
    with open(p, encoding="utf-8", errors="replace") as f:
      for i, line in enumerate(f, 1):
        total = i
        if offset <= i < offset + limit:
          line = line.rstrip("\n")
          if len(line) > maxline:
            line = line[:maxline] + " [line truncated]"
          lines.append(line)
    return {"binary": False, "lines": lines, "total": total}

  def op_text(rel):
    p = exact(rel)
    if not os.path.isfile(p):
      raise Refused(f"{rel}: not a regular file")
    if os.path.getsize(p) > MAX_TEXT:
      raise Refused(f"{rel}: larger than {MAX_TEXT >> 20} MB")
    with open(p, encoding="utf-8") as f:
      return f.read()

  def op_binary(rel):
    return is_binary(exact(rel))

  def op_grep(files, pattern, ignore_case=False, max_hits=200, seconds=120, max_size=20 << 20):
    rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    hits, deadline, timed_out = [], time.time() + seconds, False
    for rel in files:
      if len(hits) >= max_hits:
        break
      if time.time() > deadline:
        timed_out = True
        break
      try:
        p = exact(rel)
      except Refused:
        continue
      if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > max_size or is_binary(p):
        continue
      with open(p, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
          if rx.search(line):
            hits.append([rel, i, line.rstrip()[:300]])
            if len(hits) >= max_hits:
              break
    return {"hits": hits, "timeout": timed_out}

  def parents(rel):
    # create the parent directories of rel in work/, none of them a link
    parts = rel.split("/")
    if parts[0] != "work" or len(parts) < 2 or "" in parts or "." in parts or ".." in parts:
      raise Refused(f"{rel}: writes go to a resolved path in work/")
    for i in range(2, len(parts)):
      d = "/".join(parts[:i])
      p = joined(d)
      if os.path.islink(p):
        raise Refused(f"{d}: is a link")
      if not os.path.isdir(p):
        os.mkdir(p)
    exact("/".join(parts[:-1]) if len(parts) > 2 else parts[0], ("work",))

  def op_write(rel, text, append=False):
    parents(rel)
    p = joined(rel)
    if os.path.realpath(os.path.dirname(p)) != os.path.dirname(p):
      raise Refused(f"{rel}: its directory resolves elsewhere now")
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(p, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      f.write(text)
    return len(text)

  def op_mkdir(rel):
    parents(rel + "/x")
    return True

  def op_move(src, dst):
    # rename within work/ (model-compare moves a sample's agent outputs aside and back);
    # the source may be a link (it is moved, not followed), the target must not exist
    sp = src.split("/")
    if sp[0] != "work" or len(sp) < 2 or "" in sp or "." in sp or ".." in sp:
      raise Refused(f"{src}: moves are within work/")
    exact("/".join(sp[:-1]), ("work",))
    s = joined(src)
    if not os.path.lexists(s):
      raise FileNotFoundError(errno.ENOENT, "no such file", src)
    parents(dst)
    d = joined(dst)
    if os.path.lexists(d):
      raise Refused(f"{dst}: exists")
    os.rename(s, d)
    return True

  ops = {"resolve": op_resolve, "stat": op_stat, "list": op_list, "glob": op_glob, "walk": op_walk,
         "read": op_read, "text": op_text, "binary": op_binary, "grep": op_grep, "write": op_write,
         "mkdir": op_mkdir, "move": op_move, "ping": lambda: "pong"}
  for line in sys.stdin:
    try:
      req = json.loads(line)
      fn = ops[req.pop("op")]
      out = {"ok": fn(**req)}
    except Refused as e:
      out = {"error": str(e), "errno": "EREFUSED"}
    except OSError as e:
      out = {"error": e.strerror or str(e), "errno": errno.errorcode.get(e.errno, "EIO")}
    except Exception as e:  # noqa: BLE001 - one bad request must not end the helper
      out = {"error": f"{type(e).__name__}: {e}", "errno": "EINVAL"}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
  main()
