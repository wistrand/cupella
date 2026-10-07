#!/usr/bin/env python3
"""Copy named text files of one sample from work/ to exports/<name>/ on the host.

For the user: in a volume workspace (agent_docs/store-volumes.md) the files a report
cites are not on the host; this copies the ones asked for. Run only as
`./cupella export <name> <path>...`, which mounts the sample's work/ directories
read-only and exports/<name>/ as the only writable place. Agents never run it.

A path is a file or a directory under work/<name>/ or a child sample's directory
(work/<name>.emb<k>/, work/<name>.dec<k>/); a directory is copied file by file. Copied:
regular text files (no NUL byte), at most 16 MB each and 256 MB in all. Skipped and
listed: links, binary files, larger files, and files already in exports/<name>/ (never
overwritten). Files keep their path: work/<name>/x/y.txt -> exports/<name>/work/<name>/x/y.txt.

Usage: ./cupella export <name> <path>...
"""
import os
import re
import sys

MAX_FILE = 16 << 20
MAX_TOTAL = 256 << 20


def main():
  if len(sys.argv) < 3:
    sys.exit("usage: ./cupella export <name> <path>...")
  name, paths = sys.argv[1], sys.argv[2:]
  if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._()+-]*", name) or ".." in name:
    sys.exit(f"bad sample name {name!r}")
  repo = os.path.realpath("/repo")
  out = os.path.join(repo, "exports", name)
  scope = re.compile(r"work/" + re.escape(name) + r"(\.(emb|dec)\d+)*(/|$)")
  total, copied, skipped = 0, 0, []
  for arg in paths:
    rel = arg[2:] if arg.startswith("./") else arg
    rel = rel.rstrip("/")
    real = os.path.realpath(os.path.join(repo, rel))
    rr = os.path.relpath(real, repo)
    if real != os.path.normpath(os.path.join(repo, rel)) or not scope.match(rr + "/"):
      skipped.append(f"{arg}: not under work/{name}/ or its child samples (or through a link)")
      continue
    if not os.path.lexists(real):
      skipped.append(f"{arg}: no such file or directory")
      continue
    files = []
    if os.path.isdir(real):
      for d, dirs, names in os.walk(real):
        dirs.sort()
        files += [os.path.join(d, n) for n in sorted(names)]
    else:
      files = [real]
    for f in files:
      frel = os.path.relpath(f, repo)
      dst = os.path.join(out, frel)
      if os.path.islink(f) or not os.path.isfile(f):
        skipped.append(f"{frel}: a link or not a regular file")
        continue
      size = os.path.getsize(f)
      if size > MAX_FILE:
        skipped.append(f"{frel}: larger than {MAX_FILE >> 20} MB")
        continue
      if total + size > MAX_TOTAL:
        skipped.append(f"{frel}: over the {MAX_TOTAL >> 20} MB total")
        continue
      with open(f, "rb") as fh:
        data = fh.read()
      if b"\x00" in data:
        skipped.append(f"{frel}: binary")
        continue
      if os.path.lexists(dst):
        skipped.append(f"{frel}: already exported (never overwritten)")
        continue
      os.makedirs(os.path.dirname(dst), exist_ok=True)
      if not os.path.realpath(os.path.dirname(dst)).startswith(os.path.realpath(out) + os.sep):
        skipped.append(f"{frel}: its directory in exports/ is a link")
        continue
      fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
      with os.fdopen(fd, "wb") as fh:
        fh.write(data)
      total += size
      copied += 1
      print(f"exports/{name}/{frel}")
  for s in skipped:
    print(f"skipped: {s}", file=sys.stderr)
  print(f"== {copied} file(s), {total} bytes in exports/{name}/; {len(skipped)} skipped", file=sys.stderr)
  return 0 if copied or not skipped else 1


if __name__ == "__main__":
  sys.exit(main())
