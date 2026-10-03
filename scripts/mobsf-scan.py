#!/usr/bin/env python3
"""Run MobSF's static analysis on APKs, for the benchmark comparison.

Runs inside MobSF's own image (./cupella starts it offline, with the analysis limits):
starts the MobSF server on 127.0.0.1 in this container, uploads each APK through its
REST API, and writes the JSON report to work/<name>/tools/mobsf.json, where <name> is
the APK file name without .apk. APKs already scanned are skipped unless -f is given.
Standard library only; nothing leaves the container.

Usage: ./cupella mobsf-scan.py [-f] <data/...apk | list.txt> [...]
  list.txt: one APK path per line (relative to the repo root)
"""
import glob
import json
import shutil
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PORT = 8000
KEY = secrets.token_hex(32)
BASE = "http://127.0.0.1:%d" % PORT


def mobsf_dir():
  # the official image's install path; never search the file system (work/ is mounted)
  for d in ("/home/mobsf/Mobile-Security-Framework-MobSF",) + tuple(glob.glob("/home/mobsf/*/manage.py")):
    d = os.path.dirname(d) if d.endswith("manage.py") else d
    if os.path.isfile(os.path.join(d, "manage.py")):
      return d
  sys.exit("MobSF not found in this image (manage.py)")


def start():
  # MobSF writes migration files into its own code directory, which is read-only here:
  # run a copy on the container's tmpfs instead
  d = "/tmp/mobsf-app"
  if not os.path.isdir(d):
    shutil.copytree(mobsf_dir(), d, symlinks=True)
  env = dict(os.environ, MOBSF_API_KEY=KEY, MOBSF_API_ONLY="1", HOME=os.environ.get("HOME", "/tmp/home"))
  os.makedirs(env["HOME"], exist_ok=True)
  # jadx where MobSF looks for it (it would download it; ./cupella puts ours in cache/)
  jx = os.path.join(env["HOME"], ".MobSF", "tools", "jadx", "jadx-1.5.0")
  if not os.path.isdir(jx) and os.path.isdir("/cache/mobsf-jadx"):
    shutil.copytree("/cache/mobsf-jadx", jx, symlinks=True)
  log = open("/tmp/mobsf-server.log", "w")
  for args in (["manage.py", "makemigrations"], ["manage.py", "makemigrations", "StaticAnalyzer"], ["manage.py", "migrate"]):
    subprocess.run([sys.executable] + args, cwd=d, env=env, stdout=log, stderr=log)
  srv = subprocess.Popen([sys.executable, "-m", "gunicorn", "-b", "127.0.0.1:%d" % PORT, "mobsf.MobSF.wsgi:application",
                          "--workers=1", "--threads=4", "--timeout=3600"], cwd=d, env=env, stdout=log, stderr=log)
  for _ in range(180):
    try:
      urllib.request.urlopen(BASE + "/api/v1/scans?page=1", timeout=5)
    except urllib.error.HTTPError:
      return srv  # answering (401 or similar): up
    except OSError:
      time.sleep(1)
      continue
    return srv
  sys.exit("MobSF server did not start; log: /tmp/mobsf-server.log\n" + open("/tmp/mobsf-server.log").read()[-3000:])


def call(path, data=None, files=None, timeout=3600):
  headers = {"Authorization": KEY, "X-Mobsf-Api-Key": KEY}
  if files:
    boundary = secrets.token_hex(16)
    name, blob = files
    body = (b"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n" % (boundary.encode(), name.encode())) + blob + \
           b"\r\n--%s--\r\n" % boundary.encode()
    headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
  else:
    body = urllib.parse.urlencode(data or {}).encode()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
  req = urllib.request.Request(BASE + path, data=body, headers=headers)
  with urllib.request.urlopen(req, timeout=timeout) as r:
    return json.loads(r.read().decode("utf-8", "replace"))


def main():
  args = sys.argv[1:]
  force = "-f" in args
  args = [a for a in args if a != "-f"]
  if not args:
    sys.exit(__doc__)
  apks = []
  for a in args:
    if a.endswith(".txt"):
      apks += [l.strip() for l in open(os.path.join(ROOT, a)) if l.strip()]
    else:
      apks.append(a)
  todo = []
  for a in apks:
    name = os.path.basename(a)[:-4]
    out = os.path.join(ROOT, "work", name, "tools", "mobsf.json")
    if force or not os.path.isfile(out):
      todo.append((a, name, out))
  print("mobsf: %d APKs, %d to scan" % (len(apks), len(todo)), flush=True)
  if not todo:
    return
  srv = start()
  try:
    for a, name, out in todo:
      t0 = time.time()
      try:
        up = call("/api/v1/upload", files=(os.path.basename(a), open(os.path.join(ROOT, a), "rb").read()))
        call("/api/v1/scan", {"hash": up["hash"]})
        rep = call("/api/v1/report_json", {"hash": up["hash"]})
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as f:
          json.dump(rep, f)
        print("mobsf: %s %.0fs" % (name, time.time() - t0), flush=True)
      except Exception as e:  # one bad APK must not stop the batch
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out + ".error", "w") as f:
          f.write("%s: %s\n" % (type(e).__name__, e))
          try:  # the server's side of the failure
            f.write("--- server log (end)\n" + open("/tmp/mobsf-server.log", errors="replace").read()[-6000:])
          except OSError:
            pass
        print("mobsf: %s FAILED %s" % (name, e), flush=True)
  finally:
    srv.terminate()
    try:  # keep the server's log of the run
      os.makedirs(os.path.join(ROOT, "work", "_tools"), exist_ok=True)
      with open(os.path.join(ROOT, "work", "_tools", "mobsf-server.log"), "w") as f:
        f.write(open("/tmp/mobsf-server.log", errors="replace").read())
    except OSError:
      pass


if __name__ == "__main__":
  main()
