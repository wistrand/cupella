#!/usr/bin/env python3
"""Facts about a sample as data: the script-owned half of a report.

Collects what the scripts established (triage, manifest, signing, tools, coverage, hosts,
libraries, native code, decryption outputs, and the behavior facts of behavior-facts.py)
into one JSON file. report-render.py turns it into the report's tables; the agent writes
only claims and notes (reports/<name>/), never these values. Every item names the file it
came from, relative to work/<name>/.

Strings in it come from the APK and are untrusted: report-render.py prints them in code
spans, shortened.

Usage: ./cupella facts.py <name> [java-scope ...]   (scan.sh runs it last)
Output: work/<name>/facts.json
"""
import json
import os
import re
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCHEMA = 1
# hosts of XML namespaces and format specs, not contacted by an app
NAMESPACE_HOSTS = {"schemas.android.com", "www.w3.org", "xmlpull.org", "ns.adobe.com", "xml.org",
                   "www.apache.org", "apache.org", "purl.org", "json-schema.org"}
URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>()\\]+")


def read(work, rel):
  path = os.path.join(work, rel)
  if not os.path.isfile(path):
    return None
  with open(path, errors="replace") as f:
    return f.read()


def sections(text):
  """{heading: [lines]} of a '## ' sectioned text file (first occurrence of each heading)"""
  out, cur = {}, None
  for line in (text or "").split("\n"):
    if line.startswith("## "):
      cur = line[3:].strip()
      out.setdefault(cur, [])
      continue
    if cur is not None:
      out[cur].append(line)
  return out


def section(secs, prefix):
  for k, v in secs.items():
    if k.startswith(prefix):
      return [x for x in v if x.strip()]
  return []


def bullets(lines):
  return [x[2:].strip() for x in lines if x.startswith("- ")]


def identity(tri):
  out = {}
  for line in section(tri, "Identity"):
    m = re.match(r"^(file|size|sha256):\s+(.*)$", line)
    if m:
      out[m.group(1)] = m.group(2).strip()
    m = re.search(r'(?:android:)?(versionCode|versionName|compileSdkVersion|minSdkVersion|targetSdkVersion)="([^"]*)"', line)
    if m:
      out[m.group(1)] = m.group(2)
    m = re.match(r'^package="([^"]*)"', line.strip())
    if m:
      out["package"] = m.group(1)
  if "file" in out:
    out["file"] = re.sub(r"^/repo/", "", out["file"])
  return out


def signing(tri):
  lines = section(tri, "Signing")
  certs, cur = {}, None
  for line in lines:
    s = line.strip()
    if s.startswith("Owner:"):
      cur = {"subject": s[6:].strip()}
    elif cur is not None and s.startswith("Issuer:"):
      cur["issuer"] = s[7:].strip()
    elif cur is not None and s.startswith("Valid from:"):
      m = re.match(r"Valid from:\s*(.*?)\s+until:\s*(.*)$", s)
      if m:
        cur["valid_from"], cur["valid_to"] = m.group(1), m.group(2)
    elif cur is not None and s.startswith("SHA256:"):
      cur["sha256"] = s[7:].strip().replace(":", "").lower()
    elif cur is not None and s.startswith("Signature algorithm name:"):
      cur["algorithm"] = s.split(":", 1)[1].strip()
    elif cur is not None and s.startswith("Subject Public Key Algorithm:"):
      cur["key"] = s.split(":", 1)[1].strip()
      if cur.get("sha256"):
        certs.setdefault(cur["sha256"], cur)
      cur = None
  schemes = []
  if any(x.startswith("-- v1") for x in lines):
    schemes.append("v1")
  for line in lines:
    m = re.match(r"^(v[234](?:\.1)?): (\d+) certificate", line.strip())
    if m and int(m.group(2)) > 0:
      schemes.append(m.group(1))
  verify = [x.strip() for x in lines if x.strip().startswith(("=>", "RESULT:")) or "jarsigner:" in x]
  return {"certs": list(certs.values()), "schemes": schemes, "verification": verify, "source": "triage.txt"}


def tools_and_coverage(work, tri):
  tools, notes = {}, []
  for line in section(tri, "Tool results"):
    m = re.match(r"^([a-z][\w-]*)\s+(\S.*)$", line)
    if m and not line.startswith("finished"):
      tools[m.group(1)] = m.group(2).strip()
    else:
      notes.append(line.strip())  # "apktool: decoded", "jadx: N java files", error counts
  cov = {"tool_results": notes, "source": "triage.txt"}
  m = re.search(r"count: (\d+)", " ".join(notes))
  cov["jadx_errors"] = int(m.group(1)) if m else 0
  cov["class_coverage"] = section(tri, "Class coverage")[:3]
  dex = section(tri, "Dex")
  cov["dex"] = [x for x in dex if x.startswith("classes:")] + [re.sub(r"/repo/work/[^/]+/", "", x) for x in dex if x.endswith(".dex")]
  idx = read(work, "jadx-retry/INDEX.txt")
  cov["jadx_retry"] = [re.sub(r"work/[^/]+/", "", x) for x in bullets((idx or "").split("\n"))]
  cov["apkid"] = [x.strip() for x in section(tri, "APKiD") if x.strip()]
  cov["encrypted_left"] = bullets(section(tri, "Files that look encrypted"))
  cov["embedded"] = [x for x in section(tri, "Embedded code found") if x.strip() and x.strip() != "none"]
  cov["framework"] = [x[len("found: "):] for x in section(tri, "Framework markers") if x.startswith("found: ")]
  cov["framework_outputs"] = [d for d in ("flutter-summary.txt", "dart", "hermes") if os.path.exists(os.path.join(work, d))]
  cov["anti_analysis"] = {k: bullets(v) for k, v in tri.items()
                          if re.match(r"(ZIP anomalies|Symlink|Tool time limits)", k) and bullets(v)}
  return tools, cov


def permissions(work, rep, scan):
  import android_perms
  try:
    levels = android_perms.levels()
  except Exception:  # noqa: BLE001 - the framework list is optional
    levels = {}
  used = {}
  for lab, perms, ok, where in rep["gates"]:
    for p in perms:
      used.setdefault(p, []).append({"api": lab, "refs": where[:4]})
  req = []
  for p in rep["requested"]:
    lvl = levels.get(p)
    req.append({"name": p, "level": android_perms.describe(lvl) if lvl is not None else "",
                "used_by": used.get(p, [])})
  missing = bullets(section(scan, "Permissions the code names but the manifest does not request"))
  return {"requested": req, "named_not_requested": missing, "source": "manifest.xml, scan.txt"}


def network(work, ms, scan):
  hosts = {}

  def add(url, where):
    try:
      h = urlparse(url).hostname or ""
    except ValueError:
      return
    # a host, not a fragment of a string the scan cut ("https://ex"): dotted name, IP, or localhost
    if h and h not in NAMESPACE_HOSTS and re.match(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$|^localhost$", h):
      d = hosts.setdefault(h, {"host": h, "urls": [], "refs": [], "url_refs": {}})
      if url not in d["urls"] and len(d["urls"]) < 6:
        d["urls"].append(url)
      if where and where not in d["refs"] and len(d["refs"]) < 4:
        d["refs"].append(where)
      if where and url in d["urls"]:
        d["url_refs"].setdefault(url, where)
  for line in section(scan, "URLs"):
    m = re.match(r"^([\w/$.-]+\.java):(\d+):", line)
    for u in URL.findall(line):
      add(u.rstrip(".,;"), "%s:%s" % (m.group(1), m.group(2)) if m else "")
  for title in ("URLs in all dex strings", "URLs in resources.arsc"):
    for line in section(scan, title):
      for u in URL.findall(line):
        add(u.rstrip(".,;"), "")
  nsc = {}
  for line in section(ms, "Application flags"):
    m = re.match(r"^- networkSecurityConfig = @xml/([\w.]+)$", line.strip())
    if m:
      rel = "apktool/res/xml/%s.xml" % m.group(1)
      text = read(work, rel) or ""
      nsc = {"path": rel,
             "cleartext_base": bool(re.search(r"<base-config[^>]*cleartextTrafficPermitted=\"true\"", text)),
             "cleartext_domains": re.findall(r"<domain[^>]*>([^<]+)</domain>", text)[:10]
             if re.search(r"<domain-config[^>]*cleartextTrafficPermitted=\"true\"", text) else [],
             "user_certs": 'src="user"' in text,
             "pins": "<pin-set" in text}
  return {"hosts": sorted(hosts.values(), key=lambda d: (not d["refs"], d["host"])),
          "nsc": nsc,
          "tls_overrides": section(scan, "TLS overrides")[:10],
          "pinning": section(scan, "Pinning")[:10],
          "source": "scan.txt"}


def libraries(work, tri):
  tr = sections(read(work, "trackers.txt"))
  return {"packages": [x.strip() for x in section(tri, "Packages by class count")][:25],
          "tracker_sdks": bullets(section(tr, "Tracker SDK code present")),
          "tracker_domains": bullets(section(tr, "Tracker domains")),
          "source": "triage.txt, trackers.txt"}


def native(work):
  text = read(work, "native-summary.txt") or ""
  if "No native libraries" in text:
    return {"none": True, "source": "native-summary.txt"}
  ns = sections(text)
  libs, cur = [], None
  for line in text.split("\n"):
    if line.startswith("### "):
      cur = {"name": line[4:].strip()}
      libs.append(cur)
    elif cur is not None and line.startswith("- identified by"):
      cur["identified"] = line[2:].strip()
    elif cur is not None and "sha256" in line and line.startswith("- "):
      cur["file"] = line[2:].strip()
    elif cur is not None and line.startswith("- toolchain:"):
      cur["toolchain"] = line[len("- toolchain:"):].strip()
  return {"none": False, "abis": bullets(section(ns, "ABIs")), "libraries": libs[:30],
          "load_sites": bullets(section(ns, "Java load sites"))[:15], "source": "native-summary.txt"}


def decryption(work, name):
  out = {}
  notes = read(work, "decrypt/NOTES.md")
  if notes is not None:
    out["notes"] = "decrypt/NOTES.md"
    files = []
    for line in (read(work, "decrypt/outputs.txt") or "").split("\n"):
      parts = line.split("\t")
      if parts and parts[0]:
        files.append({"file": "decrypt/out/" + parts[0], "kind": parts[1] if len(parts) > 1 else "",
                      "child": parts[3] if len(parts) > 3 and parts[3] != "-" else ""})
    out["outputs"] = files
  base = os.path.dirname(work.rstrip("/"))
  out["children"] = sorted(d for d in os.listdir(base)
                           if re.match(re.escape(name) + r"(?:\.(?:dec|emb)\d+)+$", d))
  return out


def behavior(rep, bf):
  def u2(u):
    return {"func": bf.short(u), "ref": bf.cite(u)}
  entries = []
  for u, kind, found in rep["entries"]:
    for lab in sorted(found, key=lambda x: (len(found[x][0]), x)):
      path, line, how = found[lab]
      entries.append(dict(u2(u), kind=kind, api=lab, at=bf.cite(path[-1][0], line), bytecode=bool(how),
                          chain=[("%s%s" % (m, bf.short(x))) for x, m in path[1:]],
                          merged=any(bf.merged(x) for x, _m in path[1:])))
  return {
    "scope": rep["scopes"], "depth": rep["depth"], "manifest": rep["manifest"],
    "components": [{"name": c["name"], "kind": c["kind"], "exported": c["exported"], "launcher": c["launcher"],
                    "actions": c["actions"][:8], "permission": c["permission"], "class": c["status"]}
                   for c in rep["comps"]],
    "launcher_missing": rep["missing_launcher"],
    "entries": entries,
    "unreached": [dict(u2(u), apis=[h[0] for h in rep["hits"][u.id]]) for u in rep["unreached"]],
    "gates": [{"api": lab, "needs": perms, "requested": ok, "refs": where[:4]} for lab, perms, ok, where in rep["gates"]],
    "messages": [dict(u2(u), writes=list(p), reads=list(g), compares=list(c)) for u, p, g, c in rep["messages"]],
    "webview": {"interfaces": [{"name": n, "ref": r} for n, r in rep["ifaces"]],
                "js_methods": [u2(u) for u in rep["js"]],
                "calls": [dict(u2(u), rows=rows[:12]) for u, rows in rep["wv"]][:20]},
    "source": "behavior-facts.txt",
  }


def main():
  if len(sys.argv) < 2:
    sys.exit(__doc__)
  name, scopes = sys.argv[1], sys.argv[2:] or None
  work = os.path.join(ROOT, "work", name)
  if not os.path.isdir(work):
    sys.exit("work/%s not found" % name)
  bf = units.load_script("behavior-facts.py")
  text, rep = bf.compute(name, scopes)
  with open(os.path.join(work, "behavior-facts.txt"), "w") as f:
    f.write(text)
  tri = sections(read(work, "triage.txt"))
  scan = sections(read(work, "scan.txt"))
  ms = sections(read(work, "manifest-summary.txt"))
  tools, cov = tools_and_coverage(work, tri)
  facts = {
    "schema": SCHEMA, "name": name,
    "identity": identity(tri),
    "signing": signing(tri),
    "tools": tools,
    "coverage": cov,
    "app_flags": bullets(section(ms, "Application flags")),
    "permissions": permissions(work, rep, scan),
    "network": network(work, ms, scan),
    "libraries": libraries(work, tri),
    "native": native(work),
    "decryption": decryption(work, name),
    "behavior": behavior(rep, bf),
    "scan": {"family_markers": [x for x in section(scan, "Known family markers") if x.startswith("- ")][:20],
             "injection": [x for x in section(scan, "Text addressed to AI agents") if x.strip()][:20],
             "scope": [x for x in (read(work, "scan.txt") or "").split("\n")[:4] if x.startswith("scope")]},
  }
  with open(os.path.join(work, "facts.json"), "w") as f:
    json.dump(facts, f, indent=1, ensure_ascii=True)
    f.write("\n")
  print("wrote work/%s/facts.json and behavior-facts.txt" % name)


if __name__ == "__main__":
  main()
