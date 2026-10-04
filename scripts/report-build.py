#!/usr/bin/env python3
"""Build reports/<name>.json, the report as data, from its sources.

Sources, each with one owner:
  work/<name>/facts.json        scripts (facts.py): identity, signing, tools, coverage,
                                permissions, components, hosts, libraries, native code,
                                behavior facts
  reports/<name>/claims.jsonl   agents: one finding per line (claims-check.py documents
                                the fields)
  reports/<name>/notes.md       agent: short prose. "## <Section>" blocks (the section
                                names of design-report.md), "## Threat: <name>" blocks
                                for a threat in Findings, an optional first line
                                "# <title>"
  reports/<name>/indicators.jsonl  agent, optional: indicators the facts cannot hold
                                (decoded hosts, keys); fields in claims-check.py

The JSON (format "cupella-report/1") is the report: the facts, the findings in report
order with entry evidence resolved to its Behavior facts row, drafts, indicators, and the
notes as markdown per section. report-render.py turns it into markdown (and other
formats); nothing else reads the sources. Never edit the JSON; edit the sources.

./cupella runs this in a container that sees only facts.json, reports/<name>/ (read-only),
and the JSON file: no APK data. After building, ./cupella runs report-render.py.

Usage: ./cupella report-build.py <name> [--replace] [--stdout [--md]]
       --replace  overwrite a reports/<name>.json this script did not write
       --stdout   print the JSON instead of writing it (--md: the rendered markdown);
                  reports/<name>/ may be missing: a preview of what facts.json alone gives
Output: reports/<name>.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import units  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SECTIONS = ["Summary", "Identity", "Signing", "Analysis coverage", "Permissions", "Components", "Network",
            "Third-party libraries", "Data handling", "Native code", "Behavior facts", "Findings",
            "Indicators", "Open questions", "Method changes", "Outside references"]

def parse_notes(text):
  """(title, {section: text}, {threat: text}, [problems])"""
  title, secs, threats, problems, cur = "", {}, {}, [], None
  lines = (text or "").split("\n")
  if lines and lines[0].startswith("# "):
    title = lines.pop(0)[2:].strip()
  for line in lines:
    if line.startswith("## "):
      h = line[3:].strip()
      if h.startswith("Threat:"):
        cur = ("t", h[7:].strip())
      elif h in SECTIONS:
        cur = ("s", h)
      else:
        problems.append("notes.md: unknown section %r (use the design-report.md names or 'Threat: <name>')" % h)
        cur = None
      continue
    if cur is None:
      if line.strip():
        problems.append("notes.md: text outside a section: %r" % line[:60])
      continue
    d = secs if cur[0] == "s" else threats
    d[cur[1]] = d.get(cur[1], "") + line + "\n"
  return title, {k: v.strip() for k, v in secs.items()}, {k: v.strip() for k, v in threats.items()}, problems


JSON_FORMAT = "cupella-report/1"


def ordered(claims):
  """[(number, claim)] in report order: confirmed claims by threat (threats in order of first
  appearance), then drafts; rejected claims have no number"""
  conf = [c for c in claims if c.get("status") == "confirmed"]
  groups = list(dict.fromkeys(c.get("threat") or "" for c in conf))
  seq = [c for t in groups for c in conf if (c.get("threat") or "") == t]
  seq += [c for c in claims if c.get("status") == "draft"]
  return list(enumerate(seq, 1))


def indicators(f, claims, notes_have, added=()):
  """[{type, value, source[, note, added]}] for a malicious or suspected sample (a claim maps
  to ATT&CK, notes have an Indicators section, or the agent added some); None when not
  applicable. Agent rows (indicators.jsonl) come last, marked "added": true."""
  if not (any(c.get("attack") for c in claims if c.get("status") != "rejected") or notes_have or added):
    return None
  idn, sg = f.get("identity", {}), f.get("signing", {})
  b, net = f.get("behavior", {}), f.get("network", {})
  rows = []
  if idn.get("sha256"):
    rows.append({"type": "SHA-256 (APK)", "value": idn["sha256"], "source": "triage.txt"})
  for c in sg.get("certs", []):
    rows.append({"type": "Signer certificate SHA-256", "value": c.get("sha256", ""), "source": "triage.txt"})
    rows.append({"type": "Signer subject", "value": c.get("subject", ""), "source": "triage.txt"})
  if idn.get("package"):
    rows.append({"type": "Package", "value": idn["package"], "source": "manifest.xml"})
  for c in b.get("components", []):
    if not c["name"].startswith(("androidx.", "com.google.")):
      rows.append({"type": "Component", "value": c["name"], "source": "manifest.xml"})
  for h in net.get("hosts", [])[:30]:
    # every URL the scan scope's code names; of those only in dex strings, the first 4
    refs = h.get("url_refs") or {}
    for u in [u for u in h["urls"] if u in refs] + [u for u in h["urls"] if u not in refs][:4]:
      rows.append({"type": "URL", "value": u, "source": refs.get(u) or "dex strings (scan.txt)"})
  rows += [dict(r, added=True) for r in added]
  return rows


def export(name, facts, claims, notes, added=()):
  """the report as data"""
  f = facts or {}
  title, ns, threats, _problems = parse_notes(notes)
  b = f.get("behavior", {})
  entries = {(e["func"], e["api"]): e for e in b.get("entries", [])}

  def finding(num, c):
    d = {k: c[k] for k in ("id", "status", "threat", "title", "claim", "gate", "confidence", "class", "attack",
                           "inferred", "author", "verdict") if k in c}
    d["number"] = num
    ev = []
    for e in c.get("evidence", []):
      if "ref" in e:
        ev.append(dict(e))
      else:
        ev.append(dict(e, row=entries.get((e["entry"], e.get("api")))))
    d["evidence"] = ev
    return d
  seq = ordered(claims)
  idn = f.get("identity", {})
  return {
    "format": JSON_FORMAT,
    "generator": "scripts/report-build.py",
    "name": name,
    "title": title or ("%s %s" % (idn.get("package", name), idn.get("versionName", ""))).strip(),
    "sources": {"facts": "work/%s/facts.json" % name, "claims": "reports/%s/claims.jsonl" % name,
                "notes": "reports/%s/notes.md" % name, "indicators": "reports/%s/indicators.jsonl" % name},
    "facts_present": facts is not None,
    "facts": {k: v for k, v in f.items() if k not in ("schema", "name")},
    "findings": [finding(n, c) for n, c in seq if c.get("status") == "confirmed"],
    "drafts": [finding(n, c) for n, c in seq if c.get("status") == "draft"],
    "rejected": [c.get("id") for c in claims if c.get("status") == "rejected"],
    "claims_summary": dict({s: sum(1 for c in claims if c.get("status") == s) for s in ("confirmed", "draft", "rejected")},
                           verified=sum(1 for c in claims if c.get("verdict"))),
    "indicators": indicators(f, claims, bool(ns.get("Indicators")), added),
    "notes": ns,
    "threat_notes": threats,
    "evidence_base": "paths are relative to work/%s/ unless they start with work/ or .dec/.emb" % name,
  }



def problems_of(rep):
  """notes problems the JSON can show: threats without a confirmed claim, no Summary"""
  out = []
  groups = {c.get("threat") or "" for c in rep["findings"]}
  for t in rep["threat_notes"]:
    if t not in groups:
      out.append("notes.md: 'Threat: %s' has no confirmed claim" % t)
  if "Summary" not in rep["notes"]:
    out.append("notes.md: no Summary")
  return out


def main():
  args = sys.argv[1:]
  replace, stdout, as_md = "--replace" in args, "--stdout" in args, "--md" in args
  for flag in ("--replace", "--stdout", "--md"):
    if flag in args:
      args.remove(flag)
  if len(args) != 1:
    sys.exit(__doc__)
  name = args[0]
  src = os.path.join(ROOT, "reports", name)
  if not os.path.isdir(src) and not stdout:
    sys.exit("no reports/%s/ (claims.jsonl, notes.md): nothing to build" % name)
  json_path = os.path.join(ROOT, "reports", name + ".json")
  if not stdout and os.path.isfile(json_path) and os.path.getsize(json_path) and not replace:
    with open(json_path, errors="replace") as fh:
      if JSON_FORMAT not in fh.read(400):
        sys.exit("reports/%s.json was not written by report-build.py: rerun with --replace to overwrite it" % name)
  facts = None
  fp = os.path.join(ROOT, "work", name, "facts.json")
  if os.path.isfile(fp):
    with open(fp) as fh:
      facts = json.load(fh)
  cc = units.load_script("claims-check.py")
  claims, problems = cc.load(os.path.join(src, "claims.jsonl"))
  if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit("claims.jsonl has schema problems: not built (./cupella claims-check.py %s)" % name)
  added, ip = cc.load_indicators(os.path.join(src, "indicators.jsonl"))
  if ip:
    print("\n".join(ip), file=sys.stderr)
    sys.exit("indicators.jsonl has schema problems: not built (./cupella claims-check.py %s)" % name)
  notes = ""
  if os.path.isfile(os.path.join(src, "notes.md")):
    with open(os.path.join(src, "notes.md"), errors="replace") as fh:
      notes = fh.read()
  rep = export(name, facts, claims, notes, added)
  warn = parse_notes(notes)[3] + problems_of(rep)
  if facts is None:
    warn.append("no work/%s/facts.json: generated parts are empty (run ./cupella facts.py %s)" % (name, name))
  data = json.dumps(rep, indent=1, ensure_ascii=True) + "\n"
  if stdout:
    sys.stdout.write(units.load_script("report-render.py").render(rep) if as_md else data)
    for w in warn:
      print("warning: " + w, file=sys.stderr)
    return
  with open(json_path, "w") as fh:
    fh.write(data)
  print("built reports/%s.json (%d claims)" % (name, len(claims)))
  for w in warn:
    print("warning: " + w)


if __name__ == "__main__":
  main()
