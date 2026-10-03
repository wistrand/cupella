#!/usr/bin/env python3
"""Benchmark comparison with other analyzers (MobSF, Quark-Engine): APK lists to scan,
and their findings turned into the formats the agent benchmarks score.

The tools run through ./cupella mobsf-scan.py and ./cupella quark-scan.sh and leave their
reports in work/<app>/tools/. This script does the rest:

  lists           write work/_tools/ghera.txt and maleval.txt: the APKs to scan (the
                  118 Ghera apps of the blinded run, the 25 MalEval samples of the
                  agent run)
  ghera <tool>    one verdict per blinded app id, work/_ghera-blind/<tool>-verdicts/
                  <id>.json, in the agents' verdict format: every finding the tool
                  reports becomes a "vulnerability". Score them with the unchanged
                  procedure: bench-ghera-score.py packets <seed> <tool>-verdicts
                  <tool>-score, the scorer agents, then tally <tool>-score.
  maleval <tool>  the tool's findings per sample as text, work/_maleval-agent/
                  <tool>-findings/<sha>.md, for classifier agents
                  (prompts/bench/tool-maleval-classify.md) that map them to MalEval's
                  behavior classes without seeing the labels; score their verdicts
                  with bench-maleval-agent.py -v verdicts-<tool>.

What counts as reported, per tool:
  mobsf  every finding in code, manifest, network security, certificate, and binary
         analysis with a severity other than secure, good, or info-only hotspots
  quark  every rule ("crime") matched at 100% confidence (all five stages)

Usage: ./cupella bench-tools.py lists | ghera <tool> | maleval <tool>
"""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORK = os.path.join(ROOT, "work")
SKIP_SEV = {"secure", "good"}


def mobsf_findings(rep):
  out = []
  code = (rep.get("code_analysis") or {}).get("findings") or {}
  for rid, f in code.items():
    md = f.get("metadata") or {}
    sev = (md.get("severity") or "").lower()
    if sev in SKIP_SEV:
      continue
    files = list((f.get("files") or {}).keys())[:4]
    out.append({"title": md.get("description") or rid, "category": md.get("cwe", ""), "severity": sev,
                "where": ", ".join(files)})
  man = (rep.get("manifest_analysis") or {}).get("manifest_findings") or []
  for f in man:
    sev = (f.get("severity") or "").lower()
    if sev in SKIP_SEV:
      continue
    out.append({"title": f.get("title") or f.get("rule", ""), "category": "manifest", "severity": sev,
                "where": ", ".join(map(str, f.get("component") or [])) if isinstance(f.get("component"), list) else str(f.get("component", "")),
                "description": (f.get("description") or "")[:400]})
  net = (rep.get("network_security") or {}).get("network_findings") or []
  for f in net:
    sev = (f.get("severity") or "").lower()
    if sev in SKIP_SEV:
      continue
    out.append({"title": f.get("description", "")[:300], "category": "network security config", "severity": sev,
                "where": ", ".join(f.get("scope") or [])})
  cert = (rep.get("certificate_analysis") or {}).get("certificate_findings") or []
  for f in cert:
    if isinstance(f, list) and len(f) >= 3 and str(f[0]).lower() not in SKIP_SEV:
      out.append({"title": f[2], "category": "certificate", "severity": str(f[0]).lower(), "description": str(f[1])[:300]})
  binf = rep.get("binary_analysis") or []
  if isinstance(binf, list):
    for b in binf:
      for k, v in (b.items() if isinstance(b, dict) else []):
        if isinstance(v, dict) and (v.get("severity") or "").lower() in ("high", "warning"):
          out.append({"title": "%s: %s" % (b.get("name", "binary"), v.get("description", k))[:300],
                      "category": "binary", "severity": v.get("severity")})
  return out


def quark_findings(rep):
  out = []
  for c in rep.get("crimes") or []:
    conf = str(c.get("confidence", "")).rstrip("%")
    if conf != "100":
      continue
    apis = c.get("native_api") or []
    out.append({"title": c.get("crime", ""), "category": ", ".join(c.get("label") or []),
                "where": "; ".join("%s.%s" % (a.get("class", ""), a.get("method", "")) for a in apis[:2]),
                "rule": c.get("rule", "")})
  return out


TOOLS = {"mobsf": ("mobsf.json", mobsf_findings), "quark": ("quark.json", quark_findings)}


def read_report(app, tool):
  fn, conv = TOOLS[tool]
  p = os.path.join(WORK, app, "tools", fn)
  if not os.path.isfile(p):
    return None
  with open(p, errors="replace") as f:
    try:
      return conv(json.load(f))
    except (ValueError, AttributeError) as e:
      sys.stderr.write("%s: unreadable %s report (%s)\n" % (app, tool, e))
      return None


def maleval_paths():
  sel = json.load(open(os.path.join(WORK, "_maleval-agent", "selection.json")))
  paths = {}
  for split in ("benign", "malradar", "new"):
    d = os.path.join(ROOT, "data", "maleval", split)
    if os.path.isdir(d):
      for f in os.listdir(d):
        paths[f[:-4]] = "data/maleval/%s/%s" % (split, f)
  return [(sha, paths.get(sha)) for sha in sel["order"]]


def main():
  args = sys.argv[1:]
  if not args:
    sys.exit(__doc__)
  if args[0] == "lists":
    os.makedirs(os.path.join(WORK, "_tools"), exist_ok=True)
    key = json.load(open(os.path.join(WORK, "_ghera-blind", "key.json")))
    gh = sorted({"data/ghera/%s.apk" % v["app"] for v in key.values()})
    open(os.path.join(WORK, "_tools", "ghera.txt"), "w").write("\n".join(gh) + "\n")
    mv = [p for _s, p in maleval_paths() if p]
    open(os.path.join(WORK, "_tools", "maleval.txt"), "w").write("\n".join(mv) + "\n")
    print("work/_tools/ghera.txt: %d APKs; work/_tools/maleval.txt: %d APKs" % (len(gh), len(mv)))
    return
  mode, tool = args[0], args[1] if len(args) > 1 else ""
  if tool not in TOOLS:
    sys.exit("tool must be one of: %s" % ", ".join(TOOLS))
  if mode == "ghera":
    key = json.load(open(os.path.join(WORK, "_ghera-blind", "key.json")))
    out = os.path.join(WORK, "_ghera-blind", tool + "-verdicts")
    os.makedirs(out, exist_ok=True)
    n = missing = total = 0
    for bid, v in sorted(key.items()):
      fs = read_report(v["app"], tool)
      if fs is None:
        missing += 1
        continue
      with open(os.path.join(out, bid + ".json"), "w") as f:
        json.dump({"app": bid, "tool": tool, "vulnerabilities": fs}, f, indent=1)
      n += 1
      total += len(fs)
    print("%s: %d verdicts in work/_ghera-blind/%s-verdicts/ (%d findings, %.1f per app); %d apps without a report" % (
      tool, n, tool, total, total / max(n, 1), missing))
  elif mode == "maleval":
    out = os.path.join(WORK, "_maleval-agent", tool + "-findings")
    os.makedirs(out, exist_ok=True)
    n = missing = 0
    for sha, path in maleval_paths():
      fs = read_report(sha, tool)
      if fs is None:
        missing += 1
        continue
      lines = ["# %s findings for sample %s" % (tool, sha), ""]
      for f in fs:
        lines.append("- %s%s%s" % (f["title"], " [%s]" % f["category"] if f.get("category") else "",
                                    " (%s)" % f["where"] if f.get("where") else ""))
      open(os.path.join(out, sha + ".md"), "w").write("\n".join(lines) + "\n")
      n += 1
    print("%s: %d finding lists in work/_maleval-agent/%s-findings/; %d samples without a report" % (tool, n, tool, missing))
  else:
    sys.exit(__doc__)


if __name__ == "__main__":
  main()
