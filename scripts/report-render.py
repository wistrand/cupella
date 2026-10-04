#!/usr/bin/env python3
"""Render reports/<name>.json (report-build.py) as reports/<name>.md. Reads nothing else.

The markdown is a view of the JSON: never edit it; edit the sources and rebuild
(./cupella report-build.py <name>, which runs this after building). The structure is
design-report.md's. Values from the APK are printed in code spans, shortened. A markdown
report that was not rendered (no marker line) is never overwritten without --replace.

./cupella runs this in a container that sees only the JSON and the markdown file.

Usage: ./cupella report-render.py <name> [--replace] [--stdout]
Output: reports/<name>.md
"""
import json
import os
import re
import sys


ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MARK = "<!-- rendered by scripts/report-render.py from reports/%s.json (built from reports/%s/ and work/%s/facts.json): edit the sources, then rerun ./cupella report-build.py %s -->"
DATA_APIS = {"ANDROID_ID", "device model", "phone identifiers", "location", "contacts", "SMS read", "call log",
             "clipboard", "camera", "microphone", "installed apps", "crypto", "Base64"}
MAX_ROWS = 60


def code(s, n=100):
  """an APK-derived value as a code span"""
  s = re.sub(r"[^\x20-\x7e]", "?", str(s)).replace("`", "'")
  s = s if len(s) <= n else s[:n] + "..."
  return "`%s`" % s


def cell(s, n=120):
  s = re.sub(r"[^\x20-\x7e]", "?", str(s)).replace("|", "\\|").replace("`", "'")
  return s if len(s) <= n else s[:n] + "..."


def table(head, rows):
  if not rows:
    return []
  out = ["| %s |" % " | ".join(head), "|%s|" % "|".join("-" * (len(h) + 2) for h in head)]
  out += ["| %s |" % " | ".join(r) for r in rows]
  return out


def render(rep):
  """markdown of a report JSON (format cupella-report/1)"""
  if rep.get("format") != "cupella-report/1":
    raise ValueError("not a cupella-report/1 JSON")
  name = rep["name"]
  ns, threats = dict(rep["notes"]), rep["threat_notes"]
  f = rep["facts"] if rep.get("facts_present") else {}
  idn = f.get("identity", {})
  out = ["# %s" % rep["title"], "", MARK % (name, name, name, name), ""]

  def sec(h, body, empty=None):
    """a section: generated body, then the agent's notes; with facts but no rows, the
    empty text says what was searched"""
    out.append("## " + h)
    body = [x for x in body]
    if not body and f and empty:
      body = [empty]
    if ns.get(h):
      if body:
        body.append("")
      body.append(ns[h])
    out.extend(body if body else ["not reached"])
    out.append("")

  sec("Summary", [])

  rows = [[k, code(idn[k], 120)] for k in ("file", "sha256", "size", "package", "versionName", "versionCode",
                                           "minSdkVersion", "targetSdkVersion", "compileSdkVersion") if idn.get(k)]
  sec("Identity", table(["Field", "Value"], rows) + (["", "Source: `triage.txt` \"Identity\"."] if rows else []))

  sg = f.get("signing", {})
  body = []
  for c in sg.get("certs", []):
    body += table(["Field", "Value"], [["Subject", code(c.get("subject", ""), 160)],
                                       ["Issuer", code(c.get("issuer", ""), 160)],
                                       ["Validity", cell("%s to %s" % (c.get("valid_from", "?"), c.get("valid_to", "?")))],
                                       ["Key, algorithm", cell("%s, %s" % (c.get("key", "?"), c.get("algorithm", "?")))],
                                       ["SHA-256", code(c.get("sha256", ""))]]) + [""]
  if sg:
    body.append("Schemes: %s. Verification (`scripts/apksig-verify.py`, jarsigner): %s (`triage.txt` \"Signing\")." % (
      ", ".join(sg.get("schemes", [])) or "none found", "; ".join(cell(re.sub(r"^=>\s*", "", x)) for x in sg.get("verification", [])) or "no result"))
    body.append("A verified signature shows the APK is unchanged since it was signed with this key; it does not identify the signer.")
  sec("Signing", body)

  cov = f.get("coverage", {})
  body = []
  if f:
    tools = f.get("tools", {})
    body.append("- Tools: %s (`triage.txt` \"Tool results\")." % ", ".join(
      "%s %s" % (k, cell(v, 40)) for k, v in tools.items() if k in ("jadx", "apktool", "apkid", "quark", "ghidra")))
    body.append("- %s; %s." % (", ".join(cell(x) for x in cov.get("dex", [])[:3]) or "dex: not found",
                                "; ".join(cell(x) for x in cov.get("tool_results", []))))
    if cov.get("jadx_retry"):
      body.append("- jadx failures retried in simple mode (`jadx-retry/INDEX.txt`): %s." % "; ".join(
        cell(x.split(" -> ")[0]) for x in cov["jadx_retry"][:10]))
    if cov.get("class_coverage"):
      body.append("- Class coverage: %s" % cell(cov["class_coverage"][0], 200))
    if cov.get("framework"):
      body.append("- Framework markers: %s; app logic is outside the dex (%s). Behavior facts cover Java and "
                  "Kotlin code only." % (", ".join(code(x, 60) for x in cov["framework"]),
                                         ", ".join("`%s`" % x for x in cov.get("framework_outputs", [])) or "no framework output"))
    if cov.get("apkid"):
      body.append("- APKiD: %s (`apkid.txt`)." % "; ".join(cell(x) for x in cov["apkid"][:6]))
    for k, v in (cov.get("anti_analysis") or {}).items():
      body.append("- %s: %s (`triage.txt`)." % (k, "; ".join(cell(x) for x in v[:6])))
    if cov.get("encrypted_left"):
      body.append("- Files that look encrypted, not decrypted by script (`encrypted-left.txt`): %s." % "; ".join(
        code(x, 80) for x in cov["encrypted_left"][:6]))
    dec = f.get("decryption", {})
    if dec.get("notes"):
      body.append("- Decryption stage ran: `decrypt/NOTES.md`; outputs %s." % (", ".join(
        "`%s`" % o["file"] for o in dec.get("outputs", [])) or "none"))
    if dec.get("children"):
      body.append("- Child samples: %s." % ", ".join("`%s`" % c for c in dec["children"]))
    b = f.get("behavior", {})
    body.append("- Scan scope: %s (`scan.txt`); call graph depth %s for behavior facts." % (
      ", ".join("`%s`" % s for s in b.get("scope", [])) or "none", b.get("depth", "?")))
    n = rep["claims_summary"]
    ver = n.get("verified", 0)
    body.append("- Claims: %d confirmed, %d draft, %d rejected; %d with a verification verdict (`reports/%s/claims.jsonl`)." % (
      n["confirmed"], n["draft"], n["rejected"], ver, name))
  sec("Analysis coverage", body)

  perms = f.get("permissions", {})
  rows = []
  for p in perms.get("requested", []):
    used = "; ".join("%s at %s" % (u["api"], ", ".join("`%s`" % r for r in u["refs"][:3])) for u in p.get("used_by", []))
    rows.append([code(p["name"]), cell(p.get("level") or "app or unknown"), used or "no listed API found"])
  body = table(["Permission", "Level", "Used by (listed APIs)"], rows)
  if perms:
    body.append("")
    body.append("Source: `manifest.xml`, `behavior-facts.txt` \"Permission gates\". \"No listed API found\" means "
                "none of the APIs behavior-facts.py looks for, not that nothing uses it.")
    if perms.get("named_not_requested"):
      body.append("")
      body.append("Named in code but not requested (`scan.txt`; a name in a list or table is not a check, "
                  "and a feature behind a real check fails):")
      body += ["- %s" % cell(x, 200) for x in perms["named_not_requested"][:15]]
  sec("Permissions", body, "None requested (`manifest.xml`).")

  b = f.get("behavior", {})
  comps = b.get("components", [])
  # exported, launcher, and missing classes first; the rest counted when there are many
  key = lambda c: (not (c["launcher"] or c["exported"] in ("true", "implicit") or "NOT" in c["class"]), )
  ordered = sorted(comps, key=key)
  shown_c = [c for c in ordered if not key(c)[0]] + [c for c in ordered if key(c)[0]][:max(0, 25 - sum(1 for c in ordered if not key(c)[0]))]
  rows = [[code(c["name"]), cell(c["kind"]), cell(c["exported"] or "-"), "yes" if c["launcher"] else "-",
           cell(", ".join(dict.fromkeys(c.get("actions", [])[:8])) or "-"), cell(c["class"])] for c in shown_c]
  body = table(["Component", "Kind", "Exported", "Launcher", "Actions", "Class"], rows)
  if len(shown_c) < len(comps):
    body += ["", "%d more components, not exported and with classes in the dex (`behavior-facts.txt`)." % (len(comps) - len(shown_c))]
  if b.get("launcher_missing"):
    body += ["", "The launcher activity's class is not in the dex of the sample or its children: unless code "
                 "loaded at runtime supplies it, the app cannot start from the launcher."]
  if f.get("app_flags"):
    body += ["", "Application flags (`manifest-summary.txt`): %s." % "; ".join(code(x, 80) for x in f["app_flags"])]
  if rows:
    body += ["", "Source: `%s`, `dex/classes.txt` (`behavior-facts.txt` \"Components and the dex\")." % (b.get("manifest") or "manifest.xml")]
  sec("Components", body, "None declared (`manifest.xml`).")

  net = f.get("network", {})
  rows = [[code(h["host"], 60), ", ".join(code(u, 80) for u in h["urls"][:4]),
           ", ".join("`%s`" % r for r in h["refs"][:3]) or "dex strings only"] for h in net.get("hosts", [])[:40]]
  body = table(["Host", "URLs", "Where (scan scope)"], rows)
  if net and not rows:
    body = ["No hosts in the scan scope or in dex strings (`scan.txt`)."]
  if net:
    nsc = net.get("nsc") or {}
    if nsc:
      body += ["", "Network security config `%s`: cleartext %s; user CAs %s; pins %s." % (
        nsc["path"], "allowed for all hosts" if nsc.get("cleartext_base") else
        ("allowed for %s" % ", ".join(code(d, 60) for d in nsc["cleartext_domains"]) if nsc.get("cleartext_domains") else "not allowed by the config"),
        "trusted" if nsc.get("user_certs") else "not trusted", "present" if nsc.get("pins") else "none")]
    body += ["", "TLS overrides in scope: %s. Pinning code in scope: %s (`scan.txt`)." % (
      "%d lines" % len(net["tls_overrides"]) if net.get("tls_overrides") else "none",
      "%d lines" % len(net["pinning"]) if net.get("pinning") else "none")]
  sec("Network", body)

  lib = f.get("libraries", {})
  body = []
  if lib:
    body.append("Largest packages by class count (`triage.txt`): %s." % ", ".join(code(x, 60) for x in lib.get("packages", [])[:15]))
    body.append("")
    body.append("Tracker SDK code (`trackers.txt`): %s. Tracker domains without SDK code: %s." % (
      ", ".join(cell(x) for x in lib.get("tracker_sdks", [])) or "none",
      ", ".join(cell(x) for x in lib.get("tracker_domains", [])) or "none"))
  sec("Third-party libraries", body, "No package or tracker data (`triage.txt`, `trackers.txt`).")

  gate = {g["api"]: ("requested" if g["requested"] else "**not requested**") for g in b.get("gates", [])}
  rows = [[cell(e["api"]), "`%s`" % e["at"], cell(e["func"]), gate.get(e["api"], "no permission")]
          for e in b.get("entries", [])
          if e["api"] in DATA_APIS and not (e["kind"].startswith("callback") and e["merged"])]
  seen, uniq = set(), []
  for r in rows:
    if (r[0], r[1]) not in seen:
      seen.add((r[0], r[1]))
      uniq.append(r)
  body = table(["Data API", "Where", "Reached from", "Permission"], uniq[:30])
  if uniq:
    body += ["", "Reached from an entry point in the call graph, library code included (`behavior-facts.txt`); "
                 "\"not requested\" means the call fails as shipped."]
  sec("Data handling", body, "No identifier, location, contact, SMS, clipboard, camera, microphone, or crypto API "
                             "found reached from an entry point (`behavior-facts.txt`).")

  nat = f.get("native", {})
  body = []
  if nat.get("none"):
    body.append("None: the APK ships no native libraries (`native-summary.txt`).")
  elif nat:
    body.append("ABIs: %s (`native-summary.txt`)." % "; ".join(cell(x) for x in nat.get("abis", [])))
    body.append("")
    body += table(["Library", "Identified", "File"], [[code(l["name"], 60), cell(l.get("identified", ""), 100),
                                                      cell(l.get("file", ""), 100)] for l in nat.get("libraries", [])])
  sec("Native code", body, "No native summary (`native-summary.txt`).")

  body = []
  if b:
    body += ["Generated by `facts.py` (`behavior-facts.txt` has the full lists). Facts about the code, not findings. "
             "Entry points are manifest component callbacks, JavaScript interface methods, and callbacks no scanned "
             "code calls (the last only with chains that avoid merged lambda classes). A chain is the call graph's "
             "shortest path; reflection and library listeners are not in it. `*` marks a merged lambda class "
             "(one class for several lambdas, switching on a constructor argument): the step holds only when the "
             "caller created it with the matching case, so check it in the code.", ""]
    rows = []
    for e in b.get("entries", []):
      if e["kind"].startswith("callback") and e["merged"]:
        continue
      rows.append(["%s (`%s`)" % (code(e["func"], 60), e["ref"]), cell(e["kind"]), cell(e["api"]),
                   "`%s`%s" % (e["at"], " (bytecode)" if e["bytecode"] else ""), cell(" > ".join(e["chain"]) or "-", 200)])
    body += table(["Entry point", "Kind", "API", "Where", "Chain"], rows[:MAX_ROWS])
    if len(rows) > MAX_ROWS:
      body += ["", "%d more rows in `behavior-facts.txt`." % (len(rows) - MAX_ROWS)]
    msgs = b.get("messages", [])
    if msgs:
      body += ["", "Message keys in classes that use a network API:", ""]
      body += table(["Function", "Writes", "Reads", "Compares"], [
        ["%s (`%s`)" % (code(m["func"], 60), m["ref"])] + [", ".join(code(k, 40) for k in m[x]) or "-" for x in ("writes", "reads", "compares")]
        for m in msgs[:30]])
    wv = b.get("webview", {})
    if wv.get("interfaces") or wv.get("js_methods"):
      body += ["", "WebView JavaScript interfaces: %s; methods the page can call: %s." % (
        ", ".join("%s at `%s`" % (code(i["name"], 40), i["ref"]) for i in wv.get("interfaces", [])) or "none found",
        ", ".join("%s (`%s`)" % (code(m["func"], 60), m["ref"]) for m in wv.get("js_methods", [])) or "none found")]
    un = b.get("unreached", [])
    if un:
      body += ["", "Using a listed API but reached from no entry point (%d; dead code, reflection, or a library listener):" % len(un), ""]
      body += ["- %s (`%s`): %s" % (code(u["func"], 60), u["ref"], cell(", ".join(u["apis"]))) for u in un[:15]]
  sec("Behavior facts", body, "No entry point reaches a listed API (`behavior-facts.txt`).")

  # findings
  out.append("## Findings")
  if ns.get("Findings"):
    out += [ns["Findings"], ""]
  groups = list(dict.fromkeys(c.get("threat") or "" for c in rep["findings"]))

  def finding(c):
    lines = ["%d. **%s** (%s). %s" % (c["number"], c["title"].rstrip("."), c["id"], c["claim"])]
    for e in c.get("evidence", []):
      if "ref" in e:
        lines.append("   - `%s`%s" % (e["ref"], " quote: %s" % code(e["quote"], 120) if e.get("quote") else ""))
      else:
        row = e.get("row")
        if row:
          lines.append("   - %s (`%s`) reaches %s at `%s`%s" % (
            code(row["func"], 60), row["ref"], cell(row["api"]), row["at"],
            " via %s" % cell(" > ".join(row["chain"]), 200) if row["chain"] else ""))
        else:
          lines.append("   - %s reaching %s: not in facts.json" % (code(e["entry"]), cell(e.get("api", ""))))
    lines.append("   - Gate: %s" % c["gate"])
    meta = []
    if c.get("class"):
      meta.append("Class: %s" % c["class"])
    if c.get("attack"):
      meta.append("ATT&CK Mobile: %s" % ", ".join(c["attack"]))
    meta.append("Confidence: `%s`" % c["confidence"])
    lines.append("   - %s" % ". ".join(meta))
    for x in c.get("inferred") or []:
      lines.append("   - Inferred: %s" % x)
    v = c.get("verdict")
    if v:
      lines.append("   - Verification (%s): %s%s%s" % (v.get("by", "verify"), v["result"], ": %s" % v["note"] if v.get("note") else "",
                                                 " (%s)" % ", ".join("`%s`" % r for r in v.get("refs", [])[:4]) if v.get("refs") else ""))
    return lines

  for t in groups:
    if t:
      out += ["### %s" % t, ""]
      if threats.get(t):
        out += [threats[t], ""]
    for c in rep["findings"]:
      if (c.get("threat") or "") == t:
        out += finding(c)
    out.append("")
  if rep["drafts"]:
    out += ["### Not yet confirmed", "", "Draft claims: written, key steps not yet checked in the code.", ""]
    for c in rep["drafts"]:
      out += finding(c)
    out.append("")
  if not rep["findings"] and not rep["drafts"] and not ns.get("Findings"):
    out += ["not reached", ""]

  # indicators: only when a claim maps to ATT&CK (a malicious or suspected sample) or notes add some
  ind = rep["indicators"]
  if ind is not None:
    rows = [[r["type"], code(r["value"], 160), "dex strings (`scan.txt`)" if r["source"].startswith("dex strings")
             else "`%s`" % r["source"]] for r in ind]
    body = table(["Type", "Value", "Source"], rows)
    sec("Indicators", body)
  else:
    sec("Indicators", ["Not applicable: no claim maps to an ATT&CK technique and notes add none."])

  sec("Open questions", [])
  if "Method changes" not in ns:
    ns["Method changes"] = "None."
  sec("Method changes", [])
  if ns.get("Outside references"):
    sec("Outside references", [])
  return "\n".join(out).rstrip("\n") + "\n"


def main():
  args = sys.argv[1:]
  replace, stdout = "--replace" in args, "--stdout" in args
  for flag in ("--replace", "--stdout"):
    if flag in args:
      args.remove(flag)
  if len(args) != 1:
    sys.exit(__doc__)
  name = args[0]
  json_path = os.path.join(ROOT, "reports", name + ".json")
  if not os.path.isfile(json_path) or not os.path.getsize(json_path):
    sys.exit("no reports/%s.json: run ./cupella report-build.py %s" % (name, name))
  out_path = os.path.join(ROOT, "reports", name + ".md")
  if not stdout and os.path.isfile(out_path) and os.path.getsize(out_path) and not replace:
    with open(out_path, errors="replace") as fh:
      head = fh.read(4000)
    if "rendered by scripts/report-render.py" not in head:
      sys.exit("reports/%s.md was not rendered (written by hand): rerun with --replace to overwrite it" % name)
  with open(json_path) as fh:
    rep = json.load(fh)
  try:
    text = render(rep)
  except (ValueError, KeyError, TypeError) as e:
    sys.exit("reports/%s.json: cannot render (%s)" % (name, e))
  if stdout:
    sys.stdout.write(text)
    return
  with open(out_path, "w") as fh:
    fh.write(text)
  print("rendered reports/%s.md" % name)


if __name__ == "__main__":
  main()
