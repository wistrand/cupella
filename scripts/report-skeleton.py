#!/usr/bin/env python3
"""Write the report skeleton for a sample: the section headings of
agent_docs/design-report.md, Identity and Signing filled from triage.txt, every other
section reading "not reached" (agent_docs/workflow.md "Checkpoints").

Writes work/<name>/report-skeleton.md. unpack.sh calls it; ./cupella copies the file to
reports/<name>.md on the host when that report does not exist yet, so a container that
sees APK data never gets write access to reports/.

Usage: scripts/report-skeleton.py <name>
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"
# keep in step with agent_docs/design-report.md "Structure"; "Outside references" is
# added by the agent only when the user asks for outside research
SECTIONS = ["Summary", "Identity", "Signing", "Analysis coverage", "Permissions",
            "Components", "Network", "Third-party libraries", "Data handling",
            "Native code", "Findings", "Indicators", "Open questions", "Method changes"]


def section(text, title):
  m = re.search(r"^## %s\n(.*?)(?=^## |\Z)" % re.escape(title), text, re.M | re.S)
  return m.group(1) if m else ""


def first(pattern, text, default=None):
  m = re.search(pattern, text, re.M)
  return m.group(1).strip() if m else default


def app_label(work):
  # resolve android:label through res/values/strings.xml; None when absent or not a string
  try:
    app = ET.parse(os.path.join(work, "apktool", "AndroidManifest.xml")).getroot().find("application")
    label = app.get(A + "label") if app is not None else None
    if not label or not label.startswith("@string/"):
      return label
    strings = ET.parse(os.path.join(work, "apktool", "res", "values", "strings.xml")).getroot()
    for s in strings.iter("string"):
      if s.get("name") == label[len("@string/"):]:
        return (s.text or "").strip() or None
  except (OSError, ET.ParseError):
    pass
  return None


def cell(value):
  return (value or "not in `triage.txt`").replace("|", "\\|")


def identity(t):
  ident = section(t, "Identity")
  path = first(r"^file:\s*(.*)$", ident, "")
  path = re.sub(r"^/repo/", "", path)
  rows = [
    ("File", "`%s`" % path if path else None),
    ("SHA-256", "`%s`" % first(r"^sha256:\s*(\S+)", ident) if first(r"^sha256:\s*(\S+)", ident) else None),
    ("Size", "%s bytes" % first(r"^size:\s*(\d+)", ident) if first(r"^size:\s*(\d+)", ident) else None),
    ("Package", "`%s`" % first(r'package="([^"]+)"', ident) if first(r'package="([^"]+)"', ident) else None),
    ("versionName", first(r'versionName="([^"]*)"', ident)),
    ("versionCode", first(r'versionCode="([^"]*)"', ident)),
    ("min/target SDK", "%s / %s" % (first(r'minSdkVersion="([^"]*)"', ident, "?"),
                                    first(r'targetSdkVersion="([^"]*)"', ident, "?"))),
  ]
  w = max(len(k) for k, _ in rows)
  out = ["| %s | Value |" % "Field".ljust(w), "|%s|-------|" % ("-" * (w + 2))]
  out += ["| %s | %s |" % (k.ljust(w), cell(v)) for k, v in rows]
  out += ["", "Source: `triage.txt` \"Identity\"."]
  return "\n".join(out)


def signing(t):
  sig = section(t, "Signing")
  owner = first(r"^Owner:\s*(.*)$", sig)
  if not owner:
    return ("No certificate in `triage.txt` \"Signing\"; read that section and fill this "
            "in by hand.")
  issuer = first(r"^Issuer:\s*(.*)$", sig)
  valid = re.search(r"^Valid from:\s*(.*?)\s+until:\s*(.*)$", sig, re.M)
  sha = first(r"^\s*SHA256:\s*([0-9A-F:]+)", sig, "")
  schemes = []
  if "Owner:" in sig.split("-- APK Signing Block")[0]:
    schemes.append("v1")
  for v in ("v2", "v3", "v3.1"):
    if re.search(r"^%s: [1-9]\d* certificate" % re.escape(v), sig, re.M):
      schemes.append(v)
  verified = [l.strip().lstrip("=> ") for l in sig.splitlines() if "VERIFIED" in l or l.startswith("RESULT:")]
  rows = [
    ("Subject", "`%s`" % owner + (" (self-signed, issuer identical)" if issuer == owner else "")),
    ("Issuer", None if issuer == owner else ("`%s`" % issuer if issuer else None)),
    ("Validity", "%s to %s" % valid.groups() if valid else None),
    ("SHA-256", "`%s`" % sha.replace(":", "").lower() if sha else None),
    ("Algorithm", first(r"^Signature algorithm name:\s*(.*)$", sig)),
    ("Key", first(r"^Subject Public Key Algorithm:\s*(.*)$", sig)),
    ("Schemes", ", ".join(schemes) or None),
    ("Verification", "; ".join(verified) or None),
  ]
  rows = [(k, v) for k, v in rows if not (k == "Issuer" and v is None)]
  w = max(len(k) for k, _ in rows)
  out = ["| %s | Value |" % "Field".ljust(w), "|%s|-------|" % ("-" * (w + 2))]
  out += ["| %s | %s |" % (k.ljust(w), cell(v)) for k, v in rows]
  out += ["", "Source: `triage.txt` \"Signing\" (first certificate listed). Verification "
          "shows the APK was not changed after signing with this key; it does not show "
          "who holds the key."]
  return "\n".join(out)


def main():
  if len(sys.argv) != 2:
    sys.exit("usage: scripts/report-skeleton.py <name>")
  name = sys.argv[1]
  work = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name)
  try:
    with open(os.path.join(work, "triage.txt"), encoding="utf-8", errors="replace") as f:
      t = f.read()
  except OSError as e:
    sys.exit("report-skeleton: %s" % e)
  package = first(r'package="([^"]+)"', section(t, "Identity"), name)
  version = first(r'versionName="([^"]*)"', section(t, "Identity"), "")
  label = app_label(work)
  title = ("%s (%s)" % (label, package) if label and label != package else package)
  body = {"Identity": identity(t), "Signing": signing(t)}
  parts = ["# %s %s" % (title, version) if version else "# %s" % title, ""]
  for s in SECTIONS:
    parts += ["## %s" % s, body.get(s, "not reached"), ""]
  with open(os.path.join(work, "report-skeleton.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(parts))
  print("== wrote work/%s/report-skeleton.md" % name)


if __name__ == "__main__":
  main()
