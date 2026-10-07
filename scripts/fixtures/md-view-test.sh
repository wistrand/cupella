#!/usr/bin/env bash
# Checks that md-view.py never passes terminal control from a file to the terminal:
# CSI and OSC sequences (title, OSC 8 hyperlinks), C1 controls, BEL, bidi overrides,
# and invisible characters, in a paragraph, a heading, a code span, a fenced block, a
# table cell, a quote, a list item, and a link. Writes a throwaway file in
# work/_mdview-fixture/, renders it with and without colors, prints PASS or FAIL per
# case, and removes it.
#
# Usage: ./cupella fixtures/md-view-test.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
w="$root/work/_mdview-fixture"
rm -rf "$w"
mkdir -p "$w"
cd "$root"
python3 - "$w/in.md" <<'PY'
import sys
E, ST = "\x1b", "\x1b\\"
bad = {
  "csi": E + "[2J", "osc-title": E + "]0;pwned\x07", "osc8": E + "]8;;http://evil.example/" + ST + "click" + E + "]8;;" + ST,
  "c1-csi": "\u009b31m", "bidi": "\u202eexe.txt\u202c", "isolate": "\u2066x\u2069", "zero-width": "a\u200bb",
}
lines = ["# Head " + bad["csi"], "", "para " + bad["osc-title"] + " " + bad["c1-csi"] + " " + bad["zero-width"], "",
         "`code " + bad["csi"] + "`", "", "```", "block " + bad["osc8"], "```", "",
         "| a | b |", "|---|---|", "| " + bad["bidi"] + " | " + bad["isolate"] + " |", "",
         "> quote " + bad["csi"], "", "- item " + bad["osc-title"], "",
         "[label " + bad["csi"] + "](http://x.example/" + bad["c1-csi"] + ")", "", "<https://y.example/>", ""]
open(sys.argv[1], "w", encoding="utf-8").write("\n".join(lines))
PY
MDVIEW_COLOR=1 COLUMNS=100 python3 scripts/md-view.py "work/_mdview-fixture/in.md" > "$w/color.txt"
python3 scripts/md-view.py --plain "work/_mdview-fixture/in.md" > "$w/plain.txt"
python3 - "$w/color.txt" "$w/plain.txt" <<'PY'
import re
import sys
color = open(sys.argv[1], encoding="utf-8").read()
plain = open(sys.argv[2], encoding="utf-8").read()


def check(name, ok):
  print(f"{name}: {'PASS' if ok else 'FAIL'}")


rest = re.sub(r"\x1b\[[0-9;]*m", "", color)
check("color output: only SGR sequences", "\x1b" not in rest)
check("plain output: no ESC", "\x1b" not in plain)
# the color output without its own SGR sequences: nothing else may remain
for text, tag in ((rest, "color"), (plain, "plain")):
  check(f"{tag}: no C0 or C1 control but newline", not re.search(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", text))
  check(f"{tag}: no bidi or invisible characters", not re.search("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff]", text))
check("ESC shown as a marker", plain.count("<U+001B>") >= 8)
check("C1 CSI shown as a marker", "<U+009B>" in plain)
check("BEL shown as a marker", "<U+0007>" in plain)
check("bidi override shown as a marker", "<U+202E>" in plain and "<U+2066>" in plain)
check("zero-width space shown as a marker", "a<U+200B>b" in plain)
check("link as text and address", "(http://x.example/<U+009B>31m)" in plain)
check("no terminal hyperlink", "]8;" not in color.replace("<U+001B>]8;", ""))
check("table rendered", "┌" in plain and "<U+202E>exe.txt<U+202C>" in plain)
PY
rm -rf "$w"
