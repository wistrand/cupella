#!/usr/bin/env python3
"""Show a markdown file on a terminal: headings, emphasis, code, lists, quotes, tables.

Reports quote strings from APKs, so the input is untrusted for a terminal: every control
character (C0, DEL, C1, which includes ESC and so every escape sequence) and every Unicode
bidirectional or invisible formatting character is shown as a visible <U+XXXX> marker,
never passed through. The only escape sequences in the output are this script's own
colors (SGR). Links are shown as text and address, never as terminal hyperlinks.

./cupella runs this in an offline container that sees reports/ read-only and work/ (for
the files a report cites); on a terminal it pages the output with less -R on the host.

Usage: ./cupella md-view.py <path.md> [--plain] [--width N]
  path     reports/<name>.md, a file under work/, or under reports/
  --plain  no colors (also when MDVIEW_COLOR is not 1, the default off a terminal, or
           when NO_COLOR is set and not empty, https://no-color.org)
"""
import os
import re
import sys
import unicodedata

# characters that change how a terminal or a reader sees the text: shown, never sent
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
INVISIBLE = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x115F, 0x1160, 0x3164, 0xFFA0}


def safe(text):
  out = []
  for ch in text:
    o = ord(ch)
    if ch == "\t":
      out.append("    ")
    elif o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F or o in BIDI or o in INVISIBLE \
        or unicodedata.category(ch) in ("Cf", "Co", "Cs", "Cn", "Zl", "Zp"):
      out.append(f"<U+{o:04X}>")
    else:
      out.append(ch)
  return "".join(out)


def width(s):
  # display columns of plain text (no escapes)
  w = 0
  for ch in s:
    if unicodedata.combining(ch):
      continue
    w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
  return w


class Style:
  def __init__(self, color):
    self.color = color

  def sgr(self, codes, s):
    return f"\x1b[{codes}m{s}\x1b[0m" if self.color and s else s

  def h(self, level, s):
    return self.sgr({1: "1;4;36", 2: "1;36", 3: "1;34"}.get(level, "1"), s)

  def bold(self, s):
    return self.sgr("1", s)

  def italic(self, s):
    return self.sgr("3", s)

  def code(self, s):
    return self.sgr("33", s)

  def dim(self, s):
    return self.sgr("2", s)

  def link(self, s):
    return self.sgr("4", s)


INLINE = re.compile(r"(`+)(.+?)\1|\*\*(.+?)\*\*|__(.+?)__|(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?!\w)"
                    r"|(?<!\w)_(?!\s)(.+?)(?<!\s)_(?!\w)|!?\[([^\]]*)\]\(([^)\s]*)(?:\s+\"[^\"]*\")?\)|<(https?://[^>\s]+)>")


def inline(s, st):
  # s is already safe(); returns the styled text and its plain form (for widths)
  out, plain, pos = [], [], 0
  for m in INLINE.finditer(s):
    out.append(s[pos:m.start()])
    plain.append(s[pos:m.start()])
    if m.group(2) is not None:
      t = m.group(2).strip() if m.group(2).strip() else m.group(2)
      out.append(st.code(t))
      plain.append(t)
    elif m.group(3) is not None or m.group(4) is not None:
      t, p = inline(m.group(3) if m.group(3) is not None else m.group(4), st)
      out.append(st.bold(t))
      plain.append(p)
    elif m.group(5) is not None or m.group(6) is not None:
      t, p = inline(m.group(5) if m.group(5) is not None else m.group(6), st)
      out.append(st.italic(t))
      plain.append(p)
    elif m.group(8) is not None:
      label, url = m.group(7), m.group(8)
      t, p = inline(label, st)
      if url and url != label:
        out.append(st.link(t) + st.dim(f" ({url})"))
        plain.append(f"{p} ({url})")
      else:
        out.append(st.link(t))
        plain.append(p)
    else:
      out.append(st.link(m.group(9)))
      plain.append(m.group(9))
    pos = m.end()
  out.append(s[pos:])
  plain.append(s[pos:])
  return "".join(out), "".join(plain)


def split_row(line):
  line = line.strip()
  if line.startswith("|"):
    line = line[1:]
  if line.endswith("|") and not line.endswith("\\|"):
    line = line[:-1]
  cells, cur, i = [], "", 0
  while i < len(line):
    if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == "|":
      cur += "|"
      i += 2
      continue
    if line[i] == "|":
      cells.append(cur.strip())
      cur = ""
    else:
      cur += line[i]
    i += 1
  cells.append(cur.strip())
  return cells


SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def table(rows, st, cols):
  head, body = rows[0], rows[2:]
  n = max(len(r) for r in [head] + body)
  cells = [[inline(c, st) for c in r + [""] * (n - len(r))] for r in [head] + body]
  w = [max(width(r[i][1]) for r in cells) for i in range(n)]
  if sum(w) + 3 * n + 1 > cols:
    # too wide for the terminal: one block per row, "column: value"
    out = []
    for r in cells[1:]:
      for i, (t, _) in enumerate(r):
        if t:
          out.append(f"  {st.bold(cells[0][i][0])}: {t}")
      out.append("")
    return out

  def line(r, bold=False):
    return "│ " + " │ ".join((st.bold(t) if bold else t) + " " * (w[i] - width(p)) for i, (t, p) in enumerate(r)) + " │"
  top = "┌" + "┬".join("─" * (x + 2) for x in w) + "┐"
  mid = "├" + "┼".join("─" * (x + 2) for x in w) + "┤"
  bot = "└" + "┴".join("─" * (x + 2) for x in w) + "┘"
  return [st.dim(top), line(cells[0], True), st.dim(mid)] + [line(r) for r in cells[1:]] + [st.dim(bot)]


def render(text, st, cols):
  lines = [safe(x) for x in text.split("\n")]
  out, i = [], 0
  while i < len(lines):
    ln = lines[i]
    fence = re.match(r"^(\s*)(`{3,}|~{3,})(.*)$", ln)
    if fence:
      mark, lang = fence.group(2), fence.group(3).strip()
      i += 1
      if lang:
        out.append(st.dim(f"  [{lang}]"))
      while i < len(lines) and not lines[i].strip().startswith(mark):
        out.append("  " + st.code(lines[i]))
        i += 1
      i += 1
      continue
    if ln.lstrip().startswith("<!--"):
      # an HTML comment (the renderer's marker line): skipped
      while i < len(lines) and "-->" not in lines[i]:
        i += 1
      i += 1
      continue
    m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", ln)
    if m:
      if out and out[-1] != "":
        out.append("")
      t, p = inline(m.group(2), st)
      out.append(st.h(len(m.group(1)), t))
      if len(m.group(1)) == 1:
        out.append(st.dim("═" * min(cols, max(width(p), 3))))
      i += 1
      continue
    if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", ln):
      out.append(st.dim("─" * min(cols, 60)))
      i += 1
      continue
    if "|" in ln and i + 1 < len(lines) and SEP.match(lines[i + 1]):
      rows = [split_row(ln), []]
      i += 2
      while i < len(lines) and "|" in lines[i] and lines[i].strip():
        rows.append(split_row(lines[i]))
        i += 1
      out += table(rows, st, cols)
      continue
    m = re.match(r"^(\s*)>\s?(.*)$", ln)
    if m:
      out.append(m.group(1) + st.dim("│ ") + inline(m.group(2), st)[0])
      i += 1
      continue
    m = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(\[[ xX]\]\s+)?(.*)$", ln)
    if m:
      ind, mark, box, rest = m.groups()
      bullet = "•" if mark in "-*+" else mark
      if box:
        bullet += " [x]" if box.strip().lower() == "[x]" else " [ ]"
      out.append(f"{ind}{st.dim(bullet) if mark in '-*+' else bullet} {inline(rest, st)[0]}")
      i += 1
      continue
    out.append(inline(ln, st)[0])
    i += 1
  while out and out[-1] == "":
    out.pop()
  return "\n".join(out) + "\n"


def main():
  args = sys.argv[1:]
  color = os.environ.get("MDVIEW_COLOR") == "1" and not os.environ.get("NO_COLOR")
  cols = int(os.environ.get("COLUMNS", "100") or 100)
  path = None
  while args:
    a = args.pop(0)
    if a == "--plain":
      color = False
    elif a == "--width" and args:
      cols = int(args.pop(0))
    elif a in ("-h", "--help"):
      print(__doc__)
      return 0
    elif path is None:
      path = a
    else:
      sys.exit("usage: ./cupella md-view.py <path.md> [--plain] [--width N]")
  if not path:
    sys.exit("usage: ./cupella md-view.py <path.md> [--plain] [--width N]")
  real = os.path.realpath(path)
  base = os.path.realpath(".")
  if not any(real.startswith(os.path.join(base, d) + os.sep) for d in ("reports", "work")):
    sys.exit(f"{path}: only files under reports/ or work/")
  if not os.path.isfile(real):
    sys.exit(f"{path}: no such file")
  if os.path.getsize(real) > 32 << 20:
    sys.exit(f"{path}: larger than 32 MB")
  with open(real, "rb") as f:
    data = f.read()
  if b"\x00" in data[:8192]:
    sys.exit(f"{path}: binary")
  sys.stdout.write(render(data.decode("utf-8", "replace"), Style(color), max(20, cols)))
  return 0


if __name__ == "__main__":
  sys.exit(main())
