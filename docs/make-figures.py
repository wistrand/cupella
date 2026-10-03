#!/usr/bin/env python3
"""Regenerate the SVG figures in docs/index.html (hero, flow, layers, result charts).

The chart numbers are read from agent_docs/benchmarks.md (the "Tool comparison" table
and the decryption line), so that file is the one place to update after a benchmark
rerun; then run: python3 docs/make-figures.py. It stops if a row it needs is missing.
Each figure in index.html is replaced by its aria-labelledby id; nothing else changes.
"""
import os
import re
def esc(t): return t.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
DEFS = '''<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="s-arrowhead"/></marker><marker id="aha" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="s-arrowhead-a"/></marker></defs>'''
def box(x,y,w,h,t,m="",cls="s-box"):
  s='<rect x="%d" y="%d" width="%d" height="%d" rx="8" class="%s"/>'%(x,y,w,h,cls)
  s+='<text x="%d" y="%d" class="s-t" text-anchor="middle">%s</text>'%(x+w/2,y+h/2-(4 if m else -5),esc(t))
  if m: s+='<text x="%d" y="%d" class="s-m" text-anchor="middle">%s</text>'%(x+w/2,y+h/2+14,esc(m))
  return s
def line(pts,cls="s-line",mk="ah",dash=False):
  return '<polyline points="%s" class="%s" marker-end="url(#%s)"%s/>'%(" ".join("%d,%d"%p for p in pts),cls,mk,' stroke-dasharray="5 4"' if dash else "")
def lab(x,y,t,anchor="middle"): return '<text x="%d" y="%d" class="s-m" text-anchor="%s">%s</text>'%(x,y,anchor,esc(t))

# 0. hero: ore in; the cupel (scripts, offline) and the agent as two nodes on a loop; report out
h=['<svg viewBox="0 -46 760 290" role="img" aria-labelledby="hero-t"><title id="hero-t">What Cupella does: the APK goes into a loop between scripts in an offline container and the agent, which reads the leads and sends new runs back; a step no script covers is added to the scripts, so the next APK gets it; the report cites a file and line for each claim</title>',DEFS.replace('id="ah"','id="hah"').replace('id="aha"','id="haha"')]
def hlab(x,t,m):
  # h-lab: hidden on phones, where the same labels follow the drawing as text (.hero-steps)
  return '<text x="%d" y="214" class="h-t h-lab" text-anchor="middle">%s</text><text x="%d" y="234" class="h-m h-lab" text-anchor="middle">%s</text>'%(x,esc(t),x,esc(m))
# the APK: code, a locked payload, a native library, assets
h.append('<rect x="20" y="40" width="140" height="150" rx="10" class="s-box"/>')
for y,w in ((58,48),(74,70),(90,56)): h.append('<rect x="36" y="%d" width="%d" height="9" rx="2" class="h-ore"/>'%(y,w))
h.append('<rect x="110" y="62" width="28" height="22" rx="3" class="h-ore"/><path d="M115,62 v-6 a9,9 0 0 1 18,0 v6" class="h-stroke"/>')
h.append('<polygon points="74,135 67,147 53,147 46,135 53,123 67,123" class="h-stroke"/><text x="60" y="139" class="h-mono" text-anchor="middle">.so</text>')
for x,y,r in ((98,124,12),(118,140,-18),(104,158,8),(130,118,25)):
  h.append('<rect x="%d" y="%d" width="12" height="12" rx="2" class="h-ore" transform="rotate(%d %d %d)"/>'%(x,y,r,x+6,y+6))
h.append(hlab(90,"app.apk","code, libraries, assets"))
h.append(line([(166,112),(242,112)],mk="hah"))
# the loop: a ring through both nodes; leads over the top, re-runs back underneath
h.append('<path d="M323,55 A80,80 0 0 1 437,55" class="s-line" marker-end="url(#hah)"/><text x="380" y="52" class="h-m" text-anchor="middle">leads</text>')
h.append('<path d="M437,169 A80,80 0 0 1 323,169" class="s-accent-line" stroke-dasharray="5 4" marker-end="url(#haha)"/><text x="380" y="182" class="h-accent-t" text-anchor="middle">re-runs</text>')
# self-improvement: a step the agent needed becomes part of the scripts
h.append('<path d="M472,61 C472,-22 288,-22 288,56" class="s-accent-line" stroke-dasharray="5 4" marker-end="url(#haha)"/>')
h.append('<text x="380" y="-26" class="h-accent-t" text-anchor="middle">a missing step becomes a script</text>')
h.append('<text x="380" y="-8" class="h-m" text-anchor="middle">so the next APK gets it</text>')
# node 1: the cupel in its flame, inside the offline container
h.append('<circle cx="300" cy="112" r="54" class="h-node"/>')
h.append('<g transform="translate(300 114) scale(.6) translate(-295 -113)">')
h.append('<path d="M295,50 C320,84 354,104 352,140 C350,165 327,176 295,176 C263,176 240,165 238,140 C236,112 258,98 268,72 C276,92 283,98 286,104 C290,86 292,68 295,50 Z" class="h-flame-out"/>')
h.append('<path d="M297,92 C310,114 330,128 328,150 C326,167 312,176 295,176 C278,176 264,167 262,150 C261,134 274,124 280,110 C285,118 289,120 290,122 C293,112 295,102 297,92 Z" class="h-flame-in"/>')
h.append('<line x1="224" y1="176" x2="366" y2="176" class="s-line"/>')
for x,y,r in ((270,92,20),(292,80,-15),(314,100,35)):
  h.append('<rect x="%d" y="%d" width="10" height="10" rx="2" class="h-ore" transform="rotate(%d %d %d)"/>'%(x,y,r,x+5,y+5))
h.append('<path d="M248,176 L255,150 H335 L342,176 Z" class="h-cupel"/><path d="M265,150 Q295,174 325,150 Z" class="h-hollow"/>')
h.append('<circle cx="295" cy="156" r="5.5" class="h-gold"/></g>')
h.append(hlab(300,"unpack, scan","offline container"))
# node 2: the agent's lens over the leads, a few turned to gold
h.append('<circle cx="460" cy="112" r="54" class="h-node-a"/>')
h.append('<g transform="translate(460 112) scale(.7) translate(-492 -112)">')
lens=(498,118,27)
for cx in (454,472,490,508):
  for cy in (62,82,102,122,142,162):
    inside=(cx-lens[0])**2+(cy-lens[1])**2 < (lens[2]-6)**2
    gold=(cx,cy) in ((490,122),(508,102))
    h.append('<circle cx="%d" cy="%d" r="4.5" class="%s"/>'%(cx,cy,"h-gold" if gold else ("h-ore" if inside else "h-dot")))
h.append('<circle cx="%d" cy="%d" r="%d" class="h-lens"/><line x1="518" y1="138" x2="534" y2="156" class="h-handle"/></g>'%lens)
h.append(hlab(460,"agent investigates","traces and decrypts"))
h.append(line([(518,112),(592,112)],"s-accent-line","haha"))
h.append('<text x="555" y="102" class="h-accent-t" text-anchor="middle">findings</text>')
# the report: each claim with its citation
h.append('<path d="M600,34 h104 l26,26 v140 h-130 z" class="s-box"/><path d="M704,34 v26 h26" class="s-line"/>')
h.append('<rect x="614" y="50" width="62" height="9" rx="2" class="h-ink"/>')
for i,w in enumerate((58,46,62,40,54,50)):
  y=78+i*19
  h.append('<circle cx="618" cy="%d" r="4" class="h-gold"/><rect x="628" y="%d" width="%d" height="7" rx="2" class="h-ore"/><rect x="%d" y="%d" width="22" height="11" rx="3" class="h-cite"/>'%(y,y-3,w,634+w,y-5))
h.append(hlab(665,"reports/app.md","each claim cites file:line"))
h.append('</svg>')
hero="".join(h)

# 1. flow
f=['<svg viewBox="0 0 820 430" role="img" aria-labelledby="flow-t"><title id="flow-t">Cupella flow: the agent on the host, scripts in an offline container</title>',DEFS]
f.append('<rect x="8" y="8" width="804" height="140" rx="10" class="s-zone"/><text x="22" y="28" class="s-z">HOST</text>')
f.append(box(30,40,230,72,"Coding agent","reads leads, writes the report","s-agent"))
f.append(box(295,40,210,72,"AGENTS.md, roles, prompts","instructions and subagent rules"))
f.append(box(545,40,245,72,"reports/app.md","cite-check, verifier agent"))
f.append(line([(292,76),(263,76)]))
f.append(line([(145,40),(145,20),(667,20),(667,37)],"s-accent-line","aha"))
f.append('<text x="406" y="34" class="s-m" text-anchor="middle">writes</text>')
f.append(line([(110,112),(110,176),(328,176)]))
f.append(box(330,158,160,38,"./cupella","the only way in"))
f.append(line([(410,196),(410,226)]))
f.append(line([(700,250),(700,126),(200,126),(200,115)],"s-accent-line","aha",True))
f.append('<text x="450" y="141" class="s-m" text-anchor="middle">the agent reads work/, never the sample itself</text>')
f.append('<rect x="8" y="212" width="804" height="210" rx="10" class="s-zone"/><text x="22" y="232" class="s-z">CONTAINER: NO NETWORK, READ-ONLY ROOT, LIMITS</text>')
f.append(box(26,250,140,62,"data/app.apk","read-only"))
f.append(box(196,250,170,62,"unpack.sh","extract, decompile"))
f.append(box(396,250,170,62,"scan.sh","leads, decoded strings"))
f.append(box(596,250,196,62,"work/app/","triage, leads, code"))
f.append(line([(166,281),(193,281)])); f.append(line([(366,281),(393,281)])); f.append(line([(566,281),(593,281)]))
f.append(box(396,344,220,62,"decryptor","agent-written decrypt.py, linted"))
f.append(line([(396,375),(281,375),(281,315)],"s-accent-line","aha"))
f.append(lab(292,368,"decrypted payloads","start"))
f.append('</svg>')
flow="".join(f)

# 2. layers (BTMOB)
L=[("outer APK, posing as a carrier update","packer stub; junk bytecode stops jadx and baksmali"),
   ("layer 1: AES asset","dropper dex"),
   ("layer 2: XOR asset, key from native library","split APK of the second app"),
   ("layer 3: AES asset","three dex files with the app code"),
   ("layer 4: string encryption","5,032 strings decoded"),
   ("layer 5: AES configuration","C2 host, overlay pages")]
g=['<svg viewBox="0 0 820 320" role="img" aria-labelledby="lay-t"><title id="lay-t">The five layers of the BTMOB dropper, decrypted from the outside in</title>']
step=24
for i,(t,m) in enumerate(L):
  x=10+i*step; y=10+i*30; w=800-2*i*step; h=300-44*i
  g.append('<rect x="%d" y="%d" width="%d" height="%d" rx="10" class="%s"/>'%(x,y,w,h,"s-layer-fill" if i==len(L)-1 else "s-layer"))
  g.append('<text x="%d" y="%d" class="s-t">%s</text><text x="%d" y="%d" class="s-m">%s</text>'%(x+14,y+20,esc(t),x+14+len(t)*7.6+12,y+20,esc(m)))
g.append('<text x="410" y="216" class="s-t" text-anchor="middle">what the app does: remote control, SMS, overlays, keylogging</text>')
g.append('</svg>')
layers="".join(g)

# Result charts, with numbers read from agent_docs/benchmarks.md. Narrow layout (labels above the
# bars) so a chart fits a phone without scrolling sideways.
CW, L, R = 520, 12, 508  # viewBox width, bar start, bar end

def bar_chart(ident, title, rows, vmax, ticks, tick_fmt):
  """rows: (label, line text, primary value or None, secondary value or None, ours)"""
  sc = (R - L) / float(vmax)
  rowh = 80
  h = 30 + rowh * len(rows) + 26
  c = ['<svg viewBox="0 0 %d %d" role="img" aria-labelledby="%s"><title id="%s">%s</title>' % (CW, h, ident, ident, esc(title))]
  base = 30 + rowh * len(rows)
  ticks = list(ticks)
  for v in ticks:
    x = L + v * sc
    anchor = "start" if v == ticks[0] else "end" if v == ticks[-1] else "middle"
    c.append('<text x="%d" y="%d" class="s-m" text-anchor="%s">%s</text>' % (x, base + 18, anchor, tick_fmt(v)))
  for i, (name, text, a, b, us) in enumerate(rows):
    y = 30 + i * rowh
    for v in (ticks if a is not None else ()):  # grid only behind bars, not through labels
      x = L + v * sc
      c.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="s-grid"/>' % (x, y + 24, x, y + 60))
    c.append('<text x="%d" y="%d" class="s-t">%s</text><text x="%d" y="%d" class="s-m">%s</text>' % (L, y + 4, esc(name), L, y + 20, esc(text)))
    if a is None:
      continue
    c.append('<rect x="%d" y="%d" width="%d" height="14" class="%s"/>' % (L, y + 28, max(a * sc, 1), "s-bar-us" if us else "s-bar"))
    if b is not None:
      c.append('<rect x="%d" y="%d" width="%d" height="8" class="s-bar2"/>' % (L, y + 46, max(b * sc, 1)))
  c.append('</svg>')
  return "".join(c)

# 3. Ghera chart. None: no rules for this benchmark's subject; not applicable, not 0
BENCH = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent_docs", "benchmarks.md")).read()

def bench_row(label):
  """cells of the Tool comparison row that starts with label"""
  for line in BENCH.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if cells and cells[0] == label:
      return cells
  raise SystemExit("agent_docs/benchmarks.md: no Tool comparison row %r" % label)

def num(cell):
  """leading integer of a cell; None when the tool is out of scope for that benchmark"""
  m = re.match(r"(-?\d+)", cell)
  return None if m is None or "out of scope" in cell else int(m.group(1))

# label in the page, row label in benchmarks.md, ours
TOOLS = [("Cupella", "this project (agent, verified)", True), ("MobSF 4.5.3", "MobSF 4.5.3", False),
         ("Quark-Engine 26.9.1", "Quark-Engine 26.9.1", False)]
ROWS = {name: bench_row(label) for name, label, _us in TOOLS}
# columns: tool, Ghera found, fixed apps flagged, informedness, malware flagged, benign right, recall, precision
tools = [(n, num(ROWS[n][1]), num(ROWS[n][2]) if num(ROWS[n][1]) is not None else None, us) for n, _l, us in TOOLS]
ghera = bar_chart("gh-t", "Ghera: vulnerabilities found of 59 (filled bar) and fixed apps also flagged (outline); Quark-Engine not applicable",
  [(n, ("%d of 59 found; %d also in the fixed app" % (a, b)) if a is not None else
       "not applicable: a malware-behavior engine with no vulnerability rules", a, b, us) for n, a, b, us in tools],
  59, (0, 10, 20, 30, 40, 50, 59), str)

# 4. MalEval behavior chart
mt = [(n, num(ROWS[n][6]), num(ROWS[n][7]), us) for n, _l, us in TOOLS]
maleval = bar_chart("mv-t", "MalEval: behavior recall (filled bar) and precision (outline)",
  [(n, "recall %d%%, precision %d%%" % (r, p), r, p, us) for n, r, p, us in mt],
  100, range(0, 101, 20), lambda v: "%d%%" % v)

# 5. decryption effect: "recall 50% -> 66%, precision 68% -> 74%" in benchmarks.md
m = re.search(r"recall (\d+)% -> (\d+)%, precision (\d+)% -> (\d+)%", BENCH)
if not m:
  raise SystemExit("agent_docs/benchmarks.md: decryption line (recall a% -> b%, precision c% -> d%) not found")
DEC = [("recall", int(m.group(1)), int(m.group(2))), ("precision", int(m.group(3)), int(m.group(4)))]
dec = bar_chart("dc-t", "Six encrypted MalEval samples: behavior recall and precision before (outline) and after (filled bar) static decryption",
  [(k, "before %d%%, after %d%%" % (a, b), b, a, True) for k, a, b in DEC],
  100, range(0, 101, 20), lambda v: "%d%%" % v)
# the results table under the charts, from the same rows
def cell(v):
  return '<td class="num">%s</td>' % esc(v)
trs = []
for n, _l, us in TOOLS:
  r = ROWS[n]
  gh = [cell(str(num(r[1]))), cell(str(num(r[2])))] if num(r[1]) is not None else [cell("n/a"), cell("n/a")]
  trs.append('      <tr%s><td>%s</td>%s%s%s%s%s</tr>' % (' class="us"' if us else "", esc(n), "".join(gh),
             cell(r[4]), cell(r[5]), cell(r[6]), cell(r[7])))
results_tbody = "<tbody>\n" + "\n".join(trs) + "\n    </tbody>"

here = os.path.dirname(os.path.abspath(__file__))
page = os.path.join(here, "index.html")
html = open(page).read()
for svg, ident in ((hero, "hero-t"), (flow, "flow-t"), (layers, "lay-t"), (ghera, "gh-t"), (maleval, "mv-t"), (dec, "dc-t")):
  html, n = re.subn(r'<svg viewBox="[^"]*" role="img" aria-labelledby="%s">.*?</svg>' % ident, lambda m: svg, html, flags=re.S)
  print("%s: %d replaced" % (ident, n))
html, n = re.subn(r'(<table id="results-table"[^>]*>.*?)<tbody>.*?</tbody>',
                  lambda m: m.group(1) + results_tbody, html, count=1, flags=re.S)
if n != 1:
  raise SystemExit('docs/index.html: no <table id="results-table"> with a <tbody>')
print("results table: %d replaced" % n)
open(page, "w").write(html)
