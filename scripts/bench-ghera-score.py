#!/usr/bin/env python3
"""Score blinded agent verdicts on Ghera against the known vulnerabilities.

Two steps, around a scoring pass by agents that never learn which app is which:

  packets  for each pair, write work/_ghera-blind/score/<pair-id>.md: the benchmark's
           vulnerability description (from bench/ghera/<pair>.README.md, summary and
           description sections only) and the two apps' verdicts as "A" and "B" in
           random order. The A/B key goes to work/_ghera-blind/score-key.json.
  tally    read work/_ghera-blind/score/<pair-id>.json ({"A": true|false, "B": ...}:
           does the verdict report the benchmark's vulnerability) and count, per the
           Ranganath and Mitra study: TP (reported in the vulnerable app), FN (not
           reported there), FP (reported in the fixed app), TN (not reported there).

Usage: ./cupella bench-ghera-score.py packets [seed] [verdicts-dir] [score-dir]
       ./cupella bench-ghera-score.py tally [score-dir]
  verdicts-dir and score-dir are names under work/_ghera-blind/ (default verdicts,
  score); use others to score a variant, such as verifier-filtered verdicts.
"""
import json
import os
import random
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BLIND = os.path.join(ROOT, "work", "_ghera-blind")


def readme_part(pair):
  path = os.path.join(ROOT, "bench", "ghera", pair + ".README.md")
  with open(path, errors="replace") as f:
    text = f.read()
  m = re.search(r"(?s)^(.*?)(?=^#+ *Steps|^#+ *References|\Z)", text, re.M)
  part = m.group(1) if m else text
  # the vulnerable app is called Benign in the README; the verdicts call it A or B
  return re.sub(r"(?i)\bbenign\b", "the vulnerable app", part).strip()


def packets(seed, vdir="verdicts", sdir="score"):
  rng = random.Random(seed)
  key = json.load(open(os.path.join(BLIND, "key.json")))
  pairs = {}
  for bid, v in key.items():
    pairs.setdefault(v["pair"], {})[v["role"]] = bid
  os.makedirs(os.path.join(BLIND, sdir), exist_ok=True)
  skey, missing = {}, []
  for i, (pair, roles) in enumerate(sorted(pairs.items())):
    pid = "pair-%02d" % i
    order = [roles["vulnerable"], roles["fixed"]]
    rng.shuffle(order)
    verdicts = []
    for bid in order:
      p = os.path.join(BLIND, vdir, bid + ".json")
      if not os.path.exists(p):
        missing.append(bid)
        verdicts.append("(no verdict file)")
        continue
      with open(p, errors="replace") as f:
        verdicts.append(f.read().replace(bid, "<app>"))
    with open(os.path.join(BLIND, sdir, pid + ".md"), "w") as f:
      f.write("# %s\n\n## The known vulnerability\n\n%s\n\n## Verdict A\n\n```json\n%s\n```\n\n## Verdict B\n\n```json\n%s\n```\n"
              % (pid, readme_part(pair), verdicts[0], verdicts[1]))
    skey[pid] = {"pair": pair, "A": order[0], "B": order[1],
                 "A_role": key[order[0]]["role"], "B_role": key[order[1]]["role"]}
  with open(os.path.join(BLIND, sdir + "-key.json"), "w") as f:
    json.dump(skey, f, indent=1, sort_keys=True)
  print("%d packets in work/_ghera-blind/%s/; %d verdict files missing %s" % (len(skey), sdir, len(missing), missing[:5]))


def tally(sdir="score"):
  skey = json.load(open(os.path.join(BLIND, sdir + "-key.json")))
  tp = fn = fp = tn = 0
  rows, unscored = [], []
  for pid, k in sorted(skey.items(), key=lambda kv: kv[1]["pair"]):
    p = os.path.join(BLIND, sdir, pid + ".json")
    if not os.path.exists(p):
      unscored.append(pid)
      continue
    s = json.load(open(p))
    res = {}
    for side in ("A", "B"):
      res[k[side + "_role"]] = bool(s.get(side))
    tp += res["vulnerable"]
    fn += not res["vulnerable"]
    fp += res["fixed"]
    tn += not res["fixed"]
    rows.append((k["pair"], res["vulnerable"], res["fixed"], s.get("note", "")))
  print("# Ghera agent verdicts, blind")
  print("pair: vulnerable app reported / fixed app reported")
  for pair, v, f, note in rows:
    print("%-58s %-4s %-4s %s" % (pair[:58], "yes" if v else "no", "yes" if f else "no", note[:90]))
  n = len(rows)
  print()
  print("pairs scored: %d (unscored: %s)" % (n, ", ".join(unscored) or "none"))
  print("TP %d  FN %d  FP %d  TN %d" % (tp, fn, fp, tn))
  if n:
    tpr, fpr = tp / n, fp / n
    print("detected in the vulnerable app: %d of %d (%.0f%%); also reported in the fixed app: %d (%.0f%%)" % (
      tp, n, 100 * tpr, fp, 100 * fpr))
    print("informedness (TPR - FPR): %.2f" % (tpr - fpr))


def main():
  if len(sys.argv) < 2 or sys.argv[1] not in ("packets", "tally"):
    sys.exit(__doc__)
  a = sys.argv[2:]
  if sys.argv[1] == "packets":
    packets(int(a[0]) if a else 3, *(a[1:3]))
  else:
    tally(*(a[:1]))


if __name__ == "__main__":
  main()
