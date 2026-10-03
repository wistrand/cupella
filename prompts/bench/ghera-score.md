<!-- Prompt for one scoring agent in the Ghera blind benchmark, after
`./cupella bench-ghera-score.py packets`. Replace {FIRST}, {LAST} and {COUNT} with a range
of packet numbers (four agents of about 15 packets each). -->
You are scoring security-analysis verdicts against known vulnerabilities. All paths are relative to the repository root, which is your working directory.

Score these packets: work/_ghera-blind/score/pair-{FIRST}.md through work/_ghera-blind/score/pair-{LAST}.md ({COUNT} files).

Each packet has "The known vulnerability" (from a benchmark's documentation) and two verdicts, A and B, each a JSON list of vulnerabilities an analyst reported for one app. One of the two apps has the known vulnerability and the other is a fixed version, but you are not told which, and you must not try to find out.

For each verdict decide: does it report the known vulnerability? Count it as reported when an item describes the same weakness through the same mechanism (for example, "AES in ECB mode" for an ECB benchmark; "trusts all certificates" for an invalid-CA benchmark), even if worded differently, at either confidence. Do not count it when the verdict only reports a different or merely related issue (for example, logging of a token is not ECB mode; a hard-coded key alone is not ECB mode unless the benchmark's main issue is the hard-coded key). Use the benchmark's Summary and Issue as the main vulnerability; a "Note" about a secondary issue does not count on its own. Judge A and B independently; both, one, or neither may report it.

Rules: read only the packet files named above. Never read work/_ghera-blind/score-key.json, work/_ghera-blind/key.json, work/_ghera-blind/verdicts/, any work/_ghera-blind-* directory, any work/gh-* directory, data/, or bench/. Do not run scripts.

Output: for each packet write work/_ghera-blind/score/pair-NN.json (same number) with exactly this JSON: {"A": true or false, "B": true or false, "note": "one short sentence: which item matched, or why none did"}. When done, reply with only the list of files written.

Progress: append one line per step to work/_ghera-blind/progress/score-{FIRST}.md as you go ("<step number> <app or item done, result so far>"), not at the end.
