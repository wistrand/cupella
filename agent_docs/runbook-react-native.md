# Runbook: React Native apps

Read when `triage.txt` shows `assets/index.android.bundle` (a `hermes/` directory in the
unpack output). The rest of the analysis follows
[runbook-analysis.md](runbook-analysis.md); stage order and checkpoints are in
[workflow.md](workflow.md).

`triage.txt` shows `assets/index.android.bundle`. The app's logic is JavaScript in
that bundle; jadx shows the host shell and native modules. `unpack.sh` runs
`scripts/hermes-decompile.sh`, which writes `hermes/SUMMARY.txt` (format, bytecode
version, URLs, native modules referenced). For a Hermes bundle, `hermes/bundle.js` is
decompiled pseudo-JavaScript and `hermes/bundle.hasm` the disassembly; for a plain
bundle, read the bundle itself. Both are large: grep for URLs, endpoint paths,
storage keys, and the native module names, then read around the hits. The Java side
tells which native modules exist (what the JavaScript can reach); the bundle tells
what the app does with them. This path was written from hermes-dec's documentation
and has run only on a synthetic plain-JavaScript bundle: on the first real React
Native app, check `hermes/decompile.log`, fix the script if needed, and record what
you learn in [gotchas.md](gotchas.md).
