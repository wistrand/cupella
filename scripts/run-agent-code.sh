#!/usr/bin/env bash
# Lint and run agent-written Python in the container: the shared step of
# run-decryptor.sh (a decryptor) and ./cupella try-proposal (a proposal tool).
#
# The code was written by an agent that read malware. scripts/agent-code-lint.py checks
# every .py file under <code-dir>; read-only copies of the top-level ones run, so the
# code cannot rewrite a helper before importing it. The working directory is
# <out-dir>, the only directory ./cupella mounts writable for this run; the network is
# off. The lint is a filter, the container is the boundary.
#
# Usage: scripts/run-agent-code.sh <code-dir> <entry.py> <out-dir> [args ...]
#   runs inside the container only (./cupella run-decryptor.sh, ./cupella try-proposal)
set -euo pipefail

code=${1:?usage: run-agent-code.sh <code-dir> <entry.py> <out-dir> [args ...]}
entry=${2:?usage: run-agent-code.sh <code-dir> <entry.py> <out-dir> [args ...]}
out=${3:?usage: run-agent-code.sh <code-dir> <entry.py> <out-dir> [args ...]}
shift 3
root=$(cd "$(dirname "$0")/.." && pwd)
[ -n "${APK_TOOLS:-}" ] || { echo "run-agent-code.sh runs only inside the container (./cupella)" >&2; exit 1; }
[[ "$entry" =~ ^[A-Za-z0-9_]+\.py$ ]] || { echo "entry must be a plain file name: $entry" >&2; exit 1; }
[ -f "$code/$entry" ] || { echo "no $code/$entry" >&2; exit 1; }
[ -d "$out" ] || { echo "no output directory $out" >&2; exit 1; }

python3 -B "$root/scripts/agent-code-lint.py" "$code" || exit 1
stage=$(mktemp -d "${TMPDIR:-/tmp}/agent-code.XXXXXX")
cp "$code"/*.py "$stage"/
chmod 444 "$stage"/*.py && chmod 555 "$stage"
echo "== running $entry"
(cd "$out" && timeout 600 python3 -B -E -s "$stage/$entry" "$@" < /dev/null) \
  || { echo "$entry failed (exit $?)" >&2; exit 1; }
