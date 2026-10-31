#!/usr/bin/env bash
# Compares two versions of the agent docs on one sample with one model: the same
# analysis through the API harness (./cupella model-compare) once on the docs at a git
# ref and once on the docs of this checkout, everything else (scripts, harness, image,
# models.json) the same. For the user to run: it calls the model API and costs money.
#
#   host/docs-compare.sh <apk under data/> <backend:model> [old-ref] [--max-usd N]
#     old-ref   the commit with the old docs (default HEAD: the last commit, when the
#               new docs are uncommitted)
#
# Makes, under ~/cupella-docs-compare/ (DOCS_COMPARE_DIR to change it):
#   checkout-old/  a clone at old-ref with this checkout's code copied over it, so that
#                  only AGENTS.md, agent_docs/, prompts/, and roles/ differ
#   new, old       one volume workspace each (from this checkout and from checkout-old),
#                  the sample imported into both
#   new-summary.md, old-summary.md   the summary table of each model-compare run
# Each run's report is archived in its workspace's reports/_archive/model-compare/.
# Nothing is deleted; the cleanup commands are printed at the end.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[ $# -ge 2 ] || usage
apk=$1 spec=$2
shift 2
ref=HEAD usd=5
while [ $# -gt 0 ]; do
  case $1 in
    --max-usd) usd=${2:?usage}; shift 2 ;;
    -*) usage ;;
    *) ref=$1; shift ;;
  esac
done
case $apk in /*) ;; *) apk="$root/$apk" ;; esac
[ -f "$apk" ] || { echo "no file $apk" >&2; exit 1; }
[[ "$spec" == *:* ]] || { echo "the model is <backend>:<model>, e.g. openrouter:openai/gpt-5.6-sol" >&2; exit 1; }
[ -f "$root/harness/models.json" ] || { echo "no harness/models.json: ./cupella workspaces new writes it from the example" >&2; exit 1; }
name=$(basename "$apk" .apk)
base=${DOCS_COMPARE_DIR:-$HOME/cupella-docs-compare}
old="$base/checkout-old"
[ ! -e "$base/new" ] && [ ! -e "$base/old" ] || { echo "$base/new or $base/old exists: remove them first (cleanup below)" >&2; exit 1; }
mkdir -p "$base"

echo "== old docs: $ref ($(git -C "$root" rev-parse --short "$ref")); new docs: this checkout ($(git -C "$root" status --short -- AGENTS.md agent_docs prompts roles | wc -l | tr -d ' ') changed files)"
if [ ! -d "$old/.git" ]; then
  git clone --quiet "$root" "$old"
fi
git -C "$old" checkout --quiet --force "$(git -C "$root" rev-parse "$ref")"
# this checkout's code over the old docs: scripts, harness, wrapper, host scripts,
# Dockerfile, the harness configuration (models.json is gitignored)
rsync -a --delete --exclude .git --exclude AGENTS.md --exclude CLAUDE.md --exclude agent_docs/ --exclude prompts/ \
  --exclude roles/ --exclude README.md --exclude docs/ --exclude data/ --exclude work/ --exclude reports/ \
  --exclude bench/ --exclude bench-sources/ --exclude cache/ --exclude .claude/ --exclude .cupella-workspaces \
  --exclude .cupella-decisions.tsv "$root/" "$old/"
mkdir -p "$old/cache"
diff -rq --exclude .git --exclude data --exclude work --exclude reports --exclude bench --exclude bench-sources \
  --exclude cache --exclude docs --exclude .claude "$root" "$old" 2> /dev/null | sed 's/^/  differs: /' | head -40 || true

"$root/cupella" workspaces new "$base/new"
"$old/cupella" workspaces new "$base/old"
for side in new old; do
  (cd "$base/$side" && ./cupella import "$apk")
done

for side in new old; do
  echo
  echo "== $side docs: ./cupella model-compare $name $spec --max-usd $usd"
  (cd "$base/$side" && ./cupella model-compare "$name" "$spec" --max-usd "$usd") \
    | tee >(sed -n '/^# Model comparison/,$p' > "$base/$side-summary.md")
done

echo
echo "== summaries: $base/new-summary.md, $base/old-summary.md"
echo "   reports:   $base/new/reports/_archive/model-compare/, $base/old/reports/_archive/model-compare/"
echo "   read them: (cd $base/new && ./cupella md-view.py reports/_archive/model-compare/<run>/<model>/reports/$name.md)"
echo "== cleanup when done:"
echo "   $root/cupella workspaces rm $base/new"
echo "   $old/cupella workspaces rm $base/old"
echo "   rm -rf $old"
