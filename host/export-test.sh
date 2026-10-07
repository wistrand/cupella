#!/usr/bin/env bash
# Checks ./cupella export on a throwaway workspace: text files of one sample (and its
# child samples) are copied to exports/<name>/ with their paths; binary files, links,
# other samples, escapes through .., and an exports/ link are refused; an exported file
# is never overwritten; export-files.py cannot be run directly. Host side (export starts
# its own container), run by `./cupella check`. The sample is a directory of text files,
# not an APK: nothing from a real sample is involved.
#
# Usage: host/export-test.sh [work-dir]   default work/_check/export
# Prints PASS or FAIL per case.
set -euo pipefail

root=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
w=${1:-$root/work/_check/export}
rm -rf "$w"
mkdir -p "$w/work/fixture/sub" "$w/work/fixture.dec1" "$w/work/other" "$w/work/linked"
w=$(cd "$w" && pwd)
cd "$w"
export CUPELLA_WORKSPACE="$w"
run() { "$root/cupella" export "$@" 2>&1 || true; }
check() { if [ "$2" = 1 ]; then echo "PASS  $1"; else echo "FAIL  $1"; fi; }
has() { [ -f "$1" ] && echo 1 || echo 0; }
hasnt() { [ -e "$1" ] || [ -L "$1" ] && echo 0 || echo 1; }

printf 'triage\n' > work/fixture/triage.txt
printf 'a\n' > work/fixture/sub/a.txt
printf 'x\0y' > work/fixture/sub/bin.dat
ln -s ../../other/secret.txt work/fixture/sub/link.txt
printf 'decrypted\n' > work/fixture.dec1/out.txt
printf 'secret\n' > work/other/secret.txt
printf 'l\n' > work/linked/l.txt
e=exports/fixture/work

out=$(run fixture work/fixture/triage.txt)
check "a text file is copied with its path" "$(has $e/fixture/triage.txt)"
check "the copy is identical" "$( [ "$(cat $e/fixture/triage.txt)" = triage ] && echo 1 || echo 0)"
out=$(run fixture work/fixture/sub)
check "a directory: text files copied" "$(has $e/fixture/sub/a.txt)"
check "a directory: binary file skipped" "$(hasnt $e/fixture/sub/bin.dat)"
check "a directory: link skipped" "$(hasnt $e/fixture/sub/link.txt)"
check "skips are listed" "$(grep -q 'bin.dat: binary' <<< "$out" && grep -q 'link.txt: a link' <<< "$out" && echo 1 || echo 0)"
run fixture work/fixture.dec1/out.txt > /dev/null
check "a child sample's file is copied" "$(has $e/fixture.dec1/out.txt)"
run fixture work/other/secret.txt > /dev/null
check "another sample is refused" "$(hasnt $e/other/secret.txt)"
run fixture work/fixture/../other/secret.txt > /dev/null
check "an escape through .. is refused" "$( [ -z "$(find exports -name secret.txt)" ] && echo 1 || echo 0)"
run fixture work/fixture/sub/link.txt > /dev/null
check "a link given by name is refused" "$( [ -z "$(find exports -name secret.txt)" ] && echo 1 || echo 0)"
printf 'changed\n' > work/fixture/triage.txt
out=$(run fixture work/fixture/triage.txt)
check "an exported file is never overwritten" "$( [ "$(cat $e/fixture/triage.txt)" = triage ] && grep -q 'already exported' <<< "$out" && echo 1 || echo 0)"
mkdir -p "$w/elsewhere"
ln -s "$w/elsewhere" exports/linked
out=$(run linked work/linked/l.txt)
check "an exports/<name> link is refused" "$( [ -z "$(ls -A "$w/elsewhere")" ] && grep -q 'is a link' <<< "$out" && echo 1 || echo 0)"
out=$("$root/cupella" export-files.py fixture work/fixture/triage.txt 2>&1 || true)
check "export-files.py is not run directly" "$(grep -q 'runs only as ./cupella export' <<< "$out" && echo 1 || echo 0)"
cd "$root"
rm -rf "$w"
