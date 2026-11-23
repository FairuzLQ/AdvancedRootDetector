#!/usr/bin/env bash
# Prints the failure messages and RDLAB logcat lines of a Test Lab run from its results bucket.
# Usage: fetch_results.sh <gs://bucket/dir/>     (dir = the run's results directory)
set -uo pipefail
DIR="${1%/}"
out=$(mktemp -d)
gsutil -m -q cp -r "$DIR" "$out/" 2>/dev/null || { echo "could not download $DIR"; exit 1; }
for dev in "$out"/*/*/; do
    [ -d "$dev" ] || continue
    echo "=================== $(basename "$dev") ==================="
    for x in "$dev"/test_result_*.xml; do
        [ -f "$x" ] && python3 - "$x" <<'PY'
import sys, xml.etree.ElementTree as ET
for tc in ET.parse(sys.argv[1]).iter("testcase"):
    for f in list(tc.findall("failure")) + list(tc.findall("error")):
        print(f"FAILED {tc.get('classname')}.{tc.get('name')}:")
        print((f.text or f.get("message") or "").strip()[:4000])
PY
    done
    log=$(ls "$dev"/logcat* 2>/dev/null | head -1)
    [ -n "$log" ] && grep -E " RDLAB|RDLAB:" "$log" | sed 's/^.*RDLAB[ :]*/  RDLAB: /' | head -60
done
