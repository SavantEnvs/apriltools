#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the behavioral oracle built by mayhem/build.sh. AUTHORED oracle:
# upstream ships NO test suite (no ctest/make check/unit tests), so this drives the AprilTag
# detector on real frames from the repo and asserts the known-answer detections. Does NOT
# compile. Emits a CTRF summary and exits nonzero on any failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ORACLE=/mayhem/apriltools_oracle
DATA="$SRC/mayhem/oracle-data"
EXPECTED=2   # number of known-answer detections the oracle must confirm

[ -x "$ORACLE" ] || { echo "test runner missing: $ORACLE (build.sh bug)" >&2; emit_ctrf "apriltag-detect-oracle" 0 "$EXPECTED"; exit 1; }

out="$("$ORACLE" "$DATA" 2>&1)"; rc=$?
printf '%s\n' "$out"

passed=$(printf '%s\n' "$out" | grep -c '^ok - ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL - ')
# Missing results (e.g. the oracle never ran / exited early) count as failures so a neutered
# program cannot pass by producing no output.
if [ "$passed" -lt "$EXPECTED" ] && [ "$failed" -eq 0 ]; then
  failed=$(( EXPECTED - passed ))
fi

emit_ctrf "apriltag-detect-oracle" "$passed" "$failed"
