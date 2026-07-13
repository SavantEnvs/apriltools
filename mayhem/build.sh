#!/usr/bin/env bash
#
# mayhem/build.sh — build the AprilTag fuzz harness, its standalone reproducer, and the
# behavioral test oracle for AprilTools.
#
# AprilTools itself is a thin OpenCV CLI over the AprilTag library (the apriltag/ submodule):
# it decodes frames to grayscale and runs apriltag_detector_detect(). OpenCV is not in the
# base image and is not the code under test, so we build the AprilTag library (the fuzzed
# code) with sanitizers + DWARF, and link:
#   - /mayhem/apriltools_fuzz              libFuzzer harness (Mayhem target)
#   - /mayhem/apriltools_fuzz-standalone   run-once reproducer (no libFuzzer runtime)
#   - /mayhem/apriltools_oracle            behavioral oracle driver (test.sh runs it): contains no
#                                          AprilTag code; it EXECUTES /mayhem/apriltools_fuzz itself on
#                                          known-answer frames, so test.sh tests the graded binary (#1460)
# Both binaries that contain AprilTag code (the fuzz target and its -standalone reproducer) link the
# build-time LeakSanitizer off-switch (mayhem/lsan_off.c, SPEC §6 item 15).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
# AprilTag sources: upstream's apriltag SUBMODULE at its gitlink-pinned commit, populated in the
# image by mayhem/Dockerfile (git submodule update --init). This is the SAME tree rlenv flattens into
# the agent's editable working copy (ADR-0048), so a patch to apriltag/*.c reaches every binary below.
# Never fall back to a private copy under mayhem/ — the grader hides that path from the agent.
AT="$SRC/apriltag"
[ -f "$AT/apriltag.c" ] || { echo "build.sh: $AT is not populated — run 'git submodule update --init apriltag' (mayhem/Dockerfile does)" >&2; exit 1; }
INC="-I$AT"
OUT=/mayhem
BLD="$SRC/mayhem/.build"
rm -rf "$BLD"; mkdir -p "$BLD/san"

# Generated tag-family tables are large data files — compile at -O0 (fast, no perf cost at
# run time); the rest of the library at -O1.
TAGS=$(cd "$AT" && ls tag*.c)
LIBSRC=$(cd "$AT" && ls apriltag.c apriltag_pose.c apriltag_quad_thresh.c common/*.c)

# build_lib <objdir> <flags> <archive> — compile the AprilTag library into a static archive.
build_lib() {
  local objdir="$1" flags="$2" ar="$3" f pids=0
  for f in $TAGS; do
    "$CC" $flags -O0 $INC -c "$AT/$f" -o "$objdir/$(basename "$f").o" &
    pids=$((pids+1)); [ "$pids" -ge "$MAYHEM_JOBS" ] && { wait; pids=0; }
  done
  wait; pids=0
  for f in $LIBSRC; do
    "$CC" $flags -O1 $INC -c "$AT/$f" -o "$objdir/$(echo "$f" | tr / _).o" &
    pids=$((pids+1)); [ "$pids" -ge "$MAYHEM_JOBS" ] && { wait; pids=0; }
  done
  wait
  rm -f "$ar"; ar rcs "$ar" "$objdir"/*.o
}

# 1) The fuzzed code: AprilTag library with sanitizers + DWARF < 4.
build_lib "$BLD/san" "$SANITIZER_FLAGS $DEBUG_FLAGS" "$BLD/libapriltag_san.a"

# Build-time LeakSanitizer off-switch (SPEC §6 item 15 / PORTING.md): the __lsan_is_turned_off()
# hook, compiled once with $SANITIZER_FLAGS and linked into the fuzz target and its -standalone
# reproducer, so leak detection is off by default (leaks are not the fleet's bug class) while ASan's
# memory-error checks and UBSan stay fully active. test.sh's oracle runs the fuzz target itself, so the
# hook is present identically in the graded run and in the known-answer runs.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$BLD/lsan_off.o"

# 2) Harness — compiled ONCE, with the harness flags, into $BLD/fuzz_apriltools.o, and linked into the
#    libFuzzer target and its -standalone reproducer. test.sh's oracle (step 3) executes that libFuzzer
#    target itself.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INC \
  -c "$SRC/mayhem/fuzz_apriltools.c" -o "$BLD/fuzz_apriltools.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
  "$BLD/fuzz_apriltools.o" "$BLD/lsan_off.o" "$BLD/libapriltag_san.a" -lpthread -lm \
  -o "$OUT/apriltools_fuzz"
# Standalone run-once reproducer (no libFuzzer runtime): the same harness object, whose coverage
# callbacks (-fsanitize=fuzzer instrumentation) the sanitizer runtime supplies. The sanitizer
# off-switch (SANITIZER_FLAGS without -fsanitize=; an ungraded diagnostic build) links no runtime
# that could supply them, so there the reproducer compiles the harness source without the engine flag.
STANDALONE_HARNESS="$BLD/fuzz_apriltools.o"
case " $SANITIZER_FLAGS " in *" -fsanitize="*) ;; *) STANDALONE_HARNESS="$SRC/mayhem/fuzz_apriltools.c" ;; esac
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
  "$STANDALONE_FUZZ_MAIN" "$STANDALONE_HARNESS" "$BLD/lsan_off.o" "$BLD/libapriltag_san.a" -lpthread -lm \
  -o "$OUT/apriltools_fuzz-standalone"

# 3) Test oracle — the GRADED BINARY ITSELF (#1460). Any separately built or separately linked oracle
#    is a different program from the graded one, and a patch can key on the difference: the build
#    context (`#if __has_feature(address_sanitizer)` → early return in apriltag.c; a header macro on
#    __has_feature(coverage_sanitizer), __OPTIMIZE__ or the caller's __FILE__), the link content (a
#    weak reference to LLVMFuzzerTestOneInput, __libfuzzer_is_present or a libstdc++ symbol), the
#    link layout (the distance from main to apriltag_detector_detect), libFuzzer's driver hooks (an
#    LLVMFuzzerInitialize that only FuzzerDriver calls), the call stack or the program name — neutering
#    detection in the graded binary while test.sh still passes. So the oracle is a small driver
#    (mayhem/oracle_detect.c; no AprilTag code, no apriltag/ header, normal flags) that EXECUTES
#    /mayhem/apriltools_fuzz — the very binary PoV replay runs, with the same argv shape — once per
#    known-answer frame (converted to the harness input format), and asserts the detection the harness
#    reports through $MAYHEM_APRILTOOLS_RESULT plus a clean exit. Every gate above then neuters the
#    oracle's runs too and fails test.sh.
#    Coverage (optional): a non-empty $COVERAGE_FLAGS links a coverage-instrumented twin of the fuzz
#    target (library + harness with the same sanitizer/debug/engine flags plus $COVERAGE_FLAGS) at
#    $BLD/apriltools_fuzz-cov and points the oracle at it; the graded binaries stay unaffected.
ORACLE_TARGET="$OUT/apriltools_fuzz"
if [ -n "$COVERAGE_FLAGS" ]; then
  mkdir -p "$BLD/cov"
  build_lib "$BLD/cov" "$SANITIZER_FLAGS $DEBUG_FLAGS $COVERAGE_FLAGS" "$BLD/libapriltag_cov.a"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $COVERAGE_FLAGS $INC \
    -c "$SRC/mayhem/fuzz_apriltools.c" -o "$BLD/cov/fuzz_apriltools.o"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $COVERAGE_FLAGS \
    "$BLD/cov/fuzz_apriltools.o" "$BLD/lsan_off.o" "$BLD/libapriltag_cov.a" -lpthread -lm \
    -o "$BLD/apriltools_fuzz-cov"
  ORACLE_TARGET="$BLD/apriltools_fuzz-cov"
fi
"$CC" -O1 -g -Wall -DAPRILTOOLS_TARGET="\"$ORACLE_TARGET\"" \
  "$SRC/mayhem/oracle_detect.c" -o "$OUT/apriltools_oracle"
