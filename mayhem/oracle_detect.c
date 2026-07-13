/* Behavioral known-answer oracle for AprilTools (AUTHORED — upstream ships no
 * test suite). AprilTools runs the AprilTag detector over frames and reports the
 * detected tags; this oracle drives that exact code path (apriltag_detector_detect)
 * on real grayscale frames shipped in the repo (testAnim frames, pre-converted to
 * PGM under mayhem/oracle-data/) and asserts the known ground truth: each frame
 * contains exactly one tag36h11 marker with id 0 and hamming 0. A patch that
 * neuters detection (returns no tags / exits early) makes these assertions FAIL.
 *
 * The oracle is the GRADED BINARY ITSELF (#1460): this driver contains no AprilTag code and
 * includes no apriltag/ header. For each frame it writes the frame in the fuzz harness's input
 * format (LE16 width, LE16 height, pixels) to a scratch file and executes /mayhem/apriltools_fuzz on
 * it — one input per run, with the same argv shape mtv's PoV replay uses and, under rlenv, from the
 * sandbox directory PoV replay ran the target in (see run_target for what still differs) — so
 * detection runs through libFuzzer's own driver, the same harness object, the same sanitized AprilTag
 * objects, the same link and layout as the graded target. The harness appends that run's
 * first detection to the file named by $MAYHEM_APRILTOOLS_RESULT. A case passes only if the target
 * exited 0 (no sanitizer report, no libFuzzer "target exited" abort) AND reported exactly one tag36h11
 * detection with the expected id and hamming 0. The target's own output is shown only on failure,
 * prefixed with "#", so it can never be mistaken for an oracle verdict line. Any patch that neuters
 * detection in the graded binary — however it is gated — therefore also fails these assertions. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* The program under test; build.sh passes the graded target's path (or, in a COVERAGE_FLAGS build,
 * its coverage-instrumented twin). */
#ifndef APRILTOOLS_TARGET
#define APRILTOOLS_TARGET "/mayhem/apriltools_fuzz"
#endif

static int passed = 0, failed = 0;
static void ok(const char *n)  { printf("ok - %s\n", n);   passed++; }
static void bad(const char *n) { printf("FAIL - %s\n", n); failed++; }

/* Parses one PNM header integer at p[*pos..len), skipping whitespace and '#' comments
 * (netpbm rules); the single whitespace byte that ends it is consumed. */
static int pnm_int(const unsigned char *p, size_t len, size_t *pos, int *v) {
    size_t i = *pos;
    for (;;) {
        if (i >= len) return 0;
        if (p[i] == '#') { while (i < len && p[i] != '\n') i++; continue; }
        if (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r') { i++; continue; }
        break;
    }
    if (p[i] < '0' || p[i] > '9') return 0;
    long x = 0;
    while (i < len && p[i] >= '0' && p[i] <= '9') { x = x * 10 + (p[i] - '0'); if (x > 1000000) return 0; i++; }
    if (i >= len || !(p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r')) return 0;
    *v = (int)x;
    *pos = i + 1;
    return 1;
}

/* Loads an 8-bit binary PGM (P5, maxval 255) and returns it in the harness input format:
 * LE16 width, LE16 height, then width*height pixels row-major. NULL on any format error. */
static unsigned char *load_as_harness_input(const char *path, size_t *len) {
    enum { MAX_FILE = 16 << 20 };
    unsigned char *file = malloc(MAX_FILE), *buf = NULL;
    if (!file) return NULL;
    FILE *f = fopen(path, "rb");
    size_t flen = f ? fread(file, 1, MAX_FILE, f) : 0;
    if (f) fclose(f);
    size_t pos = 2, n = 0;
    int w = 0, h = 0, maxval = 0;
    if (flen < 2 || flen == MAX_FILE || file[0] != 'P' || file[1] != '5' ||
        !pnm_int(file, flen, &pos, &w) || !pnm_int(file, flen, &pos, &h) ||
        !pnm_int(file, flen, &pos, &maxval) ||
        w < 1 || h < 1 || w > 0xffff || h > 0xffff || maxval != 255)
        goto out;
    n = (size_t)w * (size_t)h;
    if (flen - pos < n) goto out;
    buf = malloc(4 + n);
    if (!buf) goto out;
    buf[0] = (unsigned char)(w & 0xff); buf[1] = (unsigned char)(w >> 8);
    buf[2] = (unsigned char)(h & 0xff); buf[3] = (unsigned char)(h >> 8);
    memcpy(buf + 4, file + pos, n);
    *len = 4 + n;
out:
    free(file);
    return buf;
}

static int write_file(const char *path, const unsigned char *buf, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); return 0; }
        off += (size_t)w;
    }
    return close(fd) == 0;
}

/* Creates a fresh scratch dir "<base>/.tmpXXXXXX" into buf, as an absolute path: the target is started
 * from another working directory (run_target), and the paths it is given (input, result file, log)
 * must still name these files. A NULL base means $TMPDIR, falling back to /tmp; an explicit base has
 * no fallback (the caller then takes the $TMPDIR path instead). */
static int make_scratch(char *buf, size_t size, const char *base) {
    const char *def = getenv("TMPDIR");
    int fallback = !base;
    if (!base) base = (def && *def) ? def : "/tmp";
    if ((size_t)snprintf(buf, size, "%s/.tmpXXXXXX", base) >= size || !mkdtemp(buf)) {
        if (!fallback) return 0;
        snprintf(buf, size, "/tmp/.tmpXXXXXX");
        if (!mkdtemp(buf)) return 0;
    }
    if (buf[0] != '/') {
        char cwd[4096], abs[4096];
        if (!getcwd(cwd, sizeof cwd) ||
            (size_t)snprintf(abs, sizeof abs, "%s/%s", cwd, buf) >= sizeof abs || strlen(abs) >= size) {
            rmdir(buf);
            return 0;
        }
        memcpy(buf, abs, strlen(abs) + 1);
    }
    return 1;
}

/* Prints the tail of the target's captured output, each line prefixed with "#   ". */
static void show_log(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char *lines[40] = { 0 }, buf[512];
    unsigned n = 0;
    while (fgets(buf, sizeof buf, f)) { free(lines[n % 40]); lines[n % 40] = strdup(buf); n++; }
    fclose(f);
    for (unsigned i = n > 40 ? n - 40 : 0; i < n; i++) {
        char *l = lines[i % 40];
        if (l) printf("#   %s%s", l, (*l && l[strlen(l) - 1] == '\n') ? "" : "\n");
    }
    for (unsigned i = 0; i < 40; i++) free(lines[i]);
}

/* The directory rlenv's PoV replay ran the target in, when this run looks like rlenv's test.sh run:
 * rlenv runs test.sh with $TMPDIR = $HOME = <sandbox>/<label> ("func") in the same sandbox dir in
 * which it replayed the PoVs just before, so that sandbox dir is dirname($TMPDIR). It is used only
 * when $TMPDIR is absolute and its parent is a directory other than "/" that this driver can write
 * and enter; otherwise (TMPDIR unset or relative, docker build, CI) this returns 0 and the $TMPDIR
 * (or /tmp) path is used. */
static int replay_dir(char *buf, size_t size) {
    const char *t = getenv("TMPDIR");
    struct stat st;
    if (!t || t[0] != '/' || strlen(t) >= size) return 0;
    memcpy(buf, t, strlen(t) + 1);
    size_t n = strlen(buf);
    while (n > 1 && buf[n - 1] == '/') buf[--n] = 0;   /* "/a/b/" -> "/a/b" */
    char *slash = strrchr(buf, '/');
    if (!slash || slash == buf) return 0;               /* the parent would be "/" */
    *slash = 0;
    return stat(buf, &st) == 0 && S_ISDIR(st.st_mode) && access(buf, W_OK | X_OK) == 0;
}

/* Runs the graded target once on <input>, with <wd> as its working directory; its stdout/stderr go
 * to <log>. If <home> is non-NULL, the target's $TMPDIR and $HOME are set to it. Returns the wait
 * status, or -1 if it could not be started.
 *
 * Working directory: rlenv's PoV replay (mtv triage) starts the target in make_sandbox's scratch dir —
 * the directory that is also its $TMPDIR and $HOME, and in which mtv made the ".tmpXXXXXX" dir that
 * holds the input copy — never in the source tree. test.sh runs from $SRC (/mayhem), so a target that
 * simply inherited this driver's cwd would let a patch gate detection on the cwd (a relative
 * "apriltag/apriltag.c" that resolves only there, a getcwd() prefix, the cwd's owner, mode, group or
 * contents, its parent) and neuter only the graded runs. Under rlenv (replay_dir), <wd> is therefore
 * that very sandbox dir: the input's ".tmpXXXXXX" dir is created in it, and the target runs in it with
 * $TMPDIR = $HOME = <wd>, so cwd, $TMPDIR, $HOME and the input path relate as in PoV replay, and the
 * directory itself (its path, owner, mode, group, parent and rlenv's staged testsuite/ and Mayhemfile
 * in it) is the one the PoVs ran in. Otherwise <wd> is $TMPDIR (or /tmp), with $TMPDIR and $HOME left
 * as inherited. OLDPWD is dropped as well: test.sh's own `cd` exports it, while replay's environment
 * (the rlenv server's, started by `bash -c` without a cd) has none. PWD is left as inherited, as in
 * replay, where the target sees the server's PWD, not its sandbox cwd. If the directory cannot be
 * entered the run fails (exit 126) rather than falling back to the source tree.
 *
 * What still differs, so a patch keyed on it can still tell the runs apart: by the time test.sh
 * runs, rlenv has also created its own test.sh scratch entry in the sandbox dir (named from its
 * label, "func"; it holds the CTRF report and cannot be hidden), so the cwd has that one extra entry;
 * and this driver's input dir and copy are owned by the runner (modes 0700/0400), not by root as
 * mtv's are. Process- and environment-level differences (the parent process, SHLVL, the umask, other
 * variables) are not covered here either. */
static int run_target(const char *input, const char *result, const char *log, const char *wd,
                      const char *home) {
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(126);
        if (fd > 2) close(fd);
        if (setenv("MAYHEM_APRILTOOLS_RESULT", result, 1) != 0) _exit(126);
        unsetenv("CTRF_REPORT");   /* test.sh's grader variable; PoV replay does not set it */
        unsetenv("OLDPWD");        /* set by test.sh's `cd "$SRC"`; absent in PoV replay */
        if (home && (setenv("TMPDIR", home, 1) != 0 || setenv("HOME", home, 1) != 0)) _exit(126);
        if (chdir(wd) != 0) _exit(126);
        /* argv as mtv's libFuzzer PoV replay builds it: <target> <input> <libFuzzer flags>. */
        execl(APRILTOOLS_TARGET, APRILTOOLS_TARGET, input,
              "-print_final_stats=1", "-rss_limit_mb=2048", (char *)NULL);
        _exit(127);
    }
    int st;
    while (waitpid(pid, &st, 0) < 0) if (errno != EINTR) return -1;
    return st;
}

int main(int argc, char **argv) {
    const char *dir = (argc > 1) ? argv[1] : ".";
    struct { const char *file; int id; } cases[] = {
        { "0001.pgm", 0 },
        { "0040.pgm", 0 },
    };

    /* Scratch: one dir holding only the harness-format inputs (named like mtv's PoV-replay copies,
     * "<dir>/.tmpXXXXXX/<name>", <dir> being the PoV-replay dir under rlenv, else $TMPDIR), and a
     * separate one in $TMPDIR for the result files and the target's logs. */
    char tmp[4096], out[4096], wd[4096], rdir[4096];
    int in_replay_dir = replay_dir(rdir, sizeof rdir) && make_scratch(tmp, sizeof tmp, rdir);
    if (!in_replay_dir && !make_scratch(tmp, sizeof tmp, NULL)) tmp[0] = 0;
    if (!make_scratch(out, sizeof out, NULL)) out[0] = 0;
    if (!tmp[0] || !out[0]) perror("apriltools_oracle: mkdtemp");
    /* The target's working directory: the one holding the input scratch dir (see run_target). */
    snprintf(wd, sizeof wd, "%s", tmp);
    char *slash = strrchr(wd, '/');
    if (slash == wd) wd[1] = 0;   /* "/.tmpXXXXXX" -> "/" */
    else if (slash) *slash = 0;

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[512], name[512], input[4200], result[4200], log[4200];
        size_t len = 0;
        snprintf(path, sizeof path, "%s/%s", dir, cases[i].file);
        unsigned char *buf = load_as_harness_input(path, &len);
        if (!buf) {
            snprintf(name, sizeof name, "load %s", cases[i].file);
            bad(name);
            continue;
        }
        snprintf(input, sizeof input, "%s/%.*s", tmp, (int)strcspn(cases[i].file, "."), cases[i].file);
        snprintf(result, sizeof result, "%s/result-%u", out, i);
        snprintf(log, sizeof log, "%s/log-%u", out, i);
        int written = tmp[0] && out[0] && write_file(input, buf, len);
        free(buf);
        if (!written) {
            snprintf(name, sizeof name, "stage %s as harness input", cases[i].file);
            bad(name);
            continue;
        }
        chmod(input, 0400);   /* read-only input, as in PoV replay */
        unlink(result);

        int st = run_target(input, result, log, wd, in_replay_dir ? wd : NULL);
        int n = -1, got_id = -1, ham = -1, have = 0;
        FILE *rf = fopen(result, "r");
        if (rf) {
            /* The report of the run on this frame: the (last) line whose size is this input's. */
            char line[256];
            while (fgets(line, sizeof line, rf)) {
                size_t sz; int a, b, c;
                if (sscanf(line, "size=%zu n=%d id=%d hamming=%d", &sz, &a, &b, &c) == 4 && sz == len) {
                    n = a; got_id = b; ham = c; have = 1;
                }
            }
            fclose(rf);
        }
        int clean = st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0;

        snprintf(name, sizeof name,
                 "%s detects exactly one tag36h11 id=%d (got n=%d id=%d ham=%d)",
                 cases[i].file, cases[i].id, n, got_id, ham);
        if (clean && have && n == 1 && got_id == cases[i].id && ham == 0) {
            ok(name);
        } else {
            bad(name);
            if (st == -1) printf("#   could not run %s\n", APRILTOOLS_TARGET);
            else if (WIFSIGNALED(st)) printf("#   %s killed by signal %d\n", APRILTOOLS_TARGET, WTERMSIG(st));
            else printf("#   %s exit status %d%s\n", APRILTOOLS_TARGET, WEXITSTATUS(st),
                        have ? "" : ", no detection result reported");
            show_log(log);
        }
        unlink(input); unlink(result); unlink(log);
    }
    if (tmp[0]) rmdir(tmp);
    if (out[0]) rmdir(out);

    printf("passed=%d failed=%d\n", passed, failed);
    return failed ? 1 : 0;
}
