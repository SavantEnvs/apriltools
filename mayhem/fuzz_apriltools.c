#include <stdint.h>
#include <stddef.h>

#include "apriltag.h"
#include "tag36h11.h"
#include "common/image_u8.h"
#include "common/zarray.h"

#include <stdio.h>
#include <stdlib.h>

/* In-process libFuzzer harness over AprilTools' fuzzable code path. AprilTools.cc
 * decodes each frame to a grayscale image with OpenCV and runs the AprilTag
 * detector on it (apriltag_detector_detect). The upstream CLI target is not
 * directly fuzzable (it wants a directory of numbered images and writes track.txt
 * under the — read-only, on Mayhem — input path), so we drive the same detector
 * in-process on a grayscale image built straight from the fuzz bytes (4-byte
 * width/height header + pixels). This feeds the instrumented AprilTag library
 * directly instead of the uninstrumented OpenCV PNG codec.
 *
 * test.sh's oracle (mayhem/oracle_detect.c -> /mayhem/apriltools_oracle) does not link its own copy
 * of this code: it EXECUTES this graded binary, /mayhem/apriltools_fuzz, on each known-answer frame
 * (one input per run, through libFuzzer's own driver, exactly as PoV replay does) and reads back the
 * first detection, which this harness appends to the file named by $MAYHEM_APRILTOOLS_RESULT when
 * that variable is set (it never is on Mayhem, so fuzzing is unaffected). The known-answer tests
 * therefore run the very program that is graded — same objects, same link, same layout, same
 * libFuzzer driver and hooks (#1460). */

#define MAX_DIM    1024u
#define MAX_PIXELS (1u << 20)

static apriltag_family_t *tf;
static apriltag_detector_t *td;
static const char *result_path;   /* $MAYHEM_APRILTOOLS_RESULT (test.sh oracle only) */

/* First detection of one run: n = number of detections (-1 if the detector did not run), id and
 * hamming of detection 0 (-1 if n <= 0). */
struct run_result { int n, id, hamming; };

/* Long-lived detector state kept for the process lifetime (allocate-once, as the
 * CLI does per run); still reachable via the static globals above, so LSan does not
 * flag it as a leak at exit — no need to override Mayhem's ASan/LSan runtime options. */

static void init(void) {
    tf = tag36h11_create();
    td = apriltag_detector_create();
    apriltag_detector_add_family_bits(td, tf, 1);
    td->quad_decimate = 2.0f;
    td->quad_sigma = 0.0f;
    td->nthreads = 1;
    td->refine_edges = 1;
    td->debug = 0;
    result_path = getenv("MAYHEM_APRILTOOLS_RESULT");
}

static int run(const uint8_t *data, size_t size, struct run_result *res) {
    res->n = -1; res->id = -1; res->hamming = -1;
    if (size < 4) return 0;

    unsigned w = (unsigned)(data[0] | (data[1] << 8));
    unsigned h = (unsigned)(data[2] | (data[3] << 8));
    data += 4; size -= 4;
    if (w < 1) w = 1; else if (w > MAX_DIM) w = MAX_DIM;
    if (h < 1) h = 1; else if (h > MAX_DIM) h = MAX_DIM;
    if ((size_t)w * h > MAX_PIXELS) return 0;

    image_u8_t *im = image_u8_create(w, h);
    if (!im) return 0;
    for (unsigned y = 0; y < h; y++) {
        for (unsigned x = 0; x < w; x++) {
            size_t idx = (size_t)y * w + x;
            im->buf[y * im->stride + x] = (idx < size) ? data[idx] : 0;
        }
    }

    zarray_t *dets = apriltag_detector_detect(td, im);
    res->n = zarray_size(dets);
    if (res->n > 0) {
        apriltag_detection_t *d;
        zarray_get(dets, 0, &d);
        res->id = d->id; res->hamming = d->hamming;
    }
    apriltag_detections_destroy(dets);
    image_u8_destroy(im);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int inited = 0;
    if (!inited) { init(); inited = 1; }
    struct run_result r;
    run(data, size, &r);
    /* Report only after the whole run (detection + cleanup) returned without a sanitizer abort; one
     * line per executed input, keyed by its size so the oracle picks the run of its own frame. */
    if (result_path) {
        FILE *f = fopen(result_path, "a");
        if (f) { fprintf(f, "size=%zu n=%d id=%d hamming=%d\n", size, r.n, r.id, r.hamming); fclose(f); }
    }
    return 0;
}
