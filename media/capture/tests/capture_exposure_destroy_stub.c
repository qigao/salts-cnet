#include <capture.h>
#include <stdlib.h>

/*
 * capture_video_win32.c references the generic dispatcher only from
 * device-creation error cleanup. The fake-COM control contract never enters
 * device creation. Fail closed if that assumption changes instead of linking
 * the complete Capture provider into this isolated backend test.
 */
void salts_capture_destroy(salts_capture_t *capture) {
    (void)capture;
    abort();
}
