#ifndef SALTS_CAPTURE_VIDEO_FRAME_H
#define SALTS_CAPTURE_VIDEO_FRAME_H
#include "capture.h"

typedef struct {
    salts_video_capture_cb_v2 callback;
    void *user;
    int unsupported; /* Fixed native layout capability, established at create. */
} salts_video_frame_sink;

/* One native context owns this registration. No external frame is retained. */
salts_video_frame_sink *salts_video_platform_frame_sink(salts_capture_t *);
int salts_video_frame_has_callback(salts_capture_t *);
int salts_video_frame_build(salts_video_frame_v2_t *, const uint8_t *, size_t,
    int, int, salts_video_frame_format_t, size_t, int, uint64_t,
    salts_video_frame_clock_t, salts_video_frame_matrix_t, salts_video_frame_range_t);
int salts_video_frame_deliver(salts_capture_t *, const uint8_t *, size_t,
    int, int, salts_video_frame_format_t, size_t, int, uint64_t,
    salts_video_frame_clock_t, salts_video_frame_matrix_t, salts_video_frame_range_t);
#endif
