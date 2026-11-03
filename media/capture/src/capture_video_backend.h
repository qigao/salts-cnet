#ifndef SALTS_CAPTURE_VIDEO_BACKEND_H
#define SALTS_CAPTURE_VIDEO_BACKEND_H

#include "capture.h"

typedef struct {
    int (*open_device)(const char *device_id, void **backend_ctx);
    void (*close_device)(void *backend_ctx);
    int (*list_modes)(void *backend_ctx,
                      salts_video_native_mode_t *modes,
                      size_t capacity,
                      size_t *out_count);
    int (*create_capture)(void *backend_ctx,
                          const salts_video_native_mode_t *mode,
                          salts_capture_t **out_capture);
} salts_video_backend_ops_t;

const salts_video_backend_ops_t *salts_video_platform_backend(void);

#endif
