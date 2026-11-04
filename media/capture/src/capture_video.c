#include "capture_video_backend.h"

#include <limits.h>
#include <stdlib.h>

struct salts_video_device_s {
    const salts_video_backend_ops_t *ops;
    void *backend_ctx;
};

static int video_backend_ops_valid(const salts_video_backend_ops_t *ops) {
    return ops && ops->open_device && ops->close_device &&
           ops->list_modes && ops->create_capture;
}
int salts_video_device_open(const char *device_id,
                            salts_video_device_t **out_device) {
    const salts_video_backend_ops_t *ops;
    salts_video_device_t *device;
    int result;

    if (!out_device) return SALTS_CAPTURE_ERR_FORMAT;
    *out_device = NULL;

    ops = salts_video_platform_backend();
    if (!video_backend_ops_valid(ops)) return SALTS_CAPTURE_ERR_UNSUPPORTED;

    device = (salts_video_device_t *)calloc(1, sizeof(*device));
    if (!device) return SALTS_CAPTURE_ERR_NOMEM;
    device->ops = ops;

    result = ops->open_device(device_id, &device->backend_ctx);
    if (result != SALTS_CAPTURE_OK) {
        free(device);
        return result;
    }

    *out_device = device;
    return SALTS_CAPTURE_OK;
}

void salts_video_device_close(salts_video_device_t *device) {
    if (!device) return;
    device->ops->close_device(device->backend_ctx);
    free(device);
}

static int video_mode_fps_internal(const salts_video_native_mode_t *mode) {
    uint64_t rounded;

    if (!mode || mode->framerate_denominator == 0) return 0;
    rounded = ((uint64_t)mode->framerate_numerator +
               mode->framerate_denominator / 2u) /
              mode->framerate_denominator;
    return rounded <= INT_MAX ? (int)rounded : 0;
}

int salts_video_mode_fps(const salts_video_native_mode_t *mode) {
    return video_mode_fps_internal(mode);
}

/* Standard broadcast/webcam frame rates matched on the rounded integer fps
 * (29.97 -> 30, 59.94 -> 60, 23.976 -> 24, 119.88 -> 120, 89.91 -> 90). */
int salts_video_mode_is_standard_fps(const salts_video_native_mode_t *mode) {
    switch (video_mode_fps_internal(mode)) {
    case 24:
    case 25:
    case 30:
    case 50:
    case 60:
    case 90:
    case 120:
        return 1;
    default:
        return 0;
    }
}

int salts_video_device_list_modes(salts_video_device_t *device,
                                  salts_video_native_mode_t *modes,
                                  size_t capacity,
                                  size_t *out_count) {
    size_t count;
    size_t written;
    int result;

    if (out_count) *out_count = 0;
    if (!device || !modes || capacity == 0 ||
        capacity > SIZE_MAX / sizeof(*modes) || !out_count) {
        return SALTS_CAPTURE_ERR_FORMAT;
    }
    result = device->ops->list_modes(device->backend_ctx, modes,
                                     capacity, out_count);
    if (result != SALTS_CAPTURE_OK) return result;

    /* Default output: only standard frame rates (24/25/30/50/60/90/120).
     * Use salts_video_device_list_modes_all() for every native mode. */
    count = *out_count;
    written = 0;
    for (size_t i = 0; i < count; ++i) {
        if (salts_video_mode_is_standard_fps(&modes[i])) {
            modes[written++] = modes[i];
        }
    }
    *out_count = written;
    return SALTS_CAPTURE_OK;
}

int salts_video_device_list_modes_all(salts_video_device_t *device,
                                      salts_video_native_mode_t *modes,
                                      size_t capacity,
                                      size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!device || !modes || capacity == 0 ||
        capacity > SIZE_MAX / sizeof(*modes) || !out_count) {
        return SALTS_CAPTURE_ERR_FORMAT;
    }
    return device->ops->list_modes(device->backend_ctx, modes,
                                   capacity, out_count);
}

int salts_video_device_create_capture(salts_video_device_t *device,
                                      const salts_video_native_mode_t *mode,
                                      salts_capture_t **out_capture) {
    if (!out_capture) return SALTS_CAPTURE_ERR_FORMAT;
    *out_capture = NULL;
    if (!device || !mode || mode->width <= 0 || mode->height <= 0 ||
        mode->framerate_numerator == 0 || mode->framerate_denominator == 0 ||
        mode->format < SALTS_VIDEO_CAPTURE_FORMAT_I420 ||
        mode->format > SALTS_VIDEO_CAPTURE_FORMAT_MJPEG) {
        return SALTS_CAPTURE_ERR_FORMAT;
    }
    return device->ops->create_capture(device->backend_ctx, mode, out_capture);
}
