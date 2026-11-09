#include "capture_video_frame.h"
#include <stdint.h>

static int plane(salts_video_frame_plane_t *out, const uint8_t *data,
    size_t size, size_t pitch, size_t row_bytes, size_t rows, size_t pixel,
    size_t *consumed) {
    if (!rows || pitch < row_bytes || pitch > SIZE_MAX / rows) return 0;
    const size_t storage = pitch * rows;
    const size_t span = pitch * (rows - 1u) + row_bytes;
    if (span > size) return 0;
    *out = (salts_video_frame_plane_t){data, span, pitch, pixel};
    *consumed = storage;
    return 1;
}

int salts_video_frame_build(salts_video_frame_v2_t *out, const uint8_t *data,
    size_t size, int width, int height, salts_video_frame_format_t format,
    size_t pitch, int bottom_up, uint64_t timestamp,
    salts_video_frame_clock_t clock, salts_video_frame_matrix_t matrix,
    salts_video_frame_range_t range) {
    salts_video_frame_v2_t f = {0};
    size_t used = 0u, count = 0u;
    if (!out || !data || !size || width <= 0 || height <= 0 ||
        (uintptr_t)data > UINTPTR_MAX - (size - 1u) ||
        bottom_up < 0 || bottom_up > 1) return SALTS_CAPTURE_ERR_FORMAT;
    const size_t w = (size_t)width, h = (size_t)height;
    f.struct_size = sizeof(f); f.version = 2u;
    f.format = format; f.width = width; f.height = height;
    f.timestamp = timestamp; f.timebase_numerator = 1u;
    f.timebase_denominator = 1000000u; f.clock = clock;
    f.color_matrix = matrix; f.color_range = range;
    f.rotation_degrees = -1; f.mirrored = -1; f.bottom_up = bottom_up;
    if (format == SALTS_VIDEO_FRAME_MJPEG) {
        f.plane_count = 1u;
        f.planes[0] = (salts_video_frame_plane_t){data, size, 0u, 0u};
    } else if (format == SALTS_VIDEO_FRAME_I420 || format == SALTS_VIDEO_FRAME_YV12 || format == SALTS_VIDEO_FRAME_NV12) {
        if (bottom_up) return SALTS_CAPTURE_ERR_UNSUPPORTED;
        if (!pitch) pitch = w;
        const size_t cw = (w + 1u) / 2u, ch = (h + 1u) / 2u;
        if (!plane(&f.planes[0], data, size, pitch, w, h, 1u, &used) || used > size)
            return SALTS_CAPTURE_ERR_FORMAT;
        if (format != SALTS_VIDEO_FRAME_NV12) {
            const size_t cp = pitch / 2u + pitch % 2u;
            if (!plane(&f.planes[1], data + used, size - used, cp, cw, ch, 1u, &count) ||
                count > size - used) return SALTS_CAPTURE_ERR_FORMAT;
            used += count;
            if (!plane(&f.planes[2], data + used, size - used, cp, cw, ch, 1u, &count))
                return SALTS_CAPTURE_ERR_FORMAT;
            f.plane_count = 3u;
        } else {
            const size_t cp = pitch < cw * 2u ? cw * 2u : pitch;
            if (!plane(&f.planes[1], data + used, size - used, cp, cw * 2u, ch, 2u, &count))
                return SALTS_CAPTURE_ERR_FORMAT;
            f.plane_count = 2u;
        }
    } else {
        size_t pixel;
        if (format == SALTS_VIDEO_FRAME_RGB24 || format == SALTS_VIDEO_FRAME_BGR24) pixel = 3u;
        else if (format == SALTS_VIDEO_FRAME_BGRA) pixel = 4u;
        else return SALTS_CAPTURE_ERR_UNSUPPORTED;
        if (w > SIZE_MAX / pixel) return SALTS_CAPTURE_ERR_FORMAT;
        const size_t row = w * pixel;
        if (!pitch) pitch = row;
        if (!plane(&f.planes[0], data, size, pitch, row, h, pixel, &used))
            return SALTS_CAPTURE_ERR_FORMAT;
        f.plane_count = 1u;
    }
    *out = f;
    return SALTS_CAPTURE_OK;
}

int salts_video_capture_set_callback_v2(salts_capture_t *capture,
    salts_video_capture_cb_v2 callback, void *user) {
    if (!capture || capture->type != SALTS_CAPTURE_TYPE_VIDEO || !capture->platform_ctx)
        return SALTS_CAPTURE_ERR_FORMAT;
    if (capture->state != SALTS_CAPTURE_STATE_STOPPED) return SALTS_CAPTURE_ERR_BUSY;
    salts_video_frame_sink *sink = salts_video_platform_frame_sink(capture);
    if (!sink || (callback && sink->unsupported)) return SALTS_CAPTURE_ERR_UNSUPPORTED;
    sink->callback = callback; sink->user = user;
    return SALTS_CAPTURE_OK;
}

int salts_video_frame_has_callback(salts_capture_t *capture) {
    if (!capture) return 0;
    salts_video_frame_sink *sink = salts_video_platform_frame_sink(capture);
    return sink && capture->state != SALTS_CAPTURE_STATE_ERROR && (sink->callback || capture->video_cb);
}

int salts_video_frame_deliver(salts_capture_t *capture, const uint8_t *data,
    size_t size, int width, int height, salts_video_frame_format_t format,
    size_t pitch, int bottom_up, uint64_t timestamp,
    salts_video_frame_clock_t clock, salts_video_frame_matrix_t matrix,
    salts_video_frame_range_t range) {
    salts_video_frame_sink *sink = salts_video_platform_frame_sink(capture);
    if (!sink || capture->state == SALTS_CAPTURE_STATE_ERROR) return SALTS_CAPTURE_ERR_FORMAT;
    if (sink->callback) {
        salts_video_frame_v2_t frame;
        int status = salts_video_frame_build(&frame, data, size, width, height,
            format, pitch, bottom_up, timestamp, clock, matrix, range);
        if (status != SALTS_CAPTURE_OK) {
            capture->state = SALTS_CAPTURE_STATE_ERROR;
            if (capture->state_cb) capture->state_cb(capture, capture->state, capture->user_data);
            return status;
        }
        sink->callback(capture, &frame, sink->user);
    } else if (capture->video_cb) {
        capture->video_cb(capture, data, size, width, height, timestamp, capture->user_data);
    }
    return SALTS_CAPTURE_OK;
}
