#include "../src/capture_video_frame.h"
#include <tinytest.h>
#include <limits.h>
#include <string.h>

static int build(salts_video_frame_v2_t *out, const uint8_t *data, size_t size,
    int w, int h, salts_video_frame_format_t format, size_t pitch, int bottom_up) {
    return salts_video_frame_build(out, data, size, w, h, format, pitch, bottom_up,
        123456u, SALTS_VIDEO_FRAME_CLOCK_MONOTONIC,
        SALTS_VIDEO_FRAME_MATRIX_UNKNOWN, SALTS_VIDEO_FRAME_RANGE_UNKNOWN);
}

suite("CPU video frame descriptors") {
    static uint8_t data[64];
    static salts_video_frame_v2_t frame;
    before_each() { memset(data, 0x35, sizeof(data)); memset(&frame, 0xa5, sizeof(frame)); }

    it("describes odd I420 planes without truncating chroma") {
        check_equal(build(&frame, data, 17u, 3, 3, SALTS_VIDEO_FRAME_I420, 0u, 0), SALTS_CAPTURE_OK);
        check_equal(frame.struct_size, sizeof(frame)); check_equal(frame.version, 2u);
        check_equal(frame.plane_count, 3u);
        check_equal(frame.planes[0].data, data); check_equal(frame.planes[0].size, 9u);
        check_equal(frame.planes[1].data, data + 9u); check_equal(frame.planes[1].size, 4u);
        check_equal(frame.planes[2].data, data + 13u); check_equal(frame.planes[2].row_stride, 2u);
        check_equal(frame.timestamp, 123456u); check_equal(frame.timebase_denominator, 1000000u);
        check_equal(frame.clock, SALTS_VIDEO_FRAME_CLOCK_MONOTONIC);
        check_equal(frame.rotation_degrees, -1); check_equal(frame.mirrored, -1);
    }
    it("describes odd NV12 UV pairs and padded planar storage") {
        check_equal(build(&frame, data, 17u, 3, 3, SALTS_VIDEO_FRAME_NV12, 0u, 0), SALTS_CAPTURE_OK);
        check_equal(frame.plane_count, 2u); check_equal(frame.planes[1].row_stride, 4u);
        check_equal(frame.planes[1].pixel_stride, 2u); check_equal(frame.planes[1].size, 8u);
        check_equal(build(&frame, data, 20u, 3, 3, SALTS_VIDEO_FRAME_YV12, 4u, 0), SALTS_CAPTURE_OK);
        check_equal(frame.format, SALTS_VIDEO_FRAME_YV12);
        check_equal(frame.planes[0].size, 11u);
        check_equal(frame.planes[1].data, data + 12u); check_equal(frame.planes[2].data, data + 16u);
    }
    it("preserves packed row padding and bottom-up order") {
        check_equal(build(&frame, data, 21u, 3, 2, SALTS_VIDEO_FRAME_BGR24, 12u, 1), SALTS_CAPTURE_OK);
        check_equal(frame.planes[0].size, 21u); check_equal(frame.planes[0].row_stride, 12u);
        check_equal(frame.planes[0].pixel_stride, 3u); check_equal(frame.bottom_up, 1);
        check_equal(build(&frame, data, 16u, 2, 2, SALTS_VIDEO_FRAME_BGRA, 0u, 0), SALTS_CAPTURE_OK);
        check_equal(frame.planes[0].pixel_stride, 4u);
    }
    it("represents one borrowed complete MJPEG image") {
        check_equal(build(&frame, data, 7u, 9, 5, SALTS_VIDEO_FRAME_MJPEG, 0u, 0), SALTS_CAPTURE_OK);
        check_equal(frame.plane_count, 1u); check_equal(frame.planes[0].size, 7u);
        check_equal(frame.planes[0].row_stride, 0u); check_equal(frame.planes[0].pixel_stride, 0u);
        check_equal(data[0], 0x35);
    }
    it("rejects short planes, invalid pitches and overflow without publishing") {
        salts_video_frame_v2_t before = frame;
        check_equal(build(&frame, data, 16u, 3, 3, SALTS_VIDEO_FRAME_I420, 0u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(&frame, &before, sizeof(frame));
        check_equal(build(&frame, data, 16u, 3, 3, SALTS_VIDEO_FRAME_NV12, 0u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(build(&frame, data, sizeof(data), 3, 3, SALTS_VIDEO_FRAME_RGB24, 8u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(build(&frame, data, sizeof(data), 1, 2, SALTS_VIDEO_FRAME_RGB24, SIZE_MAX, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(build(&frame, data, sizeof(data), INT_MAX, INT_MAX, SALTS_VIDEO_FRAME_BGRA, 0u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(build(&frame, data, sizeof(data), 3, 3, SALTS_VIDEO_FRAME_I420, 0u, 1), SALTS_CAPTURE_ERR_UNSUPPORTED);
        check_equal(build(&frame, data, sizeof(data), 3, 3, (salts_video_frame_format_t)99, 0u, 0), SALTS_CAPTURE_ERR_UNSUPPORTED);
        check_equal(build(&frame, data, 0u, 3, 3, SALTS_VIDEO_FRAME_I420, 0u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(build(&frame, NULL, 17u, 3, 3, SALTS_VIDEO_FRAME_I420, 0u, 0), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(&frame, &before, sizeof(frame));
    }
    it("requires a valid stopped camera owner before native registration") {
        salts_capture_t capture = {0};
        check_equal(salts_video_capture_set_callback_v2(NULL, NULL, NULL), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(salts_video_capture_set_callback_v2(&capture, NULL, NULL), SALTS_CAPTURE_ERR_FORMAT);
        capture.type = SALTS_CAPTURE_TYPE_VIDEO; capture.platform_ctx = &capture;
        capture.state = SALTS_CAPTURE_STATE_RUNNING;
        check_equal(salts_video_capture_set_callback_v2(&capture, NULL, NULL), SALTS_CAPTURE_ERR_BUSY);
    }
}
