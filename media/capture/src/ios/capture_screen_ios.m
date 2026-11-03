/**
 * iOS Screen Capture Implementation
 *
 * Uses ReplayKit and emits contiguous NV12 frames through salts_video_capture_cb.
 */

#import <Foundation/Foundation.h>
#import <ReplayKit/ReplayKit.h>
#import "capture_ios_guard.h"
#include "capture.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    salts_capture_t base;
    RPScreenRecorder *recorder;
    uint8_t *frame_buffer;
    size_t frame_buffer_size;
    int is_running;
    SaltsCaptureGuard *guard;
} ios_screen_capture_t;

static void ios_screen_finalize(void *capture) {
    ios_screen_capture_t *cap = (ios_screen_capture_t *)capture;
    free(cap->frame_buffer);
    cap->frame_buffer = NULL;
    cap->frame_buffer_size = 0;
    cap->guard = nil;
    free(cap);
}

static uint8_t *copy_nv12_frame(ios_screen_capture_t *cap,
                               CVPixelBufferRef pixel_buffer,
                               int *width,
                               int *height,
                               size_t *len) {
    const size_t w = CVPixelBufferGetWidth(pixel_buffer);
    const size_t h = CVPixelBufferGetHeight(pixel_buffer);
    if (w == 0 || h == 0 || w > INT_MAX || h > INT_MAX ||
        w > SIZE_MAX / h) {
        return NULL;
    }
    const size_t y_size = w * h;
    const size_t uv_size = y_size / 2;
    if (y_size > SIZE_MAX - uv_size ||
        CVPixelBufferGetPlaneCount(pixel_buffer) < 2) {
        return NULL;
    }
    const size_t needed = y_size + uv_size;

    if (cap->frame_buffer_size < needed) {
        uint8_t *new_buffer = realloc(cap->frame_buffer, needed);
        if (!new_buffer) return NULL;
        cap->frame_buffer = new_buffer;
        cap->frame_buffer_size = needed;
    }

    uint8_t *dst_y = cap->frame_buffer;
    uint8_t *dst_uv = cap->frame_buffer + y_size;
    const uint8_t *src_y = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 0);
    const uint8_t *src_uv = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 1);
    const size_t stride_y = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 0);
    const size_t stride_uv = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 1);
    if (!src_y || !src_uv || stride_y < w || stride_uv < w) return NULL;

    for (size_t row = 0; row < h; ++row) {
        memcpy(dst_y + row * w, src_y + row * stride_y, w);
    }
    for (size_t row = 0; row < h / 2; ++row) {
        memcpy(dst_uv + row * w, src_uv + row * stride_uv, w);
    }

    *width = (int)w;
    *height = (int)h;
    *len = needed;
    return cap->frame_buffer;
}

int ios_screen_start(salts_capture_t *capture) {
    ios_screen_capture_t *cap = (ios_screen_capture_t *)capture;

    @autoreleasepool {
        if (!cap->recorder.isAvailable) {
            return -1;
        }

        SaltsCaptureGuard *guard = cap->guard;
        [cap->recorder
            startCaptureWithHandler:^(CMSampleBufferRef sample_buffer,
                                      RPSampleBufferType buffer_type,
                                      NSError *error) {
                ios_screen_capture_t *cap_ref =
                    (ios_screen_capture_t *)[guard acquireCapture];
                if (!cap_ref) return;

                if (!cap_ref->base.video_cb) {
                    [guard releaseCapture];
                    return;
                }

                if (error) {
                    [guard releaseCapture];
                    return;
                }

                if (buffer_type != RPSampleBufferTypeVideo) {
                    [guard releaseCapture];
                    return;
                }

                CVPixelBufferRef pixel_buffer = CMSampleBufferGetImageBuffer(sample_buffer);
                if (!pixel_buffer) {
                    [guard releaseCapture];
                    return;
                }

                CVPixelBufferLockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);

                int width = 0;
                int height = 0;
                size_t len = 0;
                uint8_t *frame = copy_nv12_frame(cap_ref, pixel_buffer, &width, &height, &len);
                if (frame) {
                    CMTime pts = CMSampleBufferGetPresentationTimeStamp(sample_buffer);
                    uint64_t timestamp = (uint64_t)(CMTimeGetSeconds(pts) * 1000000.0);
                    cap_ref->base.video_cb((salts_capture_t *)cap_ref, frame, len,
                                           width, height, timestamp,
                                           cap_ref->base.user_data);
                }

                CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
                [guard releaseCapture];
            }
            completionHandler:^(NSError *error) {
                ios_screen_capture_t *cap_ref =
                    (ios_screen_capture_t *)[guard acquireCapture];
                if (!cap_ref) return;
                if (error) {
                    cap_ref->is_running = 0;
                    cap_ref->base.state = SALTS_CAPTURE_STATE_ERROR;
                    if (cap_ref->base.state_cb) {
                        cap_ref->base.state_cb((salts_capture_t *)cap_ref,
                                               cap_ref->base.state,
                                               cap_ref->base.user_data);
                    }
                } else {
                    cap_ref->is_running = 1;
                }
                [guard releaseCapture];
            }];

        return 0;
    }
}

void ios_screen_stop(salts_capture_t *capture) {
    ios_screen_capture_t *cap = (ios_screen_capture_t *)capture;

    @autoreleasepool {
        SaltsCaptureGuard *guard = cap->guard;
        [cap->recorder stopCaptureWithHandler:^(NSError *error) {
            (void)error;
            ios_screen_capture_t *cap_ref =
                (ios_screen_capture_t *)[guard acquireCapture];
            if (cap_ref) {
                cap_ref->is_running = 0;
                [guard releaseCapture];
            }
        }];
    }
}

void ios_screen_destroy(salts_capture_t *capture) {
    ios_screen_capture_t *cap = (ios_screen_capture_t *)capture;

    @autoreleasepool {
        if (cap->recorder) {
            [cap->recorder stopCaptureWithHandler:nil];
        }

        cap->recorder = nil;
        [cap->guard detachOwner];
    }
}

salts_capture_t *salts_screen_capture_create(const salts_screen_capture_config_t *config) {
    (void)config;

    @autoreleasepool {
        ios_screen_capture_t *cap = calloc(1, sizeof(ios_screen_capture_t));
        if (!cap) return NULL;

        cap->guard = [[SaltsCaptureGuard alloc] initWithCapture:cap
                                                     finalizer:ios_screen_finalize];
        if (!cap->guard) {
            free(cap);
            return NULL;
        }

        cap->base.type = SALTS_CAPTURE_TYPE_SCREEN;
        cap->base.state = SALTS_CAPTURE_STATE_STOPPED;
        cap->base.platform_ctx = cap;
        cap->recorder = [RPScreenRecorder sharedRecorder];

        if (!cap->recorder.isAvailable) {
            cap->recorder = nil;
            [cap->guard detachOwner];
            return NULL;
        }

        return (salts_capture_t *)cap;
    }
}
