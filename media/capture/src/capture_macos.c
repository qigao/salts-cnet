/**
 * macOS Capture Dispatcher
 *
 * Centralizes capture start/stop/destroy for all types on macOS
 */
#include "capture.h"

#if defined(__APPLE__) && defined(__MACH__)

#include <stdlib.h>

/* Internal hooks from specific implementations */
extern int coreaudio_start(salts_capture_t *capture);
extern void coreaudio_stop(salts_capture_t *capture);
extern void coreaudio_destroy(salts_capture_t *capture);

extern int avfoundation_video_start(salts_capture_t *capture);
extern void avfoundation_video_stop(salts_capture_t *capture);
extern void avfoundation_video_destroy(salts_capture_t *capture);

extern int macos_screen_start(salts_capture_t *capture);
extern void macos_screen_stop(salts_capture_t *capture);
extern void macos_screen_destroy(salts_capture_t *capture);

int salts_capture_start(salts_capture_t *capture) {
    if (!capture) return -1;
    if (capture->state == SALTS_CAPTURE_STATE_RUNNING) return 0;

    capture->state = SALTS_CAPTURE_STATE_STARTING;

    int res = -1;
    switch (capture->type) {
        case SALTS_CAPTURE_TYPE_AUDIO:
            res = coreaudio_start(capture);
            break;
        case SALTS_CAPTURE_TYPE_VIDEO:
            res = avfoundation_video_start(capture);
            break;
        case SALTS_CAPTURE_TYPE_SCREEN:
            res = macos_screen_start(capture);
            break;
        default:
            return -1;
    }

    if (res == 0) {
        capture->state = SALTS_CAPTURE_STATE_RUNNING;
        if (capture->state_cb) {
            capture->state_cb(capture, capture->state, capture->user_data);
        }
    } else {
        capture->state = SALTS_CAPTURE_STATE_ERROR;
    }

    return res;
}

void salts_capture_stop(salts_capture_t *capture) {
    if (!capture || capture->state == SALTS_CAPTURE_STATE_STOPPED) return;

    capture->state = SALTS_CAPTURE_STATE_STOPPING;

    switch (capture->type) {
        case SALTS_CAPTURE_TYPE_AUDIO:
            coreaudio_stop(capture);
            break;
        case SALTS_CAPTURE_TYPE_VIDEO:
            avfoundation_video_stop(capture);
            break;
        case SALTS_CAPTURE_TYPE_SCREEN:
            macos_screen_stop(capture);
            break;
    }

    capture->state = SALTS_CAPTURE_STATE_STOPPED;
    if (capture->state_cb) {
        capture->state_cb(capture, capture->state, capture->user_data);
    }
}

void salts_capture_destroy(salts_capture_t *capture) {
    if (!capture) return;

    switch (capture->type) {
        case SALTS_CAPTURE_TYPE_AUDIO:
            coreaudio_destroy(capture);
            break;
        case SALTS_CAPTURE_TYPE_VIDEO:
            avfoundation_video_destroy(capture);
            break;
        case SALTS_CAPTURE_TYPE_SCREEN:
            macos_screen_destroy(capture);
            break;
    }
}

salts_capture_state_t salts_capture_get_state(salts_capture_t *capture) {
    return capture ? capture->state : SALTS_CAPTURE_STATE_STOPPED;
}

void salts_capture_on_state(salts_capture_t *capture, salts_capture_state_cb cb) {
    if (capture) capture->state_cb = cb;
}

int salts_capture_list_gpu_devices(salts_capture_device_t *devices, int max_count) {
    if (!devices || max_count <= 0) return -1;
    return 0;
}

#endif /* __APPLE__ && __MACH__ */
