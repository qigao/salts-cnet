/**
 * Android Screen Capture
 *
 * Uses MediaProjection API for screen recording
 * Requires Java/JNI bridge for permission handling
 */
#include <jni.h>
#include <libyuv/convert.h>
#include <limits.h>
#include <media/NdkImageReader.h>
#include <media/NdkImage.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <thread.h>
#include <capture.h>
#include <tlog.h>

/* =============================================================================
 * Screen Capture Context
 * ============================================================================= */

typedef struct android_screen_ctx_t {
    AImageReader *image_reader;
    ANativeWindow *image_reader_window;
    AImageReader_ImageListener image_listener;

    /* Configuration */
    int width;
    int height;
    int framerate;

    /* State */
    int capturing;
    int starting;
    size_t active_callbacks;
    cmeta_mutex_t state_mutex;
    cmeta_cond_t callbacks_idle;
    atomic_uint_fast64_t frame_count;

    /* Java objects (passed from JNI) */
    jobject media_projection;  /* MediaProjection instance */
    jobject virtual_display;   /* VirtualDisplay instance */

    /* Callback */
    void (*on_frame)(void *user_data, const uint8_t *data, size_t len,
                     int width, int height, int64_t timestamp_us);
    void *user_data;
} android_screen_ctx_t;

int android_screen_stop(android_screen_ctx_t *ctx);

/* =============================================================================
 * Image Reader Callback
 * ============================================================================= */

static void on_image_available(void *context, AImageReader *reader) {
    android_screen_ctx_t *ctx = (android_screen_ctx_t *)context;
    void (*on_frame)(void *, const uint8_t *, size_t, int, int, int64_t);
    void *user_data;
    int deliver_frame;

    cmeta_mutex_lock(&ctx->state_mutex);
    ctx->active_callbacks++;
    deliver_frame = ctx->capturing;
    on_frame = ctx->on_frame;
    user_data = ctx->user_data;
    cmeta_mutex_unlock(&ctx->state_mutex);

    AImage *image = NULL;
    media_status_t status = AImageReader_acquireLatestImage(reader, &image);

    if (status != AMEDIA_OK || !image) {
        goto callback_complete;
    }
    if (!deliver_frame) {
        goto image_complete;
    }

    /* Get image properties */
    int32_t format = 0;
    int32_t width, height;
    int64_t timestamp = 0;

    if (AImage_getFormat(image, &format) != AMEDIA_OK ||
        AImage_getWidth(image, &width) != AMEDIA_OK ||
        AImage_getHeight(image, &height) != AMEDIA_OK ||
        AImage_getTimestamp(image, &timestamp) != AMEDIA_OK ||
        format != AIMAGE_FORMAT_RGBA_8888 || width <= 0 || height <= 0) {
        goto image_complete;
    }

    /* Get RGBA plane (screen capture is typically RGBA) */
    uint8_t *rgba_data = NULL;
    int rgba_len = 0;
    int32_t rgba_stride = 0;
    int32_t rgba_pixel_stride = 0;
    if (width > INT_MAX / 4) {
        goto image_complete;
    }

    if (AImage_getPlaneData(image, 0, &rgba_data, &rgba_len) != AMEDIA_OK ||
        AImage_getPlaneRowStride(image, 0, &rgba_stride) != AMEDIA_OK ||
        AImage_getPlanePixelStride(image, 0, &rgba_pixel_stride) != AMEDIA_OK ||
        !rgba_data || rgba_len < 0 || rgba_stride < width * 4 || rgba_pixel_stride != 4) {
        goto image_complete;
    }

    size_t rgba_row_tail = (size_t)width * 4u;
    size_t prior_rows = (size_t)(height - 1);
    if ((prior_rows > 0u &&
         (size_t)rgba_stride > (SIZE_MAX - rgba_row_tail) / prior_rows) ||
        (size_t)width > SIZE_MAX / (size_t)height) {
        goto image_complete;
    }

    size_t required_rgba_size = (size_t)rgba_stride * prior_rows + rgba_row_tail;
    if ((size_t)rgba_len < required_rgba_size) {
        goto image_complete;
    }

    size_t y_size = (size_t)width * (size_t)height;
    size_t uv_width = ((size_t)width + 1u) / 2u;
    size_t uv_height = ((size_t)height + 1u) / 2u;
    size_t uv_size = uv_width * uv_height;
    if (uv_size > (SIZE_MAX - y_size) / 2u) {
        goto image_complete;
    }

    size_t i420_size = y_size + 2u * uv_size;
    uint8_t *i420_data = (uint8_t *)malloc(i420_size);
    if (i420_data) {
        uint8_t *y = i420_data;
        uint8_t *u = y + y_size;
        uint8_t *v = u + uv_size;

        int convert_result = ABGRToI420(rgba_data, rgba_stride,
                                        y, width,
                                        u, (int)uv_width,
                                        v, (int)uv_width,
                                        width, height);
        if (convert_result == 0) {
            atomic_fetch_add_explicit(&ctx->frame_count, 1u, memory_order_relaxed);
            if (on_frame) {
                on_frame(user_data, i420_data, i420_size,
                         width, height, timestamp / 1000);  /* ns to us */
            }
        }

        free(i420_data);
    }

image_complete:
    AImage_delete(image);

callback_complete:
    cmeta_mutex_lock(&ctx->state_mutex);
    ctx->active_callbacks--;
    if (ctx->active_callbacks == 0) {
        cmeta_cond_broadcast(&ctx->callbacks_idle);
    }
    cmeta_mutex_unlock(&ctx->state_mutex);
}

/* =============================================================================
 * Screen Capture Management
 * ============================================================================= */

int android_screen_create(int width, int height, int framerate,
                          android_screen_ctx_t **out_ctx) {
    int result = SALTS_CAPTURE_ERR_DEVICE;
    android_screen_ctx_t *ctx;

    if (!out_ctx || width <= 0 || height <= 0 || framerate <= 0) {
        return SALTS_CAPTURE_ERR_FORMAT;
    }
    *out_ctx = NULL;
    ctx = (android_screen_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return SALTS_CAPTURE_ERR_NOMEM;

    ctx->width = width;
    ctx->height = height;
    ctx->framerate = framerate;
    ctx->capturing = 0;
    cmeta_mutex_init(&ctx->state_mutex);
    if (!ctx->state_mutex) {
        result = SALTS_CAPTURE_ERR_NOMEM;
        goto create_failed;
    }
    cmeta_cond_init(&ctx->callbacks_idle);
    if (!ctx->callbacks_idle) {
        result = SALTS_CAPTURE_ERR_NOMEM;
        goto create_failed;
    }
    atomic_init(&ctx->frame_count, 0u);
    ctx->image_listener.context = ctx;
    ctx->image_listener.onImageAvailable = on_image_available;

    /* Create image reader for RGBA format */
    media_status_t status = AImageReader_new(
        width, height,
        AIMAGE_FORMAT_RGBA_8888,
        2,  /* Max images */
        &ctx->image_reader
    );

    if (status != AMEDIA_OK) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to create image reader");
        goto create_failed;
    }

    /* Set image listener */
    status = AImageReader_setImageListener(ctx->image_reader, &ctx->image_listener);
    if (status != AMEDIA_OK) {
        SALTS_LOG_ERRORF(tlog_get_default(), "capture", "Failed to set screen image listener: {}", status);
        AImageReader_delete(ctx->image_reader);
        ctx->image_reader = NULL;
        goto create_failed;
    }

    /* Get image reader window */
    status = AImageReader_getWindow(ctx->image_reader, &ctx->image_reader_window);
    if (status != AMEDIA_OK || !ctx->image_reader_window) {
        SALTS_LOG_ERRORF(tlog_get_default(), "capture", "Failed to get screen image reader surface: {}", status);
        AImageReader_delete(ctx->image_reader);
        ctx->image_reader = NULL;
        goto create_failed;
    }

    *out_ctx = ctx;
    return SALTS_CAPTURE_OK;

create_failed:
    cmeta_cond_destroy(&ctx->callbacks_idle);
    cmeta_mutex_destroy(&ctx->state_mutex);
    free(ctx);
    return result;
}

void android_screen_destroy(android_screen_ctx_t *ctx) {
    if (!ctx) return;

    cmeta_mutex_lock(&ctx->state_mutex);
    ctx->capturing = 0;
    ctx->starting = 0;
    cmeta_mutex_unlock(&ctx->state_mutex);

    if (ctx->image_reader) {
        AImageReader_setImageListener(ctx->image_reader, NULL);
    }

    cmeta_mutex_lock(&ctx->state_mutex);
    while (ctx->active_callbacks != 0) {
        cmeta_cond_wait(&ctx->callbacks_idle, &ctx->state_mutex);
    }
    ctx->media_projection = NULL;
    ctx->virtual_display = NULL;
    cmeta_mutex_unlock(&ctx->state_mutex);

    if (ctx->image_reader) {
        AImageReader_delete(ctx->image_reader);
    }

    cmeta_cond_destroy(&ctx->callbacks_idle);
    cmeta_mutex_destroy(&ctx->state_mutex);
    free(ctx);
}

/* Java owns MediaProjection and the VirtualDisplay.  The native lifecycle may
 * start before Java attaches the ImageReader surface; frames begin only after
 * that attachment. */

int android_screen_start(android_screen_ctx_t *ctx, jobject media_projection) {
    if (!ctx) return -1;

    cmeta_mutex_lock(&ctx->state_mutex);
    if (ctx->capturing || ctx->starting) {
        cmeta_mutex_unlock(&ctx->state_mutex);
        return -1;
    }

    ctx->media_projection = media_projection;
    ctx->starting = 1;
    cmeta_mutex_unlock(&ctx->state_mutex);
    return 0;
}

int android_screen_commit_start(android_screen_ctx_t *ctx) {
    AImage *stale_image = NULL;
    media_status_t status;

    if (!ctx) return -1;

    cmeta_mutex_lock(&ctx->state_mutex);
    if (!ctx->starting || ctx->capturing) {
        cmeta_mutex_unlock(&ctx->state_mutex);
        return -1;
    }

    while (ctx->active_callbacks != 0) {
        cmeta_cond_wait(&ctx->callbacks_idle, &ctx->state_mutex);
    }
    status = AImageReader_acquireLatestImage(ctx->image_reader, &stale_image);
    if (status == AMEDIA_OK) {
        if (!stale_image) {
            ctx->starting = 0;
            ctx->media_projection = NULL;
            cmeta_mutex_unlock(&ctx->state_mutex);
            return -1;
        }
        AImage_delete(stale_image);
    } else if (status != AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE) {
        ctx->starting = 0;
        ctx->media_projection = NULL;
        cmeta_mutex_unlock(&ctx->state_mutex);
        return -1;
    }

    ctx->capturing = 1;
    ctx->starting = 0;
    cmeta_mutex_unlock(&ctx->state_mutex);

    /* The public state is RUNNING before this delivery gate is committed. */

    return 0;
}

int android_screen_stop(android_screen_ctx_t *ctx) {
    if (!ctx) return -1;

    cmeta_mutex_lock(&ctx->state_mutex);
    if (!ctx->capturing && !ctx->starting) {
        cmeta_mutex_unlock(&ctx->state_mutex);
        return -1;
    }
    ctx->capturing = 0;
    ctx->starting = 0;
    while (ctx->active_callbacks != 0) {
        cmeta_cond_wait(&ctx->callbacks_idle, &ctx->state_mutex);
    }
    ctx->media_projection = NULL;
    ctx->virtual_display = NULL;
    cmeta_mutex_unlock(&ctx->state_mutex);

    return 0;
}

void android_screen_set_callback(android_screen_ctx_t *ctx,
                                 void (*callback)(void *user_data,
                                                 const uint8_t *data, size_t len,
                                                 int width, int height,
                                                 int64_t timestamp_us),
                                 void *user_data) {
    if (!ctx) return;
    cmeta_mutex_lock(&ctx->state_mutex);
    ctx->on_frame = callback;
    ctx->user_data = user_data;
    cmeta_mutex_unlock(&ctx->state_mutex);
}

ANativeWindow *android_screen_get_surface(android_screen_ctx_t *ctx) {
    return ctx ? ctx->image_reader_window : NULL;
}

uint64_t android_screen_get_frame_count(const android_screen_ctx_t *ctx) {
    return ctx ? atomic_load_explicit(&ctx->frame_count, memory_order_relaxed) : 0u;
}
