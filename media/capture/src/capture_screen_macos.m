/**
 * macOS Screen Capture Implementation
 *
 * Uses ScreenCaptureKit for display capture. ScreenCaptureKit is the supported
 * replacement for CGDisplayStream on current macOS SDKs.
 */
#import "capture.h"

#if defined(__APPLE__) && defined(__MACH__)

#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <mach/mach_time.h>
#import <stdlib.h>
#import <string.h>
#import <dispatch/dispatch.h>

typedef struct salts_screen_ctx_s salts_screen_ctx_t;
@class SaltsScreenStreamOutput;

struct salts_screen_ctx_s {
    SCStream *stream;
    SaltsScreenStreamOutput *stream_output;
    dispatch_queue_t capture_queue;
    CGDirectDisplayID display_id;

    volatile int running;

    int monitor_index;
    int framerate;
    int capture_cursor;
    int width;
    int height;

    uint8_t *frame_buffer;
    size_t frame_buffer_size;

    salts_capture_t *capture;
};

@interface SaltsScreenStreamOutput : NSObject <SCStreamOutput> {
@public
    salts_screen_ctx_t *ctx;
}
@end

static uint64_t get_timestamp_us(void) {
    static mach_timebase_info_data_t timebase = {0};
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    uint64_t time = mach_absolute_time();
    return (time * timebase.numer / timebase.denom) / 1000;
}

static int ensure_frame_buffer(salts_screen_ctx_t *ctx, size_t required_size) {
    if (!ctx) return -1;
    if (required_size <= ctx->frame_buffer_size) return 0;

    uint8_t *new_buffer = (uint8_t *)realloc(ctx->frame_buffer, required_size);
    if (!new_buffer) return -1;

    ctx->frame_buffer = new_buffer;
    ctx->frame_buffer_size = required_size;
    return 0;
}

@implementation SaltsScreenStreamOutput

- (void)stream:(SCStream *)stream
didOutputSampleBuffer:(CMSampleBufferRef)sample_buffer
        ofType:(SCStreamOutputType)type {
    (void)stream;

    if (type != SCStreamOutputTypeScreen || !ctx || !ctx->running) return;
    if (!CMSampleBufferIsValid(sample_buffer) ||
        !CMSampleBufferDataIsReady(sample_buffer)) {
        return;
    }

    CVImageBufferRef image_buffer = CMSampleBufferGetImageBuffer(sample_buffer);
    if (!image_buffer) return;

    CVPixelBufferRef pixel_buffer = (CVPixelBufferRef)image_buffer;
    if (CVPixelBufferGetPixelFormatType(pixel_buffer) != kCVPixelFormatType_32BGRA) {
        return;
    }

    CVReturn lock_result =
        CVPixelBufferLockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
    if (lock_result != kCVReturnSuccess) return;

    void *base_address = CVPixelBufferGetBaseAddress(pixel_buffer);
    size_t bytes_per_row = CVPixelBufferGetBytesPerRow(pixel_buffer);
    size_t width = CVPixelBufferGetWidth(pixel_buffer);
    size_t height = CVPixelBufferGetHeight(pixel_buffer);

    if (!base_address || width == 0 || height == 0 ||
        width > SIZE_MAX / 4 || height > SIZE_MAX / (width * 4)) {
        CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
        return;
    }

    size_t packed_bytes_per_row = width * 4;
    size_t frame_size = packed_bytes_per_row * height;
    const uint8_t *frame_data = (const uint8_t *)base_address;

    if (bytes_per_row != packed_bytes_per_row) {
        if (ensure_frame_buffer(ctx, frame_size) != 0) {
            CVPixelBufferUnlockBaseAddress(pixel_buffer,
                                           kCVPixelBufferLock_ReadOnly);
            return;
        }

        const uint8_t *src = (const uint8_t *)base_address;
        uint8_t *dst = ctx->frame_buffer;
        for (size_t y = 0; y < height; ++y) {
            memcpy(dst, src, packed_bytes_per_row);
            src += bytes_per_row;
            dst += packed_bytes_per_row;
        }
        frame_data = ctx->frame_buffer;
    }

    salts_capture_t *capture = ctx->capture;
    if (capture && capture->video_cb && ctx->running) {
        capture->video_cb(capture,
                          frame_data,
                          frame_size,
                          (int)width,
                          (int)height,
                          get_timestamp_us(),
                          capture->user_data);
    }

    CVPixelBufferUnlockBaseAddress(pixel_buffer, kCVPixelBufferLock_ReadOnly);
}

@end

int salts_capture_list_screens(salts_capture_device_t *devices, int max_count) {
    if (!devices || max_count <= 0) return -1;

    CGDirectDisplayID display_ids[16];
    uint32_t display_count = 0;

    CGError err = CGGetActiveDisplayList(16, display_ids, &display_count);
    if (err != kCGErrorSuccess) return -1;

    int count = 0;
    CGDirectDisplayID main_display = CGMainDisplayID();

    for (uint32_t i = 0; i < display_count && count < max_count; ++i) {
        CGDirectDisplayID display_id = display_ids[i];

        salts_capture_device_t *dev = &devices[count];
        memset(dev, 0, sizeof(*dev));

        dev->index = count;
        dev->type = SALTS_CAPTURE_TYPE_SCREEN;
        dev->is_default = (display_id == main_display) ? 1 : 0;

        size_t width = CGDisplayPixelsWide(display_id);
        size_t height = CGDisplayPixelsHigh(display_id);

        snprintf(dev->name,
                 sizeof(dev->name),
                 "Display %d (%zux%zu)",
                 count,
                 width,
                 height);
        snprintf(dev->id, sizeof(dev->id), "%u", display_id);
        ++count;
    }

    return count;
}

salts_capture_t *salts_screen_capture_create(
    const salts_screen_capture_config_t *config) {
    salts_capture_t *capture =
        (salts_capture_t *)calloc(1, sizeof(salts_capture_t));
    if (!capture) return NULL;

    salts_screen_ctx_t *ctx =
        (salts_screen_ctx_t *)calloc(1, sizeof(salts_screen_ctx_t));
    if (!ctx) {
        free(capture);
        return NULL;
    }

    capture->type = SALTS_CAPTURE_TYPE_SCREEN;
    capture->state = SALTS_CAPTURE_STATE_STOPPED;
    capture->platform_ctx = ctx;
    ctx->capture = capture;

    ctx->monitor_index = config ? config->monitor_index : -1;
    ctx->framerate = config && config->framerate > 0 ? config->framerate : 30;
    ctx->capture_cursor = config ? config->capture_cursor : 1;

    if (ctx->monitor_index < 0) {
        ctx->display_id = CGMainDisplayID();
    } else {
        CGDirectDisplayID display_ids[16];
        uint32_t display_count = 0;
        if (CGGetActiveDisplayList(16, display_ids, &display_count) !=
            kCGErrorSuccess) {
            free(ctx);
            free(capture);
            return NULL;
        }

        if (ctx->monitor_index >= (int)display_count) {
            free(ctx);
            free(capture);
            return NULL;
        }
        ctx->display_id = display_ids[ctx->monitor_index];
    }

    ctx->width = (int)CGDisplayPixelsWide(ctx->display_id);
    ctx->height = (int)CGDisplayPixelsHigh(ctx->display_id);
    if (ctx->width <= 0 || ctx->height <= 0) {
        free(ctx);
        free(capture);
        return NULL;
    }

    ctx->frame_buffer_size = (size_t)ctx->width * (size_t)ctx->height * 4;
    ctx->frame_buffer = (uint8_t *)malloc(ctx->frame_buffer_size);
    if (!ctx->frame_buffer) {
        free(ctx);
        free(capture);
        return NULL;
    }

    ctx->capture_queue =
        dispatch_queue_create("salts.screen.capture", DISPATCH_QUEUE_SERIAL);
    if (!ctx->capture_queue) {
        free(ctx->frame_buffer);
        free(ctx);
        free(capture);
        return NULL;
    }

    return capture;
}

void salts_screen_capture_set_callback(salts_capture_t *capture,
                                       salts_video_capture_cb cb,
                                       void *user_data) {
    if (!capture) return;
    capture->video_cb = cb;
    capture->user_data = user_data;
}

static SCDisplay *find_shareable_display(CGDirectDisplayID display_id) {
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    if (!semaphore) return nil;

    __block SCDisplay *selected_display = nil;

    [SCShareableContent
        getShareableContentExcludingDesktopWindows:NO
                              onScreenWindowsOnly:NO
                                completionHandler:^(
                                    SCShareableContent *content,
                                    NSError *error) {
                                    if (!error && content) {
                                        for (SCDisplay *display in
                                             content.displays) {
                                            if (display.displayID ==
                                                display_id) {
                                                selected_display =
                                                    [display retain];
                                                break;
                                            }
                                        }
                                    }
                                    dispatch_semaphore_signal(semaphore);
                                }];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
#if !OS_OBJECT_USE_OBJC
    dispatch_release(semaphore);
#endif
    return selected_display;
}

int macos_screen_start(salts_capture_t *capture) {
    if (!capture || !capture->platform_ctx) return -1;
    salts_screen_ctx_t *ctx = (salts_screen_ctx_t *)capture->platform_ctx;

    SCDisplay *display = find_shareable_display(ctx->display_id);
    if (!display) return -1;

    NSArray *excluded_windows = [[NSArray alloc] init];
    SCContentFilter *filter =
        [[SCContentFilter alloc] initWithDisplay:display
                               excludingWindows:excluded_windows];
    [excluded_windows release];
    [display release];

    if (!filter) return -1;

    SCStreamConfiguration *configuration =
        [[SCStreamConfiguration alloc] init];
    configuration.width = (NSUInteger)ctx->width;
    configuration.height = (NSUInteger)ctx->height;
    configuration.pixelFormat = kCVPixelFormatType_32BGRA;
    configuration.minimumFrameInterval =
        CMTimeMake(1, (int32_t)ctx->framerate);
    configuration.queueDepth = 3;
    configuration.showsCursor = ctx->capture_cursor ? YES : NO;

    SaltsScreenStreamOutput *output =
        [[SaltsScreenStreamOutput alloc] init];
    output->ctx = ctx;

    SCStream *stream =
        [[SCStream alloc] initWithFilter:filter
                           configuration:configuration
                                delegate:nil];
    [configuration release];
    [filter release];

    if (!stream) {
        output->ctx = NULL;
        [output release];
        return -1;
    }

    NSError *add_error = nil;
    BOOL added =
        [stream addStreamOutput:output
                           type:SCStreamOutputTypeScreen
             sampleHandlerQueue:ctx->capture_queue
                          error:&add_error];
    if (!added || add_error) {
        output->ctx = NULL;
        [stream release];
        [output release];
        return -1;
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    if (!semaphore) {
        NSError *remove_error = nil;
        [stream removeStreamOutput:output
                              type:SCStreamOutputTypeScreen
                             error:&remove_error];
        output->ctx = NULL;
        [stream release];
        [output release];
        return -1;
    }

    __block int start_failed = 0;
    ctx->running = 1;
    [stream startCaptureWithCompletionHandler:^(NSError *error) {
        start_failed = error ? 1 : 0;
        dispatch_semaphore_signal(semaphore);
    }];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
#if !OS_OBJECT_USE_OBJC
    dispatch_release(semaphore);
#endif

    if (start_failed) {
        ctx->running = 0;
        NSError *remove_error = nil;
        [stream removeStreamOutput:output
                              type:SCStreamOutputTypeScreen
                             error:&remove_error];
        output->ctx = NULL;
        [stream release];
        [output release];
        return -1;
    }

    ctx->stream = stream;
    ctx->stream_output = output;
    return 0;
}

void macos_screen_stop(salts_capture_t *capture) {
    if (!capture || !capture->platform_ctx) return;
    salts_screen_ctx_t *ctx = (salts_screen_ctx_t *)capture->platform_ctx;

    ctx->running = 0;

    if (ctx->stream) {
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        if (semaphore) {
            [ctx->stream stopCaptureWithCompletionHandler:^(NSError *error) {
                (void)error;
                dispatch_semaphore_signal(semaphore);
            }];
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
#if !OS_OBJECT_USE_OBJC
            dispatch_release(semaphore);
#endif
        }

        if (ctx->stream_output) {
            NSError *remove_error = nil;
            [ctx->stream removeStreamOutput:ctx->stream_output
                                       type:SCStreamOutputTypeScreen
                                      error:&remove_error];
        }

        [ctx->stream release];
        ctx->stream = nil;
    }

    if (ctx->stream_output) {
        ctx->stream_output->ctx = NULL;
        [ctx->stream_output release];
        ctx->stream_output = nil;
    }
}

void macos_screen_destroy(salts_capture_t *capture) {
    if (!capture) return;

    macos_screen_stop(capture);

    salts_screen_ctx_t *ctx = (salts_screen_ctx_t *)capture->platform_ctx;
    if (ctx) {
        free(ctx->frame_buffer);
        ctx->frame_buffer = NULL;
        free(ctx);
    }

    free(capture);
}

#endif /* __APPLE__ && __MACH__ */
