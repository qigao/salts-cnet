/**
 * Android Audio Capture
 *
 * Uses OpenSL ES for low-latency audio capture
 * OpenSL ES is required: no alternative audio provider.
 */
#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <stdlib.h>
#include <string.h>

#include <tlog.h>

#define BUFFER_COUNT 4
#define FRAMES_PER_BUFFER 480  /* 10ms @ 48kHz */

/* =============================================================================
 * Audio Context
 * ============================================================================= */

typedef struct android_audio_ctx_t {
    /* OpenSL ES objects */
    SLObjectItf engine_object;
    SLEngineItf engine;
    SLObjectItf recorder_object;
    SLRecordItf recorder;
    SLAndroidSimpleBufferQueueItf buffer_queue;

    /* Configuration */
    int sample_rate;
    int channels;

    /* Buffers */
    int16_t *buffers[BUFFER_COUNT];
    size_t buffer_size;
    int current_buffer;

    /* State */
    int capturing;

    /* Callback */
    void (*on_audio)(void *user_data, const int16_t *data, size_t frames);
    void *user_data;
} android_audio_ctx_t;

int android_audio_stop(android_audio_ctx_t *ctx);

/* =============================================================================
 * OpenSL ES Implementation
 * ============================================================================= */

static void opensles_buffer_queue_callback(SLAndroidSimpleBufferQueueItf bq, void *context) {
    android_audio_ctx_t *ctx = (android_audio_ctx_t *)context;

    /* Get current buffer */
    int16_t *buffer = ctx->buffers[ctx->current_buffer];

    /* Call user callback */
    if (ctx->on_audio) {
        ctx->on_audio(ctx->user_data, buffer, FRAMES_PER_BUFFER);
    }

    /* Enqueue buffer again */
    (*bq)->Enqueue(bq, buffer, ctx->buffer_size);

    /* Move to next buffer */
    ctx->current_buffer = (ctx->current_buffer + 1) % BUFFER_COUNT;
}

static int opensles_init(android_audio_ctx_t *ctx) {
    SLresult result;

    /* Create engine */
    result = slCreateEngine(&ctx->engine_object, 0, NULL, 0, NULL, NULL);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to create OpenSL ES engine");
        return -1;
    }

    result = (*ctx->engine_object)->Realize(ctx->engine_object, SL_BOOLEAN_FALSE);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to realize engine");
        return -1;
    }

    result = (*ctx->engine_object)->GetInterface(ctx->engine_object,
                                                 SL_IID_ENGINE,
                                                 &ctx->engine);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to get engine interface");
        return -1;
    }

    /* Configure audio source */
    SLDataLocator_IODevice loc_dev = {
        SL_DATALOCATOR_IODEVICE,
        SL_IODEVICE_AUDIOINPUT,
        SL_DEFAULTDEVICEID_AUDIOINPUT,
        NULL
    };

    SLDataSource audio_src = {&loc_dev, NULL};

    /* Configure audio sink */
    SLDataLocator_AndroidSimpleBufferQueue loc_bq = {
        SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE,
        BUFFER_COUNT
    };

    SLDataFormat_PCM format_pcm = {
        SL_DATAFORMAT_PCM,
        ctx->channels,
        ctx->sample_rate * 1000,  /* mHz */
        SL_PCMSAMPLEFORMAT_FIXED_16,
        SL_PCMSAMPLEFORMAT_FIXED_16,
        ctx->channels == 1 ? SL_SPEAKER_FRONT_CENTER :
                            (SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT),
        SL_BYTEORDER_LITTLEENDIAN
    };

    SLDataSink audio_snk = {&loc_bq, &format_pcm};

    /* Create audio recorder */
    const SLInterfaceID ids[] = {SL_IID_ANDROIDSIMPLEBUFFERQUEUE};
    const SLboolean req[] = {SL_BOOLEAN_TRUE};

    result = (*ctx->engine)->CreateAudioRecorder(
        ctx->engine,
        &ctx->recorder_object,
        &audio_src,
        &audio_snk,
        1,
        ids,
        req
    );

    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to create audio recorder");
        return -1;
    }

    result = (*ctx->recorder_object)->Realize(ctx->recorder_object, SL_BOOLEAN_FALSE);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to realize recorder");
        return -1;
    }

    /* Get recorder interface */
    result = (*ctx->recorder_object)->GetInterface(ctx->recorder_object,
                                                   SL_IID_RECORD,
                                                   &ctx->recorder);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to get recorder interface");
        return -1;
    }

    /* Get buffer queue interface */
    result = (*ctx->recorder_object)->GetInterface(ctx->recorder_object,
                                                   SL_IID_ANDROIDSIMPLEBUFFERQUEUE,
                                                   &ctx->buffer_queue);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to get buffer queue interface");
        return -1;
    }

    /* Register callback */
    result = (*ctx->buffer_queue)->RegisterCallback(ctx->buffer_queue,
                                                    opensles_buffer_queue_callback,
                                                    ctx);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to register callback");
        return -1;
    }


    return 0;
}

static int opensles_start(android_audio_ctx_t *ctx) {
    /* Enqueue all buffers */
    for (int i = 0; i < BUFFER_COUNT; i++) {
        (*ctx->buffer_queue)->Enqueue(ctx->buffer_queue,
                                      ctx->buffers[i],
                                      ctx->buffer_size);
    }

    /* Start recording */
    SLresult result = (*ctx->recorder)->SetRecordState(ctx->recorder,
                                                       SL_RECORDSTATE_RECORDING);
    if (result != SL_RESULT_SUCCESS) {
        SALTS_LOG_ERROR(tlog_get_default(), "capture", "Failed to start recording");
        return -1;
    }


    return 0;
}

static int opensles_stop(android_audio_ctx_t *ctx) {
    if (ctx->recorder) {
        (*ctx->recorder)->SetRecordState(ctx->recorder, SL_RECORDSTATE_STOPPED);
    }

    if (ctx->buffer_queue) {
        (*ctx->buffer_queue)->Clear(ctx->buffer_queue);
    }


    return 0;
}

static void opensles_cleanup(android_audio_ctx_t *ctx) {
    if (ctx->recorder_object) {
        (*ctx->recorder_object)->Destroy(ctx->recorder_object);
        ctx->recorder_object = NULL;
    }

    if (ctx->engine_object) {
        (*ctx->engine_object)->Destroy(ctx->engine_object);
        ctx->engine_object = NULL;
    }
}

/* =============================================================================
 * Public API
 * ============================================================================= */

android_audio_ctx_t *android_audio_create(int sample_rate, int channels) {
    android_audio_ctx_t *ctx = (android_audio_ctx_t *)calloc(1, sizeof(android_audio_ctx_t));
    if (!ctx) return NULL;

    ctx->sample_rate = sample_rate;
    ctx->channels = channels;
    ctx->capturing = 0;
    ctx->current_buffer = 0;

    /* Allocate buffers */
    ctx->buffer_size = FRAMES_PER_BUFFER * channels * sizeof(int16_t);
    for (int i = 0; i < BUFFER_COUNT; i++) {
        ctx->buffers[i] = (int16_t *)malloc(ctx->buffer_size);
        if (!ctx->buffers[i]) {
            for (int j = 0; j < i; j++) {
                free(ctx->buffers[j]);
            }
            free(ctx);
            return NULL;
        }
    }

    /* The single configured native backend must initialize successfully. */
    int ret = opensles_init(ctx);

    if (ret != 0) {
        opensles_cleanup(ctx);
        for (int i = 0; i < BUFFER_COUNT; i++) {
            free(ctx->buffers[i]);
        }
        free(ctx);
        return NULL;
    }


    return ctx;
}

void android_audio_destroy(android_audio_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->capturing) {
        android_audio_stop(ctx);
    }

    opensles_cleanup(ctx);

    for (int i = 0; i < BUFFER_COUNT; i++) {
        free(ctx->buffers[i]);
    }

    free(ctx);
}

int android_audio_start(android_audio_ctx_t *ctx) {
    if (!ctx || ctx->capturing) return -1;

    int ret = opensles_start(ctx);

    if (ret == 0) {
        ctx->capturing = 1;
    }

    return ret;
}

int android_audio_stop(android_audio_ctx_t *ctx) {
    if (!ctx || !ctx->capturing) return -1;

    opensles_stop(ctx);

    ctx->capturing = 0;

    return 0;
}

void android_audio_set_callback(android_audio_ctx_t *ctx,
                                void (*callback)(void *user_data,
                                               const int16_t *data, size_t frames),
                                void *user_data) {
    if (!ctx) return;
    ctx->on_audio = callback;
    ctx->user_data = user_data;
}
