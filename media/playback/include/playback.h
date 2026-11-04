#ifndef SALTS_PLAYBACK_H
#define SALTS_PLAYBACK_H

#include <playback_export.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_PLAYBACK_MAX_DEVICES 16u
#define SALTS_PLAYBACK_DEVICE_ID_BYTES 256u
#define SALTS_PLAYBACK_MIN_BUFFER_MS 10u
#define SALTS_PLAYBACK_MAX_BUFFER_MS 2000u

typedef enum salts_playback_result {
  SALTS_PLAYBACK_OK = 0,
  SALTS_PLAYBACK_ERR_NOMEM = -1,
  SALTS_PLAYBACK_ERR_DEVICE = -2,
  SALTS_PLAYBACK_ERR_FORMAT = -3,
  SALTS_PLAYBACK_ERR_BUSY = -4,
  SALTS_PLAYBACK_ERR_TIMEOUT = -5,
  SALTS_PLAYBACK_ERR_UNSUPPORTED = -6
} salts_playback_result_t;

typedef enum salts_playback_state {
  SALTS_PLAYBACK_STATE_STOPPED = 0,
  SALTS_PLAYBACK_STATE_STARTING,
  SALTS_PLAYBACK_STATE_PLAYING,
  SALTS_PLAYBACK_STATE_PAUSED,
  SALTS_PLAYBACK_STATE_STOPPING,
  SALTS_PLAYBACK_STATE_ERROR
} salts_playback_state_t;

typedef enum salts_playback_format {
  SALTS_PLAYBACK_FORMAT_S16 = 0,
  SALTS_PLAYBACK_FORMAT_S32,
  SALTS_PLAYBACK_FORMAT_F32
} salts_playback_format_t;

typedef struct salts_playback_device {
  uint32_t index;
  char name[256];
  /* Enumeration-scoped opaque identity. Pass the whole object to create(). */
  uint8_t id[SALTS_PLAYBACK_DEVICE_ID_BYTES];
  uint32_t id_size;
  int is_default;
} salts_playback_device_t;

typedef struct salts_playback_config {
  uint32_t sample_rate; /* 8000, 16000, 24000, or 48000 Hz */
  uint32_t channels;    /* 1 or 2 */
  salts_playback_format_t format;
  uint32_t buffer_duration_ms; /* 10 through 2000 ms */
} salts_playback_config_t;

typedef struct salts_playback salts_playback_t;

/**
 * Threading contract: one control owner calls all mutating APIs except write().
 * Exactly one producer may call write(), including when the native callback is
 * active. The producer must be quiescent before clear() or destroy(). State and
 * byte-count accessors may be called concurrently.
 */

/**
 * State callbacks execute synchronously for control-initiated transitions on
 * the control-owner thread. Asynchronous device errors are observed through
 * get_state() and operation results. Callback registration is allowed only
 * while stopped. Callbacks are notifications and must not call mutating APIs.
 */
typedef void (*salts_playback_state_cb)(salts_playback_t *playback, salts_playback_state_t state,
                                        void *user_data);

SALTS_PLAYBACK_API int salts_playback_list_devices(salts_playback_device_t *devices,
                                                   size_t capacity, size_t *out_count);
SALTS_PLAYBACK_API int salts_playback_get_default_device(salts_playback_device_t *device);

/**
 * Creates a bounded PCM sink. The object owns its native device and internal
 * storage. device is NULL for the default device; otherwise it must be an
 * unchanged enumeration result. Failure clears out_playback.
 */
SALTS_PLAYBACK_API int salts_playback_create(const salts_playback_device_t *device,
                                             const salts_playback_config_t *config,
                                             salts_playback_t **out_playback);

/**
 * Stops the device, waits for its callback to quiesce, and discards storage.
 * The producer must be quiescent before this call.
 */
SALTS_PLAYBACK_API void salts_playback_destroy(salts_playback_t *playback);

SALTS_PLAYBACK_API int salts_playback_set_state_callback(salts_playback_t *playback,
                                                         salts_playback_state_cb callback,
                                                         void *user_data);
SALTS_PLAYBACK_API int salts_playback_start(salts_playback_t *playback);
SALTS_PLAYBACK_API int salts_playback_stop(salts_playback_t *playback);
SALTS_PLAYBACK_API int salts_playback_pause(salts_playback_t *playback);
SALTS_PLAYBACK_API int salts_playback_resume(salts_playback_t *playback);
SALTS_PLAYBACK_API salts_playback_state_t
salts_playback_get_state(const salts_playback_t *playback);

SALTS_PLAYBACK_API int salts_playback_set_volume(salts_playback_t *playback, float volume);
SALTS_PLAYBACK_API int salts_playback_get_volume(const salts_playback_t *playback,
                                                 float *out_volume);

/**
 * Copies frame-aligned PCM into the bounded SPSC ring. Exactly one producer may
 * call this function. Success may write fewer than len bytes; that is explicit
 * backpressure. Failure clears out_written and preserves input ownership.
 */
SALTS_PLAYBACK_API int salts_playback_write(salts_playback_t *playback, const void *samples,
                                            size_t len, size_t *out_written);
SALTS_PLAYBACK_API size_t salts_playback_get_available(const salts_playback_t *playback);
SALTS_PLAYBACK_API size_t salts_playback_get_buffered(const salts_playback_t *playback);

/**
 * Clears retained PCM without changing the public lifecycle state. The sole
 * producer must be quiescent for the duration of this call.
 */
SALTS_PLAYBACK_API int salts_playback_clear(salts_playback_t *playback);

/**
 * Waits until retained PCM is consumed. It does not stop the device or change
 * state. timeout_ms must be positive.
 */
SALTS_PLAYBACK_API int salts_playback_drain(salts_playback_t *playback, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* SALTS_PLAYBACK_H */
