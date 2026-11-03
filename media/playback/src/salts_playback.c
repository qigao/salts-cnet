#include "playback.h"

#include "playback_buffer.h"

#include <miniaudio.h>
#include <thread.h>

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  SALTS_PLAYBACK_DEFAULT_RATE = 48000u,
  SALTS_PLAYBACK_DEFAULT_CHANNELS = 2u,
  SALTS_PLAYBACK_DEFAULT_BUFFER_MS = 50u
};

struct salts_playback {
  playback_buffer_t buffer;
  size_t frame_bytes;
  salts_playback_state_cb state_callback;
  void *state_user_data;
  ma_context context;
  ma_device device;
  int context_initialized;
  int device_initialized;
  _Atomic int desired_active;
  _Atomic int stop_expected;
  _Atomic int state;
  float volume;
  salts_playback_config_t config;
#if defined(SALTS_PLAYBACK_TEST_NULL_BACKEND)
  int stop_during_next_start;
#endif
};

static ma_result playback_context_init(ma_context *context) {
#if defined(SALTS_PLAYBACK_TEST_NULL_BACKEND)
  const ma_backend backend = ma_backend_null;
  return ma_context_init(&backend, 1u, NULL, context);
#else
  return ma_context_init(NULL, 0u, NULL, context);
#endif
}

static salts_playback_config_t playback_default_config(void) {
  salts_playback_config_t config = {SALTS_PLAYBACK_DEFAULT_RATE, SALTS_PLAYBACK_DEFAULT_CHANNELS,
                                    SALTS_PLAYBACK_FORMAT_F32, SALTS_PLAYBACK_DEFAULT_BUFFER_MS};
  return config;
}

static int playback_config_valid(const salts_playback_config_t *config) {
  int valid_rate;

  if (!config) {
    return 0;
  }
  valid_rate = config->sample_rate == 8000u || config->sample_rate == 16000u ||
               config->sample_rate == 24000u || config->sample_rate == 48000u;
  return valid_rate && (config->channels == 1u || config->channels == 2u) &&
         (config->format == SALTS_PLAYBACK_FORMAT_S16 ||
          config->format == SALTS_PLAYBACK_FORMAT_S32 ||
          config->format == SALTS_PLAYBACK_FORMAT_F32) &&
         config->buffer_duration_ms >= SALTS_PLAYBACK_MIN_BUFFER_MS &&
         config->buffer_duration_ms <= SALTS_PLAYBACK_MAX_BUFFER_MS;
}

static size_t playback_sample_bytes(salts_playback_format_t format) {
  return format == SALTS_PLAYBACK_FORMAT_S16 ? 2u : 4u;
}

static ma_format playback_miniaudio_format(salts_playback_format_t format) {
  switch (format) {
  case SALTS_PLAYBACK_FORMAT_S16:
    return ma_format_s16;
  case SALTS_PLAYBACK_FORMAT_S32:
    return ma_format_s32;
  case SALTS_PLAYBACK_FORMAT_F32:
    return ma_format_f32;
  default:
    return ma_format_unknown;
  }
}

static size_t playback_buffer_capacity(const salts_playback_config_t *config, size_t frame_bytes) {
  size_t frames = ((size_t)config->sample_rate * config->buffer_duration_ms + 999u) / 1000u;
  return frames * frame_bytes;
}

_Static_assert(sizeof(ma_device_id) <= SALTS_PLAYBACK_DEVICE_ID_BYTES,
               "SALTS_PLAYBACK_DEVICE_ID_BYTES is too small for miniaudio");

static void playback_handle_unexpected_stop(salts_playback_t *playback);

static void playback_set_state(salts_playback_t *playback, salts_playback_state_t state) {
  int previous = atomic_exchange_explicit(&playback->state, (int)state, memory_order_acq_rel);
  if (previous != (int)state && playback->state_callback) {
    playback->state_callback(playback, state, playback->state_user_data);
  }
}

static int playback_complete_start(salts_playback_t *playback,
                                   salts_playback_state_t expected_state) {
  int expected = (int)expected_state;

#if defined(SALTS_PLAYBACK_TEST_NULL_BACKEND)
  if (playback->stop_during_next_start) {
    playback->stop_during_next_start = 0;
    playback_handle_unexpected_stop(playback);
  }
#endif
  if (!atomic_compare_exchange_strong_explicit(&playback->state, &expected,
                                               SALTS_PLAYBACK_STATE_PLAYING, memory_order_acq_rel,
                                               memory_order_acquire)) {
    return expected == SALTS_PLAYBACK_STATE_ERROR ? SALTS_PLAYBACK_ERR_DEVICE
                                                  : SALTS_PLAYBACK_ERR_BUSY;
  }
  if (!atomic_load_explicit(&playback->desired_active, memory_order_acquire)) {
    expected = SALTS_PLAYBACK_STATE_PLAYING;
    (void)atomic_compare_exchange_strong_explicit(&playback->state, &expected,
                                                  SALTS_PLAYBACK_STATE_ERROR, memory_order_acq_rel,
                                                  memory_order_acquire);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  if (playback->state_callback) {
    playback->state_callback(playback, SALTS_PLAYBACK_STATE_PLAYING, playback->state_user_data);
  }
  return SALTS_PLAYBACK_OK;
}

static void playback_device_callback(ma_device *device, void *output, const void *input,
                                     ma_uint32 frame_count) {
  salts_playback_t *playback = (salts_playback_t *)device->pUserData;
  size_t requested;
  size_t read = 0u;

  (void)input;
  requested = (size_t)frame_count * playback->frame_bytes;
  if (atomic_load_explicit(&playback->desired_active, memory_order_acquire)) {
    read = playback_buffer_read(&playback->buffer, output, requested);
  }
  if (read < requested) {
    memset((uint8_t *)output + read, 0, requested - read);
  }
}

static void playback_handle_unexpected_stop(salts_playback_t *playback) {
  if (atomic_exchange_explicit(&playback->desired_active, 0, memory_order_acq_rel)) {
    atomic_store_explicit(&playback->state, SALTS_PLAYBACK_STATE_ERROR, memory_order_release);
  }
}

static void playback_device_notification(const ma_device_notification *notification) {
  salts_playback_t *playback;

  if (!notification || !notification->pDevice) {
    return;
  }
  playback = (salts_playback_t *)notification->pDevice->pUserData;
  if (!playback) {
    return;
  }
  if (notification->type == ma_device_notification_type_started) {
    atomic_store_explicit(&playback->stop_expected, 0, memory_order_release);
  } else if (notification->type == ma_device_notification_type_stopped &&
             !atomic_exchange_explicit(&playback->stop_expected, 0, memory_order_acq_rel)) {
    playback_handle_unexpected_stop(playback);
  } else if (notification->type == ma_device_notification_type_interruption_began) {
    playback_handle_unexpected_stop(playback);
  }
}

static void playback_copy_device(salts_playback_device_t *destination, const ma_device_info *source,
                                 ma_uint32 index) {
  memset(destination, 0, sizeof(*destination));
  destination->index = index;
  snprintf(destination->name, sizeof(destination->name), "%s", source->name);
  memcpy(destination->id, &source->id, sizeof(source->id));
  destination->id_size = (uint32_t)sizeof(source->id);
  destination->is_default = source->isDefault ? 1 : 0;
}

static int playback_select_device(const salts_playback_device_t *device,
                                  ma_device_config *device_config, ma_device_id *selected_id) {
  if (!device) {
    return SALTS_PLAYBACK_OK;
  }
  if (device->id_size != sizeof(*selected_id)) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  memcpy(selected_id, device->id, sizeof(*selected_id));
  device_config->playback.pDeviceID = selected_id;
  return SALTS_PLAYBACK_OK;
}

int salts_playback_list_devices(salts_playback_device_t *devices, size_t capacity,
                                size_t *out_count) {
  ma_context context;
  ma_device_info *device_infos = NULL;
  ma_uint32 device_count = 0u;
  size_t count;

  if (out_count) {
    *out_count = 0u;
  }
  if (!devices || capacity == 0u || !out_count) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  if (playback_context_init(&context) != MA_SUCCESS) {
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  if (ma_context_get_devices(&context, &device_infos, &device_count, NULL, NULL) != MA_SUCCESS) {
    ma_context_uninit(&context);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }

  count = device_count < capacity ? (size_t)device_count : capacity;
  if (count > SALTS_PLAYBACK_MAX_DEVICES) {
    count = SALTS_PLAYBACK_MAX_DEVICES;
  }
  for (size_t index = 0u; index < count; ++index) {
    playback_copy_device(&devices[index], &device_infos[index], (ma_uint32)index);
  }
  *out_count = count;
  ma_context_uninit(&context);
  return SALTS_PLAYBACK_OK;
}

int salts_playback_get_default_device(salts_playback_device_t *device) {
  ma_context context;
  ma_device_info *device_infos = NULL;
  ma_uint32 device_count = 0u;

  if (!device) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  memset(device, 0, sizeof(*device));
  if (playback_context_init(&context) != MA_SUCCESS) {
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  if (ma_context_get_devices(&context, &device_infos, &device_count, NULL, NULL) != MA_SUCCESS) {
    ma_context_uninit(&context);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  for (ma_uint32 index = 0u; index < device_count; ++index) {
    if (device_infos[index].isDefault) {
      playback_copy_device(device, &device_infos[index], index);
      ma_context_uninit(&context);
      return SALTS_PLAYBACK_OK;
    }
  }
  ma_context_uninit(&context);
  return SALTS_PLAYBACK_ERR_DEVICE;
}

int salts_playback_create(const salts_playback_device_t *device,
                          const salts_playback_config_t *config, salts_playback_t **out_playback) {
  salts_playback_config_t selected_config;
  salts_playback_t *playback;
  ma_device_config device_config;
  ma_device_id selected_id;
  int result;

  if (out_playback) {
    *out_playback = NULL;
  }
  if (!out_playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  selected_config = config ? *config : playback_default_config();
  if (!playback_config_valid(&selected_config)) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }

  playback = (salts_playback_t *)calloc(1u, sizeof(*playback));
  if (!playback) {
    return SALTS_PLAYBACK_ERR_NOMEM;
  }
  playback->config = selected_config;
  playback->frame_bytes = playback_sample_bytes(selected_config.format) * selected_config.channels;
  playback->volume = 1.0f;
  atomic_init(&playback->desired_active, 0);
  atomic_init(&playback->stop_expected, 0);
  atomic_init(&playback->state, SALTS_PLAYBACK_STATE_STOPPED);

  if (playback_buffer_init(&playback->buffer,
                           playback_buffer_capacity(&selected_config, playback->frame_bytes),
                           playback->frame_bytes) != 0) {
    free(playback);
    return SALTS_PLAYBACK_ERR_NOMEM;
  }
  if (playback_context_init(&playback->context) != MA_SUCCESS) {
    playback_buffer_destroy(&playback->buffer);
    free(playback);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  playback->context_initialized = 1;

  device_config = ma_device_config_init(ma_device_type_playback);
  device_config.playback.format = playback_miniaudio_format(selected_config.format);
  device_config.playback.channels = selected_config.channels;
  device_config.sampleRate = selected_config.sample_rate;
  device_config.dataCallback = playback_device_callback;
  device_config.notificationCallback = playback_device_notification;
  device_config.pUserData = playback;
  result = playback_select_device(device, &device_config, &selected_id);
  if (result != SALTS_PLAYBACK_OK ||
      ma_device_init(&playback->context, &device_config, &playback->device) != MA_SUCCESS) {
    ma_context_uninit(&playback->context);
    playback_buffer_destroy(&playback->buffer);
    free(playback);
    return result == SALTS_PLAYBACK_OK ? SALTS_PLAYBACK_ERR_DEVICE : result;
  }
  playback->device_initialized = 1;
  *out_playback = playback;
  return SALTS_PLAYBACK_OK;
}

void salts_playback_destroy(salts_playback_t *playback) {
  if (!playback) {
    return;
  }
  atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
  if (salts_playback_get_state(playback) == SALTS_PLAYBACK_STATE_PLAYING ||
      salts_playback_get_state(playback) == SALTS_PLAYBACK_STATE_PAUSED) {
    (void)salts_playback_stop(playback);
  }
  if (playback->device_initialized) {
    ma_device_uninit(&playback->device);
  }
  if (playback->context_initialized) {
    ma_context_uninit(&playback->context);
  }
  playback_buffer_destroy(&playback->buffer);
  free(playback);
}

int salts_playback_set_state_callback(salts_playback_t *playback, salts_playback_state_cb callback,
                                      void *user_data) {
  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  if (salts_playback_get_state(playback) != SALTS_PLAYBACK_STATE_STOPPED) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  playback->state_callback = callback;
  playback->state_user_data = user_data;
  return SALTS_PLAYBACK_OK;
}

int salts_playback_start(salts_playback_t *playback) {
  salts_playback_state_t state;

  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_PLAYING) {
    return SALTS_PLAYBACK_OK;
  }
  if (state != SALTS_PLAYBACK_STATE_STOPPED) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  playback_set_state(playback, SALTS_PLAYBACK_STATE_STARTING);
  atomic_store_explicit(&playback->desired_active, 1, memory_order_release);
  if (ma_device_start(&playback->device) != MA_SUCCESS) {
    atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
    playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  return playback_complete_start(playback, SALTS_PLAYBACK_STATE_STARTING);
}

int salts_playback_stop(salts_playback_t *playback) {
  salts_playback_state_t state;

  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_STOPPED) {
    return SALTS_PLAYBACK_OK;
  }
  if (state != SALTS_PLAYBACK_STATE_PLAYING && state != SALTS_PLAYBACK_STATE_PAUSED) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  playback_set_state(playback, SALTS_PLAYBACK_STATE_STOPPING);
  atomic_store_explicit(&playback->stop_expected, 1, memory_order_release);
  if (state == SALTS_PLAYBACK_STATE_PLAYING && ma_device_stop(&playback->device) != MA_SUCCESS) {
    atomic_store_explicit(&playback->stop_expected, 0, memory_order_release);
    playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  playback_set_state(playback, SALTS_PLAYBACK_STATE_STOPPED);
  return SALTS_PLAYBACK_OK;
}

int salts_playback_pause(salts_playback_t *playback) {
  salts_playback_state_t state;

  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_PAUSED) {
    return SALTS_PLAYBACK_OK;
  }
  if (state != SALTS_PLAYBACK_STATE_PLAYING) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  atomic_store_explicit(&playback->stop_expected, 1, memory_order_release);
  if (ma_device_stop(&playback->device) != MA_SUCCESS) {
    atomic_store_explicit(&playback->stop_expected, 0, memory_order_release);
    playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  playback_set_state(playback, SALTS_PLAYBACK_STATE_PAUSED);
  return SALTS_PLAYBACK_OK;
}

int salts_playback_resume(salts_playback_t *playback) {
  salts_playback_state_t state;

  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_PLAYING) {
    return SALTS_PLAYBACK_OK;
  }
  if (state != SALTS_PLAYBACK_STATE_PAUSED) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  atomic_store_explicit(&playback->desired_active, 1, memory_order_release);
  if (ma_device_start(&playback->device) != MA_SUCCESS) {
    atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
    playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  return playback_complete_start(playback, SALTS_PLAYBACK_STATE_PAUSED);
}

salts_playback_state_t salts_playback_get_state(const salts_playback_t *playback) {
  if (!playback) {
    return SALTS_PLAYBACK_STATE_ERROR;
  }
  return (salts_playback_state_t)atomic_load_explicit(&playback->state, memory_order_acquire);
}

int salts_playback_set_volume(salts_playback_t *playback, float volume) {
  if (!playback || volume < 0.0f) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  if (ma_device_set_master_volume(&playback->device, volume) != MA_SUCCESS) {
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  playback->volume = volume;
  return SALTS_PLAYBACK_OK;
}

int salts_playback_get_volume(const salts_playback_t *playback, float *out_volume) {
  if (out_volume) {
    *out_volume = 0.0f;
  }
  if (!playback || !out_volume) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  *out_volume = playback->volume;
  return SALTS_PLAYBACK_OK;
}

int salts_playback_write(salts_playback_t *playback, const void *samples, size_t len,
                         size_t *out_written) {
  salts_playback_state_t state;

  if (out_written) {
    *out_written = 0u;
  }
  if (!playback || !samples || len == 0u || !out_written || len % playback->frame_bytes != 0u) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_ERROR) {
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  if (state == SALTS_PLAYBACK_STATE_STARTING || state == SALTS_PLAYBACK_STATE_STOPPING) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  *out_written = playback_buffer_write(&playback->buffer, samples, len);
  return SALTS_PLAYBACK_OK;
}

size_t salts_playback_get_available(const salts_playback_t *playback) {
  return playback ? playback_buffer_write_available(&playback->buffer) : 0u;
}

size_t salts_playback_get_buffered(const salts_playback_t *playback) {
  return playback ? playback_buffer_read_available(&playback->buffer) : 0u;
}

int salts_playback_clear(salts_playback_t *playback) {
  salts_playback_state_t state;

  if (!playback) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
  state = salts_playback_get_state(playback);
  if (state == SALTS_PLAYBACK_STATE_STARTING || state == SALTS_PLAYBACK_STATE_STOPPING ||
      state == SALTS_PLAYBACK_STATE_ERROR) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }
  if (state == SALTS_PLAYBACK_STATE_PLAYING) {
    atomic_store_explicit(&playback->stop_expected, 1, memory_order_release);
    if (ma_device_stop(&playback->device) != MA_SUCCESS) {
      atomic_store_explicit(&playback->stop_expected, 0, memory_order_release);
      playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
      return SALTS_PLAYBACK_ERR_DEVICE;
    }
  }
  playback_buffer_clear(&playback->buffer);
  if (state == SALTS_PLAYBACK_STATE_PLAYING) {
    atomic_store_explicit(&playback->desired_active, 1, memory_order_release);
    if (ma_device_start(&playback->device) != MA_SUCCESS) {
      atomic_store_explicit(&playback->desired_active, 0, memory_order_release);
      playback_set_state(playback, SALTS_PLAYBACK_STATE_ERROR);
      return SALTS_PLAYBACK_ERR_DEVICE;
    }
  }
  return SALTS_PLAYBACK_OK;
}

int salts_playback_drain(salts_playback_t *playback, uint32_t timeout_ms) {
  if (!playback || timeout_ms == 0u) {
    return SALTS_PLAYBACK_ERR_FORMAT;
  }
  if (salts_playback_get_buffered(playback) == 0u) {
    return SALTS_PLAYBACK_OK;
  }
  if (salts_playback_get_state(playback) == SALTS_PLAYBACK_STATE_ERROR) {
    return SALTS_PLAYBACK_ERR_DEVICE;
  }
  if (salts_playback_get_state(playback) != SALTS_PLAYBACK_STATE_PLAYING) {
    return SALTS_PLAYBACK_ERR_BUSY;
  }

  for (uint32_t elapsed = 0u; elapsed < timeout_ms; ++elapsed) {
    if (salts_playback_get_buffered(playback) == 0u) {
      return SALTS_PLAYBACK_OK;
    }
    cmeta_sleep_ms(1u);
  }
  return salts_playback_get_buffered(playback) == 0u ? SALTS_PLAYBACK_OK
                                                     : SALTS_PLAYBACK_ERR_TIMEOUT;
}

#if defined(SALTS_PLAYBACK_TEST_NULL_BACKEND)
void salts_playback_test_simulate_unexpected_stop(salts_playback_t *playback) {
  if (playback) {
    playback_handle_unexpected_stop(playback);
  }
}

void salts_playback_test_stop_during_next_start(salts_playback_t *playback) {
  if (playback) {
    playback->stop_during_next_start = 1;
  }
}
#endif
