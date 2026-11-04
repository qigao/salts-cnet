#ifndef SALTS_PLAYBACK_BUFFER_H
#define SALTS_PLAYBACK_BUFFER_H

#include <spsc_ring.h>

#include <stddef.h>
#include <stdint.h>

typedef struct playback_buffer {
  cmeta_spsc_ring ring;
  uint8_t *storage;
  size_t storage_capacity;
  size_t usable_capacity;
  size_t frame_bytes;
} playback_buffer_t;

int playback_buffer_init(playback_buffer_t *buffer, size_t usable_capacity, size_t frame_bytes);
void playback_buffer_destroy(playback_buffer_t *buffer);
size_t playback_buffer_write(playback_buffer_t *buffer, const void *data, size_t len);
size_t playback_buffer_read(playback_buffer_t *buffer, void *data, size_t len);
size_t playback_buffer_write_available(const playback_buffer_t *buffer);
size_t playback_buffer_read_available(const playback_buffer_t *buffer);
void playback_buffer_clear(playback_buffer_t *buffer);

#endif /* SALTS_PLAYBACK_BUFFER_H */
