#include "playback_buffer.h"

#include <stdlib.h>
#include <string.h>

static int playback_buffer_is_power_of_two(size_t value) {
  return value != 0u && (value & (value - 1u)) == 0u;
}

static int playback_buffer_storage_capacity(size_t usable_capacity, size_t *out_capacity) {
  size_t result = 1u;

  if (!out_capacity || usable_capacity == SIZE_MAX) {
    return -1;
  }
  while (result < usable_capacity + 1u) {
    if (result > SIZE_MAX / 2u) {
      return -1;
    }
    result <<= 1u;
  }
  *out_capacity = result;
  return 0;
}

static size_t playback_buffer_align_down(size_t value, size_t alignment) {
  return value - value % alignment;
}

int playback_buffer_init(playback_buffer_t *buffer, size_t usable_capacity, size_t frame_bytes) {
  uint8_t *storage;
  size_t storage_capacity;

  if (!buffer || usable_capacity == 0u || frame_bytes == 0u ||
      usable_capacity % frame_bytes != 0u ||
      playback_buffer_storage_capacity(usable_capacity, &storage_capacity) != 0 ||
      !playback_buffer_is_power_of_two(storage_capacity)) {
    return -1;
  }

  memset(buffer, 0, sizeof(*buffer));
  storage = (uint8_t *)malloc(storage_capacity);
  if (!storage) {
    return -1;
  }
  if (!cmeta_spsc_ring_init(&buffer->ring, storage, storage_capacity)) {
    free(storage);
    return -1;
  }

  buffer->storage = storage;
  buffer->storage_capacity = storage_capacity;
  buffer->usable_capacity = usable_capacity;
  buffer->frame_bytes = frame_bytes;
  return 0;
}

void playback_buffer_destroy(playback_buffer_t *buffer) {
  if (!buffer) {
    return;
  }
  free(buffer->storage);
  memset(buffer, 0, sizeof(*buffer));
}

size_t playback_buffer_write(playback_buffer_t *buffer, const void *data, size_t len) {
  const uint8_t *source = (const uint8_t *)data;
  size_t remaining;
  size_t written = 0u;

  if (!buffer || !buffer->storage || !data || len == 0u || len % buffer->frame_bytes != 0u) {
    return 0u;
  }

  remaining = len;
  while (remaining != 0u) {
    size_t candidate = playback_buffer_write_available(buffer);
    uint8_t *destination = NULL;

    if (candidate > remaining) {
      candidate = remaining;
    }
    while (candidate != 0u) {
      destination = cmeta_spsc_ring_write_acquire(&buffer->ring, candidate);
      if (destination) {
        break;
      }
      candidate = playback_buffer_align_down(candidate / 2u, buffer->frame_bytes);
    }
    if (!destination) {
      break;
    }

    memcpy(destination, source + written, candidate);
    cmeta_spsc_ring_write_release(&buffer->ring, candidate);
    written += candidate;
    remaining -= candidate;
  }
  return written;
}

size_t playback_buffer_read(playback_buffer_t *buffer, void *data, size_t len) {
  uint8_t *destination = (uint8_t *)data;
  size_t remaining;
  size_t total = 0u;

  if (!buffer || !buffer->storage || !data || len == 0u || len % buffer->frame_bytes != 0u) {
    return 0u;
  }

  remaining = len;
  while (remaining != 0u) {
    size_t available = 0u;
    uint8_t *source = cmeta_spsc_ring_read_acquire(&buffer->ring, &available);
    size_t count;

    if (!source) {
      break;
    }
    count = playback_buffer_align_down(available, buffer->frame_bytes);
    if (count > remaining) {
      count = remaining;
    }
    if (count == 0u) {
      break;
    }

    memcpy(destination + total, source, count);
    cmeta_spsc_ring_read_release(&buffer->ring, count);
    total += count;
    remaining -= count;
  }
  return total;
}

size_t playback_buffer_write_available(const playback_buffer_t *buffer) {
  size_t retained;
  size_t logical_available;
  size_t physical_available;

  if (!buffer || !buffer->storage) {
    return 0u;
  }
  retained = playback_buffer_align_down(cmeta_spsc_ring_read_available(&buffer->ring),
                                        buffer->frame_bytes);
  if (retained >= buffer->usable_capacity) {
    return 0u;
  }
  logical_available = buffer->usable_capacity - retained;
  physical_available = playback_buffer_align_down(cmeta_spsc_ring_write_available(&buffer->ring),
                                                  buffer->frame_bytes);
  return logical_available < physical_available ? logical_available : physical_available;
}

size_t playback_buffer_read_available(const playback_buffer_t *buffer) {
  if (!buffer || !buffer->storage) {
    return 0u;
  }
  return playback_buffer_align_down(cmeta_spsc_ring_read_available(&buffer->ring),
                                    buffer->frame_bytes);
}

void playback_buffer_clear(playback_buffer_t *buffer) {
  if (!buffer || !buffer->storage) {
    return;
  }
  (void)cmeta_spsc_ring_init(&buffer->ring, buffer->storage, buffer->storage_capacity);
}
