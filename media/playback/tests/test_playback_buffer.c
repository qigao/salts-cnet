#include "playback_buffer.h"

#include <tinytest.h>

#include <stdint.h>
#include <string.h>

suite("playback bounded PCM buffer") {
  it("rejects malformed capacity and frame alignment") {
    playback_buffer_t buffer;

    check_not_equal(playback_buffer_init(NULL, 16u, 4u), 0);
    check_not_equal(playback_buffer_init(&buffer, 15u, 4u), 0);
    check_not_equal(playback_buffer_init(&buffer, 16u, 0u), 0);
  }

  it("copies aligned frames and reports explicit backpressure") {
    playback_buffer_t buffer;
    const uint8_t input[20] = {0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u,
                               10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u};
    uint8_t output[16] = {0};

    check_equal(playback_buffer_init(&buffer, 16u, 4u), 0);
    check_equal(playback_buffer_write(&buffer, input, sizeof(input)), sizeof(output));
    check_equal(playback_buffer_read_available(&buffer), sizeof(output));
    check_equal(playback_buffer_read(&buffer, output, sizeof(output)), sizeof(output));
    check_equal(output, input, sizeof(output));
    playback_buffer_destroy(&buffer);
  }

  it("enforces a non-power-of-two logical byte limit") {
    playback_buffer_t buffer;
    const uint8_t input[24] = {0u};

    check_equal(playback_buffer_init(&buffer, 20u, 4u), 0);
    check_equal(playback_buffer_write_available(&buffer), (size_t)20u);
    check_equal(playback_buffer_write(&buffer, input, sizeof(input)), (size_t)20u);
    check_equal(playback_buffer_write_available(&buffer), (size_t)0u);
    playback_buffer_destroy(&buffer);
  }

  it("preserves byte order across a wrapped write") {
    playback_buffer_t buffer;
    const uint8_t first[12] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u};
    const uint8_t second[8] = {12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u};
    const uint8_t expected[12] = {8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u};
    uint8_t discarded[8];
    uint8_t output[12];

    check_equal(playback_buffer_init(&buffer, 16u, 4u), 0);
    check_equal(playback_buffer_write(&buffer, first, sizeof(first)), sizeof(first));
    check_equal(playback_buffer_read(&buffer, discarded, sizeof(discarded)), sizeof(discarded));
    check_equal(playback_buffer_write(&buffer, second, sizeof(second)), sizeof(second));
    check_equal(playback_buffer_read(&buffer, output, sizeof(output)), sizeof(output));
    check_equal(output, expected, sizeof(expected));
    playback_buffer_destroy(&buffer);
  }

  it("clears retained frames only at the quiescent control boundary") {
    playback_buffer_t buffer;
    const uint8_t input[8] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u};

    check_equal(playback_buffer_init(&buffer, 16u, 4u), 0);
    check_equal(playback_buffer_write(&buffer, input, sizeof(input)), sizeof(input));
    playback_buffer_clear(&buffer);
    check_equal(playback_buffer_read_available(&buffer), (size_t)0u);
    check_equal(playback_buffer_write_available(&buffer), (size_t)16u);
    playback_buffer_destroy(&buffer);
  }
}
