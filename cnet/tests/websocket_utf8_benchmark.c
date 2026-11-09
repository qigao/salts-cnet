#include <cnet/websocket.h>
#include <tinytest.h>
#include <string.h>

/* Public server-side framing with a synchronous fixture sink and no network.
 * Bytes/sample counts application payload once. Encoding/copy is included;
 * binary is the same-copy control. Setup and assertions are outside timing. */
typedef struct sink_stats { uint64_t bytes, events; } sink_stats;
static int accept_frame(void *user, const uint8_t *bytes, size_t size) {
  sink_stats *stats = user;
  if (!bytes || !size) return SALTS_EINVAL;
  stats->bytes += size;
  return SALTS_OK;
}
static void observe(void *user, cnet_websocket *ws, const cnet_websocket_event *event) {
  sink_stats *stats = user;
  (void)ws; (void)event;
  ++stats->events;
}

suite("WebSocket public send payload throughput") {
  static cnet_websocket ws;
  static uint8_t payload[65536];
  static sink_stats stats;
  static int failure;
  before_each() {
    memset(&stats, 0, sizeof(stats));
    memset(payload, 'a', sizeof(payload));
    failure = SALTS_OK;
    cnet_websocket_config config = {.size = sizeof(config), .role = CNET_WEBSOCKET_SERVER,
      .max_frame_bytes = sizeof(payload), .max_message_bytes = sizeof(payload),
      .max_buffered_input_bytes = sizeof(payload) + CNET_WEBSOCKET_MAX_HEADER_BYTES,
      .write = accept_frame, .on_event = observe, .user = &stats};
    check_equal(cnet_websocket_init(&ws, &config), SALTS_OK);
  }
  after_each() { check_equal(cnet_websocket_destroy(&ws), SALTS_OK); }
  for (size_t size = 64u; size <= sizeof(payload); size *= 32u) {
    const size_t loops = (16u * 1024u * 1024u) / size;
    it("sends ASCII text payloads of %zu bytes", size) {
      benchmark_bytes("text ASCII payload", 7, loops * size) {
        for (size_t i = 0; i < loops; ++i) {
          int next = cnet_websocket_send_text(&ws, payload, size);
          if (next != SALTS_OK) failure = next;
        }
      }
      check_equal(failure, SALTS_OK);
      check_greater(stats.bytes, UINT64_C(0));
    }
    it("sends binary payloads of %zu bytes", size) {
      benchmark_bytes("binary payload", 7, loops * size) {
        for (size_t i = 0; i < loops; ++i) {
          int next = cnet_websocket_send_binary(&ws, payload, size);
          if (next != SALTS_OK) failure = next;
        }
      }
      check_equal(failure, SALTS_OK);
    }
  }
  it("sends mixed ASCII and multi-byte text") {
    /* Every 64-byte block has a short ASCII run and one three-byte code point. */
    for (size_t i = 0; i < sizeof(payload); i += 64u) {
      payload[i + 29u] = 0xe4u; payload[i + 30u] = 0xb8u; payload[i + 31u] = 0xadu;
    }
    benchmark_bytes("mixed UTF-8 payload 65536 bytes", 7, 16u * 1024u * 1024u) {
      for (size_t i = 0; i < 256u; ++i) {
        int next = cnet_websocket_send_text(&ws, payload, sizeof(payload));
        if (next != SALTS_OK) failure = next;
      }
    }
    check_equal(failure, SALTS_OK);
  }
  it("sends multi-byte text without ASCII runs") {
    const size_t size = sizeof(payload) - 1u;
    for (size_t i = 0; i < size; i += 3u) {
      payload[i] = 0xe4u; payload[i + 1u] = 0xb8u; payload[i + 2u] = 0xadu;
    }
    benchmark_bytes("multi-byte UTF-8 payload 65535 bytes", 7, 256u * size) {
      for (size_t i = 0; i < 256u; ++i) {
        int next = cnet_websocket_send_text(&ws, payload, size);
        if (next != SALTS_OK) failure = next;
      }
    }
    check_equal(failure, SALTS_OK);
  }
}
