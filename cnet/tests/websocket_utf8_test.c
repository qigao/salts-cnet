#if defined(__linux__)
#define _DEFAULT_SOURCE 1
#endif
#include <cnet/websocket.h>
#include <tinytest.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

typedef struct utf8_sink {
  size_t writes;
  uint8_t frame[512];
  size_t size;
} utf8_sink;

static int capture_frame(void *user, const uint8_t *bytes, size_t size) {
  utf8_sink *sink = user;
  if (size > sizeof(sink->frame)) return SALTS_EMSGSIZE;
  ++sink->writes;
  memcpy(sink->frame, bytes, size);
  sink->size = size;
  return SALTS_OK;
}

static void observe(void *user, cnet_websocket *ws, const cnet_websocket_event *event) {
  (void)user; (void)ws; (void)event;
}

suite("WebSocket strict UTF-8 block boundaries") {
  static cnet_websocket ws;
  static utf8_sink sink;
  before_each() {
    memset(&sink, 0, sizeof(sink));
    cnet_websocket_config config = {.size = sizeof(config), .role = CNET_WEBSOCKET_SERVER,
      .max_frame_bytes = 256, .max_message_bytes = 256,
      .max_buffered_input_bytes = 256 + CNET_WEBSOCKET_MAX_HEADER_BYTES,
      .write = capture_frame, .on_event = observe, .user = &sink};
    check_equal(cnet_websocket_init(&ws, &config), SALTS_OK);
  }
  after_each() { check_equal(cnet_websocket_destroy(&ws), SALTS_OK); }

  it("preserves ASCII including NUL at every alignment and short tail") {
    uint8_t storage[160], expected[160];
    for (size_t i = 0; i < sizeof(storage); ++i) storage[i] = (uint8_t)(i & 127u);
    memcpy(expected, storage, sizeof(storage));
    for (size_t offset = 0; offset < 16; ++offset) {
      for (size_t size = 0; size <= 129; ++size) {
        check_equal(cnet_websocket_send_text(&ws, storage + offset, size), SALTS_OK);
        const size_t header = size < 126 ? 2 : 4;
        check_equal(sink.size, size + header);
        check_equal(sink.frame + header, storage + offset, size);
      }
    }
    check_equal(storage, expected, sizeof(storage));
  }

  it("accepts valid code points across every SIMD lane") {
    const uint8_t points[][4] = {{0xc2, 0x80}, {0xe0, 0xa0, 0x80},
      {0xed, 0x9f, 0xbf}, {0xf0, 0x90, 0x80, 0x80}, {0xf4, 0x8f, 0xbf, 0xbf}};
    const size_t lengths[] = {2, 3, 3, 4, 4};
    for (size_t offset = 0; offset < 64; ++offset) {
      for (size_t point = 0; point < sizeof(lengths) / sizeof(lengths[0]); ++point) {
        uint8_t text[96];
        memset(text, 'a', sizeof(text));
        memcpy(text + offset, points[point], lengths[point]);
        check_equal(cnet_websocket_send_text(&ws, text, sizeof(text)), SALTS_OK);
        check_equal(sink.frame + 2, text, sizeof(text));
      }
    }
  }

  it("rejects overlong surrogate out-of-range and truncated sequences before writing") {
    const uint8_t invalid[][4] = {{0x80}, {0xc0, 0x80}, {0xc1, 0xbf},
      {0xe0, 0x9f, 0xbf}, {0xed, 0xa0, 0x80}, {0xf0, 0x8f, 0xbf, 0xbf},
      {0xf4, 0x90, 0x80, 0x80}, {0xf5, 0x80, 0x80, 0x80}, {0xff},
      {0xc2}, {0xe4, 0xb8}, {0xf0, 0x90, 0x80}};
    const size_t lengths[] = {1, 2, 2, 3, 3, 4, 4, 4, 1, 1, 2, 3};
    for (size_t offset = 0; offset < 64; ++offset) {
      for (size_t point = 0; point < sizeof(lengths) / sizeof(lengths[0]); ++point) {
        uint8_t text[96];
        memset(text, 'a', sizeof(text));
        memcpy(text + offset, invalid[point], lengths[point]);
        check_equal(cnet_websocket_send_text(&ws, text, offset + lengths[point]), SALTS_ECHARSET);
        check_equal(sink.writes, (size_t)0);
      }
    }
  }

  it("retains pending continuation state after a rejected ASCII fragment") {
    uint8_t first[32], last[64];
    memset(first, 'a', sizeof(first)); first[31] = 0xe4;
    memset(last, 'b', sizeof(last)); last[0] = 0xb8; last[1] = 0xad;
    check_equal(cnet_websocket_send_fragment(&ws, CNET_WEBSOCKET_MESSAGE_TEXT,
      first, sizeof(first), false), SALTS_OK);
    const size_t writes = sink.writes;
    check_equal(cnet_websocket_send_fragment(&ws, CNET_WEBSOCKET_MESSAGE_TEXT,
      "ASCII continuation is invalid", 29, true), SALTS_ECHARSET);
    check_equal(sink.writes, writes);
    check_equal(cnet_websocket_send_fragment(&ws, CNET_WEBSOCKET_MESSAGE_TEXT,
      last, 1, true), SALTS_ECHARSET);
    check_equal(sink.writes, writes);
    check_equal(cnet_websocket_send_fragment(&ws, CNET_WEBSOCKET_MESSAGE_TEXT,
      last, sizeof(last), true), SALTS_OK);
    check_equal(sink.frame[0], (uint8_t)0x80); /* Final continuation frame. */
    check_equal(cnet_websocket_send_text(&ws, "ready", 5), SALTS_OK);
  }

  it("never reads past the borrowed payload at a protected page boundary") {
    size_t page_size;
    uint8_t *pages;
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    page_size = info.dwPageSize;
    pages = VirtualAlloc(NULL, page_size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    pages = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pages == MAP_FAILED) pages = NULL;
#endif
    check_not_null(pages);
    if (pages) {
#ifdef _WIN32
      DWORD old_protection;
      check_not_equal(VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old_protection), 0);
#else
      check_equal(mprotect(pages + page_size, page_size, PROT_NONE), 0);
#endif
      for (size_t size = 1; size <= 65; ++size) {
        uint8_t *text = pages + page_size - size;
        memset(text, 'a', size);
        check_equal(cnet_websocket_send_text(&ws, text, size), SALTS_OK);
        text[size - 1] = 0xc2;
        check_equal(cnet_websocket_send_text(&ws, text, size), SALTS_ECHARSET);
        if (size >= 3) {
          text[size - 3] = 0xe4; text[size - 2] = 0xb8; text[size - 1] = 0xad;
          check_equal(cnet_websocket_send_text(&ws, text, size), SALTS_OK);
        }
      }
#ifdef _WIN32
      check_not_equal(VirtualFree(pages, 0, MEM_RELEASE), 0);
#else
      check_equal(munmap(pages, page_size * 2), 0);
#endif
    }
  }
}
