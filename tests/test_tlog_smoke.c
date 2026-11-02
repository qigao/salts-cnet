#include <tlog.h>
#include <tinytest.h>
#include <string.h>

static size_t logged_count = 0u;

static void count_log_entry(const cmeta_log_entry_t *entry, void *ctx) {
  (void)ctx;
  if (entry && entry->message.len == 4u &&
      memcmp(entry->message.data, "test", 4u) == 0) {
    ++logged_count;
  }
}

spec("Original asynchronous TLog callback") {
  it("flushes a real log record to the callback sink exactly once") {
    logged_count = 0u;
    tlog_t *logger = tlog_create(NULL);
    check(logger != NULL);

    cmeta_log_sink_t *sink = cmeta_sink_callback_create(count_log_entry, NULL);
    if (sink == NULL) tlog_destroy(logger);
    check(sink != NULL);

    const int admitted = tlog_add_sink(logger, sink);
    if (admitted != 0) {
      cmeta_sink_destroy(sink);
      tlog_destroy(logger);
    }
    check(admitted == 0);

    tlog_set_level(logger, SALTS_LOG_LEVEL_DEBUG);
    cmeta_log_str(logger, SALTS_LOG_LEVEL_INFO, vstr_from_cstr("core"),
                 vstr_from_buf(NULL, 0), 0, vstr_from_cstr("test"));
    tlog_flush(logger);
    check(logged_count == 1u && tlog_get_written(logger) == 1u &&
          tlog_get_queue_size(logger) == 0u);
    tlog_destroy(logger);
  }
}
