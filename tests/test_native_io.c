#include <native_io.h>
#include <native_io_sharded.h>
#include <error_codes.h>
#include <tinytest.h>
#include <string.h>

static native_io_sharded *startup_runtime;
/* Main owns the runtime; each callback writes only its shard's probe. wait()
 * publishes completed callbacks before main inspects them. Static storage also
 * survives a fatal TinyTest assertion until after_each has quiesced the owner. */
typedef struct startup_probe {
  size_t context_shard;
  size_t current_shard;
  unsigned calls;
  int flush_status;
  int cancellation;
} startup_probe;
static startup_probe startup_probes[4];

static void startup_run(native_io_sharded_context *context, void *arg) {
  startup_probe *probe = arg;
  probe->context_shard = native_io_sharded_context_shard(context);
  probe->current_shard = native_io_sharded_current_shard(startup_runtime);
  probe->flush_status = native_io_sharded_context_flush(context);
  ++probe->calls;
}

static void startup_cancel(void *arg, int status) {
  startup_probe *probe = arg;
  probe->cancellation = status;
}

static native_io_backend_kind native_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#elif defined(__linux__)
  return NATIVE_IO_BACKEND_EPOLL;
#else
  return (native_io_backend_kind)0;
#endif
}

spec("NativeIO backend lifecycle") {
  before_each() {
    check(startup_runtime == NULL, "the previous runtime must be quiescent before a new case");
  }

  after_each() {
    if (startup_runtime != NULL) {
      const int status = native_io_sharded_destroy(startup_runtime);
      if (status == SALTS_OK) startup_runtime = NULL;
      check(status == SALTS_OK, "startup cleanup status=%d", status);
    }
  }

  for (size_t shards = 1u; shards <= 4u; shards *= 2u) {
    it("preserves startup, fixed owner and teardown across repeated %zu-shard generations", shards) {
      const unsigned generations = shards == 1u ? 512u : 128u;
      const native_io_sharded_config config = {shards, 8u, {native_backend(), 4u, 8u, 8u}};
      for (unsigned generation = 0u; generation < generations; ++generation) {
        memset(startup_probes, 0, sizeof(startup_probes));
        const int status = native_io_sharded_create(&config, &startup_runtime);
        check(status == SALTS_OK, "generation=%u shards=%zu backend=%d create status=%d",
            generation, shards, (int)config.backend.kind, status);
        native_io_sharded_stats stats = NATIVE_IO_SHARDED_STATS_V1_INITIALIZER;
        check(native_io_sharded_get_stats(startup_runtime, &stats));
        check_equal(stats.shard_count, shards);
        check_equal(stats.active_command_slots, 0u);
        check_equal(stats.submitted_tasks, 0u);
        check(stats.accepting);
        for (size_t i = 0u; i < shards; ++i) {
          const native_io_sharded_task task = {startup_run, startup_cancel, NULL, &startup_probes[i]};
          const int submitted = native_io_sharded_submit_to(startup_runtime, i, &task);
          check(submitted == SALTS_OK, "generation=%u shard=%zu submit status=%d", generation, i, submitted);
        }
        check_equal(native_io_sharded_wait(startup_runtime), SALTS_OK);
        for (size_t i = 0u; i < shards; ++i) {
          check_equal(startup_probes[i].calls, 1u);
          check_equal(startup_probes[i].cancellation, 0);
          check_equal(startup_probes[i].context_shard, i);
          check_equal(startup_probes[i].current_shard, i);
          check_equal(startup_probes[i].flush_status, SALTS_OK);
        }
        check(native_io_sharded_get_stats(startup_runtime, &stats));
        check_equal(stats.submitted_tasks, shards);
        check_equal(stats.completed_tasks, shards);
        check_equal(stats.active_command_slots, 0u);
        const int shutdown = native_io_sharded_shutdown(startup_runtime);
        check(shutdown == SALTS_OK, "generation=%u shards=%zu shutdown status=%d", generation, shards, shutdown);
        const native_io_sharded_task rejected = {startup_run, startup_cancel, NULL, &startup_probes[0]};
        check_equal(native_io_sharded_submit_to(startup_runtime, 0u, &rejected), SALTS_ESHUTDOWN);
        check_equal(native_io_sharded_wait(startup_runtime), SALTS_OK);
        const int destroyed = native_io_sharded_destroy(startup_runtime);
        if (destroyed == SALTS_OK) startup_runtime = NULL;
        check(destroyed == SALTS_OK, "generation=%u shards=%zu destroy status=%d", generation, shards, destroyed);
        for (size_t i = 0u; i < shards; ++i) {
          check_equal(startup_probes[i].calls, 1u);
          check_equal(startup_probes[i].cancellation, 0);
        }
      }
    }
  }

  for (unsigned invalid = 0u; invalid < 4u; ++invalid) {
    it("preserves backend startup rejection and clears ownership, case %u", invalid) {
      native_io_sharded_config config = {2u, 8u, {native_backend(), 4u, 8u, 8u}};
      if (invalid == 0u) config.backend.endpoint_capacity = 0u;
      if (invalid == 1u) config.backend.request_capacity = 0u;
      if (invalid == 2u) config.backend.completion_batch_capacity = 0u;
      if (invalid == 3u) config.backend.completion_batch_capacity = 9u;
      const int status = native_io_sharded_create(&config, &startup_runtime);
      check_equal(status, SALTS_EINVAL);
      check(startup_runtime == NULL);
    }
  }

  it("uses the platform native backend without fallback") {
    native_io_backend backend = {0};
    native_io_backend_stats stats = {0};
    native_io_backend_config config = { native_backend(), 2u, 4u, 2u };
    native_io_sharded_endpoint none = {0};
    int status;

    /* A new native platform must implement its owner; never pass vacuously. */
    check(config.kind != 0);
    check(native_io_backend_kind_supported(config.kind));
    check(native_io_backend_kind_model(config.kind) != NATIVE_IO_MODEL_NONE);

    check(!native_io_endpoint_valid((native_io_endpoint){0}));
    check(!native_io_request_valid((native_io_request){0}));
    check(!native_io_sharded_endpoint_valid(none));

    status = native_io_backend_init(&backend, &config);
    check(status == SALTS_OK, "native_io_backend_init status=%d", status);
    check(native_io_backend_get_stats(&backend, &stats));
    check(stats.endpoint_capacity == config.endpoint_capacity);
    check(stats.request_capacity == config.request_capacity);
    check(stats.active_requests == 0u);

    status = native_io_backend_close(&backend);
    check(status == SALTS_OK, "native_io_backend_close status=%d", status);

    status = native_io_backend_destroy(&backend);
    check(status == SALTS_OK, "native_io_backend_destroy status=%d", status);
    check(backend.impl == NULL);
  }
}
