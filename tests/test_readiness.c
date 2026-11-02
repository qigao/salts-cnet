/* Original Platform Readiness on the single installed shared owner. */
#include <readiness.h>
#include <error_codes.h>
#include <thread.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(_WIN32)
#include <stdatomic.h>
#include <unistd.h>
#endif

#include <tinytest.h>

#if !defined(_WIN32)
typedef struct probe {
  atomic_int ready;
  atomic_int unexpected;
} probe;

static void on_readiness(void *user, cmeta_readiness_events events, int status) {
  probe *state = (probe *)user;
  if (status != SALTS_OK || (events & SALTS_READINESS_EVENT_READ) == 0u)
    atomic_store_explicit(&state->unexpected, 1, memory_order_release);
  atomic_store_explicit(&state->ready, 1, memory_order_release);
}

static void run_poll_pipe(void) {
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_registration reg = {0};
  cmeta_readiness_config config = {2u, 2u};
  cmeta_readiness_stats stats = {0};
  probe state = {0};
  int fds[2] = {-1, -1};
  unsigned attempt;
  const char byte = 'X';
  check(pipe(fds) == 0);
  check(cmeta_readiness_reactor_init_kind(
      &reactor, &config, SALTS_READINESS_BACKEND_POLL) == SALTS_OK);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.capacity == 2u && stats.registered_count == 0u);
  check(cmeta_readiness_register(&reactor, fds[0], &reg) == SALTS_OK);
  check(cmeta_readiness_arm(
      &reg, SALTS_READINESS_EVENT_READ, on_readiness, &state) == SALTS_OK);
  check(write(fds[1], &byte, 1u) == 1);
  for (attempt = 0u; attempt < 1000u; ++attempt) {
    if (atomic_load_explicit(&state.ready, memory_order_acquire)) break;
    cmeta_sleep_ms(1u);
  }
  check(atomic_load_explicit(&state.ready, memory_order_acquire));
  check(!atomic_load_explicit(&state.unexpected, memory_order_acquire));
  check(cmeta_readiness_close(&reg) == SALTS_OK);
  check(reg.impl == NULL);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_OK);
  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_OK);
  check(reactor.impl == NULL);
  check(close(fds[0]) == 0);
  check(close(fds[1]) == 0);

}
#endif

spec("Platform Readiness backend") {
  it("validates native backend selection and reactor lifecycle") {
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_config config = {2u, 2u};
  check(!cmeta_readiness_backend_supported((cmeta_readiness_backend_kind)99));
#if defined(_WIN32)
  check(!cmeta_readiness_backend_supported(SALTS_READINESS_BACKEND_POLL));
  check(!cmeta_readiness_backend_supported(SALTS_READINESS_BACKEND_KQUEUE));
  check(!cmeta_readiness_backend_supported(SALTS_READINESS_BACKEND_EPOLL));
  check(cmeta_readiness_reactor_init_kind(
      &reactor, &config, SALTS_READINESS_BACKEND_POLL) == SALTS_ENOTSUP);
  check(reactor.impl == NULL);
#else
  check(cmeta_readiness_backend_supported(SALTS_READINESS_BACKEND_POLL));
  run_poll_pipe();
# if defined(__APPLE__)
  check(cmeta_readiness_backend_supported(SALTS_READINESS_BACKEND_KQUEUE));
  check(cmeta_readiness_reactor_init_kind(
      &reactor, &config, SALTS_READINESS_BACKEND_KQUEUE) == SALTS_OK);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_OK);
  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_OK);
# endif
#endif
  }
}
