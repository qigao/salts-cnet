/* True OS poll callback versus close/shutdown races. A blocked callback
 * holds borrowed stack state; the original shared Readiness implementation
 * MUST drain its callback before either owner may be reclaimed.
 */
#include <tinytest.h>
#include <error_codes.h>
#include <readiness.h>
#include "../platform/src/readiness_internal.h"
#include <thread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

typedef struct gate {
  cmeta_mutex_t lock;
  cmeta_cond_t changed;
  int entered;
  int released;
  int exited;
  unsigned callbacks;
  int bad_status;
} gate;

typedef struct closer {
  cmeta_readiness_reactor *reactor;
  cmeta_readiness_registration *reg;
  atomic_int started;
  atomic_int finished;
  int shutdown_mode;
  int status;
} closer;

static void blocked_callback(void *user, cmeta_readiness_events events,
                             int status) {
  gate *g = (gate *)user;
  cmeta_mutex_lock(&g->lock);
  ++g->callbacks;
  if (status != SALTS_OK || !(events & SALTS_READINESS_EVENT_READ))
    g->bad_status = 1;
  g->entered = 1;
  cmeta_cond_broadcast(&g->changed);
  while (!g->released)
    cmeta_cond_wait(&g->changed, &g->lock);
  g->exited = 1;
  cmeta_cond_broadcast(&g->changed);
  cmeta_mutex_unlock(&g->lock);
}

static void close_entry(void *arg) {
  closer *c = (closer *)arg;
  atomic_store_explicit(&c->started, 1, memory_order_release);
  c->status = c->shutdown_mode
      ? cmeta_readiness_reactor_shutdown(c->reactor)
      : cmeta_readiness_close(c->reg);
  atomic_store_explicit(&c->finished, 1, memory_order_release);
}

static int wait_callback(gate *g) {
  int status = SALTS_OK;
  cmeta_mutex_lock(&g->lock);
  while (!g->entered && status == SALTS_OK)
    status = cmeta_cond_timedwait(
        &g->changed, &g->lock, UINT64_C(2000000000));
  cmeta_mutex_unlock(&g->lock);
  return status;
}

static int run_case(int shutdown_mode, unsigned iteration) {
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_registration reg = {0};
  cmeta_readiness_config config = {1u, 1u};
  gate g = {0};
  closer c = {0};
  cmeta_thread_t thread = NULL;
  int fd[2] = {-1, -1};
  int created = 0;
  int ready = 0;
  int issue = 0;
  unsigned attempt;
  const char byte = (char)('a' + iteration);

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "Readiness close race iteration %u mode %d line %d: %s\n", \
            iteration, shutdown_mode, __LINE__, #expr); \
    issue = __LINE__; goto cleanup; \
  } } while (0)

  cmeta_mutex_init(&g.lock);
  cmeta_cond_init(&g.changed);
  REQUIRE(g.lock != NULL && g.changed != NULL);
  REQUIRE(pipe(fd) == 0);
  REQUIRE(cmeta_readiness_reactor_init_kind(
      &reactor, &config, SALTS_READINESS_BACKEND_POLL) == SALTS_OK);
  ready = 1;
  REQUIRE(cmeta_readiness_register(&reactor, fd[0], &reg) == SALTS_OK);
  REQUIRE(cmeta_readiness_arm(
      &reg, SALTS_READINESS_EVENT_READ, blocked_callback, &g) == SALTS_OK);
  REQUIRE(write(fd[1], &byte, 1u) == 1);
  REQUIRE(wait_callback(&g) == SALTS_OK);

  c.reg = &reg;
  c.reactor = &reactor;
  c.shutdown_mode = shutdown_mode;
  atomic_init(&c.started, 0);
  atomic_init(&c.finished, 0);
  c.status = SALTS_EIO;
  REQUIRE(cmeta_thread_create(&thread, close_entry, &c) == SALTS_OK);
  created = 1;
  for (attempt = 0u; attempt < 1000u; ++attempt) {
    if (atomic_load_explicit(&c.started, memory_order_acquire)) break;
    cmeta_sleep_ms(1);
  }
  REQUIRE(atomic_load_explicit(&c.started, memory_order_acquire));
  /* The callback remains blocked; both close() and reactor shutdown()
   * must join its borrow instead of freeing its owning storage early. */
  if (shutdown_mode)
    REQUIRE(cmeta_readiness_backend_wait_admission_closed(&reactor) == SALTS_OK);
  cmeta_sleep_ms(10);
  REQUIRE(!atomic_load_explicit(&c.finished, memory_order_acquire));

cleanup:
  if (g.lock != NULL) {
    cmeta_mutex_lock(&g.lock);
    g.released = 1;
    cmeta_cond_broadcast(&g.changed);
    cmeta_mutex_unlock(&g.lock);
  }
  if (created) {
    if (cmeta_thread_join(&thread) != SALTS_OK && issue == 0)
      issue = __LINE__;
    if ((c.status != SALTS_OK ||
         !atomic_load_explicit(&c.finished, memory_order_acquire)) &&
        issue == 0)
      issue = __LINE__;
  }
  if (reg.impl != NULL && cmeta_readiness_close(&reg) != SALTS_OK && issue == 0)
    issue = __LINE__;
  if (ready) {
    if (!shutdown_mode || !created || c.status != SALTS_OK) {
      if (cmeta_readiness_reactor_shutdown(&reactor) != SALTS_OK && issue == 0)
        issue = __LINE__;
    }
    if (cmeta_readiness_reactor_destroy(&reactor) != SALTS_OK && issue == 0)
      issue = __LINE__;
  }
  if (g.lock != NULL) {
    cmeta_mutex_lock(&g.lock);
    if ((g.callbacks != 1u || !g.exited || g.bad_status) && issue == 0)
      issue = __LINE__;
    cmeta_mutex_unlock(&g.lock);
  }
  if (fd[0] >= 0) (void)close(fd[0]);
  if (fd[1] >= 0) (void)close(fd[1]);
  if (g.changed != NULL) cmeta_cond_destroy(&g.changed);
  if (g.lock != NULL) cmeta_mutex_destroy(&g.lock);
  return issue;
#undef REQUIRE
}

static int saltscore_legacy_entry_test_readiness_race_c(void) {
  unsigned iteration;
  for (iteration = 0u; iteration < 8u; ++iteration) {
    int result = run_case(0, iteration);
    if (result != 0) return result;
    result = run_case(1, iteration);
    if (result != 0) return result;
  }
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Readiness race shutdown lifecycle") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_readiness_race_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
