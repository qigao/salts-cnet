#include <deadline_queue.h>
#include <tinytest.h>
#include <disruptor.h>
#include <error_codes.h>
#include <rcu.h>
#include <spsc_ring.h>
#include <thread_pool.h>

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

typedef struct sample {
  atomic_int ran;
  atomic_int final;
  atomic_int cancelled;
} sample;

static void on_run(void *ctx) { atomic_fetch_add(&((sample *)ctx)->ran, 1); }
static void on_cancel(void *ctx) { atomic_fetch_add(&((sample *)ctx)->cancelled, 1); }
static void on_final(void *ctx) { atomic_fetch_add(&((sample *)ctx)->final, 1); }

static int deadline_contract(void) {
  cmeta_deadline_queue q = {0};
  cmeta_deadline_event e = {0};
  cmeta_deadline_id first = 0, second = 0, rejected = 1;
  if (cmeta_deadline_queue_init(&q, 2u) != SALTS_OK) return 1;
  if (cmeta_deadline_queue_schedule(&q, 10u, 11u, &first) != SALTS_OK ||
      cmeta_deadline_queue_schedule(&q, 10u, 22u, &second) != SALTS_OK ||
      first == 0 || second == 0 || first == second) return 2;
  if (cmeta_deadline_queue_schedule(&q, 10u, 33u, &rejected) != SALTS_ENOBUFS ||
      rejected != 0u) return 3;
  if (cmeta_deadline_queue_take_ready(&q, 9u, &e) != SALTS_ETIMEDOUT ||
      cmeta_deadline_queue_peek(&q, &e) != SALTS_OK || e.id != first) return 4;
  if (cmeta_deadline_queue_take_ready(&q, 10u, &e) != SALTS_OK ||
      e.id != first || e.token != 11u) return 5;
  if (cmeta_deadline_queue_cancel(&q, first, &e) != SALTS_ENOENT) return 6;
  if (cmeta_deadline_queue_take_ready(&q, 10u, &e) != SALTS_OK ||
      e.id != second || e.token != 22u) return 7;
  if (cmeta_deadline_queue_size(&q) != 0u ||
      cmeta_deadline_queue_destroy(&q) != SALTS_OK || q.impl != NULL) return 8;
  return 0;
}

static int spsc_contract(void) {
  uint8_t storage[8] = {0};
  cmeta_spsc_ring ring = {0};
  size_t n = 0;
  uint8_t *ptr;
  if (!cmeta_spsc_ring_init(&ring, storage, sizeof(storage))) return 1;
  if (cmeta_spsc_ring_write_available(&ring) != 7u) return 2;
  ptr = cmeta_spsc_ring_write_acquire(&ring, 3u);
  if (ptr == NULL) return 3;
  memcpy(ptr, "abc", 3u);
  cmeta_spsc_ring_write_release(&ring, 3u);
  ptr = cmeta_spsc_ring_read_acquire(&ring, &n);
  if (ptr == NULL || n != 3u || memcmp(ptr, "abc", 3u) != 0) return 4;
  cmeta_spsc_ring_read_release(&ring, n);
  if (cmeta_spsc_ring_read_available(&ring) != 0u ||
      cmeta_spsc_ring_write_available(&ring) != 7u) return 5;
  return 0;
}

static int rcu_contract(void) {
  int a = 1, b = 2;
  cmeta_rcu r = {0};
  cmeta_rcu_guard guard = {0};
  void *reclaimed = NULL;
  if (cmeta_rcu_init(&r, &a, 1u) != SALTS_OK) return 1;
  if (cmeta_rcu_read_lock(&r, &guard) != SALTS_OK ||
      cmeta_rcu_load(&guard) != &a) return 2;
  if (cmeta_rcu_replace(&r, &b) != SALTS_OK ||
      cmeta_rcu_try_reclaim(&r, &reclaimed) != SALTS_EBUSY ||
      reclaimed != NULL) return 3;
  if (cmeta_rcu_read_unlock(&guard) != SALTS_OK ||
      cmeta_rcu_try_reclaim(&r, &reclaimed) != SALTS_OK || reclaimed != &a) return 4;
  if (cmeta_rcu_close(&r) != SALTS_OK ||
      cmeta_rcu_read_lock(&r, &guard) != SALTS_ESHUTDOWN) return 5;
  reclaimed = NULL;
  if (cmeta_rcu_destroy(&r, &reclaimed) != SALTS_OK ||
      reclaimed != &b || r.impl != NULL) return 6;
  return 0;
}

static int saltscore_legacy_entry_test_concurrency_c(void) {
  int r = deadline_contract();
  if (r) return 10 + r;
  r = spsc_contract();
  if (r) return 30 + r;
  r = rcu_contract();
  if (r) return 50 + r;

  /* Real concurrent run/finalize settlement on a bounded thread pool. */
  {
    cmeta_threadpool_config_t config = {2, 8u};
    cmeta_threadpool_t *pool = cmeta_threadpool_create_with_config(&config);
    sample counters;
    cmeta_threadpool_task_t task = {on_run, on_cancel, on_final, &counters};
    if (!pool) return 71;
    atomic_init(&counters.ran, 0);
    atomic_init(&counters.final, 0);
    atomic_init(&counters.cancelled, 0);
    if (cmeta_threadpool_try_submit_task(pool, &task) != SALTS_OK) return 72;
    if (cmeta_threadpool_wait_status(pool) != SALTS_OK) return 73;
    if (cmeta_threadpool_shutdown_with_policy(pool, SALTS_THREADPOOL_SHUTDOWN_DRAIN) != SALTS_OK)
      return 74;
    if (atomic_load(&counters.ran) != 1 || atomic_load(&counters.final) != 1 ||
        atomic_load(&counters.cancelled) != 0) return 75;
    cmeta_threadpool_destroy(pool);
  }

  /* Disruptor construction must stay available independently of CMeta. */
  {
    disruptor_config_t config = {sizeof(uint64_t), 8u, 1u, DISRUPTOR_MODE_BROADCAST};
    disruptor_t *ring = disruptor_create(&config);
    if (ring == NULL) return 81;
    disruptor_destroy(ring);
  }
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Concurrency RCU SPSC ThreadPool") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_concurrency_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
