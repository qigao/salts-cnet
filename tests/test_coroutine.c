#include <coro.h>
#include <tinytest.h>
#include <coro_executor.h>
#include <error_codes.h>
#include <thread.h>
#include <platform_thread.h>

#include <stdatomic.h>

typedef struct probe {
  atomic_int started;
  atomic_int finished;
  atomic_int cancelled;
  atomic_int finalized;
} probe;

static void manual_entry(coro_t *co, void *arg) {
  int *steps = (int *)arg;
  (void)co;
  *steps = 1;
  (void)coro_yield();
  *steps = 2;
}

static void executor_entry(coro_t *co, void *arg) {
  probe *state = (probe *)arg;
  (void)co;
  atomic_fetch_add(&state->started, 1);
  atomic_fetch_add(&state->finished, 1);
}

static void executor_cancel(void *arg, int status) {
  probe *state = (probe *)arg;
  (void)status;
  atomic_fetch_add(&state->cancelled, 1);
}

static void executor_final(void *arg) {
  probe *state = (probe *)arg;
  atomic_fetch_add(&state->finalized, 1);
}

/* Keep two native threads inside different schedulers at the same time.
 * The handshakes order every observation, so a mistakenly process-global
 * current scheduler fails deterministically without introducing a test race.
 */
typedef struct scheduler_overlap {
  atomic_int first_entered;
  atomic_int second_entered;
  atomic_int first_checked;
  atomic_int second_done;
  atomic_int aborted;
} scheduler_overlap;

typedef struct scheduler_worker {
  scheduler_overlap *overlap;
  coro_scheduler_t *scheduler;
  int second;
  int failed;
} scheduler_worker;

static int wait_for(atomic_int *flag, scheduler_overlap *overlap) {
  while (!atomic_load_explicit(flag, memory_order_acquire)) {
    if (atomic_load_explicit(&overlap->aborted, memory_order_acquire)) return -1;
    cmeta_thread_yield();
  }
  return 0;
}

static void scheduler_entry(coro_t *co, void *arg) {
  scheduler_worker *worker = (scheduler_worker *)arg;
  scheduler_overlap *overlap = worker->overlap;
  (void)co;
  if (coro_current_scheduler() != worker->scheduler) worker->failed = 1;
  if (worker->second) {
    atomic_store_explicit(&overlap->second_entered, 1, memory_order_release);
    if (wait_for(&overlap->first_checked, overlap)) worker->failed = 1;
  } else {
    atomic_store_explicit(&overlap->first_entered, 1, memory_order_release);
    if (wait_for(&overlap->second_entered, overlap)) worker->failed = 1;
    if (coro_current_scheduler() != worker->scheduler) worker->failed = 1;
    atomic_store_explicit(&overlap->first_checked, 1, memory_order_release);
    if (wait_for(&overlap->second_done, overlap)) worker->failed = 1;
    if (coro_current_scheduler() != worker->scheduler) worker->failed = 1;
  }
}

static int run_scheduler(void *arg) {
  scheduler_worker *worker = (scheduler_worker *)arg;
  scheduler_overlap *overlap = worker->overlap;
  if (worker->second && wait_for(&overlap->first_entered, overlap)) return -1;
  if (coro_current_scheduler() != NULL) worker->failed = 1;
  worker->scheduler = coro_scheduler_create();
  if (worker->scheduler == NULL ||
      coro_spawn(worker->scheduler, scheduler_entry, worker, NULL) == NULL) {
    atomic_store_explicit(&overlap->aborted, 1, memory_order_release);
    coro_scheduler_destroy(worker->scheduler);
    return -1;
  }
  coro_scheduler_run(worker->scheduler);
  if (coro_current_scheduler() != NULL) worker->failed = 1;
  coro_scheduler_destroy(worker->scheduler);
  if (worker->second)
    atomic_store_explicit(&overlap->second_done, 1, memory_order_release);
  return worker->failed ? -1 : 0;
}

static int scheduler_thread_isolation(void) {
  scheduler_overlap overlap;
  scheduler_worker workers[2] = {{&overlap, NULL, 0, 0},
                                 {&overlap, NULL, 1, 0}};
  salts_platform_thread *threads[2] = {NULL, NULL};
  int first = -1, second = -1;
  atomic_init(&overlap.first_entered, 0);
  atomic_init(&overlap.second_entered, 0);
  atomic_init(&overlap.first_checked, 0);
  atomic_init(&overlap.second_done, 0);
  atomic_init(&overlap.aborted, 0);
  if (salts_platform_thread_create(&threads[0], run_scheduler, &workers[0]))
    return -1;
  if (salts_platform_thread_create(&threads[1], run_scheduler, &workers[1])) {
    atomic_store_explicit(&overlap.aborted, 1, memory_order_release);
    (void)salts_platform_thread_join(&threads[0], &first);
    return -1;
  }
  if (salts_platform_thread_join(&threads[0], &first)) return -1;
  if (salts_platform_thread_join(&threads[1], &second)) return -1;
  return first == 0 && second == 0 && coro_current_scheduler() == NULL ? 0 : -1;
}

static int saltscore_legacy_entry_test_coroutine_c(void) {
  int steps = 0;
  coro_t *co = coro_create(manual_entry, &steps, NULL);
  if (co == NULL || !coro_alive(co) || steps != 0) return 1;
  if (coro_resume(co) != 0 || steps != 1 || coro_state(co) != coro_SUSPENDED)
    return 2;
  if (coro_resume(co) != 0 || steps != 2 || coro_state(co) != coro_DEAD)
    return 3;
  coro_destroy(co);

  {
    coro_executor_config_t config = CORO_EXECUTOR_CONFIG_DEFAULT;
    coro_executor_stats_t stats = {0};
    probe state;
    coro_executor_t *executor;
    coro_executor_task_t task = {
        executor_entry, executor_cancel, executor_final, &state};
    atomic_init(&state.started, 0);
    atomic_init(&state.finished, 0);
    atomic_init(&state.cancelled, 0);
    atomic_init(&state.finalized, 0);
    config.worker_count = 1u;
    config.queue_capacity_per_worker = 2u;
    config.coroutine_pool.max_capacity = 2u;
    executor = coro_executor_create(&config);
    if (executor == NULL) return 4;
    if (coro_executor_try_submit(executor, &task) != SALTS_OK) return 5;
    if (coro_executor_shutdown(executor) != SALTS_OK ||
        coro_executor_wait(executor) != SALTS_OK) return 6;
    coro_executor_get_stats(executor, &stats);
    if (atomic_load(&state.started) != 1 ||
        atomic_load(&state.finished) != 1 ||
        atomic_load(&state.cancelled) != 0 ||
        atomic_load(&state.finalized) != 1 ||
        stats.active_tasks != 0u) return 7;
    if (coro_executor_destroy(executor) != SALTS_OK) return 8;
  }
  if (coro_executor_yield() != SALTS_EINVAL) return 9;
  if (scheduler_thread_isolation() != 0) return 10;
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Coroutine scheduler and cancellation") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_coroutine_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
