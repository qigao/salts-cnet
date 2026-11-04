#define _POSIX_C_SOURCE 200809L

#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <capture.h>
#include <errno.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Run ONLY under media/capture/tests/native_tsan/run_private_pulse.sh. The driver
 * refuses all but a single named software PulseAudio null-sink monitor.
 * Actual salts_* functions come from this repository's full original
 * Capture Linux/miniaudio source compiled with -fsanitize=thread.
 *
 * No physical devices, model weights, audio recording, alternate Capture
 * implementation, callback malloc or secondary PCM staging are permitted. */
#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "FAIL native Capture source TSan %s:%d: %s\n", \
          __FILE__, __LINE__, #x); _Exit(1); \
} } while (0)

enum { PERIOD_BYTES = 640, POLL_MS = 2, CALLBACK_DEADLINE_MS = 5000 };

static uint64_t now_ms(void) {
  struct timespec t = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0u;
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void nap_ms(long ms) {
  struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
  (void)nanosleep(&t, NULL);
}
static salts_audio_capture_config_t audio_format(void) {
  salts_audio_capture_config_t fmt = {16000, 1, 16, 20};
  return fmt;
}

/* No implicit default IDs. The ONLY valid source in this process must
 * identify the CI-owned private software Pulse null sink, not user hardware. */
static int audited_monitor(char *id, size_t capacity) {
  const char *flag = getenv("SALTS_CAPTURE_TSAN_VIRTUAL_ONLY");
  const char *server = getenv("PULSE_SERVER");
  if (!flag || strcmp(flag, "1") != 0 || !server ||
      strncmp(server, "unix:", 5) != 0) return -1;
  salts_capture_device_t items[SALTS_CAPTURE_MAX_DEVICES] = {{0}};
  int n = salts_capture_list_audio_devices(items, SALTS_CAPTURE_MAX_DEVICES);
  if (n != 1 || items[0].type != SALTS_CAPTURE_TYPE_AUDIO ||
      !strstr(items[0].name, "CaptureTsanVirtual") ||
      !items[0].id[0] || strlen(items[0].id) >= capacity)
    return -1;
  memcpy(id, items[0].id, strlen(items[0].id) + 1);
  fprintf(stderr, "AUDIT sole virtual Capture device: name=%s id=%s\n",
          items[0].name, id);
  return 0;
}

typedef struct callback_trace {
  atomic_uint calls;
  atomic_uint invalid;
  atomic_uint_fast64_t previous_ts;
  atomic_uint_fast64_t first_ts;
} callback_trace_t;

static void regular_callback(salts_capture_t *cap, const uint8_t *borrowed,
                             size_t bytes, uint64_t timestamp_us, void *user) {
  (void)cap;
  callback_trace_t *t = user;
  if (!borrowed || bytes != PERIOD_BYTES)
    (void)atomic_fetch_add_explicit(&t->invalid, 1u, memory_order_relaxed);
  unsigned prior = atomic_fetch_add_explicit(
      &t->calls, 1u, memory_order_relaxed);
  if (prior == 0u)
    atomic_store_explicit(&t->first_ts, timestamp_us, memory_order_release);
  uint64_t old = atomic_exchange_explicit(
      &t->previous_ts, timestamp_us, memory_order_relaxed);
  if (prior > 0u && timestamp_us <= old)
    (void)atomic_fetch_add_explicit(&t->invalid, 1u, memory_order_relaxed);
  /* borrowed is not persisted or accessed after returning */
}

static int wait_for_calls(const callback_trace_t *t, unsigned minimum) {
  const uint64_t deadline = now_ms() + CALLBACK_DEADLINE_MS;
  while (atomic_load_explicit(&t->calls, memory_order_acquire) < minimum) {
    if (!now_ms() || now_ms() >= deadline) return -1;
    nap_ms(POLL_MS);
  }
  return 0;
}

static int test_real_callback_start_stop(const char *exact_id) {
  for (unsigned cycle = 0u; cycle < 3u; ++cycle) {
    salts_audio_capture_config_t format = audio_format();
    salts_capture_t *cap = salts_audio_capture_create(exact_id, &format);
    CHECK(cap != NULL);
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_STOPPED);
    callback_trace_t t = {0};
    atomic_init(&t.calls, 0u);
    atomic_init(&t.invalid, 0u);
    atomic_init(&t.previous_ts, 0u);
    atomic_init(&t.first_ts, UINT64_MAX);
    salts_audio_capture_set_callback(cap, regular_callback, &t);
    CHECK(salts_capture_start(cap) == SALTS_CAPTURE_OK);
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_RUNNING);
    CHECK(wait_for_calls(&t, 3u) == 0);
    CHECK(atomic_load_explicit(&t.invalid, memory_order_relaxed) == 0u);
    salts_capture_stop(cap); /* native ma_device_stop must quiesce callback */
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_STOPPED);
    const unsigned settled = atomic_load_explicit(&t.calls, memory_order_acquire);
    CHECK(settled >= 3u);
    nap_ms(35);
    CHECK(atomic_load_explicit(&t.calls, memory_order_acquire) == settled);
    salts_capture_stop(cap); /* idempotent */
    salts_capture_destroy(cap);
  }
  puts("PASS original source-Tsan Capture native callbacks start/stop/join, 3 cycles");
  return 0;
}

/* Reuse the SAME device/owner after a complete native stop/join. Fresh
 * create/destroy cycles above cannot guard re-opening callback admission or
 * resetting the sample timestamp origin on a retained miniaudio context.
 * All trace resets happen only while the native callback is fully joined. */
static int test_same_device_restart(const char *exact_id) {
  salts_audio_capture_config_t fmt = audio_format();
  salts_capture_t *cap = salts_audio_capture_create(exact_id, &fmt);
  CHECK(cap != NULL);
  callback_trace_t t = {0};
  atomic_init(&t.calls, 0u);
  atomic_init(&t.invalid, 0u);
  atomic_init(&t.previous_ts, 0u);
  atomic_init(&t.first_ts, UINT64_MAX);
  salts_audio_capture_set_callback(cap, regular_callback, &t); /* once, before start */

  for (unsigned cycle = 0u; cycle < 3u; ++cycle) {
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_STOPPED);
    /* The prior stop synchronously joined the native audio callback. */
    atomic_store_explicit(&t.calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&t.invalid, 0u, memory_order_relaxed);
    atomic_store_explicit(&t.previous_ts, 0u, memory_order_relaxed);
    atomic_store_explicit(&t.first_ts, UINT64_MAX, memory_order_relaxed);

    CHECK(salts_capture_start(cap) == SALTS_CAPTURE_OK);
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_RUNNING);
    CHECK(wait_for_calls(&t, 3u) == 0);
    CHECK(atomic_load_explicit(&t.invalid, memory_order_acquire) == 0u);
    CHECK(atomic_load_explicit(&t.first_ts, memory_order_acquire) == 0u);

    salts_capture_stop(cap);
    CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_STOPPED);
    const unsigned settled = atomic_load_explicit(&t.calls, memory_order_acquire);
    CHECK(settled >= 3u);
    nap_ms(35);
    CHECK(atomic_load_explicit(&t.calls, memory_order_acquire) == settled);
  }
  salts_capture_destroy(cap);
  puts("PASS same-device Capture stop/restart admission, timestamp reset, no late callback");
  return 0;
}

typedef struct held_callback {
  pthread_mutex_t lock;
  pthread_cond_t gate;
  salts_capture_t *borrowed_device;
  int entered, release;
  atomic_int callback_exited, stop_entered, stop_returned, timeout;
  atomic_uint callbacks;
} held_callback_t;

static void held_pcm(salts_capture_t *cap, const uint8_t *pcm,
                     size_t n, uint64_t timestamp_us, void *user) {
  (void)cap;
  (void)timestamp_us;
  held_callback_t *h = user;
  unsigned index = atomic_fetch_add_explicit(
      &h->callbacks, 1u, memory_order_acq_rel);
  if (!pcm || n != PERIOD_BYTES)
    atomic_store_explicit(&h->timeout, 1, memory_order_release);
  if (index != 0u) return;
  if (pthread_mutex_lock(&h->lock) != 0) {
    atomic_store_explicit(&h->timeout, 1, memory_order_release);
    return;
  }
  h->entered = 1;
  (void)pthread_cond_broadcast(&h->gate);
  struct timespec deadline = {0};
  if (clock_gettime(CLOCK_REALTIME, &deadline) == 0) {
    deadline.tv_sec += 8;
    while (!h->release) {
      if (pthread_cond_timedwait(&h->gate, &h->lock, &deadline) != 0) {
        atomic_store_explicit(&h->timeout, 1, memory_order_release);
        break; /* release safely; never abort/destroy live audio callback */
      }
    }
  } else {
    atomic_store_explicit(&h->timeout, 1, memory_order_release);
  }
  (void)pthread_mutex_unlock(&h->lock);
  atomic_store_explicit(&h->callback_exited, 1, memory_order_release);
}
static void *stop_owner(void *arg) {
  held_callback_t *h = arg;
  atomic_store_explicit(&h->stop_entered, 1, memory_order_release);
  salts_capture_stop(h->borrowed_device);
  atomic_store_explicit(&h->stop_returned, 1, memory_order_release);
  return NULL;
}

static int test_held_native_callback_stop_barrier(const char *exact_id) {
  salts_audio_capture_config_t fmt = audio_format();
  salts_capture_t *cap = salts_audio_capture_create(exact_id, &fmt);
  CHECK(cap != NULL);
  held_callback_t h = {0};
  h.borrowed_device = cap;
  CHECK(pthread_mutex_init(&h.lock, NULL) == 0);
  CHECK(pthread_cond_init(&h.gate, NULL) == 0);
  atomic_init(&h.callback_exited, 0);
  atomic_init(&h.stop_entered, 0);
  atomic_init(&h.stop_returned, 0);
  atomic_init(&h.timeout, 0);
  atomic_init(&h.callbacks, 0u);
  salts_audio_capture_set_callback(cap, held_pcm, &h);
  CHECK(salts_capture_start(cap) == SALTS_CAPTURE_OK);
  struct timespec deadline = {0};
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 7;
  CHECK(pthread_mutex_lock(&h.lock) == 0);
  while (!h.entered) {
    if (pthread_cond_timedwait(&h.gate, &h.lock, &deadline) != 0) {
      (void)pthread_mutex_unlock(&h.lock);
      CHECK(0 && "native callback did not enter blocked gate");
    }
  }
  CHECK(pthread_mutex_unlock(&h.lock) == 0);
  CHECK(atomic_load_explicit(&h.callback_exited, memory_order_acquire) == 0);
  pthread_t stopper;
  CHECK(pthread_create(&stopper, NULL, stop_owner, &h) == 0);
  const uint64_t limit = now_ms() + 1000u;
  while (!atomic_load_explicit(&h.stop_entered, memory_order_acquire)) {
    CHECK(now_ms() < limit);
    nap_ms(POLL_MS);
  }
  nap_ms(40);
  const int premature = atomic_load_explicit(
      &h.stop_returned, memory_order_acquire);
  CHECK(pthread_mutex_lock(&h.lock) == 0);
  h.release = 1; /* release even if premature for guaranteed worker cleanup */
  CHECK(pthread_cond_broadcast(&h.gate) == 0);
  CHECK(pthread_mutex_unlock(&h.lock) == 0);
  CHECK(pthread_join(stopper, NULL) == 0);
  CHECK(premature == 0);
  CHECK(atomic_load_explicit(&h.callback_exited, memory_order_acquire) == 1);
  CHECK(atomic_load_explicit(&h.stop_returned, memory_order_acquire) == 1);
  CHECK(atomic_load_explicit(&h.timeout, memory_order_acquire) == 0);
  CHECK(salts_capture_get_state(cap) == SALTS_CAPTURE_STATE_STOPPED);
  unsigned count = atomic_load_explicit(&h.callbacks, memory_order_acquire);
  nap_ms(40);
  CHECK(atomic_load_explicit(&h.callbacks, memory_order_acquire) == count);
  CHECK(pthread_cond_destroy(&h.gate) == 0);
  CHECK(pthread_mutex_destroy(&h.lock) == 0);
  salts_capture_destroy(cap); /* must only occur after native join */
  puts("PASS original source-Tsan Capture blocked callback forces concurrent stop/join");
  return 0;
}
/* Destroying an ACTIVE Capture must close admission and synchronously join
 * the same real miniaudio callback even when the caller did NOT stop first.
 * Keep the test-owned user_data live until the destroy thread has joined. */
static void *destroy_owner(void *arg) {
  held_callback_t *h = arg;
  atomic_store_explicit(&h->stop_entered, 1, memory_order_release);
  salts_capture_destroy(h->borrowed_device);
  atomic_store_explicit(&h->stop_returned, 1, memory_order_release);
  return NULL;
}

static int test_held_native_callback_destroy_barrier(const char *exact_id) {
  salts_audio_capture_config_t fmt = audio_format();
  salts_capture_t *cap = salts_audio_capture_create(exact_id, &fmt);
  CHECK(cap != NULL);
  held_callback_t h = {0};
  h.borrowed_device = cap;
  CHECK(pthread_mutex_init(&h.lock, NULL) == 0);
  CHECK(pthread_cond_init(&h.gate, NULL) == 0);
  atomic_init(&h.callback_exited, 0);
  atomic_init(&h.stop_entered, 0);
  atomic_init(&h.stop_returned, 0);
  atomic_init(&h.timeout, 0);
  atomic_init(&h.callbacks, 0u);
  salts_audio_capture_set_callback(cap, held_pcm, &h);
  CHECK(salts_capture_start(cap) == SALTS_CAPTURE_OK);

  struct timespec deadline = {0};
  CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 7;
  CHECK(pthread_mutex_lock(&h.lock) == 0);
  while (!h.entered) {
    if (pthread_cond_timedwait(&h.gate, &h.lock, &deadline) != 0) {
      (void)pthread_mutex_unlock(&h.lock);
      CHECK(0 && "native callback did not enter pre-destroy gate");
    }
  }
  CHECK(pthread_mutex_unlock(&h.lock) == 0);
  CHECK(atomic_load_explicit(&h.callback_exited, memory_order_acquire) == 0);

  pthread_t destroyer;
  CHECK(pthread_create(&destroyer, NULL, destroy_owner, &h) == 0);
  const uint64_t limit = now_ms() + 1000u;
  while (!atomic_load_explicit(&h.stop_entered, memory_order_acquire)) {
    CHECK(now_ms() < limit);
    nap_ms(POLL_MS);
  }
  nap_ms(40);
  const int premature = atomic_load_explicit(
      &h.stop_returned, memory_order_acquire);
  CHECK(pthread_mutex_lock(&h.lock) == 0);
  h.release = 1; /* release even if destroy returned too early */
  CHECK(pthread_cond_broadcast(&h.gate) == 0);
  CHECK(pthread_mutex_unlock(&h.lock) == 0);
  CHECK(pthread_join(destroyer, NULL) == 0);

  CHECK(premature == 0);
  CHECK(atomic_load_explicit(&h.callback_exited, memory_order_acquire) == 1);
  CHECK(atomic_load_explicit(&h.stop_returned, memory_order_acquire) == 1);
  CHECK(atomic_load_explicit(&h.timeout, memory_order_acquire) == 0);
  const unsigned settled = atomic_load_explicit(
      &h.callbacks, memory_order_acquire);
  CHECK(settled >= 1u);
  nap_ms(40);
  CHECK(atomic_load_explicit(&h.callbacks, memory_order_acquire) == settled);
  CHECK(pthread_cond_destroy(&h.gate) == 0);
  CHECK(pthread_mutex_destroy(&h.lock) == 0);
  /* cap is already destroyed; neither this thread nor callback may touch it. */
  puts("PASS active Capture destroy waits for blocked native callback join");
  return 0;
}

static int test_invalid_exact_device_rejects(void) {
  salts_audio_capture_config_t bad = {12345, 1, 16, 20};
  salts_audio_capture_config_t valid = audio_format();
  CHECK(salts_audio_capture_create(NULL, &bad) == NULL);
  CHECK(salts_audio_capture_create("not-an-enumerated-device", &valid) == NULL);
  puts("PASS original source-Tsan Capture invalid format and exact device no fallback");
  return 0;
}
/* Each case has a fresh process so a failed assertion cannot unwind a
 * callback's stack-owned trace while miniaudio still borrows it. The parent
 * TinyTest process reports failure; child failure exits immediately. */
static const char *test_program;
extern char **environ;

static int run_isolated_case(const char *name) {
  pid_t child;
  int status = 0;
  char *args[] = {(char *)test_program, "--capture-case", (char *)name, NULL};
  const int error = posix_spawn(&child, test_program, NULL, NULL, args, environ);
  if (error != 0) return error;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

spec("Capture native virtual monitor lifecycle") {
  it("rejects invalid formats and exact unknown devices without fallback") {
    check_equal(run_isolated_case("invalid"), 0);
  }
  it("joins callbacks across three fresh start/stop cycles") {
    check_equal(run_isolated_case("cycles"), 0);
  }
  it("reopens the same device and resets timestamps after stop") {
    check_equal(run_isolated_case("restart"), 0);
  }
  it("blocks concurrent stop until the native callback returns") {
    check_equal(run_isolated_case("stop"), 0);
  }
  it("blocks active destroy until the native callback returns") {
    check_equal(run_isolated_case("destroy"), 0);
  }
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--capture-case") == 0) {
    char id[128] = {0};
    CHECK(audited_monitor(id, sizeof(id)) == 0);
    if (strcmp(argv[2], "invalid") == 0) return test_invalid_exact_device_rejects();
    if (strcmp(argv[2], "cycles") == 0) return test_real_callback_start_stop(id);
    if (strcmp(argv[2], "restart") == 0) return test_same_device_restart(id);
    if (strcmp(argv[2], "stop") == 0) return test_held_native_callback_stop_barrier(id);
    if (strcmp(argv[2], "destroy") == 0) return test_held_native_callback_destroy_barrier(id);
    return 2;
  }
  test_program = argv[0];
  return ttest_main__(argc, argv, TTEST_INVOKE_SPEC_ADAPTER__,
      TT_USE_COLOR != 0, TT_USE_TAP != 0,
      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
