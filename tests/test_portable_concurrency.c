#include <platform_atomic.h>
#include <tinytest.h>
#include <platform_thread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum { THREADS = 6, LOOPS = 12000 };
static salts_atomic32 total32 = {0};
static salts_atomic64 total64 = {0};
static salts_platform_once once = SALTS_PLATFORM_ONCE_INIT;
static int init_count;
static salts_platform_mutex *gate_mutex;
static salts_platform_condition *gate_condition;
static int gate_open;
static int gate_payload;
static salts_atomic32 detached_done = {0};

static void once_callback(void) { ++init_count; }
static int increment(void *arg) {
    uint32_t old32 = 0; uint64_t old64 = 0; int i;
    (void)arg;
    if (salts_platform_call_once(&once, once_callback)) return -1;
    for (i = 0; i < LOOPS; ++i) {
        if (salts_atomic32_fetch_add(&total32, 1u, SALTS_MEMORY_RELAXED, &old32)) return -2;
        if (salts_atomic64_fetch_add(&total64, 1u, SALTS_MEMORY_RELAXED, &old64)) return -3;
    }
    return 24;
}
static int gate_reader(void *arg) {
    int result;
    (void)arg;
    if (salts_platform_mutex_lock(gate_mutex)) return -1;
    while (!gate_open)
        if (salts_platform_condition_wait(gate_condition, gate_mutex)) return -2;
    result = gate_payload;
    if (salts_platform_mutex_unlock(gate_mutex)) return -3;
    return result;
}
static int detached_worker(void *arg) {
    (void)arg;
    (void)salts_atomic32_store(&detached_done, 1u, SALTS_MEMORY_RELEASE);
    return 0;
}
static int basic_atomic(void) {
    salts_atomic8 b = {0}; salts_atomic16 h = {0};
    salts_atomic32 v = {0}; salts_atomic64 big = {0};
    salts_atomic_ptr ptr = {0};
    uint8_t old8 = 0; uint16_t old16 = 0;
    uint32_t expected32 = 5u, old32 = 0;
    uint64_t expected64 = 1u, old64 = 0;
    void *expected_ptr, *got = NULL;
    int a = 1, c = 2, swapped = -1;
    union { SALTS_CORE_ALIGN8 uint64_t aligned; uint8_t bytes[32]; } bad = {0};
    struct abi_align { char pad; salts_atomic64 value; };
    if (salts_platform_portable_abi_verify(SALTS_PLATFORM_PORTABLE_ABI_VERSION,
            sizeof(salts_atomic64), offsetof(struct abi_align, value),
            sizeof(salts_atomic_ptr))) return 90;
    if (salts_platform_portable_abi_verify(99u, 8u, 8u, sizeof(salts_atomic_ptr)) != SALTS_EINVAL) return 91;
    if (salts_atomic8_init(&b, 255u) ||
        salts_atomic8_fetch_add(&b, 1u, SALTS_MEMORY_RELAXED, &old8) || old8 != 255u ||
        salts_atomic8_load(&b, SALTS_MEMORY_ACQUIRE, &old8) || old8 != 0u) return 1;
    if (salts_atomic16_init(&h, 65535u) ||
        salts_atomic16_fetch_add(&h, 1u, SALTS_MEMORY_ACQ_REL, &old16) || old16 != 65535u ||
        salts_atomic16_load(&h, SALTS_MEMORY_SEQ_CST, &old16) || old16 != 0u) return 2;
    if (salts_atomic32_init(&v, 7u) ||
        salts_atomic32_cas(&v, &expected32, 9u, SALTS_MEMORY_ACQ_REL, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 0 || expected32 != 7u) return 3;
    if (salts_atomic32_cas(&v, &expected32, 9u, SALTS_MEMORY_ACQ_REL, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 1 || salts_atomic32_exchange(&v, 3u, SALTS_MEMORY_SEQ_CST, &old32) ||
        old32 != 9u) return 4;
    if (salts_atomic32_load(&v, SALTS_MEMORY_RELEASE, &old32) != SALTS_EINVAL ||
        salts_atomic32_store(&v, 4u, SALTS_MEMORY_ACQUIRE) != SALTS_EINVAL ||
        salts_atomic32_cas(&v, &expected32, 0u, SALTS_MEMORY_ACQUIRE, SALTS_MEMORY_RELEASE, &swapped) != SALTS_EINVAL ||
        salts_atomic32_load(&v, SALTS_MEMORY_ACQUIRE, &old32) || old32 != 3u) return 5;
    if (salts_atomic64_init(&big, 0x100000000ull) ||
        salts_atomic64_cas(&big, &expected64, 0u, SALTS_MEMORY_SEQ_CST, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 0 || expected64 != 0x100000000ull) return 6;
    if (salts_atomic64_cas(&big, &expected64, 0x100000002ull, SALTS_MEMORY_SEQ_CST, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 1 || salts_atomic64_fetch_add(&big, 5u, SALTS_MEMORY_RELAXED, &old64) ||
        old64 != 0x100000002ull) return 7;
    if (salts_atomic64_load(&big, SALTS_MEMORY_SEQ_CST, &old64) || old64 != 0x100000007ull) return 8;
    if (salts_atomic64_load((const salts_atomic64 *)(const void *)&bad.bytes[1], SALTS_MEMORY_SEQ_CST, &old64)
        != SALTS_EINVAL) return 9;
    if (salts_atomic_ptr_init(&ptr, &a)) return 10;
    expected_ptr = &c;
    if (salts_atomic_ptr_cas(&ptr, &expected_ptr, &c, SALTS_MEMORY_ACQ_REL, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 0 || expected_ptr != &a) return 11;
    if (salts_atomic_ptr_cas(&ptr, &expected_ptr, &c, SALTS_MEMORY_ACQ_REL, SALTS_MEMORY_ACQUIRE, &swapped) ||
        swapped != 1 || salts_atomic_ptr_load(&ptr, SALTS_MEMORY_ACQUIRE, &got) || got != &c) return 12;
    if (salts_atomic_ptr_exchange(&ptr, &a, SALTS_MEMORY_SEQ_CST, &got) || got != &c) return 13;
    if (salts_atomic_thread_fence(SALTS_MEMORY_SEQ_CST) ||
        salts_atomic_signal_fence(SALTS_MEMORY_ACQUIRE)) return 14;
    return 0;
}
static int saltscore_legacy_entry_test_portable_concurrency_c(void) {
    salts_platform_thread *workers[THREADS] = {0};
    salts_platform_thread *reader = NULL, *detached = NULL;
    uint32_t v32 = 0, done = 0; uint64_t v64 = 0;
    int i, ret, r = basic_atomic();
    if (r) { fprintf(stderr, "portable atomic check failed: %d\n", r); return 10 + r; }
    if (salts_platform_call_once(NULL, once_callback) != SALTS_EINVAL) return 30;
    for (i = 0; i < THREADS; ++i)
        if (salts_platform_thread_create(&workers[i], increment, NULL)) return 31;
    for (i = 0; i < THREADS; ++i)
        if (salts_platform_thread_join(&workers[i], &ret) || workers[i] || ret != 24) return 32;
    if (init_count != 1 || salts_atomic32_load(&total32, SALTS_MEMORY_ACQUIRE, &v32) ||
        salts_atomic64_load(&total64, SALTS_MEMORY_ACQUIRE, &v64) ||
        v32 != THREADS * LOOPS || v64 != THREADS * LOOPS) return 33;
    if (salts_platform_mutex_create(&gate_mutex) ||
        salts_platform_condition_create(&gate_condition)) return 34;
    if (salts_platform_thread_create(&reader, gate_reader, NULL)) return 35;
    if (salts_platform_mutex_lock(gate_mutex)) return 36;
    if (salts_platform_mutex_destroy(&gate_mutex) != SALTS_EBUSY || !gate_mutex) return 37;
    gate_payload = 9123; gate_open = 1;
    if (salts_platform_condition_broadcast(gate_condition) ||
        salts_platform_mutex_unlock(gate_mutex)) return 38;
    if (salts_platform_thread_join(&reader, &ret) || ret != 9123) return 39;
    if (salts_platform_condition_destroy(&gate_condition) || gate_condition ||
        salts_platform_mutex_destroy(&gate_mutex) || gate_mutex) return 40;
    if (salts_platform_thread_create(&detached, detached_worker, NULL) ||
        salts_platform_thread_detach(&detached) || detached) return 41;
    for (i = 0; i < 500000; ++i) {
        if (salts_atomic32_load(&detached_done, SALTS_MEMORY_ACQUIRE, &done)) return 42;
        if (done) break;
        salts_platform_thread_yield();
    }
    if (!done) return 43;
    puts("Salts::Platform portable atomic/thread ABI PASS");
    return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Portable atomic and thread ABI") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_portable_concurrency_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
