#include <platform_thread.h>
#include <tinytest.h>
#include <stdint.h>
#include <stdio.h>
enum { N=6 };
static salts_platform_tss *key;
static salts_platform_mutex *gate;
static salts_platform_condition *cv;
static int ready, release_all;
static salts_atomic32 dtor_count = {0};
static int values[N] = {10,11,12,13,14,15};
static void destructor(void *p) {
    uint32_t old;
    if (!p) return;
    (void)salts_atomic32_fetch_add(&dtor_count, 1u, SALTS_MEMORY_RELAXED, &old);
}
static int worker(void *opaque) {
    void *v=NULL;
    if (salts_platform_tss_set(key, opaque)) return -1;
    if (salts_platform_tss_get(key,&v) || v != opaque) return -2;
    if (salts_platform_tss_set(key, opaque)) return -3;
    if (salts_platform_mutex_lock(gate)) return -4;
    ++ready;
    if (salts_platform_condition_broadcast(cv)) return -5;
    while (!release_all)
        if (salts_platform_condition_wait(cv, gate)) return -6;
    if (salts_platform_mutex_unlock(gate)) return -7;
    return *(int *)opaque;
}
static int saltscore_legacy_entry_test_portable_tss_c(void) {
    salts_platform_thread *threads[N] = {0};
    uint32_t destructors=0;
    int i, result=0, local=7;
    void *out=(void*)1;
    if (salts_platform_tss_create(NULL,destructor)!=SALTS_EINVAL) return 1;
    if (salts_platform_tss_create(&key,destructor)) return 2;
    if (salts_platform_tss_get(key,&out) || out) return 3;
    if (salts_platform_tss_set(key,&local)) return 4;
    if (salts_platform_tss_destroy(&key)!=SALTS_EBUSY || !key) return 5;
    if (salts_platform_tss_set(key,NULL) || salts_platform_tss_get(key,&out) || out) return 6;
    if (salts_platform_mutex_create(&gate) || salts_platform_condition_create(&cv)) return 7;
    for (i=0;i<N;i++) if (salts_platform_thread_create(&threads[i],worker,&values[i])) return 8;
    if (salts_platform_mutex_lock(gate)) return 9;
    while (ready!=N)
        if (salts_platform_condition_timedwait_ns(cv, gate, 10000000000ull)) return 10;
    if (salts_platform_tss_destroy(&key)!=SALTS_EBUSY || !key) return 11;
    release_all=1;
    if (salts_platform_condition_broadcast(cv) || salts_platform_mutex_unlock(gate)) return 12;
    for (i=0;i<N;i++) {
       if (salts_platform_thread_join(&threads[i],&result) || result!=values[i]) return 13;
    }
    if (salts_atomic32_load(&dtor_count,SALTS_MEMORY_ACQUIRE,&destructors) || destructors!=N) {
       fprintf(stderr,"TSS destructors=%u expected=%d\n",destructors,N);return 14;
    }
    if (salts_platform_tss_destroy(&key) || key ||
        salts_platform_tss_destroy(&key)!=SALTS_EINVAL) return 15;
    if (salts_platform_condition_destroy(&cv) || salts_platform_mutex_destroy(&gate)) return 16;
    puts("portable TSS destructor/owner lifecycle PASS");
    return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Portable TSS ownership and destruction") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_portable_tss_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
