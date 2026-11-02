/* Source-compatible, EXPLICITLY OPT-IN C11 threads.h client.
 * Compiles with TinyCC/MSVC/Clang and makes no native _Atomic assumptions.
 */
#include <tinytest.h>
#include <threads.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

enum { WORKERS=4, LOOPS=1200 };
static mtx_t gate;
static cnd_t ready_condition;
static int go;
static once_flag once = ONCE_FLAG_INIT;
static int once_count;
static salts_atomic32 finished = {0};
static salts_atomic32 increments = {0};

static void SALTS_CORE_PLATFORM_CALL initialize_once(void) { ++once_count; }
static int SALTS_CORE_PLATFORM_CALL worker(void *arg) {
    uintptr_t index = (uintptr_t)arg;
    unsigned i;
    uint32_t previous;
    thrd_t me = thrd_current();
    if (!me || !thrd_equal(me,thrd_current())) return -1;
    call_once(&once,initialize_once);
    if (mtx_lock(&gate) != thrd_success) return -2;
    while (!go)
        if (cnd_wait(&ready_condition,&gate) != thrd_success) return -3;
    if (mtx_unlock(&gate) != thrd_success) return -4;
    for (i=0;i<LOOPS;i++)
        if (salts_atomic32_fetch_add(&increments,1u,SALTS_MEMORY_RELAXED,&previous))
            return -5;
    return (int)(index+17u);
}
static int SALTS_CORE_PLATFORM_CALL early(void *arg) {
    (void)arg;
    thrd_exit(81);
    return -1;
}
static int SALTS_CORE_PLATFORM_CALL detached(void *arg) {
    (void)arg;
    if (salts_atomic32_store(&finished,1u,SALTS_MEMORY_RELEASE)) return -1;
    return 0;
}
static int saltscore_legacy_entry_test_c11_threads_c(void) {
    thrd_t threads[WORKERS], one, loose;
    uint32_t count=0, done=0;
    struct timespec expired={0,0};
    struct timespec sleep_time={0,2000000L}, remaining={0,0};
    struct timespec deadline;
    int i, result;
    if (mtx_init(&gate,mtx_recursive) != thrd_error) return 1;
    if (mtx_init(&gate,mtx_timed) || cnd_init(&ready_condition)) return 2;
    if (mtx_lock(&gate)) return 3;
    if (mtx_trylock(&gate) != thrd_busy) return 4;
    if (mtx_timedlock(&gate,&expired) != thrd_timedout) return 5;
    if (cnd_timedwait(&ready_condition,&gate,&expired) != thrd_timedout) return 6;
    if (mtx_unlock(&gate)) return 7;
    if (mtx_trylock(&gate) || mtx_unlock(&gate)) return 8;
    deadline.tv_sec=time(NULL)+3;
    deadline.tv_nsec=0;
    if (mtx_timedlock(&gate,&deadline) || mtx_unlock(&gate)) return 9;
    for (i=0;i<WORKERS;i++) {
        int j;
        threads[i]=NULL;
        if (thrd_create(&threads[i],worker,(void *)(uintptr_t)i)) return 10;
        if (thrd_equal(threads[i], thrd_current())) return 22;
        for (j=0; j<i; j++)
            if (thrd_equal(threads[i],threads[j])) return 23;
    }
    if (mtx_lock(&gate)) return 11;
    go=1;
    if (cnd_broadcast(&ready_condition) || mtx_unlock(&gate)) return 12;
    for (i=0;i<WORKERS;i++) {
        if (thrd_join(threads[i],&result) || result!=i+17) return 13;
    }
    if (once_count!=1 || salts_atomic32_load(&increments,SALTS_MEMORY_ACQUIRE,&count) ||
        count != WORKERS*LOOPS) return 14;
    if (thrd_create(&one,early,NULL)) return 15;
    if (thrd_join(one,&result) || result!=81) return 16;
    if (thrd_create(&loose,detached,NULL) || thrd_detach(loose)) return 17;
    for (i=0;i<200000;i++) {
        if (salts_atomic32_load(&finished,SALTS_MEMORY_ACQUIRE,&done)) return 18;
        if (done) break;
        thrd_yield();
    }
    if (!done) return 19;
    if (thrd_sleep(&sleep_time,&remaining) || remaining.tv_sec || remaining.tv_nsec) return 20;
    if (thrd_sleep(NULL,&remaining) != -1) return 21;
    cnd_destroy(&ready_condition);
    mtx_destroy(&gate);
    puts("experimental C11 threads: join/detach/early-exit/current/equal/mutex/condition/once PASS");
    return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("C11 native thread synchronization") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_c11_threads_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
