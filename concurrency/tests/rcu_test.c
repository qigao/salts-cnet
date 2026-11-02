#include <rcu.h>
#include <thread.h>
#include <clock.h>
#include "tinytest.h"
#include <stdatomic.h>
#include <stdlib.h>

enum { RCU_READERS = 4, RCU_REPLACEMENTS = 2000 };
typedef struct snapshot { unsigned generation; unsigned inverse; } snapshot;
typedef struct stress {
    cmeta_rcu domain;
    atomic_bool stop;
    atomic_uint errors;
    atomic_uint ready;
    atomic_uint observed_generation;
    atomic_uint read_operations;
} stress;

static snapshot *new_snapshot(unsigned generation) {
    snapshot *value = malloc(sizeof(*value));
    if (value != NULL) { value->generation = generation; value->inverse = ~generation; }
    return value;
}
static void stress_reader(void *arg) {
    stress *ctx = arg;
    bool announced = false;
    unsigned consecutive = 0u;
    while (!atomic_load_explicit(&ctx->stop, memory_order_acquire)) {
        cmeta_rcu_guard guard = {0};
        int status = cmeta_rcu_read_lock(&ctx->domain, &guard);
        if (status == SALTS_OK) {
            const snapshot *value = cmeta_rcu_load(&guard);
            if (value == NULL || value->inverse != ~value->generation) {
                atomic_fetch_add_explicit(&ctx->errors, 1u, memory_order_relaxed);
            } else {
                /* Record the highest real generation observed under a pinned
                 * guard. A late reader of an older snapshot must not regress
                 * the writer's observation gate. */
                unsigned seen = atomic_load_explicit(&ctx->observed_generation,
                                                     memory_order_relaxed);
                while (value->generation > seen &&
                       !atomic_compare_exchange_weak_explicit(
                           &ctx->observed_generation, &seen, value->generation,
                           memory_order_release, memory_order_relaxed)) {}
            }
            if (cmeta_rcu_read_unlock(&guard) != SALTS_OK)
                atomic_fetch_add_explicit(&ctx->errors, 1u, memory_order_relaxed);
            atomic_fetch_add_explicit(&ctx->read_operations, 1u, memory_order_relaxed);
            if (!announced) {
                atomic_fetch_add_explicit(&ctx->ready, 1u, memory_order_release);
                announced = true;
            }
            /*
             * Do not continuously reacquire the Windows SRWLOCK without any
             * runnable gap. Four high-frequency readers could otherwise
             * starve the publisher/reclaimer on a constrained ARM64 runner.
             * 31 of 32 consecutive reads remain unpaced real RCU accesses.
             */
            if (++consecutive == 32u) {
                cmeta_sleep_ms(1u);
                consecutive = 0u;
            }
        } else if (status != SALTS_ENOBUFS) {
            atomic_fetch_add_explicit(&ctx->errors, 1u, memory_order_relaxed);
        } else {
            /* Reader-capacity contention is expected and not a reason
             * to monopolize a single-core scheduler. */
            cmeta_thread_yield();
        }
    }
}
typedef struct handoff { cmeta_rcu_guard *guard; const void *seen; int status; } handoff;
static void release_handoff(void *arg) {
    handoff *ctx = arg;
    ctx->seen = cmeta_rcu_load(ctx->guard);
    ctx->status = cmeta_rcu_read_unlock(ctx->guard);
}
typedef struct writer { cmeta_rcu *domain; int replacement; int status; } writer;
static void publish_once(void *arg) {
    writer *ctx = arg;
    ctx->status = cmeta_rcu_replace(ctx->domain, &ctx->replacement);
}

spec("Portable epoch RCU") {
    it("waits for old readers but permits reclamation with new readers active") {
        int first = 1, second = 2, third = 3;
        cmeta_rcu domain = {0};
        cmeta_rcu_guard old = {0}, newer = {0}, extra = {0};
        void *retired = NULL;
        check_equal(cmeta_rcu_init(&domain, &first, 2), SALTS_OK);
        check_equal(cmeta_rcu_read_lock(&domain, &old), SALTS_OK);
        check_equal(cmeta_rcu_replace(&domain, &second), SALTS_OK);
        check_equal(cmeta_rcu_read_lock(&domain, &newer), SALTS_OK);
        check_true(cmeta_rcu_load(&old) == &first);
        check_true(cmeta_rcu_load(&newer) == &second);
        check_equal(cmeta_rcu_read_lock(&domain, &extra), SALTS_ENOBUFS);
        check_equal(cmeta_rcu_replace(&domain, &third), SALTS_EBUSY);
        check_equal(cmeta_rcu_replace(&domain, &first), SALTS_EINVAL);
        check_equal(cmeta_rcu_try_reclaim(&domain, &retired), SALTS_EBUSY);
        check_null(retired);
        check_equal(cmeta_rcu_read_unlock(&old), SALTS_OK);
        check_equal(cmeta_rcu_try_reclaim(&domain, &retired), SALTS_OK);
        check_true(retired == &first);
        check_equal(cmeta_rcu_replace(&domain, &third), SALTS_OK);
        check_equal(cmeta_rcu_try_reclaim(&domain, &retired), SALTS_EBUSY);
        check_equal(cmeta_rcu_close(&domain), SALTS_OK);
        check_equal(cmeta_rcu_read_lock(&domain, &extra), SALTS_ESHUTDOWN);
        check_equal(cmeta_rcu_replace(&domain, NULL), SALTS_ESHUTDOWN);
        check_equal(cmeta_rcu_destroy(&domain, &retired), SALTS_EBUSY);
        check_equal(cmeta_rcu_read_unlock(&newer), SALTS_OK);
        check_equal(cmeta_rcu_try_reclaim(&domain, &retired), SALTS_OK);
        check_true(retired == &second);
        check_equal(cmeta_rcu_destroy(&domain, &retired), SALTS_OK);
        check_true(retired == &third);
        check_equal(cmeta_rcu_destroy(&domain, &retired), SALTS_OK);
        check_null(retired);
    }
    it("rejects copied handles and releases an address-stable guard on another thread") {
        int value = 7;
        cmeta_rcu domain = {0}, copied;
        cmeta_rcu_guard guard = {0}, copy;
        cmeta_thread_t thread = NULL;
        handoff ctx = {&guard, NULL, SALTS_EINVAL};
        void *out = NULL;
        check_equal(cmeta_rcu_init(&domain, &value, 1), SALTS_OK);
        copied = domain;
        check_equal(cmeta_rcu_read_lock(&copied, &guard), SALTS_EINVAL);
        check_equal(cmeta_rcu_read_lock(&domain, &guard), SALTS_OK);
        check_equal(cmeta_rcu_read_lock(&domain, &guard), SALTS_EALREADY);
        copy = guard;
        check_null(cmeta_rcu_load(&copy));
        check_equal(cmeta_rcu_read_unlock(&copy), SALTS_EINVAL);
        check_equal(cmeta_rcu_replace(&domain, NULL), SALTS_OK);
        check_equal(cmeta_rcu_try_reclaim(&domain, &out), SALTS_EBUSY);
        /* Creation/join transfer exclusive access to the original guard.
         * Its frame and domain survive this suspended owner interval. */
        check_equal(cmeta_thread_create(&thread, release_handoff, &ctx), 0);
        if (thread != NULL) check_equal(cmeta_thread_join(&thread), 0);
        check_true(ctx.seen == &value);
        check_equal(ctx.status, SALTS_OK);
        check_equal(cmeta_rcu_read_unlock(&guard), SALTS_EINVAL);
        check_equal(cmeta_rcu_try_reclaim(&domain, &out), SALTS_OK);
        check_true(out == &value);
        check_equal(cmeta_rcu_try_reclaim(&domain, &out), SALTS_ENOENT);
        check_equal(cmeta_rcu_close(&domain), SALTS_OK);
        check_equal(cmeta_rcu_destroy(&domain, &out), SALTS_OK);
    }
    it("publishes immutable heap snapshots to concurrent readers without premature free") {
        stress ctx = {0};
        cmeta_thread_t readers[RCU_READERS] = {0};
        snapshot *initial = new_snapshot(0);
        size_t started = 0;
        unsigned published = 0u;
        uint64_t deadline = cmeta_monotonic_ms() + UINT64_C(60000);
        void *retired = NULL;
        atomic_init(&ctx.stop, false);
        atomic_init(&ctx.errors, 0u);
        atomic_init(&ctx.ready, 0u);
        atomic_init(&ctx.observed_generation, 0u);
        atomic_init(&ctx.read_operations, 0u);
        check_not_null(initial);
        if (initial == NULL) return;
        check_equal(cmeta_rcu_init(&ctx.domain, initial, RCU_READERS), SALTS_OK);
        if (ctx.domain.impl == NULL) { free(initial); return; }
        for (; started < RCU_READERS; ++started) {
            int status = cmeta_thread_create(&readers[started], stress_reader, &ctx);
            check_equal(status, 0);
            if (status != 0) break;
        }
        /* Bound every former unbounded wait. Even on failure, stop/join all
         * live threads before reclaiming or freeing any published snapshot. */
        while (atomic_load_explicit(&ctx.ready, memory_order_acquire) != started &&
               cmeta_monotonic_ms() < deadline)
            cmeta_sleep_ms(1u);
        check_equal(atomic_load_explicit(&ctx.ready, memory_order_acquire), started);
        if (atomic_load_explicit(&ctx.ready, memory_order_acquire) == started) {
            for (unsigned generation = 1u; generation <= RCU_REPLACEMENTS; ++generation) {
                snapshot *replacement = new_snapshot(generation);
                int status;
                check_not_null(replacement);
                if (replacement == NULL) break;
                status = cmeta_rcu_replace(&ctx.domain, replacement);
                check_equal(status, SALTS_OK);
                if (status != SALTS_OK) { free(replacement); break; }
                published = generation;

                /* A real reader must see each new immutable snapshot: the
                 * test cannot pass by merely publishing 2000 unused values. */
                while (atomic_load_explicit(&ctx.observed_generation,
                                            memory_order_acquire) < generation &&
                       cmeta_monotonic_ms() < deadline)
                    cmeta_sleep_ms(1u);
                if (atomic_load_explicit(&ctx.observed_generation,
                                         memory_order_acquire) < generation) {
                    check_true(false); /* bounded observation progress failure */
                    break;
                }

                do {
                    status = cmeta_rcu_try_reclaim(&ctx.domain, &retired);
                    if (status == SALTS_EBUSY) cmeta_sleep_ms(1u);
                } while (status == SALTS_EBUSY && cmeta_monotonic_ms() < deadline);
                check_equal(status, SALTS_OK);
                if (status != SALTS_OK) break;
                free(retired);
                retired = NULL;
            }
        }
        atomic_store_explicit(&ctx.stop, true, memory_order_release);
        for (size_t i = 0; i < started; ++i)
            check_equal(cmeta_thread_join(&readers[i]), 0);

        check_equal(published, (unsigned)RCU_REPLACEMENTS);
        check_equal(atomic_load_explicit(&ctx.observed_generation,
                                         memory_order_acquire), (unsigned)RCU_REPLACEMENTS);
        check_true(atomic_load_explicit(&ctx.read_operations, memory_order_acquire) >=
                   (unsigned)RCU_REPLACEMENTS);
        check_equal(atomic_load_explicit(&ctx.errors, memory_order_acquire), 0u);

        /* A deadline failure can leave one retired snapshot. Readers are now
         * joined, so settle it before close/destroy instead of leaking it. */
        {
            int status = cmeta_rcu_try_reclaim(&ctx.domain, &retired);
            check_true(status == SALTS_ENOENT || status == SALTS_OK);
            if (status == SALTS_OK) { free(retired); retired = NULL; }
        }
        check_equal(cmeta_rcu_close(&ctx.domain), SALTS_OK);
        check_equal(cmeta_rcu_destroy(&ctx.domain, &retired), SALTS_OK);
        free(retired);
    }
    it("serializes concurrent writers with one bounded retired snapshot") {
        int initial = 0;
        cmeta_rcu domain = {0};
        cmeta_thread_t threads[RCU_READERS] = {0};
        writer writers[RCU_READERS];
        size_t started = 0, admitted = 0;
        void *out = NULL, *published = NULL;
        check_equal(cmeta_rcu_init(&domain, &initial, RCU_READERS), SALTS_OK);
        for (; started < RCU_READERS; ++started) {
            writers[started] = (writer){&domain, (int)started + 1, SALTS_EINVAL};
            int status = cmeta_thread_create(&threads[started], publish_once, &writers[started]);
            check_equal(status, 0);
            if (status != 0) break;
        }
        for (size_t i = 0; i < started; ++i) {
            check_equal(cmeta_thread_join(&threads[i]), 0);
            if (writers[i].status == SALTS_OK) { ++admitted; published = &writers[i].replacement; }
            else check_equal(writers[i].status, SALTS_EBUSY);
        }
        check_equal(admitted, (size_t)1);
        check_equal(cmeta_rcu_try_reclaim(&domain, &out), SALTS_OK);
        check_true(out == &initial);
        check_equal(cmeta_rcu_close(&domain), SALTS_OK);
        check_equal(cmeta_rcu_destroy(&domain, &out), SALTS_OK);
        check_true(out == published);
    }
    it("validates admission parameters and distinguishes an empty snapshot") {
        cmeta_rcu domain = {0}; cmeta_rcu_guard guard = {0}; void *out = NULL;
        check_equal(cmeta_rcu_init(NULL, NULL, 1), SALTS_EINVAL);
        check_equal(cmeta_rcu_init(&domain, NULL, 0), SALTS_EINVAL);
        check_equal(cmeta_rcu_read_lock(&domain, &guard), SALTS_EINVAL);
        check_equal(cmeta_rcu_init(&domain, NULL, 1), SALTS_OK);
        check_equal(cmeta_rcu_init(&domain, NULL, 1), SALTS_EALREADY);
        check_equal(cmeta_rcu_read_lock(&domain, &guard), SALTS_OK);
        check_null(cmeta_rcu_load(&guard));
        check_equal(cmeta_rcu_destroy(&domain, &out), SALTS_EBUSY);
        check_equal(cmeta_rcu_read_unlock(&guard), SALTS_OK);
        check_equal(cmeta_rcu_close(&domain), SALTS_OK);
        check_equal(cmeta_rcu_destroy(&domain, &out), SALTS_OK);
        check_null(out);
    }
}
