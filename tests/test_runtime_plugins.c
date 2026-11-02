/*
 * Load two CNet consumer plugins independently, unload A with a retained
 * Core buffer outstanding, then release it from B. Repeat to catch stale
 * module-local owner identity after unload/reload.
 */
#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <cmeta_buffer.h>
#include <thread.h>
#include <error_codes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
typedef HMODULE test_module;
static test_module load_module(const char *path) { return LoadLibraryA(path); }
static void *load_symbol(test_module m, const char *name) {
  return (void *)(uintptr_t)GetProcAddress(m, name);
}
static void unload_module(test_module m) { if (m) (void)FreeLibrary(m); }
#else
#  include <dlfcn.h>
typedef void *test_module;
static test_module load_module(const char *path) {
  return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
static void *load_symbol(test_module m, const char *name) {
  return dlsym(m, name);
}
static void unload_module(test_module m) { if (m) (void)dlclose(m); }
#endif

typedef mem_pool_t *(*pool_fn)(void);
typedef const void *(*token_fn)(void);
typedef mem_slice_t (*alloc_fn)(void);
typedef void (*release_fn)(mem_slice_t *);
typedef int (*smoke_fn)(void);

typedef struct plugin {
  test_module module;
  pool_fn pool;
  token_fn token;
  alloc_fn alloc;
  release_fn release;
  smoke_fn smoke;
} plugin;

static int open_plugin(plugin *p, const char *path) {
  p->module = load_module(path);
  if (!p->module) return -1;
  p->pool = (pool_fn)load_symbol(p->module, "saltscore_test_plugin_pool");
  p->token = (token_fn)load_symbol(p->module, "saltscore_test_plugin_thread");
  p->alloc = (alloc_fn)load_symbol(p->module, "saltscore_test_plugin_alloc");
  p->release = (release_fn)load_symbol(p->module, "saltscore_test_plugin_release");
  p->smoke = (smoke_fn)load_symbol(p->module, "saltscore_test_plugin_cnet_smoke");
  return p->pool && p->token && p->alloc && p->release && p->smoke ? 0 : -1;
}
static void close_plugin(plugin *p) {
  unload_module(p->module);
  p->module = NULL;
}

/* Concurrent last-reference release after producer plugin A has unloaded.
 * The B module must remain loaded until all callbacks are quiescent.
 * Each worker owns a distinct slice; no borrowed callback survives unload.
 */
enum { RELEASE_WORKERS = 4 };

typedef struct release_worker_context {
  release_fn release;
  pool_fn pool;
  token_fn token;
  mem_pool_t *expected_pool;
  mem_slice_t slice;
  int success;
} release_worker_context;

static void release_worker(void *opaque) {
  release_worker_context *w = (release_worker_context *)opaque;
  if (w == NULL || w->slice.buffer == NULL ||
      w->pool() != w->expected_pool ||
      w->token() != cmeta_thread_current_token() ||
      mem_global() != w->expected_pool ||
      mem_buffer_pool(w->slice.buffer) != w->expected_pool ||
      w->slice.length != 1u ||
      (unsigned char)w->slice.data[0] != 0x7bu) {
    return;
  }
  w->release(&w->slice);
  w->success = w->slice.buffer == NULL;
}

static int saltscore_original_entry_test_runtime_plugins_c(int argc, char **argv) {
  int result = 0, round;
  mem_pool_t *const pool = mem_global();
  const void *const token = cmeta_thread_current_token();
  if (argc != 3 || !pool || !token) return 1;

  for (round = 0; round != 8; ++round) {
    plugin a = {0}, b = {0};
    mem_slice_t retained = {0};
    release_worker_context workers[RELEASE_WORKERS] = {{0}};
    cmeta_thread_t threads[RELEASE_WORKERS] = {0};
    size_t i, started = 0u;
    int join_failed = 0;

#define VERIFY(e) do { if (!(e)) { \
  fprintf(stderr, "two CNet plugins failure line %d, round %d: %s\n", \
          __LINE__, round, #e); result = __LINE__; goto cleanup; \
} } while (0)
    VERIFY(open_plugin(&a, argv[1]) == 0);
    VERIFY(open_plugin(&b, argv[2]) == 0);
    VERIFY(a.pool() == pool && b.pool() == pool);
    VERIFY(a.token() == token && b.token() == token);
    VERIFY(a.smoke() == SALTS_OK && b.smoke() == SALTS_OK);
    retained = a.alloc();
    VERIFY(retained.buffer != NULL && retained.length == 1u);
    VERIFY(mem_buffer_pool(retained.buffer) == pool);
    VERIFY((unsigned char)retained.data[0] == 0x7bu);
    for (i = 0u; i < RELEASE_WORKERS; ++i) {
      workers[i].slice = a.alloc();
      VERIFY(workers[i].slice.buffer != NULL);
      VERIFY(mem_buffer_pool(workers[i].slice.buffer) == pool);
      workers[i].expected_pool = pool;
      workers[i].pool = b.pool;
      workers[i].token = b.token;
      workers[i].release = b.release;
    }

    /* Plugin A and its direct CNet link are removed while its buffers live.
     * A callback is never invoked during or after its own module's unload. */
    close_plugin(&a);
    VERIFY(mem_global() == pool && b.pool() == pool && b.token() == token);
    VERIFY((unsigned char)retained.data[0] == 0x7bu);
    b.release(&retained);
    VERIFY(retained.buffer == NULL);

    for (i = 0u; i < RELEASE_WORKERS; ++i) {
      VERIFY(cmeta_thread_create(&threads[i], release_worker, &workers[i]) == 0);
      ++started;
    }
    /* Multiple module-B callbacks can now concurrently release distinct
     * references into the one global slab/cache domain. */
    for (i = 0u; i < started; ++i) {
      if (cmeta_thread_join(&threads[i]) != 0) join_failed = 1;
    }
    started = 0u;
    VERIFY(join_failed == 0);
    for (i = 0u; i < RELEASE_WORKERS; ++i) {
      VERIFY(workers[i].success && workers[i].slice.buffer == NULL);
    }
    close_plugin(&b);
    VERIFY(mem_global() == pool && cmeta_thread_current_token() == token);
    continue;

cleanup:
    /* Quiescence is mandatory before unloading plugin B, including on an
     * allocation/thread-creation/test failure. */
    for (i = 0u; i < started; ++i) (void)cmeta_thread_join(&threads[i]);
    for (i = 0u; i < RELEASE_WORKERS; ++i) {
      if (workers[i].slice.buffer) {
        if (b.module && b.release) b.release(&workers[i].slice);
        else mem_slice_release(&workers[i].slice);
      }
    }
    if (retained.buffer) {
      if (b.module && b.release) b.release(&retained);
      else mem_slice_release(&retained);
    }
    close_plugin(&a);
    close_plugin(&b);
    return result;
#undef VERIFY
  }
  return 0;
}

/* Preserve original real peer / module argument delivery and all cleanup.
 * TinyTest owns the process result, while the original integration executes. */
static int saltscore_original_argc;
static char **saltscore_original_argv;

spec("CNet two loadable plugins and retained owner") {
  it("preserves the real native integration and external peer contract") {
    const int result = saltscore_original_entry_test_runtime_plugins_c(saltscore_original_argc, saltscore_original_argv);
    check(result == 0, "native integration returned %d", result);
  }
}

int main(int argc, char **argv) {
  saltscore_original_argc = argc;
  saltscore_original_argv = argv;
  char *runner_argv[] = {argv[0]};
  return ttest_main__(1, runner_argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
