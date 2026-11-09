#include "cnet_module.h"
#include <native_io_socket.h>

#if defined(_WIN32)
// clang-format off
#include <winsock2.h>
// clang-format on
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <ares.h>

#include <stddef.h>
#include <stdint.h>

typedef struct cnet_module_state {
  size_t references;
  size_t resolvers;
} cnet_module_state;

static cnet_module_state cnet_module_global;

/* A dynamically allocated once-initialized sync_mutex_t leaks one heap lock
 * per CNet DSO load/unload: there is no safe final-shutdown destroy while
 * another thread may already be entering init(). Instead use the native
 * process-local static mutex. No allocation, no destructor, no separate
 * mutable pointer owner and no chance to destroy a lock under a waiter.
 * The host must still drain all CNet references before unloading its DSO. */
#if defined(_WIN32)
static SRWLOCK cnet_module_native_lock = SRWLOCK_INIT;
static void cnet_module_lock(void) {
  AcquireSRWLockExclusive(&cnet_module_native_lock);
}
static void cnet_module_unlock(void) {
  ReleaseSRWLockExclusive(&cnet_module_native_lock);
}
#else
static pthread_mutex_t cnet_module_native_lock = PTHREAD_MUTEX_INITIALIZER;
static void cnet_module_lock(void) {
  (void)pthread_mutex_lock(&cnet_module_native_lock);
}
static void cnet_module_unlock(void) {
  (void)pthread_mutex_unlock(&cnet_module_native_lock);
}
#endif

int cnet_module_init(void) {
  int status;

  cnet_module_lock();
  if (cnet_module_global.references != 0u) {
    if (cnet_module_global.references == SIZE_MAX) {
      cnet_module_unlock();
      return SALTS_ERANGE;
    }
    ++cnet_module_global.references;
    cnet_module_unlock();
    return SALTS_OK;
  }

  if (native_io_network_init() != SALTS_OK) {
    cnet_module_unlock();
    return SALTS_EIO;
  }
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    native_io_network_shutdown();
    cnet_module_unlock();
    return status == ARES_ENOMEM ? SALTS_ENOMEM : SALTS_EAI_FAIL;
  }
  if (ares_threadsafety() != ARES_TRUE) {
    ares_library_cleanup();
    native_io_network_shutdown();
    cnet_module_unlock();
    return SALTS_ENOTSUP;
  }

  cnet_module_global.references = 1u;
  cnet_module_unlock();
  return SALTS_OK;
}

int cnet_module_shutdown(void) {
  cnet_module_lock();
  if (cnet_module_global.references == 0u) {
    cnet_module_unlock();
    return SALTS_EINVAL;
  }
  if (cnet_module_global.references == 1u && cnet_module_global.resolvers != 0u) {
    cnet_module_unlock();
    return SALTS_EBUSY;
  }
  --cnet_module_global.references;
  if (cnet_module_global.references == 0u) {
    ares_library_cleanup();
    native_io_network_shutdown();
  }
  cnet_module_unlock();
  return SALTS_OK;
}

int cnet_module_acquire_resolver(void) {
  cnet_module_lock();
  if (cnet_module_global.references == 0u) {
    cnet_module_unlock();
    return SALTS_ESHUTDOWN;
  }
  if (cnet_module_global.resolvers == SIZE_MAX) {
    cnet_module_unlock();
    return SALTS_ERANGE;
  }
  ++cnet_module_global.resolvers;
  cnet_module_unlock();
  return SALTS_OK;
}

void cnet_module_release_resolver(void) {
  cnet_module_lock();
  if (cnet_module_global.resolvers != 0u) --cnet_module_global.resolvers;
  cnet_module_unlock();
}
