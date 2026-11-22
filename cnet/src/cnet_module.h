#ifndef CNET_MODULE_H
#define CNET_MODULE_H

#include <cnet/export.h>

#include <core/error_codes.h>

/**
 * Initializes process-global CNet dependencies.
 *
 * The application control plane must call this before creating CNet worker
 * threads. Calls are reference counted. Shutdown fails while a resolver is
 * alive, so global c-ares state cannot disappear under a callback.
 */
SALTS_CNET_EXPORT
int cnet_module_init(void);
SALTS_CNET_EXPORT
int cnet_module_shutdown(void);

/** Internal resolver lifetime pins used by the CNet core. */
SALTS_CNET_EXPORT
int cnet_module_acquire_resolver(void);
SALTS_CNET_EXPORT
void cnet_module_release_resolver(void);

#endif /* CNET_MODULE_H */
