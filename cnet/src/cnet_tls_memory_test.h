/* Private bridge to the ONE Crypto implementation inside test-built CNet.
 * Does not expose streams, provider state, plaintext, keys or certificates. */
#ifndef CNET_TLS_MEMORY_TEST_H
#define CNET_TLS_MEMORY_TEST_H

#include <cnet/export.h>
#include "crypto_tls_memory_test.h"
SALTS_CNET_EXPORT
bool cnet_test_tls_memory_snapshot(crypto_tls_test_memory_stats *out);
#endif
