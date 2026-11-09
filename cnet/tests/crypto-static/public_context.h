/* SPDX-License-Identifier: Apache-2.0
 * PRIVATE test-only context fixture; does not alter public CNet ABI.
 */
#ifndef CNET_CRYPTO_TEST_PUBLIC_CONTEXT_H
#define CNET_CRYPTO_TEST_PUBLIC_CONTEXT_H
#include <cnet/cnet.h>
#include <crypto/tls.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Exact protocol and verified identity mandatory; the context keeps only
 * a borrowed provider reference which must outlive all client/Owner state.
 */
int cnet_crypto_test_bind_client(
    cnet_tls_client *client, crypto_tls_provider *provider,
    const cnet_tls_client_config *policy, const char *dns_hostname,
    uint32_t exact_protocol, size_t bio_capacity);
int cnet_crypto_test_bind_server(
    cnet_tls_server *server, crypto_tls_provider *provider,
    const cnet_tls_server_config *policy, uint32_t exact_protocol,
    size_t bio_capacity);
#ifdef __cplusplus
}
#endif
#endif
