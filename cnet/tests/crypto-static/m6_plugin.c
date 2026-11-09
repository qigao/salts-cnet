/* SPDX-License-Identifier: Apache-2.0
 * Module A and B are built separately and link ONLY to the shared CNet
 * candidate. Neither imports nor compiles GmSSL or STATIC Salts::Crypto.
 */
#include "m6_shared_owner.h"
#include <memory/buffer.h>
#include <threads/threads.h>
#include <core/error_codes.h>

#if defined(_WIN32)
#define M6_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define M6_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define M6_PLUGIN_EXPORT
#endif

M6_PLUGIN_EXPORT int m6_plugin_acquire(cnet_m6_lease **lease,
                                       const void **owner, uint64_t *epoch) {
    return cnet_m6_shared_acquire(lease, owner, epoch);
}
M6_PLUGIN_EXPORT int m6_plugin_release(cnet_m6_lease **lease) {
    return cnet_m6_shared_release(lease);
}
M6_PLUGIN_EXPORT int m6_plugin_snapshot(const void **owner, uint32_t *claims,
                                        uint32_t *sessions, uint64_t *epoch) {
    return cnet_m6_shared_snapshot(owner, claims, sessions, epoch);
}
/* Test-only synchronization is forwarded to the same physical CNet DLL;
 * it cannot instantiate a second TLS provider in either plugin module.
 */
M6_PLUGIN_EXPORT int m6_plugin_native_admission_gate(
    uint32_t command, uint32_t *out_admitted) {
    return cnet_m6_test_native_admission_gate(command, out_admitted);
}
M6_PLUGIN_EXPORT int m6_plugin_native_smoke(cnet_m6_lease *lease) {
    return cnet_m6_shared_native_smoke(lease);
}
/* An independent plugin invokes its shared CNet Owner's real TLS test.
 * This module never links or embeds Crypto, GmSSL or CNet source.
 */
M6_PLUGIN_EXPORT int m6_plugin_real_mtls(
    cnet_m6_lease *lease, uint32_t protocol,
    const char *ca, const char *server_cert, const char *server_key,
    const char *client_cert, const char *client_key, int expected_accept) {
    return cnet_m6_shared_native_mtls(
        lease, protocol, ca, server_cert, server_key,
        client_cert, client_key, expected_accept);
}
M6_PLUGIN_EXPORT mem_pool_t *m6_plugin_core_pool(void) {
    return mem_global();
}
M6_PLUGIN_EXPORT const void *m6_plugin_thread_identity(void) {
    return sync_thread_current_token();
}
