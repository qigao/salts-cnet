/* SPDX-License-Identifier: Apache-2.0
 * TEST-ONLY sole physical Crypto Provider for the original shared CNet.
 * The static archive is linked ONLY to this DSO, never to either plugin
 * or the dlopen/LoadLibrary host. No production entry point is changed.
 */
#include "m6_shared_owner.h"
#include "public_context.h"
#include <crypto/tls.h>
#include <crypto/cipher_bio.h>
#include <cnet/cnet.h>
#include <salts/error_codes.h>
#include <threads/threads.h>
#include <salts/clock.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef SDK_CA_FILE
#error SDK_CA_FILE is mandatory for M6 real CNet profile
#endif

struct cnet_m6_lease {
    uint64_t epoch;
    const void *owner;
    /* A module cannot release this lease while one of its CNet Owner
     * operations is active; this counter is protected by owner_lock. */
    uint32_t active_calls;
};
static atomic_flag owner_lock = ATOMIC_FLAG_INIT;
static unsigned char owner_identity;
static crypto_tls_provider *owner_provider;
static uint32_t owner_leases;
static uint32_t owner_active_calls;
static uint64_t owner_epoch;
/* Test-only native admission barrier, never used by production CNet. */
/* C11 static-storage atomics are zero-initialized by the runtime.
 * Do not use MSVC's experimental ATOMIC_VAR_INIT macro here: its expansion
 * is not a constant initializer (C2099) under /experimental:c11atomics.
 */
static atomic_uint m6_gate_armed;
static atomic_uint m6_gate_open;
static atomic_uint m6_gate_admitted;
/* The TLS acceptance function is PRIVATE to the same shared candidate.
 * It is the original M5 two-client, real NativeIO test, but borrows this
 * one Provider instead of constructing and destroying a second Provider.
 */
extern int cnet_m6_original_owner_mtls_case(
    crypto_tls_provider *shared_provider, uint32_t protocol,
    const char *ca, const char *server_cert, const char *server_key,
    const char *client_cert, const char *client_key, bool expect_accept);

/* Two separately loaded plugins must enter their original CNet tests at
 * the same time. The odd/even admission gates are bounded and never retry
 * TLS. This is test-only coordination, not a runtime policy/fallback.
 */
static atomic_uint m6_mtls_arrivals = 0u;


static int lock_owner(void)
{
    unsigned spin;
    for (spin = 0; spin != 200000u; ++spin) {
        if (!atomic_flag_test_and_set_explicit(&owner_lock,
                                                memory_order_acquire))
            return SALTS_OK;
        sync_thread_yield();
    }
    return SALTS_EBUSY;
}
static void unlock_owner(void)
{
    atomic_flag_clear_explicit(&owner_lock, memory_order_release);
}

CNET_M6_API int cnet_m6_shared_acquire(cnet_m6_lease **out_lease,
                                     const void **out_owner,
                                     uint64_t *out_epoch)
{
    cnet_m6_lease *lease;
    int status;
    if (!out_lease || !out_owner || !out_epoch || *out_lease != NULL)
        return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    if (owner_provider == NULL) {
        if (crypto_tls_abi_version() != CRYPTO_TLS_ABI_VERSION ||
            crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION,
                                       &owner_provider) != CRYPTO_TLS_OK) {
            unlock_owner();
            return SALTS_EIO;
        }
        ++owner_epoch;
    }
    if (owner_leases == UINT32_MAX) {
        unlock_owner();
        return SALTS_ENOBUFS;
    }
    lease = (cnet_m6_lease *)calloc(1u, sizeof(*lease));
    if (!lease) {
        /* Leave a freshly opened provider with no claims closed. */
        if (owner_leases == 0u)
            (void)crypto_tls_provider_destroy(&owner_provider);
        unlock_owner();
        return SALTS_ENOMEM;
    }
    lease->owner = &owner_identity;
    lease->epoch = owner_epoch;
    ++owner_leases;
    *out_lease = lease;
    *out_owner = lease->owner;
    *out_epoch = lease->epoch;
    unlock_owner();
    return SALTS_OK;
}

CNET_M6_API int cnet_m6_shared_snapshot(const void **out_owner,
                                      uint32_t *out_leases,
                                      uint32_t *out_sessions,
                                      uint64_t *out_epoch)
{
    int status;
    uint32_t count = 0u;
    if (!out_owner || !out_leases || !out_sessions || !out_epoch)
        return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    if (owner_provider &&
        crypto_tls_provider_session_count(owner_provider, &count) != CRYPTO_TLS_OK) {
        unlock_owner();
        return SALTS_EIO;
    }
    *out_owner = &owner_identity;
    *out_leases = owner_leases;
    *out_sessions = count;
    *out_epoch = owner_epoch;
    unlock_owner();
    return SALTS_OK;
}

/* CNet original M5 Worker calls this only in the private M6 shared
 * candidate, AFTER its own cnet_connect has admitted a real native TLS
 * command and BEFORE its first Owner drive/pump.
 */
int cnet_m6_test_native_admission_wait(void)
{
    const uint64_t deadline = monotonic_ms() + UINT64_C(5000);
    if (!atomic_load_explicit(&m6_gate_armed, memory_order_acquire))
        return SALTS_OK;
    atomic_fetch_add_explicit(&m6_gate_admitted, 1u, memory_order_acq_rel);
    while (!atomic_load_explicit(&m6_gate_open, memory_order_acquire)) {
        if (monotonic_ms() >= deadline)
            return SALTS_ETIMEDOUT;
        sync_thread_yield();
    }
    return SALTS_OK;
}

CNET_M6_API int cnet_m6_test_native_admission_gate(
    uint32_t command, uint32_t *out_admitted)
{
    int status;
    if (!out_admitted || command > 2u) return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    if (command == 1u) {
        if (owner_leases != 2u || owner_active_calls != 0u ||
            atomic_load_explicit(&m6_gate_armed, memory_order_relaxed)) {
            unlock_owner();
            return SALTS_EBUSY;
        }
        atomic_store_explicit(&m6_gate_admitted, 0u, memory_order_relaxed);
        atomic_store_explicit(&m6_gate_open, 0u, memory_order_relaxed);
        atomic_store_explicit(&m6_gate_armed, 1u, memory_order_release);
    } else if (command == 2u) {
        /* On errors the host calls OPEN before joining active workers. */
        atomic_store_explicit(&m6_gate_open, 1u, memory_order_release);
    }
    *out_admitted = atomic_load_explicit(&m6_gate_admitted,
                                         memory_order_acquire);
    unlock_owner();
    return SALTS_OK;
}

CNET_M6_API int cnet_m6_shared_release(cnet_m6_lease **in_out)
{
    int status;
    cnet_m6_lease *lease;
    if (!in_out || !*in_out) return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    lease = *in_out;
    if (lease->owner != &owner_identity || lease->epoch != owner_epoch ||
        !owner_provider || !owner_leases) {
        unlock_owner();
        return SALTS_EINVAL;
    }
    if (lease->active_calls != 0u) {
        /* Another plugin is trying to retire the exact lease currently
         * driving a real CNet NativeIO/TLS operation. Never free it.
         * This is a bounded lifetime ownership contract, not a retry. */
        unlock_owner();
        return SALTS_EBUSY;
    }
    if (owner_leases == 1u &&
        crypto_tls_provider_destroy(&owner_provider) != CRYPTO_TLS_OK) {
        /* In-flight NativeIO/TLS sessions must finish first. Never destroy
         * the owner or mark a lease released while Provider says BUSY. */
        unlock_owner();
        return SALTS_EBUSY;
    }
    --owner_leases;
    *in_out = NULL;
    unlock_owner();
    free(lease);
    return SALTS_OK;
}

CNET_M6_API int cnet_m6_shared_native_smoke(cnet_m6_lease *lease)
{
    cnet_client client = {0};
    cnet_client_config cfg = {0};
    cnet_tls_client tls = {0};
    cnet_tls_client_config policy = {0};
    crypto_tls_provider *provider;
    int status, live = 0;
    if (!lease) return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    if (lease->owner != &owner_identity || lease->epoch != owner_epoch ||
        owner_leases == 0u || owner_provider == NULL) {
        unlock_owner();
        return SALTS_EINVAL;
    }
    if (lease->active_calls != 0u) {
        unlock_owner();
        return SALTS_EBUSY;
    }
    ++lease->active_calls;
    ++owner_active_calls;
    provider = owner_provider;
    unlock_owner();

    policy.size = sizeof(policy);
    policy.security_profile = CNET_TLS_SECURITY_PROFILE_STANDARD;
    policy.ca_file = SDK_CA_FILE;
    policy.server_name = "localhost";
    status = cnet_crypto_test_bind_client(
        &tls, provider, &policy, "localhost", CRYPTO_TLS_1_2,
        CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY);
    if (status != SALTS_OK) goto complete;
#if defined(_WIN32)
    cfg.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
    cfg.backend = NATIVE_IO_BACKEND_KQUEUE;
#else
    cfg.backend = NATIVE_IO_BACKEND_EPOLL;
#endif
    cfg.connection_capacity = 2u;
    cfg.command_capacity = 8u;
    cfg.request_capacity = 8u;
    cfg.completion_batch_capacity = 8u;
    cfg.event_capacity = 8u;
    cfg.max_send_bytes = 1024u;
    cfg.receive_buffer_bytes = 1024u;
    cfg.tls_io_buffer_bytes = CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY;
    /* The original public CNet validator requires TLS buffer and handshake
     * deadline to be supplied together; a half-configured fixture is EINVAL.
     * Keep the real native timeout boundary, never weaken validation.
     */
    cfg.tls_handshake_timeout_ms = 15000u;
    status = cnet_client_init(&client, &cfg);
    if (status != SALTS_OK) goto done;
    live = 1;
    status = cnet_client_stop(&client, 3000u);
    if (status == SALTS_OK)
        status = cnet_client_destroy(&client);
    if (status == SALTS_OK) live = 0;
done:
    if (live) {
        (void)cnet_client_stop(&client, 3000u);
        (void)cnet_client_destroy(&client);
    }
    if (cnet_tls_client_destroy(&tls) != SALTS_OK)
        status = SALTS_EIO;
complete:
    {
        const int lock_status = lock_owner();
        if (lock_status != SALTS_OK) return lock_status;
        if (!lease->active_calls || !owner_active_calls) {
            unlock_owner();
            return SALTS_EIO;
        }
        --lease->active_calls;
        --owner_active_calls;
        unlock_owner();
    }
    return status;
}

CNET_M6_API int cnet_m6_shared_native_mtls(
    cnet_m6_lease *lease, uint32_t protocol,
    const char *ca, const char *server_cert, const char *server_key,
    const char *client_cert, const char *client_key, int expected_accept)
{
    crypto_tls_provider *shared;
    uint32_t crypto_protocol;
    int status;
    unsigned ticket;
    /* Expose only literal test protocol IDs to the plugin/loader.
     * Neither consumer needs Crypto headers, a static Crypto link or a
     * second protocol adapter. The shared DSO alone maps to Crypto ABI.
     */
    crypto_protocol = protocol == 12u ? CRYPTO_TLS_1_2 :
                      protocol == 13u ? CRYPTO_TLS_1_3 : 0u;
    if (!lease || !ca || !server_cert || !server_key ||
        ((client_cert == NULL) != (client_key == NULL)) ||
        crypto_protocol == 0u ||
        (expected_accept != 0 && expected_accept != 1))
        return SALTS_EINVAL;
    status = lock_owner();
    if (status != SALTS_OK) return status;
    if (lease->owner != &owner_identity ||
        lease->epoch != owner_epoch || owner_provider == NULL ||
        owner_leases == 0u) {
        unlock_owner();
        return SALTS_EINVAL;
    }
    /* A release from another plugin must return BUSY throughout the
     * original CNet Owner call, even if OTHER provider leases remain.
     * Never free this lease while its callback/NativeIO path uses it. */
    if (lease->active_calls != 0u) {
        unlock_owner();
        return SALTS_EBUSY;
    }
    ++lease->active_calls;
    ++owner_active_calls;
    shared = owner_provider;
    unlock_owner();

    ticket = atomic_fetch_add_explicit(
        &m6_mtls_arrivals, 1u, memory_order_acq_rel);
    if ((ticket & 1u) == 0u) {
        const uint64_t deadline = monotonic_ms() + UINT64_C(5000);
        while (atomic_load_explicit(&m6_mtls_arrivals,
                                    memory_order_acquire) <= ticket) {
            if (monotonic_ms() >= deadline) {
                status = SALTS_ETIMEDOUT;
                goto complete_mtls;
            }
            sync_thread_yield();
        }
    }
    status = cnet_m6_original_owner_mtls_case(
        shared, crypto_protocol, ca, server_cert, server_key, client_cert,
        client_key, expected_accept != 0);
complete_mtls:
    {
        const int lock_status = lock_owner();
        if (lock_status != SALTS_OK) return lock_status;
        if (!lease->active_calls || !owner_active_calls) {
            unlock_owner();
            return SALTS_EIO;
        }
        --lease->active_calls;
        --owner_active_calls;
        unlock_owner();
    }
    return status;
}
