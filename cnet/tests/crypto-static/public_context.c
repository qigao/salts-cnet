/* SPDX-License-Identifier: Apache-2.0
 * Qualification-only CNet public profile glue for the ORIGINAL CNet client
 * and Owner DSO. ALL normal public profile constructors fail closed here:
 * the current opaque Crypto API cannot represent CNet's default protocol
 * range, system trust or optional features without a separate exact-profile
 * admission. Production CNet uses its untouched original implementations.
 */
#include "public_context.h"
#include "cnet_tls_crypto_qualification.h"
#include <salts/error_codes.h>

#include <string.h>

int cnet_tls_client_context_create(
    const cnet_tls_client_config *config, cnet_tls_context **out_context)
{
    if (!out_context) return SALTS_EINVAL;
    *out_context = NULL;
    (void)config;
    return SALTS_ENOTSUP; /* never silently choose TLS 1.2 or skip trust */
}

int cnet_tls_client_init(cnet_tls_client *client,
                         const cnet_tls_client_config *config)
{
    if (!client || !config) return SALTS_EINVAL;
    if (client->impl) return SALTS_EALREADY;
    return SALTS_ENOTSUP;
}

int cnet_tls_server_init(cnet_tls_server *server,
                         const cnet_tls_server_config *config)
{
    if (!server || !config) return SALTS_EINVAL;
    if (server->impl) return SALTS_EALREADY;
    return SALTS_ENOTSUP;
}

int cnet_tls_client_destroy(cnet_tls_client *client)
{
    if (!client) return SALTS_EINVAL;
    if (client->impl) {
        cnet_tls_context_release((cnet_tls_context *)client->impl);
        client->impl = NULL;
    }
    return SALTS_OK;
}

int cnet_tls_server_destroy(cnet_tls_server *server)
{
    if (!server) return SALTS_EINVAL;
    if (server->impl) {
        cnet_tls_context_release((cnet_tls_context *)server->impl);
        server->impl = NULL;
    }
    return SALTS_OK;
}

cnet_tls_context *cnet_tls_client_context(const cnet_tls_client *client)
{
    return client ? (cnet_tls_context *)client->impl : NULL;
}

const char *cnet_tls_client_server_name(const cnet_tls_client *client)
{
    return client && client->impl
        ? cnet_crypto_tls_test_context_server_name(
            (const cnet_tls_context *)client->impl)
        : NULL;
}

cnet_tls_context *cnet_tls_server_context(const cnet_tls_server *server)
{
    return server ? (cnet_tls_context *)server->impl : NULL;
}

int cnet_crypto_test_bind_client(
    cnet_tls_client *client, crypto_tls_provider *provider,
    const cnet_tls_client_config *policy, const char *dns_hostname,
    uint32_t exact_protocol, size_t bio_capacity)
{
    cnet_tls_context *context = NULL;
    int status;
    if (!client || !provider || !policy || !dns_hostname)
        return SALTS_EINVAL;
    if (client->impl) return SALTS_EALREADY;
    status = cnet_crypto_tls_test_client_context(
        provider, policy, dns_hostname, exact_protocol,
        bio_capacity, &context);
    if (status == SALTS_OK) client->impl = context;
    return status;
}

int cnet_crypto_test_bind_server(
    cnet_tls_server *server, crypto_tls_provider *provider,
    const cnet_tls_server_config *policy, uint32_t exact_protocol,
    size_t bio_capacity)
{
    cnet_tls_context *context = NULL;
    int status;
    if (!server || !provider || !policy)
        return SALTS_EINVAL;
    if (server->impl) return SALTS_EALREADY;
    status = cnet_crypto_tls_test_server_context(
        provider, policy, exact_protocol, bio_capacity, &context);
    if (status == SALTS_OK) server->impl = context;
    return status;
}
