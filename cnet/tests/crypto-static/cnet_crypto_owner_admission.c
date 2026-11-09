/* SPDX-License-Identifier: Apache-2.0
 * CNet-facing PRIVATE qualification admission: no production TLS cutover.
 */
#include "cnet_crypto_owner_admission.h"
#include "cnet_tls.h" /* canonical private CNet hostname capacity */
#include <crypto/tls_ext.h>
#include <crypto/tls_auth.h>
#include <salts/error_codes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    CNET_CRYPTO_TEST_PATH_LIMIT = 4096u,
    CNET_CRYPTO_TEST_HOST_LIMIT = CNET_TLS_SERVER_NAME_CAPACITY - 1u
};

static bool bounded_nonempty(const char *s, size_t maximum)
{
    size_t i;
    if (s == NULL || !maximum) return false;
    for (i = 0u; i < maximum; ++i)
        if (s[i] == '\0') return i != 0u;
    return false;
}

/* Strictly admit only bounded ASCII DNS names. IP SAN handling and IDNA
 * mapping are outside this candidate. Accept neither literal v4/v6 nor
 * invalid DNS label syntax, so CNet never silently skips host checking.
 */
static bool admissible_dns_identity(const char *name)
{
    size_t i = 0u, label_length = 0u, dots = 0u;
    bool numeric_v4 = true;
    char previous = '\0';
    if (!bounded_nonempty(name, CNET_CRYPTO_TEST_HOST_LIMIT))
        return false;
    for (; name[i] != '\0'; ++i) {
        const unsigned char c = (unsigned char)name[i];
        if (c == (unsigned char)'.') {
            if (!label_length || previous == '-' || label_length > 63u)
                return false;
            label_length = 0u;
            ++dots;
        } else {
            const bool digit = c >= '0' && c <= '9';
            const bool ascii_letter = (c >= 'a' && c <= 'z') ||
                                      (c >= 'A' && c <= 'Z');
            if (!digit) numeric_v4 = false;
            if ((!ascii_letter && !digit && c != '-') ||
                (!label_length && c == '-'))
                return false;
            ++label_length;
            if (label_length > 63u) return false;
        }
        previous = (char)c;
    }
    if (!label_length || previous == '-' || label_length > 63u)
        return false;
    /* Any all-digit dotted identity is conservatively disallowed,
     * including noncanonical IPv4 literals such as 127.000.0.1.
     */
    return !numeric_v4 || dots == 0u;
}

/* Public CNet ALPN is broader. Strictly admit only the existing Crypto
 * bounded printable-text subset; never truncate or silently omit an offer.
 * No output is published until validation succeeds.
 */
static int admit_text_alpn(const char *const *names, size_t count)
{
    size_t wire_bytes = 0u, i, j, k;
    if (count == 0u) return names == NULL ? SALTS_OK : SALTS_EINVAL;
    if (names == NULL) return SALTS_EINVAL;
    if (count > CRYPTO_TLS_ALPN_MAX_PROTOCOLS) return SALTS_ENOTSUP;
    if (crypto_tls_extension_abi_version() != CRYPTO_TLS_EXTENSION_ABI_VERSION)
        return SALTS_ENOTSUP;
    for (i = 0u; i < count; ++i) {
        size_t length = 0u;
        if (names[i] == NULL) return SALTS_EINVAL;
        while (length <= CRYPTO_TLS_ALPN_MAX_NAME_BYTES &&
               names[i][length] != '\0') ++length;
        if (length == 0u) return SALTS_EINVAL;
        if (length > CRYPTO_TLS_ALPN_MAX_NAME_BYTES)
            return SALTS_ENOTSUP;
        if (wire_bytes > 128u - (length + 1u))
            return SALTS_ENOTSUP;
        for (j = 0u; j < length; ++j) {
            const unsigned char c = (unsigned char)names[i][j];
            if (c < 0x21u || c > 0x7eu) return SALTS_ENOTSUP;
        }
        for (k = 0u; k < i; ++k) {
            if (strlen(names[k]) == length &&
                memcmp(names[k], names[i], length) == 0)
                return SALTS_ENOTSUP;
        }
        wire_bytes += length + 1u;
    }
    return SALTS_OK;
}

static int admit_common(uint32_t protocol, size_t capacity,
                        cnet_crypto_owner_use use,
                        crypto_tls_session_options *out)
{
    if (out == NULL) return SALTS_EINVAL;
    /* Never let this test-only API authorize replacing full CNet Owner. */
    if (use != CNET_CRYPTO_OWNER_TEST_ONLY) return SALTS_ENOTSUP;
    if (protocol != CRYPTO_TLS_1_2 && protocol != CRYPTO_TLS_1_3)
        return SALTS_ENOTSUP;
    if (capacity < CRYPTO_TLS_CIPHER_BIO_MIN_CAPACITY ||
        capacity > CRYPTO_TLS_CIPHER_BIO_MAX_CAPACITY)
        return SALTS_ENOTSUP;
    /* Runtime ABI check is required; no provider fallback. */
    if (crypto_tls_abi_version() != CRYPTO_TLS_ABI_VERSION)
        return SALTS_ENOTSUP;
    return SALTS_OK;
}

int cnet_crypto_owner_admit_client(const cnet_tls_client_config *config,
                                   const char *source_identity,
                                   uint32_t exact_protocol,
                                   size_t cipher_capacity,
                                   cnet_crypto_owner_use use,
                                   crypto_tls_session_options *out_options)
{
    crypto_tls_session_options admitted;
    int status = admit_common(exact_protocol, cipher_capacity,
                              use, out_options);
    if (status != SALTS_OK) return status;
    if (config == NULL || config->size != sizeof(*config) ||
        !admissible_dns_identity(source_identity))
        return SALTS_EINVAL;
    if (config->server_name != NULL &&
        (!admissible_dns_identity(config->server_name) ||
         strcmp(config->server_name, source_identity) != 0))
        return SALTS_EINVAL;
    if (config->security_profile != CNET_TLS_SECURITY_PROFILE_STANDARD ||
        config->ca_path != NULL)
        return SALTS_ENOTSUP;
    if ((config->cert_file == NULL) != (config->key_file == NULL))
        return SALTS_EINVAL;
    if (config->key_password != NULL && config->key_file == NULL)
        return SALTS_EINVAL;
    if (config->cert_file != NULL) {
        if (crypto_tls_auth_abi_version() != CRYPTO_TLS_AUTH_ABI_VERSION)
            return SALTS_ENOTSUP;
        if (!bounded_nonempty(config->cert_file, CRYPTO_TLS_AUTH_MAX_PATH_BYTES)
            || !bounded_nonempty(config->key_file, CRYPTO_TLS_AUTH_MAX_PATH_BYTES))
            return SALTS_EINVAL;
        if (config->key_password != NULL &&
            !bounded_nonempty(config->key_password, CRYPTO_TLS_AUTH_MAX_PASSWORD_BYTES))
            return SALTS_EINVAL;
    }
    status = admit_text_alpn(config->alpn_protocols,
                             config->alpn_protocol_count);
    if (status != SALTS_OK) return status;
    /* Public CNet supports implicit OS roots. Crypto currently does NOT.
     * Missing or blank explicit CA is a hard rejection, not a fallback.
     */
    if (config->ca_file == NULL) return SALTS_ENOTSUP;
    if (!bounded_nonempty(config->ca_file,
            config->cert_file != NULL ? CRYPTO_TLS_AUTH_MAX_PATH_BYTES :
                CNET_CRYPTO_TEST_PATH_LIMIT))
        return SALTS_EINVAL;

    memset(&admitted, 0, sizeof(admitted));
    admitted.struct_size = (uint32_t)sizeof(admitted);
    admitted.protocol = exact_protocol;
    admitted.role = CRYPTO_TLS_CLIENT;
    admitted.verify_depth = 4u;
    admitted.hostname = source_identity;
    admitted.ca_file = config->ca_file;
    *out_options = admitted;
    return SALTS_OK;
}

int cnet_crypto_owner_admit_server(const cnet_tls_server_config *config,
                                   uint32_t exact_protocol,
                                   size_t cipher_capacity,
                                   cnet_crypto_owner_use use,
                                   crypto_tls_session_options *out_options)
{
    crypto_tls_session_options admitted;
    int status = admit_common(exact_protocol, cipher_capacity,
                              use, out_options);
    if (status != SALTS_OK) return status;
    if (config == NULL || config->size != sizeof(*config))
        return SALTS_EINVAL;
    if (config->client_auth != CNET_TLS_CLIENT_AUTH_NONE &&
        config->client_auth != CNET_TLS_CLIENT_AUTH_REQUIRED)
        return SALTS_EINVAL;
    if (config->security_profile != CNET_TLS_SECURITY_PROFILE_STANDARD ||
        config->ca_path != NULL)
        return SALTS_ENOTSUP;
    if (config->client_auth == CNET_TLS_CLIENT_AUTH_REQUIRED) {
        if (crypto_tls_auth_abi_version() != CRYPTO_TLS_AUTH_ABI_VERSION)
            return SALTS_ENOTSUP;
        if (config->ca_file == NULL)
            return SALTS_ENOTSUP; /* NEVER downgrade REQUIRED to NONE */
        if (!bounded_nonempty(config->ca_file, CRYPTO_TLS_AUTH_MAX_PATH_BYTES))
            return SALTS_EINVAL;
    } else if (config->ca_file != NULL) {
        return SALTS_ENOTSUP;
    }
    if (config->key_password != NULL &&
        !bounded_nonempty(config->key_password, CRYPTO_TLS_AUTH_MAX_PASSWORD_BYTES))
        return SALTS_EINVAL;
    status = admit_text_alpn(config->alpn_protocols,
                             config->alpn_protocol_count);
    if (status != SALTS_OK) return status;
    if (!bounded_nonempty(config->cert_file,
            config->client_auth == CNET_TLS_CLIENT_AUTH_REQUIRED ?
                CRYPTO_TLS_AUTH_MAX_PATH_BYTES : CNET_CRYPTO_TEST_PATH_LIMIT) ||
        !bounded_nonempty(config->key_file,
            config->client_auth == CNET_TLS_CLIENT_AUTH_REQUIRED ?
                CRYPTO_TLS_AUTH_MAX_PATH_BYTES : CNET_CRYPTO_TEST_PATH_LIMIT))
        return SALTS_EINVAL;

    memset(&admitted, 0, sizeof(admitted));
    admitted.struct_size = (uint32_t)sizeof(admitted);
    admitted.protocol = exact_protocol;
    admitted.role = CRYPTO_TLS_SERVER;
    admitted.verify_depth = 4u;
    admitted.certificate_file = config->cert_file;
    admitted.private_key_file = config->key_file;
    admitted.private_key_password = config->key_password;
    *out_options = admitted;
    return SALTS_OK;
}
