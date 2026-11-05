#include "cnet_tls.h"
#include <crypto/tls_stream.h>
#include <error_codes.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#if defined(CNET_TLS_MEMORY_TESTING)
#include "cnet_tls_memory_test.h"
bool cnet_test_tls_memory_snapshot(crypto_tls_test_memory_stats *out) {
  return crypto_tls_stream_test_memory_snapshot(out);
}
#endif
#if defined(CNET_INTERNAL_TESTING)
#include "cnet_test_internal.h"
#include "crypto_tls_stream_test.h"
#endif

struct cnet_tls_context {
  crypto_tls_stream_context *provider;
  atomic_size_t references;
  bool server;
};

static int cnet_tls_status(int status) {
  switch (status) {
    case CRYPTO_TLS_STREAM_OK: return SALTS_OK;
    case CRYPTO_TLS_STREAM_EALREADY: return SALTS_EALREADY;
    case CRYPTO_TLS_STREAM_EBUSY: return SALTS_EBUSY;
    case CRYPTO_TLS_STREAM_ECONNABORTED: return SALTS_ECONNABORTED;
    case CRYPTO_TLS_STREAM_EINVAL: return SALTS_EINVAL;
    case CRYPTO_TLS_STREAM_EIO: return SALTS_EIO;
    case CRYPTO_TLS_STREAM_EMSGSIZE: return SALTS_EMSGSIZE;
    case CRYPTO_TLS_STREAM_ENOBUFS: return SALTS_ENOBUFS;
    case CRYPTO_TLS_STREAM_ENOENT: return SALTS_ENOENT;
    case CRYPTO_TLS_STREAM_ENOMEM: return SALTS_ENOMEM;
    case CRYPTO_TLS_STREAM_ENOTCONN: return SALTS_ENOTCONN;
    case CRYPTO_TLS_STREAM_ENOTSUP: return SALTS_ENOTSUP;
    case CRYPTO_TLS_STREAM_EOF: return SALTS_EOF;
    case CRYPTO_TLS_STREAM_EPROTO: return SALTS_EPROTO;
    case CRYPTO_TLS_STREAM_ERANGE: return SALTS_ERANGE;
    default: return SALTS_EIO;
  }
}

static crypto_tls_stream *cnet_tls_stream(const cnet_tls_state *state) {
  return state != NULL ? (crypto_tls_stream *)state->engine : NULL;
}

int cnet_tls_sm2_crl_peer_policy_create(const cnet_tls_sm2_crl_config *config,
    cnet_tls_peer_policy *out_policy) {
  return cnet_tls_status(crypto_tls_sm2_crl_peer_policy_create(config, out_policy));
}

int cnet_tlcp_sm2_crl_peer_policy_create(const cnet_tls_sm2_crl_config *config,
    cnet_tls_peer_policy *out_policy) {
  return cnet_tls_status(crypto_tlcp_sm2_crl_peer_policy_create(config, out_policy));
}

static int cnet_tls_wrap_context(crypto_tls_stream_context *provider, bool server,
                                  cnet_tls_context **out) {
  cnet_tls_context *context = calloc(1u, sizeof(*context));
  if (context == NULL) {
    crypto_tls_stream_context_release(provider);
    return SALTS_ENOMEM;
  }
  context->provider = provider;
  context->server = server;
  atomic_init(&context->references, 1u);
  *out = context;
  return SALTS_OK;
}

void cnet_tls_context_retain(cnet_tls_context *context) {
  if (context != NULL) atomic_fetch_add_explicit(&context->references, 1u, memory_order_relaxed);
}
void cnet_tls_context_release(cnet_tls_context *context) {
  if (context != NULL && atomic_fetch_sub_explicit(&context->references, 1u, memory_order_acq_rel) == 1u) {
    crypto_tls_stream_context_release(context->provider);
    free(context);
  }
}

int cnet_tls_client_context_create(const cnet_tls_client_config *config, cnet_tls_context **out_context) {
  crypto_tls_stream_client_config policy = {sizeof(policy)};
  crypto_tls_stream_context *provider = NULL;
  int status;
  if (out_context == NULL) return SALTS_EINVAL;
  *out_context = NULL;
  if (config != NULL) {
    if (config->size != sizeof(*config)) return SALTS_EINVAL;
    policy.ca_file = config->ca_file;
    policy.ca_path = config->ca_path;
    policy.cert_file = config->cert_file;
    policy.key_file = config->key_file;
    policy.key_password = config->key_password;
    policy.server_name = config->server_name;
    policy.alpn_protocols = config->alpn_protocols;
    policy.alpn_protocol_count = config->alpn_protocol_count;
    policy.security_profile = (crypto_tls_stream_security_profile)config->security_profile;
    policy.peer_policy = config->peer_policy;
    policy.key_update_record_limit = config->key_update_record_limit;
    policy.peer_key_update_limit = config->peer_key_update_limit;
    policy.ca_data = config->ca_data;
    policy.credentials = config->credentials;
    policy.minimum_version = (crypto_tls_stream_protocol_version)config->minimum_version;
    policy.maximum_version = (crypto_tls_stream_protocol_version)config->maximum_version;
    policy.verification_depth = config->verification_depth;
    policy.cipher_suites = config->cipher_suites;
    policy.cipher_suite_count = config->cipher_suite_count;
    policy.signature_algorithms = config->signature_algorithms;
    policy.signature_algorithm_count = config->signature_algorithm_count;
  }
  status = cnet_tls_status(crypto_tls_stream_client_context_create(&policy, &provider));
  return status == SALTS_OK ? cnet_tls_wrap_context(provider, false, out_context) : status;
}
int cnet_tls_client_init(cnet_tls_client *client,
                         const cnet_tls_client_config *config) {
  cnet_tls_context *context = NULL;
  int status;
  if (client == NULL || config == NULL) return SALTS_EINVAL;
  if (client->impl != NULL) return SALTS_EALREADY;
  status = cnet_tls_client_context_create(config, &context);
  if (status != SALTS_OK) return status;
  client->impl = context;
  return SALTS_OK;
}

int cnet_tls_client_destroy(cnet_tls_client *client) {
  cnet_tls_context *context;
  if (client == NULL) return SALTS_EINVAL;
  context = (cnet_tls_context *)client->impl;
  if (context == NULL) return SALTS_OK;
  client->impl = NULL;
  cnet_tls_context_release(context);
  return SALTS_OK;
}

cnet_tls_context *cnet_tls_client_context(const cnet_tls_client *client) {
  cnet_tls_context *context =
      client != NULL ? (cnet_tls_context *)client->impl : NULL;
  return context != NULL && !context->server ? context : NULL;
}

const char *cnet_tls_client_server_name(const cnet_tls_client *client) {
  const cnet_tls_context *context = cnet_tls_client_context(client);
  return context != NULL ? crypto_tls_stream_context_server_name(context->provider) : NULL;
}

int cnet_tls_server_init(cnet_tls_server *server, const cnet_tls_server_config *config) {
  crypto_tls_stream_server_config policy = {sizeof(policy)};
  crypto_tls_stream_context *provider = NULL;
  cnet_tls_context *context = NULL;
  int status;
  if (server == NULL || config == NULL) return SALTS_EINVAL;
  if (server->impl != NULL) return SALTS_EALREADY;
  if (config->size != sizeof(*config)) return SALTS_EINVAL;
  policy.cert_file = config->cert_file;
  policy.key_file = config->key_file;
  policy.key_password = config->key_password;
  policy.ca_file = config->ca_file;
  policy.ca_path = config->ca_path;
  policy.client_auth = (crypto_tls_stream_client_auth)config->client_auth;
  policy.alpn_protocols = config->alpn_protocols;
  policy.alpn_protocol_count = config->alpn_protocol_count;
  policy.security_profile = (crypto_tls_stream_security_profile)config->security_profile;
  policy.peer_policy = config->peer_policy;
  policy.key_update_record_limit = config->key_update_record_limit;
  policy.peer_key_update_limit = config->peer_key_update_limit;
  policy.ca_data = config->ca_data;
  policy.credentials = config->credentials;
  policy.minimum_version = (crypto_tls_stream_protocol_version)config->minimum_version;
  policy.maximum_version = (crypto_tls_stream_protocol_version)config->maximum_version;
  policy.verification_depth = config->verification_depth;
  policy.cipher_suites = config->cipher_suites;
  policy.cipher_suite_count = config->cipher_suite_count;
  policy.signature_algorithms = config->signature_algorithms;
  policy.signature_algorithm_count = config->signature_algorithm_count;
  status = cnet_tls_status(crypto_tls_stream_server_context_create(&policy, &provider));
  if (status != SALTS_OK) return status;
  status = cnet_tls_wrap_context(provider, true, &context);
  if (status == SALTS_OK) server->impl = context;
  return status;
}

int cnet_tls_server_destroy(cnet_tls_server *server) {
  cnet_tls_context *context;
  if (server == NULL) return SALTS_EINVAL;
  context = (cnet_tls_context *)server->impl;
  if (context == NULL) return SALTS_OK;
  server->impl = NULL;
  cnet_tls_context_release(context);
  return SALTS_OK;
}

cnet_tls_context *cnet_tls_server_context(const cnet_tls_server *server) {
  cnet_tls_context *context =
      server != NULL ? (cnet_tls_context *)server->impl : NULL;
  return context != NULL && context->server ? context : NULL;
}

int cnet_tls_state_init(cnet_tls_state *state, cnet_tls_context *context,
                        bool server, const char *server_name, size_t io_buffer_bytes) {
  crypto_tls_stream *stream = NULL;
  int status;
  if (state == NULL || context == NULL || context->server != server) return SALTS_EINVAL;
  if (state->engine != NULL || state->context != NULL) return SALTS_EALREADY;
  status = cnet_tls_status(crypto_tls_stream_create(context->provider, server, server_name,
                                                   io_buffer_bytes, &stream));
  if (status != SALTS_OK) return status;
  state->engine = stream;
  state->context = context; /* consume caller's CNet reference only on success */
  state->server = server;
  state->io_buffer_bytes = io_buffer_bytes;
  return SALTS_OK;
}

void cnet_tls_state_destroy(cnet_tls_state *state) {
  if (state == NULL) return;
  crypto_tls_stream_destroy(cnet_tls_stream(state));
  cnet_tls_context_release(state->context);
  memset(state, 0, sizeof(*state));
}

int cnet_tls_handshake(cnet_tls_state *state, bool *out_complete) {
  int status = cnet_tls_status(crypto_tls_stream_handshake(cnet_tls_stream(state), out_complete));
  if (status == SALTS_OK) state->handshake_complete = *out_complete;
  return status;
}
bool cnet_tls_state_handshake_complete(const cnet_tls_state *state) {
  return state != NULL && state->handshake_complete;
}
int cnet_tls_state_set_protocol_range(cnet_tls_state *state, cnet_tls_protocol_version minimum,
                                      cnet_tls_protocol_version maximum) {
  return cnet_tls_status(crypto_tls_stream_set_protocol_range(cnet_tls_stream(state),
      (crypto_tls_stream_protocol_version)minimum, (crypto_tls_stream_protocol_version)maximum));
}
int cnet_tls_read(cnet_tls_state *state, void *buffer, size_t capacity,
                  size_t *out_size, bool *out_peer_closed) {
  int status = cnet_tls_status(crypto_tls_stream_read(cnet_tls_stream(state), buffer, capacity, out_size, out_peer_closed));
  if (status == SALTS_OK && *out_peer_closed) state->peer_close_notify = true;
  return status;
}
int cnet_tls_probe_peer_close(cnet_tls_state *state, bool *out_peer_closed, bool *out_plaintext_pending) {
  int status = cnet_tls_status(crypto_tls_stream_probe_peer_close(cnet_tls_stream(state), out_peer_closed, out_plaintext_pending));
  if (status == SALTS_OK && *out_peer_closed) state->peer_close_notify = true;
  return status;
}
int cnet_tls_get_diagnostic(const cnet_tls_state *state, crypto_tls_diagnostic *out) {
  return cnet_tls_status(crypto_tls_stream_get_diagnostic(cnet_tls_stream(state), out));
}
int cnet_tls_shutdown(cnet_tls_state *state, bool *out_notify_generated, bool *out_peer_notify_received) {
  int status = cnet_tls_status(crypto_tls_stream_shutdown(cnet_tls_stream(state), out_notify_generated, out_peer_notify_received));
  if (status == SALTS_OK) {
    state->close_notify_started = *out_notify_generated;
    state->peer_close_notify = *out_peer_notify_received;
  }
  return status;
}

void * cnet_tls_state_read_buffer(cnet_tls_state *state) {
  return crypto_tls_stream_read_buffer(cnet_tls_stream(state));
}

void * cnet_tls_state_write_buffer(cnet_tls_state *state) {
  return crypto_tls_stream_write_buffer(cnet_tls_stream(state));
}

size_t cnet_tls_state_io_buffer_bytes(const cnet_tls_state *state) {
  return crypto_tls_stream_io_buffer_bytes(cnet_tls_stream(state));
}

size_t cnet_tls_cipher_input_capacity(const cnet_tls_state *state) {
  return crypto_tls_stream_cipher_input_capacity(cnet_tls_stream(state));
}

bool cnet_tls_cipher_output_empty(const cnet_tls_state *state) {
  return crypto_tls_stream_cipher_output_empty(cnet_tls_stream(state));
}

int cnet_tls_feed_cipher(cnet_tls_state *state, const void *data, size_t size) {
  return cnet_tls_status(crypto_tls_stream_feed_cipher(cnet_tls_stream(state), data, size));
}

#if defined(CNET_INTERNAL_TESTING)

int cnet_tls_diagnostic_send_stats(const cnet_tls_state *state,
                                   size_t *calls, size_t *requested,
                                   size_t *accepted, size_t *queued) {
  return cnet_tls_status(crypto_tls_stream_diagnostic_send_stats(cnet_tls_stream(state), calls, requested, accepted, queued));
}
#endif

int cnet_tls_take_cipher(cnet_tls_state *state, void *buffer, size_t capacity, size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_take_cipher(cnet_tls_stream(state), buffer, capacity, out_size));
}

int cnet_tls_write(cnet_tls_state *state, const void *data, size_t size, bool *out_complete) {
  return cnet_tls_status(crypto_tls_stream_write(cnet_tls_stream(state), data, size, out_complete));
}

int cnet_tls_get_negotiated_alpn(const cnet_tls_state *state, const unsigned char **out_data,
                                 size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_get_negotiated_alpn(cnet_tls_stream(state), out_data, out_size));
}

int cnet_tls_state_negotiated_version(const cnet_tls_state *state, char *buffer, size_t capacity,
                                      size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_negotiated_version(cnet_tls_stream(state), buffer, capacity, out_size));
}

int cnet_tls_state_negotiated_cipher(const cnet_tls_state *state, char *buffer, size_t capacity,
                                     size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_negotiated_cipher(cnet_tls_stream(state), buffer, capacity, out_size));
}

int cnet_tls_state_peer_certificate_sha256(
    const cnet_tls_state *state,
    char buffer[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY]) {
  return cnet_tls_status(crypto_tls_stream_peer_certificate_sha256(cnet_tls_stream(state), buffer));
}

int cnet_tls_server_end_point_binding_from_certificate(
    const uint8_t *certificate, size_t certificate_size,
    uint8_t *output, size_t capacity, size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_server_end_point_binding_from_certificate(certificate, certificate_size, output, capacity, out_size));
}

int cnet_tls_state_server_end_point_binding(
    const cnet_tls_state *state, uint8_t *output, size_t capacity,
    size_t *out_size) {
  return cnet_tls_status(crypto_tls_stream_server_end_point_binding(cnet_tls_stream(state), output, capacity, out_size));
}

int cnet_tls_state_export_channel_binding(
    const cnet_tls_state *state, uint8_t output[CNET_TLS_CHANNEL_BINDING_BYTES]) {
  return cnet_tls_status(crypto_tls_stream_export_channel_binding(cnet_tls_stream(state), output));
}

static void cnet_tls_copy_chain(const crypto_tls_stream_peer_certificate_chain *source,
                                 cnet_tls_peer_certificate_chain *target) {
  target->count = source->count;
  target->total_bytes = source->total_bytes;
  for (size_t i = 0; i < source->count; ++i) {
    target->certificates[i].data = source->certificates[i].data;
    target->certificates[i].size = source->certificates[i].size;
  }
}
int cnet_tls_peer_certificate_chain_parse(const uint8_t *data, size_t size,
                                          cnet_tls_peer_certificate_chain *out) {
  crypto_tls_stream_peer_certificate_chain chain = {0};
  int status;
  if (out == NULL) return SALTS_EINVAL;
  memset(out, 0, sizeof(*out));
  status = cnet_tls_status(crypto_tls_stream_peer_certificate_chain_parse(data, size, &chain));
  if (status == SALTS_OK) cnet_tls_copy_chain(&chain, out);
  return status;
}
int cnet_tls_state_peer_certificate_chain(const cnet_tls_state *state,
                                          cnet_tls_peer_certificate_chain *out) {
  crypto_tls_stream_peer_certificate_chain chain = {0};
  int status;
  if (out == NULL) return SALTS_EINVAL;
  memset(out, 0, sizeof(*out));
  status = cnet_tls_status(crypto_tls_stream_get_peer_certificate_chain(cnet_tls_stream(state), &chain));
  if (status == SALTS_OK) cnet_tls_copy_chain(&chain, out);
  return status;
}
#if defined(CNET_INTERNAL_TESTING)
int cnet_test_tls_der_bundle_required_size(size_t current, size_t appended, size_t *out_required) {
  return cnet_tls_status(crypto_tls_stream_test_der_bundle_required_size(current, appended, out_required));
}
int cnet_test_tls_receive_record_gate(unsigned phase, const uint8_t *cipher, size_t size, bool *out_ready) {
  return cnet_tls_status(crypto_tls_stream_test_receive_record_gate(phase, cipher, size, out_ready));
}
#endif
