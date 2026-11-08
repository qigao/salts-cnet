#include "crypto_dtls_client.h"
#include "crypto_dtls_server.h"
#include "crypto_internal.h"
#include "crypto_tls_credentials.h"
#include <crypto/dtls_stream.h>
#include <gmssl/sha2.h>
#include <stdlib.h>
#include <string.h>

struct crypto_dtls_stream {
  union {
    crypto_dtls_client client;
    crypto_dtls_server server;
  };
  crypto_dtls_data_fn on_data;
  void *user;
  uint8_t waiting[CRYPTO_DTLS_MAX_PLAINTEXT],
      ingress[CRYPTO_DTLS_MAX_DATAGRAM_BYTES];
  size_t waiting_size, ingress_size, ingress_offset;
  bool destroying, server_role, in_delivery, data_pending;
};
struct crypto_dtls_listener {
  crypto_dtls_server_context context;
  bool destroying;
};
_Static_assert(CRYPTO_DTLS_MTU == CRYPTO_DTLS_CLIENT_MTU, "shared wire MTU");
_Static_assert(CRYPTO_DTLS_MTU == CRYPTO_DTLS_SERVER_MTU, "shared server MTU");
_Static_assert(CRYPTO_DTLS_MAX_PEER_BYTES == CRYPTO_DTLS_COOKIE_MAX_ADDRESS,
               "shared cookie peer bound");
_Static_assert(CRYPTO_DTLS_MAX_DATAGRAM_BYTES ==
                   CRYPTO_DTLS_MAX_PLAINTEXT + CRYPTO_DTLS_RECORD_OVERHEAD,
               "wire bound");
static int data(void *context, const uint8_t *bytes, size_t size) {
  crypto_dtls_stream *s = context;
  s->in_delivery = true;
  int n = s->on_data(s->user, s, bytes, size);
  s->in_delivery = false;
  if (n == CRYPTO_DTLS_BUSY) {
    if (size)
      memcpy(s->waiting, bytes, size);
    s->waiting_size = size;
    s->data_pending = true;
    return SALTS_CRYPTO_OK;
  }
  return n;
}
static bool failed(const crypto_dtls_stream *s) {
  return s->server_role ? s->server.phase == CRYPTO_DTLS_SERVER_FAILED
                        : s->client.phase == CRYPTO_DTLS_CLIENT_FAILED;
}
static void discard_input(crypto_dtls_stream *s) {
  salts_crypto_secure_zero(s->waiting, sizeof(s->waiting));
  salts_crypto_secure_zero(s->ingress, sizeof(s->ingress));
  s->waiting_size = s->ingress_size = s->ingress_offset = 0u;
  s->data_pending = false;
}
static int receive_record(crypto_dtls_stream *s, uint64_t now, const void *wire,
                          size_t n) {
  return s->server_role ? crypto_dtls_server_receive(&s->server, now, wire, n)
                        : crypto_dtls_client_receive(&s->client, now, wire, n);
}
static int pump_input(crypto_dtls_stream *s, uint64_t now) {
  if (failed(s)) {
    discard_input(s);
    return SALTS_CRYPTO_OK;
  }
  if (s->server_role ? s->server.pending || now < s->server.last_now
                     : s->client.pending || now < s->client.last_now)
    return SALTS_CRYPTO_OK;
  if (s->data_pending) {
    s->in_delivery = true;
    int n = s->on_data(s->user, s, s->waiting, s->waiting_size);
    s->in_delivery = false;
    if (n == CRYPTO_DTLS_BUSY)
      return SALTS_CRYPTO_OK;
    salts_crypto_secure_zero(s->waiting, sizeof(s->waiting));
    s->waiting_size = 0u;
    s->data_pending = false;
    if (n) {
      discard_input(s);
      return s->server_role ? crypto_dtls_server_data_failed(&s->server)
                            : crypto_dtls_client_data_failed(&s->client);
    }
  }
  for (unsigned work = 0;
       work < 64u && s->ingress_offset < s->ingress_size && !s->data_pending;
       ++work) {
    crypto_dtls_record_view record;
    if (!crypto_dtls_wire_record(s->ingress + s->ingress_offset,
                                 s->ingress_size - s->ingress_offset, &record))
      return SALTS_CRYPTO_ESTATE;
    int n = receive_record(s, now, s->ingress + s->ingress_offset,
                           record.record_size);
    if (n == CRYPTO_DTLS_BUSY)
      return SALTS_CRYPTO_OK;
    if (n < 0) {
      discard_input(s);
      return n;
    }
    s->ingress_offset += record.record_size;
  }
  if (s->ingress_offset == s->ingress_size) {
    salts_crypto_secure_zero(s->ingress, sizeof(s->ingress));
    s->ingress_size = s->ingress_offset = 0u;
  }
  return SALTS_CRYPTO_OK;
}
static bool output_alias(const crypto_dtls_stream_config *c,
                         crypto_dtls_stream **out) {
  if (salts_crypto_overlap(c, sizeof(*c), out, sizeof(*out)) ||
      salts_crypto_overlap(out, sizeof(*out), c->roots.data, c->roots.size) ||
      salts_crypto_overlap(out, sizeof(*out), c->server_name,
                           c->server_name_size) ||
      salts_crypto_overlap(out, sizeof(*out), c->alpn, c->alpn_size) ||
      (c->peer_policy && salts_crypto_overlap(out, sizeof(*out), c->peer_policy,
                                              sizeof(*c->peer_policy))))
    return true;
  const crypto_tls_credentials *k = c->credentials;
  if (!k)
    return false;
  if (salts_crypto_overlap(out, sizeof(*out), k, sizeof(*k)))
    return true;
  return salts_crypto_overlap(out, sizeof(*out), k->certificate_chain.data,
                              k->certificate_chain.size) ||
         salts_crypto_overlap(out, sizeof(*out), k->private_key.data,
                              k->private_key.size) ||
         salts_crypto_overlap(out, sizeof(*out), k->encryption_key.data,
                              k->encryption_key.size) ||
         salts_crypto_overlap(out, sizeof(*out), k->private_key_password.data,
                              k->private_key_password.size) ||
         salts_crypto_overlap(out, sizeof(*out),
                              k->encryption_key_password.data,
                              k->encryption_key_password.size);
}
int crypto_dtls_stream_create(const crypto_dtls_stream_config *c,
                              crypto_dtls_stream **out) {
  if (!out)
    return SALTS_CRYPTO_EINVAL;
  if (!c) {
    *out = NULL;
    return SALTS_CRYPTO_EINVAL;
  }
  if (output_alias(c, out))
    return SALTS_CRYPTO_EINVAL;
  *out = NULL;
  if (!c->on_data || !c->roots.data || !c->roots.size ||
      crypto_tls_memory_validate(&c->roots, c->credentials, false) != 0)
    return SALTS_CRYPTO_EINVAL;
  TLS_CTX trust = {0};
  int status = SALTS_CRYPTO_ECRYPTO;
  if (tls_ctx_init(&trust, TLS_protocol_tls12, 1) != 1 ||
      crypto_tls_memory_trust(&trust, &c->roots) != 0)
    goto done;
  crypto_dtls_stream *s = calloc(1u, sizeof(*s));
  if (!s) {
    status = CRYPTO_DTLS_ENOMEM;
    goto done;
  }
  s->on_data = c->on_data;
  s->user = c->user;
  const crypto_dtls_client_config cfg = {trust.cacerts,
                                         trust.cacertslen,
                                         c->server_name,
                                         c->server_name_size,
                                         c->alpn,
                                         c->alpn_size,
                                         c->peer_policy,
                                         data,
                                         s,
                                         c->credentials,
                                         c->enable_exporter};
  status = crypto_dtls_client_init(&s->client, &cfg);
  if (status) {
    salts_crypto_secure_zero(s, sizeof(*s));
    free(s);
  } else
    *out = s;
done:
  tls_ctx_cleanup(&trust);
  salts_crypto_secure_zero(&trust, sizeof(trust));
  return status;
}
int crypto_dtls_stream_next(crypto_dtls_stream *s, uint64_t now,
                            const uint8_t **wire, size_t *n) {
  if (!s || !wire || !n ||
      salts_crypto_overlap(wire, sizeof(*wire), n, sizeof(*n)) ||
      (wire && salts_crypto_overlap(s, sizeof(*s), wire, sizeof(*wire))) ||
      (n && salts_crypto_overlap(s, sizeof(*s), n, sizeof(*n))))
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  int status = pump_input(s, now);
  if (status < 0 && !failed(s))
    return status;
  status = s->server_role ? crypto_dtls_server_next(&s->server, now, wire, n)
                          : crypto_dtls_client_next(&s->client, now, wire, n);
  if (failed(s))
    discard_input(s);
  return status;
}
int crypto_dtls_stream_sent(crypto_dtls_stream *s, uint64_t now, bool success) {
  if (!s)
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  int status = s->server_role
                   ? crypto_dtls_server_sent(&s->server, now, success)
                   : crypto_dtls_client_sent(&s->client, now, success);
  if (failed(s))
    discard_input(s);
  return status;
}
int crypto_dtls_stream_receive(crypto_dtls_stream *s, uint64_t now,
                               const void *wire, size_t n) {
  if (!s || salts_crypto_overlap(s, sizeof(*s), wire, n))
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  const uint64_t last =
      s->server_role ? s->server.last_now : s->client.last_now;
  if (failed(s) || now < last || !wire || !n || n > sizeof(s->ingress)) {
    int status = receive_record(s, now, wire, n);
    if (failed(s))
      discard_input(s);
    return status;
  }
  if (s->data_pending || s->ingress_size)
    return CRYPTO_DTLS_BUSY;
  const uint8_t *p = wire;
  crypto_dtls_record_view record;
  for (size_t at = 0; at < n; at += record.record_size)
    if (!crypto_dtls_wire_record(p + at, n - at, &record))
      return CRYPTO_DTLS_DROP;
  if (!crypto_dtls_wire_record(p, n, &record))
    return CRYPTO_DTLS_DROP;
  int status = receive_record(s, now, p, record.record_size);
  if (status == CRYPTO_DTLS_BUSY)
    return status;
  if (status < 0) {
    if (failed(s))
      discard_input(s);
    return status;
  }
  const size_t tail = n - record.record_size;
  if (tail) {
    memcpy(s->ingress, p + record.record_size, tail);
    s->ingress_size = tail;
    s->ingress_offset = 0u;
  }
  int pumped = s->data_pending ? SALTS_CRYPTO_OK : pump_input(s, now);
  return pumped < 0 ? pumped : tail ? SALTS_CRYPTO_OK : status;
}
int crypto_dtls_stream_write(crypto_dtls_stream *s, const void *bytes,
                             size_t n) {
  if (!s || salts_crypto_overlap(s, sizeof(*s), bytes, n))
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  return s->server_role ? crypto_dtls_server_write(&s->server, bytes, n)
                        : crypto_dtls_client_write(&s->client, bytes, n);
}
int crypto_dtls_stream_close(crypto_dtls_stream *s) {
  if (!s)
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  if (s->data_pending || s->ingress_size)
    return CRYPTO_DTLS_BUSY;
  return s->server_role ? crypto_dtls_server_close(&s->server)
                        : crypto_dtls_client_close(&s->client);
}
int crypto_dtls_stream_export(const crypto_dtls_stream *s,
                              const crypto_dtls_export_request *r, void *out,
                              size_t n) {
  if (!s || !r || salts_crypto_overlap(s, sizeof(*s), r, sizeof(*r)) ||
      salts_crypto_overlap(s, sizeof(*s), out, n) ||
      salts_crypto_overlap(s, sizeof(*s), r->label, r->label_size) ||
      salts_crypto_overlap(s, sizeof(*s), r->context, r->context_size))
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  return s->server_role ? crypto_dtls_server_export(&s->server, r, out, n)
                        : crypto_dtls_client_export(&s->client, r, out, n);
}
int crypto_dtls_stream_get_info(const crypto_dtls_stream *s,
                                crypto_dtls_stream_info *out) {
  if (!s || !out || salts_crypto_overlap(s, sizeof(*s), out, sizeof(*out)))
    return SALTS_CRYPTO_EINVAL;
  if (s->destroying)
    return SALTS_CRYPTO_ESTATE;
  if (s->server_role) {
    const crypto_dtls_server *c = &s->server;
    crypto_dtls_stream_state phase = CRYPTO_DTLS_HANDSHAKING;
    switch (c->phase) {
    case CRYPTO_DTLS_SERVER_READY:
      phase = CRYPTO_DTLS_READY;
      break;
    case CRYPTO_DTLS_SERVER_CLOSING:
      phase = CRYPTO_DTLS_CLOSING;
      break;
    case CRYPTO_DTLS_SERVER_CLOSED:
      phase = CRYPTO_DTLS_CLOSED;
      break;
    case CRYPTO_DTLS_SERVER_FAILED:
      phase = CRYPTO_DTLS_FAILED;
      break;
    default:
      break;
    }
    *out = (crypto_dtls_stream_info){phase,
                                     c->failure,
                                     c->fatal.error,
                                     c->fatal.description,
                                     c->fatal.peer_description,
                                     c->pending};
    out->pending_receive = s->data_pending || s->ingress_size;
    return SALTS_CRYPTO_OK;
  }
  const crypto_dtls_client *c = &s->client;
  crypto_dtls_stream_state phase = CRYPTO_DTLS_HANDSHAKING;
  switch (c->phase) {
  case CRYPTO_DTLS_CLIENT_READY:
    phase = CRYPTO_DTLS_READY;
    break;
  case CRYPTO_DTLS_CLIENT_CLOSING:
    phase = CRYPTO_DTLS_CLOSING;
    break;
  case CRYPTO_DTLS_CLIENT_CLOSED:
    phase = CRYPTO_DTLS_CLOSED;
    break;
  case CRYPTO_DTLS_CLIENT_FAILED:
    phase = CRYPTO_DTLS_FAILED;
    break;
  default:
    break;
  }
  *out = (crypto_dtls_stream_info){phase,
                                   c->failure,
                                   c->fatal.error,
                                   c->fatal.description,
                                   c->fatal.peer_description,
                                   c->pending};
  out->pending_receive = s->data_pending || s->ingress_size;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_stream_hmac(const crypto_dtls_stream *s,
                            const crypto_dtls_export_request *r,
                            const void *data, size_t n, uint8_t out[32]) {
  if (!s || !r || !out || (!data && n) || n > CRYPTO_DTLS_MAC_INPUT_BYTES ||
      salts_crypto_overlap(out, 32u, s, sizeof(*s)) ||
      salts_crypto_overlap(out, 32u, r, sizeof(*r)) ||
      salts_crypto_overlap(out, 32u, r->label, r->label_size) ||
      salts_crypto_overlap(out, 32u, r->context, r->context_size) ||
      salts_crypto_overlap(out, 32u, data, n) ||
      salts_crypto_overlap(s, sizeof(*s), data, n) ||
      (s->server_role && (salts_crypto_overlap(out, 32u, s->server.context,
                                               sizeof(*s->server.context)) ||
                          salts_crypto_overlap(data, n, s->server.context,
                                               sizeof(*s->server.context)))))
    return SALTS_CRYPTO_EINVAL;
  uint8_t key[32] = {0};
  SHA256_HMAC_CTX h = {0};
  int status = crypto_dtls_stream_export(s, r, key, sizeof(key));
  if (!status) {
    sha256_hmac_init(&h, key, sizeof(key));
    sha256_hmac_update(&h, data, n);
    sha256_hmac_finish(&h, out);
  }
  salts_crypto_secure_zero(key, sizeof(key));
  salts_crypto_secure_zero(&h, sizeof(h));
  return status;
}
int crypto_dtls_stream_abort(crypto_dtls_stream *s) {
  if (!s)
    return SALTS_CRYPTO_EINVAL;
  if (s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  int status = s->server_role ? crypto_dtls_server_abort(&s->server)
                              : crypto_dtls_client_abort(&s->client);
  if (!status)
    discard_input(s);
  return status;
}
int crypto_dtls_stream_destroy(crypto_dtls_stream *s) {
  if (!s)
    return SALTS_CRYPTO_OK;
  if (s->destroying || s->in_delivery)
    return SALTS_CRYPTO_ESTATE;
  s->destroying = true;
  int status = s->server_role ? crypto_dtls_server_clear(&s->server)
                              : crypto_dtls_client_clear(&s->client);
  if (status) {
    s->destroying = false;
    return status;
  }
  salts_crypto_secure_zero(s, sizeof(*s));
  free(s);
  return SALTS_CRYPTO_OK;
}

int crypto_dtls_listener_create(const crypto_dtls_listener_config *c,
                                crypto_dtls_listener **out) {
  if (!out)
    return SALTS_CRYPTO_EINVAL;
  if (!c) {
    *out = NULL;
    return SALTS_CRYPTO_EINVAL;
  }
  const crypto_dtls_stream_config inputs = {
      .roots = c->client_roots ? *c->client_roots : (crypto_tls_data){0},
      .server_name = c->server_name,
      .server_name_size = c->server_name_size,
      .alpn = c->alpn,
      .alpn_size = c->alpn_size,
      .credentials = c->credentials,
      .peer_policy = c->peer_policy};
  if (salts_crypto_overlap(c, sizeof(*c), out, sizeof(*out)) ||
      (c->client_roots &&
       salts_crypto_overlap(c->client_roots, sizeof(*c->client_roots), out,
                            sizeof(*out))) ||
      output_alias(&inputs, (crypto_dtls_stream **)out))
    return SALTS_CRYPTO_EINVAL;
  *out = NULL;
  crypto_dtls_listener *l = calloc(1u, sizeof(*l));
  if (!l)
    return CRYPTO_DTLS_ENOMEM;
  const crypto_dtls_server_config cfg = {
      c->credentials,    c->client_roots,       c->peer_policy,
      c->server_name,    c->server_name_size,   c->alpn,
      c->alpn_size,      c->cookie_lifetime_ms, c->require_client_certificate,
      c->enable_exporter};
  int n = crypto_dtls_server_context_init(&l->context, &cfg);
  if (n) {
    salts_crypto_secure_zero(l, sizeof(*l));
    free(l);
    return n;
  }
  *out = l;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_listener_destroy(crypto_dtls_listener *l) {
  if (!l)
    return SALTS_CRYPTO_OK;
  if (l->destroying)
    return SALTS_CRYPTO_ESTATE;
  l->destroying = true;
  int n = crypto_dtls_server_context_clear(&l->context);
  if (n) {
    l->destroying = false;
    return n;
  }
  salts_crypto_secure_zero(l, sizeof(*l));
  free(l);
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_listener_gate(const crypto_dtls_listener *l, const void *peer,
                              size_t peer_size, const void *wire, size_t n,
                              uint64_t now, void *reply, size_t capacity,
                              size_t *reply_size, bool *verified) {
  if (!l || !peer || !wire || !reply || !reply_size || !verified ||
      !peer_size || peer_size > CRYPTO_DTLS_MAX_PEER_BYTES ||
      capacity < CRYPTO_DTLS_COOKIE_REPLY_BYTES)
    return SALTS_CRYPTO_EINVAL;
  if (salts_crypto_overlap(l, sizeof(*l), peer, peer_size) ||
      salts_crypto_overlap(l, sizeof(*l), wire, n))
    return SALTS_CRYPTO_EINVAL;
  const void *outputs[] = {reply, reply_size, verified};
  const size_t widths[] = {capacity, sizeof(*reply_size), sizeof(*verified)};
  const void *inputs[] = {l, peer, wire};
  const size_t sizes[] = {sizeof(*l), peer_size, n};
  for (size_t i = 0; i < 3u; ++i) {
    for (size_t j = 0; j < 3u; ++j)
      if (salts_crypto_overlap(outputs[i], widths[i], inputs[j], sizes[j]))
        return SALTS_CRYPTO_EINVAL;
    for (size_t j = 0; j < i; ++j)
      if (salts_crypto_overlap(outputs[i], widths[i], outputs[j], widths[j]))
        return SALTS_CRYPTO_EINVAL;
  }
  *reply_size = 0u;
  *verified = false;
  if (l->destroying)
    return SALTS_CRYPTO_ESTATE;
  crypto_dtls_cookie_result result = {0};
  int status =
      crypto_dtls_cookie_gate(&l->context.cookie, peer, peer_size, wire, n, now,
                              reply, capacity, reply_size, &result);
  if (!status)
    *verified = result.address_verified;
  return status == SALTS_CRYPTO_EVERIFY ? CRYPTO_DTLS_DROP : status;
}
int crypto_dtls_stream_accept(crypto_dtls_listener *l, const void *peer,
                              size_t peer_size, const void *wire, size_t n,
                              uint64_t now, crypto_dtls_data_fn on_data,
                              void *user, crypto_dtls_stream **out) {
  if (!out)
    return SALTS_CRYPTO_EINVAL;
  if ((l && salts_crypto_overlap(l, sizeof(*l), out, sizeof(*out))) ||
      salts_crypto_overlap(peer, peer_size, out, sizeof(*out)) ||
      salts_crypto_overlap(wire, n, out, sizeof(*out)))
    return SALTS_CRYPTO_EINVAL;
  *out = NULL;
  if (!on_data)
    return SALTS_CRYPTO_EINVAL;
  uint8_t reply[CRYPTO_DTLS_COOKIE_REPLY_BYTES];
  size_t reply_size;
  bool verified;
  int status =
      crypto_dtls_listener_gate(l, peer, peer_size, wire, n, now, reply,
                                sizeof(reply), &reply_size, &verified);
  salts_crypto_secure_zero(reply, sizeof(reply));
  if (status)
    return status;
  if (!verified)
    return CRYPTO_DTLS_DROP;
  crypto_dtls_stream *s = calloc(1u, sizeof(*s));
  if (!s)
    return CRYPTO_DTLS_ENOMEM;
  s->server_role = true;
  s->on_data = on_data;
  s->user = user;
  status = crypto_dtls_server_accept(&s->server, &l->context, peer, peer_size,
                                     wire, n, now, data, s);
  if (status && !s->server.context) {
    salts_crypto_secure_zero(s, sizeof(*s));
    free(s);
    return status;
  }
  /* Admission acquired a lease. Publish even a protocol rejection so the host
   * can drain its sealed fatal; get_info owns handshake success/failure truth.
   */
  *out = s;
  return SALTS_CRYPTO_OK;
}
