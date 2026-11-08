#include "cnet_monocypher_namespace.h"
#include <cnet/dtls.h>
#include <monocypher.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { DTLS_WORK_BUDGET = 64 };
static atomic_uint_fast64_t dtls_incarnation;
typedef struct input_slot {
  size_t size;
  uint8_t bytes[CRYPTO_DTLS_MAX_DATAGRAM_BYTES];
} input_slot;
typedef struct dtls_impl {
  cnet_dtls *owner;
  cnet_datagram *datagram;
  cnet_datagram_peer peer;
  crypto_dtls_stream *crypto;
  cnet_dtls_observer observer;
  input_slot *input;
  size_t capacity, head, count;
  const uint8_t *wire;
  size_t wire_size;
  uint64_t sequence, wire_tag, application_tag, completed_at;
  size_t application_size;
  uint32_t domain;
  uint64_t binding;
  int error, completed_status;
  bool advancing, in_callback, submitted, completed, application,
      wire_application, stopping;
} dtls_impl;
static int result(int n) {
  switch (n) {
  case SALTS_CRYPTO_OK:
    return SALTS_OK;
  case CRYPTO_DTLS_BUSY:
    return SALTS_EBUSY;
  case SALTS_CRYPTO_EINVAL:
    return SALTS_EINVAL;
  case CRYPTO_DTLS_ENOMEM:
    return SALTS_ENOMEM;
  default:
    return SALTS_EPROTO;
  }
}
static int latch(dtls_impl *d, int n) {
  if (n < 0 && !d->error)
    d->error = n;
  return n;
}
int cnet_dtls_listener_create(const crypto_dtls_listener_config *c,
                              crypto_dtls_listener **out) {
  return result(crypto_dtls_listener_create(c, out));
}
int cnet_dtls_listener_destroy(crypto_dtls_listener *l) {
  return result(crypto_dtls_listener_destroy(l));
}
static bool peer_equal(const cnet_datagram_peer *a,
                       const cnet_datagram_peer *b) {
  if (a->family != b->family || a->port != b->port ||
      a->scope_id != b->scope_id)
    return false;
  return !memcmp(a->address, b->address,
                 a->family == CNET_DATAGRAM_ADDRESS_IPV4 ? 4u : 16u);
}
static void application_done(dtls_impl *d, int status) {
  if (!d->application)
    return;
  const size_t n = d->application_size;
  const uint64_t tag = d->application_tag;
  d->application = false;
  d->application_size = 0;
  d->application_tag = 0;
  d->in_callback = true;
  d->observer.on_send(d->observer.user, d->owner, n, status, tag);
  d->in_callback = false;
}
static int data(void *context, crypto_dtls_stream *stream, const uint8_t *bytes,
                size_t size) {
  dtls_impl *d = context;
  (void)stream;
  const cnet_receive_view view = {bytes, size, CNET_MESSAGE_DATAGRAM};
  d->in_callback = true;
  int n = d->observer.on_receive(d->observer.user, d->owner, &view);
  d->in_callback = false;
  if (n == SALTS_ENOBUFS)
    return CRYPTO_DTLS_BUSY;
  if (n)
    latch(d, n < 0 ? n : SALTS_EPROTO);
  return n;
}
static int validate(cnet_dtls *owner, const cnet_dtls_config *c) {
  if (!owner || !c || !c->datagram || !c->input_slots ||
      c->input_slots > CNET_DTLS_MAX_INPUT_SLOTS || !c->tag_domain ||
      !c->observer.on_receive || !c->observer.on_send || c->security.on_data ||
      c->security.user || !c->peer.port ||
      (c->peer.family != CNET_DATAGRAM_ADDRESS_IPV4 &&
       c->peer.family != CNET_DATAGRAM_ADDRESS_IPV6) ||
      (c->peer.family == CNET_DATAGRAM_ADDRESS_IPV4 && c->peer.scope_id))
    return SALTS_EINVAL;
  if (owner->impl)
    return SALTS_EALREADY;
  uint16_t port;
  int n = cnet_datagram_port(c->datagram, &port);
  return n;
}
static dtls_impl *allocate(cnet_dtls *owner, const cnet_dtls_config *c,
                           int *status) {
  *status = SALTS_ENOMEM;
  dtls_impl *d = calloc(1u, sizeof(*d));
  if (!d)
    return NULL;
  d->input = calloc(c->input_slots, sizeof(*d->input));
  if (!d->input) {
    free(d);
    return NULL;
  }
  d->owner = owner;
  d->datagram = c->datagram;
  d->peer = c->peer;
  d->observer = c->observer;
  d->capacity = c->input_slots;
  d->domain = c->tag_domain;
  d->sequence = 1u;
  uint_fast64_t id =
      atomic_load_explicit(&dtls_incarnation, memory_order_relaxed);
  do {
    if (id == UINT64_MAX) {
      *status = SALTS_ERANGE;
      free(d->input);
      free(d);
      return NULL;
    }
  } while (!atomic_compare_exchange_weak_explicit(&dtls_incarnation, &id,
                                                  id + 1u, memory_order_relaxed,
                                                  memory_order_relaxed));
  d->binding = (uint64_t)id + 1u;
  *status = SALTS_OK;
  return d;
}
static void release_impl(dtls_impl *d) {
  crypto_wipe(d->input, d->capacity * sizeof(*d->input));
  free(d->input);
  crypto_wipe(d, sizeof(*d));
  free(d);
}
int cnet_dtls_init(cnet_dtls *owner, const cnet_dtls_config *c) {
  int n = validate(owner, c);
  if (n)
    return n;
  dtls_impl *d = allocate(owner, c, &n);
  if (!d)
    return n;
  crypto_dtls_stream_config cfg = c->security;
  cfg.on_data = data;
  cfg.user = d;
  n = crypto_dtls_stream_create(&cfg, &d->crypto);
  if (n) {
    release_impl(d);
    return result(n);
  }
  owner->impl = d;
  return SALTS_OK;
}
/* Stable cookie identity, independent of sockaddr padding/host endianness. */
static size_t peer_bytes(const cnet_datagram_peer *p, uint8_t out[23]) {
  if (!p || !p->port ||
      (p->family != CNET_DATAGRAM_ADDRESS_IPV4 &&
       p->family != CNET_DATAGRAM_ADDRESS_IPV6) ||
      (p->family == CNET_DATAGRAM_ADDRESS_IPV4 && p->scope_id))
    return 0u;
  const size_t n = p->family == CNET_DATAGRAM_ADDRESS_IPV4 ? 4u : 16u;
  out[0] = (uint8_t)(n == 4u ? 4u : 6u);
  out[1] = (uint8_t)(p->port >> 8u);
  out[2] = (uint8_t)p->port;
  memcpy(out + 3u, p->address, n);
  if (n == 4u)
    return 7u;
  for (unsigned i = 0; i < 4u; ++i)
    out[19u + i] = (uint8_t)(p->scope_id >> (24u - 8u * i));
  return 23u;
}
static bool overlap(const void *a, size_t an, const void *b, size_t bn) {
  if (!a || !b || !an || !bn)
    return false;
  const uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
  return x <= y ? y - x < an : x - y < bn;
}
int cnet_dtls_cookie_gate(const crypto_dtls_listener *l,
                          const cnet_datagram_peer *peer,
                          const cnet_receive_view *view, uint64_t now,
                          void *reply, size_t capacity, size_t *reply_size,
                          bool *verified) {
  uint8_t address[23];
  const size_t n = peer_bytes(peer, address);
  if (!n || !view || view->kind != CNET_MESSAGE_DATAGRAM || !view->data ||
      view->size > CRYPTO_DTLS_MAX_DATAGRAM_BYTES)
    return SALTS_EINVAL;
  /* Preserve public peer/view metadata if the caller's outputs overlap it. */
  const void *outputs[] = {reply, reply_size, verified};
  const size_t sizes[] = {capacity, sizeof(*reply_size), sizeof(*verified)};
  for (size_t i = 0; i < 3u; ++i)
    if (overlap(outputs[i], sizes[i], peer, sizeof(*peer)) ||
        overlap(outputs[i], sizes[i], view, sizeof(*view)))
      return SALTS_EINVAL;
  int status =
      crypto_dtls_listener_gate(l, address, n, view->data, view->size, now,
                                reply, capacity, reply_size, verified);
  return status == CRYPTO_DTLS_DROP ? SALTS_OK : result(status);
}
int cnet_dtls_accept(cnet_dtls *owner, const cnet_dtls_accept_config *c,
                     const cnet_receive_view *view, uint64_t now) {
  if (!c || !c->listener)
    return SALTS_EINVAL;
  const cnet_dtls_config cfg = {.datagram = c->datagram,
                                .peer = c->peer,
                                .observer = c->observer,
                                .input_slots = c->input_slots,
                                .tag_domain = c->tag_domain};
  int n = validate(owner, &cfg);
  if (n)
    return n;
  uint8_t reply[CRYPTO_DTLS_COOKIE_REPLY_BYTES];
  size_t reply_size;
  bool verified;
  n = cnet_dtls_cookie_gate(c->listener, &c->peer, view, now, reply,
                            sizeof(reply), &reply_size, &verified);
  if (n)
    return n;
  if (!verified)
    return SALTS_EPROTO;
  dtls_impl *d = allocate(owner, &cfg, &n);
  if (!d)
    return n;
  uint8_t address[23];
  size_t address_size = peer_bytes(&c->peer, address);
  n = crypto_dtls_stream_accept(c->listener, address, address_size, view->data,
                                view->size, now, data, d, &d->crypto);
  if (n) {
    release_impl(d);
    return result(n);
  }
  owner->impl = d;
  return SALTS_OK;
}
int cnet_dtls_receive(cnet_dtls *owner, cnet_datagram *datagram,
                      const cnet_datagram_peer *peer,
                      const cnet_receive_view *view, bool *matched) {
  if (!owner || !owner->impl || !peer || !view || !matched)
    return SALTS_EINVAL;
  *matched = false;
  dtls_impl *d = owner->impl;
  if (datagram != d->datagram || !peer_equal(peer, &d->peer))
    return SALTS_OK;
  *matched = true;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  if (d->stopping)
    return SALTS_ESHUTDOWN;
  if (d->error)
    return d->error;
  if (view->kind != CNET_MESSAGE_DATAGRAM || (!view->data && view->size) ||
      view->size > CRYPTO_DTLS_MAX_DATAGRAM_BYTES)
    return SALTS_EINVAL;
  if (d->count == d->capacity)
    return SALTS_ENOBUFS;
  input_slot *s = &d->input[(d->head + d->count) % d->capacity];
  if (view->size)
    memcpy(s->bytes, view->data, view->size);
  s->size = view->size;
  ++d->count;
  return SALTS_OK;
}
int cnet_dtls_send_complete(cnet_dtls *owner, cnet_datagram *datagram,
                            const cnet_datagram_peer *peer, size_t size,
                            int status, uint64_t tag, uint64_t now,
                            bool *matched) {
  if (!owner || !owner->impl || !peer || !matched)
    return SALTS_EINVAL;
  *matched = false;
  dtls_impl *d = owner->impl;
  if (datagram != d->datagram || !d->submitted || tag != d->wire_tag ||
      !peer_equal(peer, &d->peer))
    return SALTS_OK;
  *matched = true;
  if (d->completed)
    return SALTS_EALREADY;
  d->completed = true;
  d->completed_at = now;
  d->completed_status =
      size == d->wire_size && status <= 0 ? status : SALTS_EPROTO;
  return d->completed_status == SALTS_EPROTO ? SALTS_EPROTO : SALTS_OK;
}
static void complete(dtls_impl *d) {
  const int actual = d->completed_status;
  int n =
      crypto_dtls_stream_sent(d->crypto, d->completed_at, actual == SALTS_OK);
  bool application = d->wire_application;
  d->wire = NULL;
  d->wire_size = 0;
  d->submitted = d->completed = d->wire_application = false;
  if (actual < 0)
    latch(d, actual);
  if (n < 0 && !d->stopping)
    latch(d, result(n));
  if (application)
    application_done(d, actual);
}
int cnet_dtls_advance(cnet_dtls *owner, uint64_t now, size_t *events) {
  if (!owner || !owner->impl || !events)
    return SALTS_EINVAL;
  *events = 0;
  dtls_impl *d = owner->impl;
  if (d->advancing || d->in_callback)
    return SALTS_EBUSY;
  d->advancing = true;
  if (d->completed) {
    complete(d);
    ++*events;
  }
  if (d->stopping) {
    d->advancing = false;
    return d->error;
  }
  for (unsigned work = 0; work < DTLS_WORK_BUDGET; ++work) {
    if (d->wire) {
      if (d->submitted)
        break;
      int n = cnet_datagram_send(d->datagram, &d->peer, d->wire, d->wire_size,
                                 d->wire_tag);
      if (n == SALTS_ENOBUFS)
        break;
      if (n) {
        d->completed_status = n;
        d->completed_at = now;
        complete(d);
        ++*events;
        break;
      }
      d->submitted = true;
      ++*events;
      break;
    }
    bool consumed = false;
    if (d->count) {
      input_slot *s = &d->input[d->head];
      int n = crypto_dtls_stream_receive(d->crypto, now, s->bytes, s->size);
      if (n != CRYPTO_DTLS_BUSY) {
        crypto_wipe(s->bytes, s->size);
        s->size = 0;
        d->head = (d->head + 1u) % d->capacity;
        --d->count;
        ++*events;
        consumed = true;
        if (n < 0)
          latch(d, result(n));
      }
    }
    crypto_dtls_stream_info info;
    int n = crypto_dtls_stream_get_info(d->crypto, &info);
    if (n) {
      latch(d, result(n));
      break;
    }
    if (info.state == CRYPTO_DTLS_FAILED)
      latch(d, result(info.error));
    n = crypto_dtls_stream_next(d->crypto, now, &d->wire, &d->wire_size);
    if (n == CRYPTO_DTLS_IDLE || n == CRYPTO_DTLS_BUSY) {
      if (consumed)
        continue;
      break;
    }
    if (n < 0) {
      latch(d, result(n));
      if (d->application)
        application_done(d, d->error);
      break;
    }
    if (d->sequence > UINT32_MAX) {
      latch(d, SALTS_ERANGE);
      (void)crypto_dtls_stream_sent(d->crypto, now, false);
      d->wire = NULL;
      d->wire_size = 0;
      application_done(d, d->error);
      break;
    }
    n = crypto_dtls_stream_get_info(d->crypto, &info);
    if (n) {
      latch(d, result(n));
      break;
    }
    if (info.state == CRYPTO_DTLS_FAILED)
      latch(d, result(info.error));
    d->wire_tag = (uint64_t)d->domain << 32u | d->sequence++;
    d->wire_application = d->application && info.state == CRYPTO_DTLS_READY;
  }
  d->advancing = false;
  return d->error;
}
int cnet_dtls_send(cnet_dtls *owner, const void *bytes, size_t n,
                   uint64_t tag) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  if (d->stopping)
    return SALTS_ESHUTDOWN;
  if (d->error)
    return d->error;
  if (d->application || d->wire)
    return SALTS_EBUSY;
  int status = crypto_dtls_stream_write(d->crypto, bytes, n);
  if (status)
    return result(status);
  d->application = true;
  d->application_tag = tag;
  d->application_size = n;
  return SALTS_OK;
}
int cnet_dtls_close(cnet_dtls *owner) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  if (d->stopping)
    return SALTS_ESHUTDOWN;
  if (d->error)
    return d->error;
  if (d->application || d->wire)
    return SALTS_EBUSY;
  return result(crypto_dtls_stream_close(d->crypto));
}
int cnet_dtls_export(cnet_dtls *owner, const crypto_dtls_export_request *r,
                     void *out, size_t n) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  if (d->stopping)
    return SALTS_ESHUTDOWN;
  if (d->error)
    return d->error;
  return result(crypto_dtls_stream_export(d->crypto, r, out, n));
}
int cnet_dtls_get_info(const cnet_dtls *owner, cnet_dtls_info *out) {
  if (!owner || !owner->impl || !out)
    return SALTS_EINVAL;
  const dtls_impl *d = owner->impl;
  crypto_dtls_stream_info security;
  int n = crypto_dtls_stream_get_info(d->crypto, &security);
  if (n)
    return result(n);
  *out = (cnet_dtls_info){security,
                          d->error,
                          d->count,
                          d->capacity - d->count,
                          d->wire != NULL || d->application,
                          d->stopping};
  out->binding = d->binding;
  return SALTS_OK;
}
int cnet_dtls_hmac(cnet_dtls *owner, const crypto_dtls_export_request *r,
                   const void *data, size_t n, uint8_t out[32]) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  if (d->stopping)
    return SALTS_ESHUTDOWN;
  if (d->error)
    return d->error;
  return result(crypto_dtls_stream_hmac(d->crypto, r, data, n, out));
}
int cnet_dtls_abort(cnet_dtls *owner) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (d->in_callback || d->advancing)
    return SALTS_EBUSY;
  int n = crypto_dtls_stream_abort(d->crypto);
  if (n)
    return result(n);
  d->stopping = true;
  for (size_t i = 0; i < d->capacity; ++i) {
    crypto_wipe(d->input[i].bytes, d->input[i].size);
    d->input[i].size = 0;
  }
  d->count = 0;
  if (d->completed)
    complete(d);
  if (d->wire && !d->submitted) {
    (void)crypto_dtls_stream_sent(d->crypto, 0u, false);
    d->wire = NULL;
    d->wire_size = 0;
    application_done(d, SALTS_ECANCELED);
  }
  if (d->application && !d->wire)
    application_done(d, SALTS_ECANCELED);
  return d->wire ? SALTS_EBUSY : SALTS_OK;
}
int cnet_dtls_destroy(cnet_dtls *owner) {
  if (!owner)
    return SALTS_EINVAL;
  dtls_impl *d = owner->impl;
  if (!d)
    return SALTS_OK;
  if (d->in_callback || d->advancing || d->wire || d->application)
    return SALTS_EBUSY;
  int n = crypto_dtls_stream_destroy(d->crypto);
  if (n)
    return result(n);
  release_impl(d);
  owner->impl = NULL;
  return SALTS_OK;
}
