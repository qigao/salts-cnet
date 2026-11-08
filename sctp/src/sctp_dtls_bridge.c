#include <cnet/sctp_dtls.h>
#include <stdlib.h>
#include <string.h>

enum { INPUT_MAX = 64, WORK_MAX = 64 };
typedef struct packet_slot {
  size_t size;
  uint8_t bytes[CNET_SCTP_SESSION_MAX_PACKET_BYTES];
} packet_slot;
typedef struct bridge {
  cnet_dtls *transport;
  cnet_sctp_session *session;
  packet_slot *input;
  size_t capacity, head, count, written;
  uint8_t output[CRYPTO_DTLS_MAX_APPLICATION_BYTES];
  uint64_t binding, sequence, tag;
  uint32_t domain;
  int error;
  bool reserved, pending, submitted, advancing, stopping;
} bridge;
static int map(cnet_sctp_session_status s) {
  switch (s) {
  case CNET_SCTP_SESSION_OK:
  case CNET_SCTP_SESSION_EMPTY:
    return SALTS_OK;
  case CNET_SCTP_SESSION_INVALID:
    return SALTS_EINVAL;
  case CNET_SCTP_SESSION_CAPACITY:
    return SALTS_ENOBUFS;
  case CNET_SCTP_SESSION_BUSY:
    return SALTS_EBUSY;
  case CNET_SCTP_SESSION_OWNER:
    return SALTS_EPERM;
  case CNET_SCTP_SESSION_STALE:
    return SALTS_EPROTO;
  case CNET_SCTP_SESSION_CLOSED:
    return SALTS_ESHUTDOWN;
  default:
    return SALTS_EPROTO;
  }
}
static int latch(bridge *b, int n) {
  if (n < 0 && !b->error)
    b->error = n;
  return n;
}
static bool overlap(const void *a, size_t an, const void *p, size_t pn) {
  if (!a || !p || !an || !pn)
    return false;
  uintptr_t x = (uintptr_t)a, y = (uintptr_t)p;
  return x <= y ? y - x < an : x - y < pn;
}
static int guard(bridge *b) {
  if (b->error)
    return b->error;
  if (b->stopping)
    return SALTS_ESHUTDOWN;
  uint64_t binding;
  int n = map(cnet_sctp_session_get_peer_binding(b->session, &binding));
  if (n)
    return n == SALTS_EPERM ? n : latch(b, n);
  cnet_dtls_info info;
  n = cnet_dtls_get_info(b->transport, &info);
  if (n)
    return latch(b, n);
  if (binding != b->binding || info.binding != b->binding)
    return latch(b, SALTS_EPROTO);
  if (info.security.state != CRYPTO_DTLS_READY || info.stopping)
    return latch(b, info.error ? info.error : SALTS_ESHUTDOWN);
  return SALTS_OK;
}
int cnet_sctp_dtls_init(cnet_sctp_dtls *owner, const cnet_sctp_dtls_config *c) {
  if (!owner || !c || !c->transport || !c->session || !c->input_slots ||
      c->input_slots > INPUT_MAX || !c->tag_domain)
    return SALTS_EINVAL;
  if (owner->impl)
    return SALTS_EALREADY;
  uint64_t binding;
  int n = map(cnet_sctp_session_get_peer_binding(c->session, &binding));
  if (n)
    return n;
  cnet_dtls_info info;
  n = cnet_dtls_get_info(c->transport, &info);
  if (n)
    return n;
  if (binding != info.binding || !binding)
    return SALTS_EINVAL;
  if (info.security.state != CRYPTO_DTLS_READY || info.stopping)
    return SALTS_EPROTO;
  bridge *b = calloc(1u, sizeof(*b));
  if (!b)
    return SALTS_ENOMEM;
  b->input = calloc(c->input_slots, sizeof(*b->input));
  if (!b->input) {
    free(b);
    return SALTS_ENOMEM;
  }
  b->transport = c->transport;
  b->session = c->session;
  b->capacity = c->input_slots;
  b->binding = binding;
  b->domain = c->tag_domain;
  b->sequence = 1u;
  owner->impl = b;
  return SALTS_OK;
}
int cnet_sctp_dtls_receive(cnet_sctp_dtls *owner, cnet_dtls *transport,
                           const cnet_receive_view *v) {
  if (!owner || !owner->impl || !v || !v->data ||
      v->kind != CNET_MESSAGE_DATAGRAM || !v->size ||
      v->size > CNET_SCTP_SESSION_MAX_PACKET_BYTES)
    return SALTS_EINVAL;
  bridge *b = owner->impl;
  if (transport != b->transport)
    return SALTS_EINVAL;
  if (b->reserved || b->advancing)
    return SALTS_EBUSY;
  if (b->stopping)
    return SALTS_ESHUTDOWN;
  if (b->error)
    return b->error;
  if (b->count == b->capacity)
    return SALTS_ENOBUFS;
  packet_slot *p = &b->input[(b->head + b->count) % b->capacity];
  memcpy(p->bytes, v->data, v->size);
  p->size = v->size;
  ++b->count;
  return SALTS_OK;
}
int cnet_sctp_dtls_send_complete(cnet_sctp_dtls *owner, cnet_dtls *transport,
                                 size_t size, int status, uint64_t tag,
                                 bool *matched) {
  if (!owner || !owner->impl || !matched)
    return SALTS_EINVAL;
  *matched = false;
  bridge *b = owner->impl;
  if (transport != b->transport || !b->submitted || tag != b->tag)
    return SALTS_OK;
  const size_t expected = b->written;
  *matched = true;
  if (status > 0 || size != expected)
    return latch(b, SALTS_EPROTO);
  b->submitted = b->pending = false;
  b->written = 0u;
  return status < 0 ? latch(b, status) : SALTS_OK;
}
int cnet_sctp_dtls_reserve(cnet_sctp_dtls *owner, void **packet,
                           size_t *capacity) {
  if (!owner || !owner->impl || !packet || !capacity)
    return SALTS_EINVAL;
  bridge *b = owner->impl;
  if (overlap(packet, sizeof(*packet), owner, sizeof(*owner)) ||
      overlap(capacity, sizeof(*capacity), owner, sizeof(*owner)) ||
      overlap(packet, sizeof(*packet), b, sizeof(*b)) ||
      overlap(capacity, sizeof(*capacity), b, sizeof(*b)) ||
      overlap(packet, sizeof(*packet), capacity, sizeof(*capacity)))
    return SALTS_EINVAL;
  *packet = NULL;
  *capacity = 0u;
  if (b->reserved || b->advancing)
    return SALTS_EBUSY;
  int n = guard(b);
  if (n)
    return n;
  if (b->pending)
    return SALTS_ENOBUFS;
  if (b->sequence > UINT32_MAX)
    return latch(b, SALTS_ERANGE);
  b->reserved = true;
  *packet = b->output;
  *capacity = sizeof(b->output);
  return SALTS_OK;
}
static int committed(bridge *b, cnet_sctp_session_status status,
                     size_t written) {
  if (status != CNET_SCTP_SESSION_OK) {
    if (written)
      return latch(b, SALTS_EPROTO);
    int n = map(status);
    return n;
  }
  if (written > sizeof(b->output))
    return latch(b, SALTS_EPROTO);
  if (!written)
    return SALTS_OK;
  if (b->sequence > UINT32_MAX)
    return latch(b, SALTS_ERANGE);
  b->tag = (uint64_t)b->domain << 32u | b->sequence++;
  b->written = written;
  b->pending = true;
  return SALTS_OK;
}
int cnet_sctp_dtls_commit(cnet_sctp_dtls *owner,
                          cnet_sctp_session_status status, size_t written) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  bridge *b = owner->impl;
  if (!b->reserved)
    return SALTS_EINVAL;
  b->reserved = false;
  return committed(b, status, written);
}
int cnet_sctp_dtls_advance(cnet_sctp_dtls *owner, uint64_t now,
                           size_t *events) {
  if (!owner || !owner->impl || !events)
    return SALTS_EINVAL;
  *events = 0u;
  bridge *b = owner->impl;
  if (b->advancing || b->reserved)
    return SALTS_EBUSY;
  int n = guard(b);
  if (n)
    return n;
  b->advancing = true;
  for (unsigned work = 0; work < WORK_MAX; ++work) {
    if (b->pending) {
      if (!b->submitted) {
        n = cnet_dtls_send(b->transport, b->output, b->written, b->tag);
        if (n == SALTS_EBUSY || n == SALTS_ENOBUFS) {
          n = SALTS_OK;
          break;
        }
        if (n) {
          latch(b, n);
          break;
        }
        b->submitted = true;
        ++*events;
      }
      break;
    }
    if (b->sequence > UINT32_MAX) {
      n = latch(b, SALTS_ERANGE);
      break;
    }
    size_t written = 0u;
    cnet_sctp_session_status s;
    if (b->count) {
      packet_slot *p = &b->input[b->head];
      s = cnet_sctp_session_input(b->session, now, p->bytes, p->size, b->output,
                                  sizeof(b->output), &written);
      if (s == CNET_SCTP_SESSION_OK) {
        memset(p, 0, sizeof(*p));
        b->head = (b->head + 1u) % b->capacity;
        --b->count;
        ++*events;
      }
    } else {
      s = cnet_sctp_session_advance(b->session, now, b->output,
                                    sizeof(b->output), &written);
      if ((s == CNET_SCTP_SESSION_OK || s == CNET_SCTP_SESSION_EMPTY) &&
          !written) {
        int ready = 0;
        s = cnet_sctp_session_data_ready(b->session, &ready);
        if (!s)
          s = ready
                  ? cnet_sctp_session_pump_message(b->session, now, b->output,
                                                   sizeof(b->output), &written)
                  : CNET_SCTP_SESSION_EMPTY;
      }
    }
    n = committed(b, s, written);
    if (n) {
      if (n != SALTS_ENOBUFS && n != SALTS_EBUSY && n != SALTS_EPERM)
        latch(b, n);
      break;
    }
    if (!written)
      break;
    ++*events;
  }
  b->advancing = false;
  return b->error ? b->error : n;
}
int cnet_sctp_dtls_get_info(const cnet_sctp_dtls *owner,
                            cnet_sctp_dtls_info *out) {
  if (!owner || !owner->impl || !out)
    return SALTS_EINVAL;
  const bridge *b = owner->impl;
  if (overlap(out, sizeof(*out), owner, sizeof(*owner)) ||
      overlap(out, sizeof(*out), b, sizeof(*b)))
    return SALTS_EINVAL;
  *out = (cnet_sctp_dtls_info){
      b->binding,  b->count,   b->capacity - b->count, b->error,
      b->reserved, b->pending, b->submitted,           b->stopping};
  return SALTS_OK;
}
int cnet_sctp_dtls_abort(cnet_sctp_dtls *owner) {
  if (!owner || !owner->impl)
    return SALTS_EINVAL;
  bridge *b = owner->impl;
  if (b->advancing || b->reserved)
    return SALTS_EBUSY;
  if (!b->stopping) {
    int n = map(cnet_sctp_session_stop(b->session));
    if (n)
      return n;
    b->stopping = true;
  }
  memset(b->input, 0, b->capacity * sizeof(*b->input));
  b->count = 0u;
  if (!b->submitted) {
    b->pending = false;
    b->written = 0u;
  }
  return b->submitted ? SALTS_EBUSY : SALTS_OK;
}
int cnet_sctp_dtls_destroy(cnet_sctp_dtls *owner) {
  if (!owner)
    return SALTS_EINVAL;
  bridge *b = owner->impl;
  if (!b)
    return SALTS_OK;
  if (!b->stopping || b->reserved || b->advancing || b->submitted)
    return SALTS_EBUSY;
  free(b->input);
  memset(b, 0, sizeof(*b));
  free(b);
  owner->impl = NULL;
  return SALTS_OK;
}
