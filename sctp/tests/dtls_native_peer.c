/* Formal SCTP-over-production-DTLS host. One bounded peer table, one socket,
 * one NativeIO observer; only public CNet/Crypto/SCTP APIs. */
#include <core/clock.h>
#include <sctp_dtls.h>
#include <core/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
enum { PEERS = 8 };
typedef struct host host;
typedef struct peer {
  host *host;
  cnet_dtls dtls;
  cnet_sctp_dtls bridge;
  cnet_sctp_session *session;
  cnet_datagram_peer address;
  uint8_t cookie[60], cookie_secret[32],
      message[CNET_SCTP_SESSION_MAX_MESSAGE_BYTES];
  size_t cookie_size, message_size;
  uint64_t cookie_tag, generation;
  unsigned messages, acks, sends;
  int error;
  bool registered, stopping, cookie_submitted, echo, owner;
} peer;
struct host {
  cnet_datagram datagram, neighbor;
  native_io_backend backend;
  crypto_dtls_listener *listener;
  peer peers[PEERS];
  size_t count, cursor;
  uint16_t port, neighbor_port;
  unsigned neighbor_rx, neighbor_tx;
  int error, refs, checks;
  uint64_t cookie_sequence;
  bool external, client, rearm, draining;
};
static void put32(uint8_t *p, uint32_t n) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = (uint8_t)(n >> (24u - 8u * i));
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] << 24u | (uint32_t)p[1] << 16u | (uint32_t)p[2] << 8u |
         p[3];
}
static void error(host *h, int n) {
  if (h->draining && (n == SALTS_ECANCELED || n == SALTS_ESHUTDOWN))
    return;
  if (n < 0 && !h->error)
    h->error = n;
}
static int establish(peer *, uint64_t);
static int owner(void *p) { return ((peer *)p)->owner; }
static int entropy(void *p, uint8_t *out, size_t n) {
  (void)p;
  return secure_random(out, n);
}
static int mac(void *p, const uint8_t *data, size_t n, uint8_t out[32]) {
  const char label[] = "EXPERIMENTAL-SCTP-cookie";
  peer *x = p;
  /* Exporter alone is shared with the remote peer: add an untransmitted
   * server-private CSPRNG context so the peer cannot forge SCTP state cookies.
   */
  const crypto_dtls_export_request r = {label, sizeof(label) - 1u,
                                        x->cookie_secret,
                                        sizeof(x->cookie_secret), true};
  return cnet_dtls_hmac(&((peer *)p)->dtls, &r, data, n, out);
}
static int verify(void *p, const uint8_t *data, size_t n,
                  const uint8_t expected[32]) {
  uint8_t proof[32];
  if (mac(p, data, n, proof))
    return -1;
  unsigned difference = 0;
  for (size_t i = 0; i < 32u; i++)
    difference |= proof[i] ^ expected[i];
  memset(proof, 0, sizeof(proof));
  return difference ? -1 : 0;
}
static void retain(void *p) { ++((host *)p)->refs; }
static void release(void *p) { --((host *)p)->refs; }
static int policy(void *p,
                  const crypto_tls_stream_peer_certificate_chain *chain,
                  bool server, crypto_tls_stream_security_profile profile) {
  ++((host *)p)->checks;
  return !chain->count || server != ((host *)p)->client ||
         profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD;
}
static int application(void *p, cnet_dtls *d, const cnet_receive_view *v) {
  peer *x = p;
  if (!x->session) {
    int n = establish(x, monotonic_ms());
    if (n)
      return n;
  }
  return x->bridge.impl ? cnet_sctp_dtls_receive(&x->bridge, d, v)
                        : SALTS_EPROTO;
}
static void application_sent(void *p, cnet_dtls *d, size_t size, int status,
                             uint64_t tag) {
  peer *x = p;
  bool matched = false;
  if (cnet_sctp_dtls_send_complete(&x->bridge, d, size, status, tag ^ 1u,
                                   &matched) ||
      matched)
    error(x->host, SALTS_EPROTO);
  int n =
      cnet_sctp_dtls_send_complete(&x->bridge, d, size, status, tag, &matched);
  if (!matched)
    error(x->host, SALTS_EPROTO);
  if (n && !x->stopping)
    x->error = n;
  ++x->sends;
  matched = true;
  if (cnet_sctp_dtls_send_complete(&x->bridge, d, size, status, tag,
                                   &matched) ||
      matched)
    error(x->host, SALTS_EPROTO);
}
static peer *find(host *h, const cnet_datagram_peer *a) {
  for (size_t i = 0; i < h->count; i++)
    if (a->family == h->peers[i].address.family &&
        a->port == h->peers[i].address.port &&
        !memcmp(a->address, h->peers[i].address.address, 4u))
      return &h->peers[i];
  return NULL;
}
static void receive(void *p, cnet_datagram *d, const cnet_datagram_peer *a,
                    const cnet_receive_view *v) {
  host *h = p;
  if (d == &h->neighbor) {
    ++h->neighbor_rx;
    return;
  }
  h->rearm = true;
  peer *x = find(h, a);
  if (!x || x->stopping)
    return;
  if (x->registered) {
    cnet_dtls_info info;
    if (cnet_dtls_get_info(&x->dtls, &info)) {
      error(h, SALTS_EPROTO);
      return;
    }
    if (info.security.state == CRYPTO_DTLS_FAILED ||
        info.security.state == CRYPTO_DTLS_CLOSED)
      return;
    bool matched = false;
    int n = cnet_dtls_receive(&x->dtls, d, a, v, &matched);
    if (n || !matched)
      error(h, n ? n : SALTS_EPROTO);
    return;
  }
  if (!h->listener)
    return;
  uint8_t reply[60];
  size_t written = 0;
  bool verified = false;
  int n = cnet_dtls_cookie_gate(h->listener, a, v, monotonic_ms(), reply,
                                sizeof(reply), &written, &verified);
  if (n) {
    error(h, n);
    return;
  }
  if (!verified) {
    if (written) {
      if (x->cookie_size) {
        error(h, SALTS_ENOBUFS);
        return;
      }
      memcpy(x->cookie, reply, written);
      x->cookie_size = written;
      x->cookie_tag = UINT64_C(1) << 32u | ++h->cookie_sequence;
    }
    return;
  }
  const cnet_dtls_accept_config c = {
      d,           *a,
      h->listener, {application, application_sent, x},
      4u,          (uint32_t)(16u + (x - h->peers))};
  n = cnet_dtls_accept(&x->dtls, &c, v, monotonic_ms());
  if (n)
    error(h, n);
  else
    x->registered = true;
}
static void sent(void *p, cnet_datagram *d, const cnet_datagram_peer *a,
                 size_t size, int status, uint64_t tag) {
  host *h = p;
  if (d == &h->neighbor) {
    ++h->neighbor_tx;
    error(h, status);
    return;
  }
  peer *x = find(h, a);
  if (!x) {
    error(h, SALTS_EPROTO);
    return;
  }
  if (x->cookie_submitted && tag == x->cookie_tag) {
    if (size != x->cookie_size)
      error(h, SALTS_EPROTO);
    x->cookie_submitted = false;
    x->cookie_size = 0;
    error(h, status);
    return;
  }
  bool matched = false;
  int n = cnet_dtls_send_complete(&x->dtls, d, a, size, status, tag,
                                  monotonic_ms(), &matched);
  if (n || !matched)
    error(h, n ? n : SALTS_EPROTO);
}
static int establish(peer *x, uint64_t now) {
  cnet_dtls_info info;
  int n = cnet_dtls_get_info(&x->dtls, &info);
  if (n)
    return n;
  if (info.security.state != CRYPTO_DTLS_READY)
    return SALTS_OK;
  if (secure_random(x->cookie_secret, sizeof(x->cookie_secret)))
    return SALTS_EIO;
  cnet_sctp_session_create_config c = {0};
  c.abi_version = CNET_SCTP_SESSION_ABI_VERSION;
  c.struct_size = sizeof(c);
  c.local_port = c.remote_port = 5000u;
  c.receive_window = 32768u;
  c.inbound_streams = c.outbound_streams = 16u;
  c.t1_ms = 100u;
  c.t1_max_ms = 800u;
  c.cookie_lifetime_ms = 5000u;
  c.peer_binding = info.binding;
  c.max_retransmits = 8u;
  c.is_dtls_client = x->host->client;
  c.is_owner = owner;
  c.entropy = entropy;
  c.mac = mac;
  c.verify_mac = verify;
  c.provider_context = x;
  /* An incompatible transport generation is rejected before bridge admission.
   */
  cnet_sctp_session *wrong = NULL;
  c.peer_binding = info.binding == UINT64_MAX ? 1u : info.binding + 1u;
  if (cnet_sctp_session_create(&c, now, &wrong))
    return SALTS_EPROTO;
  cnet_sctp_dtls probe = {0};
  const cnet_sctp_dtls_config bad = {&x->dtls, wrong, 1u, 255u};
  int refused = cnet_sctp_dtls_init(&probe, &bad);
  bool published = probe.impl != NULL;
  if (published) {
    (void)cnet_sctp_dtls_abort(&probe);
    (void)cnet_sctp_dtls_destroy(&probe);
  }
  if (cnet_sctp_session_stop(wrong) || cnet_sctp_session_destroy(wrong))
    return SALTS_EPROTO;
  if (refused != SALTS_EINVAL || published)
    return SALTS_EPROTO;
  c.peer_binding = info.binding;
  if (cnet_sctp_session_create(&c, now, &x->session))
    return SALTS_EPROTO;
  const cnet_sctp_dtls_config cfg = {&x->dtls, x->session, 1u,
                                     (uint32_t)(32u + (x - x->host->peers))};
  int status = cnet_sctp_dtls_init(&x->bridge, &cfg);
  if (status)
    return status;
  void *packet, *second;
  size_t capacity, other;
  if (cnet_sctp_dtls_reserve(&x->bridge, &packet, &capacity) ||
      capacity != CRYPTO_DTLS_MAX_APPLICATION_BYTES ||
      cnet_sctp_dtls_reserve(&x->bridge, &second, &other) != SALTS_EBUSY ||
      cnet_sctp_dtls_abort(&x->bridge) != SALTS_EBUSY ||
      cnet_sctp_dtls_destroy(&x->bridge) != SALTS_EBUSY ||
      cnet_sctp_dtls_commit(&x->bridge, CNET_SCTP_SESSION_INVALID, 0u) !=
          SALTS_EINVAL ||
      cnet_sctp_dtls_commit(&x->bridge, CNET_SCTP_SESSION_EMPTY, 0u) !=
          SALTS_EINVAL ||
      cnet_sctp_dtls_reserve(&x->bridge, &x->bridge.impl, &capacity) !=
          SALTS_EINVAL ||
      cnet_sctp_dtls_reserve(&x->bridge, &packet, &capacity) ||
      cnet_sctp_dtls_commit(&x->bridge, CNET_SCTP_SESSION_CAPACITY, 0u) !=
          SALTS_ENOBUFS)
    return SALTS_EPROTO;
  if (x->host->client) {
    if (cnet_sctp_dtls_reserve(&x->bridge, &packet, &capacity))
      return SALTS_EPROTO;
    size_t written = 0u;
    cnet_sctp_session_status started =
        cnet_sctp_session_start(x->session, now, packet, capacity, &written);
    return cnet_sctp_dtls_commit(&x->bridge, started, written);
  }
  return SALTS_OK;
}
static int advance_peer(peer *x, uint64_t now) {
  if (!x->registered)
    return SALTS_OK;
  size_t events = 0;
  int first = 0;
  if (!x->session && !x->stopping) {
    first = establish(x, now);
    if (first)
      return first;
  }
  if (x->bridge.impl && !x->stopping) {
    int n = cnet_sctp_dtls_advance(&x->bridge, now, &events);
    if (n && n != SALTS_ENOBUFS && n != SALTS_EBUSY)
      first = n;
    void *packet;
    size_t capacity;
    n = cnet_sctp_dtls_reserve(&x->bridge, &packet, &capacity);
    if (!n) {
      cnet_sctp_session_event event;
      size_t written = 0;
      cnet_sctp_session_status s = CNET_SCTP_SESSION_EMPTY;
      int ready = 0;
      if (cnet_sctp_session_data_ready(x->session, &ready))
        s = CNET_SCTP_SESSION_PROTOCOL;
      else if (!x->echo && ready)
        s = cnet_sctp_session_poll(x->session, now, &event, x->message,
                                   sizeof(x->message), packet, capacity,
                                   &written);
      n = cnet_sctp_dtls_commit(&x->bridge, s, written);
      if (n && n != SALTS_ENOBUFS && !first)
        first = n;
      if (s == CNET_SCTP_SESSION_OK) {
        if (event.kind == CNET_SCTP_SESSION_EVENT_CHANNEL_OPEN)
          x->generation = event.generation;
        if (event.kind == CNET_SCTP_SESSION_EVENT_MESSAGE) {
          if (event.stream_id != (x->host->client ? 1u : 0u) ||
              event.generation != x->generation || !event.binary) {
            error(x->host, SALTS_EPROTO);
            return SALTS_EPROTO;
          }
          x->message_size = event.message_size;
          for (size_t i = 0; i < x->message_size; ++i) {
            if (x->message[i] != (uint8_t)(31u + (size_t)(x - x->host->peers))) {
              fprintf(stderr, "SCTP ingress peer=%zu size=%zu offset=%zu byte=%u\n",
                      (size_t)(x - x->host->peers), x->message_size, i,
                      (unsigned)x->message[i]);
              error(x->host, SALTS_EPROTO);
              return SALTS_EPROTO;
            }
          }
          x->echo = true;
          ++x->messages;
        }
      }
    } else if (n != SALTS_ENOBUFS && n != SALTS_EBUSY && !first)
      first = n;
    if (x->echo) {
      uint64_t ticket;
      cnet_sctp_session_status s = cnet_sctp_session_queue_reliable_tracked(
          x->session, now, x->host->client ? 1u : 0u, x->generation, 1,
          x->message, x->message_size, &ticket);
      if (!s) {
        x->echo = false;
        /* Successful queue admission owns its copy through fragmentation. */
        memset(x->message, 0xa5, sizeof(x->message));
      } else if (s != CNET_SCTP_SESSION_CAPACITY && s != CNET_SCTP_SESSION_BUSY &&
               !first)
        first = SALTS_EPROTO;
    }
    cnet_sctp_session_reliable_ack ack;
    while (cnet_sctp_session_take_reliable_ack(x->session, &ack) ==
           CNET_SCTP_SESSION_OK) {
      if (ack.generation != x->generation ||
          ack.stream_id != (x->host->client ? 1u : 0u))
        error(x->host, SALTS_EPROTO);
      ++x->acks;
    }
  }
  int n = cnet_dtls_advance(&x->dtls, now, &events);
  if (n && !first)
    first = n;
  if (first && !x->error)
    x->error = first;
  return SALTS_OK; /* Association error never abandons sibling progress. */
}
static int step(host *h) {
  bool credits = true;
  uint64_t now = monotonic_ms();
  for (size_t k = 0; !h->draining && k < h->count; k++) {
    peer *x = &h->peers[(h->cursor + k) % h->count];
    if (x->cookie_size && !x->cookie_submitted) {
      int n = cnet_datagram_send(&h->datagram, &x->address, x->cookie,
                                 x->cookie_size, x->cookie_tag);
      if (!n)
        x->cookie_submitted = true;
      else if (n != SALTS_ENOBUFS)
        error(h, n);
    }
    (void)advance_peer(x, now);
    if (x->cookie_size)
      credits = false;
    if (x->registered && !x->stopping) {
      cnet_dtls_info info;
      cnet_dtls_get_info(&x->dtls, &info);
      if (info.security.state != CRYPTO_DTLS_FAILED &&
          info.security.state != CRYPTO_DTLS_CLOSED && !info.free_input)
        credits = false;
    }
  }
  h->cursor = (h->cursor + 1u) % h->count;
  if (!h->draining && h->rearm && credits) {
    int n = cnet_datagram_receive(&h->datagram, 1u);
    error(h, n);
    if (!n)
      h->rearm = false;
  }
  size_t events = 0;
  if (!h->external) {
    error(h, cnet_datagram_poll(&h->datagram, 1u, &events));
    return h->error;
  }
  error(h, cnet_datagram_advance_external(&h->datagram, &events));
  error(h, cnet_datagram_advance_external(&h->neighbor, &events));
  native_io_completion batch[4];
  size_t count = 0;
  int n = native_io_backend_observe(&h->backend, batch, 4u, 1u, &count);
  if (n != SALTS_ETIMEDOUT)
    error(h, n);
  for (size_t i = 0; i < count; i++) {
    bool matched = false;
    size_t callbacks = 0;
    n = cnet_datagram_route_external_completion(&h->datagram, &batch[i],
                                                &matched, &callbacks);
    error(h, n);
    if (matched)
      continue;
    n = cnet_datagram_route_external_completion(&h->neighbor, &batch[i],
                                                &matched, &callbacks);
    error(h, n);
    if (!matched)
      error(h, SALTS_EPROTO);
  }
  return h->error;
}
static size_t file(const char *path, uint8_t *out, size_t capacity) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0u;
  size_t n = fread(out, 1u, capacity, f);
  bool bad = ferror(f) || fgetc(f) != EOF;
  if (fclose(f))
    bad = true;
  return bad ? 0u : n;
}
int main(int argc, char **argv) {
  if (argc < 6 || argc > 5 + PEERS)
    return 2;
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1)
    return 2;
  const native_io_backend_kind kind = NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  const native_io_backend_kind kind = NATIVE_IO_BACKEND_KQUEUE;
#else
  const native_io_backend_kind kind = NATIVE_IO_BACKEND_EPOLL;
#endif
  host *h = calloc(1u, sizeof(*h));
  if (!h)
    return 2;
  h->external =
      !strcmp(argv[1], "external") || !strcmp(argv[1], "external-client");
  h->client =
      !strcmp(argv[1], "owned-client") || !strcmp(argv[1], "external-client");
  h->count = (size_t)argc - 5u;
  if (strcmp(argv[1], "owned") && !h->external && !h->client) {
    free(h);
    return 2;
  }
  for (size_t i = 0; i < h->count; i++) {
    unsigned port;
    char tail;
    if (sscanf(argv[5 + i], "%u%c", &port, &tail) != 1 || !port ||
        port > 65535u) {
      free(h);
      return 2;
    }
    h->peers[i].host = h;
    h->peers[i].owner = true;
    h->peers[i].address = (cnet_datagram_peer){
        CNET_DATAGRAM_ADDRESS_IPV4, (uint16_t)port, 0, {127, 0, 0, 1}};
  }
  int result = 0;
  uint8_t roots[16384], cert[16384], key[16384];
  size_t rn = file(argv[2], roots, sizeof(roots)),
         cn = file(argv[3], cert, sizeof(cert)),
         kn = file(argv[4], key, sizeof(key));
  if (!rn || !cn || !kn) {
    result = 2;
    goto done;
  }
  cnet_datagram_config dc = CNET_DATAGRAM_CONFIG_INIT;
  dc.backend = kind;
  dc.host = "127.0.0.1";
  dc.send_capacity = 2u;
  dc.request_capacity = dc.completion_batch_capacity = 4u;
  dc.max_datagram_bytes = dc.receive_buffer_bytes =
      CRYPTO_DTLS_MAX_DATAGRAM_BYTES;
  dc.observer = (cnet_datagram_observer){receive, sent, h};
  if (h->external) {
    native_io_backend_config bc = {0};
    bc.kind = kind;
    bc.endpoint_capacity = 2u;
    bc.request_capacity = bc.completion_batch_capacity = 4u;
    if (native_io_backend_init(&h->backend, &bc) ||
        cnet_datagram_init_external(&h->datagram, &dc, &h->backend) ||
        cnet_datagram_init_external(&h->neighbor, &dc, &h->backend) ||
        cnet_datagram_port(&h->neighbor, &h->neighbor_port) ||
        cnet_datagram_receive(&h->neighbor, 1u)) {
      result = 3;
      goto done;
    }
  } else if (cnet_datagram_init(&h->datagram, &dc)) {
    result = 3;
    goto done;
  }
  if (cnet_datagram_port(&h->datagram, &h->port) ||
      cnet_datagram_receive(&h->datagram, 1u)) {
    result = 3;
    goto done;
  }
  const crypto_tls_credentials credentials = {
      .size = sizeof(credentials),
      .certificate_chain = {cert, cn, CRYPTO_TLS_ENCODING_PEM},
      .private_key = {key, kn, CRYPTO_TLS_ENCODING_PEM}};
  const crypto_tls_data trust = {roots, rn, CRYPTO_TLS_ENCODING_PEM};
  const crypto_tls_stream_peer_policy pp = {
      policy,
      retain,
      release,
      h,
      CRYPTO_TLS_PEER_POLICY_STANDARD,
      h->client ? CRYPTO_TLS_PEER_POLICY_SERVER
                : CRYPTO_TLS_PEER_POLICY_CLIENT};
  const crypto_dtls_listener_config lc = {
      &credentials, &trust, &pp, NULL, 0u, "test", 4u, 60000u, true, true};
  if (h->client) {
    for (size_t i = 0; i < h->count; i++) {
      peer *x = &h->peers[i];
      const cnet_dtls_config cfg = {
          .datagram = &h->datagram,
          .peer = x->address,
          .security = {.roots = trust,
                       .server_name = "localhost",
                       .server_name_size = 9u,
                       .alpn = "test",
                       .alpn_size = 4u,
                       .credentials = &credentials,
                       .peer_policy = &pp,
                       .enable_exporter = true},
          .observer = {application, application_sent, x},
          .input_slots = 4u,
          .tag_domain = (uint32_t)(16u + i)};
      if (cnet_dtls_init(&x->dtls, &cfg)) {
        result = 3;
        goto done;
      }
      x->registered = true;
    }
  } else if (cnet_dtls_listener_create(&lc, &h->listener)) {
    result = 3;
    goto done;
  }
  memset(key, 0, sizeof(key));
  for (;;) {
    uint8_t request[2];
    size_t got = fread(request, 1u, 2u, stdin);
    if (!got && feof(stdin))
      break;
    if (got != 2u || request[1] >= h->count) {
      result = 2;
      break;
    }
    peer *x = &h->peers[request[1]];
    int status = 0;
    uint8_t proof[32] = {0};
    switch (request[0]) {
    case 'I':
      break;
    case 'P':
      status = step(h);
      break;
    case 'A':
      x->stopping = true;
      if (x->bridge.impl)
        status = cnet_sctp_dtls_abort(&x->bridge);
      if (x->registered) {
        int n = cnet_dtls_abort(&x->dtls);
        if (n)
          status = n;
      }
      break;
    case 'C':
      if (x->bridge.impl)
        status = cnet_sctp_dtls_destroy(&x->bridge);
      if (!status && x->session) {
        status = cnet_sctp_session_destroy(x->session) ? SALTS_EBUSY : SALTS_OK;
        if (!status)
          x->session = NULL;
      }
      if (!status && x->registered) {
        status = cnet_dtls_destroy(&x->dtls);
        if (!status)
          x->registered = false;
      }
      break;
    case 'K':
      status = cnet_dtls_listener_destroy(h->listener);
      if (!status)
        h->listener = NULL;
      break;
    case 'N': {
      const cnet_datagram_peer a = {
          CNET_DATAGRAM_ADDRESS_IPV4, h->neighbor_port, 0, {127, 0, 0, 1}};
      status = h->external ? SALTS_OK : SALTS_ENOTSUP;
      if (!status && h->neighbor_rx)
        status = cnet_datagram_receive(&h->neighbor, 1u);
      if (!status)
        status = cnet_datagram_send(&h->neighbor, &a, "neighbor", 8u, 3u);
      break;
    }
    case 'V': {
      void *packet;
      size_t capacity;
      x->owner = false;
      status = cnet_sctp_dtls_reserve(&x->bridge, &packet, &capacity);
      x->owner = true;
      break;
    }
    case 'M': {
      const char label[] = "EXPERIMENTAL-SCTP-cookie";
      const crypto_dtls_export_request r = {label, sizeof(label) - 1u, NULL, 0u,
                                            false};
      status = cnet_dtls_hmac(&x->dtls, &r, "cookie-proof", 12u, proof);
      break;
    }
    case 'F':
      status = mac(x, (const uint8_t *)"cookie-proof", 12u, proof);
      break;
    case 'R': {
      /* Deliberate stale-borrow misuse: replace the public DTLS instance at a
       * quiescent point, then prove the old Session cannot issue any I/O. */
      cnet_dtls_info info;
      cnet_sctp_dtls_info si;
      if (!x->registered || !x->bridge.impl ||
          cnet_dtls_get_info(&x->dtls, &info) ||
          cnet_sctp_dtls_get_info(&x->bridge, &si)) {
        status = SALTS_EINVAL;
        break;
      }
      if (info.send_pending || info.security.pending_receive ||
          info.queued_input || si.output_pending || si.queued_input) {
        status = SALTS_EBUSY;
        break;
      }
      uint8_t trust_bytes[16384];
      size_t n = file(argv[2], trust_bytes, sizeof(trust_bytes));
      if (!n) {
        status = SALTS_EIO;
        break;
      }
      status = cnet_dtls_destroy(&x->dtls);
      if (status)
        break;
      x->registered = false;
      const cnet_dtls_config replacement = {
          .datagram = &h->datagram,
          .peer = x->address,
          .security = {.roots = {trust_bytes, n, CRYPTO_TLS_ENCODING_PEM},
                       .server_name = "localhost",
                       .server_name_size = 9u},
          .observer = {application, application_sent, x},
          .input_slots = 1u,
          .tag_domain = 77u};
      status = cnet_dtls_init(&x->dtls, &replacement);
      if (status)
        break;
      x->registered = true;
      cnet_dtls_info fresh;
      size_t events = 99u;
      if (cnet_dtls_get_info(&x->dtls, &fresh) ||
          fresh.binding == info.binding || !fresh.binding) {
        status = SALTS_EPROTO;
        break;
      }
      status =
          cnet_sctp_dtls_advance(&x->bridge, monotonic_ms(), &events);
      if (status != SALTS_EPROTO || events != 0u)
        error(h, SALTS_EPROTO);
      break;
    }
    default:
      status = SALTS_EINVAL;
      break;
    }
    cnet_dtls_info di = {0};
    cnet_sctp_dtls_info bi = {0};
    if (x->registered)
      cnet_dtls_get_info(&x->dtls, &di);
    if (x->bridge.impl)
      cnet_sctp_dtls_get_info(&x->bridge, &bi);
    uint8_t response[40] = {0};
    put32(response, (uint32_t)status);
    response[4] = (uint8_t)di.security.state;
    response[5] = (uint8_t)(di.send_pending | bi.output_pending << 1u |
                            bi.submitted << 2u | x->stopping << 3u);
    response[6] = (uint8_t)h->refs;
    response[7] = (uint8_t)h->checks;
    put32(response + 8u, x->messages);
    put32(response + 12u, x->acks);
    for (unsigned i = 0; i < 8u; i++)
      response[16u + i] = (uint8_t)(x->generation >> (56u - 8u * i));
    response[24] = (uint8_t)(h->port >> 8u);
    response[25] = (uint8_t)h->port;
    response[26] = (uint8_t)h->count;
    response[27] =
        (uint8_t)(h->neighbor_rx == h->neighbor_tx && h->neighbor_rx != 0u);
    put32(response + 28u, (uint32_t)x->error);
    put32(response + 32u, h->neighbor_tx);
    put32(response + 36u, x->sends);
    if (fwrite(response, 1u, sizeof(response), stdout) != sizeof(response) ||
        ((request[0] == 'M' || request[0] == 'F') && !status &&
         fwrite(proof, 1u, sizeof(proof), stdout) != sizeof(proof)) ||
        fflush(stdout)) {
      result = 2;
      break;
    }
    memset(proof, 0, sizeof(proof));
  }
done:
  h->draining = true;
  for (size_t i = 0; i < h->count; i++) {
    peer *x = &h->peers[i];
    x->stopping = true;
    if (x->bridge.impl)
      (void)cnet_sctp_dtls_abort(&x->bridge);
    if (x->registered)
      (void)cnet_dtls_abort(&x->dtls);
  }
  if (h->external) {
    bool a = !h->datagram.impl, b = !h->neighbor.impl;
    uint64_t start = monotonic_ms();
    while ((!a || !b) && monotonic_ms() - start < 5000u) {
      int n = a ? 0 : cnet_datagram_stop_external(&h->datagram, &a);
      if (n && n != SALTS_EBUSY)
        result = 3;
      n = b ? 0 : cnet_datagram_stop_external(&h->neighbor, &b);
      if (n && n != SALTS_EBUSY)
        result = 3;
      (void)step(h);
    }
    if (!a || !b)
      result = 3;
  } else if (h->datagram.impl && cnet_datagram_stop(&h->datagram, 5000u))
    result = 3;
  for (size_t i = 0; i < h->count; i++) {
    peer *x = &h->peers[i];
    size_t events;
    if (x->registered)
      (void)cnet_dtls_advance(&x->dtls, monotonic_ms(), &events);
    if (x->bridge.impl && cnet_sctp_dtls_destroy(&x->bridge))
      result = 3;
    if (x->session && cnet_sctp_session_destroy(x->session))
      result = 3;
    if (x->registered && cnet_dtls_destroy(&x->dtls))
      result = 3;
  }
  if (h->listener && cnet_dtls_listener_destroy(h->listener))
    result = 3;
  if (h->datagram.impl && cnet_datagram_destroy(&h->datagram))
    result = 3;
  if (h->neighbor.impl && cnet_datagram_destroy(&h->neighbor))
    result = 3;
  if (h->backend.impl && (native_io_backend_close(&h->backend) ||
                          native_io_backend_destroy(&h->backend)))
    result = 3;
  if (h->refs || h->error)
    result = 3;
  if (result)
    fprintf(stderr, "secure SCTP host failure result=%d route=%d refs=%d\n",
            result, h->error, h->refs);
  memset(key, 0, sizeof(key));
  for (size_t i = 0; i < h->count; i++) {
    volatile uint8_t *secret = h->peers[i].cookie_secret;
    for (size_t k = 0; k < 32u; k++)
      secret[k] = 0u;
  }
  free(h);
  return result;
}
