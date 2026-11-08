/* Formal production CNet/NativeIO driver. The host owns observation and socket
 * lifetimes; protocol callbacks forward borrowed views and actual terminals. */
#include <clock.h>
#include <cnet/dtls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
typedef struct fixture {
  cnet_dtls dtls;
  crypto_dtls_listener *listener;
  cnet_datagram datagram, neighbor;
  native_io_backend backend;
  uint8_t application[32768];
  size_t application_size;
  uint8_t input_probe[15];
  uint32_t received, sent, wire_sent, neighbor_received, neighbor_sent;
  int error, last_send, policy_refs, policy_checks;
  uint16_t port, neighbor_port;
  bool external, registered, rearm, callback_ok, data_reject, server_role;
  uint8_t cookie_reply[CRYPTO_DTLS_COOKIE_REPLY_BYTES];
  size_t cookie_size;
  bool cookie_submitted;
  unsigned deferred;
  bool defer_empty;
  uint32_t cookies;
  cnet_datagram_peer remote;
} fixture;
static unsigned get32(const uint8_t *p) {
  return (unsigned)p[0] << 24u | (unsigned)p[1] << 16u | (unsigned)p[2] << 8u |
         p[3];
}
static void put32(uint8_t *p, uint32_t n) {
  for (unsigned i = 0; i < 4u; ++i)
    p[i] = (uint8_t)(n >> (24u - i * 8u));
}
static void erase(void *p, size_t n) {
  volatile uint8_t *b = p;
  while (n--)
    *b++ = 0;
}
static void error(fixture *f, int n) {
  if (n < 0 && !f->error)
    f->error = n;
}
static int application(void *context, cnet_dtls *d,
                       const cnet_receive_view *v) {
  fixture *f = context;
  if (f->defer_empty && !v->size) {
    f->defer_empty = false;
    f->deferred = 2u;
  }
  if(f->deferred){--f->deferred;
    f->callback_ok &= cnet_dtls_abort(d)==SALTS_EBUSY && cnet_dtls_destroy(d)==SALTS_EBUSY;
    return f->callback_ok ? SALTS_ENOBUFS : SALTS_EPROTO;
  }
  if (f->application_size > sizeof(f->application) - 2u ||
      v->size > sizeof(f->application) - f->application_size - 2u)
    return SALTS_ENOBUFS;
  ++f->received;
  uint8_t *p = f->application + f->application_size;
  p[0] = (uint8_t)(v->size >> 8u);
  p[1] = (uint8_t)v->size;
  if (v->size)
    memcpy(p + 2u, v->data, v->size);
  f->application_size += 2u + v->size;
  f->callback_ok &=
      cnet_dtls_abort(d) == SALTS_EBUSY && cnet_dtls_destroy(d) == SALTS_EBUSY;
  return !f->callback_ok  ? SALTS_EPROTO
         : f->data_reject ? SALTS_ECANCELED
                          : SALTS_OK;
}
static void application_sent(void *context, cnet_dtls *d, size_t size,
                             int status, uint64_t tag) {
  fixture *f = context;
  ++f->sent;
  f->last_send = status;
  (void)size;
  if (tag != 41u)
    error(f, SALTS_EPROTO);
  f->callback_ok &=
      cnet_dtls_abort(d) == SALTS_EBUSY && cnet_dtls_destroy(d) == SALTS_EBUSY;
}
static void receive(void *context, cnet_datagram *d,
                    const cnet_datagram_peer *peer,
                    const cnet_receive_view *v) {
  fixture *f = context;
  if (d == &f->neighbor) {
    ++f->neighbor_received;
    return;
  }
  f->rearm = true;
  if (!f->registered && f->server_role && f->listener &&
      peer->family == f->remote.family && peer->port == f->remote.port &&
      !memcmp(peer->address, f->remote.address, 4u)) {
    bool verified = false;
    size_t reply_size = 0;
    uint8_t reply[CRYPTO_DTLS_COOKIE_REPLY_BYTES];
    int n = cnet_dtls_cookie_gate(f->listener, peer, v, cmeta_monotonic_ms(),
                                  reply, sizeof(reply), &reply_size, &verified);
    if (n) {
      error(f, n);
      return;
    }
    if (!verified) {
      const cnet_dtls_accept_config rejected = {
          &f->datagram, *peer, f->listener, {application, application_sent, f},
          1u,           7u};
      int refused =
          cnet_dtls_accept(&f->dtls, &rejected, v, cmeta_monotonic_ms());
      if (refused != SALTS_EPROTO || f->dtls.impl) {
        f->registered = f->dtls.impl != NULL;
        error(f, SALTS_EPROTO);
        return;
      }
      if (reply_size) {
        /* One reply reservation; receive credit is paused until its terminal.
         */
        if (f->cookie_size) {
          error(f, SALTS_ENOBUFS);
          return;
        }
        memcpy(f->cookie_reply, reply, reply_size);
        f->cookie_size = reply_size;
      }
      return;
    }
    const cnet_dtls_accept_config cfg = {
        &f->datagram, *peer, f->listener, {application, application_sent, f},
        1u,           7u};
    n = cnet_dtls_accept(&f->dtls, &cfg, v, cmeta_monotonic_ms());
    if (n) {
      error(f, n);
      return;
    }
    f->registered = true;
    return;
  }
  if (!f->registered)
    return;
  cnet_dtls_info info;
  if (cnet_dtls_get_info(&f->dtls, &info) != SALTS_OK) {
    error(f, SALTS_EPROTO);
    return;
  }
  if (info.stopping || info.security.state == CRYPTO_DTLS_FAILED ||
      info.security.state == CRYPTO_DTLS_CLOSED)
    return;
  bool matched = false;
  int n = cnet_dtls_receive(&f->dtls, d, peer, v, &matched);
  error(f, n);
  /* An unconfigured UDP source is not an unclaimed NativeIO completion. */
}
static void sent(void *context, cnet_datagram *d,
                 const cnet_datagram_peer *peer, size_t size, int status,
                 uint64_t tag) {
  fixture *f = context;
  if (d == &f->neighbor) {
    ++f->neighbor_sent;
    error(f, status);
    return;
  }
  ++f->wire_sent;
  if (tag == 5u && f->server_role) {
    if (!f->cookie_submitted || size != f->cookie_size) {
      error(f, SALTS_EPROTO);
      return;
    }
    f->cookie_submitted = false;
    f->cookie_size = 0u;
    ++f->cookies;
    error(f, status);
    return;
  }
  if (!f->registered) {
    error(f, SALTS_EPROTO);
    return;
  }
  bool matched = false;
  /* Same-sized unrelated tags and duplicate routes cannot settle this send. */
  int n = cnet_dtls_send_complete(&f->dtls, d, peer, size, status, tag ^ 1u,
                                  cmeta_monotonic_ms(), &matched);
  if (n || matched)
    error(f, SALTS_EPROTO);
  n = cnet_dtls_send_complete(&f->dtls, d, peer, size, status, tag,
                              cmeta_monotonic_ms(), &matched);
  error(f, n);
  if (!matched)
    error(f, SALTS_EPROTO);
  n = cnet_dtls_send_complete(&f->dtls, d, peer, size, status, tag,
                              cmeta_monotonic_ms(), &matched);
  if (n != SALTS_EALREADY || !matched)
    error(f, SALTS_EPROTO);
}
static void retain(void *context) { ++((fixture *)context)->policy_refs; }
static void release(void *context) { --((fixture *)context)->policy_refs; }
static int policy(void *context,
                  const crypto_tls_stream_peer_certificate_chain *chain,
                  bool server, crypto_tls_stream_security_profile profile) {
  fixture *f = context;
  ++f->policy_checks;
  if (!chain->count || server == f->server_role ||
      profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD)
    return -1;
  return f->last_send
             ? -1
             : 0; /* last_send initialized to 1 in policy-reject cases. */
}
static int observe(fixture *f, uint32_t timeout) {
  if (!f->external) {
    size_t events;
    return cnet_datagram_poll(&f->datagram, timeout, &events);
  }
  size_t events;
  int first = cnet_datagram_advance_external(&f->datagram, &events);
  int n = cnet_datagram_advance_external(&f->neighbor, &events);
  if (n < 0 && !first)
    first = n;
  native_io_completion batch[8];
  size_t count = 0;
  n = native_io_backend_observe(&f->backend, batch, 8u, timeout, &count);
  if (n < 0 && n != SALTS_ETIMEDOUT && !first)
    first = n;
  for (size_t i = 0; i < count; ++i) {
    bool matched = false;
    size_t callbacks = 0;
    n = cnet_datagram_route_external_completion(&f->datagram, &batch[i],
                                                &matched, &callbacks);
    if (n < 0 && !first)
      first = n;
    if (matched)
      continue;
    n = cnet_datagram_route_external_completion(&f->neighbor, &batch[i],
                                                &matched, &callbacks);
    if (n < 0 && !first)
      first = n;
    if (!matched && !first)
      first = SALTS_EPROTO;
  }
  return first;
}
static int step(fixture *f, uint32_t timeout, bool observe_io) {
  int first = 0;
  size_t events;
  if (f->cookie_size && !f->cookie_submitted) {
    int n = cnet_datagram_send(&f->datagram, &f->remote, f->cookie_reply,
                               f->cookie_size, 5u);
    if (!n)
      f->cookie_submitted = true;
    else if (n != SALTS_ENOBUFS)
      first = n;
  }
  if (f->server_role && !f->registered && f->rearm && !f->cookie_size) {
    int n = cnet_datagram_receive(&f->datagram, 1u);
    if (n && !first)
      first = n;
    if (!n)
      f->rearm = false;
  }
  if (f->registered) {
    int advanced = cnet_dtls_advance(&f->dtls, cmeta_monotonic_ms(), &events);
    if (advanced && !first)
      first = advanced;
    cnet_dtls_info info;
    int n = cnet_dtls_get_info(&f->dtls, &info);
    if (n)
      return n;
    if (f->rearm && info.free_input && !info.stopping &&
        info.security.state != CRYPTO_DTLS_FAILED &&
        info.security.state != CRYPTO_DTLS_CLOSED) {
      n = cnet_datagram_receive(&f->datagram, 1u);
      if (n < 0 && !first)
        first = n;
      if (!n)
        f->rearm = false;
    }
  }
  if (observe_io) {
    int n = observe(f, timeout);
    if (n < 0 && !first)
      first = n;
  }
  return first ? first : f->error;
}
static size_t read_file(const char *path, uint8_t *out, size_t cap) {
  FILE *file = fopen(path, "rb");
  if (!file)
    return 0;
  size_t n = fread(out, 1u, cap, file);
  bool bad = ferror(file) || fgetc(file) != EOF;
  if (fclose(file))
    bad = true;
  return bad ? 0 : n;
}
int main(int argc, char **argv) {
  if (argc != 5 && argc != 7)
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
  unsigned remote_port = 0;
  char tail;
  if (sscanf(argv[1], "%u%c", &remote_port, &tail) != 1 || !remote_port ||
      remote_port > 65535u)
    return 2;
  fixture *f = calloc(1u, sizeof(*f));
  if (!f)
    return 2;
  f->external = !strcmp(argv[2], "external");
  f->callback_ok = true;
  if (strcmp(argv[2], "external") && strcmp(argv[2], "owned")) {
    free(f);
    return 2;
  }
  f->server_role = !strncmp(argv[3], "server-", 7u);
  const char *scenario = f->server_role ? argv[3] + 7u : argv[3];
  f->last_send = !strcmp(scenario, "reject");
  f->remote = (cnet_datagram_peer){
      CNET_DATAGRAM_ADDRESS_IPV4, (uint16_t)remote_port, 0, {127, 0, 0, 1}};
  f->data_reject = !strcmp(scenario, "data-reject") || !strcmp(scenario,"deferred-reject");
  f->deferred=!strcmp(scenario,"backpressure") ? 2u : !strcmp(scenario,"deferred-reject") ? 1u : 0u;
  f->defer_empty = !strcmp(scenario, "backpressure-empty");
  uint8_t roots[16384], cert[16384], key[16384];
  size_t roots_size = read_file(argv[4], roots, sizeof(roots)), cert_size = 0,
         key_size = 0;
  int result = 0, status = 0;
  if (!roots_size) {
    result = 2;
    goto done;
  }
  if (argc == 7) {
    cert_size = read_file(argv[5], cert, sizeof(cert));
    key_size = read_file(argv[6], key, sizeof(key));
    if (!cert_size || !key_size) {
      result = 2;
      goto done;
    }
  }
  cnet_datagram_config dc = CNET_DATAGRAM_CONFIG_INIT;
  dc.backend = kind;
  dc.host = "127.0.0.1";
  dc.send_capacity = 1u;
  dc.request_capacity = 3u;
  dc.completion_batch_capacity = 3u;
  dc.max_datagram_bytes = dc.receive_buffer_bytes =
      CRYPTO_DTLS_MAX_DATAGRAM_BYTES;
  dc.observer = (cnet_datagram_observer){receive, sent, f};
  if (f->external) {
    native_io_backend_config bc = {0};
    bc.kind = kind;
    bc.endpoint_capacity = 2u;
    bc.request_capacity = 3u;
    bc.completion_batch_capacity = 3u;
    status = native_io_backend_init(&f->backend, &bc);
    if (status) {
      result = 3;
      goto done;
    }
    status = cnet_datagram_init_external(&f->datagram, &dc, &f->backend);
    if (!status)
      status = cnet_datagram_init_external(&f->neighbor, &dc, &f->backend);
    if (!status)
      status = cnet_datagram_port(&f->neighbor, &f->neighbor_port);
    if (!status)
      status = cnet_datagram_receive(&f->neighbor, 1u);
  } else
    status = cnet_datagram_init(&f->datagram, &dc);
  if (status) {
    result = 3;
    goto done;
  }
  status = cnet_datagram_port(&f->datagram, &f->port);
  if (status) {
    result = 3;
    goto done;
  }
  const crypto_tls_stream_peer_policy pp = {
      policy,
      retain,
      release,
      f,
      CRYPTO_TLS_PEER_POLICY_STANDARD,
      f->server_role ? CRYPTO_TLS_PEER_POLICY_CLIENT
                     : CRYPTO_TLS_PEER_POLICY_SERVER};
  const crypto_tls_credentials credentials = {
      .size = sizeof(credentials),
      .certificate_chain = {cert, cert_size, CRYPTO_TLS_ENCODING_PEM},
      .private_key = {key, key_size, CRYPTO_TLS_ENCODING_PEM}};
  cnet_dtls_config config = {0};
  config.datagram = &f->datagram;
  config.peer = f->remote;
  config.input_slots = 1u;
  config.tag_domain = 7u;
  config.observer = (cnet_dtls_observer){application, application_sent, f};
  config.security = (crypto_dtls_stream_config){
      .roots = {roots, roots_size, CRYPTO_TLS_ENCODING_PEM},
      .server_name = "localhost",
      .server_name_size = 9u,
      .alpn = "test",
      .alpn_size = 4u,
      .credentials = argc == 7 ? &credentials : NULL,
      .peer_policy = &pp,
      .enable_exporter = true};
  if (f->server_role) {
    if (argc != 7) {
      result = 2;
      goto done;
    }
    const crypto_tls_data client_roots = {roots, roots_size,
                                          CRYPTO_TLS_ENCODING_PEM};
    const bool mtls =
        !strcmp(scenario, "mtls") || !strcmp(scenario, "reject") ||
        !strcmp(scenario, "missing") || !strcmp(scenario, "untrusted") || !strcmp(scenario,"pkix");
    /* Pion's pinned shared SNI decoder rejects valid empty ServerHello ACKs.
     * Positive Pion cases explicitly select fixed identity; strict mismatch is
     * separate, and the existing Python oracle qualifies strict SNI success. */
    const bool strict = !strcmp(scenario, "sni");
    const crypto_dtls_listener_config lc = {&credentials,
                                            mtls ? &client_roots : NULL,
                                            mtls ? &pp : NULL,
                                            strict ? "localhost" : NULL,
                                            strict ? 9u : 0u,
                                            "test",
                                            4u,
                                            60000u,
                                            mtls,
                                            true};
    status = cnet_dtls_listener_create(&lc, &f->listener);
  } else
    status = cnet_dtls_init(&f->dtls, &config);
  erase(key, sizeof(key));
  erase(cert, sizeof(cert));
  erase(roots, sizeof(roots));
  if (status) {
    result = 3;
    goto done;
  }
  f->registered = !f->server_role;
  status = cnet_datagram_receive(&f->datagram, 1u);
  if (status) {
    result = 3;
    goto done;
  }
  uint8_t header[5], input[2048];
  for (;;) {
    size_t n = fread(header, 1u, sizeof(header), stdin);
    if (!n && feof(stdin))
      break;
    if (n != sizeof(header)) {
      result = 2;
      break;
    }
    const size_t size = get32(header + 1u);
    if (size > sizeof(input) || fread(input, 1u, size, stdin) != size) {
      result = 2;
      break;
    }
    f->application_size = 0u;
    switch (header[0]) {
    case 'I':
      status = SALTS_OK;
      break;
    case 'U': {
      /* Release the host receive credit before synthetic capacity probes. */
      status = cnet_datagram_pause_receive(&f->datagram);
      bool quiet = false;
      uint64_t started = cmeta_monotonic_ms();
      while (!status && !quiet && cmeta_monotonic_ms() - started < 1000u) {
        status = cnet_datagram_quiescent(&f->datagram, &quiet);
        if (!status && !quiet)
          status = observe(f, 1u);
      }
      if (!status && !quiet)
        status = SALTS_ETIMEDOUT;
      if (status)
        break;
      memset(f->input_probe, 0, sizeof(f->input_probe));
      const cnet_receive_view view = {f->input_probe, sizeof(f->input_probe),
                                      CNET_MESSAGE_DATAGRAM};
      bool matched = false;
      status = cnet_dtls_receive(&f->dtls, &f->datagram, &f->remote, &view,
                                 &matched);
      if (status || !matched) {
        status = SALTS_EPROTO;
        break;
      }
      /* A retained view or overwrite-on-full would now inject a valid fatal. */
      const uint8_t fatal[] = {21, 0xfe, 0xfd, 0, 0, 0, 0, 0,
                               0,  0,    1,    0, 2, 2, 40};
      memcpy(f->input_probe, fatal, sizeof(fatal));
      int full = cnet_dtls_receive(&f->dtls, &f->datagram, &f->remote, &view,
                                   &matched);
      cnet_dtls_info info;
      status = cnet_dtls_get_info(&f->dtls, &info);
      if (status || full != SALTS_ENOBUFS || !matched ||
          info.queued_input != 1u || info.free_input != 0u)
        status = SALTS_EPROTO;
      f->rearm = true;
      break;
    }
    case 'P':
      status = step(f, 10u, true);
      break;
    case 'T':
      status = step(f, 0u, false);
      break;
    case 'W':
      status = cnet_dtls_send(&f->dtls, input, size, 41u);
      break;
    case 'O':
      status = cnet_dtls_close(&f->dtls);
      break;
    case 'A':
      status = cnet_dtls_abort(&f->dtls);
      break;
    case 'C':
      status = cnet_dtls_destroy(&f->dtls);
      if (!status)
        f->registered = false;
      break;
    case 'K':
      status = cnet_dtls_listener_destroy(f->listener);
      if (!status)
        f->listener = NULL;
      break;
    case 'H':
      put32(f->application, f->cookies);
      f->application_size = 4u;
      status = 0;
      break;
    case 'N': {
      const cnet_datagram_peer peer = {
          CNET_DATAGRAM_ADDRESS_IPV4, f->neighbor_port, 0, {127, 0, 0, 1}};
      status = f->external ? SALTS_OK : SALTS_ENOTSUP;
      if (!status && f->neighbor_received)
        status = cnet_datagram_receive(&f->neighbor, 1u);
      if (!status)
        status = cnet_datagram_send(&f->neighbor, &peer, "neighbor", 8u, 3u);
      break;
    }
    case 'E': {
      const crypto_dtls_export_request r = {"EXPERIMENTAL-cnet", 17u, NULL, 0u,
                                            false};
      status = cnet_dtls_export(&f->dtls, &r, f->application, 65u);
      if (!status)
        f->application_size = 65u;
      break;
    }
    case 'L':
      put32(f->application, (uint32_t)f->last_send);
      f->application_size = 4u;
      status = SALTS_OK;
      break;
    default:
      status = SALTS_EINVAL;
      break;
    }
    cnet_dtls_info info = {0};
    if (f->registered && cnet_dtls_get_info(&f->dtls, &info)) {
      result = 3;
      break;
    }
    uint8_t response[36] = {0};
    put32(response, (uint32_t)status);
    response[4] = (uint8_t)info.security.state;
    response[5] = info.security.local_alert;
    response[6] = info.security.peer_alert;
    response[7] =
        (uint8_t)(info.security.pending_send | info.send_pending << 1u |
                  info.stopping << 2u | f->callback_ok << 3u);
    put32(response + 8u, f->received);
    put32(response + 12u, f->sent);
    put32(response + 16u, f->wire_sent);
    put32(response + 20u, f->neighbor_received);
    put32(response + 24u, f->neighbor_sent);
    response[28] = (uint8_t)(f->port >> 8u);
    response[29] = (uint8_t)f->port;
    response[30] = (uint8_t)f->policy_checks;
    response[31] = (uint8_t)f->policy_refs;
    put32(response + 32u, (uint32_t)f->application_size);
    if (fwrite(response, 1u, sizeof(response), stdout) != sizeof(response) ||
        (f->application_size && fwrite(f->application, 1u, f->application_size,
                                       stdout) != f->application_size) ||
        fflush(stdout)) {
      result = 2;
      break;
    }
    erase(f->application, sizeof(f->application));
    erase(input, sizeof(input));
  }
done:
  if (result)
    fprintf(stderr,
            "DTLS native fixture failed: result=%d status=%d callbacks=%d\n",
            result, status, f->error);
  if (f->registered)
    (void)cnet_dtls_abort(&f->dtls);
  if (f->external) {
    bool a = !f->datagram.impl, b = !f->neighbor.impl;
    uint64_t start = cmeta_monotonic_ms();
    while ((!a || !b) && cmeta_monotonic_ms() - start < 5000u) {
      int x = a ? 0 : cnet_datagram_stop_external(&f->datagram, &a),
          y = b ? 0 : cnet_datagram_stop_external(&f->neighbor, &b);
      if ((x && x != SALTS_EBUSY) || (y && y != SALTS_EBUSY))
        result = 3;
      (void)observe(f, 1u);
      if (f->registered) {
        size_t events;
        (void)cnet_dtls_advance(&f->dtls, cmeta_monotonic_ms(), &events);
      }
    }
    if (!a || !b)
      result = 3;
  } else if (f->datagram.impl && cnet_datagram_stop(&f->datagram, 5000u))
    result = 3;
  if (f->registered) {
    size_t events;
    (void)cnet_dtls_advance(&f->dtls, cmeta_monotonic_ms(), &events);
    if (cnet_dtls_destroy(&f->dtls))
      result = 3;
  }
  if (f->listener && cnet_dtls_listener_destroy(f->listener))
    result = 3;
  if (f->datagram.impl && cnet_datagram_destroy(&f->datagram))
    result = 3;
  if (f->neighbor.impl && cnet_datagram_destroy(&f->neighbor))
    result = 3;
  if (f->backend.impl) {
    if (native_io_backend_close(&f->backend))
      result = 3;
    if (native_io_backend_destroy(&f->backend))
      result = 3;
  }
  if (f->policy_refs || !f->callback_ok)
    result = 3;
  erase(key, sizeof(key));
  erase(cert, sizeof(cert));
  erase(roots, sizeof(roots));
  erase(f, sizeof(*f));
  free(f);
  return result;
}
