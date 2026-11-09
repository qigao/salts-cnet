#include <cnet/cnet.h>
#include <crypto/tls_peer_policy.h>
#include <memory/buffer.h>
#include <salts/clock.h>
#include <salts/error_codes.h>
#include <tinytest.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct probe {
  cnet_connection connection;
  unsigned connected, terminal, failed, received, sent;
  crypto_tls_failure_reason reason;
} probe;
static void state_changed(void *user, cnet_connection c, cnet_connection_state state, const cnet_error *error) {
  probe *p = user; p->connection = c;
  if (state == CNET_CONNECTION_CONNECTED) ++p->connected;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    ++p->terminal;
    if (state == CNET_CONNECTION_FAILED || error) ++p->failed;
    if (error) p->reason = error->tls.reason;
  }
}
static void received(void *user, cnet_connection c, const cnet_receive_view *view) {
  probe *p = user; (void)c;
  if (!view || view->kind != CNET_MESSAGE_BYTES || view->size != 1u || ((const uint8_t *)view->data)[0] != 'F') ++p->failed;
  ++p->received;
}
static void sent(void *user, cnet_connection c, size_t bytes) {
  probe *p = user; (void)c; if (bytes != 1u) ++p->failed; ++p->sent;
}
typedef struct policy_state { atomic_uint refs, checks; bool deny, shangmi; } policy_state;
static void retain(void *p) { atomic_fetch_add(&((policy_state *)p)->refs,1u); }
static void release(void *p) { atomic_fetch_sub(&((policy_state *)p)->refs,1u); }
static int admit(void *user, const crypto_tls_stream_peer_certificate_chain *chain,
    bool peer_is_server, crypto_tls_stream_security_profile profile) {
  policy_state *p = user; atomic_fetch_add(&p->checks,1u);
  if (peer_is_server || !chain || !chain->count || !chain->certificates[0].size ||
      (profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13) != p->shangmi) return -1;
  return p->deny ? -1 : 0;
}
#define REQUIRE(expr) do { if (!(expr)) { fprintf(stderr,"server tickets line %d: %s\n",__LINE__,#expr); result = 1; goto cleanup; } } while (0)
static int run_server(void) {
  int result = 0; size_t events = 0u; uint16_t port = 0u;
  cnet_client client = {0}; cnet_tls_server tls = {0}; cnet_listener listener = {0};
  bool client_live = false, listener_live = false; FILE *ready = NULL; mem_buffer_t *buffer = NULL;
  const char *path = getenv("SALTS_TICKET_READY"), *cert = getenv("SALTS_TICKET_CERT"), *key = getenv("SALTS_TICKET_KEY");
  const char *ca = getenv("SALTS_TICKET_CLIENT_CA"), *mode = getenv("SALTS_TICKET_MODE");
  const char *expected = getenv("SALTS_TICKET_EXPECTED"), *profile = getenv("SALTS_TICKET_PROFILE");
  policy_state policy = {0}; atomic_init(&policy.refs,1u); atomic_init(&policy.checks,0u);
  const bool shangmi = profile && !strcmp(profile,"shangmi13"); policy.shangmi = shangmi;
  REQUIRE(path && cert && key && mode && expected && strlen(expected) > 0u && strlen(expected) <= 4u);
  const bool disabled = !strcmp(mode,"disabled"), reject = !strcmp(mode,"policy"), expired = !strcmp(mode,"expired");
  const bool bad_binder = !strcmp(mode,"binder");
  const bool constraints = strstr(mode,"constraints-invalid") != NULL;
  crypto_tls_stream_peer_policy auth = {.check=admit,.retain=retain,.release=release,.context=&policy};
  const char *alpn[] = {"h2","http/1.1"};
  cnet_tls_server_config tc = {.size=sizeof(tc),.cert_file=cert,.key_file=key,.ca_file=ca,
    .client_auth=ca ? CNET_TLS_CLIENT_AUTH_REQUIRED : CNET_TLS_CLIENT_AUTH_NONE,
    .security_profile=shangmi ? CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 : CNET_TLS_SECURITY_PROFILE_STANDARD,
    .minimum_version=shangmi ? 0 : CNET_TLS_PROTOCOL_VERSION_1_3,.maximum_version=shangmi ? 0 : CNET_TLS_PROTOCOL_VERSION_1_3,
    .alpn_protocols=alpn,.alpn_protocol_count=2u,.peer_policy=ca ? &auth : NULL,
    .session_ticket_capacity=disabled ? 0u : !strcmp(mode,"capacity") ? 1u : 2u,
    .session_ticket_lifetime_seconds=disabled ? 0u : !strcmp(mode,"ticket-expired") ? 1u : 60u};
  cnet_client_config cfg = {0};
#ifdef _WIN32
  cfg.backend=NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  cfg.backend=NATIVE_IO_BACKEND_KQUEUE;
#else
  cfg.backend=NATIVE_IO_BACKEND_EPOLL;
#endif
  cfg.connection_capacity=2u; cfg.command_capacity=16u; cfg.request_capacity=8u; cfg.completion_batch_capacity=8u;
  cfg.event_capacity=16u; cfg.max_send_bytes=1024u; cfg.receive_buffer_bytes=1024u;
  cfg.read_timeout_ms=20000u; cfg.write_timeout_ms=20000u; cfg.tls_handshake_timeout_ms=20000u;
  cfg.tls_io_buffer_bytes=CNET_TLS_MIN_IO_BUFFER_BYTES;
  const cnet_listener_config lc = {cfg.backend,"127.0.0.1",0u,2u};
  REQUIRE(cnet_tls_server_init(&tls,&tc) == SALTS_OK);
  REQUIRE(cnet_client_init(&client,&cfg) == SALTS_OK); client_live=true;
  REQUIRE(cnet_listener_init(&listener,&lc) == SALTS_OK); listener_live=true;
  REQUIRE(cnet_listener_port(&listener,&port) == SALTS_OK && port);
  ready=fopen(path,"wb"); REQUIRE(ready);
  REQUIRE(fprintf(ready,"%u\n",(unsigned)port) > 0);
  { int status=fclose(ready); ready=NULL; REQUIRE(status == 0); }
  for (size_t round=0u; round < strlen(expected); ++round) {
    probe p={0}; bool accepted=false, demand=false, replied=false;
    policy.deny=reject && round != 0u;
    const bool reject_round=((reject || expired) && round != 0u) || (bad_binder && round == 1u) || constraints;
    const uint64_t deadline=monotonic_ms()+25000u;
    while (!p.terminal && monotonic_ms() < deadline) {
      if (!accepted) {
        int available=0; REQUIRE(cnet_listener_wait(&listener,0u,&available) == SALTS_OK);
        if (available) {
          const cnet_observer observer={state_changed,received,&p,sent};
          REQUIRE(cnet_listener_accept_tls(&listener,&client,&tls,&observer,&p.connection) == SALTS_OK);
          accepted=true;
          if (round+1u == strlen(expected)) REQUIRE(cnet_tls_server_destroy(&tls) == SALTS_OK);
        }
      }
      REQUIRE(cnet_client_poll(&client,1u,&events) == SALTS_OK);
      if (p.connected && !demand) {
        bool reused=false; REQUIRE(!reject_round);
        REQUIRE(cnet_tls_session_reused(&client,p.connection,&reused) == SALTS_OK);
        REQUIRE(reused == (expected[round] == '1'));
        if (ca) { char fingerprint[CNET_TLS_PEER_CERTIFICATE_SHA256_CAPACITY];
          REQUIRE(cnet_tls_peer_certificate_sha256(&client,p.connection,fingerprint) == SALTS_OK); }
        REQUIRE(cnet_receive(&client,p.connection,1u) == SALTS_OK); demand=true;
      }
      if (p.received && !replied) {
        REQUIRE(!p.failed && p.received == 1u);
        buffer=mem_get_buffer(mem_global(),1u); REQUIRE(buffer);
        ((uint8_t *)mem_buffer_data(buffer))[0]='G'; mem_set_used(buffer,1u);
        REQUIRE(cnet_send_buffer(&client,p.connection,buffer) == SALTS_OK);
        mem_buffer_release(buffer); buffer=NULL; replied=true;
      }
    }
    REQUIRE(accepted && p.terminal == 1u);
    if (reject_round) {
      REQUIRE(p.failed == 1u && !p.connected && !p.received && !p.sent);
      REQUIRE(p.reason == (reject ? CRYPTO_TLS_FAILURE_PEER_POLICY : expired ? CRYPTO_TLS_FAILURE_EXPIRED : constraints ? CRYPTO_TLS_FAILURE_CONSTRAINTS : CRYPTO_TLS_FAILURE_HANDSHAKE));
    } else REQUIRE(p.connected == 1u && !p.failed && p.received == 1u && p.sent == 1u);
    REQUIRE(cnet_client_poll(&client,0u,&events) == SALTS_OK);
  }
  if (ca) REQUIRE(atomic_load(&policy.checks) == (constraints ? 0u : expired ? 1u : (unsigned)strlen(expected)));
cleanup:
  if (ready && fclose(ready)) result=1;
  if (buffer) mem_buffer_release(buffer);
  if (listener_live) { if (cnet_listener_close(&listener)) result=1; if (cnet_listener_destroy(&listener)) result=1; }
  if (client_live) { if (cnet_client_stop(&client,5000u)) result=1; if (cnet_client_destroy(&client)) result=1; }
  if (cnet_tls_server_destroy(&tls)) result=1;
  if (atomic_load(&policy.refs) != 1u) result=1;
  return result;
}
spec("CNet context-owned TLS1.3 server ticket peer") {
  it("rejects invalid or unsupported ticket settings before absent identity I/O") {
    for (unsigned i=0u; i < 6u; ++i) {
      cnet_tls_server server={0};
      cnet_tls_server_config cfg={.size=sizeof(cfg),.cert_file="absent-ticket-cert.pem",.key_file="absent-ticket-key.pem",
        .session_ticket_capacity=i==0u ? 17u : i==1u ? 0u : 1u,
        .session_ticket_lifetime_seconds=i==2u ? 0u : i==3u ? 604801u : 60u,
        .security_profile=i==5u ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD};
      check_equal(cnet_tls_server_init(&server,&cfg),i < 4u ? SALTS_EINVAL : SALTS_ENOTSUP);
      check_true(server.impl == NULL);
    }
  }
  it("retains ticket/authentication state across independent client connections") { check_equal(run_server(),0); }
}
