#include <cnet/cnet.h>
#include <clock.h>
#include <cnet/destination_policy.h>
#include <cnet/owner_placement.h>
#include <cnet/recovery_policy.h>
#include <error_codes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tinytest.h>

static void destination_contract(void) {
  cnet_destination_hint nodes[] = {
    {10u, 1u, 4u, true}, {20u, 3u, 2u, true}, {30u, 2u, 1u, true}};
  cnet_destination_selection s = {0};
  cnet_destination_result out = {0};
  s.size = sizeof s;
  s.version = CNET_DESTINATION_POLICY_VERSION;
  s.kind = CNET_DESTINATION_EXPLICIT;
  s.endpoints = nodes;
  s.endpoint_count = 3u;
  s.snapshot_generation = 1u;
  s.expires_at_ms = UINT64_MAX;
  s.explicit_endpoint_id = 20u;
  check(cnet_destination_validate(nodes, 3u) == SALTS_OK);
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  check(out.endpoint_id == 20u && out.index == 1u &&
        out.snapshot_generation == 1u);
  nodes[1].eligible = false;
  check(cnet_destination_choose(&s, &out) == SALTS_ENOBUFS);
  check(out.index == SIZE_MAX && out.endpoint_id == 0u);
  nodes[1].eligible = true;
  s.expires_at_ms = 50u;
  s.now_ms = 50u;
  check(cnet_destination_choose(&s, &out) == SALTS_ETIMEDOUT);
  s.expires_at_ms = UINT64_MAX;
  s.kind = CNET_DESTINATION_WEIGHTED_RR;
  s.sequence = 2u;
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  check(out.index == 1u && out.endpoint_id == 20u);
  s.kind = CNET_DESTINATION_STRICT_KEY;
  s.key_known = true;
  s.key_hash = UINT64_C(0x123456789);
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  const size_t strict_winner = out.index;
  nodes[strict_winner].eligible = false;
  check(cnet_destination_choose(&s, &out) == SALTS_ENOBUFS);
  check(out.index == SIZE_MAX); /* no alternative peer / security downgrade */
  nodes[strict_winner].eligible = true;
  nodes[1].endpoint_id = 10u;
  check(cnet_destination_validate(nodes, 3u) == SALTS_EINVAL);
  check(cnet_destination_choose(&s, &out) == SALTS_EINVAL);
}

static void owner_contract(void) {
  cnet_owner_placement_hint owners[] = {{true, 3u}, {true, 1u}, {true, 2u}};
  cnet_owner_placement_input input = {0};
  size_t selected = SIZE_MAX;
  input.size = sizeof input;
  input.version = CNET_OWNER_PLACEMENT_VERSION;
  input.owners = owners;
  input.owner_count = 3u;
  input.kind = CNET_OWNER_PLACE_LOWEST_PRESSURE;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 1u);
  input.kind = CNET_OWNER_PLACE_STRICT_KEY;
  input.key_known = true;
  input.key_hash = 5u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 2u);
  owners[2].eligible = false;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_ENOBUFS);
  check(selected == SIZE_MAX);
  input.kind = CNET_OWNER_PLACE_EXPLICIT;
  input.explicit_owner = 1u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 1u);
  input.version = 999u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_EINVAL);
  check(selected == SIZE_MAX);
}

static void recovery_contract(void) {
  cnet_reconnect_config config = {0};
  cnet_reconnect_state state = {0};
  cnet_reconnect_ticket first = {0}, second = {0};
  cnet_reconnect_snapshot snapshot = {0};
  uint64_t wait_ms = 0u;
  config.size = sizeof config;
  config.version = CNET_RECOVERY_POLICY_VERSION;
  config.max_attempts = 2u;
  config.deadline_ms = 1000u;
  config.initial_backoff_ms = 10u;
  config.maximum_backoff_ms = 100u;
  config.jitter_seed = 17u;
  check(cnet_reconnect_init(&state, &config) == SALTS_OK);
  check(cnet_reconnect_begin(&state, 10u, &first, &wait_ms) == SALTS_OK);
  check(first.generation != 0u && first.state == (uintptr_t)&state);
  check(cnet_reconnect_connected(&state, first, 11u) == SALTS_OK);
  check(cnet_reconnect_protocol_ready(&state, first, 12u) == SALTS_OK);
  check(cnet_reconnect_get_snapshot(&state, &snapshot) == SALTS_OK);
  check(snapshot.protocol_ready && snapshot.attempts == 0u);
  check(cnet_reconnect_lost(&state, first, CNET_RECONNECT_TRANSIENT,
                            20u, 2000u) == SALTS_OK);
  check(cnet_reconnect_get_snapshot(&state, &snapshot) == SALTS_OK);
  check(snapshot.next_attempt_ms > 20u && snapshot.next_attempt_ms < 2000u);
  check(cnet_reconnect_begin(&state, 20u, &second, &wait_ms) == SALTS_EBUSY);
  check(second.generation == 0u && wait_ms != 0u);
  check(cnet_reconnect_begin(&state, snapshot.next_attempt_ms,
                             &second, &wait_ms) == SALTS_OK);
  check(second.generation > first.generation);
  check(cnet_reconnect_failed(&state, second, CNET_RECONNECT_SECURITY,
                               snapshot.next_attempt_ms) == SALTS_OK);
  check(cnet_reconnect_begin(&state, snapshot.next_attempt_ms,
                             &second, &wait_ms) == SALTS_ESHUTDOWN);
  check(second.generation == 0u);
}


/*
 * M1: exercise the real CNet DSO's admission and fixed channel protocol
 * contracts. This test adds no host strategy runtime, public ABI, mock,
 * second queue or caller-owned socket. Every rejected operation must leave
 * its output handle zero and must not publish a partly initialized owner.
 */
static native_io_backend_kind policy_backend_kind(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static void policy_connection_state(void *user, cnet_connection connection,
                                    cnet_connection_state state, const cnet_error *error) {
  (void)user;
  (void)connection;
  (void)state;
  (void)error;
}

static void policy_packet_receive(void *user, cnet_packet_endpoint *endpoint,
                                  cnet_packet_session session, const cnet_receive_view *view) {
  (void)user;
  (void)endpoint;
  (void)session;
  (void)view;
}

static void policy_packet_terminal(void *user, cnet_packet_endpoint *endpoint,
                                   cnet_packet_session session, size_t size, int status,
                                   uint64_t tag) {
  (void)user;
  (void)endpoint;
  (void)session;
  (void)size;
  (void)status;
  (void)tag;
}

static cnet_client_config policy_client_config(void) {
  cnet_client_config config = {0};
  config.backend = policy_backend_kind();
  config.connection_capacity = 2u;
  config.command_capacity = 8u;
  config.request_capacity = 4u;
  config.completion_batch_capacity = 4u;
  config.event_capacity = 8u;
  config.max_send_bytes = 256u;
  config.receive_buffer_bytes = 256u;
  return config;
}

static void rejected_channel_connect(cnet_client *owner, const char *uri,
                                     const cnet_tls_client_config *tls, int expected) {
  cnet_connection connection = {17u, 19u};
  cnet_connect_options options = {0};
  options.uri = uri;
  options.observer.on_state = policy_connection_state;
  options.tls = tls;
  check(cnet_connect(owner, &options, &connection) == expected);
  check(connection.slot == 0u && connection.generation == 0u);
}

static void stream_channel_admission_contract(void) {
  cnet_client owner = {0};
  cnet_client rejected_owner = {0};
  cnet_client_config config = policy_client_config();
  cnet_tls_client_config tls = {0};
  tls.size = sizeof tls;

  config.max_send_bytes = 0u;
  check(cnet_client_init(&rejected_owner, &config) == SALTS_EINVAL);
  check(rejected_owner.impl == NULL);
  config = policy_client_config();
  config.completion_batch_capacity = config.request_capacity + 1u;
  check(cnet_client_init(&rejected_owner, &config) == SALTS_EINVAL);
  check(rejected_owner.impl == NULL);

  config = policy_client_config(); /* TLS admission intentionally disabled. */
  check(cnet_client_init(&owner, &config) == SALTS_OK);
  if (owner.impl == NULL) return;

  /* TLS is only admitted for tls://; no upgrade of plain UDP/TCP or IPC. */
  rejected_channel_connect(&owner, "tcp://127.0.0.1:12345", &tls, SALTS_EINVAL);
  rejected_channel_connect(&owner, "udp://127.0.0.1:12345", &tls, SALTS_EINVAL);

  /* Explicit unsupported recipes never fall back to TCP/UDP. */
  rejected_channel_connect(&owner, "dtls://127.0.0.1:12345", NULL, SALTS_ENOTSUP);
  rejected_channel_connect(&owner, "kcp://127.0.0.1:12345", NULL, SALTS_ENOTSUP);
  rejected_channel_connect(&owner, "quic://127.0.0.1:12345", NULL, SALTS_ENOTSUP);

  /* No fallback to plaintext even when tls:// is otherwise syntactically valid. */
  rejected_channel_connect(&owner, "tls://127.0.0.1:12345", NULL, SALTS_ENOTSUP);
  rejected_channel_connect(&owner, "tls://127.0.0.1:12345", &tls, SALTS_ENOTSUP);
  check(cnet_client_stop(&owner, 1000u) == SALTS_OK);
  check(cnet_client_destroy(&owner) == SALTS_OK);
  check(owner.impl == NULL);
}

static cnet_packet_endpoint_config policy_packet_config(cnet_packet_protocol protocol) {
  cnet_packet_endpoint_config config = CNET_PACKET_ENDPOINT_CONFIG_INIT;
  config.protocol = protocol;
  config.session_capacity = 2u;
  config.datagram.backend = policy_backend_kind();
  config.datagram.host = "127.0.0.1";
  config.datagram.port = 0u; /* Bind a real ephemeral local UDP port, never an external peer. */
  config.datagram.send_capacity = 2u;
  config.datagram.request_capacity = 4u;
  config.datagram.completion_batch_capacity = 4u;
  config.datagram.max_datagram_bytes = 1400u;
  config.datagram.receive_buffer_bytes = 1400u;
  config.observer.on_receive = policy_packet_receive;
  return config;
}

static void reject_packet_channel(cnet_packet_endpoint *endpoint,
                                  const cnet_packet_endpoint_config *config,
                                  const cnet_packet_terminal_config *terminal) {
  check(cnet_packet_endpoint_init_ex(endpoint, config, terminal) == SALTS_EINVAL);
  check(endpoint->impl == NULL);
}

static void packet_channel_admission_contract(void) {
  cnet_packet_endpoint endpoint = {0};
  cnet_packet_endpoint_config config = policy_packet_config(CNET_PACKET_UDP);
  cnet_packet_terminal_config terminal = CNET_PACKET_TERMINAL_CONFIG_INIT;
  terminal.send_capacity = 2u;
  terminal.on_send = policy_packet_terminal;

  config.size--;
  reject_packet_channel(&endpoint, &config, &terminal);
  config = policy_packet_config(CNET_PACKET_UDP);
  config.protocol = (cnet_packet_protocol)99;
  reject_packet_channel(&endpoint, &config, &terminal);
  config = policy_packet_config(CNET_PACKET_UDP);
  config.security.mode = CNET_KCP_SECURITY_PSK_V1;
  reject_packet_channel(&endpoint, &config, &terminal); /* UDP cannot silently ignore PSK. */

  config = policy_packet_config(CNET_PACKET_UDP);
  terminal.version++;
  reject_packet_channel(&endpoint, &config, &terminal);
  terminal.version = CNET_PACKET_TERMINAL_API_VERSION;
  terminal.send_capacity = config.datagram.send_capacity + 1u;
  reject_packet_channel(&endpoint, &config, &terminal); /* Cannot exceed Owner send credits. */
  terminal.send_capacity = config.datagram.send_capacity;

  config = policy_packet_config(CNET_PACKET_KCP);
  config.kcp.mtu = (uint32_t)config.datagram.max_datagram_bytes + 1u;
  reject_packet_channel(&endpoint, &config, &terminal); /* No implicit IP fragmentation. */
  config = policy_packet_config(CNET_PACKET_KCP);
  config.kcp.stream_mode = true;
  reject_packet_channel(&endpoint, &config, &terminal); /* Tagged messages require boundaries. */

  config = policy_packet_config(CNET_PACKET_KCP);
  config.kcp.mtu = 1200u;
  config.security.mode = CNET_KCP_SECURITY_PSK_V1;
  reject_packet_channel(&endpoint, &config, &terminal); /* Zero PSK cannot authenticate. */
  config.security.pre_shared_key[0] = 0x5au;
  config.datagram.max_datagram_bytes = 1200u;
  reject_packet_channel(&endpoint, &config, &terminal); /* FEC/record expansion exceeds budget. */

  /* Nonnegative controls use the real packet endpoint and the same stop/drain. */
  config = policy_packet_config(CNET_PACKET_UDP);
  check(cnet_packet_endpoint_init_ex(&endpoint, &config, &terminal) == SALTS_OK);
  if (endpoint.impl != NULL) {
    check(cnet_packet_endpoint_stop(&endpoint, 3000u) == SALTS_OK);
    check(cnet_packet_endpoint_destroy(&endpoint) == SALTS_OK);
  }
  check(endpoint.impl == NULL);

  config = policy_packet_config(CNET_PACKET_KCP);
  check(cnet_packet_endpoint_init_ex(&endpoint, &config, &terminal) == SALTS_OK);
  if (endpoint.impl != NULL) {
    check(cnet_packet_endpoint_stop(&endpoint, 3000u) == SALTS_OK);
    check(cnet_packet_endpoint_destroy(&endpoint) == SALTS_OK);
  }
  check(endpoint.impl == NULL);

  config = policy_packet_config(CNET_PACKET_KCP);
  config.kcp.mtu = 1200u;
  config.security.mode = CNET_KCP_SECURITY_PSK_V1;
  config.security.pre_shared_key[0] = 0x5au;
  check(cnet_packet_endpoint_init_ex(&endpoint, &config, &terminal) == SALTS_OK);
  if (endpoint.impl != NULL) {
    check(cnet_packet_endpoint_stop(&endpoint, 3000u) == SALTS_OK);
    check(cnet_packet_endpoint_destroy(&endpoint) == SALTS_OK);
  }
  check(endpoint.impl == NULL);
}

typedef struct policy_secure_probe {
  unsigned wire_count;
  unsigned received_count;
  unsigned established_count;
} policy_secure_probe;

static int policy_secure_wire(void *user, cnet_secure_kcp *session,
                              const void *data, size_t size) {
  policy_secure_probe *probe = (policy_secure_probe *)user;
  (void)session;
  if (data == NULL || size == 0u) return SALTS_EINVAL;
  ++probe->wire_count;
  return SALTS_OK;
}
static void policy_secure_received(void *user, cnet_secure_kcp *session,
                                   const cnet_receive_view *view) {
  policy_secure_probe *probe = (policy_secure_probe *)user;
  (void)session;
  (void)view;
  ++probe->received_count;
}
static void policy_secure_established(void *user, cnet_secure_kcp *session) {
  policy_secure_probe *probe = (policy_secure_probe *)user;
  (void)session;
  ++probe->established_count;
}

static void secure_channel_ready_contract(void) {
  cnet_secure_kcp session = {0};
  cnet_secure_kcp_config config = CNET_SECURE_KCP_CONFIG_INIT;
  policy_secure_probe probe = {0};
  uint32_t conversation = 11u;
  const unsigned char message = 0x7au;

  config.role = CNET_SECURE_KCP_CLIENT;
  config.kcp.mtu = 1200u;
  config.security.mode = CNET_KCP_SECURITY_PSK_V1;
  config.security.pre_shared_key[0] = 0x5au;
  config.observer.output = policy_secure_wire;
  config.observer.on_receive = policy_secure_received;
  config.observer.on_established = policy_secure_established;
  config.observer.user = &probe;

  check(cnet_secure_kcp_init(&session, &config) == SALTS_OK);
  if (session.impl == NULL) return;
  check(cnet_secure_kcp_start(&session, 10u) == SALTS_OK);
  check(probe.wire_count != 0u);
  check(!cnet_secure_kcp_established(&session));
  check(cnet_secure_kcp_conversation(&session, &conversation) == SALTS_EBUSY);
  check(conversation == 0u);
  check(cnet_secure_kcp_send(&session, &message, sizeof message) == SALTS_EBUSY);
  check(probe.received_count == 0u && probe.established_count == 0u);
  check(cnet_secure_kcp_destroy(&session) == SALTS_OK);
  check(session.impl == NULL);
}


/*
 * M2: two genuinely bound CNet UDP/KCP endpoints on the one test thread.
 * Each endpoint drives its own *existing* NativeIO owner; no mock peer,
 * replacement queue, timer thread or second observe pass is introduced.
 * Contrast a local UDP terminal with peer-ACKed KCP logical-message terminal.
 */
typedef struct policy_loopback_probe {
  cnet_packet_protocol protocol;
  uint32_t conversation;
  cnet_packet_session session;
  unsigned admitted;
  unsigned opened;
  unsigned connecting;
  unsigned closed;
  unsigned received;
  unsigned terminals;
  unsigned errors;
  int last_error;
  int terminal_status;
  uint64_t terminal_tag;
  size_t terminal_size;
  cnet_packet_session terminal_session;
  cnet_message_kind receive_kind;
  size_t receive_size;
  unsigned char receive_data[32];
} policy_loopback_probe;

static int policy_loopback_admit(void *user, cnet_packet_endpoint *endpoint,
                                 cnet_packet_protocol protocol,
                                 const cnet_datagram_peer *peer, uint32_t conversation) {
  policy_loopback_probe *probe = (policy_loopback_probe *)user;
  (void)endpoint;
  if (peer == NULL || peer->family != CNET_DATAGRAM_ADDRESS_IPV4 ||
      peer->address[0] != 127u || peer->address[1] != 0u ||
      peer->address[2] != 0u || peer->address[3] != 1u ||
      peer->port == 0u || protocol != probe->protocol ||
      conversation != probe->conversation)
    return SALTS_EPERM;
  ++probe->admitted;
  return SALTS_OK;
}

static void policy_loopback_state(void *user, cnet_packet_endpoint *endpoint,
                                  cnet_packet_session session,
                                  cnet_packet_session_state state,
                                  const cnet_datagram_peer *peer, uint32_t conversation) {
  policy_loopback_probe *probe = (policy_loopback_probe *)user;
  (void)endpoint;
  (void)peer;
  (void)conversation;
  if (state == CNET_PACKET_SESSION_OPEN) {
    probe->session = session;
    ++probe->opened;
  } else if (state == CNET_PACKET_SESSION_CONNECTING) {
    ++probe->connecting;
  } else if (state == CNET_PACKET_SESSION_CLOSED) {
    ++probe->closed;
  }
}

static void policy_loopback_receive(void *user, cnet_packet_endpoint *endpoint,
                                    cnet_packet_session session,
                                    const cnet_receive_view *view) {
  policy_loopback_probe *probe = (policy_loopback_probe *)user;
  (void)endpoint;
  probe->session = session;
  ++probe->received;
  if (view == NULL || view->data == NULL ||
      view->size > sizeof(probe->receive_data)) {
    ++probe->errors;
    return;
  }
  probe->receive_kind = view->kind;
  probe->receive_size = view->size;
  memcpy(probe->receive_data, view->data, view->size);
}

static void policy_loopback_error(void *user, cnet_packet_endpoint *endpoint,
                                  cnet_packet_session session, int status) {
  policy_loopback_probe *probe = (policy_loopback_probe *)user;
  (void)endpoint;
  (void)session;
  ++probe->errors;
  probe->last_error = status;
}

static void policy_loopback_terminal(void *user, cnet_packet_endpoint *endpoint,
                                     cnet_packet_session session, size_t size,
                                     int status, uint64_t tag) {
  policy_loopback_probe *probe = (policy_loopback_probe *)user;
  (void)endpoint;
  ++probe->terminals;
  probe->terminal_status = status;
  probe->terminal_tag = tag;
  probe->terminal_size = size;
  probe->terminal_session = session;
}

static cnet_datagram_peer policy_loopback_peer(uint16_t port) {
  cnet_datagram_peer peer = {0};
  peer.family = CNET_DATAGRAM_ADDRESS_IPV4;
  peer.port = port;
  peer.address[0] = 127u;
  peer.address[3] = 1u;
  return peer;
}

static int policy_loopback_drive(cnet_packet_endpoint *endpoint) {
  size_t events = 0u;
  return cnet_packet_poll(endpoint, 5u, &events);
}

static int policy_loopback_pair(cnet_packet_protocol protocol, bool secure) {
  const unsigned char payload[] = {0x52u, 0x43u, 0x4eu, 0x45u, 0x54u};
  const uint64_t tag = UINT64_C(0x5a26abcdef123456);
  const uint32_t conversation = protocol == CNET_PACKET_KCP && !secure
                                    ? UINT32_C(0x12345678) : 0u;
  cnet_packet_endpoint client = {0}, server = {0};
  cnet_packet_endpoint_config client_config = policy_packet_config(protocol);
  cnet_packet_endpoint_config server_config = policy_packet_config(protocol);
  cnet_packet_terminal_config terminal = CNET_PACKET_TERMINAL_CONFIG_INIT;
  policy_loopback_probe outbound = {0}, inbound = {0};
  cnet_packet_session session = {0};
  cnet_packet_session_info info = {0};
  cnet_datagram_peer peer;
  uint16_t client_port = 0u, server_port = 0u;
  uint64_t deadline;
  int failure = 0;
  int stop_status;
  const bool is_kcp = protocol == CNET_PACKET_KCP;
#define PAIR_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)

  outbound.protocol = protocol;
  inbound.protocol = protocol;
  inbound.conversation = conversation;
  client_config.datagram.send_capacity = 8u;
  client_config.datagram.request_capacity = 16u;
  client_config.datagram.completion_batch_capacity = 16u;
  server_config.datagram.send_capacity = 8u;
  server_config.datagram.request_capacity = 16u;
  server_config.datagram.completion_batch_capacity = 16u;
  client_config.observer.on_state = policy_loopback_state;
  client_config.observer.on_receive = policy_loopback_receive;
  client_config.observer.on_error = policy_loopback_error;
  client_config.observer.user = &outbound;
  server_config.observer.on_admit = policy_loopback_admit;
  server_config.observer.on_state = policy_loopback_state;
  server_config.observer.on_receive = policy_loopback_receive;
  server_config.observer.on_error = policy_loopback_error;
  server_config.observer.user = &inbound;

  terminal.send_capacity = 4u;
  terminal.on_send = policy_loopback_terminal;
  terminal.user = &outbound;
  if (secure) {
    PAIR_REQUIRE(is_kcp);
    client_config.kcp.mtu = 1200u;
    server_config.kcp.mtu = 1200u;
    client_config.security.mode = CNET_KCP_SECURITY_PSK_V1;
    server_config.security.mode = CNET_KCP_SECURITY_PSK_V1;
    client_config.security.pre_shared_key[0] = 0x5au;
    server_config.security.pre_shared_key[0] = 0x5au;
  }
  PAIR_REQUIRE(cnet_packet_endpoint_init_ex(&client, &client_config, &terminal) == SALTS_OK);
  terminal.user = &inbound;
  PAIR_REQUIRE(cnet_packet_endpoint_init_ex(&server, &server_config, &terminal) == SALTS_OK);
  PAIR_REQUIRE(cnet_packet_endpoint_port(&client, &client_port) == SALTS_OK &&
               client_port != 0u);
  PAIR_REQUIRE(cnet_packet_endpoint_port(&server, &server_port) == SALTS_OK &&
               server_port != 0u);
  peer = policy_loopback_peer(server_port);
  PAIR_REQUIRE(cnet_packet_session_open(&client, &peer, conversation, &session) == SALTS_OK);
  PAIR_REQUIRE(cnet_packet_session_valid(session));
  PAIR_REQUIRE(cnet_packet_session_get_info(&client, session, &info) == SALTS_OK);
  PAIR_REQUIRE(info.protocol == protocol && info.peer.port == server_port &&
               info.conversation == conversation);

  if (secure) {
    /* Native wire hello is not an authenticated channel or application READY. */
    PAIR_REQUIRE(outbound.connecting == 1u && outbound.opened == 0u);
    PAIR_REQUIRE(cnet_packet_send_tagged(&client, session, payload,
                                        sizeof(payload), tag) == SALTS_EBUSY);
    PAIR_REQUIRE(outbound.terminals == 0u);
    deadline = cmeta_monotonic_ms() + 8000u;
    while ((outbound.opened == 0u || inbound.opened == 0u) &&
           cmeta_monotonic_ms() < deadline) {
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
      PAIR_REQUIRE(outbound.errors == 0u && inbound.errors == 0u);
    }
    PAIR_REQUIRE(outbound.opened == 1u && inbound.opened == 1u);
    PAIR_REQUIRE(inbound.admitted == 1u);
    PAIR_REQUIRE(cnet_packet_session_get_info(&client, session, &info) == SALTS_OK &&
                 info.conversation != 0u); /* Session-derived KCP conversation. */
  } else {
    PAIR_REQUIRE(outbound.opened == 1u);
  }

  PAIR_REQUIRE(cnet_packet_send_tagged(&client, session, payload,
                                      sizeof(payload), tag) == SALTS_OK);
  PAIR_REQUIRE(outbound.terminals == 0u);
  deadline = cmeta_monotonic_ms() + 8000u;
  if (!is_kcp) {
    /* UDP terminal is local: the peer has NOT been progressed or delivered. */
    while (outbound.terminals == 0u && cmeta_monotonic_ms() < deadline)
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
    PAIR_REQUIRE(outbound.terminals == 1u && inbound.received == 0u);
    while (inbound.received == 0u && cmeta_monotonic_ms() < deadline)
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
  } else {
    /* KCP cannot terminal before this peer has received and emitted an ACK. */
    while (inbound.received == 0u && cmeta_monotonic_ms() < deadline) {
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
      PAIR_REQUIRE(outbound.errors == 0u && inbound.errors == 0u);
    }
    PAIR_REQUIRE(inbound.received == 1u && outbound.terminals == 0u);
    while (outbound.terminals == 0u && cmeta_monotonic_ms() < deadline) {
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
      PAIR_REQUIRE(outbound.errors == 0u && inbound.errors == 0u);
    }
  }
  PAIR_REQUIRE(inbound.received == 1u && inbound.admitted == 1u);
  PAIR_REQUIRE(inbound.opened == 1u);
  PAIR_REQUIRE(inbound.receive_kind == (is_kcp ? CNET_MESSAGE_BYTES : CNET_MESSAGE_DATAGRAM));
  PAIR_REQUIRE(inbound.receive_size == sizeof(payload) &&
               memcmp(inbound.receive_data, payload, sizeof(payload)) == 0);
  PAIR_REQUIRE(outbound.terminals == 1u &&
               outbound.terminal_status == SALTS_OK &&
               outbound.terminal_tag == tag &&
               outbound.terminal_size == sizeof(payload) &&
               outbound.terminal_session.slot == session.slot &&
               outbound.terminal_session.generation == session.generation);
  PAIR_REQUIRE(outbound.errors == 0u && inbound.errors == 0u);

  /* A session generation closes independently of its shared UDP socket. */
  PAIR_REQUIRE(cnet_packet_session_close(&client, session) == SALTS_OK);
  PAIR_REQUIRE(cnet_packet_session_get_info(&client, session, &info) == SALTS_ENOENT);
cleanup:
  if (client.impl != NULL) {
    stop_status = cnet_packet_endpoint_stop(&client, 4000u);
    if (stop_status == SALTS_ETIMEDOUT)
      stop_status = cnet_packet_endpoint_stop(&client, 4000u);
    if (stop_status != SALTS_OK && failure == 0) failure = __LINE__;
    if (stop_status != SALTS_ETIMEDOUT) {
      if (cnet_packet_endpoint_destroy(&client) != SALTS_OK && failure == 0)
        failure = __LINE__;
    }
  }
  if (server.impl != NULL) {
    stop_status = cnet_packet_endpoint_stop(&server, 4000u);
    if (stop_status == SALTS_ETIMEDOUT)
      stop_status = cnet_packet_endpoint_stop(&server, 4000u);
    if (stop_status != SALTS_OK && failure == 0) failure = __LINE__;
    if (stop_status != SALTS_ETIMEDOUT) {
      if (cnet_packet_endpoint_destroy(&server) != SALTS_OK && failure == 0)
        failure = __LINE__;
    }
  }
#undef PAIR_REQUIRE
  return failure;
}

spec("CNet native policy and channel admission") {
  it("preserves destination policy validation and strict-key no-downgrade") {
    destination_contract();
  }
  it("preserves owner placement selection and version rejection") {
    owner_contract();
  }
  it("preserves reconnect lifecycle, deadlines and security shutdown") {
    recovery_contract();
  }
  it("rejects unsupported stream/TLS channel recipes with no partial handle") {
    stream_channel_admission_contract();
  }
  it("checks real UDP/KCP/PSK/FEC admission and Owner resource bounds") {
    packet_channel_admission_contract();
  }
  it("blocks secure KCP application data until authenticated channel READY") {
    secure_channel_ready_contract();
  }
  it("contrasts real UDP local send terminal with peer-delivered datagrams") {
    const int failed = policy_loopback_pair(CNET_PACKET_UDP, false);
    check(failed == 0, "UDP packet endpoint: failed source line %d", failed);
  }
  it("requires real KCP peer ACK before logical-send terminal") {
    const int failed = policy_loopback_pair(CNET_PACKET_KCP, false);
    check(failed == 0, "KCP packet endpoint: failed source line %d", failed);
  }
  it("requires secure KCP handshake READY and authenticated protocol ACK") {
    const int failed = policy_loopback_pair(CNET_PACKET_KCP, true);
    check(failed == 0, "Secure KCP packet endpoint: failed source line %d", failed);
  }
}
