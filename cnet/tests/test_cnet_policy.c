#include <cnet/cnet.h>
#include <cnet/client_pool.h>
#include <cnet/handoff.h>
#include <cnet/managed_dial.h>
#include <stdlib.h>
#include <core/clock.h>
#include <cnet/destination_policy.h>
#include <cnet/owner_placement.h>
#include <cnet/recovery_policy.h>
#include <core/error_codes.h>
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
  unsigned terminals_at_close;
  cnet_packet_session closed_session;
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
    probe->terminals_at_close = probe->terminals;
    probe->closed_session = session;
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
    deadline = monotonic_ms() + 8000u;
    while ((outbound.opened == 0u || inbound.opened == 0u) &&
           monotonic_ms() < deadline) {
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
  deadline = monotonic_ms() + 8000u;
  if (!is_kcp) {
    /* UDP terminal is local: the peer has NOT been progressed or delivered. */
    while (outbound.terminals == 0u && monotonic_ms() < deadline)
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
    PAIR_REQUIRE(outbound.terminals == 1u && inbound.received == 0u);
    while (inbound.received == 0u && monotonic_ms() < deadline)
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
  } else {
    /* KCP cannot terminal before this peer has received and emitted an ACK. */
    while (inbound.received == 0u && monotonic_ms() < deadline) {
      PAIR_REQUIRE(policy_loopback_drive(&client) == SALTS_OK);
      PAIR_REQUIRE(policy_loopback_drive(&server) == SALTS_OK);
      PAIR_REQUIRE(outbound.errors == 0u && inbound.errors == 0u);
    }
    PAIR_REQUIRE(inbound.received == 1u && outbound.terminals == 0u);
    while (outbound.terminals == 0u && monotonic_ms() < deadline) {
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

/* Keep callback storage alive even if an unexpected stop timeout prevents
 * destruction. All normal paths must stop and destroy every real endpoint. */
typedef struct policy_packet_lifecycle {
  cnet_packet_endpoint endpoints[3];
  policy_loopback_probe probes[3];
  cnet_datagram wire_peer;
  uint16_t source_port;
  unsigned pushes, wire_errors;
} policy_packet_lifecycle;

static int policy_lifecycle_init(policy_packet_lifecycle *fixture, size_t index,
                                  cnet_packet_protocol protocol) {
  cnet_packet_endpoint_config config = policy_packet_config(protocol);
  cnet_packet_terminal_config terminal = CNET_PACKET_TERMINAL_CONFIG_INIT;
  policy_loopback_probe *probe = &fixture->probes[index];
  probe->protocol = protocol;
  config.observer = (cnet_packet_observer){policy_loopback_admit, policy_loopback_state,
      policy_loopback_receive, policy_loopback_error, probe};
  terminal.send_capacity = 2u;
  terminal.on_send = policy_loopback_terminal;
  terminal.user = probe;
  return cnet_packet_endpoint_init_ex(&fixture->endpoints[index], &config, &terminal);
}

static int policy_lifecycle_cleanup(policy_packet_lifecycle *fixture, int failure) {
  bool drained = true;
  for (size_t i = 0u; i < 3u; ++i) {
    if (fixture->endpoints[i].impl == NULL) continue;
    const int status = cnet_packet_endpoint_stop(&fixture->endpoints[i], 4000u);
    if (status != SALTS_OK && failure == 0) failure = __LINE__;
    if (cnet_packet_endpoint_destroy(&fixture->endpoints[i]) != SALTS_OK) {
      drained = false;
      if (failure == 0) failure = __LINE__;
    }
  }
  if (fixture->wire_peer.impl != NULL) {
    const int status = cnet_datagram_stop(&fixture->wire_peer, 4000u);
    if (status != SALTS_OK && failure == 0) failure = __LINE__;
    if (cnet_datagram_destroy(&fixture->wire_peer) != SALTS_OK) {
      drained = false;
      if (failure == 0) failure = __LINE__;
    }
  }
  if (drained) free(fixture);
  return failure;
}

static bool policy_same_session(cnet_packet_session a, cnet_packet_session b) {
  return a.slot == b.slot && a.generation == b.generation;
}

static int policy_kcp_passive_start(void) {
  policy_packet_lifecycle *fixture = calloc(1u, sizeof(*fixture));
  if (fixture == NULL) return __LINE__;
  cnet_packet_endpoint *wire = &fixture->endpoints[0];
  cnet_packet_endpoint *server = &fixture->endpoints[1];
  policy_loopback_probe *rx = &fixture->probes[1];
  cnet_packet_session wire_session;
  uint16_t port;
  int failure = 0;
  /* Wire records from the same UDP source and conversation as the new peer. */
  static const unsigned char ack[24] = {0x78, 0x56, 0x34, 0x12, 82};
  static const unsigned char later_push[25] = {
      0x78, 0x56, 0x34, 0x12, 81, [6] = 32, [12] = 3, [20] = 1, [24] = 'x'};
  static const unsigned char first_push[25] = {
      0x78, 0x56, 0x34, 0x12, 81, [6] = 32, [20] = 1, [24] = 'a'};
#define PASSIVE_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)
  PASSIVE_REQUIRE(policy_lifecycle_init(fixture, 0u, CNET_PACKET_UDP) == SALTS_OK);
  PASSIVE_REQUIRE(policy_lifecycle_init(fixture, 1u, CNET_PACKET_KCP) == SALTS_OK);
  rx->conversation = UINT32_C(0x12345678);
  PASSIVE_REQUIRE(cnet_packet_endpoint_port(server, &port) == SALTS_OK && port != 0u);
  const cnet_datagram_peer peer = policy_loopback_peer(port);
  PASSIVE_REQUIRE(cnet_packet_session_open(wire, &peer, 0u, &wire_session) == SALTS_OK);
  const unsigned char *records[] = {ack, later_push, first_push};
  const size_t sizes[] = {sizeof(ack), sizeof(later_push), sizeof(first_push)};
  for (size_t i = 0u; i < sizeof(records) / sizeof(records[0]); ++i) {
    size_t events = 0u;
    PASSIVE_REQUIRE(cnet_packet_send_tagged(wire, wire_session, records[i], sizes[i], i + 1u) ==
                    SALTS_OK);
    const uint64_t deadline = monotonic_ms() + 5000u;
    do {
      PASSIVE_REQUIRE(policy_loopback_drive(wire) == SALTS_OK);
      PASSIVE_REQUIRE(cnet_packet_poll(server, 5u, &events) == SALTS_OK);
    } while (events == 0u && monotonic_ms() < deadline);
    PASSIVE_REQUIRE(events != 0u);
    if (i < 2u)
      PASSIVE_REQUIRE(rx->admitted == 0u && rx->opened == 0u && rx->received == 0u);
  }
  PASSIVE_REQUIRE(rx->admitted == 1u && rx->opened == 1u && rx->received == 1u &&
                  rx->receive_size == 1u && rx->receive_data[0] == 'a' && rx->errors == 0u);
cleanup:
#undef PASSIVE_REQUIRE
  return policy_lifecycle_cleanup(fixture, failure);
}

static int policy_kcp_unreachable_peer(void) {
  policy_packet_lifecycle *fixture = calloc(1u, sizeof(*fixture));
  if (fixture == NULL) return __LINE__;
  cnet_packet_endpoint *client = &fixture->endpoints[0];
  cnet_packet_endpoint *closed = &fixture->endpoints[1];
  cnet_packet_endpoint *server = &fixture->endpoints[2];
  policy_loopback_probe *tx = &fixture->probes[0];
  policy_loopback_probe *rx = &fixture->probes[2];
  const uint32_t conversation = UINT32_C(0x12345678);
  const unsigned char data = 0x55u;
  cnet_packet_session absent, healthy;
  uint16_t closed_port, server_port;
  int failure = 0;
#define UNREACHABLE_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)
  UNREACHABLE_REQUIRE(policy_lifecycle_init(fixture, 0u, CNET_PACKET_KCP) == SALTS_OK);
  UNREACHABLE_REQUIRE(policy_lifecycle_init(fixture, 1u, CNET_PACKET_UDP) == SALTS_OK);
  UNREACHABLE_REQUIRE(policy_lifecycle_init(fixture, 2u, CNET_PACKET_KCP) == SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_endpoint_port(closed, &closed_port) == SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_endpoint_port(server, &server_port) == SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_endpoint_stop(closed, 4000u) == SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_endpoint_destroy(closed) == SALTS_OK);
  const cnet_datagram_peer closed_peer = policy_loopback_peer(closed_port);
  const cnet_datagram_peer server_peer = policy_loopback_peer(server_port);
  rx->conversation = conversation;
  UNREACHABLE_REQUIRE(cnet_packet_session_open(client, &closed_peer, conversation, &absent) ==
                      SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_send_tagged(client, absent, &data, 1u, 1u) == SALTS_OK);
  uint64_t deadline = monotonic_ms() + 250u;
  do {
    UNREACHABLE_REQUIRE(policy_loopback_drive(client) == SALTS_OK);
  } while (monotonic_ms() < deadline);
  UNREACHABLE_REQUIRE(tx->terminals == 0u && tx->errors == 0u);

  UNREACHABLE_REQUIRE(cnet_packet_session_open(client, &server_peer, conversation, &healthy) ==
                      SALTS_OK);
  UNREACHABLE_REQUIRE(cnet_packet_send_tagged(client, healthy, &data, 1u, 2u) == SALTS_OK);
  deadline = monotonic_ms() + 5000u;
  while (tx->terminals == 0u && monotonic_ms() < deadline) {
    UNREACHABLE_REQUIRE(policy_loopback_drive(server) == SALTS_OK);
    UNREACHABLE_REQUIRE(policy_loopback_drive(client) == SALTS_OK);
  }
  UNREACHABLE_REQUIRE(rx->received == 1u && rx->receive_size == 1u &&
                      rx->receive_data[0] == data && rx->errors == 0u);
  UNREACHABLE_REQUIRE(tx->terminals == 1u && tx->terminal_tag == 2u &&
                      tx->terminal_status == SALTS_OK && tx->errors == 0u);
cleanup:
#undef UNREACHABLE_REQUIRE
  return policy_lifecycle_cleanup(fixture, failure);
}

static int policy_udp_generation_drain(void) {
  policy_packet_lifecycle *fixture = calloc(1u, sizeof(*fixture));
  cnet_packet_session old = {0}, neighbor = {0}, replacement = {0}, rejected = {0};
  cnet_packet_session_info info;
  cnet_datagram_peer peers[3];
  const unsigned char payloads[] = {0xa1u, 0xb2u, 0xc3u};
  uint64_t deadline;
  int failure = 0;
  if (fixture == NULL) return __LINE__;
  cnet_packet_endpoint *client = &fixture->endpoints[0];
  policy_loopback_probe *probe = &fixture->probes[0];
#define LIFECYCLE_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)
  for (size_t i = 0u; i < 3u; ++i) {
    uint16_t port = 0u;
    LIFECYCLE_REQUIRE(policy_lifecycle_init(fixture, i, CNET_PACKET_UDP) == SALTS_OK);
    LIFECYCLE_REQUIRE(cnet_packet_endpoint_port(&fixture->endpoints[i], &port) == SALTS_OK && port != 0u);
    peers[i] = policy_loopback_peer(port);
  }
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peers[1], 0u, &old) == SALTS_OK);
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peers[2], 0u, &neighbor) == SALTS_OK);
  LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, old, &payloads[0], 1u, 101u) == SALTS_OK);
  /* No owner poll has observed the real UDP terminal yet. Closing must keep
   * its key/slot reserved instead of recycling storage under that write. */
  LIFECYCLE_REQUIRE(probe->terminals == 0u && probe->closed == 0u);
  LIFECYCLE_REQUIRE(cnet_packet_session_close(client, old) == SALTS_OK);
  LIFECYCLE_REQUIRE(probe->terminals == 0u && probe->closed == 0u);
  LIFECYCLE_REQUIRE(cnet_packet_session_get_info(client, old, &info) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, old, &payloads[0], 1u, 999u) == SALTS_ESHUTDOWN);
  LIFECYCLE_REQUIRE(cnet_packet_session_close(client, old) == SALTS_EALREADY);
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peers[1], 0u, &rejected) == SALTS_EALREADY);
  LIFECYCLE_REQUIRE(!cnet_packet_session_valid(rejected));
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peers[0], 0u, &rejected) == SALTS_ENOBUFS);
  LIFECYCLE_REQUIRE(!cnet_packet_session_valid(rejected));
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_destroy(client) == SALTS_EBUSY);
  deadline = monotonic_ms() + 5000u;
  while (probe->closed == 0u && monotonic_ms() < deadline)
    LIFECYCLE_REQUIRE(policy_loopback_drive(client) == SALTS_OK);
  LIFECYCLE_REQUIRE(probe->closed == 1u && probe->terminals == 1u && probe->terminals_at_close == 1u);
  LIFECYCLE_REQUIRE(policy_same_session(probe->closed_session, old) &&
      policy_same_session(probe->terminal_session, old) && probe->terminal_tag == 101u &&
      probe->terminal_status == SALTS_OK && probe->terminal_size == 1u);
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peers[1], 0u, &replacement) == SALTS_OK);
  LIFECYCLE_REQUIRE(replacement.slot == old.slot && replacement.generation != old.generation);
  LIFECYCLE_REQUIRE(cnet_packet_session_get_info(client, old, &info) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(cnet_packet_session_close(client, old) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(cnet_packet_send(client, old, &payloads[0], 1u) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, old, &payloads[0], 1u, 999u) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(probe->terminals == 1u && probe->closed == 1u);
  LIFECYCLE_REQUIRE(cnet_packet_session_get_info(client, replacement, &info) == SALTS_OK && info.peer.port == peers[1].port);
  LIFECYCLE_REQUIRE(cnet_packet_session_get_info(client, neighbor, &info) == SALTS_OK && info.peer.port == peers[2].port);
  /* Prove the old copied datagram really reached its peer independently of
   * local completion, then use both the neighbor and the recycled slot. */
  deadline = monotonic_ms() + 5000u;
  while (fixture->probes[1].received == 0u && monotonic_ms() < deadline)
    LIFECYCLE_REQUIRE(policy_loopback_drive(&fixture->endpoints[1]) == SALTS_OK);
  LIFECYCLE_REQUIRE(fixture->probes[1].received == 1u && fixture->probes[1].receive_size == 1u &&
      fixture->probes[1].receive_data[0] == payloads[0]);
  for (size_t i = 1u; i < 3u; ++i) {
    const size_t receiver = i == 1u ? 2u : 1u;
    const cnet_packet_session session = i == 1u ? neighbor : replacement;
    LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, session, &payloads[i], 1u, 101u + i) == SALTS_OK);
    deadline = monotonic_ms() + 5000u;
    while ((probe->terminals != i + 1u || fixture->probes[receiver].received != i) &&
           monotonic_ms() < deadline) {
      LIFECYCLE_REQUIRE(policy_loopback_drive(client) == SALTS_OK);
      LIFECYCLE_REQUIRE(policy_loopback_drive(&fixture->endpoints[receiver]) == SALTS_OK);
    }
    LIFECYCLE_REQUIRE(probe->terminals == i + 1u && probe->terminal_tag == 101u + i &&
        probe->terminal_status == SALTS_OK && policy_same_session(probe->terminal_session, session));
    LIFECYCLE_REQUIRE(fixture->probes[receiver].received == i &&
        fixture->probes[receiver].receive_size == 1u && fixture->probes[receiver].receive_data[0] == payloads[i]);
  }
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_stop(client, 4000u) == SALTS_OK);
  LIFECYCLE_REQUIRE(probe->closed == 3u && probe->terminals == 3u && probe->terminals_at_close == 3u);
  for (size_t i = 0u; i < 3u; ++i) LIFECYCLE_REQUIRE(fixture->probes[i].errors == 0u);
cleanup:
#undef LIFECYCLE_REQUIRE
  return policy_lifecycle_cleanup(fixture, failure);
}

static void policy_kcp_unacked_wire(void *user, cnet_datagram *datagram,
                                    const cnet_datagram_peer *peer, const cnet_receive_view *view) {
  policy_packet_lifecycle *fixture = user;
  const unsigned char *bytes = view->data;
  (void)datagram;
  /* One real single-segment PUSH, conversation 0x12345678, SN 0. Its timestamp
   * may change on retransmission; the payload and logical sequence do not. */
  const unsigned char conversation[] = {0x78u, 0x56u, 0x34u, 0x12u};
  if (peer->port != fixture->source_port || view->size != 25u ||
      memcmp(bytes, conversation, sizeof(conversation)) != 0 || bytes[4] != 81u || bytes[5] != 0u ||
      bytes[12] != 0u || bytes[13] != 0u || bytes[14] != 0u || bytes[15] != 0u ||
      bytes[20] != 1u || bytes[21] != 0u || bytes[22] != 0u || bytes[23] != 0u || bytes[24] != 0xadu) {
    ++fixture->wire_errors;
    return;
  }
  ++fixture->pushes; /* Deliberately no ACK: a local UDP terminal is insufficient. */
}

static void policy_kcp_unexpected_send(void *user, cnet_datagram *datagram,
                                       const cnet_datagram_peer *peer, size_t size, int status, uint64_t tag) {
  policy_packet_lifecycle *fixture = user;
  (void)datagram; (void)peer; (void)size; (void)status; (void)tag;
  ++fixture->wire_errors; /* This independent peer only receives, never ACKs. */
}

static int policy_kcp_retransmission_stop(void) {
  policy_packet_lifecycle *fixture = calloc(1u, sizeof(*fixture));
  cnet_packet_endpoint_config config = policy_packet_config(CNET_PACKET_KCP);
  cnet_datagram_config wire_config = config.datagram;
  cnet_packet_session session = {0}, rejected = {0};
  const unsigned char payload = 0xadu;
  cnet_datagram_peer peer;
  uint16_t port = 0u;
  uint64_t deadline;
  size_t events = 0u;
  int failure = 0;
  if (fixture == NULL) return __LINE__;
  cnet_packet_endpoint *client = &fixture->endpoints[0];
  policy_loopback_probe *probe = &fixture->probes[0];
#define LIFECYCLE_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)
  LIFECYCLE_REQUIRE(policy_lifecycle_init(fixture, 0u, CNET_PACKET_KCP) == SALTS_OK);
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_port(client, &fixture->source_port) == SALTS_OK);
  wire_config.observer = (cnet_datagram_observer){policy_kcp_unacked_wire, policy_kcp_unexpected_send, fixture};
  LIFECYCLE_REQUIRE(cnet_datagram_init(&fixture->wire_peer, &wire_config) == SALTS_OK);
  LIFECYCLE_REQUIRE(cnet_datagram_port(&fixture->wire_peer, &port) == SALTS_OK && port != 0u);
  LIFECYCLE_REQUIRE(cnet_datagram_receive(&fixture->wire_peer, 8u) == SALTS_OK);
  peer = policy_loopback_peer(port);
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peer, UINT32_C(0x12345678), &session) == SALTS_OK);
  LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, session, &payload, 1u, 201u) == SALTS_OK);
  deadline = monotonic_ms() + 5000u;
  while (fixture->pushes < 2u && monotonic_ms() < deadline) {
    LIFECYCLE_REQUIRE(policy_loopback_drive(client) == SALTS_OK);
    LIFECYCLE_REQUIRE(cnet_datagram_poll(&fixture->wire_peer, 5u, &events) == SALTS_OK);
    LIFECYCLE_REQUIRE(fixture->wire_errors == 0u && probe->terminals == 0u && probe->errors == 0u);
  }
  LIFECYCLE_REQUIRE(fixture->pushes >= 2u && probe->closed == 0u);
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_destroy(client) == SALTS_EBUSY);
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_stop(client, 4000u) == SALTS_OK);
  LIFECYCLE_REQUIRE(probe->terminals == 1u && probe->terminal_status == SALTS_ECANCELED &&
      probe->terminal_tag == 201u && probe->terminal_size == 1u && policy_same_session(probe->terminal_session, session));
  LIFECYCLE_REQUIRE(probe->closed == 1u && probe->terminals_at_close == 1u &&
      policy_same_session(probe->closed_session, session) && probe->errors == 0u);
  LIFECYCLE_REQUIRE(cnet_packet_poll(client, 0u, &events) == SALTS_ESHUTDOWN && events == 0u);
  LIFECYCLE_REQUIRE(cnet_packet_session_open(client, &peer, UINT32_C(0x12345678), &rejected) == SALTS_ESHUTDOWN);
  LIFECYCLE_REQUIRE(!cnet_packet_session_valid(rejected));
  LIFECYCLE_REQUIRE(cnet_packet_send_tagged(client, session, &payload, 1u, 999u) == SALTS_ENOENT);
  LIFECYCLE_REQUIRE(cnet_packet_endpoint_stop(client, 0u) == SALTS_OK);
  LIFECYCLE_REQUIRE(probe->terminals == 1u && probe->closed == 1u);
cleanup:
#undef LIFECYCLE_REQUIRE
  return policy_lifecycle_cleanup(fixture, failure);
}

enum { POLICY_SHARED_PACKET_COUNT = 3u, POLICY_SHARED_BATCH_CAPACITY = 32u };

typedef struct policy_shared_packets {
  native_io_backend backend;
  cnet_packet_endpoint endpoints[POLICY_SHARED_PACKET_COUNT];
  policy_loopback_probe probes[POLICY_SHARED_PACKET_COUNT];
  bool corrupt_cancel_terminal;
} policy_shared_packets;

static int policy_shared_packet_init(policy_shared_packets *fixture, size_t index,
                                     cnet_packet_protocol protocol, bool secure) {
  cnet_packet_endpoint_config config = policy_packet_config(protocol);
  cnet_packet_terminal_config terminal = CNET_PACKET_TERMINAL_CONFIG_INIT;
  policy_loopback_probe *probe = &fixture->probes[index];
  probe->protocol = protocol;
  config.datagram.send_capacity = 8u;
  config.datagram.request_capacity = 12u;
  config.observer = (cnet_packet_observer){policy_loopback_admit, policy_loopback_state,
      policy_loopback_receive, policy_loopback_error, probe};
  terminal.send_capacity = 4u;
  terminal.on_send = policy_loopback_terminal;
  terminal.user = probe;
  if (secure) {
    config.kcp.mtu = 1200u;
    config.security.mode = CNET_KCP_SECURITY_PSK_V1;
    config.security.pre_shared_key[0] = 0x5au;
  }
  return cnet_packet_endpoint_init_external(&fixture->endpoints[index], &config,
                                             &terminal, &fixture->backend);
}

static int policy_shared_packet_step(policy_shared_packets *fixture) {
  native_io_completion batch[POLICY_SHARED_BATCH_CAPACITY];
  uint32_t wait_ms = 500u;
  size_t count = 0u;
  int first_error = SALTS_OK;
  for (size_t i = 0u; i < POLICY_SHARED_PACKET_COUNT; ++i) {
    cnet_packet_endpoint *endpoint = &fixture->endpoints[i];
    size_t events;
    uint32_t timeout;
    if (endpoint->impl == NULL) continue;
    int status = cnet_packet_advance_external(endpoint, 1u, &events);
    if (status != SALTS_OK && first_error == SALTS_OK) first_error = status;
    status = cnet_packet_external_timeout(endpoint, wait_ms, &timeout);
    if (status != SALTS_OK && first_error == SALTS_OK) first_error = status;
    if (status == SALTS_OK) wait_ms = timeout;
  }

  const int observed = native_io_backend_observe(&fixture->backend, batch,
      POLICY_SHARED_BATCH_CAPACITY, wait_ms, &count);
  if (observed == SALTS_ETIMEDOUT) return first_error;
  if (observed != SALTS_OK) return first_error == SALTS_OK ? observed : first_error;
  for (size_t n = 0u; n < count; ++n) {
    size_t owners = 0u;
    for (size_t i = 0u; i < POLICY_SHARED_PACKET_COUNT; ++i) {
      cnet_packet_endpoint *endpoint = &fixture->endpoints[i];
      bool consumed;
      size_t events;
      if (endpoint->impl == NULL) continue;
      native_io_completion completion = batch[n];
      const bool corrupt = i == 0u && fixture->corrupt_cancel_terminal &&
          completion.kind == NATIVE_IO_COMPLETION_CANCELLED && completion.user_data == 0u;
      if (corrupt) ++completion.user_data;
      int status = cnet_packet_route_external_completion(endpoint, &completion,
                                                          &consumed, &events);
      if (status != SALTS_OK && first_error == SALTS_OK) first_error = status;
      if (consumed) {
        ++owners;
        if (corrupt) fixture->corrupt_cancel_terminal = false;
        status = cnet_packet_route_external_completion(endpoint, &batch[n],
                                                        &consumed, &events);
      }
      if (first_error == SALTS_OK && (status != SALTS_OK || consumed || events != 0u))
        first_error = SALTS_EPROTO;
    }
    if (owners != 1u && first_error == SALTS_OK) first_error = SALTS_EPROTO;
  }
  return first_error;
}

static int policy_shared_packet_stop(policy_shared_packets *fixture, size_t index) {
  cnet_packet_endpoint *endpoint = &fixture->endpoints[index];
  const uint64_t deadline = monotonic_ms() + 5000u;
  bool stopped = false;
  int first_error = SALTS_OK;
  do {
    int status = cnet_packet_endpoint_stop_external(endpoint, &stopped);
    if (status != SALTS_OK && status != SALTS_EBUSY && first_error == SALTS_OK)
      first_error = status;
    if (stopped) return first_error;
    status = policy_shared_packet_step(fixture);
    if (status != SALTS_OK && first_error == SALTS_OK) first_error = status;
  } while (monotonic_ms() < deadline);
  return SALTS_ETIMEDOUT;
}

static int policy_shared_kcp(bool secure) {
  policy_shared_packets *fixture = calloc(1u, sizeof(*fixture));
  if (fixture == NULL) return __LINE__;
  cnet_packet_endpoint *client = &fixture->endpoints[0];
  cnet_packet_endpoint *server = &fixture->endpoints[1];
  cnet_packet_endpoint *neighbor = &fixture->endpoints[2];
  policy_loopback_probe *tx = &fixture->probes[0];
  policy_loopback_probe *rx = &fixture->probes[1];
  policy_loopback_probe *udp = &fixture->probes[2];
  const native_io_backend_config config = {
      .kind = policy_backend_kind(), .endpoint_capacity = POLICY_SHARED_PACKET_COUNT,
      .request_capacity = 48u, .completion_batch_capacity = POLICY_SHARED_BATCH_CAPACITY};
  const uint32_t conversation = secure ? 0u : UINT32_C(0x12345678);
  const unsigned char data[] = {0x46u, 0x4du, 0x51u};
  const unsigned char udp_data = 0x55u;
  cnet_packet_session session, unacked, udp_session;
  uint16_t port;
  uint32_t timeout;
  size_t events;
  int failure = 0;
  bool backend_open = false;
#define SHARED_REQUIRE(expr) do { if (!(expr)) { failure = __LINE__; goto cleanup; } } while (0)
  SHARED_REQUIRE(native_io_backend_init(&fixture->backend, &config) == SALTS_OK);
  backend_open = true;
  SHARED_REQUIRE(policy_shared_packet_init(fixture, 0u, CNET_PACKET_KCP, secure) == SALTS_OK);
  SHARED_REQUIRE(policy_shared_packet_init(fixture, 1u, CNET_PACKET_KCP, secure) == SALTS_OK);
  SHARED_REQUIRE(policy_shared_packet_init(fixture, 2u, CNET_PACKET_UDP, false) == SALTS_OK);
  rx->conversation = conversation;

  SHARED_REQUIRE(cnet_packet_poll(client, 0u, &events) == SALTS_ENOTSUP && events == 0u);
  SHARED_REQUIRE(cnet_packet_endpoint_stop(client, 0u) == SALTS_ENOTSUP);
  SHARED_REQUIRE(cnet_packet_advance_external(client, 0u, &events) == SALTS_EINVAL);
  SHARED_REQUIRE(cnet_packet_external_timeout(client, 500u, &timeout) == SALTS_OK &&
                 timeout == 500u);
  SHARED_REQUIRE(cnet_packet_endpoint_port(server, &port) == SALTS_OK && port != 0u);
  cnet_datagram_peer peer = policy_loopback_peer(port);
  SHARED_REQUIRE(cnet_packet_session_open(client, &peer, conversation, &session) == SALTS_OK);
  SHARED_REQUIRE(cnet_packet_external_timeout(client, 500u, &timeout) == SALTS_OK &&
                 timeout < 500u);

  uint64_t deadline = monotonic_ms() + 5000u;
  if (secure) {
    SHARED_REQUIRE(tx->connecting == 1u && tx->opened == 0u);
    SHARED_REQUIRE(cnet_packet_send_tagged(client, session, data, sizeof(data), 11u) == SALTS_EBUSY);
    while ((tx->opened == 0u || rx->opened == 0u) && monotonic_ms() < deadline)
      SHARED_REQUIRE(policy_shared_packet_step(fixture) == SALTS_OK);
    SHARED_REQUIRE(tx->opened == 1u && rx->opened == 1u);
  }
  SHARED_REQUIRE(cnet_packet_send_tagged(client, session, data, sizeof(data), 11u) == SALTS_OK);
  while (rx->received == 0u && monotonic_ms() < deadline)
    SHARED_REQUIRE(policy_shared_packet_step(fixture) == SALTS_OK);
  SHARED_REQUIRE(rx->received == 1u && tx->terminals == 0u);
  SHARED_REQUIRE(rx->receive_kind == CNET_MESSAGE_BYTES &&
                 rx->receive_size == sizeof(data) &&
                 memcmp(rx->receive_data, data, sizeof(data)) == 0);
  while (tx->terminals == 0u && monotonic_ms() < deadline)
    SHARED_REQUIRE(policy_shared_packet_step(fixture) == SALTS_OK);
  SHARED_REQUIRE(tx->terminals == 1u && tx->terminal_status == SALTS_OK &&
                 tx->terminal_tag == 11u && policy_same_session(tx->terminal_session, session));

  SHARED_REQUIRE(cnet_packet_endpoint_port(neighbor, &port) == SALTS_OK && port != 0u);
  const cnet_datagram_peer udp_peer = policy_loopback_peer(port);
  unacked = session;
  if (!secure)
    SHARED_REQUIRE(cnet_packet_session_open(client, &udp_peer, conversation, &unacked) == SALTS_OK);
  SHARED_REQUIRE(cnet_packet_send_tagged(client, unacked, data, sizeof(data), 12u) == SALTS_OK);
  if (!secure) {
    /* The UDP neighbor receives actual KCP PUSH packets and sends no ACK.
     * Host waits follow CNet's deadlines while the one-slot budget rotates. */
    deadline = monotonic_ms() + 5000u;
    while (udp->received < 2u && monotonic_ms() < deadline)
      SHARED_REQUIRE(policy_shared_packet_step(fixture) == SALTS_OK);
    SHARED_REQUIRE(udp->received == 2u && tx->terminals == 1u);
    SHARED_REQUIRE(udp->receive_kind == CNET_MESSAGE_DATAGRAM &&
                   udp->receive_size == 24u + sizeof(data) &&
                   memcmp(udp->receive_data + 24u, data, sizeof(data)) == 0);
  }

  SHARED_REQUIRE(cnet_packet_session_open(neighbor, &udp_peer, 0u, &udp_session) == SALTS_OK);
  const unsigned udp_before = udp->received;
  SHARED_REQUIRE(cnet_packet_send_tagged(neighbor, udp_session, &udp_data, 1u, 13u) == SALTS_OK);
  SHARED_REQUIRE(cnet_packet_endpoint_destroy(client) == SALTS_EBUSY);
  /* A malformed terminal with the right request identity still drains. The
   * host routes the rest of the batch and stop preserves the first error. */
  fixture->corrupt_cancel_terminal = !secure;
  const int stop_status = secure ? SALTS_OK : SALTS_EPROTO;
  SHARED_REQUIRE(policy_shared_packet_stop(fixture, 0u) == stop_status);
  SHARED_REQUIRE(!fixture->corrupt_cancel_terminal);
  bool stopped;
  SHARED_REQUIRE(cnet_packet_endpoint_stop_external(client, &stopped) == stop_status &&
                 stopped);
  SHARED_REQUIRE(tx->terminals == 2u && tx->terminal_status == SALTS_ECANCELED &&
                 tx->terminal_tag == 12u && policy_same_session(tx->terminal_session, unacked));
  SHARED_REQUIRE(tx->closed == (secure ? 1u : 2u) && tx->terminals_at_close == 2u);
  SHARED_REQUIRE(cnet_packet_endpoint_destroy(client) == SALTS_OK);

  deadline = monotonic_ms() + 5000u;
  while ((udp->terminals == 0u || udp->received == udp_before) && monotonic_ms() < deadline)
    SHARED_REQUIRE(policy_shared_packet_step(fixture) == SALTS_OK);
  SHARED_REQUIRE(udp->terminals == 1u && udp->terminal_status == SALTS_OK &&
                 udp->terminal_tag == 13u && udp->received == udp_before + 1u &&
                 udp->receive_size == 1u && udp->receive_data[0] == udp_data);
  SHARED_REQUIRE(tx->errors == 0u && rx->errors == 0u && udp->errors == 0u);

cleanup:
  for (size_t i = 0u; i < POLICY_SHARED_PACKET_COUNT; ++i) {
    if (fixture->endpoints[i].impl == NULL) continue;
    const int stop_status = policy_shared_packet_stop(fixture, i);
    const int destroy_status = cnet_packet_endpoint_destroy(&fixture->endpoints[i]);
    if (destroy_status != SALTS_OK) return failure != 0 ? failure : __LINE__;
    if (stop_status != SALTS_OK && failure == 0) failure = __LINE__;
  }
  if (backend_open) {
    const int close_status = native_io_backend_close(&fixture->backend);
    const int destroy_status = native_io_backend_destroy(&fixture->backend);
    if ((close_status != SALTS_OK || destroy_status != SALTS_OK) && failure == 0)
      failure = __LINE__;
  }
  free(fixture);
#undef SHARED_REQUIRE
  return failure;
}

static int select_destination_index(void *user, const cnet_destination_selection *input, size_t *out) {
  (void)input; *out = *(size_t *)user; return SALTS_OK;
}
static int select_owner_index(void *user, const cnet_owner_placement_input *input, size_t *out) {
  (void)input; *out = *(size_t *)user; return SALTS_OK;
}
static void custom_selection_contract(void) {
  size_t chosen = 1u, out = 0u;
  cnet_destination_hint endpoints[] = {{1u,1u,0u,true}, {2u,1u,0u,false}};
  cnet_destination_selection selection = {.size = sizeof(selection),
      .version = CNET_DESTINATION_POLICY_VERSION, .kind = CNET_DESTINATION_CUSTOM,
      .endpoints = endpoints, .endpoint_count = 2u, .snapshot_generation = 1u,
      .expires_at_ms = UINT64_MAX, .choose = select_destination_index, .choose_user = &chosen};
  cnet_destination_result result;
  check_equal(cnet_destination_choose(&selection, &result), SALTS_ENOBUFS);
  check_equal(result.index, SIZE_MAX);
  chosen = 2u;
  check_equal(cnet_destination_choose(&selection, &result), SALTS_EINVAL);
  chosen = 0u;
  check_equal(cnet_destination_choose(&selection, &result), SALTS_OK);
  check_equal(result.endpoint_id, (uint64_t)1u);
  cnet_owner_placement_hint owners[] = {{true,0u},{false,0u}};
  cnet_owner_placement_input placement = {.size = sizeof(placement),
      .version = CNET_OWNER_PLACEMENT_VERSION, .kind = CNET_OWNER_PLACE_CUSTOM,
      .owners = owners, .owner_count = 2u, .choose = select_owner_index, .choose_user = &chosen};
  check_equal(cnet_owner_placement_choose(&placement, &out), SALTS_OK);
  chosen = 1u;
  check_equal(cnet_owner_placement_choose(&placement, &out), SALTS_ENOBUFS);
  check_equal(out, SIZE_MAX);
  chosen = SIZE_MAX;
  check_equal(cnet_owner_placement_choose(&placement, &out), SALTS_EINVAL);
}
static int excessive_backoff(void *user, const cnet_backoff_input *input, uint64_t *delay) {
  (void)user; *delay = input->maximum_ms + 1u; return SALTS_OK;
}
static void replaceable_backoff_contract(void) {
  for (unsigned invalid = 0; invalid < 2; ++invalid) {
    cnet_reconnect_state state = {0};
    cnet_reconnect_ticket ticket = {0};
    uint64_t wait = 0u;
    cnet_reconnect_config config = {.size = sizeof(config), .version = CNET_RECOVERY_POLICY_VERSION,
        .max_attempts = 3u, .deadline_ms = 1000u, .initial_backoff_ms = 10u,
        .maximum_backoff_ms = 100u, .backoff = {invalid ? excessive_backoff : cnet_backoff_fixed, NULL}};
    check_equal(cnet_reconnect_init(&state, &config), SALTS_OK);
    check_equal(cnet_reconnect_begin(&state, 1u, &ticket, &wait), SALTS_OK);
    check_equal(cnet_reconnect_failed(&state, ticket, CNET_RECONNECT_TRANSIENT, 2u),
                invalid ? SALTS_EINVAL : SALTS_OK);
    if (invalid) check_equal(cnet_reconnect_begin(&state, 20u, &ticket, &wait), SALTS_ESHUTDOWN);
    else {
      check_equal(cnet_reconnect_begin(&state, 3u, &ticket, &wait), SALTS_EBUSY);
      check_equal(wait, (uint64_t)9u);
      check_equal(cnet_reconnect_begin(&state, 12u, &ticket, &wait), SALTS_OK);
      check_equal(cnet_reconnect_failed(&state, ticket, CNET_RECONNECT_SECURITY, 13u), SALTS_OK);
      check_equal(cnet_reconnect_begin(&state, 30u, &ticket, &wait), SALTS_ESHUTDOWN);
    }
  }
}
typedef struct backoff_boundary_probe {
  cnet_reconnect_state *state;
  cnet_backoff_input input;
  uint64_t delay;
  int result, begin_status, seal_status, snapshot_status;
  unsigned calls;
  cnet_reconnect_ticket nested_ticket;
  uint64_t nested_wait;
} backoff_boundary_probe;

static int boundary_backoff(void *user, const cnet_backoff_input *input, uint64_t *delay) {
  backoff_boundary_probe *probe = user;
  cnet_reconnect_snapshot snapshot = {0};
  ++probe->calls;
  probe->input = *input;
  probe->nested_ticket = (cnet_reconnect_ticket){1u, 1u, 1u};
  probe->nested_wait = UINT64_MAX;
  probe->begin_status = cnet_reconnect_begin(probe->state, 1u, &probe->nested_ticket, &probe->nested_wait);
  probe->seal_status = cnet_reconnect_seal(probe->state);
  probe->snapshot_status = cnet_reconnect_get_snapshot(probe->state, &snapshot);
  *delay = probe->delay;
  return probe->result;
}

typedef struct backoff_boundary_case {
  const char *name;
  uint64_t delay, now, deadline, next;
  uint32_t attempts;
  cnet_reconnect_failure_kind kind;
  int callback_status, failed_status, begin_status;
  unsigned calls;
  bool sealed;
} backoff_boundary_case;

static const backoff_boundary_case backoff_boundaries[] = {
  {"bounded delay", 5u, 2u, 1000u, 7u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_EBUSY, 1u, false},
  {"zero delay", 0u, 2u, 1000u, 2u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_OK, 1u, false},
  {"maximum delay", 20u, 2u, 1000u, 22u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_EBUSY, 1u, false},
  {"excessive delay", 21u, 2u, 1000u, 0u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_EINVAL, SALTS_ESHUTDOWN, 1u, true},
  {"policy error", 5u, 2u, 1000u, 0u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_EIO, SALTS_EIO, SALTS_ESHUTDOWN, 1u, true},
  {"deadline equality", 10u, 990u, 1000u, UINT64_MAX, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_ETIMEDOUT, 1u, false},
  {"clock overflow", 10u, UINT64_MAX - 5u, UINT64_MAX, UINT64_MAX, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_ETIMEDOUT, 1u, false},
  {"attempt exhaustion", 5u, 2u, 1000u, 7u, 1u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_ENOBUFS, 1u, false},
  {"security failure", 0u, 2u, 1000u, 0u, 2u, CNET_RECONNECT_SECURITY, SALTS_OK, SALTS_OK, SALTS_ESHUTDOWN, 0u, true},
  {"permanent failure", 0u, 2u, 1000u, 0u, 2u, CNET_RECONNECT_PERMANENT, SALTS_OK, SALTS_OK, SALTS_ESHUTDOWN, 0u, true},
  {"expired failure", 0u, 1000u, 1000u, 0u, 2u, CNET_RECONNECT_TRANSIENT, SALTS_OK, SALTS_OK, SALTS_ESHUTDOWN, 0u, true}
};

static void backoff_boundary_contract(const backoff_boundary_case *test) {
  cnet_reconnect_state state = {0};
  cnet_reconnect_ticket first = {0}, next = {0};
  cnet_reconnect_snapshot snapshot = {0};
  backoff_boundary_probe probe = {.state = &state, .delay = test->delay, .result = test->callback_status};
  const cnet_reconnect_config config = {
      .size = sizeof(config), .version = CNET_RECOVERY_POLICY_VERSION,
      .max_attempts = test->attempts, .deadline_ms = test->deadline,
      .initial_backoff_ms = 10u, .maximum_backoff_ms = 20u,
      .backoff = {boundary_backoff, &probe}};
  uint64_t wait = UINT64_MAX;
  check_equal(cnet_reconnect_init(&state, &config), SALTS_OK);
  check_equal(cnet_reconnect_begin(&state, 1u, &first, &wait), SALTS_OK);
  check_equal(cnet_reconnect_failed(&state, first, test->kind, test->now), test->failed_status);
  check_equal(probe.calls, test->calls);
  if (probe.calls != 0u) {
    check_equal(probe.input.attempts, (uint32_t)1u);
    check_equal(probe.input.initial_ms, (uint64_t)10u);
    check_equal(probe.input.maximum_ms, (uint64_t)20u);
    check_equal(probe.input.exponential_ms, (uint64_t)10u);
    check_equal(probe.begin_status, SALTS_EBUSY);
    check_equal(probe.seal_status, SALTS_EBUSY);
    check_equal(probe.snapshot_status, SALTS_EBUSY);
    check_equal(probe.nested_ticket.state, (uintptr_t)0u);
    check_equal(probe.nested_ticket.incarnation, (uint64_t)0u);
    check_equal(probe.nested_ticket.generation, (uint64_t)0u);
    check_equal(probe.nested_wait, (uint64_t)0u);
  }
  check_equal(cnet_reconnect_get_snapshot(&state, &snapshot), SALTS_OK);
  check_equal(snapshot.next_attempt_ms, test->next);
  check_equal(snapshot.attempts, (uint32_t)1u);
  check_equal(snapshot.generation, first.generation);
  check_equal(snapshot.sealed, test->sealed);
  check(!snapshot.in_flight && !snapshot.awaiting_protocol && !snapshot.protocol_ready);
  next = (cnet_reconnect_ticket){1u, 1u, 1u};
  wait = UINT64_MAX;
  check_equal(cnet_reconnect_begin(&state, test->now, &next, &wait), test->begin_status);
  check_equal(wait, test->begin_status == SALTS_EBUSY ? test->delay : (uint64_t)0u);
  if (test->begin_status != SALTS_OK) {
    check_equal(next.state, (uintptr_t)0u);
    check_equal(next.incarnation, (uint64_t)0u);
    check_equal(next.generation, (uint64_t)0u);
  }
  if (test->begin_status == SALTS_EBUSY) {
    check_equal(cnet_reconnect_begin(&state, test->next, &next, &wait), SALTS_OK);
    check_equal(wait, (uint64_t)0u);
  }
  if (test->begin_status == SALTS_OK || test->begin_status == SALTS_EBUSY) {
    check(next.generation > first.generation);
    check_equal(cnet_reconnect_failed(&state, first, CNET_RECONNECT_TRANSIENT, test->next), SALTS_ENOENT);
    check_equal(cnet_reconnect_get_snapshot(&state, &snapshot), SALTS_OK);
    check(snapshot.in_flight && snapshot.attempts == 2u && snapshot.generation == next.generation);
  } else {
    check_equal(cnet_reconnect_get_snapshot(&state, &snapshot), SALTS_OK);
    check(snapshot.attempts == 1u && snapshot.generation == first.generation && !snapshot.in_flight);
  }
}

typedef struct failed_storage { size_t calls, fail_at, live; } failed_storage;
static void *fail_allocate(void *user, size_t bytes) {
  failed_storage *s = user;
  if (++s->calls == s->fail_at) return NULL;
  void *result = malloc(bytes);
  if (result != NULL) ++s->live;
  return result;
}
static void fail_free(void *user, void *memory, size_t bytes) {
  (void)bytes; --((failed_storage *)user)->live; free(memory);
}
static void allocation_rollback_contract(bool external) {
  bool completed = false;
  for (size_t failure = 1u; failure < 128u; ++failure) {
    cnet_client client = {0};
    cnet_client_config config = policy_client_config();
    native_io_backend backend = {0};
    if (external) {
      const native_io_backend_config native_config = {config.backend,
          config.connection_capacity * 2u, config.request_capacity, config.completion_batch_capacity};
      check_equal(native_io_backend_init(&backend, &native_config), SALTS_OK);
    }
    failed_storage storage = {0, failure, 0};
    config.resources.storage = (cnet_allocator){fail_allocate, fail_free, &storage};
    int status = external ? cnet_client_init_external(&client, &config, &backend)
                          : cnet_client_init(&client, &config);
    if (status == SALTS_OK) {
      status = external ? cnet_client_stop_external(&client) : cnet_client_stop(&client, 2000u);
      if (status == SALTS_OK) status = cnet_client_destroy(&client);
      completed = true;
    }
    check(status == SALTS_OK || status == SALTS_ENOMEM,
          "allocation failure %zu, external %d: status %d", failure, (int)external, status);
    check_null(client.impl);
    check_equal(storage.live, (size_t)0u);
    if (external) {
      /* Failure rollback must not close or destroy the host's backend. */
      check_equal(native_io_backend_wake(&backend), SALTS_OK);
      check_equal(native_io_backend_close(&backend), SALTS_OK);
      check_equal(native_io_backend_destroy(&backend), SALTS_OK);
    }
    if (completed) break;
  }
  check_true(completed);
}
static int management_allocation_contract(unsigned kind) {
  cnet_client client = {0};
  cnet_manager owner = {0};
  const cnet_client_config client_config = policy_client_config();
  const cnet_manager_config owner_config = {
      sizeof(cnet_manager_config), CNET_MANAGER_VERSION, &client, 2u, 2u};
  bool completed = false;
  int result = 0;
  failed_storage storage = {0};
  cnet_manager manager = {0};
  cnet_handoff handoff = {0};
  cnet_managed_dial dial = {0};
  cnet_client_pool pool = {0};
  cnet_handoff_ticket ticket = {0};
  cnet_pool_connection pool_connection = {0};
#define MANAGEMENT_REQUIRE(expr) do { if (!(expr)) { result = __LINE__; goto cleanup; } } while (0)
  MANAGEMENT_REQUIRE(cnet_client_init(&client, &client_config) == SALTS_OK);
  MANAGEMENT_REQUIRE(cnet_manager_init(&owner, &owner_config) == SALTS_OK);
  for (size_t failure = 1u; failure < 16u; ++failure) {
    storage = (failed_storage){0, failure, 0};
    const cnet_allocator allocator = {fail_allocate, fail_free, &storage};
    int status;
    if (kind == 0u) {
      cnet_manager_config config = owner_config;
      config.storage = allocator;
      status = cnet_manager_init(&manager, &config);
    } else if (kind == 1u) {
      const cnet_handoff_config config = {
          .size = sizeof(config), .version = CNET_HANDOFF_VERSION,
          .connection_capacity = 2u, .queue_capacity = 1u, .storage = allocator};
      status = cnet_handoff_init(&handoff, &config);
    } else if (kind == 2u) {
      const cnet_managed_dial_config config = {
          .size = sizeof(config), .version = CNET_MANAGED_DIAL_VERSION,
          .manager = &owner, .client = &client,
          .connection = {.uri = "tcp://127.0.0.1:9", .observer = {.on_state = policy_connection_state}},
          .recovery = {.size = sizeof(cnet_reconnect_config), .version = CNET_RECOVERY_POLICY_VERSION,
              .max_attempts = 1u, .deadline_ms = 1000u},
          .recovery_episode_ms = 1000u, .storage = allocator};
      status = cnet_managed_dial_init(&dial, &config);
    } else {
      const cnet_pool_config config = {
          .size = sizeof(config), .version = CNET_CLIENT_POOL_VERSION,
          .manager = &owner, .owner_id = 1u, .max_connections = 2u,
          .max_connecting = 1u, .max_leases = 2u, .storage = allocator};
      status = cnet_pool_init(&pool, &config);
    }
    MANAGEMENT_REQUIRE(status == SALTS_OK || status == SALTS_ENOMEM);
    if (status != SALTS_OK) {
      MANAGEMENT_REQUIRE(storage.calls == failure);
      MANAGEMENT_REQUIRE(manager.impl == NULL);
      MANAGEMENT_REQUIRE(handoff.impl == NULL);
      MANAGEMENT_REQUIRE(dial.impl == NULL);
      MANAGEMENT_REQUIRE(pool.impl == NULL);
    } else {
      completed = true;
      if (kind == 0u) {
        cnet_managed_connection connection = {0};
        const cnet_manager_attachment attachment = {.observer = {.on_state = policy_connection_state}};
        size_t work = 0u;
        MANAGEMENT_REQUIRE(cnet_manager_reserve(&manager, &attachment, &connection) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_manager_cancel(&manager, connection) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_manager_advance(&manager, 2u, &work) == SALTS_OK);
        MANAGEMENT_REQUIRE(work == (size_t)1u);
        MANAGEMENT_REQUIRE(cnet_manager_destroy(&manager) == SALTS_OK);
      } else if (kind == 1u) {
        MANAGEMENT_REQUIRE(cnet_handoff_reserve(&handoff, &ticket) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_handoff_release(&handoff, ticket) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_handoff_seal(&handoff) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_handoff_destroy(&handoff) == SALTS_OK);
      } else if (kind == 2u) {
        MANAGEMENT_REQUIRE(cnet_managed_dial_seal(&dial) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_managed_dial_destroy(&dial) == SALTS_OK);
      } else {
        const cnet_pool_key key = {.size = sizeof(key), .version = CNET_CLIENT_POOL_VERSION,
            .runtime_id = 1u, .owner_id = 1u, .endpoint_id = 1u, .authority_id = 1u,
            .transport_id = 1u, .protocol_id = 1u};
        MANAGEMENT_REQUIRE(cnet_pool_reserve_connecting(&pool, &key, &pool_connection) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_pool_terminal(&pool, pool_connection) == SALTS_OK);
        MANAGEMENT_REQUIRE(cnet_pool_destroy(&pool) == SALTS_OK);
      }
    }
    MANAGEMENT_REQUIRE(storage.live == (size_t)0u);
    cnet_manager_snapshot snapshot = {0};
    MANAGEMENT_REQUIRE(cnet_manager_get_snapshot(&owner, &snapshot) == SALTS_OK);
    MANAGEMENT_REQUIRE(snapshot.drained);
    if (completed) break;
  }
  MANAGEMENT_REQUIRE(completed);
cleanup:
  if (dial.impl != NULL) {
    (void)cnet_managed_dial_seal(&dial);
    (void)cnet_managed_dial_destroy(&dial);
  }
  if (pool.impl != NULL) {
    if (pool_connection.slot != 0u) (void)cnet_pool_terminal(&pool, pool_connection);
    (void)cnet_pool_destroy(&pool);
  }
  if (handoff.impl != NULL) {
    if (ticket.slot != 0u) (void)cnet_handoff_release(&handoff, ticket);
    (void)cnet_handoff_destroy(&handoff);
  }
  if (manager.impl != NULL) {
    size_t work = 0u;
    (void)cnet_manager_request_close(&manager);
    (void)cnet_manager_advance(&manager, 2u, &work);
    (void)cnet_manager_advance(&manager, 2u, &work);
    (void)cnet_manager_destroy(&manager);
  }
  if (owner.impl != NULL && cnet_manager_destroy(&owner) != SALTS_OK && result == 0) result = __LINE__;
  if (client.impl != NULL) {
    if (cnet_client_stop(&client, 2000u) != SALTS_OK && result == 0) result = __LINE__;
    if (cnet_client_destroy(&client) != SALTS_OK && result == 0) result = __LINE__;
  }
#undef MANAGEMENT_REQUIRE
  return result;
}

static void pool_selection_contract(void) {
  cnet_pool_candidate candidates[3] = {{0}};
  size_t selected = SIZE_MAX;
  candidates[0].eligible = candidates[1].eligible = true;
  candidates[0].leases = 4u; candidates[1].leases = 1u;
  check_equal(cnet_pool_select_first(NULL, candidates, 3u, 1u, &selected), SALTS_OK);
  check_equal(selected, (size_t)0u);
  check_equal(cnet_pool_select_round_robin(NULL, candidates, 3u, 1u, &selected), SALTS_OK);
  check_equal(selected, (size_t)1u);
  check_equal(cnet_pool_select_least_used(NULL, candidates, 3u, 0u, &selected), SALTS_OK);
  check_equal(selected, (size_t)1u);
  candidates[0].eligible = candidates[1].eligible = false;
  check_equal(cnet_pool_select_least_used(NULL, candidates, 3u, 0u, &selected), SALTS_ENOBUFS);
  check_equal(selected, SIZE_MAX);
}

spec("CNet native policy and channel admission") {
  it("rejects a size-only socket policy before reading unavailable fields") {
    size_t *descriptor = (size_t *)malloc(sizeof(*descriptor));
    check_not_null(descriptor);
    *descriptor = sizeof(*descriptor);
    const int status = cnet_client_set_stream_socket_options(NULL,
        (const cnet_stream_socket_options *)descriptor);
    free(descriptor);
    check_equal(status, SALTS_EINVAL);
  }
  it("validates custom destination and Owner choices against authoritative eligibility") { custom_selection_contract(); }
  it("replaces recovery backoff without bypassing bounds or security sealing") { replaceable_backoff_contract(); }
  for (size_t i = 0u; i < sizeof(backoff_boundaries) / sizeof(backoff_boundaries[0]); ++i) {
    it("enforces custom backoff authority for %s", backoff_boundaries[i].name) {
      backoff_boundary_contract(&backoff_boundaries[i]);
    }
  }
  it("returns every provider allocation after each initialization failure") { allocation_rollback_contract(false); }
  it("preserves the borrowed backend after every initialization failure") { allocation_rollback_contract(true); }
  for (unsigned kind = 0u; kind < 4u; ++kind) {
    it("stops at the first management allocation failure and returns all storage, kind %u", kind) {
      const int result = management_allocation_contract(kind);
      check(result == 0, "management allocation kind %u failed at line %d", kind, result);
    }
  }
  it("selects pool candidates through interchangeable bounded strategies") { pool_selection_contract(); }
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
  it("admits passive plain KCP only on the first PUSH segment") {
    const int failed = policy_kcp_passive_start();
    check(failed == 0, "Passive KCP start: failed source line %d", failed);
  }
  it("keeps a KCP neighbor working when another UDP port is unreachable") {
    const int failed = policy_kcp_unreachable_peer();
    check(failed == 0, "KCP unreachable peer: failed source line %d", failed);
  }
  it("drains a closing UDP generation before reuse and preserves its neighbor") {
    const int failed = policy_udp_generation_drain();
    check(failed == 0, "UDP generation drain: failed source line %d", failed);
  }
  it("cancels one unacknowledged KCP tag after real wire retransmission before CLOSED") {
    const int failed = policy_kcp_retransmission_stop();
    check(failed == 0, "KCP retransmission stop: failed source line %d", failed);
  }
  it("drives plain KCP timers, retransmission and stop on a borrowed Owner beside UDP") {
    const int failed = policy_shared_kcp(false);
    check(failed == 0, "Shared plain KCP: failed source line %d", failed);
  }
  it("drives authenticated KCP and UDP through a borrowed Owner") {
    const int failed = policy_shared_kcp(true);
    check(failed == 0, "Shared authenticated KCP: failed source line %d", failed);
  }
  it("requires secure KCP handshake READY and authenticated protocol ACK") {
    const int failed = policy_loopback_pair(CNET_PACKET_KCP, true);
    check(failed == 0, "Secure KCP packet endpoint: failed source line %d", failed);
  }
}
