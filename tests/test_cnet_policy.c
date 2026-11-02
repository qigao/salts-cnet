#include <cnet/cnet.h>
#include <cnet/destination_policy.h>
#include <cnet/owner_placement.h>
#include <cnet/recovery_policy.h>
#include <error_codes.h>
#include <stddef.h>
#include <stdint.h>
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
}
