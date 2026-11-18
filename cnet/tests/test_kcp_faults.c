#include <cnet/cnet.h>
#include <core/error_codes.h>
#include <tinytest.h>
#include <string.h>

enum { WIRE_CAPACITY = 512, WIRE_BYTES = 128, MESSAGE_BYTES = 512, MESSAGE_COUNT = 3 };
enum { DROP = 1, REORDER = 2, DUPLICATE = 4 };

typedef struct wire_packet {
  unsigned char data[WIRE_BYTES];
  size_t size;
  unsigned destination;
} wire_packet;

typedef struct fault_pair fault_pair;
typedef struct fault_peer {
  fault_pair *pair;
  cnet_kcp kcp;
  unsigned index;
  unsigned received;
  unsigned emitted;
  unsigned char messages[MESSAGE_COUNT][MESSAGE_BYTES];
} fault_peer;

struct fault_pair {
  fault_peer peers[2];
  wire_packet packets[WIRE_CAPACITY];
  size_t head, count;
  unsigned delivered;
  int error;
  bool blackhole;
};

static int emit(void *user, cnet_kcp *session, const void *data, size_t size) {
  fault_peer *peer = user;
  fault_pair *pair = peer->pair;
  wire_packet *packet;
  (void)session;
  ++peer->emitted;
  if (pair->blackhole) return SALTS_OK;
  if (size > WIRE_BYTES || pair->count == WIRE_CAPACITY) return SALTS_ENOBUFS;
  packet = &pair->packets[(pair->head + pair->count) % WIRE_CAPACITY];
  memcpy(packet->data, data, size);
  packet->size = size;
  packet->destination = 1u - peer->index;
  ++pair->count;
  return SALTS_OK;
}

static void receive_message(void *user, cnet_kcp *session, const cnet_receive_view *view) {
  fault_peer *peer = user;
  (void)session;
  if (view->size != MESSAGE_BYTES || peer->received == MESSAGE_COUNT) {
    peer->pair->error = SALTS_EPROTO;
    return;
  }
  memcpy(peer->messages[peer->received++], view->data, view->size);
}

static int initialize(fault_pair *pair) {
  for (unsigned i = 0; i < 2; ++i) {
    fault_peer *peer = &pair->peers[i];
    cnet_kcp_config config = CNET_KCP_CONFIG_INIT;
    peer->pair = pair;
    peer->index = i;
    config.conversation = 901u;
    config.mtu = WIRE_BYTES;
    config.max_message_bytes = MESSAGE_BYTES;
    config.observer = (cnet_kcp_observer){emit, receive_message, peer};
    const int status = cnet_kcp_init(&peer->kcp, &config);
    if (status != SALTS_OK) return status;
  }
  return SALTS_OK;
}

static int deliver(fault_pair *pair, unsigned faults) {
  size_t budget = WIRE_CAPACITY;
  while (pair->count != 0u && budget-- != 0u) {
    wire_packet packet;
    int status;
    if ((faults & REORDER) != 0u && pair->count > 1u) {
      --pair->count;
      packet = pair->packets[(pair->head + pair->count) % WIRE_CAPACITY];
    } else {
      packet = pair->packets[pair->head];
      pair->head = (pair->head + 1u) % WIRE_CAPACITY;
      --pair->count;
    }
    ++pair->delivered;
    if ((faults & DROP) != 0u && pair->delivered % 7u == 0u) continue;
    status = cnet_kcp_input(&pair->peers[packet.destination].kcp, packet.data, packet.size);
    if (status != SALTS_OK) return status;
    if ((faults & DUPLICATE) != 0u && pair->delivered % 5u == 0u) {
      status = cnet_kcp_input(&pair->peers[packet.destination].kcp, packet.data, packet.size);
      if (status != SALTS_OK) return status;
    }
  }
  return pair->error;
}

typedef struct secure_probe { unsigned emitted, received; } secure_probe;
static int secure_drop(void *user, cnet_secure_kcp *session, const void *data, size_t size) {
  (void)session; (void)data; (void)size;
  ++((secure_probe *)user)->emitted;
  return SALTS_OK;
}
static void secure_receive(void *user, cnet_secure_kcp *session, const cnet_receive_view *view) {
  (void)session; (void)view;
  ++((secure_probe *)user)->received;
}

spec("KCP deterministic wire faults and dead link") {
  static fault_pair pair;
  static cnet_secure_kcp secure;
  static secure_probe secure_result;
  before_each() {
    memset(&pair, 0, sizeof(pair));
    secure = (cnet_secure_kcp){0};
    secure_result = (secure_probe){0};
  }
  after_each() {
    cnet_kcp_destroy(&pair.peers[0].kcp);
    cnet_kcp_destroy(&pair.peers[1].kcp);
    cnet_secure_kcp_destroy(&secure);
  }

  for (unsigned faults = 0; faults < 8; ++faults) {
    it("delivers ordered messages exactly once with fault mask %u", faults) {
      unsigned char expected[MESSAGE_COUNT][MESSAGE_BYTES];
      check_equal(initialize(&pair), SALTS_OK);
      for (unsigned i = 0; i < MESSAGE_COUNT; ++i) {
        memset(expected[i], (int)(i + 1u), MESSAGE_BYTES);
        check_equal(cnet_kcp_send(&pair.peers[0].kcp, expected[i], MESSAGE_BYTES), SALTS_OK);
      }
      check_equal(cnet_kcp_set_dead_link(&pair.peers[0].kcp, 3), SALTS_EBUSY);
      for (uint32_t elapsed = 0; elapsed < 20000u; elapsed += 10u) {
        /* Exercise the protocol's 32-bit monotonic clock wrap as well. */
        const uint32_t clock = UINT32_MAX - 99u + elapsed;
        check_equal(cnet_kcp_update(&pair.peers[0].kcp, clock), SALTS_OK);
        check_equal(cnet_kcp_update(&pair.peers[1].kcp, clock), SALTS_OK);
        check_equal(deliver(&pair, faults), SALTS_OK);
        if (elapsed > 2000u && pair.count == 0u && pair.peers[1].received == MESSAGE_COUNT) break;
      }
      check_equal(pair.peers[1].received, MESSAGE_COUNT);
      check_equal(pair.peers[1].messages, expected, sizeof(expected));
      check_equal(cnet_kcp_terminal_status(&pair.peers[0].kcp), SALTS_OK);
    }
  }

  it("permanently expires unacknowledged traffic at the configured limit") {
    uint32_t next = 99u;
    check_equal(initialize(&pair), SALTS_OK);
    check_equal(cnet_kcp_set_dead_link(&pair.peers[0].kcp, 0), SALTS_EINVAL);
    check_equal(cnet_kcp_set_dead_link(&pair.peers[0].kcp, 3), SALTS_OK);
    pair.blackhole = true;
    check_equal(cnet_kcp_send(&pair.peers[0].kcp, "x", 1), SALTS_OK);
    int status = SALTS_OK;
    for (uint32_t clock = 0; clock < 20000u && status == SALTS_OK; clock += 10u)
      status = cnet_kcp_update(&pair.peers[0].kcp, clock);
    check_equal(status, SALTS_ETIMEDOUT);
    check_equal(pair.peers[0].emitted, 3u);
    check_equal(cnet_kcp_terminal_status(&pair.peers[0].kcp), SALTS_ETIMEDOUT);
    check_equal(cnet_kcp_update(&pair.peers[0].kcp, 30000u), SALTS_ETIMEDOUT);
    check_equal(cnet_kcp_send(&pair.peers[0].kcp, "x", 1), SALTS_ETIMEDOUT);
    const unsigned char late[24] = {0};
    check_equal(cnet_kcp_input(&pair.peers[0].kcp, late, sizeof(late)), SALTS_ETIMEDOUT);
    check_equal(cnet_kcp_check(&pair.peers[0].kcp, 30000u, &next), SALTS_ETIMEDOUT);
    check_equal(next, 0u);
    check_equal(pair.peers[0].emitted, 3u);
  }

  it("does not expire an idle peer without outstanding data") {
    check_equal(initialize(&pair), SALTS_OK);
    check_equal(cnet_kcp_set_dead_link(&pair.peers[0].kcp, 2), SALTS_OK);
    for (uint32_t clock = 0; clock < 1000000u; clock += 10000u)
      check_equal(cnet_kcp_update(&pair.peers[0].kcp, clock), SALTS_OK);
    check_equal(cnet_kcp_terminal_status(&pair.peers[0].kcp), SALTS_OK);
    check_equal(pair.peers[0].emitted, 0u);
  }

  it("bounds unanswered authenticated handshakes without admitting application data") {
    cnet_secure_kcp_config config = CNET_SECURE_KCP_CONFIG_INIT;
    uint32_t next = 99u;
    config.role = CNET_SECURE_KCP_CLIENT;
    config.security.mode = CNET_KCP_SECURITY_PSK_V1;
    config.kcp.mtu = CNET_KCP_DEFAULT_FEC_MAX_PAYLOAD_BYTES - CNET_KCP_SECURE_RECORD_OVERHEAD;
    memset(config.security.pre_shared_key, 0x17, sizeof(config.security.pre_shared_key));
    config.observer.output = secure_drop;
    config.observer.on_receive = secure_receive;
    config.observer.user = &secure_result;
    check_equal(cnet_secure_kcp_init(&secure, &config), SALTS_OK);
    check_equal(cnet_secure_kcp_set_dead_link(&secure, 3u), SALTS_OK);
    check_equal(cnet_secure_kcp_start(&secure, 0u), SALTS_OK);
    check_equal(cnet_secure_kcp_set_dead_link(&secure, 2u), SALTS_EBUSY);
    check_equal(cnet_secure_kcp_terminal_status(&secure), SALTS_EBUSY);
    for (unsigned i = 1; i < 3; ++i)
      check_equal(cnet_secure_kcp_update(&secure, i * config.security.handshake_retry_ms), SALTS_OK);
    check_equal(cnet_secure_kcp_update(&secure, 3u * config.security.handshake_retry_ms), SALTS_ETIMEDOUT);
    check_equal(secure_result.emitted, 3u);
    check_false(cnet_secure_kcp_established(&secure));
    check_equal(cnet_secure_kcp_terminal_status(&secure), SALTS_ETIMEDOUT);
    check_equal(cnet_secure_kcp_send(&secure, "x", 1), SALTS_ETIMEDOUT);
    check_equal(cnet_secure_kcp_input(&secure, "x", 1), SALTS_ETIMEDOUT);
    check_equal(cnet_secure_kcp_check(&secure, 2000u, &next), SALTS_ETIMEDOUT);
    check_equal(next, 0u);
    check_equal(cnet_secure_kcp_update(&secure, 4000u), SALTS_ETIMEDOUT);
    check_equal(secure_result.emitted, 3u);
    check_equal(secure_result.received, 0u);
  }
}
