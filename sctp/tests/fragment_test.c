#include "sctp_data_internal.h"

#include <tinytest.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct test_owner { int admitted; } test_owner;
static int owned(void *context) { return ((test_owner *)context)->admitted; }

static void initialize_pair(cnet_sctp_data *a, cnet_sctp_data *b,
                            test_owner *oa, test_owner *ob,
                            uint32_t sender_tsn) {
  cnet_sctp_data_config ca = {0}, cb = {0};
  memset(a, 0, sizeof(*a));
  memset(b, 0, sizeof(*b));
  oa->admitted = ob->admitted = 1;
  ca.local_port = 5000u; ca.remote_port = 5001u;
  ca.local_tag = UINT32_C(0x10203040);
  ca.peer_tag = UINT32_C(0x50607080);
  ca.local_initial_tsn = sender_tsn;
  ca.peer_initial_tsn = 700u;
  ca.inbound_streams = ca.outbound_streams = 4u;
  ca.peer_receive_window = CNET_SCTP_DATA_RECEIVE_CEILING;
  ca.t3_initial_ms = 100u; ca.t3_max_ms = 400u;
  ca.max_retransmits = 3u;
  ca.is_owner = owned; ca.owner_context = oa;
  cb = ca;
  cb.local_port = ca.remote_port; cb.remote_port = ca.local_port;
  cb.local_tag = ca.peer_tag; cb.peer_tag = ca.local_tag;
  cb.local_initial_tsn = ca.peer_initial_tsn;
  cb.peer_initial_tsn = ca.local_initial_tsn;
  cb.owner_context = ob;
  check(cnet_sctp_data_init(a, &ca, 0u) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_data_init(b, &cb, 0u) == CNET_SCTP_DATA_OK);
}

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void test_twenty_kib_loss_gap_ack_reassembly(void) {
  enum { MESSAGE_SIZE = 20480, FRAGMENTS = 20 };
  cnet_sctp_data a, b;
  test_owner oa = {0}, ob = {0};
  uint8_t payload[MESSAGE_SIZE], expected[MESSAGE_SIZE], decoded[MESSAGE_SIZE];
  uint8_t packet[CNET_SCTP_DATA_MTU], sack[CNET_SCTP_DATA_MTU];
  uint8_t reply[CNET_SCTP_DATA_MTU];
  cnet_sctp_wire_header header = {0};
  cnet_sctp_wire_decoder decoder = {0};
  cnet_sctp_wire_chunk ch = {0};
  cnet_sctp_data_message message = {0};
  size_t n = 0u, ns = 0u, nr = 0u;
  uint64_t now = 2u, deadline = 0u;
  int has_deadline = 0;
  unsigned int i;
  const uint32_t first_tsn = UINT32_C(0xfffffff8);
  initialize_pair(&a, &b, &oa, &ob, first_tsn);
  for (i = 0u; i < MESSAGE_SIZE; ++i)
    payload[i] = (uint8_t)(i * 37u + 11u);
  memcpy(expected, payload, MESSAGE_SIZE);
  check(cnet_sctp_data_queue_message(&a, 1u, 0u, 53u, 0,
                                      payload, MESSAGE_SIZE) == CNET_SCTP_DATA_OK);
  memset(payload, 0xff, sizeof(payload)); /* no borrowed app lifetime */
  check(cnet_sctp_data_queue_message(&a, 1u, 0u, 53u, 0,
                                      expected, MESSAGE_SIZE) == CNET_SCTP_DATA_CAPACITY);
  check(cnet_sctp_data_pump(&a, 2u, packet, 16u, &n) == CNET_SCTP_DATA_CAPACITY);
  check(n == 0u && a.pending.offset == 0u && a.next_tsn == first_tsn);
  check(a.tx_ssn[0] == 0u);
  check(cnet_sctp_data_pump(&a, 2u, packet, sizeof(packet), &n) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_wire_decode(packet, n, &header, &decoder) == CNET_SCTP_WIRE_OK);
  check(cnet_sctp_wire_next_chunk(&decoder, &ch) == CNET_SCTP_WIRE_OK);
  check(ch.type == 0u && ch.flags == 2u); /* first B=1 E=0 */
  check(be32(ch.value) == first_tsn);
  /* First fragment lost. Gap ACKs keep owned TX tickets until
   * cumulative ACK; recover the missing first fragment before pumping more. */
  for (i = 1u; i < FRAGMENTS; ++i) {
    now += 3u;
    if (i == 4u) {
      /* Three higher Gap ACKs mark the lost B for Fast Retransmit.
       * Owner advance() must transmit the retained TSN first. */
      const size_t offset = a.pending.offset;
      check(cnet_sctp_data_pump(&a, now, packet,
          sizeof(packet), &n) == CNET_SCTP_DATA_RETRANSMIT_PENDING);
      check(n == 0u && offset == i * CNET_SCTP_DATA_PAYLOAD_MAX);
      check(cnet_sctp_data_deadline(&a, &deadline, &has_deadline) ==
             CNET_SCTP_DATA_OK);
      check(has_deadline && deadline <= now);
      check(cnet_sctp_data_advance(&a, now, packet,
          sizeof(packet), &n) == CNET_SCTP_DATA_OK);
      check(cnet_sctp_wire_decode(packet, n, &header, &decoder) ==
             CNET_SCTP_WIRE_OK);
      check(cnet_sctp_wire_next_chunk(&decoder, &ch) == CNET_SCTP_WIRE_OK);
      check(ch.flags == 2u && be32(ch.value) == first_tsn);
      check(cnet_sctp_data_input(&b, now + 1u, packet, n,
          sack, sizeof(sack), &ns) == CNET_SCTP_DATA_OK);
      check(cnet_sctp_data_input(&a, now + 2u, sack, ns,
          reply, sizeof(reply), &nr) == CNET_SCTP_DATA_OK);
      check(nr == 0u && a.in_flight == 0u && a.pending.offset == offset);
      now += 3u;
    }
    check(cnet_sctp_data_pump(&a, now, packet,
                               sizeof(packet), &n) == CNET_SCTP_DATA_OK);
    check(cnet_sctp_wire_decode(packet, n, &header, &decoder) == CNET_SCTP_WIRE_OK);
    check(cnet_sctp_wire_next_chunk(&decoder, &ch) == CNET_SCTP_WIRE_OK);
    check(ch.type == 0u && ch.value_size == 1036u);
    check(be32(ch.value) == first_tsn + i);
    check(((ch.flags & 2u) != 0u) == 0);
    check(((ch.flags & 1u) != 0u) == (i == FRAGMENTS - 1u));
    check(((ch.flags & 4u) != 0u) == 0);
    check(a.tx_ssn[0] == (i == FRAGMENTS - 1u ? 1u : 0u));
    check(cnet_sctp_data_input(&b, now + 1u, packet, n,
                                sack, sizeof(sack), &ns) == CNET_SCTP_DATA_OK);
    check(cnet_sctp_data_input(&a, now + 2u, sack, ns,
                                reply, sizeof(reply), &nr) == CNET_SCTP_DATA_OK);
    check(nr == 0u);
    if (i + 1u < FRAGMENTS)
      check(cnet_sctp_data_take(&b, &message, decoded,
                                 sizeof(decoded), &nr) == CNET_SCTP_DATA_EMPTY);
  }
  check(!a.pending.active && a.next_tsn == first_tsn + FRAGMENTS);
  check(cnet_sctp_data_pump(&a, now + 3u, packet, sizeof(packet), &n) ==
         CNET_SCTP_DATA_EMPTY);
  check(n == 0u && a.in_flight == 0u);
  check(b.buffered_rx == MESSAGE_SIZE);
  check(cnet_sctp_data_deadline(&a, &deadline, &has_deadline) == CNET_SCTP_DATA_OK);
  check(!has_deadline);
  check(cnet_sctp_data_take(&b, &message, decoded, 1024u, &nr) ==
         CNET_SCTP_DATA_CAPACITY);
  check(b.buffered_rx == MESSAGE_SIZE && nr == 0u);
  check(cnet_sctp_data_take(&b, &message, decoded,
                             sizeof(decoded), &nr) == CNET_SCTP_DATA_OK);
  check(nr == MESSAGE_SIZE && message.size == MESSAGE_SIZE);
  check(message.stream_id == 0u && message.stream_sequence == 0u &&
         message.ppid == 53u && message.tsn == first_tsn &&
         !message.unordered);
  check(memcmp(decoded, expected, MESSAGE_SIZE) == 0);
  check(b.buffered_rx == 0u && b.rx_ssn[0] == 1u);
  check(a.in_flight == 0u && a.t3_deadline_ms == 0u);
  check(cnet_sctp_data_stop(&a) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_data_stop(&b) == CNET_SCTP_DATA_OK);
}

static void test_bounded_queue_and_unordered_fragments(void) {
  cnet_sctp_data a, b;
  test_owner oa = {0}, ob = {0};
  uint8_t payload[3072], wire[CNET_SCTP_DATA_MTU], sack[CNET_SCTP_DATA_MTU];
  uint8_t event[3072], response[CNET_SCTP_DATA_MTU];
  cnet_sctp_data_message meta = {0};
  size_t n = 0u, ns = 0u, nr = 0u;
  unsigned int i;
  initialize_pair(&a, &b, &oa, &ob, 100u);
  for (i = 0u; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;
  check(cnet_sctp_data_queue_message(&a, 1u, 1u, 53u, 1,
      payload, sizeof(payload)) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_data_send(&a, 2u, 0u, 51u, 0, payload, 1u,
      wire, sizeof(wire), &n) == CNET_SCTP_DATA_CAPACITY);
  check(cnet_sctp_data_queue_message(&a, 2u, 1u, 53u, 1,
      payload, sizeof(payload)) == CNET_SCTP_DATA_CAPACITY);
  for (i = 0u; i < 3u; ++i) {
    check(cnet_sctp_data_pump(&a, 2u + i, wire, sizeof(wire), &n) ==
           CNET_SCTP_DATA_OK);
    check(cnet_sctp_data_input(&b, 2u + i, wire, n,
                                sack, sizeof(sack), &ns) == CNET_SCTP_DATA_OK);
    check(cnet_sctp_data_input(&a, 2u + i, sack, ns,
                                response, sizeof(response), &nr) == CNET_SCTP_DATA_OK);
  }
  check(!a.pending.active && a.tx_ssn[1] == 0u);
  check(cnet_sctp_data_take(&b, &meta, event, sizeof(event), &nr) == CNET_SCTP_DATA_OK);
  check(nr == sizeof(payload) && meta.unordered && meta.stream_id == 1u &&
         meta.ppid == 53u && meta.stream_sequence == 0u);
  check(memcmp(event, payload, sizeof(payload)) == 0);
  check(cnet_sctp_data_stop(&a) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_data_stop(&b) == CNET_SCTP_DATA_OK);
}

spec("SCTP native fragment contract") {
  it("preserves all original RFC, boundary and negative-path assertions") {
  test_twenty_kib_loss_gap_ack_reassembly();
  test_bounded_queue_and_unordered_fragments();
  puts("C11 SCTP 20KiB DATA B/E TSN reassembly, T3 and backpressure PASS");
  }
}
