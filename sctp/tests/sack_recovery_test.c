#include "sctp_data_internal.h"

#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <stdio.h>
#include <string.h>

/* Original RFC 9260 6.2.1/6.3.2 regression vectors. The peer emits real
 * CRC32C-sealed SACK packets; no sender-state injection or external engine. */
static int owner(void *context) { return *(int *)context; }
static void init(cnet_sctp_data *d, int *admitted, uint32_t tsn) {
  cnet_sctp_data_config cfg = {0};
  memset(d, 0, sizeof(*d));
  *admitted = 1;
  cfg.local_port = 5000u;
  cfg.remote_port = 5001u;
  cfg.local_tag = 123u;
  cfg.peer_tag = 456u;
  cfg.local_initial_tsn = tsn;
  cfg.peer_initial_tsn = 900u;
  cfg.outbound_streams = cfg.inbound_streams = 4u;
  cfg.peer_receive_window = CNET_SCTP_DATA_RECEIVE_CEILING;
  cfg.t3_initial_ms = 100u;
  cfg.t3_max_ms = 400u;
  cfg.max_retransmits = 3u;
  cfg.is_owner = owner;
  cfg.owner_context = admitted;
  check(cnet_sctp_data_init(d, &cfg, 0u) == CNET_SCTP_DATA_OK);
}
static void wr16(uint8_t *p, uint16_t n) {
  p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n;
}
static void wr32(uint8_t *p, uint32_t n) {
  p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16);
  p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}
static size_t sack(const cnet_sctp_data *d, uint32_t cumulative,
    uint32_t window, const uint16_t *gaps, size_t blocks, uint8_t *out) {
  uint8_t value[12u + 16u * 4u] = {0};
  cnet_sctp_wire_chunk ch = {0};
  size_t i, written = 0u;
  check(blocks <= 16u);
  wr32(value, cumulative);
  wr32(value + 4u, window);
  wr16(value + 8u, (uint16_t)blocks);
  for (i = 0u; i < 2u * blocks; ++i) wr16(value + 12u + i * 2u, gaps[i]);
  ch.type = 3u;
  ch.value = value;
  ch.value_size = 12u + 4u * blocks;
  check(cnet_sctp_wire_encode(d->config.remote_port, d->config.local_port,
      d->config.local_tag, &ch, 1u, out, CNET_SCTP_DATA_MTU, &written) ==
      CNET_SCTP_WIRE_OK);
  return written;
}
static cnet_sctp_data_status ack(cnet_sctp_data *d, uint64_t now,
    uint32_t cumulative, uint32_t window, const uint16_t *gaps, size_t blocks) {
  uint8_t packet[CNET_SCTP_DATA_MTU], out[CNET_SCTP_DATA_MTU];
  size_t n = sack(d, cumulative, window, gaps, blocks, packet), written = 99u;
  cnet_sctp_data_status status = cnet_sctp_data_input(d, now, packet, n,
      out, sizeof(out), &written);
  if (status != CNET_SCTP_DATA_OWNER) check(written == 0u);
  return status;
}
static size_t send_byte(cnet_sctp_data *d, uint64_t now, uint8_t value,
    uint8_t *packet) {
  size_t n = 0u;
  check(cnet_sctp_data_send(d, now, 0u, 53u, 0, &value, 1u,
      packet, CNET_SCTP_DATA_MTU, &n) == CNET_SCTP_DATA_OK);
  return n;
}
static unsigned int retained(const cnet_sctp_data *d) {
  unsigned int i, n = 0u;
  for (i = 0u; i < CNET_SCTP_DATA_TX_SLOTS; ++i) if (d->tx[i].used) ++n;
  return n;
}
static void retransmit(cnet_sctp_data *d, uint64_t now,
    const uint8_t *expected, size_t size) {
  uint8_t out[CNET_SCTP_DATA_MTU];
  size_t n = 0u;
  check(cnet_sctp_data_advance(d, now, out, sizeof(out), &n) == CNET_SCTP_DATA_OK);
  check(n == size && memcmp(out, expected, size) == 0);
}

static void gap_retains_bytes(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packets[3][CNET_SCTP_DATA_MTU];
  const uint16_t gaps[] = {2u, 3u};
  unsigned int i;
  init(&d, &admitted, 100u);
  for (i = 0u; i < 3u; ++i) (void)send_byte(&d, 1u + i, (uint8_t)i, packets[i]);
  check(ack(&d, 10u, 99u, 32768u, gaps, 1u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 1u);
  check(retained(&d) == 3u); /* Gap ACK is revocable, NOT a release. */
  check(ack(&d, 11u, 102u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 0u && retained(&d) == 0u && d.t3_deadline_ms == 0u);
}

static void gap_does_not_postpone_t3(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packets[3][CNET_SCTP_DATA_MTU];
  const uint16_t gap1[] = {2u, 2u}, gap2[] = {2u, 3u};
  size_t n0;
  init(&d, &admitted, 100u);
  n0 = send_byte(&d, 1u, 'a', packets[0]);
  (void)send_byte(&d, 2u, 'b', packets[1]);
  (void)send_byte(&d, 3u, 'c', packets[2]);
  check(ack(&d, 90u, 99u, 32768u, gap1, 1u) == CNET_SCTP_DATA_OK);
  check(d.t3_deadline_ms == 101u);
  check(ack(&d, 100u, 99u, 32768u, gap2, 1u) == CNET_SCTP_DATA_OK);
  check(d.t3_deadline_ms == 101u);
  retransmit(&d, 101u, packets[0], n0);
}

static void reneging_recovers_wraparound(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packets[3][CNET_SCTP_DATA_MTU];
  const uint16_t gaps[] = {2u, 3u}, only_last[] = {2u, 2u};
  size_t n0, n1, n2;
  init(&d, &admitted, UINT32_MAX - 1u);
  n0 = send_byte(&d, 1u, 'a', packets[0]);
  n1 = send_byte(&d, 2u, 'b', packets[1]);
  n2 = send_byte(&d, 3u, 'c', packets[2]);
  check(ack(&d, 10u, UINT32_MAX - 2u, 32768u, gaps, 1u) == CNET_SCTP_DATA_OK);
  retransmit(&d, 101u, packets[0], n0);
  /* Peer now cumulatively ACKs the first TSN but retracts the middle one. */
  check(ack(&d, 102u, UINT32_MAX - 1u, 32768u, only_last, 1u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 1u && retained(&d) == 2u);
  check(d.rto_ms == 200u && d.t3_deadline_ms == 302u);
  retransmit(&d, 302u, packets[1], n1);
  /* The remaining last gap is also revoked, across TSN UINT32_MAX -> 0. */
  check(ack(&d, 303u, UINT32_MAX, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 1u && d.rto_ms == 400u && d.t3_deadline_ms == 703u);
  retransmit(&d, 703u, packets[2], n2);
  check(ack(&d, 704u, 0u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(retained(&d) == 0u && d.in_flight == 0u && d.t3_deadline_ms == 0u);
}

static void all_gap_acked_timer_restart(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packet[CNET_SCTP_DATA_MTU], out[CNET_SCTP_DATA_MTU];
  const uint16_t gap[] = {1u, 1u};
  size_t n0, n = 0u;
  init(&d, &admitted, 100u);
  n0 = send_byte(&d, 1u, 'a', packet);
  check(ack(&d, 2u, 99u, 32768u, gap, 1u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 0u && d.t3_deadline_ms == 0u);
  check(cnet_sctp_data_advance(&d, 500u, out, sizeof(out), &n) == CNET_SCTP_DATA_OK);
  check(n == 0u); /* Do not retransmit still gap-acknowledged bytes. */
  check(ack(&d, 501u, 99u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(d.in_flight == 1u && d.t3_deadline_ms == 601u);
  retransmit(&d, 601u, packet, n0);
}

static void rto_backoff_survives_ack(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packets[2][CNET_SCTP_DATA_MTU];
  size_t n0, n1;
  init(&d, &admitted, 100u);
  n0 = send_byte(&d, 1u, 'a', packets[0]);
  n1 = send_byte(&d, 2u, 'b', packets[1]);
  retransmit(&d, 101u, packets[0], n0);
  check(d.rto_ms == 200u);
  check(ack(&d, 102u, 100u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(d.rto_ms == 200u && d.t3_deadline_ms == 302u);
  check(ack(&d, 103u, 100u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(d.rto_ms == 200u && d.t3_deadline_ms == 302u);
  retransmit(&d, 302u, packets[1], n1);
}

static void bounded_gap_tickets(void) {
  cnet_sctp_data d, before;
  int admitted;
  uint8_t packet[CNET_SCTP_DATA_MTU], byte = 0u;
  const uint16_t gap[] = {2u, CNET_SCTP_DATA_TX_SLOTS};
  size_t n = 0u;
  unsigned int i;
  init(&d, &admitted, 100u);
  for (i = 0u; i < CNET_SCTP_DATA_TX_SLOTS; ++i)
    (void)send_byte(&d, 1u + i, (uint8_t)i, packet);
  check(ack(&d, 20u, 99u, 32768u, gap, 1u) == CNET_SCTP_DATA_OK);
  memcpy(&before, &d, sizeof(d));
  check(cnet_sctp_data_send(&d, 21u, 0u, 53u, 0, &byte, 1u,
      packet, sizeof(packet), &n) == CNET_SCTP_DATA_CAPACITY);
  check(n == 0u && memcmp(&d, &before, sizeof(d)) == 0);
  check(ack(&d, 22u, 115u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  (void)send_byte(&d, 23u, 'n', packet); /* Cumulative ACK releases slots. */
  check(retained(&d) == 1u);
}

static void stale_sack_is_ignored(void) {
  cnet_sctp_data d, before;
  int admitted;
  uint8_t packet[CNET_SCTP_DATA_MTU];
  init(&d, &admitted, 100u);
  (void)send_byte(&d, 1u, 'a', packet);
  check(ack(&d, 2u, 100u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
  (void)send_byte(&d, 3u, 'b', packet);
  memcpy(&before, &d, sizeof(d));
  check(ack(&d, 4u, 99u, 0u, NULL, 0u) == CNET_SCTP_DATA_OK);
  check(memcmp(&d, &before, sizeof(d)) == 0);
}

static void rejection_is_atomic(void) {
  cnet_sctp_data d, before;
  int admitted;
  uint8_t packet[CNET_SCTP_DATA_MTU], out[CNET_SCTP_DATA_MTU];
  const uint16_t unsent[] = {2u, 3u}, overlap[] = {1u, 2u, 2u, 2u};
  size_t n = 0u;
  init(&d, &admitted, 100u);
  (void)send_byte(&d, 1u, 'a', packet);
  (void)send_byte(&d, 2u, 'b', packet);
  memcpy(&before, &d, sizeof(d));
  check(ack(&d, 3u, 102u, 1u, NULL, 0u) == CNET_SCTP_DATA_PROTOCOL);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  check(ack(&d, 3u, 99u + UINT32_C(0x80000000), 1u, NULL, 0u) ==
      CNET_SCTP_DATA_PROTOCOL);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  check(ack(&d, 3u, 99u, 1u, unsent, 1u) == CNET_SCTP_DATA_PROTOCOL);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  check(ack(&d, 3u, 99u, 1u, overlap, 2u) == CNET_SCTP_DATA_PROTOCOL);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  admitted = 0;
  check(ack(&d, 3u, 100u, 1u, NULL, 0u) == CNET_SCTP_DATA_OWNER);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  admitted = 1;
  check(ack(&d, 0u, 100u, 1u, NULL, 0u) == CNET_SCTP_DATA_CLOCK);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  check(ack(&d, UINT64_MAX, 100u, 1u, NULL, 0u) == CNET_SCTP_DATA_CLOCK);
  check(memcmp(&d, &before, sizeof(d)) == 0);
  check(cnet_sctp_data_advance(&d, 101u, out, 0u, &n) == CNET_SCTP_DATA_CAPACITY);
  check(n == 0u && memcmp(&d, &before, sizeof(d)) == 0);
}

static void gap_reack_does_not_inflate_cwnd(void) {
  cnet_sctp_data d;
  int admitted;
  uint8_t packet[CNET_SCTP_DATA_MTU];
  const uint16_t gap[] = {2u, 2u};
  uint32_t initial;
  unsigned int i;
  init(&d, &admitted, 100u);
  (void)send_byte(&d, 1u, 'a', packet);
  (void)send_byte(&d, 2u, 'b', packet);
  initial = d.cwnd;
  for (i = 0u; i < 20u; ++i) {
    check(ack(&d, 3u + 2u * i, 99u, 32768u, gap, 1u) == CNET_SCTP_DATA_OK);
    check(ack(&d, 4u + 2u * i, 99u, 32768u, NULL, 0u) == CNET_SCTP_DATA_OK);
    check(d.cwnd == initial && d.t3_deadline_ms == 101u);
    check(d.in_flight == 2u && retained(&d) == 2u);
  }
}


spec("SCTP SACK retention and reneging") {
  it("[case:gap-retains]") { gap_retains_bytes(); }
  it("[case:gap-timer]") { gap_does_not_postpone_t3(); }
  it("[case:reneging-wrap]") { reneging_recovers_wraparound(); }
  it("[case:timer-restart]") { all_gap_acked_timer_restart(); }
  it("[case:rto-backoff]") { rto_backoff_survives_ack(); }
  it("[case:bounded-tickets]") { bounded_gap_tickets(); }
  it("[case:stale-sack]") { stale_sack_is_ignored(); }
  it("[case:atomic-rejection]") { rejection_is_atomic(); }
  it("[case:cwnd-reack]") { gap_reack_does_not_inflate_cwnd(); }
}

/* Preserve the original exact-name CLI admission. CTest runs all cases.
 * An explicit legacy name must resolve to exactly one TinyTest case. */
int main(int argc, char **argv) {
  if (argc == 1) {
    return ttest_main__(argc, argv, TTEST_INVOKE_SPEC_ADAPTER__,
                        TT_USE_COLOR != 0, TT_USE_TAP != 0,
                        TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
  }
  if (argc != 2 || argv[1] == NULL) {
    fprintf(stderr, "expected one exact SCTP case name\n");
    return 2;
  }
  static const char *const names[] = {"gap-retains", "gap-timer", "reneging-wrap", "timer-restart", "rto-backoff", "bounded-tickets", "stale-sack", "atomic-rejection", "cwnd-reack"};
  bool accepted = false;
  for (size_t i = 0u; i < sizeof(names)/sizeof(names[0]); ++i) {
    if (strcmp(argv[1], names[i]) == 0) { accepted = true; break; }
  }
  if (!accepted) {
    fprintf(stderr, "unknown SCTP case '%s'\n", argv[1]);
    return 2;
  }
  char filter[160];
  int count = snprintf(filter, sizeof(filter), "[case:%s]", argv[1]);
  if (count < 0 || (size_t)count >= sizeof(filter)) return 2;
  char *filtered_argv[] = {argv[0], "--filter", filter};
  return ttest_main__(3, filtered_argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
