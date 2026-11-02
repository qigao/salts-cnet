#include "sctp_data_internal.h"

#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <stdio.h>
#include <string.h>

/* Original virtual-wire tests. All protocol state is reached through
 * init/send/input/advance/take. No writes to cwnd, tickets or loss counters.
 * The reference model uses emitted chunk lengths, independently of the
 * runtime's payload counter and congestion-avoidance credit. */
enum { Q = CNET_SCTP_DATA_MTU - 12u, LIMIT = 16u * CNET_SCTP_DATA_MTU };
typedef struct packet { uint8_t bytes[1200]; size_t n; } packet;
typedef struct sctp_virtual_link {
  cnet_sctp_data a, b;
  int owner;
  uint64_t now;
} sctp_virtual_link;
static int owns(void *p) { return *(const int *)p; }
static void init(sctp_virtual_link *l, uint32_t tsn, uint32_t rwnd) {
  cnet_sctp_data_config c = {0};
  memset(l, 0, sizeof(*l)); l->owner = 1; l->now = 1u;
  c.local_port = 5000u; c.remote_port = 5001u;
  c.local_tag = 111u; c.peer_tag = 222u;
  c.local_initial_tsn = tsn; c.peer_initial_tsn = 700u;
  c.inbound_streams = c.outbound_streams = 4u;
  c.peer_receive_window = rwnd;
  c.t3_initial_ms = 100u; c.t3_max_ms = 400u; c.max_retransmits = 3u;
  c.is_owner = owns; c.owner_context = &l->owner;
  check(cnet_sctp_data_init(&l->a, &c, 0u) == CNET_SCTP_DATA_OK);
  c.local_port = 5001u; c.remote_port = 5000u;
  c.local_tag = 222u; c.peer_tag = 111u;
  c.local_initial_tsn = 700u; c.peer_initial_tsn = tsn;
  c.peer_receive_window = 32768u;
  check(cnet_sctp_data_init(&l->b, &c, 0u) == CNET_SCTP_DATA_OK);
}
static cnet_sctp_data_status send(sctp_virtual_link *l, packet *p, size_t bytes) {
  uint8_t body[1024];
  memset(body, (int)(l->a.next_tsn & 255u), sizeof(body));
  return cnet_sctp_data_send(&l->a, l->now++, 0u, 53u, 0,
      body, bytes, p->bytes, sizeof(p->bytes), &p->n);
}
static void receive(sctp_virtual_link *l, const packet *p, packet *sack) {
  check(cnet_sctp_data_input(&l->b, l->now++, p->bytes, p->n,
      sack->bytes, sizeof(sack->bytes), &sack->n) == CNET_SCTP_DATA_OK);
}
static void ack(sctp_virtual_link *l, const packet *sack) {
  packet out;
  check(cnet_sctp_data_input(&l->a, l->now++, sack->bytes, sack->n,
      out.bytes, sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_OK);
  check(out.n == 0u);
}
static void take(sctp_virtual_link *l, size_t expected) {
  uint8_t out[1024]; size_t n;
  cnet_sctp_data_message m = {0};
  check(cnet_sctp_data_take(&l->b, &m, out, sizeof(out), &n) ==
         CNET_SCTP_DATA_OK);
  check(n == expected && m.size == expected && !m.unordered && m.ppid == 53u);
  check(out[0] == (uint8_t)m.tsn);
}
static void deliver(sctp_virtual_link *l, const packet *p) {
  packet s;
  receive(l, p, &s); ack(l, &s); take(l, p->n - 28u); /* aligned tests */
}
static void stop(sctp_virtual_link *l) {
  check(cnet_sctp_data_stop(&l->a) == CNET_SCTP_DATA_OK);
  check(cnet_sctp_data_stop(&l->b) == CNET_SCTP_DATA_OK);
}
static void put16(uint8_t *p, uint16_t n) {
  p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n;
}
static void put32(uint8_t *p, uint32_t n) {
  p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16);
  p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}
static packet peer_sack(sctp_virtual_link *l, uint32_t cumulative,
                        uint16_t first, uint16_t last) {
  packet out; uint8_t v[16] = {0}; cnet_sctp_wire_chunk c = {0};
  put32(v, cumulative); put32(v + 4u, 32768u);
  put16(v + 8u, first != 0u); put16(v + 12u, first); put16(v + 14u, last);
  c.type = 3u; c.value = v; c.value_size = first ? 16u : 12u;
  check(cnet_sctp_wire_encode(l->b.config.local_port, l->b.config.remote_port,
      l->a.config.local_tag, &c, 1u, out.bytes, sizeof(out.bytes), &out.n) ==
      CNET_SCTP_WIRE_OK);
  return out;
}

static void application_limited(void) {
  sctp_virtual_link l; packet p, s; unsigned int i; uint32_t window;
  init(&l, 100u, 32768u); window = l.a.cwnd;
  for (i = 1u; i <= 32u; ++i) {
    check(send(&l, &p, i) == CNET_SCTP_DATA_OK);
    receive(&l, &p, &s); ack(&l, &s); take(&l, i);
    check(l.a.cwnd == window); /* tiny stop-and-wait never fills cwnd */
  }
  stop(&l);
}

static void padded_admission(void) {
  sctp_virtual_link l; packet p[16], out; cnet_sctp_data before;
  size_t flight = 0u, count = 0u;
  init(&l, UINT32_C(0xfffffffd), 32768u);
  while (flight < l.a.cwnd) {
    check(count < 16u);
    check(send(&l, &p[count], 609u) == CNET_SCTP_DATA_OK);
    check(p[count].n == 640u); /* 12 common + 16 DATA + 609 + 3 pad */
    flight += p[count++].n - 12u;
  }
  check(flight < l.a.cwnd + Q && l.a.in_flight == 609u * count);
  memcpy(&before, &l.a, sizeof(before)); memset(&out, 0xa5, sizeof(out));
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_CAPACITY);
  check(out.n == 0u && out.bytes[0] == 0xa5u);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  stop(&l);
  /* Receiver window is a separate user-buffer limit, never overbooked. */
  init(&l, 100u, 1024u);
  check(send(&l, &out, 1024u) == CNET_SCTP_DATA_OK);
  memcpy(&before, &l.a, sizeof(before));
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_CAPACITY);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  stop(&l);
}

static void full_window_growth(void) {
  unsigned int bundled;
  for (bundled = 1u; bundled <= 2u; ++bundled) {
    sctp_virtual_link l; packet p[16], s; unsigned int count = 0u, i;
    size_t flight = 0u; uint32_t window;
    init(&l, 100u, 32768u); window = l.a.cwnd;
    while (flight < window) {
      check(count < 16u);
      check(send(&l, &p[count], 1024u) == CNET_SCTP_DATA_OK);
      flight += p[count++].n - 12u;
    }
    for (i = 0u; i < bundled; ++i) receive(&l, &p[i], &s);
    ack(&l, &s); /* delayed SACK may acknowledge two chunks, L remains 1 */
    check(l.a.cwnd == window + (bundled == 1u ? 1040u : Q));
    window = l.a.cwnd; ack(&l, &s); check(l.a.cwnd == window);
    stop(&l);
  }
}

/* A full-rate ring keeps an independent byte-credit/window model. */
typedef struct stream {
  sctp_virtual_link l;
  packet queued[16];
  unsigned int first, count;
  size_t flight;
  uint32_t window, threshold, credit;
  unsigned int ca_growth, ca_no_growth;
} stream;
static void prepare_ca(stream *s) {
  packet p, retransmit, sack;
  memset(s, 0, sizeof(*s)); init(&s->l, 100u, 32768u);
  check(send(&s->l, &p, 1024u) == CNET_SCTP_DATA_OK);
  s->l.now = s->l.a.t3_deadline_ms;
  check(cnet_sctp_data_advance(&s->l.a, s->l.now++, retransmit.bytes,
      sizeof(retransmit.bytes), &retransmit.n) == CNET_SCTP_DATA_OK);
  check(retransmit.n == p.n && memcmp(p.bytes, retransmit.bytes, p.n) == 0);
  receive(&s->l, &retransmit, &sack); ack(&s->l, &sack); take(&s->l, 1024u);
  s->window = s->l.a.cwnd; s->threshold = s->l.a.ssthresh;
}
static void fill(stream *s, unsigned int max_new) {
  unsigned int added = 0u;
  while (s->count < 16u && s->flight < s->window && added < max_new) {
    packet *p = &s->queued[(s->first + s->count) % 16u];
    check(send(&s->l, p, 1024u) == CNET_SCTP_DATA_OK);
    s->flight += p->n - 12u; ++s->count; ++added;
  }
}
static void step(stream *s) {
  const packet *p = &s->queued[s->first];
  const uint32_t old_window = s->window;
  const int full = s->flight >= old_window;
  const int ca = old_window > s->threshold;
  const uint32_t bytes = (uint32_t)(p->n - 12u);
  uint32_t increment = 0u;
  check(s->count > 0u);
  if (ca) {
    s->credit += bytes;
    if (!full && s->credit > old_window) s->credit = old_window;
    if (full && s->credit >= old_window) {
      s->credit -= old_window; increment = Q; ++s->ca_growth;
    } else { ++s->ca_no_growth; }
  } else {
    s->credit = 0u;
    if (full) increment = bytes < Q ? bytes : Q;
  }
  if (increment > LIMIT - old_window) increment = LIMIT - old_window;
  s->window += increment;
  deliver(&s->l, p);
  s->flight -= bytes; --s->count; s->first = (s->first + 1u) % 16u;
  if (!s->count) s->credit = 0u;
  check(s->l.a.cwnd == s->window);
}
static void congestion_avoidance(void) {
  stream s; unsigned int i;
  prepare_ca(&s);
  for (i = 0u; i < 100u; ++i) { fill(&s, 16u); step(&s); }
  check(s.ca_growth >= 3u && s.ca_no_growth > s.ca_growth);
  stop(&s.l);
}
static void idle_credit_reset(void) {
  stream s; unsigned int i = 0u;
  prepare_ca(&s);
  while ((s.window <= s.threshold || !s.credit) && i++ < 100u) {
    fill(&s, 16u); step(&s);
  }
  check(i < 100u && s.credit);
  while (s.count) step(&s); /* application goes idle, all tickets settle */
  check(s.credit == 0u && s.l.a.in_flight == 0u);
  fill(&s, 16u); step(&s); /* no saved credit can cause premature growth */
  check(s.credit == 1040u);
  stop(&s.l);
}

static void gap_restore_accounting(void) {
  sctp_virtual_link l; packet p[16], s; unsigned int n = 0u, i;
  size_t flight = 0u; const uint32_t first = UINT32_C(0xfffffffd);
  uint32_t window;
  init(&l, first, 32768u); window = l.a.cwnd;
  while (flight < window) {
    check(n < 16u); check(send(&l, &p[n], 1024u) == CNET_SCTP_DATA_OK);
    flight += p[n++].n - 12u;
  }
  for (i = 0u; i < 4u; ++i) {
    s = peer_sack(&l, first - 1u, 3u, (uint16_t)n); ack(&l, &s);
    check(l.a.in_flight == 2048u && l.a.cwnd == window);
    s = peer_sack(&l, first - 1u, 0u, 0u); ack(&l, &s);
    check(l.a.in_flight == 1024u * n && l.a.cwnd == window);
  }
  s = peer_sack(&l, first - 1u, 3u, (uint16_t)n); ack(&l, &s);
  s = peer_sack(&l, first + n - 1u, 0u, 0u); ack(&l, &s);
  check(l.a.cwnd == window && l.a.in_flight == 0u);
  for (i = 0u; i < 16u; ++i) check(!l.a.tx[i].used);
  stop(&l);
}

static void refusal_atomicity(void) {
  stream s; cnet_sctp_data before;
  packet out, invalid; uint8_t body = 1u; unsigned int i = 0u;
  prepare_ca(&s);
  while ((s.window <= s.threshold || !s.credit) && i++ < 100u) {
    fill(&s, 16u); step(&s);
  }
  check(i < 100u && s.credit); /* rejection must preserve saved CA credit */
  memcpy(&before, &s.l.a, sizeof(before)); memset(&out, 0xa5, sizeof(out));
  check(cnet_sctp_data_send(&s.l.a, s.l.now, 0u, 53u, 0, &body, 1u,
      out.bytes, 0u, &out.n) == CNET_SCTP_DATA_CAPACITY);
  check(out.n == 0u && out.bytes[0] == 0xa5u);
  check(memcmp(&before, &s.l.a, sizeof(before)) == 0);
  s.l.owner = 0;
  check(cnet_sctp_data_send(&s.l.a, s.l.now, 0u, 53u, 0, &body, 1u,
      out.bytes, sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_OWNER);
  check(memcmp(&before, &s.l.a, sizeof(before)) == 0); s.l.owner = 1;
  invalid = peer_sack(&s.l, s.l.a.next_tsn + 1u, 0u, 0u);
  check(cnet_sctp_data_input(&s.l.a, s.l.now, invalid.bytes, invalid.n,
      out.bytes, sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_PROTOCOL);
  check(memcmp(&before, &s.l.a, sizeof(before)) == 0);
  stop(&s.l);
}

static void t3_single_packet(void) {
  sctp_virtual_link l; packet first, later, rtx, s, out; cnet_sctp_data before;
  init(&l, 100u, 32768u);
  check(send(&l, &first, 1u) == CNET_SCTP_DATA_OK);
  check(send(&l, &later, 1u) == CNET_SCTP_DATA_OK);
  l.now = l.a.t3_deadline_ms;
  check(cnet_sctp_data_advance(&l.a, l.now++, rtx.bytes,
      sizeof(rtx.bytes), &rtx.n) == CNET_SCTP_DATA_OK);
  memcpy(&before, &l.a, sizeof(before));
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_CAPACITY);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  receive(&l, &later, &s); ack(&l, &s); /* ACKing another chunk is not enough */
  memcpy(&before, &l.a, sizeof(before));
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_CAPACITY);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  receive(&l, &rtx, &s); ack(&l, &s);
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_OK);
  stop(&l);
}

/* A Gap ACK of the T3 retransmitted TSN is revocable; it must not
 * lift the one-packet post-timeout send gate before cumulative progress. */
static void t3_gap_ack_keeps_gate(void) {
  sctp_virtual_link l; packet first, later, sack, out;
  cnet_sctp_data before;
  init(&l, 100u, 32768u);
  check(send(&l, &first, 1u) == CNET_SCTP_DATA_OK);
  check(send(&l, &later, 1u) == CNET_SCTP_DATA_OK);
  l.now = l.a.t3_deadline_ms;
  check(cnet_sctp_data_advance(&l.a, l.now++, out.bytes,
      sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_OK);
  check(out.n == first.n && l.a.t3_wait_ack);
  sack = peer_sack(&l, 99u, 1u, 1u);
  ack(&l, &sack);
  check(l.a.t3_wait_ack);
  memcpy(&before, &l.a, sizeof(before));
  check(send(&l, &out, 1u) == CNET_SCTP_DATA_CAPACITY);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  sack = peer_sack(&l, 100u, 0u, 0u);
  ack(&l, &sack);
  check(!l.a.t3_wait_ack);
  stop(&l);
}

static void later_retransmit_window(void) {
  sctp_virtual_link l; packet p[8], s, out, first; cnet_sctp_data before;
  unsigned int i; uint32_t window;
  init(&l, 100u, 32768u);
  for (i = 0u; i < 7u; ++i)
    check(send(&l, &p[i], i < 4u ? 1024u : 1u) == CNET_SCTP_DATA_OK);
  for (i = 4u; i < 6u; ++i) { receive(&l, &p[i], &s); ack(&l, &s); }
  check(send(&l, &p[7], 1024u) == CNET_SCTP_DATA_OK);
  receive(&l, &p[6], &s); ack(&l, &s); /* third report, five big chunks in flight */
  check(cnet_sctp_data_advance(&l.a, l.now++, first.bytes,
      sizeof(first.bytes), &first.n) == CNET_SCTP_DATA_OK);
  check(first.n == p[0].n && memcmp(first.bytes, p[0].bytes, first.n) == 0);
  window = l.a.cwnd; memcpy(&before, &l.a, sizeof(before));
  memset(&out, 0xa5, sizeof(out));
  check(cnet_sctp_data_advance(&l.a, l.now++, out.bytes,
      sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_CAPACITY);
  check(out.n == 0u && out.bytes[0] == 0xa5u);
  check(memcmp(&before, &l.a, sizeof(before)) == 0);
  receive(&l, &first, &s); ack(&l, &s);
  check(cnet_sctp_data_advance(&l.a, l.now++, out.bytes,
      sizeof(out.bytes), &out.n) == CNET_SCTP_DATA_OK);
  check(out.n == p[1].n && memcmp(out.bytes, p[1].bytes, out.n) == 0);
  check(l.a.cwnd == window);
  stop(&l);
}

/* Exercise a legitimate huge monotonic clock delta without unsigned
 * overflow in the fixed-point SRTT/RTO estimator. */
static void huge_rtt_arithmetic(void) {
  sctp_virtual_link l; packet p, sack;
  const uint64_t late = UINT64_MAX / 2u;
  init(&l, 100u, 32768u);
  l.a.config.t3_max_ms = UINT64_MAX / 2u;
  l.a.config.t3_initial_ms = 100u;
  check(send(&l, &p, 1u) == CNET_SCTP_DATA_OK);
  receive(&l, &p, &sack);
  check(cnet_sctp_data_input(&l.a, late, sack.bytes, sack.n,
      p.bytes, sizeof(p.bytes), &p.n) == CNET_SCTP_DATA_OK);
  check(l.a.rtt_valid);
  check(l.a.srtt_x8_ms <= UINT64_MAX / 8u);
  check(l.a.rto_ms >= 100u && l.a.rto_ms <= UINT64_MAX / 2u);
  l.now = late + 1u;
  check(send(&l, &p, 1u) == CNET_SCTP_DATA_OK);
  receive(&l, &p, &sack);
  check(cnet_sctp_data_input(&l.a, late + UINT64_MAX / 4u,
      sack.bytes, sack.n, p.bytes, sizeof(p.bytes), &p.n) ==
      CNET_SCTP_DATA_OK);
  check(l.a.rtt_valid && l.a.srtt_x8_ms <= UINT64_MAX / 8u);
  check(l.a.rttvar_x4_ms <= UINT64_MAX / 32u);
  check(l.a.rto_ms >= 100u && l.a.rto_ms <= UINT64_MAX / 2u);
  stop(&l);
}

/* Gap-only SACKs can free flight accounting, but cannot prepay
 * congestion-avoidance credit before cumulative TSN progress. */
static void gap_only_no_ca_credit(void) {
  stream s; packet p[16], sack; unsigned int i = 0u;
  prepare_ca(&s);
  /* Reach congestion avoidance through real DATA/SACK exchanges. */
  while (s.window <= s.threshold && i++ < 100u) {
    fill(&s, 16u); step(&s);
  }
  check(i < 100u);
  while (s.count) step(&s);
  check(s.l.a.partial_bytes_acked == 0u);
  for (i = 0u; i < 4u; ++i)
    check(send(&s.l, &p[i], 1024u) == CNET_SCTP_DATA_OK);
  sack = peer_sack(&s.l, s.l.a.last_ack, 2u, 4u);
  ack(&s.l, &sack);
  check(s.l.a.partial_bytes_acked == 0u);
  check(s.l.a.in_flight == 1024u);
  stop(&s.l);
}


spec("SCTP Congestion window and backpressure") {
  it("[case:application_limited]") { application_limited(); }
  it("[case:padded_admission]") { padded_admission(); }
  it("[case:full_window_growth]") { full_window_growth(); }
  it("[case:congestion_avoidance]") { congestion_avoidance(); }
  it("[case:idle_credit_reset]") { idle_credit_reset(); }
  it("[case:gap_restore_accounting]") { gap_restore_accounting(); }
  it("[case:refusal_atomicity]") { refusal_atomicity(); }
  it("[case:t3_single_packet]") { t3_single_packet(); }
  it("[case:t3_gap_ack_keeps_gate]") { t3_gap_ack_keeps_gate(); }
  it("[case:later_retransmit_window]") { later_retransmit_window(); }
  it("[case:huge_rtt_arithmetic]") { huge_rtt_arithmetic(); }
  it("[case:gap_only_no_ca_credit]") { gap_only_no_ca_credit(); }
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
  static const char *const names[] = {"application_limited", "padded_admission", "full_window_growth", "congestion_avoidance", "idle_credit_reset", "gap_restore_accounting", "refusal_atomicity", "t3_single_packet", "t3_gap_ack_keeps_gate", "later_retransmit_window", "huge_rtt_arithmetic", "gap_only_no_ca_credit"};
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
