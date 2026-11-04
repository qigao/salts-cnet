/* Private formal-test workload shared by the two production transport paths.
 * No spec/main, sockets, second runtime, or production policy is defined here. */
#ifndef SALTSCORE_TEST_TLS_MIXED_WORKLOAD_H
#define SALTSCORE_TEST_TLS_MIXED_WORKLOAD_H

enum { TLS_MIXED_BYTES = 32768, TLS_MIXED_EXCHANGES = 512 };
typedef struct tls_mixed_state tls_mixed_state;
typedef struct tls_mixed_lane {
  tls_mixed_state *owner;
  bool bulk;
  size_t window;
  mem_buffer_t *source[2];
  size_t admitted[2], sent[2];
  uint64_t received[2];
  bool credit[2];
} tls_mixed_lane;
struct tls_mixed_state {
  tls_mixed_lane lane[2];
  size_t target;
  int error;
  uint64_t starts[TLS_MIXED_EXCHANGES], latency[TLS_MIXED_EXCHANGES];
};
typedef struct tls_mixed_usage { size_t operations, bytes, backing; } tls_mixed_usage;
typedef struct tls_mixed_stats {
  tls_mixed_usage usage[2][2];
  uint64_t native_submissions[2];
  size_t allocations, receives, policy_calls;
} tls_mixed_stats;
typedef struct tls_mixed_ops {
  void *context;
  int (*send)(void *, size_t, size_t, mem_buffer_t *);
  int (*receive)(void *, size_t, size_t);
  int (*progress)(void *, size_t);
  int (*snapshot)(void *, tls_mixed_stats *);
} tls_mixed_ops;
typedef struct tls_mixed_result {
  uint64_t elapsed, cpu, p50, p95, p99, bulk_bytes;
  uint64_t bulk_native, control_native, drain_bytes, drain_ns, drain_native;
  size_t bulk_admitted, rounds, rejected, calls, allocations, receives, peak_bytes, peak_backing;
} tls_mixed_result;

static int tls_mixed_init(tls_mixed_state *s, size_t window) {
  if (window != 1u && window != 8u) return SALTS_EINVAL;
  for (size_t i = 0u; i < 2u; ++i) {
    s->lane[i].owner = s;
    s->lane[i].bulk = i == 0u;
    s->lane[i].window = i == 0u ? window : 1u;
    for (size_t e = 0u; e < (i == 0u ? 1u : 2u); ++e) {
      const size_t bytes = i == 0u ? TLS_MIXED_BYTES : 1u;
      s->lane[i].source[e] = mem_get_buffer(mem_global(), bytes);
      if (!s->lane[i].source[e]) return SALTS_ENOMEM;
      mem_set_used(s->lane[i].source[e], bytes);
      for (size_t b = 0u; b < bytes; ++b)
        mem_buffer_data(s->lane[i].source[e])[b] = (char)((0x5au + b * 29u) & 0xffu);
    }
  }
  return SALTS_OK;
}
static void tls_mixed_release(tls_mixed_state *s) {
  for (size_t i = 0u; i < 2u; ++i)
    for (size_t e = 0u; e < 2u; ++e)
      if (s->lane[i].source[e]) mem_buffer_release(s->lane[i].source[e]);
}
static size_t tls_mixed_physical(const tls_mixed_state *s) {
  return mem_buffer_capacity(s->lane[0].source[0]) + mem_buffer_capacity(s->lane[1].source[0]) +
         mem_buffer_capacity(s->lane[1].source[1]);
}
static void tls_mixed_sent(tls_mixed_lane *lane, size_t end, size_t bytes) {
  if (end > 1u || (lane->bulk && end != 0u) || bytes != (lane->bulk ? TLS_MIXED_BYTES : 1u) ||
      lane->sent[end] >= lane->admitted[end]) { lane->owner->error = SALTS_EPROTO; return; }
  ++lane->sent[end];
}
static void tls_mixed_received(tls_mixed_lane *lane, size_t end, const void *data, size_t bytes) {
  tls_mixed_state *s = lane->owner;
  if (end > 1u || !lane->credit[end] || !data || bytes == 0u) { s->error = SALTS_EPROTO; return; }
  lane->credit[end] = false;
  const unsigned char *p = data;
  if (lane->bulk) {
    const uint64_t expected = (uint64_t)lane->admitted[0] * TLS_MIXED_BYTES;
    if (end != 1u || lane->received[1] > expected || bytes > expected - lane->received[1]) {
      s->error = SALTS_EPROTO; return;
    }
    for (size_t i = 0u; i < bytes; ++i)
      if (p[i] != (unsigned char)((0x5au + ((lane->received[1] + i) % TLS_MIXED_BYTES) * 29u) & 0xffu)) {
        s->error = SALTS_EPROTO; return;
      }
    lane->received[1] += bytes;
  } else {
    const uint64_t index = lane->received[end];
    const size_t admitted = lane->admitted[end == 0u ? 1u : 0u];
    if (bytes != 1u || index >= admitted || index >= s->target ||
        p[0] != (unsigned char)((end == 0u ? 0xc0u : 0x40u) + index)) {
      s->error = SALTS_EPROTO; return;
    }
    if (end == 0u) s->latency[index] = cmeta_hrtime() - s->starts[index];
    ++lane->received[end];
  }
}
static int tls_mixed_cpu(uint64_t *out) {
#if defined(_WIN32)
  FILETIME created, exited, kernel, user;
  if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return SALTS_EIO;
  *out = ((((uint64_t)kernel.dwHighDateTime << 32u) | kernel.dwLowDateTime) +
          (((uint64_t)user.dwHighDateTime << 32u) | user.dwLowDateTime)) * UINT64_C(100);
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) return SALTS_EIO;
  *out = ((uint64_t)usage.ru_utime.tv_sec + (uint64_t)usage.ru_stime.tv_sec) * UINT64_C(1000000000) +
         ((uint64_t)usage.ru_utime.tv_usec + (uint64_t)usage.ru_stime.tv_usec) * UINT64_C(1000);
#endif
  return SALTS_OK;
}
static int tls_mixed_compare(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static bool tls_mixed_control_done(const tls_mixed_state *s) {
  const tls_mixed_lane *c = &s->lane[1];
  return c->admitted[0] == s->target && c->admitted[1] == s->target &&
      c->sent[0] == s->target && c->sent[1] == s->target &&
      c->received[0] == s->target && c->received[1] == s->target;
}
static bool tls_mixed_bulk_done(const tls_mixed_state *s) {
  const tls_mixed_lane *b = &s->lane[0];
  return b->sent[0] == b->admitted[0] && b->received[1] == (uint64_t)b->admitted[0] * TLS_MIXED_BYTES;
}
static int tls_mixed_send(tls_mixed_state *s, const tls_mixed_ops *ops, size_t lane, size_t end) {
  tls_mixed_lane *l = &s->lane[lane];
  if (l->admitted[end] >= UINT64_MAX / TLS_MIXED_BYTES) return SALTS_ERANGE;
  const int status = ops->send(ops->context, lane, end, l->source[end]);
  if (status == SALTS_OK) ++l->admitted[end];
  return status;
}
static int tls_mixed_receive(tls_mixed_state *s, const tls_mixed_ops *ops) {
  for (size_t i = 0u; i < 2u; ++i) {
    tls_mixed_lane *l = &s->lane[i];
    for (size_t e = 0u; e < 2u; ++e) {
      const uint64_t expected = l->bulk ? (e == 1u ? (uint64_t)l->admitted[0] * TLS_MIXED_BYTES : 0u)
                                        : l->admitted[e == 0u ? 1u : 0u];
      if (!l->credit[e] && l->received[e] < expected) {
        const int status = ops->receive(ops->context, i, e);
        if (status != SALTS_OK) return status;
        l->credit[e] = true;
      }
    }
  }
  return SALTS_OK;
}
static int tls_mixed_progress(tls_mixed_state *s, const tls_mixed_ops *ops) {
  int first = SALTS_OK;
  for (size_t i = 0u; i < 2u; ++i) {
    const int status = ops->progress(ops->context, i);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
  }
  return first != SALTS_OK ? first : s->error;
}
static int tls_mixed_usage_check(tls_mixed_state *s, const tls_mixed_stats *stats, tls_mixed_result *out) {
  size_t bytes = 0u, backing = 0u;
  for (size_t i = 0u; i < 2u; ++i) {
    tls_mixed_lane *l = &s->lane[i];
    for (size_t e = 0u; e < 2u; ++e) {
      const tls_mixed_usage *u = &stats->usage[i][e];
      if (l->sent[e] > l->admitted[e] || u->operations != l->admitted[e] - l->sent[e]) return SALTS_EPROTO;
      if (!l->source[e]) { if (u->operations || u->bytes || u->backing) return SALTS_EPROTO; continue; }
      if (u->operations > l->window || u->bytes != u->operations * mem_buffer_used(l->source[e]) ||
          u->backing != u->operations * mem_buffer_capacity(l->source[e]) ||
          mem_buffer_ref_count(l->source[e]) != 1u + u->operations) return SALTS_EPROTO;
      bytes += u->bytes; backing += u->backing;
    }
  }
  if (bytes > out->peak_bytes) out->peak_bytes = bytes;
  if (backing > out->peak_backing) out->peak_backing = backing;
  return SALTS_OK;
}
static int tls_mixed_phase(tls_mixed_state *s, const tls_mixed_ops *ops, size_t exchanges, tls_mixed_result *out) {
  tls_mixed_stats before, after, drained;
  uint64_t cpu_start, cpu_end;
  if (exchanges == 0u || exchanges > TLS_MIXED_EXCHANGES || s->error) return SALTS_EINVAL;
  if (s->target && (!tls_mixed_control_done(s) || !tls_mixed_bulk_done(s))) return SALTS_EBUSY;
  *out = (tls_mixed_result){0};
  for (size_t i = 0u; i < 2u; ++i) {
    tls_mixed_lane *l = &s->lane[i];
    for (size_t e = 0u; e < 2u; ++e) {
      if (l->admitted[e] != l->sent[e] || l->credit[e] ||
          (l->source[e] && mem_buffer_ref_count(l->source[e]) != 1u)) return SALTS_EBUSY;
      l->admitted[e] = l->sent[e] = 0u; l->received[e] = 0u;
    }
  }
  s->target = exchanges;
  if (ops->snapshot(ops->context, &before) != SALTS_OK || tls_mixed_cpu(&cpu_start) != SALTS_OK) return SALTS_EIO;
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(20000000000);
  while (!tls_mixed_control_done(s) && cmeta_hrtime() < deadline) {
    tls_mixed_lane *b = &s->lane[0], *c = &s->lane[1];
    while (b->admitted[0] - b->sent[0] < b->window) {
      const int status = tls_mixed_send(s, ops, 0u, 0u);
      if (status != SALTS_OK) return status;
    }
    if (b->window == 8u) {
      const unsigned refs = mem_buffer_ref_count(b->source[0]);
      if (ops->send(ops->context, 0u, 0u, b->source[0]) != SALTS_ENOBUFS ||
          mem_buffer_ref_count(b->source[0]) != refs) return SALTS_EPROTO;
      ++out->rejected;
    }
    const size_t n = c->admitted[0];
    if (n < exchanges && c->sent[0] == n && c->sent[1] == n && c->received[0] == n && c->received[1] == n) {
      if (mem_buffer_ref_count(c->source[0]) != 1u || mem_buffer_ref_count(c->source[1]) != 1u) return SALTS_EPROTO;
      *mem_buffer_data(c->source[0]) = (char)(0x40u + n);
      s->starts[n] = cmeta_hrtime();
      const int status = tls_mixed_send(s, ops, 1u, 0u);
      if (status != SALTS_OK) return status;
    }
    if (c->received[1] > c->admitted[1]) {
      if (mem_buffer_ref_count(c->source[1]) != 1u) return SALTS_EPROTO;
      *mem_buffer_data(c->source[1]) = (char)(0xc0u + c->admitted[1]);
      const int status = tls_mixed_send(s, ops, 1u, 1u);
      if (status != SALTS_OK) return status;
    }
    int status = tls_mixed_receive(s, ops);
    if (status != SALTS_OK) return status;
    if (ops->snapshot(ops->context, &after) != SALTS_OK ||
        tls_mixed_usage_check(s, &after, out) != SALTS_OK) return SALTS_EPROTO;
    status = tls_mixed_progress(s, ops);
    if (status != SALTS_OK) return status;
    ++out->rounds;
  }
  out->elapsed = cmeta_hrtime() - start;
  if (tls_mixed_cpu(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu = cpu_end - cpu_start;
  if (!tls_mixed_control_done(s)) return SALTS_ETIMEDOUT;
  if (ops->snapshot(ops->context, &after) != SALTS_OK ||
      tls_mixed_usage_check(s, &after, out) != SALTS_OK) return SALTS_EPROTO;
  out->bulk_bytes = s->lane[0].received[1];
  out->bulk_admitted = s->lane[0].admitted[0];
  out->bulk_native = after.native_submissions[0] - before.native_submissions[0];
  out->control_native = after.native_submissions[1] - before.native_submissions[1];
  out->calls = after.policy_calls - before.policy_calls;
  out->allocations = after.allocations - before.allocations;
  out->receives = after.receives - before.receives;
  const uint64_t drain_start = cmeta_hrtime(), drain_deadline = drain_start + UINT64_C(20000000000);
  while (!tls_mixed_bulk_done(s) && cmeta_hrtime() < drain_deadline) {
    int status = tls_mixed_receive(s, ops);
    if (status == SALTS_OK) status = tls_mixed_progress(s, ops);
    if (status != SALTS_OK) return status;
  }
  out->drain_ns = cmeta_hrtime() - drain_start;
  out->drain_bytes = s->lane[0].received[1] - out->bulk_bytes;
  if (!tls_mixed_bulk_done(s) || ops->snapshot(ops->context, &drained) != SALTS_OK ||
      tls_mixed_usage_check(s, &drained, out) != SALTS_OK) return SALTS_EPROTO;
  out->drain_native = drained.native_submissions[0] + drained.native_submissions[1] -
                      after.native_submissions[0] - after.native_submissions[1];
  for (size_t i = 0u; i < 2u; ++i)
    for (size_t e = 0u; e < 2u; ++e)
      if (drained.usage[i][e].operations || s->lane[i].credit[e] ||
          (s->lane[i].source[e] && mem_buffer_ref_count(s->lane[i].source[e]) != 1u)) return SALTS_EPROTO;
  if (out->elapsed == 0u || out->bulk_bytes == 0u || out->allocations != 0u ||
      (s->lane[0].window == 8u) != (out->rejected != 0u))
    return SALTS_EPROTO;
  qsort(s->latency, exchanges, sizeof(s->latency[0]), tls_mixed_compare);
  out->p50 = s->latency[(exchanges * 50u + 99u) / 100u - 1u];
  out->p95 = s->latency[(exchanges * 95u + 99u) / 100u - 1u];
  out->p99 = s->latency[(exchanges * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}
static void tls_mixed_print(const char *mode, unsigned repetition, const tls_mixed_state *s,
                            const tls_mixed_result *r, uint64_t close_ns, const char *version, const char *cipher) {
  printf("CNET_TLS_MIXED_CSV,mode,repeat,bulk_depth,exchanges,elapsed_ns,cpu_ns,p50_rtt_ns,p95_rtt_ns,p99_rtt_ns,bulk_peer_bytes,bulk_admitted,host_rounds,rejected,policy_calls,storage_allocations,receive_acquires,peak_logical_bytes,peak_backing_bytes,physical_source_bytes,bulk_native_submissions,control_native_submissions,bulk_drain_bytes,bulk_drain_ns,drain_native_submissions,close_ns,version,cipher\n");
  printf("CNET_TLS_MIXED_CSV,%s,%u,%zu,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%s\n",
      mode, repetition, s->lane[0].window, s->target,
      (unsigned long long)r->elapsed, (unsigned long long)r->cpu,
      (unsigned long long)r->p50, (unsigned long long)r->p95, (unsigned long long)r->p99,
      (unsigned long long)r->bulk_bytes, r->bulk_admitted, r->rounds, r->rejected,
      r->calls, r->allocations, r->receives, r->peak_bytes, r->peak_backing, tls_mixed_physical(s),
      (unsigned long long)r->bulk_native, (unsigned long long)r->control_native,
      (unsigned long long)r->drain_bytes, (unsigned long long)r->drain_ns,
      (unsigned long long)r->drain_native, (unsigned long long)close_ns, version, cipher);
}
#endif
