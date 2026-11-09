#include <cnet/recovery_policy.h>
#include <salts/error_codes.h>
#include <threads/threads.h>
#include <stdatomic.h>
#include <string.h>

static atomic_uint_fast64_t recovery_incarnation;

static int recovery_check(const cnet_reconnect_state *s) {
  if (s == NULL || s->owner_address != (uintptr_t)s ||
      s->config.size != sizeof(s->config) ||
      s->config.version != CNET_RECOVERY_POLICY_VERSION ||
      s->incarnation == 0u) return SALTS_EINVAL;
  if (s->evaluating) return SALTS_EBUSY;
  return s->owner_thread == sync_thread_current_token() ? SALTS_OK : SALTS_EPERM;
}
static int recovery_ticket(const cnet_reconnect_state *s, cnet_reconnect_ticket t) {
  int status = recovery_check(s);
  if (status != SALTS_OK) return status;
  return t.state == (uintptr_t)s && t.incarnation == s->incarnation &&
         t.generation == s->generation && t.generation != 0u
             ? SALTS_OK : SALTS_ENOENT;
}
static uint64_t recovery_mix64(uint64_t *state) {
  uint64_t x = (*state += UINT64_C(0x9e3779b97f4a7c15));
  x = (x ^ (x >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27u)) * UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31u);
}
int cnet_backoff_fixed(void *user, const cnet_backoff_input *input, uint64_t *out) {
  (void)user;
  if (input == NULL || out == NULL || input->initial_ms > input->maximum_ms) return SALTS_EINVAL;
  *out = input->initial_ms;
  return SALTS_OK;
}
int cnet_backoff_exponential_jitter(void *user, const cnet_backoff_input *input, uint64_t *out) {
  (void)user;
  if (input == NULL || out == NULL || input->exponential_ms > input->maximum_ms) return SALTS_EINVAL;
  uint64_t half = input->exponential_ms / 2u + input->exponential_ms % 2u;
  uint64_t span = input->exponential_ms - half;
  *out = half + (span == 0u ? 0u : input->random_value % (span + 1u));
  return SALTS_OK;
}
static int recovery_schedule(cnet_reconnect_state *s, uint64_t now_ms) {
  const uint64_t upper = s->config.maximum_backoff_ms;
  uint64_t delay = 0u;
  if (s->last_backoff_ms == 0u) {
    s->last_backoff_ms = s->config.initial_backoff_ms;
  } else if (s->last_backoff_ms >= upper || s->last_backoff_ms > upper / 2u) {
    s->last_backoff_ms = upper;
  } else {
    s->last_backoff_ms *= 2u;
  }
  const cnet_backoff_input input = {s->attempts, s->config.initial_backoff_ms,
      upper, s->last_backoff_ms, recovery_mix64(&s->random_state)};
  cnet_backoff_fn choose = s->config.backoff.delay != NULL
      ? s->config.backoff.delay : cnet_backoff_exponential_jitter;
  s->evaluating = true;
  int status = choose(s->config.backoff.user, &input, &delay);
  s->evaluating = false;
  if (status != SALTS_OK || delay > upper) {
    s->sealed = true;
    return status != SALTS_OK ? status : SALTS_EINVAL;
  }
  s->next_attempt_ms = delay > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + delay;
  if (s->next_attempt_ms >= s->config.deadline_ms) s->next_attempt_ms = UINT64_MAX;
  return SALTS_OK;
}
int cnet_reconnect_init(cnet_reconnect_state *s, const cnet_reconnect_config *c) {
  uint_fast64_t current;
  if (s == NULL || c == NULL || c->size != sizeof(*c) ||
      c->version != CNET_RECOVERY_POLICY_VERSION || c->max_attempts == 0u ||
      c->deadline_ms == 0u || c->initial_backoff_ms > c->maximum_backoff_ms ||
      (c->backoff.delay == NULL && c->backoff.user != NULL))
    return SALTS_EINVAL;
  if (s->owner_address == (uintptr_t)s && s->incarnation != 0u)
    return SALTS_EALREADY;
  current = atomic_load_explicit(&recovery_incarnation, memory_order_relaxed);
  do {
    if (current == UINT64_MAX) return SALTS_ERANGE;
  } while (!atomic_compare_exchange_weak_explicit(
      &recovery_incarnation, &current, current + 1u,
      memory_order_relaxed, memory_order_relaxed));
  memset(s, 0, sizeof(*s));
  s->config = *c;
  s->owner_thread = sync_thread_current_token();
  s->owner_address = (uintptr_t)s;
  s->incarnation = (uint64_t)(current + 1u);
  s->random_state = c->jitter_seed;
  return SALTS_OK;
}
int cnet_reconnect_begin(cnet_reconnect_state *s, uint64_t now_ms,
                         cnet_reconnect_ticket *out, uint64_t *out_wait_ms) {
  int status;
  if (out != NULL) *out = (cnet_reconnect_ticket){0};
  if (out_wait_ms != NULL) *out_wait_ms = 0u;
  status = recovery_check(s);
  if (status != SALTS_OK) return status;
  if (out == NULL || out_wait_ms == NULL) return SALTS_EINVAL;
  if (s->sealed) return SALTS_ESHUTDOWN;
  if (s->in_flight || s->awaiting_protocol || s->protocol_ready) return SALTS_EBUSY;
  if (now_ms >= s->config.deadline_ms || s->next_attempt_ms == UINT64_MAX)
    return SALTS_ETIMEDOUT;
  if (s->attempts >= s->config.max_attempts) return SALTS_ENOBUFS;
  if (now_ms < s->next_attempt_ms) {
    *out_wait_ms = s->next_attempt_ms - now_ms;
    return SALTS_EBUSY;
  }
  if (s->generation == UINT64_MAX) return SALTS_ERANGE;
  ++s->generation;
  ++s->attempts;
  s->in_flight = true;
  *out = (cnet_reconnect_ticket){(uintptr_t)s, s->incarnation, s->generation};
  return SALTS_OK;
}
int cnet_reconnect_connected(cnet_reconnect_state *s, cnet_reconnect_ticket t,
                             uint64_t now_ms) {
  int status = recovery_ticket(s, t);
  if (status != SALTS_OK) return status;
  if (!s->in_flight || s->awaiting_protocol || s->protocol_ready) return SALTS_EALREADY;
  s->in_flight = false;
  if (now_ms >= s->config.deadline_ms) {
    s->sealed = true;
    return SALTS_ETIMEDOUT;
  }
  s->awaiting_protocol = true;
  return SALTS_OK;
}
int cnet_reconnect_protocol_ready(cnet_reconnect_state *s, cnet_reconnect_ticket t,
                                  uint64_t now_ms) {
  int status = recovery_ticket(s, t);
  if (status != SALTS_OK) return status;
  if (s->protocol_ready) return SALTS_EALREADY;
  if (!s->awaiting_protocol || s->sealed) return SALTS_EBUSY;
  if (now_ms >= s->config.deadline_ms) {
    s->awaiting_protocol = false;
    s->sealed = true;
    return SALTS_ETIMEDOUT;
  }
  s->awaiting_protocol = false;
  s->protocol_ready = true;
  s->attempts = 0u; /* New failure episode starts after an authorized READY. */
  s->last_backoff_ms = 0u;
  s->next_attempt_ms = 0u;
  return SALTS_OK;
}
int cnet_reconnect_failed(cnet_reconnect_state *s, cnet_reconnect_ticket t,
                          cnet_reconnect_failure_kind kind, uint64_t now_ms) {
  int status = recovery_ticket(s, t);
  if (status != SALTS_OK) return status;
  if (kind != CNET_RECONNECT_TRANSIENT && kind != CNET_RECONNECT_SECURITY &&
      kind != CNET_RECONNECT_PERMANENT) return SALTS_EINVAL;
  if (!s->in_flight && !s->awaiting_protocol) return SALTS_EALREADY;
  s->in_flight = false;
  s->awaiting_protocol = false;
  if (kind != CNET_RECONNECT_TRANSIENT || now_ms >= s->config.deadline_ms) {
    s->sealed = true;
    return SALTS_OK;
  }
  return recovery_schedule(s, now_ms);
}
int cnet_reconnect_lost(cnet_reconnect_state *s, cnet_reconnect_ticket t,
                        cnet_reconnect_failure_kind kind, uint64_t now_ms,
                        uint64_t next_deadline_ms) {
  int status = recovery_ticket(s, t);
  if (status != SALTS_OK) return status;
  if (!s->protocol_ready) return SALTS_EALREADY;
  if (kind != CNET_RECONNECT_TRANSIENT && kind != CNET_RECONNECT_SECURITY &&
      kind != CNET_RECONNECT_PERMANENT) return SALTS_EINVAL;
  if (next_deadline_ms <= now_ms) {
    /* The peer is gone regardless of whether the new budget is usable. */
    s->protocol_ready = false;
    s->sealed = true;
    return SALTS_ETIMEDOUT;
  }
  s->protocol_ready = false;
  s->config.deadline_ms = next_deadline_ms;
  if (kind != CNET_RECONNECT_TRANSIENT) {
    s->sealed = true;
    return SALTS_OK;
  }
  return recovery_schedule(s, now_ms);
}
int cnet_reconnect_seal(cnet_reconnect_state *s) {
  int status = recovery_check(s);
  if (status != SALTS_OK) return status;
  s->sealed = true;
  return SALTS_OK;
}
int cnet_reconnect_get_snapshot(const cnet_reconnect_state *s,
                                cnet_reconnect_snapshot *out) {
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_reconnect_snapshot){0};
  status = recovery_check(s);
  if (status != SALTS_OK) return status;
  *out = (cnet_reconnect_snapshot){
      s->attempts, s->config.max_attempts, s->generation, s->next_attempt_ms,
      s->config.deadline_ms, s->in_flight, s->awaiting_protocol,
      s->protocol_ready, s->sealed};
  return SALTS_OK;
}
int cnet_retry_evaluate(const cnet_retry_input *in, cnet_retry_result *out) {
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_retry_result){false, CNET_RETRY_DISABLED};
  if (in == NULL || in->size != sizeof(*in) ||
      in->version != CNET_RECOVERY_POLICY_VERSION || in->max_attempts == 0u ||
      in->attempts_used == 0u || in->deadline_ms == 0u)
    return SALTS_EINVAL;
  if (!in->explicitly_enabled) out->reason = CNET_RETRY_DISABLED;
  else if (in->one_attempt_contract) out->reason = CNET_RETRY_ONE_ATTEMPT;
  else if (in->cancelled) out->reason = CNET_RETRY_CANCELLED;
  else if (in->security_failure) out->reason = CNET_RETRY_SECURITY;
  else if (in->now_ms >= in->deadline_ms ||
           in->backoff_not_before_ms >= in->deadline_ms)
    out->reason = CNET_RETRY_DEADLINE;
  else if (in->attempts_used >= in->max_attempts ||
           in->request_body_bytes > in->remaining_retry_byte_budget)
    out->reason = CNET_RETRY_BUDGET;
  else if (!in->owned_replayable_body) out->reason = CNET_RETRY_UNREPLAYABLE;
  else if (!in->protocol_proves_not_executed &&
           !in->application_declares_idempotent)
    out->reason = CNET_RETRY_UNAUTHORIZED;
  else if (in->backoff_not_before_ms > in->now_ms)
    out->reason = CNET_RETRY_WAIT_BACKOFF;
  else {
    out->allowed = true;
    out->reason = CNET_RETRY_ALLOWED;
  }
  return SALTS_OK;
}
