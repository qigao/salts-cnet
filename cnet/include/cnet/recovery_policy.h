#ifndef CNET_RECOVERY_POLICY_H
#define CNET_RECOVERY_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_RECOVERY_POLICY_VERSION 1u

/* Explicit, owner-local bounded transport restoration. No socket, deadline
 * timer, background worker, retrying payload or hidden connection is created.
 * One client/transport attempt and its FMQ/HTTP/other protocol handshake are
 * owned by the embedding caller. This state is address-stable; do not copy it. */
typedef struct cnet_backoff_input {
  uint32_t attempts;
  uint64_t initial_ms;
  uint64_t maximum_ms;
  uint64_t exponential_ms;
  uint64_t random_value;
} cnet_backoff_input;
typedef int (*cnet_backoff_fn)(void *user, const cnet_backoff_input *input, uint64_t *delay_ms);
typedef struct cnet_backoff_policy { cnet_backoff_fn delay; void *user; } cnet_backoff_policy;
int cnet_backoff_fixed(void *user, const cnet_backoff_input *input, uint64_t *delay_ms);
int cnet_backoff_exponential_jitter(void *user, const cnet_backoff_input *input, uint64_t *delay_ms);
/* Copied per recovery episode. Pure bounded decision, no I/O/reentrant mutation.
 * Delay must be <= maximum_backoff_ms. Core still enforces attempts, deadlines,
 * security sealing and generation identity. Zero selects exponential jitter. */
typedef struct cnet_reconnect_config {
  size_t size;
  uint32_t version;
  uint32_t max_attempts;
  uint64_t deadline_ms; /* Absolute monotonic budget for this recovery episode. */
  uint64_t initial_backoff_ms;
  uint64_t maximum_backoff_ms;
  cnet_backoff_policy backoff;
  uint64_t jitter_seed; /* Explicit deterministic seed for tests/reproducibility. */
} cnet_reconnect_config;

typedef struct cnet_reconnect_state {
  cnet_reconnect_config config;
  const void *owner_thread;
  uintptr_t owner_address;
  uint64_t incarnation;
  uint64_t generation;
  uint64_t random_state;
  uint64_t last_backoff_ms;
  uint64_t next_attempt_ms;
  uint32_t attempts;
  bool in_flight;
  bool awaiting_protocol;
  bool protocol_ready;
  bool sealed;
  bool evaluating;
} cnet_reconnect_state;

typedef struct cnet_reconnect_ticket {
  uintptr_t state;
  uint64_t incarnation;
  uint64_t generation;
} cnet_reconnect_ticket;

typedef enum cnet_reconnect_failure_kind {
  CNET_RECONNECT_TRANSIENT = 1,
  CNET_RECONNECT_SECURITY = 2,
  CNET_RECONNECT_PERMANENT = 3
} cnet_reconnect_failure_kind;

typedef struct cnet_reconnect_snapshot {
  uint32_t attempts;
  uint32_t max_attempts;
  uint64_t generation;
  uint64_t next_attempt_ms;
  uint64_t deadline_ms;
  bool in_flight;
  bool awaiting_protocol;
  bool protocol_ready;
  bool sealed;
} cnet_reconnect_snapshot;

int cnet_reconnect_init(cnet_reconnect_state *state, const cnet_reconnect_config *config);
/* Returns EBUSY and the exact remaining delay if still waiting. No timer is
 * armed. One accepted attempt returns a unique generation token. */
int cnet_reconnect_begin(cnet_reconnect_state *state, uint64_t now_ms,
                         cnet_reconnect_ticket *out_ticket, uint64_t *out_wait_ms);
/* TRANSPORT_CONNECTED is not protocol READY; it does not reset backoff. */
int cnet_reconnect_connected(cnet_reconnect_state *state,
                             cnet_reconnect_ticket ticket, uint64_t now_ms);
/* Caller must verify full protocol handshake, authority and identity. */
int cnet_reconnect_protocol_ready(cnet_reconnect_state *state,
                                  cnet_reconnect_ticket ticket, uint64_t now_ms);
/* Failure of connect or protocol handshake schedules the configured bounded
 * delay (default: deterministic half-to-full jitter). Security/auth failures
 * seal instead of downgrading. */
int cnet_reconnect_failed(cnet_reconnect_state *state, cnet_reconnect_ticket ticket,
                          cnet_reconnect_failure_kind kind, uint64_t now_ms);
/* Only an already protocol-ready session may start a new recovery episode.
 * next_deadline_ms is its new absolute monotonic overall deadline. */
int cnet_reconnect_lost(cnet_reconnect_state *state, cnet_reconnect_ticket ticket,
                        cnet_reconnect_failure_kind kind, uint64_t now_ms,
                        uint64_t next_deadline_ms);
int cnet_reconnect_seal(cnet_reconnect_state *state);
int cnet_reconnect_get_snapshot(const cnet_reconnect_state *state,
                                cnet_reconnect_snapshot *out);

/* Pure authorization gate for one *logical application request* retry. A
 * successful decision is not a retry, data replay, or remote exactly-once ACK.
 * Protocol layers must establish the listed facts and keep body bytes alive. */
typedef enum cnet_retry_reason {
  CNET_RETRY_ALLOWED = 0,
  CNET_RETRY_DISABLED,
  CNET_RETRY_ONE_ATTEMPT,
  CNET_RETRY_CANCELLED,
  CNET_RETRY_SECURITY,
  CNET_RETRY_DEADLINE,
  CNET_RETRY_BUDGET,
  CNET_RETRY_UNREPLAYABLE,
  CNET_RETRY_UNAUTHORIZED,
  CNET_RETRY_WAIT_BACKOFF
} cnet_retry_reason;

typedef struct cnet_retry_input {
  size_t size;
  uint32_t version;
  uint32_t attempts_used; /* Including the original attempt. */
  uint32_t max_attempts;
  uint64_t now_ms;
  uint64_t deadline_ms;
  uint64_t backoff_not_before_ms;
  size_t request_body_bytes;
  size_t remaining_retry_byte_budget;
  bool explicitly_enabled;
  bool one_attempt_contract;
  bool cancelled;
  bool security_failure;
  bool owned_replayable_body;
  bool protocol_proves_not_executed;
  bool application_declares_idempotent;
} cnet_retry_input;

typedef struct cnet_retry_result {
  bool allowed;
  cnet_retry_reason reason;
} cnet_retry_result;
int cnet_retry_evaluate(const cnet_retry_input *input, cnet_retry_result *out);

#ifdef __cplusplus
}
#endif
#endif
