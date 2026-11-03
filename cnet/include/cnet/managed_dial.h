#ifndef CNET_MANAGED_DIAL_H
#define CNET_MANAGED_DIAL_H

#include <cnet/manager.h>
#include <cnet/recovery_policy.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_MANAGED_DIAL_VERSION 1u

typedef struct cnet_managed_dial {
  void *impl;
} cnet_managed_dial;

/* Application/protocol classifies real transport failures. A missing classifier
 * fails permanently, not by silently retrying. TLS authentication failures
 * must be classified SECURITY; CNet never falls back to plaintext. */
typedef cnet_reconnect_failure_kind (*cnet_dial_failure_classify_fn)(
    void *user, cnet_connection_state state, const cnet_error *error);

typedef struct cnet_managed_dial_config {
  size_t size;
  uint32_t version;
  cnet_manager *manager;  /* Borrowed. Host owns manager progress/recycle. */
  cnet_client *client;    /* Same CNet client passed to manager initialization. */
  cnet_connect_options connection; /* URI copied; TLS profile pointers borrowed. */
  cnet_reconnect_config recovery;
  uint64_t recovery_episode_ms; /* New absolute budget after a READY peer is lost. */
  cnet_dial_failure_classify_fn classify;
  void *classify_user;
  cnet_allocator storage;
} cnet_managed_dial_config;

typedef struct cnet_managed_dial_snapshot {
  cnet_reconnect_snapshot recovery;
  /* Current opaque attempt capability, snapshot only, NOT a new ownership
   * reference. The value becomes stale after a new attempt or dial destroy.
   * Pass back unchanged to protocol_ready only after handshake/auth succeeds. */
  cnet_reconnect_ticket recovery_ticket;
  cnet_managed_connection managed;
  cnet_connection connection;
  bool stopping;
  int last_error;
} cnet_managed_dial_snapshot;

/* One physical connection at a time, fixed initializing Owner. No implicit
 * NativeIO observe, worker/timer, retrying application DATA or new Manager.
 * The whole link + observer lifetime is kept until Manager on_recycle. */
int cnet_managed_dial_init(cnet_managed_dial *dial,
                            const cnet_managed_dial_config *config);

/* Optional owner-local admission hook, called before each eligible attempt,
 * after physical recycle/backoff checks and before consuming an attempt ticket.
 * It must verify old protocol settlement and reserve real host/pool capacity.
 * Return OK to admit, EBUSY/ENOBUFS to defer without consuming an attempt, or a
 * permanent error to the host. No callback is made while waiting for backoff.
 * No reentrant dial mutation, I/O progress or blocking is permitted. user is
 * borrowed until dial destroy. Host owns reservations and must release them
 * on abandoned episodes, including synchronous connect/admission failures.
 * Example: reject while old WS/leases remain, then pool_reserve_connecting;
 * retain that reservation across sequential opening retries until bind/abort.
 * Existing init remains ungated; config layout and its version are unchanged. */
typedef int (*cnet_dial_admit_fn)(void *user);
int cnet_managed_dial_init_admitted(cnet_managed_dial *dial,
    const cnet_managed_dial_config *config, cnet_dial_admit_fn admit, void *user);

/* Owner host calls only from its existing progress loop and **also** advances
 * CNet and cnet_manager_advance independently. An active/retired-but-not-yet
 * recycled Manager record returns EBUSY. The single ready-to-dial transition
 * actually calls manager_reserve/connect, with a generation-safe attempt
 * ticket. Local admission failures fail fast, not hidden recovery attempts.
 * EBUSY out_wait_ms describes remaining backoff only, never sleeps. */
int cnet_managed_dial_advance(cnet_managed_dial *dial, uint64_t now_ms,
                              uint64_t *out_wait_ms);

/* FlowMQ, HTTP, RPC etc. explicitly call this only after all of their
 * protocol authentication/handshake/admission is READY. CONNECTED alone
 * never resets backoff or grants application replay. Obtain the current
 * snapshot.recovery_ticket after observing CONNECTED; copy it unchanged.
 * Zero/stale/future attempt tickets fail closed (ENOENT/EALREADY).
 * Requires the current transport to remain OPEN: opening/handshaking returns
 * EBUSY; admitted close, FINAL send, directional shutdown, stopped client or
 * Manager request_close returns ESHUTDOWN before changing recovery accounting.
 * A rejected READY does not replace transport terminal or Manager recycle. */
int cnet_managed_dial_protocol_ready(cnet_managed_dial *dial,
                                     cnet_reconnect_ticket ticket,
                                     uint64_t now_ms);
int cnet_managed_dial_get_snapshot(cnet_managed_dial *dial,
                                   cnet_managed_dial_snapshot *out);

/* Stop only this dial's own physical connection, never unrelated manager
 * records. Recovery is sealed even when close admission fails. On failure,
 * keep the dial and drive CNet/Manager progress, then retry seal; repeated seal
 * reports the pending admission error until close is accepted. After success,
 * repeated seal is idempotent. Existing CNet terminal/Manager recycle must still
 * complete before destroy. advance remains ESHUTDOWN after recovery is sealed. */
int cnet_managed_dial_seal(cnet_managed_dial *dial);
int cnet_managed_dial_destroy(cnet_managed_dial *dial); /* EBUSY until recycle. */

#ifdef __cplusplus
}
#endif
#endif
