#include "cnet_resources.h"
#include <cnet/managed_dial.h>
#include <clock.h>
#include <error_codes.h>
#include <thread.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { CNET_MANAGED_DIAL_URI_MAX = 4096u };

typedef struct dial_impl {
  cnet_manager *manager;
  cnet_client *client;
  const void *owner_thread;
  cnet_connect_options options;
  cnet_observer user_observer;
  cnet_dial_failure_classify_fn classifier;
  void *classify_user;
  cnet_dial_admit_fn admit;
  void *admit_user;
  cnet_reconnect_state recovery;
  cnet_reconnect_ticket ticket;
  cnet_managed_connection managed;
  cnet_connection connection;
  char *uri;
  uint64_t episode_ms;
  int last_error;
  bool stopping;
  bool close_admitted;
  bool in_callback;
} dial_impl;

static int dial_owner(cnet_managed_dial *dial, dial_impl **out) {
  if (out != NULL) *out = NULL;
  if (dial == NULL || dial->impl == NULL || out == NULL) return SALTS_EINVAL;
  *out = (dial_impl *)dial->impl;
  return (*out)->owner_thread == cmeta_thread_current_token() ? SALTS_OK : SALTS_EPERM;
}
static void dial_record_error(dial_impl *impl, int status) {
  if (status != SALTS_OK && impl->last_error == SALTS_OK)
    impl->last_error = status;
}
static uint64_t dial_deadline(uint64_t now_ms, uint64_t episode_ms) {
  return episode_ms > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + episode_ms;
}
static cnet_reconnect_failure_kind dial_classify(
    dial_impl *impl, cnet_connection_state state, const cnet_error *error) {
  cnet_reconnect_failure_kind kind =
      impl->classifier == NULL ? CNET_RECONNECT_PERMANENT :
      impl->classifier(impl->classify_user, state, error);
  if (kind != CNET_RECONNECT_TRANSIENT &&
      kind != CNET_RECONNECT_PERMANENT &&
      kind != CNET_RECONNECT_SECURITY) {
    dial_record_error(impl, SALTS_EINVAL);
    return CNET_RECONNECT_PERMANENT;
  }
  return kind;
}
static void dial_on_state(void *user, cnet_connection connection,
                          cnet_connection_state state, const cnet_error *error) {
  dial_impl *impl = (dial_impl *)user;
  int status = SALTS_OK;
  impl->in_callback = true;
  if (state == CNET_CONNECTION_CONNECTED && !impl->stopping) {
    status = cnet_reconnect_connected(
        &impl->recovery, impl->ticket, cmeta_monotonic_ms());
    if (status != SALTS_OK) (void)cnet_close(impl->client, connection);
  } else if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    if (!impl->stopping) {
      cnet_reconnect_snapshot snapshot = {0};
      const uint64_t now_ms = cmeta_monotonic_ms();
      status = cnet_reconnect_get_snapshot(&impl->recovery, &snapshot);
      if (status == SALTS_OK && snapshot.protocol_ready) {
        const uint64_t deadline = dial_deadline(now_ms, impl->episode_ms);
        status = cnet_reconnect_lost(
            &impl->recovery, impl->ticket, dial_classify(impl, state, error),
            now_ms, deadline);
      } else if (status == SALTS_OK) {
        status = cnet_reconnect_failed(
            &impl->recovery, impl->ticket, dial_classify(impl, state, error),
            now_ms);
      }
    }
  }
  dial_record_error(impl, status);
  impl->user_observer.on_state(
      impl->user_observer.user, connection, state, error);
  impl->in_callback = false;
}
static void dial_on_receive(void *user, cnet_connection connection,
                            const cnet_receive_view *view) {
  dial_impl *impl = (dial_impl *)user;
  impl->in_callback = true;
  impl->user_observer.on_receive(impl->user_observer.user, connection, view);
  impl->in_callback = false;
}
static void dial_on_send(void *user, cnet_connection connection, size_t size) {
  dial_impl *impl = (dial_impl *)user;
  impl->in_callback = true;
  impl->user_observer.on_send(impl->user_observer.user, connection, size);
  impl->in_callback = false;
}
static void dial_on_recycle(void *user) {
  dial_impl *impl = (dial_impl *)user;
  impl->in_callback = true;
  impl->managed = (cnet_managed_connection){0};
  impl->connection = (cnet_connection){0};
  impl->close_admitted = false;
  impl->in_callback = false;
}

int cnet_managed_dial_init(cnet_managed_dial *dial,
                            const cnet_managed_dial_config *config) {
  dial_impl *impl;
  cnet_manager_snapshot manager_snapshot;
  size_t uri_len;
  int status;
  if (dial == NULL || config == NULL || dial->impl != NULL ||
      !cnet_allocator_valid(&config->storage) || config->size != sizeof(*config) ||
      config->version != CNET_MANAGED_DIAL_VERSION ||
      config->manager == NULL || config->client == NULL ||
      config->client->impl == NULL ||
      config->connection.uri == NULL ||
      config->connection.observer.on_state == NULL ||
      config->recovery_episode_ms == 0u ||
      (config->connection.tls != NULL && config->connection.tls_client != NULL))
    return SALTS_EINVAL;
  if (strncmp(config->connection.uri, "tcp://", 6u) != 0 &&
      strncmp(config->connection.uri, "tls://", 6u) != 0)
    return SALTS_ENOTSUP;
  if (strncmp(config->connection.uri, "tcp://", 6u) == 0 &&
      (config->connection.tls != NULL || config->connection.tls_client != NULL))
    return SALTS_EINVAL;
  uri_len = strlen(config->connection.uri);
  if (uri_len > CNET_MANAGED_DIAL_URI_MAX) return SALTS_EMSGSIZE;
  status = cnet_manager_get_snapshot(config->manager, &manager_snapshot);
  if (status != SALTS_OK) return status;
  if (manager_snapshot.sealed) return SALTS_ESHUTDOWN;
  impl = (dial_impl *)cnet_storage_alloc(&config->storage, 1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->uri = (char *)cnet_storage_alloc(&config->storage, uri_len + 1u, 1u);
  if (impl->uri == NULL) { cnet_storage_free(impl); return SALTS_ENOMEM; }
  memcpy(impl->uri, config->connection.uri, uri_len + 1u);
  status = cnet_reconnect_init(&impl->recovery, &config->recovery);
  if (status != SALTS_OK) {
    cnet_storage_free(impl->uri);
    cnet_storage_free(impl);
    return status;
  }
  impl->owner_thread = cmeta_thread_current_token();
  impl->manager = config->manager;
  impl->client = config->client;
  impl->user_observer = config->connection.observer;
  impl->options = config->connection;
  impl->options.uri = impl->uri;
  impl->classifier = config->classify;
  impl->classify_user = config->classify_user;
  impl->episode_ms = config->recovery_episode_ms;
  dial->impl = impl;
  return SALTS_OK;
}
int cnet_managed_dial_advance(cnet_managed_dial *dial, uint64_t now_ms,
                              uint64_t *out_wait_ms) {
  dial_impl *impl;
  cnet_reconnect_ticket ticket = {0};
  cnet_manager_snapshot manager_snapshot;
  cnet_manager_attachment attachment;
  int status;
  if (out_wait_ms == NULL) return SALTS_EINVAL;
  *out_wait_ms = 0u;
  status = dial_owner(dial, &impl);
  if (status != SALTS_OK) return status;
  if (impl->in_callback) return SALTS_EBUSY;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (impl->managed.slot != 0u) return SALTS_EBUSY;
  status = cnet_manager_get_snapshot(impl->manager, &manager_snapshot);
  if (status != SALTS_OK) return status;
  if (manager_snapshot.sealed) return SALTS_ESHUTDOWN;
  if (manager_snapshot.reserved + manager_snapshot.bound >=
      manager_snapshot.connection_capacity) return SALTS_ENOBUFS;
  if (impl->admit != NULL) {
    /* Preflight without changing generation/attempt accounting. The final
     * begin below remains authoritative; the callback cannot mutate this dial. */
    const cnet_reconnect_state *r = &impl->recovery;
    if (r->sealed) return SALTS_ESHUTDOWN;
    if (r->in_flight || r->awaiting_protocol || r->protocol_ready) return SALTS_EBUSY;
    if (now_ms >= r->config.deadline_ms || r->next_attempt_ms == UINT64_MAX)
      return SALTS_ETIMEDOUT;
    if (r->attempts >= r->config.max_attempts) return SALTS_ENOBUFS;
    if (now_ms < r->next_attempt_ms) {
      *out_wait_ms = r->next_attempt_ms - now_ms;
      return SALTS_EBUSY;
    }
    if (r->generation == UINT64_MAX) return SALTS_ERANGE;
    impl->in_callback = true;
    status = impl->admit(impl->admit_user);
    impl->in_callback = false;
    if (status != SALTS_OK) return status;
  }
  status = cnet_reconnect_begin(
      &impl->recovery, now_ms, &ticket, out_wait_ms);
  if (status != SALTS_OK) return status;
  impl->ticket = ticket;
  attachment = (cnet_manager_attachment){
      .observer = {.on_state = dial_on_state,
                   .on_receive = impl->user_observer.on_receive != NULL ? dial_on_receive : NULL,
                   .user = impl,
                   .on_send = impl->user_observer.on_send != NULL ? dial_on_send : NULL},
      .on_recycle = dial_on_recycle, .hold_context = false};
  status = cnet_manager_reserve(impl->manager, &attachment, &impl->managed);
  if (status != SALTS_OK) {
    /* Local admission is a hard error, not an authorized remote retry. */
    (void)cnet_reconnect_failed(
        &impl->recovery, ticket, CNET_RECONNECT_PERMANENT, now_ms);
    return status;
  }
  status = cnet_manager_connect(
      impl->manager, impl->managed, &impl->options, &impl->connection);
  if (status != SALTS_OK) {
    /* Rejected connect retires the record without fabricating callbacks.
     * Owner must still drive manager_advance to recycle it. */
    (void)cnet_reconnect_failed(
        &impl->recovery, ticket, CNET_RECONNECT_PERMANENT, now_ms);
  }
  return status;
}
int cnet_managed_dial_init_admitted(cnet_managed_dial *dial,
    const cnet_managed_dial_config *config, cnet_dial_admit_fn admit, void *user) {
  int status;
  if (admit == NULL) return SALTS_EINVAL;
  status = cnet_managed_dial_init(dial, config);
  if (status == SALTS_OK) {
    dial_impl *impl = (dial_impl *)dial->impl;
    impl->admit = admit;
    impl->admit_user = user;
  }
  return status;
}
int cnet_managed_dial_protocol_ready(cnet_managed_dial *dial,
                                     cnet_reconnect_ticket ticket,
                                     uint64_t now_ms) {
  dial_impl *impl;
  int status = dial_owner(dial, &impl);
  if (status != SALTS_OK) return status;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (impl->managed.slot == 0u || impl->connection.slot == 0u ||
      ticket.state != impl->ticket.state ||
      ticket.generation != impl->ticket.generation ||
      ticket.incarnation != impl->ticket.incarnation)
    return SALTS_ENOENT;
  return cnet_reconnect_protocol_ready(&impl->recovery, ticket, now_ms);
}
int cnet_managed_dial_get_snapshot(cnet_managed_dial *dial,
                                   cnet_managed_dial_snapshot *out) {
  dial_impl *impl;
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_managed_dial_snapshot){0};
  status = dial_owner(dial, &impl);
  if (status != SALTS_OK) return status;
  status = cnet_reconnect_get_snapshot(&impl->recovery, &out->recovery);
  if (status != SALTS_OK) return status;
  /* Previously a client could see a generation but not obtain the state+
   * incarnation capability required by protocol_ready(). Publish the exact
   * attempt ticket; it grants no transport ownership or replay authority. */
  out->recovery_ticket = impl->ticket;
  out->managed = impl->managed;
  out->connection = impl->connection;
  out->stopping = impl->stopping;
  out->last_error = impl->last_error;
  return SALTS_OK;
}
int cnet_managed_dial_seal(cnet_managed_dial *dial) {
  dial_impl *impl;
  int status = dial_owner(dial, &impl);
  if (status != SALTS_OK) return status;
  if (impl->in_callback) return SALTS_EBUSY;
  if (!impl->stopping) {
    status = cnet_reconnect_seal(&impl->recovery);
    if (status != SALTS_OK) return status;
    impl->stopping = true;
  }
  /* Sealing recovery does not prove that the bounded transport queue accepted
   * close. Preserve that obligation for the next seal call until admission or
   * actual terminal/recycle; never stop the borrowed client or its neighbors. */
  if (impl->close_admitted || impl->connection.slot == 0u) return SALTS_OK;
  status = cnet_close(impl->client, impl->connection);
  if (status != SALTS_OK && status != SALTS_EALREADY &&
      status != SALTS_ENOENT) return status;
  impl->close_admitted = true;
  return SALTS_OK;
}
int cnet_managed_dial_destroy(cnet_managed_dial *dial) {
  dial_impl *impl;
  int status = dial_owner(dial, &impl);
  if (status != SALTS_OK) return status;
  if (impl->in_callback || !impl->stopping || impl->managed.slot != 0u)
    return SALTS_EBUSY;
  cnet_storage_free(impl->uri);
  cnet_storage_free(impl);
  dial->impl = NULL;
  return SALTS_OK;
}
