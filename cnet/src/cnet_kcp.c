#include <cnet/cnet.h>

#include "cnet_kcp_internal.h"

#include <ikcp.h>

#include <limits.h>
#include <stdlib.h>

enum {
  CNET_KCP_PROTOCOL_OVERHEAD = 24,
  CNET_KCP_FRAGMENT_LIMIT = 127,
  CNET_KCP_MIN_INTERVAL_MS = 10,
  CNET_KCP_MAX_INTERVAL_MS = 5000
};

typedef struct cnet_kcp_impl {
  cnet_kcp *owner;
  ikcpcb *protocol;
  ikcpcb *marked_admission;
  unsigned char *receive_buffer;
  size_t max_message_bytes;
  size_t send_segment_capacity;
  size_t receive_window;
  size_t input_segments_since_update;
  uint32_t mtu;
  bool stream_mode;
  cnet_kcp_observer observer;
  int output_status;
  bool admission_started;
} cnet_kcp_impl;

static int cnet_kcp_set_mtu(ikcpcb *protocol, uint32_t mtu) {
  const int status = ikcp_setmtu(protocol, (int)mtu);
  if (status == 0) return SALTS_OK;
  return status == -2 ? SALTS_ENOMEM : SALTS_EINVAL;
}

static int cnet_kcp_marked_admission_reset(cnet_kcp_impl *impl) {
  int status;
  if (impl->marked_admission != NULL) ikcp_release(impl->marked_admission);
  impl->marked_admission = ikcp_create(impl->protocol->conv, NULL);
  if (impl->marked_admission == NULL) return SALTS_ENOMEM;
  status = cnet_kcp_set_mtu(impl->marked_admission, impl->mtu);
  if (status != SALTS_OK) {
    ikcp_release(impl->marked_admission);
    impl->marked_admission = NULL;
    return status;
  }
  return SALTS_OK;
}

static cnet_kcp_impl *cnet_kcp_get(const cnet_kcp *session) {
  return session != NULL ? (cnet_kcp_impl *)session->impl : NULL;
}

static uint32_t cnet_kcp_decode_u32_le(const unsigned char *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8u) | ((uint32_t)input[2] << 16u) |
         ((uint32_t)input[3] << 24u);
}

static int cnet_kcp_wire_segment_count(const void *data, size_t size, size_t *out_count) {
  const unsigned char *cursor = (const unsigned char *)data;
  size_t remaining = size;
  size_t count = 0u;
  if (out_count == NULL) return SALTS_EINVAL;
  *out_count = 0u;
  while (remaining != 0u) {
    uint32_t payload_size;
    if (remaining < CNET_KCP_PROTOCOL_OVERHEAD) return SALTS_EPROTO;
    payload_size = cnet_kcp_decode_u32_le(cursor + 20u);
    if ((size_t)payload_size > remaining - CNET_KCP_PROTOCOL_OVERHEAD) return SALTS_EPROTO;
    cursor += CNET_KCP_PROTOCOL_OVERHEAD + (size_t)payload_size;
    remaining -= CNET_KCP_PROTOCOL_OVERHEAD + (size_t)payload_size;
    ++count;
  }
  *out_count = count;
  return SALTS_OK;
}

static bool cnet_kcp_config_valid(const cnet_kcp_config *config) {
  return config != NULL && config->size == sizeof(*config) && config->conversation != 0u &&
         config->mtu > CNET_KCP_PROTOCOL_OVERHEAD &&
         config->mtu <= CNET_DATAGRAM_MAX_PAYLOAD_BYTES &&
         config->send_window != 0u && config->send_window <= (uint32_t)INT_MAX &&
         config->receive_window != 0u && config->receive_window <= (uint32_t)INT_MAX &&
         config->interval_ms >= CNET_KCP_MIN_INTERVAL_MS &&
         config->interval_ms <= CNET_KCP_MAX_INTERVAL_MS &&
         config->fast_resend <= (uint32_t)INT_MAX && config->send_segment_capacity != 0u &&
         config->send_segment_capacity <= (size_t)INT_MAX && config->max_message_bytes != 0u &&
         config->max_message_bytes <= (size_t)INT_MAX && config->observer.output != NULL &&
         config->observer.on_receive != NULL;
}

static int cnet_kcp_output_bridge(const char *buffer, int length, ikcpcb *protocol, void *user) {
  cnet_kcp_impl *impl = (cnet_kcp_impl *)user;
  int status;
  (void)protocol;
  if (impl == NULL || length <= 0) return -1;
  if (impl->output_status != SALTS_OK) return -1;
  status = impl->observer.output(impl->observer.user, impl->owner, buffer, (size_t)length);
  if (status != SALTS_OK) {
    impl->output_status = status < SALTS_OK ? status : SALTS_EIO;
    return -1;
  }
  return 0;
}

static int cnet_kcp_drain(cnet_kcp_impl *impl) {
  for (;;) {
    const int message_size = ikcp_peeksize(impl->protocol);
    cnet_receive_view view;
    int received;
    if (message_size == -1) return SALTS_OK;
    if (message_size < 0) return SALTS_EPROTO;
    if ((size_t)message_size > impl->max_message_bytes) return SALTS_EMSGSIZE;
    received = ikcp_recv(impl->protocol, (char *)impl->receive_buffer, message_size);
    if (received != message_size) return SALTS_EPROTO;
    view = (cnet_receive_view){impl->receive_buffer, (size_t)received, CNET_MESSAGE_BYTES};
    impl->observer.on_receive(impl->observer.user, impl->owner, &view);
  }
}

int cnet_kcp_init(cnet_kcp *session, const cnet_kcp_config *config) {
  cnet_kcp_impl *impl;
  int status;
  if (session == NULL) return SALTS_EINVAL;
  if (session->impl != NULL) return SALTS_EALREADY;
  if (!cnet_kcp_config_valid(config)) return SALTS_EINVAL;
  impl = (cnet_kcp_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->receive_buffer = (unsigned char *)malloc(config->max_message_bytes);
  if (impl->receive_buffer == NULL) {
    free(impl);
    return SALTS_ENOMEM;
  }
  impl->protocol = ikcp_create((IUINT32)config->conversation, impl);
  if (impl->protocol == NULL) {
    free(impl->receive_buffer);
    free(impl);
    return SALTS_ENOMEM;
  }
  impl->owner = session;
  impl->max_message_bytes = config->max_message_bytes;
  impl->send_segment_capacity = config->send_segment_capacity;
  impl->receive_window = config->receive_window;
  impl->mtu = config->mtu;
  impl->stream_mode = config->stream_mode;
  impl->observer = config->observer;
  impl->output_status = SALTS_OK;
  impl->protocol->output = cnet_kcp_output_bridge;
  impl->protocol->stream = config->stream_mode ? 1 : 0;
  impl->protocol->dead_link = CNET_KCP_DEFAULT_DEAD_LINK;
  status = cnet_kcp_set_mtu(impl->protocol, config->mtu);
  if (status == SALTS_OK &&
      (ikcp_wndsize(impl->protocol, (int)config->send_window, (int)config->receive_window) != 0 ||
      ikcp_nodelay(impl->protocol, 1, (int)config->interval_ms, (int)config->fast_resend,
                   config->no_congestion_window ? 1 : 0) != 0))
    status = SALTS_EINVAL;
  if (status != SALTS_OK) {
    ikcp_release(impl->protocol);
    free(impl->receive_buffer);
    free(impl);
    return status;
  }
  session->impl = impl;
  return SALTS_OK;
}

int cnet_kcp_set_dead_link(cnet_kcp *session, uint32_t max_transmissions) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  if (impl == NULL || max_transmissions == 0u) return SALTS_EINVAL;
  if (impl->admission_started) return SALTS_EBUSY;
  impl->protocol->dead_link = max_transmissions;
  return SALTS_OK;
}

int cnet_kcp_send_validate(const cnet_kcp *session, const void *data, size_t size, bool marked) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  size_t fragments;
  size_t retained;
  size_t mss;
  size_t unmerged_size;
  if (impl == NULL || data == NULL || size == 0u) return SALTS_EINVAL;
  if (cnet_kcp_terminal_status(session) != SALTS_OK) return SALTS_ETIMEDOUT;
  if (marked && impl->stream_mode) return SALTS_ENOTSUP;
  if (size > impl->max_message_bytes || size > (size_t)INT_MAX) return SALTS_EMSGSIZE;
  mss = (size_t)impl->mtu - CNET_KCP_PROTOCOL_OVERHEAD;
  unmerged_size = size;
  if (impl->stream_mode && !iqueue_is_empty(&impl->protocol->snd_queue)) {
    const struct IKCPSEG *tail =
        iqueue_entry(impl->protocol->snd_queue.prev, struct IKCPSEG, node);
    if ((size_t)tail->len < mss) {
      const size_t available = mss - (size_t)tail->len;
      unmerged_size = size > available ? size - available : 0u;
    }
  }
  /* KCP checks this after mutating a stream tail; reject before it retains input. */
  if (unmerged_size != 0u &&
      1u + ((unmerged_size - 1u) / mss) > CNET_KCP_FRAGMENT_LIMIT)
    return SALTS_EMSGSIZE;
  fragments = 1u + ((size - 1u) / mss);
  retained = (size_t)ikcp_waitsnd(impl->protocol);
  if (retained > impl->send_segment_capacity ||
      fragments > impl->send_segment_capacity - retained)
    return SALTS_ENOBUFS;
  return SALTS_OK;
}

static int cnet_kcp_send_marked_atomic(cnet_kcp_impl *impl, const void *data, size_t size,
                                       cnet_kcp_send_marker *out_marker) {
  int status;
  if (impl->marked_admission == NULL) {
    status = cnet_kcp_marked_admission_reset(impl);
    if (status != SALTS_OK) return status;
  }
  status = ikcp_send(impl->marked_admission, (const char *)data, (int)size);
  if (status != 0) {
    (void)cnet_kcp_marked_admission_reset(impl);
    return SALTS_ENOMEM;
  }
  while (!iqueue_is_empty(&impl->marked_admission->snd_queue)) {
    struct IQUEUEHEAD *node = impl->marked_admission->snd_queue.next;
    iqueue_del_init(node);
    iqueue_add_tail(node, &impl->protocol->snd_queue);
    --impl->marked_admission->nsnd_que;
    ++impl->protocol->nsnd_que;
  }
  out_marker->final_sequence =
      impl->protocol->snd_nxt + impl->protocol->nsnd_que - UINT32_C(1);
  return SALTS_OK;
}

static int cnet_kcp_send_impl(cnet_kcp *session, const void *data, size_t size,
                              cnet_kcp_send_marker *out_marker) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  int status;
  if (out_marker != NULL) *out_marker = (cnet_kcp_send_marker){0};
  status = cnet_kcp_send_validate(session, data, size, out_marker != NULL);
  if (status != SALTS_OK) return status;
  if (out_marker != NULL) {
    status = cnet_kcp_send_marked_atomic(impl, data, size, out_marker);
    if (status == SALTS_OK) impl->admission_started = true;
    return status;
  }
  status = ikcp_send(impl->protocol, (const char *)data, (int)size);
  if (status == 0) impl->admission_started = true;
  return status == 0 ? SALTS_OK : SALTS_EPROTO;
}

int cnet_kcp_send(cnet_kcp *session, const void *data, size_t size) {
  return cnet_kcp_send_impl(session, data, size, NULL);
}

int cnet_kcp_send_marked(cnet_kcp *session, const void *data, size_t size,
                         cnet_kcp_send_marker *out_marker) {
  if (out_marker == NULL) return SALTS_EINVAL;
  return cnet_kcp_send_impl(session, data, size, out_marker);
}

bool cnet_kcp_send_marker_complete(const cnet_kcp *session, cnet_kcp_send_marker marker) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  return impl != NULL && (int32_t)(impl->protocol->snd_una - marker.final_sequence) > 0;
}

int cnet_kcp_terminal_status(const cnet_kcp *session) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  if (impl == NULL) return SALTS_EINVAL;
  return impl->protocol->state == 0u ? SALTS_OK : SALTS_ETIMEDOUT;
}

int cnet_kcp_input(cnet_kcp *session, const void *data, size_t size) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  size_t segment_count;
  int status;
  if (impl == NULL || data == NULL || size < CNET_KCP_PROTOCOL_OVERHEAD) return SALTS_EINVAL;
  if (cnet_kcp_terminal_status(session) != SALTS_OK) return SALTS_ETIMEDOUT;
  if (size > impl->mtu || size > (size_t)LONG_MAX) return SALTS_EMSGSIZE;
  status = cnet_kcp_wire_segment_count(data, size, &segment_count);
  if (status != SALTS_OK) return status;
  if (impl->input_segments_since_update > impl->receive_window ||
      segment_count > impl->receive_window - impl->input_segments_since_update)
    return SALTS_ENOBUFS;
  status = ikcp_input(impl->protocol, (const char *)data, (long)size);
  if (status != 0) return SALTS_EPROTO;
  impl->admission_started = true;
  impl->input_segments_since_update += segment_count;
  return cnet_kcp_drain(impl);
}

int cnet_kcp_update(cnet_kcp *session, uint32_t now_ms) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  if (impl == NULL) return SALTS_EINVAL;
  if (cnet_kcp_terminal_status(session) != SALTS_OK) return SALTS_ETIMEDOUT;
  impl->output_status = SALTS_OK;
  ikcp_update(impl->protocol, (IUINT32)now_ms);
  impl->input_segments_since_update = 0u;
  return impl->output_status != SALTS_OK ? impl->output_status : cnet_kcp_terminal_status(session);
}

int cnet_kcp_check(const cnet_kcp *session, uint32_t now_ms, uint32_t *out_next_ms) {
  cnet_kcp_impl *impl = cnet_kcp_get(session);
  if (out_next_ms == NULL) return SALTS_EINVAL;
  *out_next_ms = 0u;
  if (impl == NULL) return SALTS_EINVAL;
  if (cnet_kcp_terminal_status(session) != SALTS_OK) return SALTS_ETIMEDOUT;
  *out_next_ms = (uint32_t)ikcp_check(impl->protocol, (IUINT32)now_ms);
  return SALTS_OK;
}

int cnet_kcp_destroy(cnet_kcp *session) {
  cnet_kcp_impl *impl;
  if (session == NULL) return SALTS_EINVAL;
  impl = cnet_kcp_get(session);
  if (impl == NULL) return SALTS_OK;
  if (impl->marked_admission != NULL) ikcp_release(impl->marked_admission);
  ikcp_release(impl->protocol);
  free(impl->receive_buffer);
  free(impl);
  session->impl = NULL;
  return SALTS_OK;
}
