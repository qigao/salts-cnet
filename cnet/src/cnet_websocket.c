#include <cnet/websocket.h>

#include "websocket_frame_parser.h"

#include <core/error_codes.h>
#include <core/platform.h>
#include <simd.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct cnet_websocket_utf8_state {
  uint8_t remaining;
  uint8_t next_min;
  uint8_t next_max;
} cnet_websocket_utf8_state;

_Static_assert(sizeof(v128) == 16u, "UTF-8 bit masks require the SIMD 16-byte carrier");

typedef struct cnet_websocket_impl {
  cnet_websocket *public_value;
  cnet_websocket_role role;
  cnet_websocket_state state;
  int last_error;
  size_t max_frame_bytes;
  size_t max_message_bytes;
  cnet_websocket_write_fn write;
  cnet_websocket_event_fn on_event;
  void *user;

  uint8_t *input;
  size_t input_capacity;
  size_t input_start;
  size_t input_size;

  uint8_t *message;
  size_t message_size;
  cnet_websocket_message_type inbound_message_type;

  uint8_t *output;
  mem_buffer_t *output_buffer;
  size_t output_capacity;
  size_t output_size;

  cnet_websocket_message_type outbound_message_type;
  size_t outbound_message_size;
  cnet_websocket_utf8_state outbound_utf8;
  bool sent_close;
  bool received_close;
  bool close_event_delivered;
  bool operation_active;
  bool callback_active;
  bool write_active;
  bool output_async_pending;
  cnet_websocket_tagged_policy tagged_policy;
  uint8_t *tagged_data;
  size_t tagged_size;
  size_t tagged_offset;
  size_t tagged_frame_size;
  uint64_t tagged_tag;
  cnet_websocket_message_type tagged_type;
  int tagged_status;
  bool tagged_active;
  bool tagged_ready;
  bool tagged_emitting;
  bool output_tagged;
  bool tagged_frame_final;
  bool advance_active;
  size_t advance_write_budget;
} cnet_websocket_impl;

static cnet_websocket_impl *cnet_websocket_get(cnet_websocket *websocket) {
  return websocket != NULL ? (cnet_websocket_impl *)websocket->impl : NULL;
}

static const cnet_websocket_impl *cnet_websocket_const_get(const cnet_websocket *websocket) {
  return websocket != NULL ? (const cnet_websocket_impl *)websocket->impl : NULL;
}

static bool cnet_websocket_utf8_update(cnet_websocket_utf8_state *state, const uint8_t *data,
                                       size_t size, bool final_chunk) {
  size_t index = 0u;

  if (state == NULL || (data == NULL && size != 0u)) return false;
  while (index < size) {
    const uint8_t first = data[index];

    if (state->remaining != 0u) {
      if (first < state->next_min || first > state->next_max) return false;
      --state->remaining;
      state->next_min = 0x80u;
      state->next_max = 0xbfu;
      ++index;
      continue;
    }
    if (first < 0x80u) {
      /* Read only complete borrowed blocks, with no pending continuation.
       * Non-ASCII bytes still pass through the strict state machine below. */
      if (size - index >= sizeof(v128)) {
        v128 block;
        uint32_t high_bits;
        /* The public carrier is neutral byte storage; copying it avoids a
         * second cross-library call for this small, bounded load. */
        memcpy(block.bytes, data + index, sizeof(block.bytes));
        if (!simd_reduce(&simd_u8x16, SALTS_SIMD_REDUCE_BITMASK, &block, &high_bits))
          return false;
        if (high_bits == 0u) {
          index += sizeof(v128);
        } else {
          do {
            ++index;
            high_bits >>= 1u;
          } while ((high_bits & 1u) == 0u);
        }
        continue;
      }
      ++index;
      continue;
    }
    if (first >= 0xc2u && first <= 0xdfu) {
      state->remaining = 1u;
      state->next_min = 0x80u;
      state->next_max = 0xbfu;
    } else if (first == 0xe0u) {
      state->remaining = 2u;
      state->next_min = 0xa0u;
      state->next_max = 0xbfu;
    } else if ((first >= 0xe1u && first <= 0xecu) || (first >= 0xeeu && first <= 0xefu)) {
      state->remaining = 2u;
      state->next_min = 0x80u;
      state->next_max = 0xbfu;
    } else if (first == 0xedu) {
      state->remaining = 2u;
      state->next_min = 0x80u;
      state->next_max = 0x9fu;
    } else if (first == 0xf0u) {
      state->remaining = 3u;
      state->next_min = 0x90u;
      state->next_max = 0xbfu;
    } else if (first >= 0xf1u && first <= 0xf3u) {
      state->remaining = 3u;
      state->next_min = 0x80u;
      state->next_max = 0xbfu;
    } else if (first == 0xf4u) {
      state->remaining = 3u;
      state->next_min = 0x80u;
      state->next_max = 0x8fu;
    } else {
      return false;
    }
    ++index;
  }
  return !final_chunk || state->remaining == 0u;
}

static bool cnet_websocket_utf8_valid(const uint8_t *data, size_t size) {
  cnet_websocket_utf8_state state = {0};
  return cnet_websocket_utf8_update(&state, data, size, true);
}

static bool cnet_websocket_close_code_valid(uint16_t code) {
  if (code >= 3000u && code <= 4999u) return true;
  if (code < 1000u || code > 1014u) return false;
  return code != 1004u && code != 1005u && code != 1006u;
}

static void cnet_websocket_record_error(cnet_websocket_impl *impl, int status) {
  if (impl->last_error == SALTS_OK && status != SALTS_OK) impl->last_error = status;
}

static void cnet_websocket_consume(cnet_websocket_impl *impl, size_t size) {
  impl->input_start += size;
  impl->input_size -= size;
  if (impl->input_size == 0u) impl->input_start = 0u;
}

static void cnet_websocket_emit_event(cnet_websocket_impl *impl, cnet_websocket_event_kind kind,
                                      cnet_websocket_message_type message_type, const uint8_t *data,
                                      size_t size, uint16_t close_code) {
  cnet_websocket_event event = {
      .kind = kind,
      .message_type = message_type,
      .data = data,
      .size = size,
      .close_code = close_code,
  };
  impl->callback_active = true;
  impl->on_event(impl->user, impl->public_value, &event);
  impl->callback_active = false;
}

static void cnet_websocket_tagged_frame_terminal(cnet_websocket_impl *impl, int status) {
  if (!impl->output_tagged) return;
  impl->output_tagged = false;
  if (!impl->tagged_active || impl->tagged_ready) return;
  if (status != SALTS_OK) {
    impl->tagged_status = status;
    impl->tagged_ready = true;
  } else {
    impl->tagged_offset += impl->tagged_frame_size;
    if (impl->tagged_frame_final) impl->tagged_ready = true;
  }
}

static int cnet_websocket_write_output(cnet_websocket_impl *impl) {
  int status;
  if (impl->output_size == 0u) return SALTS_OK;
  if (impl->output_async_pending) return SALTS_EBUSY;
  if (impl->advance_active) {
    if (impl->advance_write_budget == 0u) return SALTS_EBUSY;
    --impl->advance_write_budget;
  }
  if (impl->output_buffer != NULL) mem_set_used(impl->output_buffer, impl->output_size);
  impl->write_active = true;
  status = impl->write(impl->user, impl->output, impl->output_size);
  impl->write_active = false;
  if (status == SALTS_OK) {
    cnet_websocket_tagged_frame_terminal(impl, SALTS_OK);
    impl->output_size = 0u;
  } else if (status == CNET_WEBSOCKET_WRITE_PENDING) {
    if (impl->output_buffer == NULL) {
      cnet_websocket_tagged_frame_terminal(impl, SALTS_EPROTO);
      impl->output_size = 0u;
      cnet_websocket_record_error(impl, SALTS_EPROTO);
      impl->state = CNET_WEBSOCKET_FAILED;
      return SALTS_EPROTO;
    }
    impl->output_async_pending = true;
  } else if (status != SALTS_EBUSY) {
    cnet_websocket_tagged_frame_terminal(impl, status);
    impl->output_size = 0u;
    cnet_websocket_record_error(impl, status);
    impl->state = CNET_WEBSOCKET_FAILED;
  }
  return status;
}

static int cnet_websocket_emit_frame(cnet_websocket_impl *impl, uint8_t opcode, bool final_frame,
                                     const uint8_t *payload, size_t payload_size) {
  uint8_t masking_key[4] = {0};
  size_t header_size = 0u;
  int masked = impl->role == CNET_WEBSOCKET_CLIENT;
  int status;

  if (impl->output_size != 0u) return SALTS_EBUSY;
  if (payload_size > impl->max_frame_bytes) return SALTS_EMSGSIZE;
  if (payload == NULL && payload_size != 0u) return SALTS_EINVAL;
  if (masked) {
    status = secure_random(masking_key, sizeof(masking_key));
    if (status != SALTS_OK) {
      cnet_websocket_record_error(impl, status);
      impl->state = CNET_WEBSOCKET_FAILED;
      return status;
    }
  }
  if (ws_frame_build_header(impl->output, impl->output_capacity, opcode, payload_size,
                            final_frame ? 1 : 0, masked, masked ? masking_key : NULL,
                            &header_size) != WS_PARSE_OK)
    return SALTS_EPROTO;
  if (payload_size != 0u) memcpy(impl->output + header_size, payload, payload_size);
  if (masked) {
    status = ws_frame_unmask(impl->output + header_size, payload_size, masking_key);
    if (status != WS_PARSE_OK) return SALTS_EPROTO;
  }
  impl->output_size = header_size + payload_size;
  impl->output_tagged = impl->tagged_emitting;
  status = cnet_websocket_write_output(impl);
  return status == SALTS_EBUSY || status == CNET_WEBSOCKET_WRITE_PENDING ? SALTS_OK : status;
}

static int cnet_websocket_fail(cnet_websocket_impl *impl, int status, uint16_t close_code) {
  uint8_t payload[2];

  cnet_websocket_record_error(impl, status);
  impl->state = CNET_WEBSOCKET_FAILED;
  impl->input_start = 0u;
  impl->input_size = 0u;
  impl->message_size = 0u;
  impl->inbound_message_type = CNET_WEBSOCKET_MESSAGE_NONE;
  if (!impl->sent_close && impl->output_size == 0u) {
    payload[0] = (uint8_t)(close_code >> 8u);
    payload[1] = (uint8_t)close_code;
    if (cnet_websocket_emit_frame(impl, WS_OPCODE_CLOSE, true, payload, sizeof(payload)) ==
        SALTS_OK)
      impl->sent_close = true;
  }
  impl->state = CNET_WEBSOCKET_FAILED;
  return status;
}

static int cnet_websocket_append_message(cnet_websocket_impl *impl, const uint8_t *data,
                                         size_t size) {
  if (size > impl->max_message_bytes - impl->message_size) return SALTS_EMSGSIZE;
  if (size != 0u) memcpy(impl->message + impl->message_size, data, size);
  impl->message_size += size;
  return SALTS_OK;
}

static int cnet_websocket_deliver_data(cnet_websocket_impl *impl, const ws_frame_t *frame,
                                       size_t wire_size) {
  const cnet_websocket_message_type frame_type =
      frame->opcode == WS_OPCODE_TEXT ? CNET_WEBSOCKET_MESSAGE_TEXT : CNET_WEBSOCKET_MESSAGE_BINARY;
  int status;

  if (frame->opcode == WS_OPCODE_CONTINUATION) {
    if (impl->inbound_message_type == CNET_WEBSOCKET_MESSAGE_NONE)
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    status = cnet_websocket_append_message(impl, frame->payload, (size_t)frame->payload_len);
    if (status != SALTS_OK)
      return cnet_websocket_fail(impl, status, CNET_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG);
    cnet_websocket_consume(impl, wire_size);
    if (!frame->fin) return SALTS_OK;
    if (impl->inbound_message_type == CNET_WEBSOCKET_MESSAGE_TEXT &&
        !cnet_websocket_utf8_valid(impl->message, impl->message_size))
      return cnet_websocket_fail(impl, SALTS_ECHARSET, CNET_WEBSOCKET_CLOSE_INVALID_TEXT);
    cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_MESSAGE, impl->inbound_message_type,
                              impl->message, impl->message_size, 0u);
    impl->message_size = 0u;
    impl->inbound_message_type = CNET_WEBSOCKET_MESSAGE_NONE;
    return SALTS_OK;
  }

  if (impl->inbound_message_type != CNET_WEBSOCKET_MESSAGE_NONE)
    return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
  if (!frame->fin) {
    status = cnet_websocket_append_message(impl, frame->payload, (size_t)frame->payload_len);
    if (status != SALTS_OK)
      return cnet_websocket_fail(impl, status, CNET_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG);
    impl->inbound_message_type = frame_type;
    cnet_websocket_consume(impl, wire_size);
    return SALTS_OK;
  }

  if (frame_type == CNET_WEBSOCKET_MESSAGE_TEXT &&
      !cnet_websocket_utf8_valid(frame->payload, (size_t)frame->payload_len))
    return cnet_websocket_fail(impl, SALTS_ECHARSET, CNET_WEBSOCKET_CLOSE_INVALID_TEXT);
  cnet_websocket_consume(impl, wire_size);
  cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_MESSAGE, frame_type, frame->payload,
                            (size_t)frame->payload_len, 0u);
  return SALTS_OK;
}

static int cnet_websocket_deliver_close(cnet_websocket_impl *impl, const ws_frame_t *frame,
                                        size_t wire_size) {
  uint16_t code = 0u;
  const uint8_t *reason = NULL;
  size_t reason_size = 0u;
  int status = SALTS_OK;

  if (frame->payload_len == 1u)
    return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
  if (frame->payload_len >= 2u) {
    code = (uint16_t)(((uint16_t)frame->payload[0] << 8u) | frame->payload[1]);
    reason = frame->payload + 2u;
    reason_size = (size_t)frame->payload_len - 2u;
    if (!cnet_websocket_close_code_valid(code))
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    if (!cnet_websocket_utf8_valid(reason, reason_size))
      return cnet_websocket_fail(impl, SALTS_ECHARSET, CNET_WEBSOCKET_CLOSE_INVALID_TEXT);
  }

  cnet_websocket_consume(impl, wire_size);
  impl->received_close = true;
  impl->state = CNET_WEBSOCKET_CLOSING;
  if (!impl->sent_close) {
    status = cnet_websocket_emit_frame(impl, WS_OPCODE_CLOSE, true, frame->payload,
                                       (size_t)frame->payload_len);
    if (status == SALTS_OK) impl->sent_close = true;
  }
  if (!impl->close_event_delivered) {
    impl->close_event_delivered = true;
    cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_CLOSE, CNET_WEBSOCKET_MESSAGE_NONE, reason,
                              reason_size, code);
  }
  if (status == SALTS_OK && impl->sent_close)
    impl->state = impl->output_size == 0u ? CNET_WEBSOCKET_CLOSED : CNET_WEBSOCKET_CLOSING;
  return status;
}

static int cnet_websocket_process_input(cnet_websocket_impl *impl) {
  while (impl->input_size != 0u && impl->output_size == 0u) {
    uint8_t *wire = impl->input + impl->input_start;
    ws_frame_t frame = {0};
    size_t needed = 0u;
    size_t header_size;
    size_t payload_size;
    ws_parse_result_t parse_status = ws_frame_peek_size(wire, impl->input_size, &needed);
    int status;

    if (parse_status == WS_PARSE_NEED_MORE) return SALTS_OK;
    if (parse_status != WS_PARSE_OK)
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    header_size = 2u +
                  ((wire[1] & 0x7fu) == 126u   ? 2u
                   : (wire[1] & 0x7fu) == 127u ? 8u
                                               : 0u) +
                  ((wire[1] & 0x80u) != 0u ? 4u : 0u);
    payload_size = needed - header_size;
    if (payload_size > impl->max_frame_bytes)
      return cnet_websocket_fail(impl, SALTS_EMSGSIZE, CNET_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG);
    if (needed > impl->input_size) return SALTS_OK;
    parse_status = ws_frame_parse(wire, impl->input_size, &frame);
    if (parse_status != WS_PARSE_OK)
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    if ((impl->role == CNET_WEBSOCKET_SERVER && !frame.masked) ||
        (impl->role == CNET_WEBSOCKET_CLIENT && frame.masked))
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    if (frame.masked && ws_frame_unmask((uint8_t *)frame.payload, (size_t)frame.payload_len,
                                        frame.masking_key) != WS_PARSE_OK)
      return cnet_websocket_fail(impl, SALTS_EPROTO, CNET_WEBSOCKET_CLOSE_PROTOCOL_ERROR);

    if (impl->state == CNET_WEBSOCKET_CLOSING && frame.opcode != WS_OPCODE_CLOSE) {
      cnet_websocket_consume(impl, needed);
      continue;
    }
    if (frame.opcode == WS_OPCODE_CLOSE)
      status = cnet_websocket_deliver_close(impl, &frame, needed);
    else if (frame.opcode == WS_OPCODE_PING) {
      status = cnet_websocket_emit_frame(impl, WS_OPCODE_PONG, true, frame.payload,
                                         (size_t)frame.payload_len);
      cnet_websocket_consume(impl, needed);
      cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_PING, CNET_WEBSOCKET_MESSAGE_NONE,
                                frame.payload, (size_t)frame.payload_len, 0u);
    } else if (frame.opcode == WS_OPCODE_PONG) {
      cnet_websocket_consume(impl, needed);
      cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_PONG, CNET_WEBSOCKET_MESSAGE_NONE,
                                frame.payload, (size_t)frame.payload_len, 0u);
      status = SALTS_OK;
    } else {
      status = cnet_websocket_deliver_data(impl, &frame, needed);
    }
    if (status != SALTS_OK) return status;
    if (impl->state == CNET_WEBSOCKET_FAILED) return impl->last_error;
    if (impl->state == CNET_WEBSOCKET_CLOSED) return SALTS_OK;
  }
  return SALTS_OK;
}

int cnet_websocket_init(cnet_websocket *websocket, const cnet_websocket_config *config) {
  cnet_websocket_impl *impl;
  size_t output_capacity;
  size_t total_capacity;

  if (websocket == NULL || config == NULL || websocket->impl != NULL ||
      config->size != sizeof(*config) ||
      (config->role != CNET_WEBSOCKET_CLIENT && config->role != CNET_WEBSOCKET_SERVER) ||
      config->max_frame_bytes < CNET_WEBSOCKET_MIN_FRAME_BYTES ||
      config->max_message_bytes < config->max_frame_bytes ||
      config->max_frame_bytes > (size_t)INT64_MAX ||
      config->max_frame_bytes > SIZE_MAX - CNET_WEBSOCKET_MAX_HEADER_BYTES ||
      config->write == NULL || config->on_event == NULL)
    return SALTS_EINVAL;
  output_capacity = config->max_frame_bytes + CNET_WEBSOCKET_MAX_HEADER_BYTES;
  if (config->max_buffered_input_bytes < output_capacity) return SALTS_EINVAL;
  if (config->max_buffered_input_bytes > SIZE_MAX - config->max_message_bytes ||
      config->max_buffered_input_bytes + config->max_message_bytes > SIZE_MAX - output_capacity)
    return SALTS_ERANGE;
  total_capacity = config->max_buffered_input_bytes + config->max_message_bytes + output_capacity;
  if (total_capacity == 0u) return SALTS_ERANGE;

  if (config->output_buffer != NULL &&
      (mem_buffer_data(config->output_buffer) == NULL ||
       mem_buffer_capacity(config->output_buffer) < output_capacity))
    return SALTS_EINVAL;

  impl = (cnet_websocket_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) return SALTS_ENOMEM;
  impl->input = (uint8_t *)malloc(config->max_buffered_input_bytes);
  impl->message = (uint8_t *)malloc(config->max_message_bytes);
  if (config->output_buffer != NULL) {
    impl->output_buffer = mem_buffer_retain(config->output_buffer);
    impl->output = impl->output_buffer != NULL
                       ? (uint8_t *)mem_buffer_data(impl->output_buffer)
                       : NULL;
    if (impl->output_buffer != NULL) mem_set_used(impl->output_buffer, 0u);
  } else {
    impl->output = (uint8_t *)malloc(output_capacity);
  }
  if (impl->input == NULL || impl->message == NULL || impl->output == NULL) {
    if (impl->output_buffer != NULL) mem_buffer_release(impl->output_buffer);
    else free(impl->output);
    free(impl->message);
    free(impl->input);
    free(impl);
    return SALTS_ENOMEM;
  }
  impl->public_value = websocket;
  impl->role = config->role;
  impl->state = CNET_WEBSOCKET_OPEN;
  impl->max_frame_bytes = config->max_frame_bytes;
  impl->max_message_bytes = config->max_message_bytes;
  impl->input_capacity = config->max_buffered_input_bytes;
  impl->output_capacity = output_capacity;
  impl->write = config->write;
  impl->on_event = config->on_event;
  impl->user = config->user;
  websocket->impl = impl;
  return SALTS_OK;
}

int cnet_websocket_init_tagged(cnet_websocket *websocket, const cnet_websocket_config *config,
                                const cnet_websocket_tagged_policy *policy) {
  cnet_websocket_impl *impl;
  size_t remaining;
  int status;
  if (config == NULL || policy == NULL || policy->size != sizeof(*policy) ||
      policy->version != CNET_WEBSOCKET_TAGGED_SEND_VERSION || policy->on_send == NULL ||
      policy->fragment_bytes == 0u || policy->fragment_bytes > config->max_frame_bytes)
    return SALTS_EINVAL;
  /* Include both receive and send message buffers in the aggregate budget. */
  remaining = SIZE_MAX - CNET_WEBSOCKET_MAX_HEADER_BYTES;
  if (config->max_frame_bytes > remaining) return SALTS_ERANGE;
  remaining -= config->max_frame_bytes;
  if (config->max_buffered_input_bytes > remaining) return SALTS_ERANGE;
  remaining -= config->max_buffered_input_bytes;
  if (config->max_message_bytes > remaining / 2u) return SALTS_ERANGE;
  status = cnet_websocket_init(websocket, config);
  if (status != SALTS_OK) return status;
  impl = cnet_websocket_get(websocket);
  impl->tagged_data = (uint8_t *)malloc(config->max_message_bytes);
  if (impl->tagged_data == NULL) {
    (void)cnet_websocket_destroy(websocket);
    return SALTS_ENOMEM;
  }
  impl->tagged_policy = *policy;
  return SALTS_OK;
}

int cnet_websocket_destroy(cnet_websocket *websocket) {
  cnet_websocket_impl *impl;
  if (websocket == NULL) return SALTS_EINVAL;
  impl = cnet_websocket_get(websocket);
  if (impl == NULL) return SALTS_OK;
  if (impl->operation_active || impl->callback_active || impl->write_active ||
      impl->output_async_pending || impl->tagged_active)
    return SALTS_EBUSY;
  if (impl->output_buffer != NULL) mem_buffer_release(impl->output_buffer);
  else free(impl->output);
  free(impl->tagged_data);
  free(impl->message);
  free(impl->input);
  free(impl);
  websocket->impl = NULL;
  return SALTS_OK;
}

int cnet_websocket_state_get(const cnet_websocket *websocket, cnet_websocket_state *out_state) {
  const cnet_websocket_impl *impl = cnet_websocket_const_get(websocket);
  if (impl == NULL || out_state == NULL) return SALTS_EINVAL;
  *out_state = impl->state;
  return SALTS_OK;
}

int cnet_websocket_last_error(const cnet_websocket *websocket, int *out_status) {
  const cnet_websocket_impl *impl = cnet_websocket_const_get(websocket);
  if (impl == NULL || out_status == NULL) return SALTS_EINVAL;
  *out_status = impl->last_error;
  return SALTS_OK;
}

bool cnet_websocket_has_pending_output(const cnet_websocket *websocket) {
  const cnet_websocket_impl *impl = cnet_websocket_const_get(websocket);
  return impl != NULL && impl->output_size != 0u;
}

int cnet_websocket_feed(cnet_websocket *websocket, const void *data, size_t size) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  int status;

  if (impl == NULL || (data == NULL && size != 0u)) return SALTS_EINVAL;
  if (impl->operation_active || impl->callback_active || impl->write_active) return SALTS_EBUSY;
  if (impl->state == CNET_WEBSOCKET_FAILED || impl->state == CNET_WEBSOCKET_CLOSED)
    return SALTS_ESHUTDOWN;
  if (impl->output_size != 0u) return SALTS_EBUSY;
  if (size > impl->input_capacity - impl->input_size) return SALTS_ENOSPC;

  if (size > impl->input_capacity - (impl->input_start + impl->input_size)) {
    if (impl->input_size != 0u)
      memmove(impl->input, impl->input + impl->input_start, impl->input_size);
    impl->input_start = 0u;
  }
  if (size != 0u) memcpy(impl->input + impl->input_start + impl->input_size, data, size);
  impl->input_size += size;
  impl->operation_active = true;
  status = cnet_websocket_process_input(impl);
  impl->operation_active = false;
  return status;
}

int cnet_websocket_flush(cnet_websocket *websocket) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  int status;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->operation_active || impl->callback_active || impl->write_active ||
      impl->output_async_pending)
    return SALTS_EBUSY;
  impl->operation_active = true;
  status = cnet_websocket_write_output(impl);
  if (status == SALTS_OK && impl->output_size == 0u && impl->sent_close && impl->received_close &&
      impl->state == CNET_WEBSOCKET_CLOSING)
    impl->state = CNET_WEBSOCKET_CLOSED;
  if (status == SALTS_OK && impl->state != CNET_WEBSOCKET_FAILED &&
      impl->state != CNET_WEBSOCKET_CLOSED)
    status = cnet_websocket_process_input(impl);
  impl->operation_active = false;
  return status;
}

int cnet_websocket_write_complete(cnet_websocket *websocket, size_t bytes, int status) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  int process_status = SALTS_OK;

  if (impl == NULL || status > SALTS_OK) return SALTS_EINVAL;
  if (impl->operation_active || impl->callback_active || impl->write_active) return SALTS_EBUSY;
  if (!impl->output_async_pending || impl->output_size == 0u) return SALTS_ENOENT;

  impl->operation_active = true;
  impl->output_async_pending = false;
  if (status != SALTS_OK) {
    cnet_websocket_tagged_frame_terminal(impl, status);
    impl->output_size = 0u;
    cnet_websocket_record_error(impl, status);
    impl->state = CNET_WEBSOCKET_FAILED;
    impl->operation_active = false;
    return status;
  }
  if (bytes != impl->output_size) {
    cnet_websocket_tagged_frame_terminal(impl, SALTS_EPROTO);
    impl->output_size = 0u;
    cnet_websocket_record_error(impl, SALTS_EPROTO);
    impl->state = CNET_WEBSOCKET_FAILED;
    impl->operation_active = false;
    return SALTS_EPROTO;
  }

  cnet_websocket_tagged_frame_terminal(impl, SALTS_OK);
  impl->output_size = 0u;
  if (impl->sent_close && impl->received_close && impl->state == CNET_WEBSOCKET_CLOSING)
    impl->state = CNET_WEBSOCKET_CLOSED;
  if (impl->state != CNET_WEBSOCKET_FAILED && impl->state != CNET_WEBSOCKET_CLOSED)
    process_status = cnet_websocket_process_input(impl);
  impl->operation_active = false;
  return process_status;
}

static int cnet_websocket_send_frame(cnet_websocket_impl *impl, uint8_t opcode, const void *data,
                                     size_t size) {
  if (size > CNET_WEBSOCKET_MAX_CONTROL_BYTES || size > impl->max_frame_bytes)
    return SALTS_EMSGSIZE;
  if (data == NULL && size != 0u) return SALTS_EINVAL;
  return cnet_websocket_emit_frame(impl, opcode, true, (const uint8_t *)data, size);
}

int cnet_websocket_send_tagged(cnet_websocket *websocket,
                                cnet_websocket_message_type message_type,
                                const void *data, size_t size, uint64_t tag) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  if (impl == NULL || (data == NULL && size != 0u) ||
      (message_type != CNET_WEBSOCKET_MESSAGE_TEXT &&
       message_type != CNET_WEBSOCKET_MESSAGE_BINARY)) return SALTS_EINVAL;
  if (impl->tagged_data == NULL) return SALTS_ENOTSUP;
  if (impl->write_active || (impl->operation_active && !impl->callback_active)) return SALTS_EBUSY;
  if (impl->state != CNET_WEBSOCKET_OPEN) return SALTS_ESHUTDOWN;
  if (impl->tagged_active || impl->output_size != 0u ||
      impl->outbound_message_type != CNET_WEBSOCKET_MESSAGE_NONE) return SALTS_EBUSY;
  if (size > impl->max_message_bytes) return SALTS_EMSGSIZE;
  if (message_type == CNET_WEBSOCKET_MESSAGE_TEXT &&
      !cnet_websocket_utf8_valid((const uint8_t *)data, size)) return SALTS_ECHARSET;
  if (size != 0u) memcpy(impl->tagged_data, data, size);
  impl->tagged_size = size;
  impl->tagged_offset = 0u;
  impl->tagged_tag = tag;
  impl->tagged_type = message_type;
  impl->tagged_status = SALTS_OK;
  impl->tagged_ready = false;
  impl->tagged_active = true;
  return SALTS_OK;
}

static void cnet_websocket_tagged_check_close(cnet_websocket_impl *impl) {
  if (!impl->tagged_active || impl->tagged_ready || impl->state == CNET_WEBSOCKET_OPEN) return;
  impl->tagged_status = impl->last_error != SALTS_OK ? impl->last_error : SALTS_ECANCELED;
  impl->tagged_ready = true;
  /* A rejected frame owns no transport borrow. Pending native writes remain
   * frozen until their authoritative terminal, even after protocol failure. */
  if (impl->output_tagged && !impl->output_async_pending) {
    impl->output_tagged = false;
    impl->output_size = 0u;
  }
}

int cnet_websocket_advance(cnet_websocket *websocket, size_t max_frames, size_t *out_events) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  int status = SALTS_OK;
  if (out_events != NULL) *out_events = 0u;
  if (impl == NULL || out_events == NULL || max_frames == 0u) return SALTS_EINVAL;
  if (impl->tagged_data == NULL) return SALTS_ENOTSUP;
  if (impl->operation_active || impl->callback_active || impl->write_active) return SALTS_EBUSY;
  impl->operation_active = true;
  impl->advance_active = true;
  impl->advance_write_budget = max_frames;
  cnet_websocket_tagged_check_close(impl);
  for (size_t frame = 0u; frame < max_frames && !impl->output_async_pending; ++frame) {
    if (impl->state == CNET_WEBSOCKET_FAILED || impl->state == CNET_WEBSOCKET_CLOSED) break;
    if (impl->output_size != 0u) {
      status = cnet_websocket_write_output(impl);
      if (status == SALTS_EBUSY || status == CNET_WEBSOCKET_WRITE_PENDING) {
        status = SALTS_OK;
        break;
      }
      if (status != SALTS_OK) break;
      if (impl->sent_close && impl->received_close) impl->state = CNET_WEBSOCKET_CLOSED;
      continue;
    }
    /* Give already-buffered control/input work a chance between data frames. */
    status = cnet_websocket_process_input(impl);
    if (status != SALTS_OK) break;
    cnet_websocket_tagged_check_close(impl);
    if (impl->output_size != 0u) continue;
    if (impl->state != CNET_WEBSOCKET_OPEN || !impl->tagged_active || impl->tagged_ready) break;
    {
      const size_t remaining = impl->tagged_size - impl->tagged_offset;
      const size_t size = remaining < impl->tagged_policy.fragment_bytes
                              ? remaining : impl->tagged_policy.fragment_bytes;
      const uint8_t opcode = impl->tagged_offset != 0u ? WS_OPCODE_CONTINUATION
          : impl->tagged_type == CNET_WEBSOCKET_MESSAGE_TEXT ? WS_OPCODE_TEXT : WS_OPCODE_BINARY;
      impl->tagged_frame_size = size;
      impl->tagged_frame_final = size == remaining;
      impl->tagged_emitting = true;
      status = cnet_websocket_emit_frame(impl, opcode, impl->tagged_frame_final,
                                          impl->tagged_data + impl->tagged_offset, size);
      impl->tagged_emitting = false;
      if (status != SALTS_OK) {
        impl->tagged_status = status;
        impl->tagged_ready = true;
        break;
      }
      if (impl->output_size != 0u) break;
    }
  }
  cnet_websocket_tagged_check_close(impl);
  if (impl->tagged_active && impl->tagged_ready && !impl->output_async_pending) {
    const size_t size = impl->tagged_size;
    const uint64_t tag = impl->tagged_tag;
    const int terminal = impl->tagged_status;
    impl->tagged_active = false;
    impl->tagged_ready = false;
    impl->callback_active = true;
    impl->tagged_policy.on_send(impl->tagged_policy.user, websocket, tag, size, terminal);
    impl->callback_active = false;
    *out_events = 1u;
  }
  impl->advance_active = false;
  impl->operation_active = false;
  return status;
}

int cnet_websocket_send_fragment(cnet_websocket *websocket,
                                 cnet_websocket_message_type message_type, const void *data,
                                 size_t size, bool final_fragment) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  cnet_websocket_message_type prior_type;
  cnet_websocket_utf8_state next_utf8;
  size_t prior_size;
  uint8_t opcode;
  int status;
  bool nested;

  if (impl == NULL ||
      (message_type != CNET_WEBSOCKET_MESSAGE_TEXT &&
       message_type != CNET_WEBSOCKET_MESSAGE_BINARY) ||
      (data == NULL && size != 0u))
    return SALTS_EINVAL;
  if (impl->write_active || (impl->operation_active && !impl->callback_active)) return SALTS_EBUSY;
  if (impl->state != CNET_WEBSOCKET_OPEN) return SALTS_ESHUTDOWN;
  if (impl->tagged_active) return SALTS_EBUSY;
  if (impl->output_size != 0u) return SALTS_EBUSY;
  if (size > impl->max_frame_bytes) return SALTS_EMSGSIZE;
  if (impl->outbound_message_type != CNET_WEBSOCKET_MESSAGE_NONE &&
      impl->outbound_message_type != message_type)
    return SALTS_EPROTO;
  if (size > impl->max_message_bytes - impl->outbound_message_size) return SALTS_EMSGSIZE;

  prior_type = impl->outbound_message_type;
  prior_size = impl->outbound_message_size;
  next_utf8 = impl->outbound_utf8;
  if (message_type == CNET_WEBSOCKET_MESSAGE_TEXT) {
    if (prior_type == CNET_WEBSOCKET_MESSAGE_NONE) memset(&next_utf8, 0, sizeof(next_utf8));
    if (!cnet_websocket_utf8_update(&next_utf8, (const uint8_t *)data, size, final_fragment))
      return SALTS_ECHARSET;
  }
  opcode = prior_type == CNET_WEBSOCKET_MESSAGE_NONE
               ? (message_type == CNET_WEBSOCKET_MESSAGE_TEXT ? WS_OPCODE_TEXT : WS_OPCODE_BINARY)
               : WS_OPCODE_CONTINUATION;
  nested = impl->callback_active;
  if (!nested) impl->operation_active = true;
  status = cnet_websocket_emit_frame(impl, opcode, final_fragment, (const uint8_t *)data, size);
  if (status == SALTS_OK) {
    if (final_fragment) {
      impl->outbound_message_type = CNET_WEBSOCKET_MESSAGE_NONE;
      impl->outbound_message_size = 0u;
      memset(&impl->outbound_utf8, 0, sizeof(impl->outbound_utf8));
    } else {
      impl->outbound_message_type = message_type;
      impl->outbound_message_size = prior_size + size;
      if (message_type == CNET_WEBSOCKET_MESSAGE_TEXT) impl->outbound_utf8 = next_utf8;
    }
  }
  if (!nested) impl->operation_active = false;
  return status;
}

int cnet_websocket_send_text(cnet_websocket *websocket, const void *data, size_t size) {
  return cnet_websocket_send_fragment(websocket, CNET_WEBSOCKET_MESSAGE_TEXT, data, size, true);
}

int cnet_websocket_send_binary(cnet_websocket *websocket, const void *data, size_t size) {
  return cnet_websocket_send_fragment(websocket, CNET_WEBSOCKET_MESSAGE_BINARY, data, size, true);
}

static int cnet_websocket_send_control(cnet_websocket *websocket, uint8_t opcode, const void *data,
                                       size_t size) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  int status;
  bool nested;
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->write_active || (impl->operation_active && !impl->callback_active)) return SALTS_EBUSY;
  if (impl->state != CNET_WEBSOCKET_OPEN) return SALTS_ESHUTDOWN;
  if (impl->output_size != 0u) return SALTS_EBUSY;
  nested = impl->callback_active;
  if (!nested) impl->operation_active = true;
  status = cnet_websocket_send_frame(impl, opcode, data, size);
  if (!nested) impl->operation_active = false;
  return status;
}

int cnet_websocket_send_ping(cnet_websocket *websocket, const void *data, size_t size) {
  return cnet_websocket_send_control(websocket, WS_OPCODE_PING, data, size);
}

int cnet_websocket_send_pong(cnet_websocket *websocket, const void *data, size_t size) {
  return cnet_websocket_send_control(websocket, WS_OPCODE_PONG, data, size);
}

int cnet_websocket_close(cnet_websocket *websocket, uint16_t code, const void *reason,
                         size_t reason_size) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  uint8_t payload[CNET_WEBSOCKET_MAX_CONTROL_BYTES];
  size_t payload_size = 0u;
  int status;
  bool nested;

  if (impl == NULL || (reason == NULL && reason_size != 0u)) return SALTS_EINVAL;
  if ((code == 0u && reason_size != 0u) || (code != 0u && !cnet_websocket_close_code_valid(code)))
    return SALTS_EINVAL;
  if (reason_size > CNET_WEBSOCKET_MAX_CONTROL_BYTES - 2u) return SALTS_EMSGSIZE;
  if (!cnet_websocket_utf8_valid((const uint8_t *)reason, reason_size)) return SALTS_ECHARSET;
  if (impl->write_active || (impl->operation_active && !impl->callback_active)) return SALTS_EBUSY;
  if (impl->state == CNET_WEBSOCKET_CLOSING) return SALTS_EALREADY;
  if (impl->state != CNET_WEBSOCKET_OPEN) return SALTS_ESHUTDOWN;
  if (impl->output_size != 0u || impl->tagged_active) return SALTS_EBUSY;

  if (code != 0u) {
    payload[0] = (uint8_t)(code >> 8u);
    payload[1] = (uint8_t)code;
    payload_size = 2u;
    if (reason_size != 0u) memcpy(payload + payload_size, reason, reason_size);
    payload_size += reason_size;
  }
  nested = impl->callback_active;
  if (!nested) impl->operation_active = true;
  status = cnet_websocket_emit_frame(impl, WS_OPCODE_CLOSE, true, payload, payload_size);
  if (status == SALTS_OK) {
    impl->sent_close = true;
    impl->state = impl->received_close ? CNET_WEBSOCKET_CLOSED : CNET_WEBSOCKET_CLOSING;
  }
  if (!nested) impl->operation_active = false;
  return status;
}

int cnet_websocket_transport_closed(cnet_websocket *websocket) {
  cnet_websocket_impl *impl = cnet_websocket_get(websocket);
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->operation_active || impl->callback_active || impl->write_active) return SALTS_EBUSY;
  if (impl->state == CNET_WEBSOCKET_CLOSED) return SALTS_EALREADY;
  impl->operation_active = true;
  impl->output_async_pending = false;
  impl->output_size = 0u;
  impl->input_start = 0u;
  impl->input_size = 0u;
  impl->message_size = 0u;
  if (impl->state != CNET_WEBSOCKET_FAILED) {
    impl->state = CNET_WEBSOCKET_CLOSED;
    if (!impl->close_event_delivered) {
      impl->close_event_delivered = true;
      cnet_websocket_emit_event(impl, CNET_WEBSOCKET_EVENT_CLOSE, CNET_WEBSOCKET_MESSAGE_NONE, NULL,
                                0u, CNET_WEBSOCKET_CLOSE_ABNORMAL);
    }
  }
  impl->operation_active = false;
  return SALTS_OK;
}
