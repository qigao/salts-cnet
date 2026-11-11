#include "cnet_ipc_internal.h"
#include "cnet_module.h"
#include "cnet_transport.h"
#include "cnet_uri.h"
#include <limits.h>
#include <native_io_accept.h>
#include <native_ipc.h>
#include <stdlib.h>
#include <string.h>

/* One owner; fixed-capacity accepted-handle FIFO, not a reflection/CSTL container.
 * No allocation after listener init. The queue owns accepted handles until
 * the caller takes them or stop drains and closes them. */
typedef struct cnet_ipc_ready_queue {
  cnet_ipc_child *items;
  size_t capacity;
  size_t front;
  size_t count;
} cnet_ipc_ready_queue;

static int cnet_ipc_queue_init(cnet_ipc_ready_queue *q, size_t capacity) {
  if (q == NULL || capacity == 0u) return SALTS_EINVAL;
  if (capacity > SIZE_MAX / sizeof(*q->items)) return SALTS_ERANGE;
  q->items = (cnet_ipc_child *)calloc(capacity, sizeof(*q->items));
  if (q->items == NULL) return SALTS_ENOMEM;
  q->capacity = capacity;
  q->front = 0u;
  q->count = 0u;
  return SALTS_OK;
}

static void cnet_ipc_queue_destroy(cnet_ipc_ready_queue *q) {
  if (q == NULL) return;
  /* Callers close all owned native handles before invoking destroy. */
  free(q->items);
  *q = (cnet_ipc_ready_queue){0};
}

static size_t cnet_ipc_queue_size(const cnet_ipc_ready_queue *q) {
  return q != NULL ? q->count : 0u;
}

static bool cnet_ipc_queue_empty(const cnet_ipc_ready_queue *q) {
  return cnet_ipc_queue_size(q) == 0u;
}

static int cnet_ipc_queue_push(cnet_ipc_ready_queue *q,
                               const cnet_ipc_child *accepted) {
  size_t slot;
  if (q == NULL || accepted == NULL || q->items == NULL) return SALTS_EINVAL;
  if (q->count == q->capacity) return SALTS_ENOBUFS;
  slot = q->front + q->count;
  if (slot >= q->capacity) slot -= q->capacity;
  q->items[slot] = *accepted;
  ++q->count;
  return SALTS_OK;
}

static int cnet_ipc_queue_pop(cnet_ipc_ready_queue *q, cnet_ipc_child *out) {
  if (q == NULL || out == NULL || q->items == NULL) return SALTS_EINVAL;
  if (q->count == 0u) return SALTS_ENOENT;
  *out = q->items[q->front];
  q->items[q->front] = (cnet_ipc_child){0};
  if (++q->front == q->capacity) q->front = 0u;
  --q->count;
  return SALTS_OK;
}

typedef struct cnet_ipc_listener_impl {
  cnet_ipc_ready_queue ready;
  size_t accept_capacity;
  size_t child_capacity;
  int progress_status;
  int stop_status;
  bool advancing;
  bool stopping;
  bool stopped;
  native_io_backend_kind backend_kind;
  native_io_backend *external_backend;
  native_io_endpoint external_endpoint;
  native_io_request external_request;
  bool external_cancel_requested;
#if defined(_WIN32)
  ipc_pipe_server server;
  uintptr_t *wait_handles;
  char *pipe_name;
  size_t input_buffer_bytes;
  size_t output_buffer_bytes;
  ipc_pipe_endpoint external_pipe;
#else
  uintptr_t socket_value;
#endif
} cnet_ipc_listener_impl;

static bool cnet_ipc_descriptor_valid(const cnet_ipc_accepted *accepted) {
  return accepted != NULL && accepted->native_handle != UINTPTR_MAX &&
         (accepted->kind == CNET_IPC_RESOURCE_PIPE || accepted->kind == CNET_IPC_RESOURCE_SOCKET);
}

int cnet_ipc_accepted_close(cnet_ipc_accepted *accepted) {
  cnet_ipc_accepted owned;
  if (accepted == NULL) return SALTS_EINVAL;
  if (accepted->kind == CNET_IPC_RESOURCE_NONE) return SALTS_EALREADY;
  if (!cnet_ipc_descriptor_valid(accepted)) return SALTS_EINVAL;
  owned = *accepted;
  *accepted = (cnet_ipc_accepted){0};
#if defined(_WIN32)
  if (owned.kind == CNET_IPC_RESOURCE_PIPE) return cnet_transport_close_ipc(owned.native_handle);
  cnet_transport_close_socket(owned.native_handle);
  return SALTS_OK;
#else
  return cnet_transport_close_ipc(owned.native_handle);
#endif
}

int cnet_ipc_child_close(cnet_ipc_child *child, native_io_backend *backend) {
  if (!native_io_endpoint_valid(child->attached_pipe))
    return cnet_ipc_accepted_close(&child->descriptor);
  cnet_transport transport = cnet_transport_attached_pipe(child->descriptor.native_handle,
                                                         child->attached_pipe);
  const int status = cnet_transport_close(&transport, backend);
  *child = (cnet_ipc_child){0};
  return status;
}

#if defined(_WIN32)
static cnet_ipc_child cnet_ipc_take_pipe(cnet_ipc_listener_impl *impl) {
  const cnet_ipc_child child = {
      .descriptor = {impl->external_pipe.handle, CNET_IPC_RESOURCE_PIPE},
      .attached_pipe = impl->external_endpoint};
  ipc_pipe_endpoint_init(&impl->external_pipe);
  impl->external_endpoint = (native_io_endpoint){0};
  return child;
}

static void cnet_ipc_accept_terminal(void *user, const ipc_completion *completion,
                                     ipc_pipe_endpoint endpoint) {
  cnet_ipc_listener_impl *impl = (cnet_ipc_listener_impl *)user;
  int status = SALTS_OK;
  if (ipc_pipe_endpoint_valid(&endpoint)) {
    cnet_ipc_child accepted = {.descriptor = {endpoint.handle, CNET_IPC_RESOURCE_PIPE}};
    if (!impl->stopping) status = cnet_ipc_queue_push(&impl->ready, &accepted);
    if (impl->stopping || status != SALTS_OK) {
      const int close_status = cnet_ipc_accepted_close(&accepted.descriptor);
      if (status == SALTS_OK) status = close_status;
    }
  } else if (!(impl->stopping && completion->kind == SALTS_IPC_COMPLETION_CANCELLED)) {
    status = completion->status < SALTS_OK ? completion->status : SALTS_EPROTO;
  }
  if (impl->progress_status == SALTS_OK) impl->progress_status = status;
}
#else
static int cnet_ipc_socket_status(native_io_socket_result result) {
  return result.native_status > 0 ? -result.native_status : result.status;
}
static int cnet_ipc_nonblocking(uintptr_t socket_value) {
  native_io_socket_result result = native_io_socket_nonblocking(socket_value);
  if (result.status == SALTS_OK) result = native_io_socket_close_on_exec(socket_value);
  return cnet_ipc_socket_status(result);
}

static int cnet_ipc_publish_socket(cnet_ipc_listener_impl *impl, uintptr_t descriptor) {
  cnet_ipc_child accepted = {.descriptor = {descriptor, CNET_IPC_RESOURCE_SOCKET}};
  if (impl->stopping) return cnet_ipc_accepted_close(&accepted.descriptor);
  int status = cnet_ipc_nonblocking(descriptor);
  if (status == SALTS_OK) status = cnet_ipc_queue_push(&impl->ready, &accepted);
  if (status != SALTS_OK) (void)cnet_ipc_accepted_close(&accepted.descriptor);
  return status;
}
#endif

int cnet_ipc_listener_init(cnet_ipc_listener *listener, const cnet_ipc_listener_config *config) {
  cnet_ipc_listener_impl *impl;
  cnet_uri uri;
  int status;
  if (listener == NULL || config == NULL || config->size != sizeof(*config) ||
      config->version != CNET_IPC_VERSION || config->accept_capacity == 0u ||
      config->child_capacity < config->accept_capacity || config->input_buffer_bytes == 0u ||
      config->output_buffer_bytes == 0u)
    return SALTS_EINVAL;
  if (listener->impl != NULL) return SALTS_EALREADY;
  if (!native_io_backend_kind_supported(config->backend)) return SALTS_ENOTSUP;
  if (config->child_capacity > SIZE_MAX / sizeof(cnet_ipc_child) ||
      config->accept_capacity > SIZE_MAX / sizeof(uintptr_t))
    return SALTS_ERANGE;
#if defined(_WIN32)
  if (config->backend != NATIVE_IO_BACKEND_IOCP) return SALTS_ENOTSUP;
  if (config->accept_capacity > 255u || config->input_buffer_bytes > UINT32_MAX ||
      config->output_buffer_bytes > UINT32_MAX)
    return SALTS_ERANGE;
#else
  if (config->accept_capacity > INT_MAX) return SALTS_ERANGE;
#endif
  status = cnet_uri_parse(config->uri, &uri);
  if (status != SALTS_OK) return status;
  if (uri.scheme != CNET_URI_IPC) return SALTS_EINVAL;
  status = cnet_module_init();
  if (status != SALTS_OK) return status;
  impl = (cnet_ipc_listener_impl *)calloc(1u, sizeof(*impl));
  if (impl == NULL) {
    (void)cnet_module_shutdown();
    return SALTS_ENOMEM;
  }
#if !defined(_WIN32)
  impl->socket_value = UINTPTR_MAX;
#endif
  impl->backend_kind = config->backend;
  impl->accept_capacity = config->accept_capacity;
  impl->child_capacity = config->child_capacity;
  status = cnet_ipc_queue_init(&impl->ready, config->child_capacity);
  if (status != SALTS_OK) goto fail;
#if defined(_WIN32)
  {
    ipc_pipe_server_config native_config = {0};
    impl->wait_handles = (uintptr_t *)calloc(config->accept_capacity, sizeof(uintptr_t));
    if (impl->wait_handles == NULL) {
      status = SALTS_ENOMEM;
      goto fail;
    }
    status = cnet_transport_ipc_native_name(uri.path, &impl->pipe_name);
    if (status != SALTS_OK) goto fail;
    impl->input_buffer_bytes = config->input_buffer_bytes;
    impl->output_buffer_bytes = config->output_buffer_bytes;
    ipc_pipe_endpoint_init(&impl->external_pipe);
    native_config.name = impl->pipe_name;
    native_config.direction = SALTS_IPC_PIPE_DUPLEX;
    native_config.request_capacity = config->accept_capacity;
    native_config.input_buffer_size = config->input_buffer_bytes;
    native_config.output_buffer_size = config->output_buffer_bytes;
    native_config.completion = cnet_ipc_accept_terminal;
    native_config.completion_user = impl;
    status = ipc_pipe_server_init(&impl->server, &native_config);
    if (status != SALTS_OK) goto fail;
  }
#else
  {
    native_io_socket_address address;
    size_t length = 0u;
    status = cnet_transport_ipc_address(uri.path, &address, sizeof(address), &length);
    if (status != SALTS_OK) goto fail;
    status = cnet_ipc_socket_status(native_io_socket_create_unattached(
        native_io_socket_domain(NATIVE_IO_SOCKET_LOCAL), false, &impl->socket_value));
    if (status != SALTS_OK) goto fail;
    status = cnet_ipc_nonblocking(impl->socket_value);
    if (status != SALTS_OK) goto fail;
    status = cnet_ipc_socket_status(native_io_socket_bind(impl->socket_value, &address, length));
    if (status == SALTS_OK)
      status = cnet_ipc_socket_status(native_io_socket_listen(impl->socket_value, config->accept_capacity));
    if (status != SALTS_OK) goto fail;
  }
#endif
  listener->impl = impl;
  return SALTS_OK;
fail:
#if defined(_WIN32)
  free(impl->pipe_name);
  free(impl->wait_handles);
#else
  if (impl->socket_value != UINTPTR_MAX) (void)native_io_socket_close(impl->socket_value);
#endif
  cnet_ipc_queue_destroy(&impl->ready);
  free(impl);
  (void)cnet_module_shutdown();
  return status;
}

int cnet_ipc_listener_attach_external(cnet_ipc_listener *listener,
                                      native_io_backend *borrowed_backend) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  native_io_backend_config config;
  if (impl == NULL || borrowed_backend == NULL || borrowed_backend->impl == NULL)
    return SALTS_EINVAL;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->external_backend != NULL)
    return impl->external_backend == borrowed_backend ? SALTS_EALREADY : SALTS_EBUSY;
  if (!native_io_backend_get_config(borrowed_backend, &config) ||
      config.kind != impl->backend_kind) return SALTS_EINVAL;
#if defined(_WIN32)
  ipc_pipe_server_stats stats;
  if (!ipc_pipe_server_get_stats(&impl->server, &stats)) return SALTS_EPROTO;
  if (stats.active_requests != 0u || !cnet_ipc_queue_empty(&impl->ready)) return SALTS_EBUSY;
#else
  if (impl->backend_kind != NATIVE_IO_BACKEND_EPOLL &&
      impl->backend_kind != NATIVE_IO_BACKEND_KQUEUE) return SALTS_ENOTSUP;
  const int status = native_io_backend_attach_socket(borrowed_backend, impl->socket_value,
                                                      &impl->external_endpoint);
  if (status != SALTS_OK) return status;
#endif
  impl->external_backend = borrowed_backend;
  return SALTS_OK;
}

int cnet_ipc_listener_submit_external_accept(cnet_ipc_listener *listener,
                                             native_io_request *out_request) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  if (out_request == NULL) return SALTS_EINVAL;
  *out_request = (native_io_request){0};
  if (impl == NULL) return SALTS_EINVAL;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  if (impl->external_backend == NULL) return SALTS_ENOTSUP;
  if (native_io_request_valid(impl->external_request)) {
    *out_request = impl->external_request;
    return SALTS_OK;
  }
  if (cnet_ipc_queue_size(&impl->ready) == impl->child_capacity) return SALTS_ENOBUFS;
#if defined(_WIN32)
  int status = ipc_named_pipe_create_instance(impl->pipe_name, SALTS_IPC_PIPE_DUPLEX,
                                              impl->input_buffer_bytes, impl->output_buffer_bytes,
                                              &impl->external_pipe);
  if (status != SALTS_OK) return status;
  status = native_io_backend_attach_pipe(impl->external_backend, impl->external_pipe.handle,
                                         impl->external_pipe.native_io_flags,
                                         &impl->external_endpoint);
  if (status == SALTS_OK)
    status = native_io_internal_submit_pipe_accept(impl->external_backend, impl->external_endpoint,
                                                    out_request);
  if (status != SALTS_OK) {
    cnet_ipc_child child = cnet_ipc_take_pipe(impl);
    const int close_status = cnet_ipc_child_close(&child, impl->external_backend);
    return close_status == SALTS_OK ? status : close_status;
  }
#else
  const int status = native_io_internal_submit_stream_accept(
      impl->external_backend, impl->external_endpoint, out_request);
#endif
  if (status == SALTS_OK) impl->external_request = *out_request;
  return status;
}

int cnet_ipc_listener_route_external_completion(cnet_ipc_listener *listener,
                                                 const native_io_completion *completion,
                                                 bool *out_consumed) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  if (out_consumed == NULL) return SALTS_EINVAL;
  *out_consumed = false;
  if (impl == NULL || completion == NULL) return SALTS_EINVAL;
  int status = SALTS_OK;
  if (!native_io_request_valid(impl->external_request) ||
      completion->request.slot != impl->external_request.slot ||
      completion->request.generation != impl->external_request.generation)
    return SALTS_OK;
  if (completion->endpoint.slot != impl->external_endpoint.slot ||
      completion->endpoint.generation != impl->external_endpoint.generation)
    return SALTS_EPROTO;

  *out_consumed = true;
  impl->external_request = (native_io_request){0};
  impl->external_cancel_requested = false;
  const bool accepted = completion->kind == NATIVE_IO_COMPLETION_OK && completion->status == SALTS_OK;
#if defined(_WIN32)
  cnet_ipc_child child = cnet_ipc_take_pipe(impl);
  if (accepted && !impl->stopping) {
    status = cnet_ipc_queue_push(&impl->ready, &child);
    if (status != SALTS_OK) (void)cnet_ipc_child_close(&child, impl->external_backend);
  } else {
    status = cnet_ipc_child_close(&child, impl->external_backend);
  }
#else
  if (accepted) {
    uintptr_t descriptor;
    status = native_io_internal_take_stream_accept(impl->external_backend,
                                                    completion->request, &descriptor);
    if (status == SALTS_OK) status = cnet_ipc_publish_socket(impl, descriptor);
  }
#endif
  if (!accepted && status == SALTS_OK &&
      !(impl->stopping && (completion->kind == NATIVE_IO_COMPLETION_CANCELLED ||
                           completion->status == SALTS_ECANCELED))) {
    status = completion->status == SALTS_OK ? SALTS_EIO : completion->status;
  }
  if (impl->stopping && impl->stop_status == SALTS_OK) impl->stop_status = status;
  return status;
}

int cnet_ipc_listener_advance(cnet_ipc_listener *listener, size_t max_events, size_t *out_events) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  int status = SALTS_OK;
  if (out_events != NULL) *out_events = 0u;
  if (impl == NULL || out_events == NULL || max_events == 0u) return SALTS_EINVAL;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->external_backend != NULL) return SALTS_ENOTSUP;
  if (impl->stopped) return SALTS_OK;
  impl->advancing = true;
  impl->progress_status = SALTS_OK;
#if defined(_WIN32)
  status = ipc_pipe_server_observe(&impl->server, max_events, out_events);
  if (status == SALTS_OK) status = impl->progress_status;
  if (!impl->stopping && status == SALTS_OK) {
    ipc_pipe_server_stats stats;
    if (!ipc_pipe_server_get_stats(&impl->server, &stats)) status = SALTS_EPROTO;
    else {
      size_t active = stats.active_requests;
      const size_t ready = cnet_ipc_queue_size(&impl->ready);
      for (size_t count = 0u; count < max_events && active < impl->accept_capacity &&
                              active < impl->child_capacity - ready;
           ++count, ++active) {
        ipc_request_id request;
        status = ipc_pipe_server_try_accept(&impl->server, &request);
        if (status != SALTS_OK) break;
      }
    }
  }
#else
  while (!impl->stopping && *out_events < max_events &&
         cnet_ipc_queue_size(&impl->ready) < impl->child_capacity) {
    uintptr_t descriptor;
    native_io_socket_result result = native_io_socket_accept(impl->socket_value, &descriptor, NULL, 0, NULL);
    if (result.status != SALTS_OK) {
      status = result.status == SALTS_ETIMEDOUT || result.status == SALTS_EINTR ?
          SALTS_OK : cnet_ipc_socket_status(result);
      break;
    }
    status = cnet_ipc_publish_socket(impl, descriptor);
    if (status != SALTS_OK) break;
    ++*out_events;
  }
#endif
  if (impl->stopping && status != SALTS_OK && impl->stop_status == SALTS_OK)
    impl->stop_status = status;
  impl->advancing = false;
  return status;
}

int cnet_ipc_listener_accept_detached(cnet_ipc_listener *listener,
                                      cnet_ipc_accepted *out_accepted) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  if (impl == NULL || out_accepted == NULL) return SALTS_EINVAL;
  if (out_accepted->kind != CNET_IPC_RESOURCE_NONE) return SALTS_EALREADY;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->stopping) return SALTS_ESHUTDOWN;
#if defined(_WIN32)
  if (impl->external_backend != NULL) return SALTS_ENOTSUP;
#endif
  cnet_ipc_child child;
  const int status = cnet_ipc_queue_pop(&impl->ready, &child);
  if (status == SALTS_OK) *out_accepted = child.descriptor;
  return status;
}

int cnet_ipc_listener_take_external(cnet_ipc_listener *listener, native_io_backend *backend,
                                     cnet_ipc_child *out_child) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  if (impl == NULL || backend == NULL || impl->external_backend == NULL ||
      impl->external_backend->impl != backend->impl) return SALTS_EINVAL;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->stopping) return SALTS_ESHUTDOWN;
  return cnet_ipc_queue_pop(&impl->ready, out_child);
}

int cnet_ipc_listener_wait_sources(const cnet_ipc_listener *listener,
                                   cnet_ipc_wait_source *out_sources, size_t capacity,
                                   size_t *out_count, bool *out_ready) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  size_t count = 0u;
  if (out_count != NULL) *out_count = 0u;
  if (out_ready != NULL) *out_ready = false;
  if (impl == NULL || out_count == NULL || out_ready == NULL ||
      (capacity != 0u && out_sources == NULL))
    return SALTS_EINVAL;
  if (impl->advancing) return SALTS_EBUSY;
  if (impl->stopped) return SALTS_OK;
  if (impl->external_backend != NULL) return SALTS_ENOTSUP;
#if defined(_WIN32)
  {
    const int status = ipc_pipe_server_wait_sources(&impl->server, impl->wait_handles,
                                                          impl->accept_capacity, &count, out_ready);
    if (status != SALTS_OK) return status;
  }
#else
  if (!impl->stopping && cnet_ipc_queue_size(&impl->ready) < impl->child_capacity) count = 1u;
#endif
  *out_ready = *out_ready || !cnet_ipc_queue_empty(&impl->ready);
  *out_count = count;
  if (count > capacity) return SALTS_ENOBUFS;
  for (size_t index = 0; index < count; ++index) {
#if defined(_WIN32)
    out_sources[index] =
        (cnet_ipc_wait_source){CNET_IPC_WAIT_WINDOWS_EVENT, impl->wait_handles[index]};
#else
    out_sources[index] =
        (cnet_ipc_wait_source){CNET_IPC_WAIT_READABLE_FD, (uintptr_t)impl->socket_value};
#endif
  }
  return SALTS_OK;
}

int cnet_ipc_listener_stop(cnet_ipc_listener *listener, bool *out_stopped) {
  cnet_ipc_listener_impl *impl = listener != NULL ? listener->impl : NULL;
  int status = SALTS_OK;
  if (out_stopped != NULL) *out_stopped = false;
  if (impl == NULL || out_stopped == NULL) return SALTS_EINVAL;
  if (impl->advancing) return SALTS_EBUSY;
  impl->stopping = true;
  while (!cnet_ipc_queue_empty(&impl->ready)) {
    cnet_ipc_child accepted;
    status = cnet_ipc_queue_pop(&impl->ready, &accepted);
    if (status != SALTS_OK) return status;
    status = cnet_ipc_child_close(&accepted, impl->external_backend);
    if (status != SALTS_OK && impl->stop_status == SALTS_OK) impl->stop_status = status;
  }
  if (native_io_request_valid(impl->external_request)) {
    if (!impl->external_cancel_requested) {
      status = native_io_backend_cancel(impl->external_backend, impl->external_request);
      if (status != SALTS_OK && status != SALTS_EALREADY && status != SALTS_ENOENT)
        return status;
      impl->external_cancel_requested = true;
    }
    return impl->stop_status == SALTS_OK ? SALTS_EBUSY : impl->stop_status;
  }
#if defined(_WIN32)
  if (!impl->stopped) {
    status = ipc_pipe_server_close(&impl->server);
    if (status != SALTS_OK && impl->stop_status == SALTS_OK) impl->stop_status = status;
    impl->stopped = ipc_pipe_server_is_quiescent(&impl->server);
  }
#else
  if (impl->socket_value != UINTPTR_MAX) {
    status = cnet_ipc_socket_status(native_io_socket_close(impl->socket_value));
    impl->socket_value = UINTPTR_MAX;
    if (status != SALTS_OK && impl->stop_status == SALTS_OK) impl->stop_status = status;
  }
  if (impl->external_backend != NULL) {
    status = native_io_backend_release_socket(impl->external_backend, impl->external_endpoint);
    if (status != SALTS_OK) return status;
  }
  impl->stopped = true;
#endif
  if (impl->stopped) impl->external_backend = NULL;
  *out_stopped = impl->stopped;
  if (impl->stop_status != SALTS_OK) return impl->stop_status;
  return impl->stopped ? SALTS_OK : SALTS_EBUSY;
}

int cnet_ipc_listener_destroy(cnet_ipc_listener *listener) {
  cnet_ipc_listener_impl *impl;
  if (listener == NULL) return SALTS_EINVAL;
  impl = listener->impl;
  if (impl == NULL) return SALTS_OK;
  if (impl->advancing || !impl->stopped) return SALTS_EBUSY;
#if defined(_WIN32)
  {
    const int status = ipc_pipe_server_destroy(&impl->server);
    if (status != SALTS_OK) return status;
  }
  free(impl->pipe_name);
  free(impl->wait_handles);
#endif
  cnet_ipc_queue_destroy(&impl->ready);
  free(impl);
  listener->impl = NULL;
  return cnet_module_shutdown();
}
