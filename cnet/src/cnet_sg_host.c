#include <cnet/sg_host.h>
#include <salts/error_codes.h>

int cnet_sg_host_route_batch(const native_io_sharded_completion *events,
                             size_t count, const cnet_sg_host_routes *routes,
                             size_t *out_accepts, size_t *out_sharded) {
  return cnet_sg_host_route_batch_with_datagrams(
      events, count, routes, NULL, 0u, out_accepts, out_sharded);
}

int cnet_sg_host_route_batch_with_datagrams(
    const native_io_sharded_completion *events, size_t count,
    const cnet_sg_host_routes *routes, cnet_datagram *const *datagrams,
    size_t datagram_count, size_t *out_accepts, size_t *out_sharded) {
  int first_error = SALTS_OK;
  if (out_accepts != NULL) *out_accepts = 0u;
  if (out_sharded != NULL) *out_sharded = 0u;
  if (routes == NULL || routes->size != sizeof(*routes) ||
      routes->version != CNET_SG_HOST_ROUTING_VERSION ||
      (count != 0u && events == NULL) ||
      (routes->client_count != 0u && routes->clients == NULL) ||
      (datagram_count != 0u && datagrams == NULL) ||
      out_accepts == NULL || out_sharded == NULL)
    return SALTS_EINVAL;
  for (size_t i = 0u; i < routes->client_count; ++i)
    if (routes->clients[i] == NULL) return SALTS_EINVAL;
  for (size_t i = 0u; i < datagram_count; ++i)
    if (datagrams[i] == NULL || datagrams[i]->impl == NULL) return SALTS_EINVAL;

  for (size_t i = 0u; i < count; ++i) {
    const native_io_sharded_completion *event = &events[i];
    native_io_completion raw = {0};
    bool consumed = false;
    int status = SALTS_OK;

    if (event->sharded_owned) {
      ++*out_sharded;
      continue;
    }
    raw.request = event->request.native_request;
    raw.endpoint = event->endpoint.native_endpoint;
    raw.kind = event->kind;
    raw.bytes = event->bytes;
    raw.status = event->status;
    raw.native_status = event->native_status;
    raw.user_data = event->user_data;
    raw.address_length = event->address_length;

    for (size_t j = 0u; j < datagram_count; ++j) {
      size_t callbacks = 0u;
      status = cnet_datagram_route_external_completion(datagrams[j], &raw, &consumed, &callbacks);
      if (status != SALTS_OK || consumed) break;
    }
    if (status == SALTS_OK && !consumed &&
        routes->listener != NULL && routes->listener->impl != NULL) {
      status = cnet_listener_route_external_completion(routes->listener, &raw, &consumed);
      if (status == SALTS_OK && consumed) ++*out_accepts;
    }
    if (status == SALTS_OK && !consumed) {
      for (size_t j = 0u; j < routes->client_count; ++j) {
        size_t callbacks = 0u;
        status = cnet_client_route_external_completion(
            routes->clients[j], &raw, &consumed, &callbacks);
        if (status != SALTS_OK || consumed) break;
      }
    }
    if (status == SALTS_OK && !consumed) status = SALTS_EPROTO;
    if (first_error == SALTS_OK && status != SALTS_OK)
      first_error = status;
    /* Never abandon the remainder of an already-observed native batch. */
  }
  return first_error;
}
