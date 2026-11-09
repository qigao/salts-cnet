/*
 * Test-only independently loaded CNet client. The host executable does not
 * link CNet: the native loader must resolve this module's CNet dependency.
 */
#include <cnet/cnet.h>
#include <memory/buffer.h>
#include <threads/threads.h>
#include <core/error_codes.h>

#if defined(_WIN32)
#  define PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#  define PLUGIN_EXPORT
#endif

PLUGIN_EXPORT mem_pool_t *saltscore_test_plugin_pool(void) {
  return mem_global();
}

PLUGIN_EXPORT const void *saltscore_test_plugin_thread(void) {
  return sync_thread_current_token();
}

PLUGIN_EXPORT mem_slice_t saltscore_test_plugin_alloc(void) {
  mem_slice_t out = {0};
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), 1u);
  if (!buffer) return out;
  mem_buffer_data(buffer)[0] = (char)0x7bu;
  mem_set_used(buffer, 1u);
  out = mem_slice(buffer, 0u, 1u);
  mem_buffer_release(buffer);
  return out;
}

PLUGIN_EXPORT void saltscore_test_plugin_release(mem_slice_t *slice) {
  mem_slice_release(slice);
}

PLUGIN_EXPORT int saltscore_test_plugin_cnet_smoke(void) {
  cnet_client client = {0};
  cnet_client_config cfg = {0};
  int status;
#if defined(_WIN32)
  cfg.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  cfg.backend = NATIVE_IO_BACKEND_KQUEUE;
#else
  cfg.backend = NATIVE_IO_BACKEND_EPOLL;
#endif
  cfg.connection_capacity = 2u;
  cfg.command_capacity = 8u;
  cfg.request_capacity = 8u;
  cfg.completion_batch_capacity = 8u;
  cfg.event_capacity = 8u;
  cfg.max_send_bytes = 1024u;
  cfg.receive_buffer_bytes = 1024u;
  status = cnet_client_init(&client, &cfg);
  if (status != SALTS_OK) return status;
  status = cnet_client_stop(&client, 2000u);
  if (status != SALTS_OK) return status;
  return cnet_client_destroy(&client);
}
