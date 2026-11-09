/*
 * Test-only shared module: all identities must resolve to one installed
 * SaltsCore foundation, even when called from separate ELF/Mach-O/PE images.
 * Never ship this as part of the SDK.
 */
#include <memory/buffer.h>
#include <threads/threads.h>

#if defined(_WIN32)
#  define OWNER_PROBE_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define OWNER_PROBE_API __attribute__((visibility("default")))
#else
#  define OWNER_PROBE_API
#endif

OWNER_PROBE_API mem_pool_t *saltscore_owner_probe_pool(void) {
  return mem_global();
}

OWNER_PROBE_API const void *saltscore_owner_probe_thread(void) {
  return sync_thread_current_token();
}

OWNER_PROBE_API void saltscore_owner_probe_release(mem_slice_t *slice) {
  mem_slice_release(slice);
}

OWNER_PROBE_API mem_slice_t saltscore_owner_probe_make_slice(void) {
  mem_slice_t result = {0};
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), 1u);
  if (buffer == NULL) return result;
  mem_buffer_data(buffer)[0] = (char)0x5au;
  mem_set_used(buffer, 1u);
  result = mem_slice(buffer, 0u, 1u);
  mem_buffer_release(buffer);
  return result;
}
