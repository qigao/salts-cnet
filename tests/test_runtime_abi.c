#include <runtime_abi.h>
#include <tinytest.h>
#include <cmeta_buffer.h>
spec("Core runtime ABI 0.1") {
  it("retains the required ABI symbol and public native layout") {
    salts_core_runtime_abi_0_1_required();
    check(salts_core_runtime_abi_version() == SALTS_CORE_RUNTIME_ABI_VERSION);
    check(SALTS_CORE_RUNTIME_ABI_MAJOR == 0u);
    check(SALTS_CORE_RUNTIME_ABI_MINOR == 1u);
    check(salts_core_runtime_mem_pool_size() == sizeof(mem_pool_t));
    check(salts_core_runtime_mem_buffer_size() == sizeof(mem_buffer_t));
    check(salts_core_runtime_mem_slice_size() == sizeof(mem_slice_t));
  }
}
