#include <bytes.h>
#include <tinytest.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

_Static_assert(offsetof(salts_core_bytes_view, data) == 0u,
               "byte view data offset drift");
_Static_assert(offsetof(salts_core_bytes_view, len) == sizeof(const char *),
               "byte view size offset drift");

spec("Core byte views") {
  it("validate slices and error-state preservation") {
  static const char input[] = "a\0bc";
  salts_core_bytes_view root = {"sentinel", 100u};
  salts_core_bytes_view slice = {"unchanged", 17u};

  check(salts_core_bytes_view_init(&root, input, sizeof(input) - 1u) == SALTS_CORE_OK);
  check(root.data == input && root.len == 4u);
  check(salts_core_bytes_view_slice(root, 1u, 3u, &slice) == SALTS_CORE_OK);
  check(slice.len == 3u && memcmp(slice.data, "\0bc", 3u) == 0);

  check(salts_core_bytes_view_slice(root, 5u, 0u, &slice) == SALTS_CORE_EINVAL);
  check(slice.len == 3u && slice.data == input + 1u);
  check(salts_core_bytes_view_slice(root, 1u, SIZE_MAX, &slice) == SALTS_CORE_EINVAL);
  check(slice.len == 3u && slice.data == input + 1u);
  check(salts_core_bytes_view_init(&root, NULL, 1u) == SALTS_CORE_EINVAL);
  check(root.data == input && root.len == 4u);
  check(salts_core_bytes_view_init(&root, NULL, 0u) == SALTS_CORE_OK);
  check(salts_core_bytes_view_slice(root, 0u, 0u, &slice) == SALTS_CORE_OK);
  check(slice.data == NULL && slice.len == 0u);
  }
}
