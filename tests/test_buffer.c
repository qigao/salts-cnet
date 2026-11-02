#include <cmeta_buffer.h>
#include <tinytest.h>
#include <error_codes.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void external_release(void *data, void *ctx) {
  unsigned *calls = (unsigned *)ctx;
  ++*calls;
  free(data);
}

spec("Core buffer lifetime") {
  it("preserves borrowed slices, refcounts, external release and allocation limits") {
    mem_pool_t pool = {0};
    mem_buffer_t *buffer = NULL;
    mem_buffer_t *external = NULL;
    mem_slice_t slice = {0};
    char *owned = NULL;
    unsigned released = 0;
    char *storage = NULL;

    check(mem_init(&pool, 0) == 0);
    buffer = mem_get_buffer(&pool, 32u);
    check(buffer != NULL && mem_buffer_capacity(buffer) >= 32u &&
          mem_buffer_ref_count(buffer) == 1u && !mem_is_external(buffer));

    memcpy(mem_buffer_data(buffer), "buffer", 6u);
    mem_set_used(buffer, 6u);
    slice = mem_slice(buffer, 1u, 99u);
    check(slice.length == 5u && memcmp(slice.data, "uffer", 5u) == 0 &&
          mem_buffer_ref_count(buffer) == 2u);
    mem_buffer_release(buffer); /* Slice still owns buffer. */
    check(slice.data != NULL && memcmp(slice.data, "uffer", 5u) == 0);
    mem_slice_release(&slice);
    check(slice.buffer == NULL && slice.data == NULL && slice.length == 0u);

    storage = (char *)malloc(4u);
    check(storage != NULL);
    memcpy(storage, "abcd", 4u);
    external = mem_wrap_external(storage, 4u, external_release, &released);
    if (external == NULL) free(storage);
    check(external != NULL);
    check(mem_is_external(external) && mem_buffer_used(external) == 4u);
    mem_buffer_retain(external);
    mem_buffer_release(external);
    check(released == 0u);
    mem_buffer_release(external);
    check(released == 1u);

    owned = mem_strdup(&pool, "ok");
    check(owned != NULL && strcmp(owned, "ok") == 0);
    mem_free(&pool, owned);
    check(mem_alloc_array(&pool, SIZE_MAX, 2u) == NULL);
    mem_destroy(&pool);
  }
}
