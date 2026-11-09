#include "cnet_resources.h"
#include <memory/object_pool.h>
#include <tinytest.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct resource_value {
  long double floating;
  long long integer;
  void *pointer;
} resource_value;

static struct {
  void *payload;
  void *allocation;
  size_t bytes;
  size_t allocated;
  size_t released;
  bool fail;
  bool exact_release;
} fixture;

static void *resource_allocate(void *user, size_t bytes) {
  (void)user;
  ++fixture.allocated;
  fixture.bytes = bytes;
  if (fixture.fail) return NULL;
  fixture.allocation = malloc(bytes);
  return fixture.allocation;
}

static void resource_deallocate(void *user, void *storage, size_t bytes) {
  fixture.exact_release = user == &fixture && storage == fixture.allocation &&
                          bytes == fixture.bytes;
  ++fixture.released;
  free(storage);
  fixture.allocation = NULL;
}

suite("CNet storage ownership and fundamental alignment") {
  before_each() {
    fixture.payload = NULL;
    fixture.allocation = NULL;
    fixture.bytes = fixture.allocated = fixture.released = 0;
    fixture.fail = fixture.exact_release = false;
  }
  after_each() {
    cnet_storage_free(fixture.payload);
  }

  it("aligns and zeroes system storage for fundamental C values") {
    fixture.payload = cnet_storage_alloc(NULL, 3, sizeof(resource_value));
    check_not_null(fixture.payload);
    check_equal((uintptr_t)fixture.payload % object_pool_max_alignment(), (uintptr_t)0);
    const unsigned char *bytes = fixture.payload;
    for (size_t i = 0; i < 3 * sizeof(resource_value); ++i)
      check_equal(bytes[i], (unsigned char)0);
    resource_value *values = fixture.payload;
    values[2].floating = 1.25L;
    values[2].integer = 42;
    values[2].pointer = &fixture;
    check(values[2].floating == 1.25L);
    check_equal(values[2].integer, 42LL);
    check(values[2].pointer == &fixture);
  }

  it("preserves provider alignment and the original deallocator binding") {
    cnet_allocator allocator = {resource_allocate, resource_deallocate, &fixture};
    fixture.payload = cnet_storage_alloc(&allocator, 3, sizeof(resource_value));
    check_not_null(fixture.payload);
    check_equal((uintptr_t)fixture.payload % object_pool_max_alignment(), (uintptr_t)0);
    check(fixture.bytes > 3 * sizeof(resource_value));
    const unsigned char *bytes = fixture.payload;
    for (size_t i = 0; i < 3 * sizeof(resource_value); ++i)
      check_equal(bytes[i], (unsigned char)0);
    allocator = (cnet_allocator){0};
    cnet_storage_free(fixture.payload);
    fixture.payload = NULL;
    check_equal(fixture.allocated, (size_t)1);
    check_equal(fixture.released, (size_t)1);
    check(fixture.exact_release);
  }

  it("rejects overflow and zero extents before calling the provider") {
    const cnet_allocator allocator = {resource_allocate, resource_deallocate, &fixture};
    check(cnet_storage_alloc(&allocator, SIZE_MAX, 2) == NULL);
    check(cnet_storage_alloc(&allocator, 0, sizeof(resource_value)) == NULL);
    check(cnet_storage_alloc(&allocator, 1, 0) == NULL);
    check_equal(fixture.allocated, (size_t)0);
    check_equal(fixture.released, (size_t)0);
  }

  it("returns provider failure without borrowing or substituting storage") {
    const cnet_allocator allocator = {resource_allocate, resource_deallocate, &fixture};
    fixture.fail = true;
    check(cnet_storage_alloc(&allocator, 1, sizeof(resource_value)) == NULL);
    check_equal(fixture.allocated, (size_t)1);
    check_equal(fixture.released, (size_t)0);
    check(fixture.allocation == NULL);
  }
}
