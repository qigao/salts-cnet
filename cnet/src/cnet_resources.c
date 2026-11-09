#include "cnet_resources.h"
#include <core/error_codes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef union cnet_storage_header {
  max_align_t alignment;
  struct { cnet_allocator allocator; size_t bytes; } value;
} cnet_storage_header;

bool cnet_allocator_valid(const cnet_allocator *a) {
  return a != NULL && ((a->allocate == NULL) == (a->deallocate == NULL)) &&
         (a->allocate != NULL || a->user == NULL);
}
bool cnet_resources_valid(const cnet_resources *r) {
  return r != NULL && cnet_allocator_valid(&r->storage) &&
         (r->receive.acquire != NULL || r->receive.user == NULL);
}

void *cnet_storage_alloc(const cnet_allocator *allocator, size_t count, size_t size) {
  cnet_storage_header *header;
  cnet_allocator selected = allocator != NULL ? *allocator : (cnet_allocator){0};
  size_t bytes;
  if ((selected.allocate == NULL) != (selected.deallocate == NULL) ||
      size == 0u || count == 0u || count > (SIZE_MAX - sizeof(*header)) / size)
    return NULL;
  bytes = sizeof(*header) + count * size;
  header = selected.allocate != NULL ? selected.allocate(selected.user, bytes) : malloc(bytes);
  if (header == NULL) return NULL;
  header->value.allocator = selected;
  header->value.bytes = bytes;
  memset(header + 1, 0, count * size);
  return header + 1;
}

void cnet_storage_free(void *storage) {
  cnet_storage_header *header;
  cnet_allocator allocator;
  if (storage == NULL) return;
  header = (cnet_storage_header *)storage - 1;
  allocator = header->value.allocator;
  if (allocator.deallocate != NULL)
    allocator.deallocate(allocator.user, header, header->value.bytes);
  else free(header);
}

int cnet_buffer_acquire(const cnet_buffer_provider *provider, size_t bytes,
                         mem_buffer_t **out) {
  int status;
  if (out == NULL) return SALTS_EINVAL;
  *out = NULL;
  if (bytes == 0u || (provider != NULL && provider->acquire == NULL && provider->user != NULL))
    return SALTS_EINVAL;
  if (provider != NULL && provider->acquire != NULL) {
    status = provider->acquire(provider->user, bytes, out);
    if (status != SALTS_OK) {
      if (*out != NULL) { mem_buffer_release(*out); *out = NULL; return SALTS_EPROTO; }
      return status;
    }
  } else {
    *out = mem_get_buffer(mem_global(), bytes);
    if (*out == NULL) return SALTS_ENOMEM;
  }
  if (*out == NULL) return SALTS_EPROTO;
  if (mem_buffer_data(*out) == NULL || mem_buffer_capacity(*out) < bytes ||
      mem_buffer_ref_count(*out) != 1u) {
    mem_buffer_release(*out);
    *out = NULL;
    return SALTS_EPROTO;
  }
  mem_set_used(*out, 0u);
  return SALTS_OK;
}
