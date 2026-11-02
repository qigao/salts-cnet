#ifndef CNET_RESOURCES_INTERNAL_H
#define CNET_RESOURCES_INTERNAL_H
#include <cnet/resources.h>
/* Header records the original deallocator; every block returns to its source.
 * All allocations are zero initialized, including custom-provider storage. */
void *cnet_storage_alloc(const cnet_allocator *allocator, size_t count, size_t size);
void cnet_storage_free(void *storage);
#endif
