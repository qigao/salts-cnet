#include <bucket_priority_queue.h>
#include <tinytest.h>
#include <stddef.h>

spec("Original bounded priority queue") {
  it("orders critical and high priorities with FIFO within equal priority") {
    bucket_priority_queue_t q = {0};
    bucket_priority_value_t val = 0;
    check(bucket_priority_queue_init(&q, 1u));
    check(bucket_priority_queue_push(&q, BUCKET_PRIORITY_LOW, 10u) &&
          bucket_priority_queue_push(&q, BUCKET_PRIORITY_HIGH, 20u) &&
          bucket_priority_queue_push(&q, BUCKET_PRIORITY_HIGH, 21u) &&
          bucket_priority_queue_push(&q, BUCKET_PRIORITY_CRITICAL, 30u));
    const size_t expected[] = {30u, 20u, 21u, 10u};
    for (size_t i = 0u; i < 4u; ++i) {
      check(bucket_priority_queue_pop(&q, &val) && val == expected[i]);
    }
    check(bucket_priority_queue_empty(&q) && bucket_priority_queue_size(&q) == 0u);
    bucket_priority_queue_destroy(&q);
  }
}
