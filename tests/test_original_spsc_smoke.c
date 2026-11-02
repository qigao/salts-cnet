#include <ring_buffer_spsc.h>
#include <bucket_priority_queue_spsc.h>
#include <tinytest.h>
#include <stdint.h>
#include <string.h>

spec("Original SPSC ring and priority queue") {
  it("preserves ring bytes and priority order across SPSC operations") {
    uint8_t buffer[32] = {0};
    ring_spsc_t ring = {0};
    check(ring_spsc_init(&ring, buffer, sizeof(buffer)));
    uint8_t *p = ring_spsc_write_acquire(&ring, 4);
    check(p != NULL);
    memcpy(p, "test", 4);
    ring_spsc_write_release(&ring, 4);
    size_t n = 0;
    p = ring_spsc_read_acquire(&ring, &n);
    check(p != NULL && n == 4 && memcmp(p, "test", 4) == 0);
    ring_spsc_read_release(&ring, 4);
    check(ring_spsc_read_available(&ring) == 0);

    bucket_priority_queue_spsc_t q = {0};
    check(bucket_priority_queue_spsc_init(&q, 16));
    check(bucket_priority_queue_spsc_push(&q, BUCKET_PRIORITY_SPSC_LOW, 11) &&
          bucket_priority_queue_spsc_push(&q, BUCKET_PRIORITY_SPSC_HIGH, 21));
    bucket_priority_spsc_value_t value = 0;
    check(bucket_priority_queue_spsc_pop(&q, &value) && value == 21);
    check(bucket_priority_queue_spsc_pop(&q, &value) && value == 11);
    bucket_priority_queue_spsc_destroy(&q);
  }
}
