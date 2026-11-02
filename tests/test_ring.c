#include <ring_buffer.h>
#include <tinytest.h>
#include <stdint.h>
#include <string.h>

spec("Core ring buffer") {
  it("preserves unread data across wrap and rejects writes when full") {
    uint8_t data[16] = {0};
    ring_data_type queue = {0};
    uint8_t *ptr;
    size_t available = 999u;
    ring_init(&queue, data, sizeof(data));
    check(ring_read_acquire(&queue, &available) == NULL && available == 0u);
    ptr = ring_write_acquire(&queue, 10u);
    check(ptr != NULL);
    memcpy(ptr, "abcdefghij", 10u);
    ring_write_release(&queue, 10u);
    ptr = ring_read_acquire(&queue, &available);
    check(ptr != NULL && available == 10u && memcmp(ptr, "abcdefghij", 10u) == 0);
    ring_read_release(&queue, available);

    /* After a full read, wrap without leaking invalidated tail bytes. */
    ptr = ring_write_acquire(&queue, 8u);
    check(ptr == data);
    memcpy(ptr, "12345678", 8u);
    ring_write_release(&queue, 8u);
    ptr = ring_read_acquire(&queue, &available);
    check(ptr == data && available == 8u && memcmp(ptr, "12345678", 8u) == 0);
    ring_read_release(&queue, 8u);
    check(ring_read_acquire(&queue, &available) == NULL && available == 0u);
    check(ring_write_acquire(&queue, sizeof(data)) == NULL);
  }
}
