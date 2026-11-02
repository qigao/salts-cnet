#include <serial.h>
#include <tinytest.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif

#define REQUIRE(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "Serial PTY contract failed at line %d: %s\n", \
            __LINE__, #condition); \
    goto cleanup; \
  } \
} while (0)

static int read_peer(int fd, void *buffer, size_t expected) {
  unsigned char *bytes = (unsigned char *)buffer;
  size_t count = 0u;
  while (count < expected) {
    struct pollfd ready = {fd, POLLIN, 0};
    ssize_t got;
    if (poll(&ready, 1u, 1000) != 1) return 0;
    got = read(fd, bytes + count, expected - count);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) return 0;
    count += (size_t)got;
  }
  return 1;
}

static int wait_rx(salts_serial_t *serial, size_t expected) {
  size_t attempt;
  for (attempt = 0u; attempt < 1000u; ++attempt) {
    const struct timespec interval = {0, 1000000L};
    if (salts_serial_rx_available(serial) == expected) return 1;
    (void)nanosleep(&interval, NULL);
  }
  return 0;
}

static int serial_pty_native_contract(void) {
  const unsigned char payload[] = {'A', 0u, 0xffu, 0x80u, 0xc3u, 0xa9u, 'Z'};
  unsigned char received[sizeof(payload)] = {0};
  salts_serial_config_t config;
  salts_serial_t *serial = NULL;
  salts_serial_event_set_t *events = NULL;
  struct termios initial;
  char name[256] = {0};
  int master = -1;
  int slave = -1;
  unsigned int mask = 0u;
  size_t count = 99u;
  int result = 1;

  REQUIRE(openpty(&master, &slave, name, NULL, NULL) == 0);
  /* Set the fixture's initial line discipline explicitly. The original
   * backend's configure path is then exercised without inventing a promise
   * that it resets every pre-existing termios input flag. */
  REQUIRE(tcgetattr(slave, &initial) == 0);
  cfmakeraw(&initial);
  REQUIRE(tcsetattr(slave, TCSANOW, &initial) == 0);
  salts_serial_config_default(&config);
  config.rx_buffer_size = 8u;
  config.tx_buffer_size = 8u;
  config.io_chunk_size = 4u;
  config.poll_interval_ms = 1u;
  REQUIRE(salts_serial_create(&serial, &config) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_open(serial, name, SALTS_SERIAL_MODE_READ_WRITE) == SALTS_SERIAL_OK);
  REQUIRE(close(slave) == 0);
  slave = -1;
  REQUIRE(salts_serial_event_set_create(&events) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_event_set_add(events, serial,
      SALTS_SERIAL_EVENT_RX_READY | SALTS_SERIAL_EVENT_ERROR) == SALTS_SERIAL_OK);

  REQUIRE(write(master, payload, sizeof(payload)) == (ssize_t)sizeof(payload));
  REQUIRE(salts_serial_event_wait_ex(events, 1000u, &mask) == SALTS_SERIAL_OK);
  REQUIRE((mask & SALTS_SERIAL_EVENT_RX_READY) != 0u);
  REQUIRE(salts_serial_read(serial, received, sizeof(received), 1000u, &count) == SALTS_SERIAL_OK);
  REQUIRE(count == sizeof(payload));
  REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
  REQUIRE(salts_serial_write(serial, payload, sizeof(payload), 1000u, &count) == SALTS_SERIAL_OK);
  REQUIRE(count == sizeof(payload));
  REQUIRE(read_peer(master, received, sizeof(received)));
  REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
  REQUIRE(salts_serial_read(serial, received, sizeof(received), 1u, &count) == SALTS_SERIAL_OK);
  REQUIRE(count == 0u);
  mask = 99u;
  REQUIRE(salts_serial_event_wait_ex(events, 1u, &mask) == SALTS_SERIAL_WOULD_BLOCK);
  REQUIRE(mask == 0u);

  REQUIRE(salts_serial_start_async(serial) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_read(serial, received, sizeof(received), 1u, &count) == SALTS_SERIAL_INVALID_STATE);
  REQUIRE(count == 0u);
  REQUIRE(salts_serial_write(serial, payload, sizeof(payload), 1u, &count) == SALTS_SERIAL_INVALID_STATE);
  REQUIRE(count == 0u);
  REQUIRE(salts_serial_buffer_rx(serial, payload, sizeof(payload), &count) == SALTS_SERIAL_INVALID_STATE);
  REQUIRE(count == 0u);
  REQUIRE(salts_serial_drain_tx_buffer(serial, received, sizeof(received), &count) == SALTS_SERIAL_INVALID_STATE);
  REQUIRE(count == 0u);
  REQUIRE(salts_serial_write_buffered(serial, payload, sizeof(payload), &count) == SALTS_SERIAL_OK);
  REQUIRE(count == sizeof(payload));
  REQUIRE(read_peer(master, received, sizeof(received)));
  REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
  REQUIRE(write(master, payload, sizeof(payload)) == (ssize_t)sizeof(payload));
  REQUIRE(wait_rx(serial, sizeof(payload)));
  REQUIRE(salts_serial_read_buffered(serial, received, sizeof(received), &count) == SALTS_SERIAL_OK);
  REQUIRE(count == sizeof(payload));
  REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
  REQUIRE(salts_serial_stop_async(serial) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_async_running(serial) == 0);
  REQUIRE(salts_serial_stop_async(serial) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_last_error(serial) == SALTS_SERIAL_OK);

  REQUIRE(close(master) == 0);
  master = -1;
  REQUIRE(salts_serial_event_wait_ex(events, 1000u, &mask) == SALTS_SERIAL_OK);
  REQUIRE((mask & SALTS_SERIAL_EVENT_ERROR) != 0u);
  salts_serial_event_set_destroy(events);
  events = NULL;
  REQUIRE(salts_serial_close(serial) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_close(serial) == SALTS_SERIAL_OK);
  REQUIRE(salts_serial_read(serial, received, sizeof(received), 1u, &count) == SALTS_SERIAL_INVALID_STATE);
  REQUIRE(count == 0u);
  result = 0;

cleanup:
  salts_serial_event_set_destroy(events);
  salts_serial_destroy(serial);
  if (slave >= 0) (void)close(slave);
  if (master >= 0) (void)close(master);
  return result;
}

/* Keep the exact real POSIX PTY peer and goto-cleanup failure atomicity.
 * TinyTest reports the original nonzero status after all owned fds close. */
spec("Serial real POSIX pseudo-terminal") {
  it("preserves synchronous and asynchronous RX/TX and stop/error drain") {
    const int result = serial_pty_native_contract();
    check(result == 0, "serial PTY native contract returned %d", result);
  }
}
