#ifndef CRYPTO_DTLS_HANDSHAKE_INTERNAL_H
#define CRYPTO_DTLS_HANDSHAKE_INTERNAL_H
#include <crypto/status.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Internal message framing/reassembly only. Not a DTLS handshake or READY. */
enum { CRYPTO_DTLS_HANDSHAKE_HEADER=12, CRYPTO_DTLS_HANDSHAKE_MAX_BODY=16384,
       CRYPTO_DTLS_HANDSHAKE_SLOTS=8, CRYPTO_DTLS_HANDSHAKE_NEED=1,
       CRYPTO_DTLS_HANDSHAKE_OLD=2, CRYPTO_DTLS_TIMER_EXHAUSTED=2,
       CRYPTO_DTLS_TIMER_MAX_RETRIES=16, CRYPTO_DTLS_TIMER_MAX_MS=60000 };
typedef struct crypto_dtls_fragment {
  const uint8_t *body;
  size_t total, offset, size, wire_size;
  uint16_t sequence;
  uint8_t type;
} crypto_dtls_fragment;
typedef struct crypto_dtls_message {
  const uint8_t *body;
  size_t size;
  uint16_t sequence;
  uint8_t type;
} crypto_dtls_message;
typedef struct crypto_dtls_message_slot {
  uint8_t body[CRYPTO_DTLS_HANDSHAKE_MAX_BODY];
  uint8_t bitmap[(CRYPTO_DTLS_HANDSHAKE_MAX_BODY+7)/8];
  size_t total, received;
  uint16_t sequence;
  uint8_t type;
  bool present;
} crypto_dtls_message_slot;
typedef struct crypto_dtls_reassembly {
  crypto_dtls_message_slot slots[CRYPTO_DTLS_HANDSHAKE_SLOTS];
  uint32_t next;
  size_t body_limit;
  bool ready;
} crypto_dtls_reassembly;

/* Header can also normalize a full message for transcript hashing, even when
 * that message is larger than one record. Actual fragments must fit a record. */
int crypto_dtls_handshake_header(uint8_t type,uint16_t sequence,size_t total,
    size_t offset,size_t fragment_size,uint8_t out[CRYPTO_DTLS_HANDSHAKE_HEADER]);
int crypto_dtls_fragment_write(uint8_t type,uint16_t sequence,const void *body,size_t total,
    size_t offset,size_t size,void *out,size_t capacity,size_t *written);
/* Parses ONE fragment; wire_size permits walking coalesced messages. */
int crypto_dtls_fragment_parse(const void *wire,size_t size,crypto_dtls_fragment *out);
int crypto_dtls_reassembly_init(crypto_dtls_reassembly *state,uint16_t first,size_t body_limit);
void crypto_dtls_reassembly_clear(crypto_dtls_reassembly *state);
/* Exclusive owner, owned bytes, no allocations. Identical overlaps are legal;
 * conflicts are transactional. OLD/NEED denote old/outside-window drops with
 * consumed set to the parsed frame size. Failures consume zero bytes. */
int crypto_dtls_reassembly_feed(crypto_dtls_reassembly *state,const void *wire,size_t size,size_t *consumed);
/* View borrows stable owned state until consume/clear. Only expected complete
 * messages are visible; NEED has a zero view. Hash/validate before consuming. */
int crypto_dtls_reassembly_peek(const crypto_dtls_reassembly *state,crypto_dtls_message *out);
int crypto_dtls_reassembly_consume(crypto_dtls_reassembly *state);

typedef enum crypto_dtls_timer_phase {
  CRYPTO_DTLS_TIMER_IDLE, CRYPTO_DTLS_TIMER_WAIT, CRYPTO_DTLS_TIMER_SEND,
  CRYPTO_DTLS_TIMER_ACKED, CRYPTO_DTLS_TIMER_FAILED, CRYPTO_DTLS_TIMER_DONE
} crypto_dtls_timer_phase;
typedef struct crypto_dtls_flight_timer {
  uint64_t last_now, deadline;
  uint32_t interval, ceiling;
  unsigned retries, maximum;
  crypto_dtls_timer_phase phase;
  bool ready, sampled;
} crypto_dtls_flight_timer;
/* One owner; initialize zero/cleared state. Intervals 1..60000 ms, ceiling >=
 * initial, retries 1..16. Production defaults remain 1000 / 60000 ms. */
int crypto_dtls_flight_timer_init(crypto_dtls_flight_timer *timer,uint32_t initial,
    uint32_t ceiling,unsigned retries);
void crypto_dtls_flight_timer_clear(crypto_dtls_flight_timer *timer);
/* Called only after actual success terminals for the complete flight. */
int crypto_dtls_flight_timer_sent(crypto_dtls_flight_timer *timer,uint64_t now);
/* due is true ONCE per timeout. Pending output returns false until sent again.
 * Exhaustion is terminal; clock rollback/overflow latch ESTATE. */
int crypto_dtls_flight_timer_poll(crypto_dtls_flight_timer *timer,uint64_t now,bool *due);
/* Owner recognized a retransmitted previous peer flight (RFC6347 4.2.4).
 * Shares the bounded retry budget with timeouts; a retry already in SEND is
 * not authorized twice. Actual sent still arms the new deadline. */
int crypto_dtls_flight_timer_repeat(crypto_dtls_flight_timer *timer,uint64_t now,bool *due);
int crypto_dtls_flight_timer_ack(crypto_dtls_flight_timer *timer);
#endif
