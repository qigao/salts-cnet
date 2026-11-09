#ifndef CRYPTO_TLS_SESSION_CACHE_INTERNAL_H
#define CRYPTO_TLS_SESSION_CACHE_INTERNAL_H
#include <crypto/tls_stream.h>

enum { CRYPTO_TLS_SESSION_TICKET_MAX = 459, CRYPTO_TLS_SESSION_CACHE_MAX = 16 };
typedef struct crypto_tls_cached_session {
  uint64_t received_ms;
  uint32_t lifetime_seconds, age_add;
  int cipher;
  bool server_ticket;
  size_t ticket_size, chain_size, alpn_size;
  char hostname[CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY];
  uint8_t psk[32], ticket[CRYPTO_TLS_SESSION_TICKET_MAX];
  uint8_t chain[CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES];
  uint8_t alpn[CRYPTO_TLS_STREAM_ALPN_NAME_MAX_BYTES];
  uint8_t local_leaf_sha256[32];
} crypto_tls_cached_session;
typedef struct crypto_tls_session_cache crypto_tls_session_cache;
/* Internal bounded monotonic sampler, never an application callback. Returns
 * 1 on success. It runs under the cache lock: no reentry or blocking work.
 * clock_user is borrowed until destroy; production uses the stateless OS clock. */
typedef int (*crypto_tls_session_cache_clock)(void *clock_user, uint64_t *now_ms);
int crypto_tls_session_cache_create(size_t capacity, crypto_tls_session_cache_clock clock,
    void *clock_user, crypto_tls_session_cache **out);
void crypto_tls_session_cache_destroy(crypto_tls_session_cache *cache);
int crypto_tls_session_cache_put(crypto_tls_session_cache *cache, const crypto_tls_cached_session *session);
/* ENOENT is a cache miss. Other errors never select a session. out is separate
 * caller-owned storage; consuming a ticket is irreversible, including on later
 * transport failure. The cache samples its clock after acquiring the lock;
 * out_now_ms returns that same sample for ticket-age encoding. Clock failure
 * or a sample preceding a published receipt is EIO without consuming a ticket.
 * No application code runs under the cache lock. */
int crypto_tls_session_cache_take(crypto_tls_session_cache *cache, const char *hostname,
    uint64_t *out_now_ms, crypto_tls_cached_session *out);
/* Server lookup copies without consuming; proof is verified after this lookup.
 * Public opaque identity only, exact match. Does not extend expiry. */
int crypto_tls_session_cache_find(crypto_tls_session_cache *cache, const uint8_t *ticket,
    size_t ticket_size, uint64_t *out_now_ms, crypto_tls_cached_session *out);
#endif
