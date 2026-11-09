#include "../../src/crypto_tls_session_cache.h"
#include <tinytest.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

static crypto_tls_cached_session entry(const char *name, uint8_t id) {
  crypto_tls_cached_session s = {0};
  s.received_ms = 100u; s.lifetime_seconds = 1u; s.ticket_size = 1u;
  s.chain_size = 1u; s.alpn_size = 2u; s.cipher = 0x1301;
  strcpy(s.hostname,name); s.ticket[0] = id; s.psk[0] = id;
  s.chain[0] = id; memcpy(s.alpn,"h2",2u);
  return s;
}
/* The private cache owns sampling; this test clock is shared atomically by
 * the concurrent lookup fixture. No public clock configuration is introduced. */
static atomic_uint_fast64_t clock_ms;
static atomic_bool clock_failed;
static int sample_clock(void *user, uint64_t *out) {
  (void)user;
  if (atomic_load(&clock_failed)) return -1;
  *out = atomic_load(&clock_ms);
  return 1;
}
static int create_cache(size_t capacity, crypto_tls_session_cache **out) {
  return crypto_tls_session_cache_create(capacity,sample_clock,NULL,out);
}
static int take_at(crypto_tls_session_cache *c, const char *name, uint64_t now,
    crypto_tls_cached_session *out) {
  atomic_store(&clock_ms,now);
  uint64_t sampled = 0u;
  return crypto_tls_session_cache_take(c,name,&sampled,out);
}
static int find_at(crypto_tls_session_cache *c, const uint8_t *ticket, size_t size,
    uint64_t now, crypto_tls_cached_session *out) {
  atomic_store(&clock_ms,now);
  uint64_t sampled = 0u;
  return crypto_tls_session_cache_find(c,ticket,size,&sampled,out);
}

typedef struct contenders { crypto_tls_session_cache *cache; atomic_int wins, misses, failures; bool peek; } contenders;
#ifdef _WIN32
static DWORD WINAPI consume(void *arg) {
#else
static void *consume(void *arg) {
#endif
  contenders *c = arg; crypto_tls_cached_session out = {0};
  uint8_t ticket[32] = {7u};
  int status = c->peek ? find_at(c->cache,ticket,sizeof(ticket),101u,&out) :
      take_at(c->cache,"localhost",101u,&out);
  if (status == CRYPTO_TLS_STREAM_OK && out.ticket[0] == 7u) atomic_fetch_add(&c->wins,1);
  else if (status == CRYPTO_TLS_STREAM_ENOENT) atomic_fetch_add(&c->misses,1);
  else atomic_fetch_add(&c->failures,1);
  memset(&out,0,sizeof(out));
  return 0;
}
static int contend(contenders *c) {
  size_t created = 0u;
  int status = 0;
#ifdef _WIN32
  HANDLE threads[8];
  for (; created < 8u; ++created) {
    threads[created] = CreateThread(NULL,0u,consume,c,0u,NULL);
    if (!threads[created]) { status = 1; break; }
  }
  for (size_t i = 0u; i < created; ++i) {
    if (WaitForSingleObject(threads[i],INFINITE) != WAIT_OBJECT_0) abort();
    if (!CloseHandle(threads[i])) status = 1;
  }
#else
  pthread_t threads[8];
  for (; created < 8u; ++created)
    if (pthread_create(&threads[created],NULL,consume,c)) { status = 1; break; }
  for (size_t i = 0u; i < created; ++i)
    if (pthread_join(threads[i],NULL)) abort();
#endif
  return status;
}

spec("Bounded context-owned TLS session cache") {
  before_each() { atomic_store(&clock_ms,100u); atomic_store(&clock_failed,false); }
  it("rejects unsupported capacity and malformed entries before mutation") {
    crypto_tls_session_cache *c = NULL; crypto_tls_cached_session s = entry("localhost",1u), out = {0};
    check_equal(crypto_tls_session_cache_create(1u,NULL,NULL,&c),CRYPTO_TLS_STREAM_EINVAL);
    check_true(c == NULL);
    check_equal(create_cache(0u,&c),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(create_cache(17u,&c),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(create_cache(1u,&c),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    s.ticket_size = sizeof(s.ticket)+1u;
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_EINVAL);
    s = entry("localhost",2u); s.lifetime_seconds = 604801u;
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_EINVAL);
    s = entry("localhost",2u); memset(s.hostname,'x',sizeof(s.hostname));
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_EINVAL);
    check_equal(take_at(c,"localhost",100u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(out.ticket[0],1u);
    crypto_tls_session_cache_destroy(c);
  }
  it("copies entries, selects newest exact hostname, consumes once and evicts at fixed capacity") {
    crypto_tls_session_cache *c = NULL; crypto_tls_cached_session s = entry("a",1u),out = {0};
    check_equal(create_cache(2u,&c),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    s = entry("b",2u); check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    s = entry("a",3u); check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    memset(&s,0,sizeof(s));
    check_equal(take_at(c,"A",101u,&out),CRYPTO_TLS_STREAM_ENOENT);
    check_equal(take_at(c,"a",101u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(out.ticket[0],3u); check_equal(out.psk[0],3u); check_equal(out.chain[0],3u);
    check_equal(out.alpn,"h2",2u);
    check_equal(take_at(c,"a",101u,&out),CRYPTO_TLS_STREAM_ENOENT);
    check_equal(take_at(c,"b",101u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(out.ticket[0],2u);
    crypto_tls_session_cache_destroy(c);
  }
  it("expires at the exact lifetime boundary and rejects backwards clocks without consuming") {
    crypto_tls_session_cache *c = NULL; crypto_tls_cached_session s = entry("localhost",4u),out = {0};
    check_equal(create_cache(2u,&c),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(take_at(c,"localhost",99u,&out),CRYPTO_TLS_STREAM_EIO);
    check_equal(take_at(c,"localhost",1099u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(take_at(c,"localhost",1100u,&out),CRYPTO_TLS_STREAM_ENOENT);
    check_equal(take_at(c,"localhost",100u,&out),CRYPTO_TLS_STREAM_ENOENT);
    s.received_ms = UINT64_MAX-500u;
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(take_at(c,"localhost",UINT64_MAX,&out),CRYPTO_TLS_STREAM_OK);
    crypto_tls_session_cache_destroy(c);
  }
  it("does not multiply a repeated ticket into multiple cached identities") {
    crypto_tls_session_cache *c = NULL; crypto_tls_cached_session s = entry("localhost",6u),out = {0};
    check_equal(create_cache(2u,&c),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(take_at(c,"localhost",100u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(take_at(c,"localhost",100u,&out),CRYPTO_TLS_STREAM_ENOENT);
    crypto_tls_session_cache_destroy(c);
  }
  it("allows exactly one concurrent stream to consume a cached entry") {
    contenders c = {0}; crypto_tls_cached_session s = entry("localhost",7u);
    check_equal(create_cache(1u,&c.cache),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c.cache,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(contend(&c),0);
    check_equal(atomic_load(&c.wins),1); check_equal(atomic_load(&c.misses),7);
    check_equal(atomic_load(&c.failures),0);
    crypto_tls_session_cache_destroy(c.cache);
  }
  it("keeps server tickets until expiry, rejects identity collisions and bounds eviction") {
    crypto_tls_session_cache *c=NULL; crypto_tls_cached_session s=entry("",5u),out={0};
    s.server_ticket=true; s.chain_size=0u; s.ticket_size=32u;
    check_equal(create_cache(1u,&c),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_EIO);
    check_equal(find_at(c,s.ticket,32u,99u,&out),CRYPTO_TLS_STREAM_EIO);
    check_equal(find_at(c,s.ticket,32u,100u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(out.chain_size,0u); check_true(out.server_ticket);
    check_equal(find_at(c,s.ticket,32u,1099u,&out),CRYPTO_TLS_STREAM_OK);
    check_equal(find_at(c,s.ticket,32u,1100u,&out),CRYPTO_TLS_STREAM_ENOENT);
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    uint8_t old[32]; memcpy(old,s.ticket,32u); s.ticket[0]=6u;
    check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(find_at(c,old,32u,101u,&out),CRYPTO_TLS_STREAM_ENOENT);
    check_equal(find_at(c,s.ticket,32u,101u,&out),CRYPTO_TLS_STREAM_OK);
    crypto_tls_session_cache_destroy(c);
  }
  it("allows concurrent server lookups without unauthenticated consumption") {
    contenders c={0}; c.peek=true; crypto_tls_cached_session s=entry("localhost",7u);
    s.server_ticket=true; s.ticket_size=32u;
    check_equal(create_cache(1u,&c.cache),CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_session_cache_put(c.cache,&s),CRYPTO_TLS_STREAM_OK);
    check_equal(contend(&c),0);
    check_equal(atomic_load(&c.wins),8); check_equal(atomic_load(&c.misses),0);
    check_equal(atomic_load(&c.failures),0);
    crypto_tls_session_cache_destroy(c.cache);
  }

  it("samples lookup time after a concurrent newer publication, for both cache roles") {
    for (unsigned server = 0u; server < 2u; ++server) {
      crypto_tls_session_cache *c = NULL;
      crypto_tls_cached_session a = entry("target",1u), b = entry("other",2u), out = {0};
      if (server) { a.server_ticket = b.server_ticket = true; a.ticket_size = b.ticket_size = 32u; }
      check_equal(create_cache(2u,&c),CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_session_cache_put(c,&a),CRYPTO_TLS_STREAM_OK);
      /* The caller was preempted after sampling 101. Another owner publishes
       * at 102 before this lookup acquires the cache. The old sample must not
       * become authoritative for observing the newer cache state. */
      uint64_t sampled = 101u;
      b.received_ms = 102u;
      atomic_store(&clock_ms,102u);
      check_equal(crypto_tls_session_cache_put(c,&b),CRYPTO_TLS_STREAM_OK);
      check_equal(server ? crypto_tls_session_cache_find(c,a.ticket,32u,&sampled,&out) :
          crypto_tls_session_cache_take(c,"target",&sampled,&out),CRYPTO_TLS_STREAM_OK);
      check_equal(sampled,102u); check_equal(out.ticket[0],1u);
      crypto_tls_session_cache_destroy(c);
    }
  }
  it("does not consume tickets on clock failure or a genuine backwards sample") {
    for (unsigned server = 0u; server < 2u; ++server) {
      crypto_tls_session_cache *c = NULL;
      crypto_tls_cached_session s = entry("target",1u), out = {0};
      if (server) { s.server_ticket = true; s.ticket_size = 32u; }
      check_equal(create_cache(1u,&c),CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_session_cache_put(c,&s),CRYPTO_TLS_STREAM_OK);
      for (unsigned failure = 0u; failure < 2u; ++failure) {
        atomic_store(&clock_failed,failure == 0u);
        atomic_store(&clock_ms,99u);
        uint64_t sampled = 123u;
        out.ticket[0] = 42u;
        check_equal(server ? crypto_tls_session_cache_find(c,s.ticket,32u,&sampled,&out) :
            crypto_tls_session_cache_take(c,"target",&sampled,&out),CRYPTO_TLS_STREAM_EIO);
        check_equal(sampled,0u); check_equal(out.ticket[0],42u);
      }
      atomic_store(&clock_failed,false);
      check_equal(server ? find_at(c,s.ticket,32u,100u,&out) :
          take_at(c,"target",100u,&out),CRYPTO_TLS_STREAM_OK);
      check_equal(out.ticket[0],1u);
      crypto_tls_session_cache_destroy(c);
    }
  }

}
