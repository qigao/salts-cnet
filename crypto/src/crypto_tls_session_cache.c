#include "crypto_tls_session_cache.h"
#include "crypto_internal.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

struct crypto_tls_session_cache {
#ifdef _WIN32
  SRWLOCK lock;
#else
  pthread_mutex_t lock;
#endif
  size_t capacity, next;
  crypto_tls_cached_session entries[];
};
static void lock_cache(crypto_tls_session_cache *c) {
#ifdef _WIN32
  AcquireSRWLockExclusive(&c->lock);
#else
  if (pthread_mutex_lock(&c->lock) != 0) abort();
#endif
}
static void unlock_cache(crypto_tls_session_cache *c) {
#ifdef _WIN32
  ReleaseSRWLockExclusive(&c->lock);
#else
  if (pthread_mutex_unlock(&c->lock) != 0) abort();
#endif
}
int crypto_tls_session_cache_create(size_t capacity, crypto_tls_session_cache **out) {
  if (!out) return CRYPTO_TLS_STREAM_EINVAL;
  *out = NULL;
  if (!capacity || capacity > CRYPTO_TLS_SESSION_CACHE_MAX) return CRYPTO_TLS_STREAM_EINVAL;
  /* Independently bounded count/entry size, including 32-bit size_t. */
  crypto_tls_session_cache *c = calloc(1u,sizeof(*c)+capacity*sizeof(c->entries[0]));
  if (!c) return CRYPTO_TLS_STREAM_ENOMEM;
#ifdef _WIN32
  InitializeSRWLock(&c->lock);
#else
  if (pthread_mutex_init(&c->lock,NULL) != 0) { free(c); return CRYPTO_TLS_STREAM_EIO; }
#endif
  c->capacity = capacity;
  *out = c;
  return CRYPTO_TLS_STREAM_OK;
}
void crypto_tls_session_cache_destroy(crypto_tls_session_cache *c) {
  if (!c) return;
  /* Last owning context reference implies no stream/callback/borrow remains. */
#ifndef _WIN32
  if (pthread_mutex_destroy(&c->lock) != 0) abort();
#endif
  const size_t bytes = sizeof(*c)+c->capacity*sizeof(c->entries[0]);
  salts_crypto_secure_zero(c,bytes);
  free(c);
}
int crypto_tls_session_cache_put(crypto_tls_session_cache *c, const crypto_tls_cached_session *s) {
  if (!c || !s || !s->ticket_size || s->ticket_size > sizeof(s->ticket) ||
      !s->lifetime_seconds || s->lifetime_seconds > 604800u ||
      s->chain_size > sizeof(s->chain) || s->alpn_size > sizeof(s->alpn) ||
      (!s->server_ticket && (!s->chain_size || !s->hostname[0])) ||
      (s->server_ticket && s->ticket_size != 32u) ||
      !memchr(s->hostname,0,sizeof(s->hostname))) return CRYPTO_TLS_STREAM_EINVAL;
  lock_cache(c);
  if (s->server_ticket) {
    for (size_t i = 0u; i < c->capacity; ++i) {
      const crypto_tls_cached_session *old = &c->entries[i];
      if (old->ticket_size == s->ticket_size && !memcmp(old->ticket,s->ticket,s->ticket_size)) {
        unlock_cache(c); return CRYPTO_TLS_STREAM_EIO;
      }
    }
  }
  /* A peer may repeat an NST. Keep one currently cached copy per host/ticket;
   * a repeated message must not create parallel consumers for that identity. */
  for (size_t i = 0u; i < c->capacity; ++i) {
    crypto_tls_cached_session *old = &c->entries[i];
    if (old->ticket_size == s->ticket_size && !strcmp(old->hostname,s->hostname) &&
        !memcmp(old->ticket,s->ticket,s->ticket_size)) salts_crypto_secure_zero(old,sizeof(*old));
  }
  salts_crypto_secure_zero(&c->entries[c->next],sizeof(*s));
  memcpy(&c->entries[c->next],s,sizeof(*s));
  c->next = (c->next+1u)%c->capacity;
  unlock_cache(c);
  return CRYPTO_TLS_STREAM_OK;
}
int crypto_tls_session_cache_take(crypto_tls_session_cache *c, const char *hostname,
    uint64_t now, crypto_tls_cached_session *out) {
  if (!c || !hostname || !out) return CRYPTO_TLS_STREAM_EINVAL;
  int status = CRYPTO_TLS_STREAM_ENOENT;
  lock_cache(c);
  for (size_t i = 0u; i < c->capacity; ++i)
    if (c->entries[i].ticket_size && now < c->entries[i].received_ms) {
      status = CRYPTO_TLS_STREAM_EIO; goto end;
    }
  for (size_t i = 0u; i < c->capacity; ++i) {
    const size_t slot = (c->next+c->capacity-1u-i)%c->capacity;
    crypto_tls_cached_session *s = &c->entries[slot];
    if (!s->ticket_size) continue;
    if (now-s->received_ms >= (uint64_t)s->lifetime_seconds*1000u) {
      salts_crypto_secure_zero(s,sizeof(*s)); continue;
    }
    if (strcmp(s->hostname,hostname)) continue;
    memcpy(out,s,sizeof(*s));
    salts_crypto_secure_zero(s,sizeof(*s));
    status = CRYPTO_TLS_STREAM_OK; break;
  }
end:
  unlock_cache(c);
  return status;
}
int crypto_tls_session_cache_find(crypto_tls_session_cache *c, const uint8_t *ticket,
    size_t size, uint64_t now, crypto_tls_cached_session *out) {
  if (!c || !ticket || size != 32u || !out) return CRYPTO_TLS_STREAM_EINVAL;
  int status = CRYPTO_TLS_STREAM_ENOENT;
  lock_cache(c);
  for (size_t i = 0u; i < c->capacity; ++i)
    if (c->entries[i].ticket_size && now < c->entries[i].received_ms) {
      status = CRYPTO_TLS_STREAM_EIO; goto end;
    }
  for (size_t i = 0u; i < c->capacity; ++i) {
    crypto_tls_cached_session *s = &c->entries[i];
    if (!s->ticket_size) continue;
    if (now-s->received_ms >= (uint64_t)s->lifetime_seconds*1000u) {
      salts_crypto_secure_zero(s,sizeof(*s)); continue;
    }
    if (!s->server_ticket || s->ticket_size != size || memcmp(s->ticket,ticket,size)) continue;
    memcpy(out,s,sizeof(*s)); status = CRYPTO_TLS_STREAM_OK; break;
  }
end:
  unlock_cache(c);
  return status;
}
