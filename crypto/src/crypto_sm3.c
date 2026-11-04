#include <crypto/sm3.h>
#include "crypto_internal.h"
#include <gmssl/sm3.h>
#include <gmssl/hkdf.h>
#include <string.h>

typedef struct sm3_state {
  uint32_t mode;
  uint64_t total;
  union { SM3_CTX hash; SM3_HMAC_CTX hmac; } native;
} sm3_state;
enum { SM3_HASH_LIVE = 0x534d3301u, SM3_HMAC_LIVE = 0x534d3302u };
_Static_assert(sizeof(sm3_state) <= SALTS_CRYPTO_SM3_CONTEXT_SIZE, "SM3 context capacity");

int salts_crypto_sm3_init(salts_crypto_sm3_ctx_t *ctx) {
  sm3_state state = {0};
  if (!ctx) return SALTS_CRYPTO_EINVAL;
  state.mode = SM3_HASH_LIVE;
  sm3_init(&state.native.hash);
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->bytes, &state, sizeof(state));
  salts_crypto_secure_zero(&state, sizeof(state));
  return SALTS_CRYPTO_OK;
}

int salts_crypto_hmac_sm3_init(salts_crypto_sm3_ctx_t *ctx, const void *key, size_t n) {
  sm3_state state = {0};
  static const uint8_t empty = 0u;
  if (!ctx || (!key && n) || n > UINT64_MAX / 8u) return SALTS_CRYPTO_EINVAL;
  state.mode = SM3_HMAC_LIVE;
  state.total = 64u; /* Inner HMAC starts with one padded key block. */
  sm3_hmac_init(&state.native.hmac, key ? key : &empty, n);
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->bytes, &state, sizeof(state));
  salts_crypto_secure_zero(&state, sizeof(state));
  return SALTS_CRYPTO_OK;
}

int salts_crypto_sm3_update(salts_crypto_sm3_ctx_t *ctx, const void *data, size_t n) {
  sm3_state state;
  if (!ctx || (!data && n)) return SALTS_CRYPTO_EINVAL;
  memcpy(&state, ctx->bytes, sizeof(state));
  if (state.mode != SM3_HASH_LIVE && state.mode != SM3_HMAC_LIVE) {
    salts_crypto_secure_zero(&state, sizeof(state));
    return SALTS_CRYPTO_ESTATE;
  }
  if (state.total > UINT64_MAX / 8u || n > UINT64_MAX / 8u - state.total) {
    salts_crypto_secure_zero(&state, sizeof(state));
    return SALTS_CRYPTO_EINVAL;
  }
  state.total += n;
  if (n) {
    if (state.mode == SM3_HASH_LIVE) sm3_update(&state.native.hash, data, n);
    else sm3_hmac_update(&state.native.hmac, data, n);
  }
  memcpy(ctx->bytes, &state, sizeof(state));
  salts_crypto_secure_zero(&state, sizeof(state));
  return SALTS_CRYPTO_OK;
}

int salts_crypto_sm3_final(salts_crypto_sm3_ctx_t *ctx, uint8_t digest[32]) {
  sm3_state state;
  if (!ctx || !digest || salts_crypto_overlap(ctx, sizeof(*ctx), digest, 32u))
    return SALTS_CRYPTO_EINVAL;
  memcpy(&state, ctx->bytes, sizeof(state));
  if (state.mode != SM3_HASH_LIVE && state.mode != SM3_HMAC_LIVE) {
    salts_crypto_secure_zero(&state, sizeof(state));
    return SALTS_CRYPTO_ESTATE;
  }
  if (state.mode == SM3_HASH_LIVE) sm3_finish(&state.native.hash, digest);
  else sm3_hmac_finish(&state.native.hmac, digest);
  salts_crypto_secure_zero(&state, sizeof(state));
  salts_crypto_sm3_clear(ctx);
  return SALTS_CRYPTO_OK;
}

void salts_crypto_sm3_clear(salts_crypto_sm3_ctx_t *ctx) {
  if (ctx) salts_crypto_secure_zero(ctx, sizeof(*ctx));
}

int salts_crypto_sm3(const void *data, size_t n, uint8_t digest[32]) {
  salts_crypto_sm3_ctx_t ctx;
  if ((!data && n) || !digest) return SALTS_CRYPTO_EINVAL;
  salts_crypto_sm3_init(&ctx);
  int status = salts_crypto_sm3_update(&ctx, data, n);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_final(&ctx, digest);
  salts_crypto_sm3_clear(&ctx);
  return status;
}

int salts_crypto_hmac_sm3(const void *key, size_t kn, const void *data, size_t n, uint8_t mac[32]) {
  salts_crypto_sm3_ctx_t ctx;
  if ((!key && kn) || (!data && n) || !mac) return SALTS_CRYPTO_EINVAL;
  int status = salts_crypto_hmac_sm3_init(&ctx, key, kn);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_update(&ctx, data, n);
  if (status == SALTS_CRYPTO_OK) status = salts_crypto_sm3_final(&ctx, mac);
  salts_crypto_sm3_clear(&ctx);
  return status;
}

int salts_crypto_hkdf_sm3_extract(const void *salt, size_t sn, const void *ikm, size_t in, uint8_t prk[32]) {
  uint8_t zeros[32] = {0};
  if ((!salt && sn) || (!ikm && in) || !prk) return SALTS_CRYPTO_EINVAL;
  return salts_crypto_hmac_sm3(salt ? salt : zeros, salt ? sn : sizeof(zeros), ikm, in, prk);
}

int salts_crypto_hkdf_sm3_expand(const uint8_t prk[32], const void *info, size_t n, void *out, size_t on) {
  if (!prk || (!info && n) || n > UINT64_MAX / 8u - 97u || (!out && on) || on > 255u * 32u ||
      salts_crypto_overlap(out, on, prk, 32u) || salts_crypto_overlap(out, on, info, n))
    return SALTS_CRYPTO_EINVAL;
  if (!on) return SALTS_CRYPTO_OK;
  return sm3_hkdf_expand(prk, info, n, on, out) == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}

int salts_crypto_pbkdf2_sm3(const void *password, size_t pn, const void *salt, size_t sn,
                           uint32_t iterations, void *out, size_t on) {
  static const uint8_t empty = 0u;
  if ((!password && pn) || pn > UINT64_MAX / 8u || !salt || sn < 1u || sn > SM3_PBKDF2_MAX_SALT_SIZE ||
      (!out && on) || iterations < SM3_PBKDF2_MIN_ITER || iterations > SM3_PBKDF2_MAX_ITER ||
      on > (uint64_t)UINT32_MAX * 32u ||
      salts_crypto_overlap(out, on, password, pn) || salts_crypto_overlap(out, on, salt, sn))
    return SALTS_CRYPTO_EINVAL;
  if (!on) return SALTS_CRYPTO_OK;
  return sm3_pbkdf2(password ? password : (const void *)&empty, pn,
      salt ? salt : &empty, sn, iterations, on, out) == 1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}
