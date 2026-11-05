#include <crypto/sm2_exchange.h>
#include "crypto_internal.h"
#include <gmssl/sm2.h>
#include <string.h>

typedef struct sm2_exchange_state {
  uint32_t phase;
  size_t key_size;
  uint8_t combined[32], peer_public[65], own_share[65], za[32], zb[32];
  uint8_t pending[1024], expected_a[32];
} sm2_exchange_state;
enum { SM2_WAIT_B = 0x534d3201u, SM2_WAIT_A = 0x534d3202u };
_Static_assert(sizeof(sm2_exchange_state) <= SALTS_CRYPTO_SM2_EXCHANGE_CONTEXT_SIZE,
    "SM2 exchange context capacity");

void salts_crypto_sm2_exchange_clear(salts_crypto_sm2_exchange_ctx *ctx) {
  if (ctx) salts_crypto_secure_zero(ctx, sizeof(*ctx));
}
typedef struct sm2_range { const void *data; size_t size; } sm2_range;
static int overlaps(const sm2_range *ranges, size_t outputs, size_t count) {
  for (size_t i = 0; i < outputs; ++i)
    for (size_t j = i + 1u; j < count; ++j)
      if (salts_crypto_overlap(ranges[i].data, ranges[i].size, ranges[j].data, ranges[j].size)) return 1;
  return 0;
}
static int sizes_valid(const void *a, size_t an, const void *b, size_t bn, size_t kn) {
  return a && an && an <= 8191u && b && bn && bn <= 8191u && kn && kn <= 1024u;
}
static int scalar_import(sm2_z256_t scalar, const uint8_t raw[32]) {
  sm2_z256_from_bytes(scalar, raw);
  return !sm2_z256_is_zero(scalar) && sm2_z256_cmp(scalar, sm2_z256_order()) < 0;
}
static int point_import(SM2_Z256_POINT *point, const uint8_t raw[65]) {
  /* Canonical field coordinates, curve membership and finite point. The fixed
   * curveSM2 group has cofactor 1, so no additional subgroup test is needed. */
  return raw[0] == 4u && sm2_z256_point_from_bytes(point, raw + 1u) == 1 &&
      !sm2_z256_point_is_at_infinity(point);
}
static void x_bar(sm2_z256_t out, const uint8_t share[65]) {
  uint8_t reduced[32] = {0};
  /* w=127: 2^127 + (x mod 2^127). */
  memcpy(reduced + 16u, share + 17u, 16u); reduced[16] |= 0x80u;
  sm2_z256_from_bytes(out, reduced);
  salts_crypto_secure_zero(reduced, sizeof(reduced));
}
static int prepare(sm2_exchange_state *state, const uint8_t private_key[32], const uint8_t peer[65],
    const void *a, size_t an, const void *b, size_t bn, size_t kn, int initiator) {
  SM2_Z256_POINT own = {0}, other = {0}, share = {0};
  sm2_z256_t d = {0}, r = {0}, x = {0}, t = {0};
  int status = SALTS_CRYPTO_EINVAL;
  if (!scalar_import(d, private_key) || !point_import(&other, peer)) goto done;
  sm2_z256_point_mul_generator(&own, d);
  status = SALTS_CRYPTO_ECRYPTO;
  if (sm2_compute_z(state->za, initiator ? &own : &other, a, an) != 1 ||
      sm2_compute_z(state->zb, initiator ? &other : &own, b, bn) != 1) goto done;
  status = SALTS_CRYPTO_ERANDOM;
  for (unsigned attempt = 0; attempt < 128u; ++attempt) {
    if (sm2_z256_rand_range(r, sm2_z256_order()) != 1) goto done;
    if (sm2_z256_is_zero(r)) continue;
    sm2_z256_point_mul_generator(&share, r);
    if (sm2_z256_point_to_uncompressed_octets(&share, state->own_share) != 1) {
      status = SALTS_CRYPTO_ECRYPTO; goto done;
    }
    x_bar(x, state->own_share);
    sm2_z256_modn_mul(t, x, r); sm2_z256_modn_add(t, t, d);
    if (sm2_z256_is_zero(t)) continue;
    status = SALTS_CRYPTO_OK; break;
  }
  if (status != SALTS_CRYPTO_OK) goto done;
  sm2_z256_to_bytes(t, state->combined);
  memcpy(state->peer_public, peer, 65u); state->key_size = kn;
done:
  salts_crypto_secure_zero(&own, sizeof(own)); salts_crypto_secure_zero(&other, sizeof(other));
  salts_crypto_secure_zero(&share, sizeof(share)); salts_crypto_secure_zero(d, sizeof(d));
  salts_crypto_secure_zero(r, sizeof(r)); salts_crypto_secure_zero(x, sizeof(x)); salts_crypto_secure_zero(t, sizeof(t));
  return status;
}

static int derive(const sm2_exchange_state *state, const uint8_t peer_share[65], int initiator,
    uint8_t secret[1024], uint8_t sa[32], uint8_t sb[32]) {
  SM2_Z256_POINT peer = {0}, share = {0}, sum = {0}, shared = {0};
  sm2_z256_t t = {0}, x = {0};
  uint8_t xy[64], inner[32], prefix;
  SM3_CTX hash;
  SM3_KDF_CTX kdf;
  unsigned bits = 0;
  const uint8_t *ra = initiator ? state->own_share : peer_share;
  const uint8_t *rb = initiator ? peer_share : state->own_share;
  int status = SALTS_CRYPTO_EVERIFY;
  if (!point_import(&share, peer_share) || !point_import(&peer, state->peer_public) ||
      !scalar_import(t, state->combined)) goto done;
  x_bar(x, peer_share);
  sm2_z256_point_mul(&sum, x, &share); sm2_z256_point_add(&sum, &sum, &peer);
  if (sm2_z256_point_is_at_infinity(&sum)) goto done;
  /* U=[h*t](Ppeer+[xbar_peer]Rpeer), h=1 for the only admitted curve. */
  sm2_z256_point_mul(&shared, t, &sum);
  if (sm2_z256_point_is_at_infinity(&shared) || sm2_z256_point_to_bytes(&shared, xy) != 1) goto done;
  sm3_kdf_init(&kdf, state->key_size);
  sm3_kdf_update(&kdf, xy, sizeof(xy));
  sm3_kdf_update(&kdf, state->za, 32u); sm3_kdf_update(&kdf, state->zb, 32u);
  sm3_kdf_finish(&kdf, secret);
  for (size_t i = 0; i < state->key_size; ++i) bits |= secret[i];
  if (!bits) { status = SALTS_CRYPTO_ECRYPTO; goto done; }
  sm3_init(&hash); sm3_update(&hash, xy, 32u);
  sm3_update(&hash, state->za, 32u); sm3_update(&hash, state->zb, 32u);
  sm3_update(&hash, ra + 1u, 64u); sm3_update(&hash, rb + 1u, 64u); sm3_finish(&hash, inner);
  prefix = 2u;
  sm3_init(&hash); sm3_update(&hash, &prefix, 1u);
  sm3_update(&hash, xy + 32u, 32u); sm3_update(&hash, inner, 32u); sm3_finish(&hash, sb);
  prefix = 3u;
  sm3_init(&hash); sm3_update(&hash, &prefix, 1u);
  sm3_update(&hash, xy + 32u, 32u); sm3_update(&hash, inner, 32u); sm3_finish(&hash, sa);
  status = SALTS_CRYPTO_OK;
done:
  salts_crypto_secure_zero(&peer, sizeof(peer)); salts_crypto_secure_zero(&share, sizeof(share));
  salts_crypto_secure_zero(&sum, sizeof(sum)); salts_crypto_secure_zero(&shared, sizeof(shared));
  salts_crypto_secure_zero(t, sizeof(t)); salts_crypto_secure_zero(x, sizeof(x));
  salts_crypto_secure_zero(xy, sizeof(xy)); salts_crypto_secure_zero(inner, sizeof(inner));
  salts_crypto_secure_zero(&hash, sizeof(hash)); salts_crypto_secure_zero(&kdf, sizeof(kdf));
  return status;
}

int salts_crypto_sm2_exchange_start(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t key[32], const uint8_t peer[65], const void *a, size_t an,
    const void *b, size_t bn, size_t kn, uint8_t ra[65]) {
  sm2_exchange_state state = {0};
  const sm2_range ranges[] = {{ctx, sizeof(*ctx)}, {ra, 65u}, {key, 32u}, {peer, 65u}, {a, an}, {b, bn}};
  if (!ctx || !key || !peer || !ra || !sizes_valid(a, an, b, bn, kn) || overlaps(ranges, 2u, 6u))
    return SALTS_CRYPTO_EINVAL;
  salts_crypto_sm2_exchange_clear(ctx);
  int status = prepare(&state, key, peer, a, an, b, bn, kn, 1);
  if (status == SALTS_CRYPTO_OK) {
    state.phase = SM2_WAIT_B; memcpy(ctx->bytes, &state, sizeof(state)); memcpy(ra, state.own_share, 65u);
  } else salts_crypto_secure_zero(ra, 65u);
  salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}
int salts_crypto_sm2_exchange_respond(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t key[32], const uint8_t peer[65], const void *a, size_t an,
    const void *b, size_t bn, size_t kn, const uint8_t ra[65], uint8_t rb[65], uint8_t sb[32]) {
  sm2_exchange_state state = {0}, pending = {0};
  SM2_Z256_POINT point;
  const sm2_range ranges[] = {{ctx, sizeof(*ctx)}, {rb, 65u}, {sb, 32u},
      {key, 32u}, {peer, 65u}, {a, an}, {b, bn}, {ra, 65u}};
  if (!ctx || !key || !peer || !ra || !rb || !sb || !sizes_valid(a, an, b, bn, kn) || overlaps(ranges, 3u, 8u))
    return SALTS_CRYPTO_EINVAL;
  salts_crypto_sm2_exchange_clear(ctx);
  int status = SALTS_CRYPTO_EVERIFY;
  if (!point_import(&point, ra)) goto done;
  status = prepare(&state, key, peer, a, an, b, bn, kn, 0);
  if (status != SALTS_CRYPTO_OK) goto done;
  status = derive(&state, ra, 0, pending.pending, pending.expected_a, sb);
  if (status != SALTS_CRYPTO_OK) goto done;
  pending.phase = SM2_WAIT_A; pending.key_size = kn;
  memcpy(ctx->bytes, &pending, sizeof(pending)); memcpy(rb, state.own_share, 65u);
done:
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(rb, 65u); salts_crypto_secure_zero(sb, 32u); }
  salts_crypto_secure_zero(&point, sizeof(point));
  salts_crypto_secure_zero(&state, sizeof(state)); salts_crypto_secure_zero(&pending, sizeof(pending));
  return status;
}
int salts_crypto_sm2_exchange_finish_initiator(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t rb[65], const uint8_t sb[32], uint8_t sa[32], void *out, size_t cap, size_t *written) {
  sm2_exchange_state state;
  uint8_t secret[1024] = {0}, expected[32] = {0}, confirmation[32] = {0};
  unsigned diff = 0;
  const sm2_range ranges[] = {{ctx, sizeof(*ctx)}, {out, 1024u}, {written, sizeof(*written)},
      {sa, 32u}, {rb, 65u}, {sb, 32u}};
  if (!ctx || !rb || !sb || !sa || !out || cap < 1024u || !written || overlaps(ranges, 4u, 6u))
    return SALTS_CRYPTO_EINVAL;
  *written = 0;
  memcpy(&state, ctx->bytes, sizeof(state)); salts_crypto_sm2_exchange_clear(ctx);
  int status = SALTS_CRYPTO_ESTATE;
  if (state.phase != SM2_WAIT_B || !state.key_size || state.key_size > 1024u) goto done;
  status = derive(&state, rb, 1, secret, confirmation, expected);
  if (status != SALTS_CRYPTO_OK) goto done;
  for (size_t i = 0; i < 32u; ++i) diff |= expected[i] ^ sb[i];
  if (diff) { status = SALTS_CRYPTO_EVERIFY; goto done; }
  memcpy(out, secret, state.key_size); memcpy(sa, confirmation, 32u); *written = state.key_size;
done:
  if (status != SALTS_CRYPTO_OK) { salts_crypto_secure_zero(out, 1024u); salts_crypto_secure_zero(sa, 32u); }
  salts_crypto_secure_zero(secret, sizeof(secret)); salts_crypto_secure_zero(expected, sizeof(expected));
  salts_crypto_secure_zero(confirmation, sizeof(confirmation)); salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}
int salts_crypto_sm2_exchange_finish_responder(salts_crypto_sm2_exchange_ctx *ctx,
    const uint8_t sa[32], void *out, size_t cap, size_t *written) {
  sm2_exchange_state state;
  unsigned diff = 0;
  const sm2_range ranges[] = {{ctx, sizeof(*ctx)}, {out, 1024u}, {written, sizeof(*written)}, {sa, 32u}};
  if (!ctx || !sa || !out || cap < 1024u || !written || overlaps(ranges, 3u, 4u)) return SALTS_CRYPTO_EINVAL;
  *written = 0;
  memcpy(&state, ctx->bytes, sizeof(state)); salts_crypto_sm2_exchange_clear(ctx);
  int status = SALTS_CRYPTO_ESTATE;
  if (state.phase != SM2_WAIT_A || !state.key_size || state.key_size > 1024u) goto done;
  for (size_t i = 0; i < 32u; ++i) diff |= state.expected_a[i] ^ sa[i];
  if (diff) { status = SALTS_CRYPTO_EVERIFY; goto done; }
  memcpy(out, state.pending, state.key_size); *written = state.key_size; status = SALTS_CRYPTO_OK;
done:
  if (status != SALTS_CRYPTO_OK) salts_crypto_secure_zero(out, 1024u);
  salts_crypto_secure_zero(&state, sizeof(state));
  return status;
}
