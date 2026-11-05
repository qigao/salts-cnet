/* Formal independent CRL peer and real pinned-chain callback composition. */
#include <crypto/sm2_crl.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
typedef struct cursor { const uint8_t *p; size_t n; } cursor;
static const uint8_t *take(cursor *c, size_t n) {
  if (n > c->n) return NULL;
  const uint8_t *p = c->p; c->p += n; c->n -= n; return p;
}
static uint64_t number(const uint8_t *p, size_t n) {
  uint64_t result = 0; while (n--) result = result*256+*p++; return result;
}
static int span(cursor *c, salts_crypto_sm2_cert_span *out) {
  const uint8_t *p = take(c,4); if (!p) return 0;
  out->size = (size_t)number(p,4); out->der = take(c,out->size); return out->der != NULL;
}
typedef struct context { salts_crypto_sm2_crl_policy policy; unsigned calls; } context;
static int check_crl(void *ctx, size_t depth, const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t now) {
  context *c = ctx; if (depth != c->calls++) return SALTS_CRYPTO_EVERIFY;
  return salts_crypto_sm2_check_crl(cert, issuer, now, &c->policy);
}
int main(void) {
  static uint8_t input[100000]; uint8_t output[69]; context ctx = {0};
  salts_crypto_sm2_cert_span cert, issuer, id, crl; salts_crypto_sm2_chain_entry entry = {0};
  salts_crypto_sm2_trust_policy trust = {0};
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
  size_t n = fread(input,1,sizeof(input),stdin);
  if (ferror(stdin) || !feof(stdin)) return 2;
  cursor c = {input,n}; const uint8_t *header = take(&c,20), *pin = take(&c,65);
  if (!header || !pin || !span(&c,&cert) || !span(&c,&issuer) || !span(&c,&id) || !span(&c,&crl) || c.n) return 2;
  int64_t now = (int64_t)number(header,8);
  ctx.policy = (salts_crypto_sm2_crl_policy){crl.der,crl.size,id.der,id.size,number(header+8,8),(uint32_t)number(header+16,4)};
  memset(output,0xa5,sizeof(output));
  output[0] = (uint8_t)salts_crypto_sm2_check_crl(&cert,&issuer,now,&ctx.policy);
  entry.certificate = cert; entry.issuer_identity = "1234567812345678"; entry.issuer_identity_size = 16;
  trust.anchor = issuer; trust.expected_leaf_public_key = pin; trust.validation_time = now;
  trust.purpose = SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING; trust.revocation = SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL;
  trust.check_revocation = check_crl; trust.revocation_context = &ctx;
  output[1] = (uint8_t)salts_crypto_sm2_validate_pinned_chain(&entry,1,&trust,output+3);
  output[2] = (uint8_t)ctx.calls;
  return fwrite(output,1,sizeof(output),stdout) == sizeof(output) && fflush(stdout) == 0 ? 0 : 3;
}
