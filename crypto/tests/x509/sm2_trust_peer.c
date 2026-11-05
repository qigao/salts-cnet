/* Binary pipe endpoint for independently generated certificate-path tests. */
#include <crypto/sm2_trust.h>
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
static int span(cursor *c, salts_crypto_sm2_cert_span *out) {
  const uint8_t *p = take(c, 2); if (!p) return 0;
  out->size = (size_t)p[0]*256+p[1]; out->der = take(c, out->size); return out->der != NULL;
}
typedef struct decision { unsigned calls, fail_depth; int result; int64_t now; } decision;
static int check_revocation(void *context, size_t depth, const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t now) {
  decision *d = context;
  if (d->calls++ != depth || !cert->der || !issuer->der || !cert->size || !issuer->size || now != d->now) return -99;
  return depth == d->fail_depth ? d->result : SALTS_CRYPTO_OK;
}
int main(void) {
  uint8_t input[65536], output[68]; salts_crypto_sm2_chain_entry chain[4] = {0};
  salts_crypto_sm2_trust_policy policy = {0}; decision d = {0};
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
  size_t n = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) return 2;
  cursor c = {input,n}; const uint8_t *header = take(&c, 13);
  if (!header || header[8] < 1 || header[8] > 4) return 2;
  uint64_t seconds = 0; for (size_t i=0; i<8; ++i) seconds = seconds*256+header[i];
  policy.validation_time = (int64_t)seconds; d.now = policy.validation_time;
  size_t count = header[8]; policy.purpose = (salts_crypto_sm2_trust_purpose)header[9];
  policy.revocation = (salts_crypto_sm2_revocation_policy)header[10];
  d.fail_depth = header[11]; d.result = (int)(int8_t)header[12];
  if (policy.revocation == SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL) {
    policy.check_revocation = check_revocation; policy.revocation_context = &d;
  }
  policy.expected_leaf_public_key = take(&c,65);
  if (!policy.expected_leaf_public_key || !span(&c, &policy.anchor)) return 2;
  for (size_t i=0; i<count; ++i) {
    salts_crypto_sm2_cert_span id;
    if (!span(&c, &id) || !span(&c, &chain[i].certificate)) return 2;
    chain[i].issuer_identity = id.der; chain[i].issuer_identity_size = id.size;
  }
  if (c.n) return 2;
  memset(output,0xa5,sizeof(output));
  int status = salts_crypto_sm2_validate_pinned_chain(chain, count, &policy, output+2);
  output[0] = (uint8_t)status; output[1] = (uint8_t)d.calls;
  return fwrite(output,1,sizeof(output),stdout) == sizeof(output) && fflush(stdout) == 0 ? 0 : 3;
}
