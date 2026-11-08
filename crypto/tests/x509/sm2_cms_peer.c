/* Formal independent CMS endpoint. Binary framing is test-owned, not an API. */
#include <crypto/sm2_cms.h>
#include <crypto/sm2_cms_envelope.h>
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
  const uint8_t *size = take(c,2u);
  if (!size) return 0;
  out->size = (size_t)size[0]*256u+size[1]; out->der = take(c,out->size);
  return out->der != NULL;
}
static const uint8_t *blob(cursor *c, size_t *n) {
  const uint8_t *bytes = take(c,4u);
  if (!bytes) return NULL;
  *n = 0u;
  for (unsigned i = 0u; i < 4u; ++i) *n = *n*256u+bytes[i];
  return take(c,*n);
}
typedef struct decision { unsigned calls, fail_depth; int64_t time; } decision;
static int check_revocation(void *user, size_t depth, const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t time) {
  decision *d = user;
  if (d->calls++ != depth || time != d->time || !cert->der || !issuer->der) return SALTS_CRYPTO_EVERIFY;
  return depth == d->fail_depth ? SALTS_CRYPTO_EVERIFY : SALTS_CRYPTO_OK;
}
int main(void) {
  static uint8_t input[512*1024], output[SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER+1u];
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY) == -1 || _setmode(_fileno(stdout),_O_BINARY) == -1) return 2;
#endif
  size_t n = fread(input,1u,sizeof(input),stdin);
  if (ferror(stdin) || !feof(stdin)) return 2;
  cursor r = {input,n}; const uint8_t *header = take(&r,15u);
  if (!header || header[6] < 1u || header[6] > 4u) return 2;
  uint64_t seconds = 0u;
  for (unsigned i = 7u; i < 15u; ++i) seconds = seconds*256u+header[i];
  decision d = {0u,header[5],(int64_t)seconds};
  const uint8_t *pin = take(&r,65u), *key = take(&r,32u);
  salts_crypto_sm2_cert_span id, anchor, certs[4];
  salts_crypto_sm2_chain_entry chain[4];
  if (!pin || !key || !span(&r,&id) || !span(&r,&anchor)) return 2;
  for (size_t i = 0u; i < header[6]; ++i) {
    salts_crypto_sm2_cert_span issuer_id;
    if (!span(&r,&issuer_id) || !span(&r,&certs[i])) return 2;
    chain[i] = (salts_crypto_sm2_chain_entry){certs[i],issuer_id.der,issuer_id.size};
  }
  size_t content_size, der_size;
  const uint8_t *content = blob(&r,&content_size), *der = blob(&r,&der_size);
  if (!content || !der || r.n) return 2;
  memset(output,0xa5,sizeof(output)); size_t written = SIZE_MAX;
  int status; size_t bound;
    salts_crypto_sm2_trust_policy trust = {anchor,pin,(int64_t)seconds,
        (salts_crypto_sm2_trust_purpose)header[3],(salts_crypto_sm2_revocation_policy)header[4],NULL,NULL};
    if (header[4] == SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL) {
      trust.check_revocation = check_revocation; trust.revocation_context = &d;
    }
  if (header[0] == 0u) {
    salts_crypto_sm2_cms_sign_config config = {(salts_crypto_sm2_cms_format)header[1],header[2] != 0u,
        key,id.der,id.size,certs,header[6]};
    status = salts_crypto_sm2_cms_sign(&config,content,content_size,output,sizeof(output),&written);
    bound = SALTS_CRYPTO_SM2_CMS_MAX_DER;
  } else if (header[0] == 2u) {
    salts_crypto_sm2_cms_envelope_recipient config = {chain,header[6],&trust};
    status = salts_crypto_sm2_cms_envelope_encrypt(&config,content,content_size,output,sizeof(output),&written);
    bound = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER;
  } else if (header[0] == 3u) {
    salts_crypto_sm2_cms_envelope_key config = {certs[0],key};
    status = salts_crypto_sm2_cms_envelope_decrypt(&config,der,der_size,output,sizeof(output),&written);
    bound = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT;
  } else {
    salts_crypto_sm2_cms_verify_config config = {(salts_crypto_sm2_cms_format)header[1],header[2] != 0u,
        id.der,id.size,chain,header[6],&trust};
    status = salts_crypto_sm2_cms_verify(&config,der,der_size,
        header[2] ? content : NULL,content_size,output,sizeof(output),&written);
    bound = SALTS_CRYPTO_SM2_CMS_MAX_CONTENT;
  }
  unsigned erased = 1u;
  for (size_t i = 0u; i < bound; ++i) if (output[i] != 0u) erased = 0u;
  uint8_t result[9] = {(uint8_t)status,(uint8_t)d.calls,(uint8_t)erased,output[bound],written == 0u};
  size_t output_size = status == SALTS_CRYPTO_OK ? written : 0u;
  if (output_size > bound) return 3;
  for (unsigned i = 0u; i < 4u; ++i) result[5u+i] = (uint8_t)(output_size >> (24u-8u*i));
  if (fwrite(result,1u,sizeof(result),stdout) != sizeof(result) || fwrite(output,1u,output_size,stdout) != output_size || fflush(stdout)) return 3;
  return 0;
}
