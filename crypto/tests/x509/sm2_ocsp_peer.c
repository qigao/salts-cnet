/* Formal direct-issuer OCSP and pinned-trust callback endpoint. */
#include <crypto/sm2_ocsp.h>
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
static uint64_t number(const uint8_t *bytes, unsigned n) {
  uint64_t value = 0u;
  for (unsigned i = 0u; i < n; ++i) value = value*256u+bytes[i];
  return value;
}
static int span(cursor *c, salts_crypto_sm2_cert_span *out) {
  const uint8_t *length = take(c,2u);
  if (!length) return 0;
  out->size = (size_t)number(length,2u); out->der = take(c,out->size);
  return out->der != NULL;
}
typedef struct callback { salts_crypto_sm2_ocsp_policy policy; unsigned calls;
  salts_crypto_sm2_delegated_ocsp_policy *delegate; } callback;
static int check_ocsp(void *user, size_t depth, const salts_crypto_sm2_cert_span *cert,
    const salts_crypto_sm2_cert_span *issuer, int64_t time) {
  callback *c = user;
  if (depth != c->calls++) return SALTS_CRYPTO_EVERIFY;
  return c->delegate ? salts_crypto_sm2_check_delegated_ocsp(cert,issuer,time,c->delegate) :
      salts_crypto_sm2_check_direct_ocsp(cert,issuer,time,&c->policy);
}
int main(void) {
  static uint8_t input[128*1024]; uint8_t output[68];
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY) == -1 || _setmode(_fileno(stdout),_O_BINARY) == -1) return 2;
#endif
  size_t n = fread(input,1u,sizeof(input),stdin);
  if (ferror(stdin) || !feof(stdin)) return 2;
  cursor r = {input,n}; const uint8_t *header = take(&r,25u), *pin = take(&r,65u);
  salts_crypto_sm2_cert_span cert,issuer,signer_id,certificate_id,nonce;
  if (!header || !pin || !span(&r,&cert) || !span(&r,&issuer) || !span(&r,&signer_id) ||
      !span(&r,&certificate_id) || !span(&r,&nonce)) return 2;
  salts_crypto_sm2_cert_span responder = {0}, responder_id = {0};
  if (header[0] >= 3u && (!span(&r,&responder) || !span(&r,&responder_id))) return 2;
  const uint8_t *length = take(&r,4u);
  if (!length) return 2;
  n = (size_t)number(length,4u); const uint8_t *response = take(&r,n);
  if (!response || r.n) return 2;
  int64_t time = (int64_t)number(header+1u,8u);
  callback c = {{response,n,signer_id.der,signer_id.size,(uint32_t)number(header+9u,4u),
      (uint32_t)number(header+13u,4u),(int64_t)number(header+17u,8u),nonce.size ? nonce.der : NULL,nonce.size},0u,NULL};
  salts_crypto_sm2_delegated_ocsp_policy delegate = {c.policy,responder,responder_id.der,responder_id.size};
  if (header[0] >= 3u) c.delegate = &delegate;
  memset(output,0xa5,sizeof(output)); int status;
  if (header[0] == 1u || header[0] == 4u) {
    salts_crypto_sm2_chain_entry entry = {cert,certificate_id.der,certificate_id.size};
    salts_crypto_sm2_trust_policy trust = {issuer,pin,time,SALTS_CRYPTO_SM2_TRUST_SERVER_SIGNING,
        SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL,check_ocsp,&c};
    status = salts_crypto_sm2_validate_pinned_chain(&entry,1u,&trust,output+2u);
  } else {
    if (c.delegate)
      status = header[0] == 5u ? salts_crypto_sm2_validate_delegated_ocsp(&issuer,time,c.delegate) :
          salts_crypto_sm2_check_delegated_ocsp(&cert,&issuer,time,c.delegate);
    else
      status = header[0] == 2u ? salts_crypto_sm2_validate_direct_ocsp(&issuer,time,&c.policy) :
          salts_crypto_sm2_check_direct_ocsp(&cert,&issuer,time,&c.policy);
    memset(output+2u,0,65u);
  }
  output[0] = (uint8_t)status; output[1] = (uint8_t)c.calls;
  return fwrite(output,1u,sizeof(output),stdout) == sizeof(output) && fflush(stdout) == 0 ? 0 : 3;
}
