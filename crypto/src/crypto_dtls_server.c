#include "crypto_dtls_server.h"
#include "crypto_tls_credentials.h"
#include "crypto_internal.h"
#include <crypto/tls_cipher.h>
#include <crypto/tls_signature.h>
#include <crypto/x509_der.h>
#include <gmssl/x509.h>
#include <gmssl/oid.h>
#include <gmssl/ecdsa.h>
#include <gmssl/rsa.h>
#include <gmssl/mem.h>
#include <string.h>

typedef struct cursor { const uint8_t *p; size_t size; } cursor;
static unsigned get16(const uint8_t *p) { return (unsigned)p[0]*256u+p[1]; }
static size_t get24(const uint8_t *p) { return (size_t)p[0]*65536u+(size_t)p[1]*256u+p[2]; }
static void put16(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>8u); p[1]=(uint8_t)n; }
static void put24(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>16u); p[1]=(uint8_t)(n>>8u); p[2]=(uint8_t)n; }
static int take(cursor *c,size_t n,const uint8_t **out) {
  if (n>c->size) return 0; *out=c->p; c->p+=n; c->size-=n; return 1;
}
static int list16(const uint8_t *p,size_t n,unsigned wanted) {
  if (n%2u) return 0;
  for (size_t i=0;i<n;i+=2u) if (get16(p+i)==wanted) return 1;
  return 0;
}
static int fail(crypto_dtls_server *s,int status) {
  s->failure=status; s->phase=CRYPTO_DTLS_SERVER_FAILED;
  crypto_dtls_ephemeral_clear(&s->ephemeral); crypto_dtls_secrets_clear(&s->secrets);
  crypto_dtls_transcript_clear(&s->transcript); crypto_dtls_reassembly_clear(&s->messages);
  crypto_dtls_flight_timer_clear(&s->timer); salts_crypto_secure_zero(s->flight,sizeof(s->flight));
  salts_crypto_secure_zero(s->scratch,sizeof(s->scratch));
  s->flight_count=s->flight_index=s->flight_offset=0u;
  return status; /* A pending native wire borrow remains stable until sent. */
}
static int reject(crypto_dtls_server *s,int status) {
  uint8_t description=s->fatal.description;
  if (!description) description=status==SALTS_CRYPTO_EINVAL ? TLS_alert_decode_error :
    status==SALTS_CRYPTO_ECRYPTO ? TLS_alert_internal_error : TLS_alert_handshake_failure;
  crypto_dtls_fatal_prepare(&s->fatal,&s->secrets.server_write,s->write_epoch,&s->plain_sequence,description);
  return fail(s,status);
}
int crypto_dtls_server_data_failed(crypto_dtls_server *s){
  if(!s || s->in_callback || s->phase!=CRYPTO_DTLS_SERVER_READY)return SALTS_CRYPTO_ESTATE;
  s->fatal.description=TLS_alert_internal_error;return reject(s,SALTS_CRYPTO_EVERIFY);
}
static int sample(crypto_dtls_server *s,uint64_t now) {
  if (now<s->last_now) return fail(s,SALTS_CRYPTO_ESTATE);
  s->last_now=now; return SALTS_CRYPTO_OK;
}
static int policy_valid(const crypto_tls_stream_peer_policy *p) {
  return !p || (p->check && p->retain && p->release &&
    !(p->supported_profiles & ~(CRYPTO_TLS_PEER_POLICY_STANDARD|CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13|CRYPTO_TLS_PEER_POLICY_TLCP11)) &&
    !(p->supported_peer_roles & ~(CRYPTO_TLS_PEER_POLICY_CLIENT|CRYPTO_TLS_PEER_POLICY_SERVER)) &&
    (!p->supported_profiles || (p->supported_profiles & CRYPTO_TLS_PEER_POLICY_STANDARD)) &&
    (!p->supported_peer_roles || (p->supported_peer_roles & CRYPTO_TLS_PEER_POLICY_CLIENT)));
}
int crypto_dtls_server_context_init(crypto_dtls_server_context *c,const crypto_dtls_server_config *cfg) {
  if (!c || !cfg || salts_crypto_overlap(c,sizeof(*c),cfg,sizeof(*cfg)) || !cfg->credentials ||
      salts_crypto_overlap(c,sizeof(*c),cfg->credentials,sizeof(*cfg->credentials)) ||
      (cfg->server_name_size ? !crypto_dtls_dns_name(cfg->server_name,cfg->server_name_size) : cfg->server_name!=NULL) ||
      cfg->alpn_size>sizeof(c->alpn) ||
      (!cfg->alpn && cfg->alpn_size) || salts_crypto_overlap(c,sizeof(*c),cfg->server_name,cfg->server_name_size) ||
      salts_crypto_overlap(c,sizeof(*c),cfg->alpn,cfg->alpn_size) ||
      !cfg->cookie_lifetime_ms || cfg->cookie_lifetime_ms>CRYPTO_DTLS_COOKIE_MAX_AGE_MS ||
      !policy_valid(cfg->peer_policy) ||
      (cfg->peer_policy && salts_crypto_overlap(c,sizeof(*c),cfg->peer_policy,sizeof(*cfg->peer_policy))) ||
      (cfg->require_client_certificate ? !cfg->client_roots : cfg->client_roots || cfg->peer_policy)) return SALTS_CRYPTO_EINVAL;
  if (c->ready || c->in_callback) return SALTS_CRYPTO_ESTATE;
  const crypto_tls_credentials *input=cfg->credentials;
  const crypto_tls_data *spans[]={&input->certificate_chain,&input->private_key,&input->encryption_key,cfg->client_roots};
  for (size_t i=0;i<sizeof(spans)/sizeof(spans[0]);++i)
    if (spans[i] && (salts_crypto_overlap(c,sizeof(*c),spans[i],sizeof(*spans[i])) ||
      salts_crypto_overlap(c,sizeof(*c),spans[i]->data,spans[i]->size))) return SALTS_CRYPTO_EINVAL;
  if (salts_crypto_overlap(c,sizeof(*c),input->private_key_password.data,input->private_key_password.size) ||
      salts_crypto_overlap(c,sizeof(*c),input->encryption_key_password.data,input->encryption_key_password.size)) return SALTS_CRYPTO_EINVAL;
  if (crypto_tls_memory_validate(cfg->client_roots,cfg->credentials,false)!=0) return SALTS_CRYPTO_EINVAL;
  /* All config data is borrowed until return; native import owns independent
   * decoded key material, including when the input is a credential object. */
  memset(c,0,sizeof(*c)); atomic_init(&c->leases,0u);
  int status=SALTS_CRYPTO_ECRYPTO;
  if (tls_ctx_init(&c->identity,TLS_protocol_tls12,0)!=1 ||
      tls_ctx_set_strict_protocol(&c->identity,TLS_protocol_tls12)!=1 ||
      crypto_tls_memory_identity(&c->identity,cfg->credentials)!=0) goto end;
  if (c->identity.x509_keys_cnt!=1u || c->identity.cert_chains_len<3u) goto end;
  c->chain_size=get24(c->identity.cert_chains);
  if (c->chain_size+3u!=c->identity.cert_chains_len) goto end;
  crypto_tls_stream_peer_certificate_chain chain;
  if (crypto_dtls_chain_views(c->identity.cert_chains+3u,c->chain_size,&chain)!=0) goto end;
  X509_KEY *key=&c->identity.x509_keys[0];
  if (key->algor==OID_rsa_encryption) {
    c->cipher=CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256; c->signature=CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256;
  } else if (key->algor==OID_ec_public_key && key->algor_param==OID_secp256r1) {
    c->cipher=CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256; c->signature=CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
  } else goto end;
  for (size_t i=0;i<chain.count;++i) {
    int algorithm;
    if (x509_cert_get_signature_algor(chain.certificates[i].data,chain.certificates[i].size,&algorithm)!=1 ||
        (algorithm!=OID_ecdsa_with_sha256 && algorithm!=OID_rsasign_with_sha256)) goto end;
  }
  if (cfg->require_client_certificate) {
    if (crypto_tls_memory_trust(&c->identity,cfg->client_roots)!=0 ||
        crypto_dtls_chain_views(c->identity.cacerts,c->identity.cacertslen,&chain)!=0) goto end;
  }
  if (cfg->server_name_size) memcpy(c->server_name,cfg->server_name,cfg->server_name_size); c->server_name_size=cfg->server_name_size;
  if (cfg->alpn_size) memcpy(c->alpn,cfg->alpn,cfg->alpn_size); c->alpn_size=cfg->alpn_size;
  c->require_client_certificate=cfg->require_client_certificate;
  c->exporter_enabled=cfg->enable_exporter;
  status=crypto_dtls_cookie_init(&c->cookie,cfg->cookie_lifetime_ms); if (status) goto end;
  c->ready=true;
  if (cfg->peer_policy) { c->policy=*cfg->peer_policy; c->in_callback=true; c->policy.retain(c->policy.context);
    c->in_callback=false; c->policy_retained=true; }
  return SALTS_CRYPTO_OK;
end:
  tls_ctx_cleanup(&c->identity); crypto_dtls_cookie_clear(&c->cookie); salts_crypto_secure_zero(c,sizeof(*c));
  return status;
}
int crypto_dtls_server_context_clear(crypto_dtls_server_context *c) {
  if (!c) return SALTS_CRYPTO_EINVAL;
  if (c->in_callback) return SALTS_CRYPTO_ESTATE;
  if (!c->ready) return SALTS_CRYPTO_OK;
  if (atomic_load_explicit(&c->leases,memory_order_acquire)) return CRYPTO_DTLS_SERVER_BUSY;
  const crypto_tls_stream_peer_policy policy=c->policy; const bool retained=c->policy_retained;
  tls_ctx_cleanup(&c->identity); crypto_dtls_cookie_clear(&c->cookie); salts_crypto_secure_zero(c,sizeof(*c));
  if (retained) policy.release(policy.context);
  return SALTS_CRYPTO_OK;
}
static int lease(crypto_dtls_server_context *c) {
  size_t n=atomic_load_explicit(&c->leases,memory_order_relaxed);
  do { if (n==SIZE_MAX) return SALTS_CRYPTO_ESTATE; }
  while (!atomic_compare_exchange_weak_explicit(&c->leases,&n,n+1u,memory_order_relaxed,memory_order_relaxed));
  return SALTS_CRYPTO_OK;
}
static int same_dns(const uint8_t *p,const char *name,size_t n) {
  for (size_t i=0;i<n;++i) {
    unsigned a=p[i],b=(unsigned char)name[i];
    if (a>='A' && a<='Z') a+='a'-'A'; if (b>='A' && b<='Z') b+='a'-'A'; if (a!=b) return 0;
  }
  return 1;
}
static int client_hello(crypto_dtls_server *s,const crypto_dtls_cookie_result *hello) {
  crypto_dtls_server_context *ctx=s->context; cursor c={hello->client_hello,hello->client_hello_size}; const uint8_t *p;
  if (!take(&c,35u,&p) || p[34]>32u) return SALTS_CRYPTO_EVERIFY;
  memcpy(s->client_random,p+2u,32u); const size_t sid=p[34];
  if (!take(&c,sid,&p) || !take(&c,1u,&p)) return SALTS_CRYPTO_EVERIFY;
  const size_t cookie=p[0]; if (!take(&c,cookie,&p) || !take(&c,2u,&p)) return SALTS_CRYPTO_EVERIFY;
  const size_t suites=get16(p); if (!take(&c,suites,&p) || !list16(p,suites,ctx->cipher) || !take(&c,1u,&p)) return SALTS_CRYPTO_EVERIFY;
  const size_t compressions=p[0]; if (!take(&c,compressions,&p) || !take(&c,2u,&p) || get16(p)!=c.size) return SALTS_CRYPTO_EVERIFY;
  bool ems=false,group=false,signature=false,alpn=!ctx->alpn_size;
  const uint8_t *cert_schemes=NULL; size_t cert_schemes_size=0u;
  const uint8_t *schemes=NULL; size_t schemes_size=0u;
  while (c.size) {
    if (!take(&c,4u,&p)) return SALTS_CRYPTO_EVERIFY;
    const unsigned type=get16(p); const size_t n=get16(p+2u);
    if (!take(&c,n,&p)) return SALTS_CRYPTO_EVERIFY;
    switch (type) {
      case 0:
        if (n<5u || get16(p)!=n-2u || p[2] || get16(p+3u)!=n-5u || !crypto_dtls_dns_name((const char *)p+5u,n-5u))
          return SALTS_CRYPTO_EVERIFY;
        if (ctx->server_name_size && (n-5u!=ctx->server_name_size || !same_dns(p+5u,ctx->server_name,ctx->server_name_size)))
          return SALTS_CRYPTO_EVERIFY;
        s->offered_sni=true; break;
      case 10:
        if (n<4u || get16(p)!=n-2u || (n-2u)%2u) return SALTS_CRYPTO_EVERIFY;
        group=list16(p+2u,n-2u,23u); break;
      case 11: {
        if (n<2u || p[0]!=n-1u) return SALTS_CRYPTO_EVERIFY;
        bool uncompressed=false; for (size_t i=1u;i<n;++i) uncompressed|=p[i]==0u;
        if (!uncompressed) return SALTS_CRYPTO_EVERIFY; s->offered_points=true; break;
      }
      case 13:
        if (n<4u || get16(p)!=n-2u || (n-2u)%2u) return SALTS_CRYPTO_EVERIFY;
        schemes=p+2u; schemes_size=n-2u; signature=list16(schemes,schemes_size,ctx->signature); break;
      case 50:
        if (n<4u || get16(p)!=n-2u || (n-2u)%2u) return SALTS_CRYPTO_EVERIFY;
        cert_schemes=p+2u; cert_schemes_size=n-2u; break;
      case 16: {
        if (n<3u || get16(p)!=n-2u) return SALTS_CRYPTO_EVERIFY;
        size_t at=2u;
        while (at<n) { size_t len=p[at++]; if (!len || len>n-at) return SALTS_CRYPTO_EVERIFY;
          if (len==ctx->alpn_size && !memcmp(p+at,ctx->alpn,len)) alpn=true; at+=len; }
        break;
      }
      case 23: if (n) return SALTS_CRYPTO_EVERIFY; ems=true; break;
      case 0xff01: if (n!=1u || p[0]) return SALTS_CRYPTO_EVERIFY; s->offered_renegotiation=true; break;
      default: break; /* TLS requires ignoring well-formed unrecognized CH extensions. */
    }
  }
  if (!ems || !group || !signature || !alpn || (ctx->server_name_size && !s->offered_sni)) return SALTS_CRYPTO_EVERIFY;
  if (!cert_schemes) { cert_schemes=schemes; cert_schemes_size=schemes_size; }
  crypto_tls_stream_peer_certificate_chain chain;
  if (crypto_dtls_chain_views(ctx->identity.cert_chains+3u,ctx->chain_size,&chain)!=0) return SALTS_CRYPTO_EVERIFY;
  for (size_t i=0;i<chain.count;++i) {
    int algorithm; if (x509_cert_get_signature_algor(chain.certificates[i].data,chain.certificates[i].size,&algorithm)!=1 ||
      !list16(cert_schemes,cert_schemes_size,algorithm==OID_ecdsa_with_sha256 ? TLS_sig_ecdsa_secp256r1_sha256 : TLS_sig_rsa_pkcs1_sha256))
      return SALTS_CRYPTO_EVERIFY;
  }
  return SALTS_CRYPTO_OK;
}
static int append(crypto_dtls_server *s,crypto_dtls_sender sender,uint8_t type,uint16_t sequence,const uint8_t *body,size_t size) {
  const crypto_dtls_message m={body,size,sequence,type}; return crypto_dtls_transcript_append(&s->transcript,sender,&m);
}
static int handshake(crypto_dtls_server *s,size_t at,uint8_t type,uint16_t sequence,size_t size) {
  crypto_dtls_server_message *m=&s->flight[at];
  if (size>sizeof(m->body)) return SALTS_CRYPTO_EINVAL;
  m->type=22u; m->handshake_type=type; m->sequence=sequence; m->size=size;
  return append(s,CRYPTO_DTLS_SERVER,type,sequence,m->body,size);
}
static int initial_flight(crypto_dtls_server *s) {
  crypto_dtls_server_context *ctx=s->context; uint8_t *body=s->flight[0].body,*p=body;
  *p++=0xfe; *p++=0xfd; memcpy(p,s->server_random,32u); p+=32u; *p++=0; put16(p,ctx->cipher); p+=2u; *p++=0;
  uint8_t *length=p; p+=2u;
  const uint8_t ems[]={0,23,0,0},sni[]={0,0,0,0},points[]={0,11,0,2,1,0},reneg[]={0xff,1,0,1,0};
  memcpy(p,ems,sizeof(ems)); p+=sizeof(ems);
  /* RFC6066 requires the acknowledgment when SNI guides security policy. */
  if (ctx->server_name_size) { memcpy(p,sni,sizeof(sni)); p+=sizeof(sni); }
  if (s->offered_points) { memcpy(p,points,sizeof(points)); p+=sizeof(points); }
  if (s->offered_renegotiation) { memcpy(p,reneg,sizeof(reneg)); p+=sizeof(reneg); }
  if (ctx->alpn_size) { put16(p,16u); put16(p+2u,ctx->alpn_size+3u); put16(p+4u,ctx->alpn_size+1u);
    p[6]=(uint8_t)ctx->alpn_size; memcpy(p+7u,ctx->alpn,ctx->alpn_size); p+=7u+ctx->alpn_size; }
  put16(length,(size_t)(p-length-2u)); int status=handshake(s,0u,2u,1u,(size_t)(p-body)); if (status) return status;
  crypto_tls_stream_peer_certificate_chain chain;
  status=crypto_dtls_chain_views(ctx->identity.cert_chains+3u,ctx->chain_size,&chain); if (status) return status;
  body=s->flight[1].body; p=body+3u;
  for (size_t i=0;i<chain.count;++i) { put24(p,chain.certificates[i].size); p+=3u;
    memcpy(p,chain.certificates[i].data,chain.certificates[i].size); p+=chain.certificates[i].size; }
  put24(body,(size_t)(p-body-3u)); status=handshake(s,1u,11u,2u,(size_t)(p-body)); if (status) return status;
  status=crypto_dtls_ephemeral_init(&s->ephemeral); if (status) return status;
  body=s->flight[2].body; body[0]=3u; body[1]=0u; body[2]=23u; body[3]=65u;
  status=crypto_dtls_ephemeral_public(&s->ephemeral,body+4u); if (status) return status;
  X509_SIGN_CTX sign={0}; size_t signature_size=0u;
  const bool signed_ok=x509_sign_init(&sign,&ctx->identity.x509_keys[0],NULL,0u)==1 &&
    x509_sign_update(&sign,s->client_random,32u)==1 && x509_sign_update(&sign,s->server_random,32u)==1 &&
    x509_sign_update(&sign,body,69u)==1 && x509_sign_finish(&sign,body+73u,&signature_size)==1;
  x509_sign_ctx_cleanup(&sign);
  if (!signed_ok || !signature_size || signature_size>CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE) return SALTS_CRYPTO_ECRYPTO;
  put16(body+69u,ctx->signature); put16(body+71u,signature_size);
  status=handshake(s,2u,12u,3u,73u+signature_size); if (status) return status;
  size_t done=3u;
  if (ctx->require_client_certificate) {
    const uint8_t request[]={2,1,64,0,4,4,3,4,1,0,0};
    memcpy(s->flight[3].body,request,sizeof(request)); status=handshake(s,3u,13u,4u,sizeof(request)); if (status) return status; ++done;
  }
  status=handshake(s,done,14u,(uint16_t)(done+1u),0u); if (status) return status;
  s->server_finished_sequence=(uint16_t)(done+2u); s->flight_count=done+1u;
  return crypto_dtls_flight_timer_init(&s->timer,1000u,60000u,6u);
}
int crypto_dtls_server_accept(crypto_dtls_server *s,crypto_dtls_server_context *c,
    const void *address,size_t address_size,const void *wire,size_t size,uint64_t now,
    int (*on_data)(void *,const uint8_t *,size_t),void *data_context) {
  if (!s || !c || !wire || !on_data || salts_crypto_overlap(s,sizeof(*s),c,sizeof(*c)) ||
      salts_crypto_overlap(s,sizeof(*s),wire,size) || salts_crypto_overlap(s,sizeof(*s),address,address_size)) return SALTS_CRYPTO_EINVAL;
  if (s->phase!=CRYPTO_DTLS_SERVER_ZERO || s->context || !c->ready || c->in_callback) return SALTS_CRYPTO_ESTATE;
  uint8_t reply[CRYPTO_DTLS_COOKIE_REPLY_BYTES]; size_t reply_size; crypto_dtls_cookie_result hello;
  int status=crypto_dtls_cookie_gate(&c->cookie,address,address_size,wire,size,now,reply,sizeof(reply),&reply_size,&hello);
  if (status) return status;
  if (!hello.address_verified) return CRYPTO_DTLS_SERVER_DROP;
  if (!hello.message_sequence || hello.message_sequence>UINT16_MAX-4u || hello.record_sequence==CRYPTO_DTLS_MAX_SEQUENCE) return SALTS_CRYPTO_EVERIFY;
  status=lease(c); if (status) return status;
  memset(s,0,sizeof(*s)); s->context=c; s->on_data=on_data; s->data_context=data_context; s->last_now=now; s->verify_index=SIZE_MAX;
  s->client_first=hello.message_sequence; s->client_finished_sequence=(uint16_t)(s->client_first+(c->require_client_certificate ? 4u : 2u));
  s->plain_sequence=hello.record_sequence+1u;
  status=client_hello(s,&hello); if (status) return reject(s,status);
  status=crypto_dtls_transcript_init(&s->transcript,s->client_first,1u); if (status) return fail(s,status);
  status=append(s,CRYPTO_DTLS_CLIENT,1u,s->client_first,hello.client_hello,hello.client_hello_size); if (status) return fail(s,status);
  SHA256_CTX hash; sha256_init(&hash); sha256_update(&hash,(const uint8_t *)wire+13u,size-13u); sha256_finish(&hash,s->hello_hash);
  salts_crypto_secure_zero(&hash,sizeof(hash));
  status=crypto_dtls_reassembly_init(&s->messages,(uint16_t)(s->client_first+1u),CRYPTO_DTLS_HANDSHAKE_MAX_BODY);
  if (!status && salts_crypto_random_bytes(s->server_random,32u)!=0) status=SALTS_CRYPTO_ERANDOM;
  if (!status) status=initial_flight(s);
  if (status) return fail(s,status);
  s->phase=c->require_client_certificate ? CRYPTO_DTLS_SERVER_CERTIFICATE : CRYPTO_DTLS_SERVER_KEY;
  return SALTS_CRYPTO_OK;
}
static int verify_client_chain(crypto_dtls_server *s) {
  static const int groups[]={TLS_curve_secp256r1};
  static const int schemes[]={TLS_sig_ecdsa_secp256r1_sha256,TLS_sig_rsa_pkcs1_sha256};
  TLS_CTX *ctx=&s->context->identity;
  int result=tls_cert_chain_verify_ex(TLS_protocol_tls12,X509_cert_chain_client,s->context->cipher,1,
    s->chain,s->chain_size,ctx->cacerts,ctx->cacertslen,NULL,0u,NULL,0u,4,groups,1u,schemes,2u,schemes,2u,
    NULL,0u,NULL,0u,NULL,0u,&s->verify_result,NULL,&s->verify_index,NULL);
  return result==1 && s->verify_result==X509_verify_ok ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}
static int client_certificate(crypto_dtls_server *s,const crypto_dtls_message *m) {
  cursor c={m->body,m->size}; const uint8_t *p;
  if (!take(&c,3u,&p) || !c.size || get24(p)!=c.size) return SALTS_CRYPTO_EVERIFY;
  s->chain_size=0u; size_t count=0u;
  while (c.size) {
    if (!take(&c,3u,&p)) return SALTS_CRYPTO_EVERIFY;
    const size_t n=get24(p);
    if (!n || n>sizeof(s->chain)-s->chain_size || !take(&c,n,&p) || ++count>CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES) return SALTS_CRYPTO_EVERIFY;
    crypto_x509_der_view view; if (crypto_x509_der_inspect(p,n,&view)!=SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
    memcpy(s->chain+s->chain_size,p,n); s->chain_size+=n;
  }
  int status=verify_client_chain(s); if (status) s->fatal.description=TLS_alert_certificate_unknown; return status;
}
static int client_key(crypto_dtls_server *s,const crypto_dtls_message *m) {
  if (m->size!=66u || m->body[0]!=65u) return SALTS_CRYPTO_EVERIFY;
  uint8_t shared[32],hash[32];
  int status=append(s,CRYPTO_DTLS_CLIENT,m->type,m->sequence,m->body,m->size);
  if (!status) status=crypto_dtls_transcript_hash(&s->transcript,hash);
  if (!status) status=crypto_dtls_ephemeral_exchange(&s->ephemeral,m->body+1u,65u,shared);
  if (!status) status=crypto_dtls_secrets_derive(&s->secrets,shared,hash,s->client_random,s->server_random);
  salts_crypto_secure_zero(shared,sizeof(shared)); salts_crypto_secure_zero(hash,sizeof(hash)); return status;
}
static int certificate_verify(crypto_dtls_server *s,const crypto_dtls_message *m) {
  if (m->size<4u || get16(m->body+2u)!=m->size-4u || m->size-4u>CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE) return SALTS_CRYPTO_EVERIFY;
  const uint8_t *p=s->chain,*leaf; size_t remaining=s->chain_size,n; X509_KEY key={0}; uint8_t hash[32];
  int status=SALTS_CRYPTO_EVERIFY;
  if (x509_cert_from_der(&leaf,&n,&p,&remaining)!=1 || x509_cert_get_subject_public_key(leaf,n,&key)!=1 ||
      crypto_dtls_transcript_hash(&s->transcript,hash)!=0) goto end;
  const unsigned scheme=get16(m->body);
  if (scheme==TLS_sig_ecdsa_secp256r1_sha256 && key.algor==OID_ec_public_key && key.algor_param==OID_secp256r1 &&
      ecdsa_verify(&key.u.secp256r1_key,hash,m->body+4u,m->size-4u)==1) status=SALTS_CRYPTO_OK;
  else if (scheme==TLS_sig_rsa_pkcs1_sha256 && key.algor==OID_rsa_encryption &&
      rsa_verify_pkcs1_v15_sha256(&key.u.rsa_public_key,hash,m->body+4u,m->size-4u)==1) status=SALTS_CRYPTO_OK;
end:
  x509_key_cleanup(&key); salts_crypto_secure_zero(hash,sizeof(hash)); return status;
}
static void final_flight(crypto_dtls_server *s,bool repeat) {
  salts_crypto_secure_zero(s->flight,sizeof(s->flight));
  s->flight_count=2u; s->flight_index=s->flight_offset=0u;
  s->flight_kind=repeat ? CRYPTO_DTLS_SERVER_REPEAT_FLIGHT : CRYPTO_DTLS_SERVER_FINAL_FLIGHT;
  s->flight[0].type=20u; s->flight[0].body[0]=1u; s->flight[0].size=1u;
  s->flight[1].type=22u; s->flight[1].handshake_type=20u; s->flight[1].sequence=s->server_finished_sequence;
  s->flight[1].size=12u; s->flight[1].encrypted=true; memcpy(s->flight[1].body,s->server_finished,12u);
}
static int finish(crypto_dtls_server *s) {
  if (!s->verified_finished || !s->saw_ccs) return SALTS_CRYPTO_OK;
  if (s->context->require_client_certificate) {
    int status=verify_client_chain(s); if (status) return status;
    if (s->context->policy_retained) {
      crypto_tls_stream_peer_certificate_chain chain;
      status=crypto_dtls_chain_views(s->chain,s->chain_size,&chain); if (status) return status;
      s->in_callback=true;
      status=s->context->policy.check(s->context->policy.context,&chain,false,CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD);
      s->in_callback=false; if (status) { s->fatal.description=TLS_alert_access_denied; return SALTS_CRYPTO_EVERIFY; }
    }
  }
  uint8_t hash[32]; int status=crypto_dtls_transcript_hash(&s->transcript,hash);
  if (!status) status=crypto_dtls_finished(&s->secrets,CRYPTO_DTLS_SERVER,hash,s->server_finished);
  salts_crypto_secure_zero(hash,sizeof(hash)); if (status) return status;
  status=append(s,CRYPTO_DTLS_SERVER,20u,s->server_finished_sequence,s->server_finished,12u); if (status) return status;
  crypto_dtls_transcript_clear(&s->transcript);
  if (!s->context->exporter_enabled) crypto_dtls_secrets_forget_master(&s->secrets);
  crypto_dtls_flight_timer_clear(&s->timer); crypto_dtls_reassembly_clear(&s->messages);
  status=crypto_dtls_reassembly_init(&s->messages,s->client_finished_sequence,12u); if (status) return status;
  final_flight(s,false); s->phase=CRYPTO_DTLS_SERVER_SEND_FINAL; return SALTS_CRYPTO_OK;
}
static int completed(crypto_dtls_server *s) {
  for (;;) {
    crypto_dtls_message m; int status=crypto_dtls_reassembly_peek(&s->messages,&m);
    if (status==CRYPTO_DTLS_HANDSHAKE_NEED) return SALTS_CRYPTO_OK;
    if (status) return status;
    bool appended=false;
    switch (s->phase) {
      case CRYPTO_DTLS_SERVER_CERTIFICATE:
        if (m.type!=11u) return SALTS_CRYPTO_EVERIFY;
        status=client_certificate(s,&m); s->phase=CRYPTO_DTLS_SERVER_KEY; break;
      case CRYPTO_DTLS_SERVER_KEY:
        if (m.type!=16u) return SALTS_CRYPTO_EVERIFY;
        status=client_key(s,&m); appended=true;
        s->phase=s->context->require_client_certificate ? CRYPTO_DTLS_SERVER_VERIFY : CRYPTO_DTLS_SERVER_FINISHED; break;
      case CRYPTO_DTLS_SERVER_VERIFY:
        if (m.type!=15u) return SALTS_CRYPTO_EVERIFY;
        status=certificate_verify(s,&m); if (status) s->fatal.description=TLS_alert_decrypt_error;
        s->phase=CRYPTO_DTLS_SERVER_FINISHED; break;
      case CRYPTO_DTLS_SERVER_FINISHED: {
        if (m.type!=20u || m.size!=12u || s->verified_finished) return SALTS_CRYPTO_EVERIFY;
        uint8_t hash[32]; status=crypto_dtls_transcript_hash(&s->transcript,hash);
        if (!status) status=crypto_dtls_finished_check(&s->secrets,CRYPTO_DTLS_CLIENT,hash,m.body,m.size);
        if (status) s->fatal.description=TLS_alert_decrypt_error;
        salts_crypto_secure_zero(hash,sizeof(hash));
        if (!status) { s->verified_finished=true; memcpy(s->client_finished,m.body,12u); }
        break;
      }
      default: return SALTS_CRYPTO_ESTATE;
    }
    if (status) return status;
    if (!appended) { status=append(s,CRYPTO_DTLS_CLIENT,m.type,m.sequence,m.body,m.size); if (status) return status; }
    status=crypto_dtls_reassembly_consume(&s->messages); if (status) return status;
    if (s->verified_finished) return finish(s);
  }
}
static int fragments(crypto_dtls_server *s,const uint8_t *data,size_t size,bool encrypted) {
  size_t at=0;
  while (at<size) {
    crypto_dtls_fragment f; int status=crypto_dtls_fragment_parse(data+at,size-at,&f); if (status) return status;
    if (encrypted) {
      if (f.type!=20u || f.sequence!=s->client_finished_sequence) return SALTS_CRYPTO_EVERIFY;
      if (s->phase!=CRYPTO_DTLS_SERVER_VERIFY && s->phase!=CRYPTO_DTLS_SERVER_FINISHED &&
          s->phase!=CRYPTO_DTLS_SERVER_READY) return SALTS_CRYPTO_EVERIFY;
    } else {
      if (s->phase>=CRYPTO_DTLS_SERVER_SEND_FINAL || f.type==20u) return CRYPTO_DTLS_SERVER_DROP;
      if (f.type==1u && f.sequence==s->client_first && !f.offset && f.size==f.total) {
        uint8_t digest[32]; SHA256_CTX hash; sha256_init(&hash); sha256_update(&hash,data+at,f.wire_size); sha256_finish(&hash,digest);
        const bool equal=gmssl_secure_memcmp(digest,s->hello_hash,32u)==0; salts_crypto_secure_zero(digest,sizeof(digest));
        salts_crypto_secure_zero(&hash,sizeof(hash));
        if (!equal) return CRYPTO_DTLS_SERVER_DROP;
        bool due=false; status=crypto_dtls_flight_timer_repeat(&s->timer,s->last_now,&due);
        if (status) return SALTS_CRYPTO_ESTATE;
        if (due) s->flight_index=s->flight_offset=0u; return SALTS_CRYPTO_OK;
      }
      if (f.sequence<=s->client_first || f.sequence>=s->client_finished_sequence) return CRYPTO_DTLS_SERVER_DROP;
      if (f.type!=11u && f.type!=16u && f.type!=15u) return SALTS_CRYPTO_EVERIFY;
    }
    size_t consumed=0u; status=crypto_dtls_reassembly_feed(&s->messages,data+at,size-at,&consumed);
    if (status!=0 && status!=CRYPTO_DTLS_HANDSHAKE_NEED && status!=CRYPTO_DTLS_HANDSHAKE_OLD) return status;
    if (!consumed || consumed>size-at) return SALTS_CRYPTO_ESTATE; at+=consumed;
    if (s->phase==CRYPTO_DTLS_SERVER_READY) {
      crypto_dtls_message m; status=crypto_dtls_reassembly_peek(&s->messages,&m);
      if (status==CRYPTO_DTLS_HANDSHAKE_NEED) continue;
      if (status || m.size!=12u || gmssl_secure_memcmp(m.body,s->client_finished,12u)) {
        s->fatal.description=TLS_alert_decrypt_error; return SALTS_CRYPTO_EVERIFY;
      }
      crypto_dtls_reassembly_clear(&s->messages);
      status=crypto_dtls_reassembly_init(&s->messages,s->client_finished_sequence,12u); if (status) return status;
      final_flight(s,true); return SALTS_CRYPTO_OK;
    }
    status=completed(s); if (status) return status;
    if (s->phase==CRYPTO_DTLS_SERVER_SEND_FINAL) return SALTS_CRYPTO_OK;
  }
  return SALTS_CRYPTO_OK;
}
static int alert(crypto_dtls_server *s) {
  crypto_dtls_secrets_forget_master(&s->secrets);
  salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=1u; s->flight_index=s->flight_offset=0u;
  s->flight[0].type=21u; s->flight[0].size=2u; s->flight[0].body[0]=1u; s->flight[0].body[1]=0u; s->flight[0].encrypted=true;
  s->phase=CRYPTO_DTLS_SERVER_CLOSING; s->flight_kind=CRYPTO_DTLS_SERVER_CLOSE; return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_receive(crypto_dtls_server *s,uint64_t now,const void *wire,size_t size) {
  if (!s || !wire || salts_crypto_overlap(s,sizeof(*s),wire,size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase==CRYPTO_DTLS_SERVER_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase==CRYPTO_DTLS_SERVER_FAILED) return s->failure;
  if (s->phase==CRYPTO_DTLS_SERVER_CLOSED) return CRYPTO_DTLS_SERVER_DROP;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_SERVER_BUSY;
  int status=sample(s,now); if (status) return status;
  if (!size || size>CRYPTO_DTLS_MAX_PLAINTEXT+CRYPTO_DTLS_RECORD_OVERHEAD) return CRYPTO_DTLS_SERVER_DROP;
  const uint8_t *data=wire;
  for (size_t at=0;at<size;) { crypto_dtls_record_view v;
    if (!crypto_dtls_wire_record(data+at,size-at,&v)) return CRYPTO_DTLS_SERVER_DROP; at+=v.record_size; }
  for (size_t at=0;at<size;) {
    crypto_dtls_record_view v; if (!crypto_dtls_wire_record(data+at,size-at,&v)) return fail(s,SALTS_CRYPTO_ESTATE);
    const uint8_t *record=data+at; at+=v.record_size;
    if (!v.epoch) {
      /* A verified client Finished ends plaintext admission, including while
       * our final flight is pending. Authenticated retransmissions use epoch 1. */
      if (s->phase>=CRYPTO_DTLS_SERVER_SEND_FINAL) continue;
      if (record[2]!=0xfd) continue;
      if (v.type==22u) status=fragments(s,v.payload,v.payload_size,false);
      else if (v.type==20u && s->phase<CRYPTO_DTLS_SERVER_SEND_FINAL) {
        if (v.payload_size!=1u || v.payload[0]!=1u) { s->fatal.description=TLS_alert_decode_error; return reject(s,SALTS_CRYPTO_EVERIFY); }
        s->saw_ccs=s->read_epoch=true; status=finish(s);
      } else if (v.type==21u && !s->read_epoch) {
        if (v.payload_size!=2u || (v.payload[0]!=1u && v.payload[0]!=2u)) {
          s->fatal.description=TLS_alert_decode_error; return reject(s,SALTS_CRYPTO_EVERIFY);
        }
        s->fatal.peer_description=v.payload[1]; return fail(s,SALTS_CRYPTO_EVERIFY);
      }
      else status=CRYPTO_DTLS_SERVER_DROP;
    } else {
      if (v.epoch!=1u || !s->secrets.ready) continue;
      size_t plain_size=0; uint8_t type=0;
      status=crypto_dtls_record_open(&s->secrets.client_write,record,v.record_size,s->scratch,sizeof(s->scratch),&plain_size,&type);
      if (status==SALTS_CRYPTO_EVERIFY || status==CRYPTO_DTLS_RECORD_DROP) continue;
      if (status) return fail(s,status);
      s->read_epoch=true;
      if (type==22u) status=fragments(s,s->scratch,plain_size,true);
      else if (type==23u && s->phase==CRYPTO_DTLS_SERVER_READY) {
        s->in_callback=true; status=s->on_data(s->data_context,s->scratch,plain_size); s->in_callback=false;
        if (status) { s->fatal.description=TLS_alert_internal_error; status=SALTS_CRYPTO_EVERIFY; }
      } else if (type==21u) {
        if (plain_size!=2u || (s->scratch[0]!=1u && s->scratch[0]!=2u)) {
          s->fatal.description=TLS_alert_decode_error; status=SALTS_CRYPTO_EVERIFY;
        } else if (s->scratch[0]==2u || s->scratch[1]!=0u) {
          s->fatal.peer_description=s->scratch[1]; return fail(s,SALTS_CRYPTO_EVERIFY);
        }
        else if (s->phase==CRYPTO_DTLS_SERVER_READY) status=alert(s);
        else if (s->phase==CRYPTO_DTLS_SERVER_CLOSING) status=SALTS_CRYPTO_OK;
        else status=SALTS_CRYPTO_EVERIFY;
      } else status=CRYPTO_DTLS_SERVER_DROP;
      salts_crypto_secure_zero(s->scratch,sizeof(s->scratch));
    }
    if (status<0) return reject(s,status);
    if (s->flight_index<s->flight_count) break;
  }
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_next(crypto_dtls_server *s,uint64_t now,const uint8_t **wire,size_t *size) {
  if (!s || !wire || !size || salts_crypto_overlap(s,sizeof(*s),wire,sizeof(*wire)) ||
      salts_crypto_overlap(s,sizeof(*s),size,sizeof(*size)) || salts_crypto_overlap(wire,sizeof(*wire),size,sizeof(*size))) return SALTS_CRYPTO_EINVAL;
  *wire=NULL; *size=0u;
  if (s->in_callback || s->phase==CRYPTO_DTLS_SERVER_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase==CRYPTO_DTLS_SERVER_FAILED) {
    if (s->pending) return CRYPTO_DTLS_SERVER_BUSY;
    if (!s->fatal.size) return s->failure;
    memcpy(s->pending_wire,s->fatal.wire,s->fatal.size); s->pending_size=s->fatal.size;
    salts_crypto_secure_zero(s->fatal.wire,sizeof(s->fatal.wire)); s->fatal.size=0u;
    s->pending=true; *wire=s->pending_wire; *size=s->pending_size; return SALTS_CRYPTO_OK;
  }
  if (s->phase==CRYPTO_DTLS_SERVER_CLOSED) return CRYPTO_DTLS_SERVER_IDLE;
  int status=sample(s,now); if (status) return status;
  if (s->pending) return CRYPTO_DTLS_SERVER_BUSY;
  if (s->flight_index==s->flight_count) {
    if (s->phase>=CRYPTO_DTLS_SERVER_SEND_FINAL) return CRYPTO_DTLS_SERVER_IDLE;
    bool due=false; status=crypto_dtls_flight_timer_poll(&s->timer,now,&due); if (status) return fail(s,SALTS_CRYPTO_ESTATE);
    if (!due) return CRYPTO_DTLS_SERVER_IDLE; s->flight_index=s->flight_offset=0u;
  }
  crypto_dtls_server_message *m=&s->flight[s->flight_index]; const uint8_t *plain=m->body; size_t n=m->size;
  if (m->handshake_type) {
    const size_t limit=CRYPTO_DTLS_SERVER_MTU-(m->encrypted ? CRYPTO_DTLS_RECORD_OVERHEAD : CRYPTO_DTLS_HEADER_SIZE)-12u;
    size_t fragment=m->size-s->flight_offset; if (fragment>limit) fragment=limit;
    status=crypto_dtls_fragment_write(m->handshake_type,m->sequence,m->body,m->size,s->flight_offset,fragment,
      s->scratch,sizeof(s->scratch),&n); if (status) return fail(s,status);
    plain=s->scratch; s->pending_advance=fragment;
  } else s->pending_advance=m->size;
  if (m->encrypted) status=crypto_dtls_record_seal(&s->secrets.server_write,m->type,plain,n,s->pending_wire,sizeof(s->pending_wire),&s->pending_size);
  else {
    if (s->plain_sequence>CRYPTO_DTLS_MAX_SEQUENCE || n>sizeof(s->pending_wire)-13u) return fail(s,SALTS_CRYPTO_ESTATE);
    uint8_t *p=s->pending_wire; p[0]=m->type; p[1]=0xfe; p[2]=0xfd; p[3]=p[4]=0;
    uint64_t seq=s->plain_sequence++; for (size_t i=11u;i>5u;) {p[--i]=(uint8_t)seq;seq>>=8u;}
    put16(p+11u,n); memcpy(p+13u,plain,n); s->pending_size=13u+n;
  }
  salts_crypto_secure_zero(s->scratch,sizeof(s->scratch)); if (status) return fail(s,status);
  s->pending=true; *wire=s->pending_wire; *size=s->pending_size; return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_sent(crypto_dtls_server *s,uint64_t now,bool success) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || !s->pending) return SALTS_CRYPTO_ESTATE;
  s->pending=false; s->pending_size=0u; salts_crypto_secure_zero(s->pending_wire,sizeof(s->pending_wire));
  if (s->phase==CRYPTO_DTLS_SERVER_FAILED) { if (!success && s->fatal.description) s->fatal.error=SALTS_CRYPTO_ECRYPTO; return s->failure; }
  if (!success) return fail(s,SALTS_CRYPTO_ECRYPTO);
  int status=sample(s,now); if (status) return status;
  if (s->flight[s->flight_index].type==20u) s->write_epoch=true;
  crypto_dtls_server_message *m=&s->flight[s->flight_index]; s->flight_offset+=s->pending_advance;
  if (s->flight_offset>=m->size) { ++s->flight_index; s->flight_offset=0u; }
  if (s->flight_index==s->flight_count) {
    if (s->flight_kind==CRYPTO_DTLS_SERVER_INITIAL_FLIGHT) {
      status=crypto_dtls_flight_timer_sent(&s->timer,now); if (status) return fail(s,status);
    } else {
      if (s->flight_kind==CRYPTO_DTLS_SERVER_CLOSE) { s->phase=CRYPTO_DTLS_SERVER_CLOSED; crypto_dtls_secrets_clear(&s->secrets); }
      else s->phase=CRYPTO_DTLS_SERVER_READY;
      salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=s->flight_index=0u;
    }
  }
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_write(crypto_dtls_server *s,const void *data,size_t size) {
  if (!s || (!data && size) || size>CRYPTO_DTLS_SERVER_MTU-CRYPTO_DTLS_RECORD_OVERHEAD ||
      salts_crypto_overlap(s,sizeof(*s),data,size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_SERVER_READY) return SALTS_CRYPTO_ESTATE;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_SERVER_BUSY;
  s->flight_kind=CRYPTO_DTLS_SERVER_APPLICATION; s->flight_count=1u; s->flight_index=s->flight_offset=0u;
  s->flight[0].type=23u; s->flight[0].encrypted=true; s->flight[0].size=size;
  if (size) memcpy(s->flight[0].body,data,size); return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_close(crypto_dtls_server *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_SERVER_READY) return SALTS_CRYPTO_ESTATE;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_SERVER_BUSY;
  return alert(s);
}
int crypto_dtls_server_export(const crypto_dtls_server *s,const crypto_dtls_export_request *r,void *out,size_t n) {
  if (!s || !r || salts_crypto_overlap(s,sizeof(*s),r,sizeof(*r))) return SALTS_CRYPTO_EINVAL;
  if (salts_crypto_overlap(s,sizeof(*s),out,n) || salts_crypto_overlap(s,sizeof(*s),r->label,r->label_size) ||
      salts_crypto_overlap(s,sizeof(*s),r->context,r->context_size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_SERVER_READY || !s->context->exporter_enabled) return SALTS_CRYPTO_ESTATE;
  const crypto_dtls_server_context *c=s->context;
  if (salts_crypto_overlap(c,sizeof(*c),r,sizeof(*r)) || salts_crypto_overlap(c,sizeof(*c),out,n) ||
      salts_crypto_overlap(c,sizeof(*c),r->label,r->label_size) || salts_crypto_overlap(c,sizeof(*c),r->context,r->context_size))
    return SALTS_CRYPTO_EINVAL;
  return crypto_dtls_exporter(&s->secrets,s->client_random,s->server_random,r,out,n);
}
int crypto_dtls_server_abort(crypto_dtls_server *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase==CRYPTO_DTLS_SERVER_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase!=CRYPTO_DTLS_SERVER_FAILED && s->phase!=CRYPTO_DTLS_SERVER_CLOSED) (void)fail(s,SALTS_CRYPTO_ESTATE);
  salts_crypto_secure_zero(s->fatal.wire,sizeof(s->fatal.wire)); s->fatal.size=0u;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_server_clear(crypto_dtls_server *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback) return SALTS_CRYPTO_ESTATE;
  if (s->pending) return CRYPTO_DTLS_SERVER_BUSY;
  crypto_dtls_server_context *c=s->context;
  if (c && !atomic_load_explicit(&c->leases,memory_order_relaxed)) return SALTS_CRYPTO_ESTATE;
  salts_crypto_secure_zero(s,sizeof(*s));
  if (c) atomic_fetch_sub_explicit(&c->leases,1u,memory_order_release);
  return SALTS_CRYPTO_OK;
}
