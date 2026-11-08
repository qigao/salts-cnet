#include "crypto_dtls_client.h"
#include "crypto_internal.h"
#include "crypto_tls_credentials.h"
#include <crypto/tls_cipher.h>
#include <crypto/x509_der.h>
#include <gmssl/tls.h>
#include <gmssl/x509.h>
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/ecdsa.h>
#include <gmssl/rsa.h>
#include <string.h>

enum { DTLS_HELLO_BODY_BOUND=1024, DTLS_FLIGHT_RETRIES=6 };
_Static_assert(DTLS_HELLO_BODY_BOUND+12+13<=CRYPTO_DTLS_CLIENT_MTU,"bounded ClientHello fits datagram");
typedef struct dtls_cursor { const uint8_t *p; size_t size; } dtls_cursor;
static int take(dtls_cursor *c,size_t n,const uint8_t **p) {
  if (n>c->size) return 0;
  *p=c->p; c->p+=n; c->size-=n; return 1;
}
static unsigned u16(const uint8_t *p) { return (unsigned)p[0]*256u+p[1]; }
static size_t u24(const uint8_t *p) { return (size_t)p[0]*65536u+(size_t)p[1]*256u+p[2]; }
static void put16(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>8u); p[1]=(uint8_t)n; }
static void emit16(uint8_t **p,size_t n) { put16(*p,n); *p+=2; }
static void put24(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>16u); p[1]=(uint8_t)(n>>8u); p[2]=(uint8_t)n; }
static void clear_identity(crypto_dtls_client *s) {
  tls_ctx_cleanup(&s->identity); salts_crypto_secure_zero(&s->identity,sizeof(s->identity));
}
static int fail(crypto_dtls_client *s,int status) {
  s->phase=CRYPTO_DTLS_CLIENT_FAILED; s->failure=status;
  crypto_dtls_ephemeral_clear(&s->ephemeral); crypto_dtls_secrets_clear(&s->secrets);
  crypto_dtls_transcript_clear(&s->transcript); crypto_dtls_reassembly_clear(&s->messages);
  crypto_dtls_flight_timer_clear(&s->timer);
  salts_crypto_secure_zero(s->scratch,sizeof(s->scratch));
  clear_identity(s);
  salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=s->flight_index=0u;
  /* pending_wire belongs to a real native borrow until sent, even on abort. */
  return status;
}
static int reject(crypto_dtls_client *s,int status) {
  if (s->cookie_size) {
    uint8_t description=s->fatal.description;
    if (!description) description=status==SALTS_CRYPTO_EINVAL ? TLS_alert_decode_error :
      status==SALTS_CRYPTO_ECRYPTO ? TLS_alert_internal_error : TLS_alert_handshake_failure;
    crypto_dtls_fatal_prepare(&s->fatal,&s->secrets.client_write,s->write_epoch,&s->plain_sequence,description);
  }
  return fail(s,status);
}
int crypto_dtls_client_data_failed(crypto_dtls_client *s){
  if(!s || s->in_callback || s->phase!=CRYPTO_DTLS_CLIENT_READY)return SALTS_CRYPTO_ESTATE;
  s->fatal.description=TLS_alert_internal_error;return reject(s,SALTS_CRYPTO_EVERIFY);
}
static int sample(crypto_dtls_client *s,uint64_t now) {
  if (s->clock_sampled && now<s->last_now) return fail(s,SALTS_CRYPTO_ESTATE);
  s->last_now=now; s->clock_sampled=true; return SALTS_CRYPTO_OK;
}
static int verify_chain(crypto_dtls_client *s) {
  static const int groups[]={TLS_curve_secp256r1};
  static const int schemes[]={TLS_sig_ecdsa_secp256r1_sha256,TLS_sig_rsa_pkcs1_sha256};
  const int result=tls_cert_chain_verify_ex(TLS_protocol_tls12,X509_cert_chain_server,s->cipher,1,
      s->chain,s->chain_size,s->roots,s->roots_size,NULL,0u,NULL,0u,4,
      groups,1u,schemes,2u,schemes,2u,NULL,0u,NULL,0u,(const uint8_t *)s->server_name,s->server_name_size,
      &s->verify_result,NULL,&s->verify_index,NULL);
  return result==1 && s->verify_result==X509_verify_ok ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}
static int new_flight(crypto_dtls_client *s,size_t count) {
  salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=count; s->flight_index=s->flight_offset=0u;
  crypto_dtls_flight_timer_clear(&s->timer);
  return crypto_dtls_flight_timer_init(&s->timer,1000u,60000u,DTLS_FLIGHT_RETRIES);
}
static int message(crypto_dtls_client *s,size_t slot,uint8_t type,uint16_t seq,const void *body,size_t n,bool encrypted) {
  crypto_dtls_client_flight *f=&s->flight[slot];
  if (n>sizeof(f->data)) return SALTS_CRYPTO_EINVAL;
  if (n) memcpy(f->data,body,n); f->size=n; f->sequence=seq; f->handshake_type=type;
  f->type=22u; f->encrypted=encrypted; return SALTS_CRYPTO_OK;
}
static int import_identity(crypto_dtls_client *s,const crypto_tls_credentials *input) {
  if (!input) return SALTS_CRYPTO_OK;
  if (tls_ctx_init(&s->identity,TLS_protocol_tls12,1)!=1 || crypto_tls_memory_identity(&s->identity,input)!=0 ||
      s->identity.x509_keys_cnt!=1u || s->identity.cert_chains_len<3u) return SALTS_CRYPTO_ECRYPTO;
  s->identity_chain_size=u24(s->identity.cert_chains);
  if (s->identity_chain_size+3u!=s->identity.cert_chains_len) return SALTS_CRYPTO_EINVAL;
  crypto_tls_stream_peer_certificate_chain chain;
  if (crypto_dtls_chain_views(s->identity.cert_chains+3u,s->identity_chain_size,&chain)!=0) return SALTS_CRYPTO_EINVAL;
  const X509_KEY *key=&s->identity.x509_keys[0];
  if (key->algor==OID_rsa_encryption) s->signature=TLS_sig_rsa_pkcs1_sha256;
  else if (key->algor==OID_ec_public_key && key->algor_param==OID_secp256r1) s->signature=TLS_sig_ecdsa_secp256r1_sha256;
  else return SALTS_CRYPTO_EINVAL;
  for (size_t i=0;i<chain.count;++i) {
    int algorithm;
    if (x509_cert_get_signature_algor(chain.certificates[i].data,chain.certificates[i].size,&algorithm)!=1 ||
        (algorithm!=OID_ecdsa_with_sha256 && algorithm!=OID_rsasign_with_sha256)) return SALTS_CRYPTO_EINVAL;
  }
  return SALTS_CRYPTO_OK;
}
static int hello(crypto_dtls_client *s) {
  /* Maximum encoded body is 958 bytes: all dynamic fields were admitted at
   * DNS<=253, ALPN<=255 and cookie<=255. No size is inferred from a C string. */
  uint8_t body[DTLS_HELLO_BODY_BOUND],*p=body;
  *p++=0xfe; *p++=0xfd; memcpy(p,s->client_random,32u); p+=32u; *p++=0;
  *p++=(uint8_t)s->cookie_size; memcpy(p,s->cookie,s->cookie_size); p+=s->cookie_size;
  emit16(&p,4u); emit16(&p,CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256);
  emit16(&p,CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256); *p++=1; *p++=0;
  uint8_t *extension_length=p; p+=2u;
  emit16(&p,0u); emit16(&p,5u+s->server_name_size); emit16(&p,3u+s->server_name_size);
  *p++=0; emit16(&p,s->server_name_size); memcpy(p,s->server_name,s->server_name_size); p+=s->server_name_size;
  const uint8_t fixed[]={0,10,0,4,0,2,0,23, 0,11,0,2,1,0,
    0,13,0,6,0,4,4,3,4,1, 0,23,0,0, 0xff,1,0,1,0};
  memcpy(p,fixed,sizeof(fixed)); p+=sizeof(fixed);
  if (s->alpn_size) { emit16(&p,16u); emit16(&p,3u+s->alpn_size); emit16(&p,1u+s->alpn_size);
    *p++=(uint8_t)s->alpn_size; memcpy(p,s->alpn,s->alpn_size); p+=s->alpn_size; }
  put16(extension_length,(size_t)(p-extension_length-2u));
  int status=new_flight(s,1u); if (status) return status;
  status=message(s,0u,1u,(uint16_t)s->client_sequence,body,(size_t)(p-body),false);
  if (status || !s->cookie_size) return status;
  crypto_dtls_transcript_clear(&s->transcript); crypto_dtls_reassembly_clear(&s->messages);
  status=crypto_dtls_transcript_init(&s->transcript,(uint16_t)s->client_sequence,(uint16_t)s->server_first);
  if (status) return status;
  status=crypto_dtls_reassembly_init(&s->messages,(uint16_t)s->server_first,CRYPTO_DTLS_HANDSHAKE_MAX_BODY);
  if (status) return status;
  const crypto_dtls_message m={body,(size_t)(p-body),(uint16_t)s->client_sequence,1u};
  return crypto_dtls_transcript_append(&s->transcript,CRYPTO_DTLS_CLIENT,&m);
}
int crypto_dtls_client_init(crypto_dtls_client *s,const crypto_dtls_client_config *c) {
  if (!s || !c || salts_crypto_overlap(s,sizeof(*s),c,sizeof(*c)) || !c->roots || !c->roots_size ||
      c->roots_size>sizeof(s->roots) || !crypto_dtls_dns_name(c->server_name,c->server_name_size) || !c->on_data ||
      c->alpn_size>sizeof(s->alpn) || (!c->alpn && c->alpn_size) ||
      salts_crypto_overlap(s,sizeof(*s),c->roots,c->roots_size) ||
      salts_crypto_overlap(s,sizeof(*s),c->server_name,c->server_name_size) ||
      salts_crypto_overlap(s,sizeof(*s),c->alpn,c->alpn_size) ||
      (c->peer_policy && salts_crypto_overlap(s,sizeof(*s),c->peer_policy,sizeof(*c->peer_policy)))) return SALTS_CRYPTO_EINVAL;
  if (s->phase!=CRYPTO_DTLS_CLIENT_ZERO || s->pending || s->in_callback) return SALTS_CRYPTO_ESTATE;
  const crypto_tls_stream_peer_policy *policy=c->peer_policy;
  if (policy && (!policy->check || !policy->retain || !policy->release ||
      (policy->supported_profiles & ~(CRYPTO_TLS_PEER_POLICY_STANDARD|CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13|CRYPTO_TLS_PEER_POLICY_TLCP11)) ||
      (policy->supported_peer_roles & ~(CRYPTO_TLS_PEER_POLICY_CLIENT|CRYPTO_TLS_PEER_POLICY_SERVER)) ||
      (policy->supported_profiles && !(policy->supported_profiles & CRYPTO_TLS_PEER_POLICY_STANDARD)) ||
      (policy->supported_peer_roles && !(policy->supported_peer_roles & CRYPTO_TLS_PEER_POLICY_SERVER)))) return SALTS_CRYPTO_EINVAL;
  crypto_tls_stream_peer_certificate_chain roots;
  if (crypto_dtls_chain_views(c->roots,c->roots_size,&roots)!=0) return SALTS_CRYPTO_EINVAL;
  if (c->credentials) {
    const crypto_tls_credentials *input=c->credentials;
    if (salts_crypto_overlap(s,sizeof(*s),input,sizeof(*input))) return SALTS_CRYPTO_EINVAL;
    const crypto_tls_data *spans[]={&input->certificate_chain,&input->private_key,&input->encryption_key};
    for (size_t i=0;i<sizeof(spans)/sizeof(spans[0]);++i)
      if (salts_crypto_overlap(s,sizeof(*s),spans[i]->data,spans[i]->size)) return SALTS_CRYPTO_EINVAL;
    if (salts_crypto_overlap(s,sizeof(*s),input->private_key_password.data,input->private_key_password.size) ||
        salts_crypto_overlap(s,sizeof(*s),input->encryption_key_password.data,input->encryption_key_password.size) ||
        crypto_tls_memory_validate(NULL,input,false)!=0) return SALTS_CRYPTO_EINVAL;
  }
  memset(s,0,sizeof(*s)); s->verify_index=SIZE_MAX;
  int status=import_identity(s,c->credentials); if (status) goto invalid;
  memcpy(s->roots,c->roots,c->roots_size); s->roots_size=c->roots_size;
  memcpy(s->server_name,c->server_name,c->server_name_size); s->server_name_size=c->server_name_size;
  if (c->alpn_size) memcpy(s->alpn,c->alpn,c->alpn_size); s->alpn_size=c->alpn_size;
  s->on_data=c->on_data; s->data_context=c->data_context;
  s->exporter_enabled=c->enable_exporter;
  if (salts_crypto_random_bytes(s->client_random,sizeof(s->client_random))!=0) { status=SALTS_CRYPTO_ERANDOM; goto invalid; }
  status=hello(s); if (status) goto invalid;
  s->phase=CRYPTO_DTLS_CLIENT_COOKIE;
  if (policy) { s->policy=*policy; s->in_callback=true; s->policy.retain(s->policy.context);
    s->in_callback=false; s->policy_retained=true; }
  return SALTS_CRYPTO_OK;
invalid:
  clear_identity(s); salts_crypto_secure_zero(s,sizeof(*s)); return status;
}
static int server_hello(crypto_dtls_client *s,const crypto_dtls_message *m) {
  dtls_cursor c={m->body,m->size}; const uint8_t *p;
  if (!take(&c,35u,&p) || p[0]!=0xfe || p[1]!=0xfd || p[34]>32u) return SALTS_CRYPTO_EVERIFY;
  memcpy(s->server_random,p+2u,32u); const size_t sid=p[34];
  if (!take(&c,sid,&p) || !take(&c,3u,&p) || p[2]!=0u) return SALTS_CRYPTO_EVERIFY;
  s->cipher=(uint16_t)u16(p);
  if (s->cipher!=CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256 &&
      s->cipher!=CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256) return SALTS_CRYPTO_EVERIFY;
  if (!take(&c,2u,&p) || u16(p)!=c.size) return SALTS_CRYPTO_EVERIFY;
  unsigned seen=0; bool ems=false,alpn=false;
  while (c.size) {
    if (!take(&c,4u,&p)) return SALTS_CRYPTO_EVERIFY;
    const unsigned type=u16(p); const size_t n=u16(p+2u);
    if (!take(&c,n,&p)) return SALTS_CRYPTO_EVERIFY;
    unsigned bit;
    switch (type) {
      case 0: bit=1u; if (n) return SALTS_CRYPTO_EVERIFY; break;
      case 11: {
        bit=2u; if (n<2u || p[0]!=n-1u) return SALTS_CRYPTO_EVERIFY;
        bool uncompressed=false; for (size_t i=1u;i<n;++i) uncompressed|=p[i]==0u;
        if (!uncompressed) return SALTS_CRYPTO_EVERIFY; break;
      }
      case 23: bit=4u; if (n) return SALTS_CRYPTO_EVERIFY; ems=true; break;
      case 0xff01: bit=8u; if (n!=1u || p[0]) return SALTS_CRYPTO_EVERIFY; break;
      case 16: bit=16u;
        if (!s->alpn_size || n!=s->alpn_size+3u || u16(p)!=s->alpn_size+1u || p[2]!=s->alpn_size ||
            memcmp(p+3u,s->alpn,s->alpn_size)) return SALTS_CRYPTO_EVERIFY;
        alpn=true; break;
      default: return SALTS_CRYPTO_EVERIFY;
    }
    if (seen&bit) return SALTS_CRYPTO_EVERIFY; seen|=bit;
  }
  return ems && (!s->alpn_size || alpn) ? SALTS_CRYPTO_OK : SALTS_CRYPTO_EVERIFY;
}
static int certificate(crypto_dtls_client *s,const crypto_dtls_message *m) {
  dtls_cursor c={m->body,m->size}; const uint8_t *p;
  if (!take(&c,3u,&p) || !c.size || u24(p)!=c.size) return SALTS_CRYPTO_EVERIFY;
  s->chain_size=s->chain_count=0u;
  while (c.size) {
    if (!take(&c,3u,&p)) return SALTS_CRYPTO_EVERIFY;
    const size_t n=u24(p);
    if (!n || n>sizeof(s->chain)-s->chain_size || !take(&c,n,&p) ||
        s->chain_count==CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES) return SALTS_CRYPTO_EVERIFY;
    crypto_x509_der_view view;
    if (crypto_x509_der_inspect(p,n,&view)!=SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
    memcpy(s->chain+s->chain_size,p,n); s->chain_size+=n; ++s->chain_count;
  }
  int status=verify_chain(s); if (status) s->fatal.description=TLS_alert_certificate_unknown; return status;
}
static int certificate_request(crypto_dtls_client *s,const crypto_dtls_message *m) {
  dtls_cursor c={m->body,m->size}; const uint8_t *p,*types,*schemes,*names;
  if (s->requested_certificate || !take(&c,1u,&p) || !p[0]) return SALTS_CRYPTO_EVERIFY;
  const size_t types_size=p[0];
  if (!take(&c,types_size,&types) || !take(&c,2u,&p)) return SALTS_CRYPTO_EVERIFY;
  const size_t schemes_size=u16(p);
  if (!schemes_size || schemes_size%2u || !take(&c,schemes_size,&schemes) || !take(&c,2u,&p) || u16(p)!=c.size)
    return SALTS_CRYPTO_EVERIFY;
  names=c.p; const size_t names_size=c.size;
  /* Native issuer matching checks the enclosing sequence, not RDN contents.
   * Validate every name before matching, including a tail after a match. */
  dtls_cursor authorities={names,names_size};
  while (authorities.size) {
    const uint8_t *name,*dn; size_t dn_size;
    if (!take(&authorities,2u,&p)) return SALTS_CRYPTO_EVERIFY;
    size_t n=u16(p);
    if (!n || !take(&authorities,n,&name) || x509_name_from_der(&dn,&dn_size,&name,&n)!=1 || n ||
        x509_name_check(dn,dn_size)!=1) return SALTS_CRYPTO_EVERIFY;
  }
  /* CA names are selection hints only, never a replacement trust store. */
  const int issuer=names_size ? tls_authorities_issued_certificate(names,names_size,
    s->signature ? s->identity.cert_chains+3u : NULL,s->identity_chain_size) : 1;
  if (issuer<0) return SALTS_CRYPTO_EVERIFY;
  bool type=false,scheme=false,certs=true;
  for (size_t i=0;i<types_size;++i)
    type|=types[i]==(s->signature==TLS_sig_rsa_pkcs1_sha256 ? TLS_cert_type_rsa_sign : TLS_cert_type_ecdsa_sign);
  for (size_t i=0;i<schemes_size;i+=2u) scheme|=u16(schemes+i)==s->signature;
  if (s->signature) {
    crypto_tls_stream_peer_certificate_chain chain;
    if (crypto_dtls_chain_views(s->identity.cert_chains+3u,s->identity_chain_size,&chain)!=0) return SALTS_CRYPTO_ESTATE;
    for (size_t i=0;i<chain.count;++i) {
      int algorithm; bool found=false;
      if (x509_cert_get_signature_algor(chain.certificates[i].data,chain.certificates[i].size,&algorithm)!=1) return SALTS_CRYPTO_ESTATE;
      const unsigned wanted=algorithm==OID_ecdsa_with_sha256 ? TLS_sig_ecdsa_secp256r1_sha256 : TLS_sig_rsa_pkcs1_sha256;
      for (size_t j=0;j<schemes_size;j+=2u) found|=u16(schemes+j)==wanted;
      certs&=found;
    }
  }
  s->requested_certificate=true; s->selected_identity=s->signature && type && scheme && certs && issuer==1;
  return SALTS_CRYPTO_OK;
}
static int append_client(crypto_dtls_client *s,size_t at,uint8_t type,const uint8_t *body,size_t n,bool encrypted) {
  if (s->transcript.next[CRYPTO_DTLS_CLIENT]>UINT16_MAX) return SALTS_CRYPTO_ESTATE;
  const uint16_t sequence=(uint16_t)s->transcript.next[CRYPTO_DTLS_CLIENT];
  int status=message(s,at,type,sequence,body,n,encrypted); if (status) return status;
  const crypto_dtls_message m={s->flight[at].data,n,sequence,type};
  return crypto_dtls_transcript_append(&s->transcript,CRYPTO_DTLS_CLIENT,&m);
}
static int final_flight(crypto_dtls_client *s) {
  uint8_t body[CRYPTO_DTLS_CLIENT_CHAIN_BYTES+18],hash[32],shared[32],proof[12];
  int status=crypto_dtls_ephemeral_init(&s->ephemeral); size_t at=0u;
  if (status) goto end;
  status=new_flight(s,3u+(s->requested_certificate ? 1u : 0u)+(s->selected_identity ? 1u : 0u)); if (status) goto end;
  if (s->requested_certificate) {
    uint8_t *p=body+3u;
    if (s->selected_identity) {
      crypto_tls_stream_peer_certificate_chain chain;
      status=crypto_dtls_chain_views(s->identity.cert_chains+3u,s->identity_chain_size,&chain); if (status) goto end;
      for (size_t i=0;i<chain.count;++i) {
        put24(p,chain.certificates[i].size); p+=3u; memcpy(p,chain.certificates[i].data,chain.certificates[i].size); p+=chain.certificates[i].size;
      }
    }
    put24(body,(size_t)(p-body-3u)); status=append_client(s,at++,11u,body,(size_t)(p-body),false); if (status) goto end;
  }
  body[0]=65u; status=crypto_dtls_ephemeral_public(&s->ephemeral,body+1u); if (status) goto end;
  status=append_client(s,at++,16u,body,66u,false); if (status) goto end;
  status=crypto_dtls_transcript_hash(&s->transcript,hash); if (status) goto end;
  status=crypto_dtls_ephemeral_exchange(&s->ephemeral,s->peer_point,sizeof(s->peer_point),shared); if (status) goto end;
  status=crypto_dtls_secrets_derive(&s->secrets,shared,hash,s->client_random,s->server_random); if (status) goto end;
  if (s->selected_identity) {
    size_t n=0u; const X509_KEY *key=&s->identity.x509_keys[0];
    const int result=s->signature==TLS_sig_rsa_pkcs1_sha256 ?
      rsa_sign_pkcs1_v15_sha256(&key->rsa_private_key,hash,body+4u,CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE,&n) :
      ecdsa_sign(&key->u.secp256r1_key,hash,body+4u,&n);
    if (result!=1 || !n || n>CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE) { status=SALTS_CRYPTO_ECRYPTO; goto end; }
    put16(body,s->signature); put16(body+2u,n);
    status=append_client(s,at++,15u,body,n+4u,false); if (status) goto end;
    status=crypto_dtls_transcript_hash(&s->transcript,hash); if (status) goto end;
  }
  status=crypto_dtls_finished(&s->secrets,CRYPTO_DTLS_CLIENT,hash,proof); if (status) goto end;
  s->flight[at].data[0]=1u; s->flight[at].size=1u; s->flight[at++].type=20u;
  status=append_client(s,at,20u,proof,sizeof(proof),true);
end:
  clear_identity(s);
  salts_crypto_secure_zero(body,sizeof(body)); salts_crypto_secure_zero(hash,sizeof(hash));
  salts_crypto_secure_zero(shared,sizeof(shared)); salts_crypto_secure_zero(proof,sizeof(proof));
  return status;
}
static int admit_ready(crypto_dtls_client *s) {
  if (!s->saw_ccs || !s->verified_finished) return SALTS_CRYPTO_OK;
  int status=verify_chain(s); if (status) return status;
  if (s->policy_retained) {
    crypto_tls_stream_peer_certificate_chain chain;
    status=crypto_dtls_chain_views(s->chain,s->chain_size,&chain); if (status) return status;
    s->in_callback=true;
    status=s->policy.check(s->policy.context,&chain,true,CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD);
    s->in_callback=false; if (status) { s->fatal.description=TLS_alert_access_denied; return SALTS_CRYPTO_EVERIFY; }
  }
  s->phase=CRYPTO_DTLS_CLIENT_READY; crypto_dtls_flight_timer_clear(&s->timer);
  salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=s->flight_index=0u;
  if (!s->exporter_enabled) crypto_dtls_secrets_forget_master(&s->secrets);
  crypto_dtls_transcript_clear(&s->transcript); crypto_dtls_reassembly_clear(&s->messages);
  return SALTS_CRYPTO_OK;
}
static int completed_messages(crypto_dtls_client *s) {
  for (;;) {
    crypto_dtls_message m;
    int status=crypto_dtls_reassembly_peek(&s->messages,&m);
    if (status==CRYPTO_DTLS_HANDSHAKE_NEED) return SALTS_CRYPTO_OK;
    if (status) return status;
    crypto_dtls_client_phase next;
    switch (s->phase) {
      case CRYPTO_DTLS_CLIENT_HELLO:
        if (m.type!=2u) return SALTS_CRYPTO_EVERIFY;
        status=server_hello(s,&m); next=CRYPTO_DTLS_CLIENT_CERTIFICATE; break;
      case CRYPTO_DTLS_CLIENT_CERTIFICATE:
        if (m.type!=11u) return SALTS_CRYPTO_EVERIFY;
        status=certificate(s,&m); next=CRYPTO_DTLS_CLIENT_KEY; break;
      case CRYPTO_DTLS_CLIENT_KEY: {
        if (m.type!=12u) return SALTS_CRYPTO_EVERIFY;
        const uint8_t *p=s->chain,*leaf; size_t left=s->chain_size,n;
        if (x509_cert_from_der(&leaf,&n,&p,&left)!=1) return SALTS_CRYPTO_EVERIFY;
        status=crypto_dtls_server_exchange_verify(leaf,n,s->cipher,s->client_random,s->server_random,m.body,m.size,s->peer_point);
        if (status) s->fatal.description=TLS_alert_decrypt_error;
        next=CRYPTO_DTLS_CLIENT_DONE; break;
      }
      case CRYPTO_DTLS_CLIENT_DONE:
        if (m.type==13u) {
          const bool duplicate=s->requested_certificate; status=certificate_request(s,&m);
          if (status) s->fatal.description=duplicate ? TLS_alert_unexpected_message : TLS_alert_decode_error;
          next=CRYPTO_DTLS_CLIENT_DONE; break;
        }
        if (m.type!=14u || m.size) return SALTS_CRYPTO_EVERIFY;
        s->server_done_sequence=m.sequence;
        status=SALTS_CRYPTO_OK; next=CRYPTO_DTLS_CLIENT_FINISHED; break;
      case CRYPTO_DTLS_CLIENT_FINISHED: {
        if (m.type!=20u || m.size!=12u || s->verified_finished) return SALTS_CRYPTO_EVERIFY;
        uint8_t hash[32]; status=crypto_dtls_transcript_hash(&s->transcript,hash);
        if (!status) status=crypto_dtls_finished_check(&s->secrets,CRYPTO_DTLS_SERVER,hash,m.body,m.size);
        if (status) s->fatal.description=TLS_alert_decrypt_error;
        salts_crypto_secure_zero(hash,sizeof(hash));
        if (!status) { memcpy(s->server_finished,m.body,12u); s->verified_finished=true; }
        next=CRYPTO_DTLS_CLIENT_FINISHED; break;
      }
      default: return SALTS_CRYPTO_ESTATE;
    }
    if (status) return status;
    status=crypto_dtls_transcript_append(&s->transcript,CRYPTO_DTLS_SERVER,&m); if (status) return status;
    status=crypto_dtls_reassembly_consume(&s->messages); if (status) return status;
    const bool send_final=s->phase==CRYPTO_DTLS_CLIENT_DONE && m.type==14u; s->phase=next;
    if (send_final) return final_flight(s);
    if (s->verified_finished) return admit_ready(s);
  }
}
static int repeat_flight(crypto_dtls_client *s) {
  bool due=false;
  int status=crypto_dtls_flight_timer_repeat(&s->timer,s->last_now,&due);
  if (status) return SALTS_CRYPTO_ESTATE;
  if (due) s->flight_index=s->flight_offset=0u;
  return SALTS_CRYPTO_OK;
}
static int challenge(crypto_dtls_client *s,const uint8_t *data,size_t size) {
  crypto_dtls_fragment f;
  if (crypto_dtls_fragment_parse(data,size,&f)!=0 || f.type!=3u || f.offset || f.size!=f.total ||
      f.wire_size!=size || f.size<4u || f.body[0]!=0xfe || (f.body[1]!=0xfd && f.body[1]!=0xff) ||
      !f.body[2] || f.body[2]!=f.size-3u || f.sequence>UINT16_MAX-6u) return SALTS_CRYPTO_EVERIFY;
  if (s->phase==CRYPTO_DTLS_CLIENT_HELLO && (uint32_t)f.sequence+1u==s->server_first && f.body[2]==s->cookie_size &&
      !memcmp(s->cookie,f.body+3u,s->cookie_size)) return repeat_flight(s);
  if (s->challenges==CRYPTO_DTLS_CLIENT_MAX_CHALLENGES || s->client_sequence==UINT16_MAX) return SALTS_CRYPTO_ESTATE;
  ++s->challenges; ++s->client_sequence; s->server_first=(uint32_t)f.sequence+1u;
  s->cookie_size=f.body[2]; memcpy(s->cookie,f.body+3u,s->cookie_size);
  int status=hello(s); if (status) return status;
  s->phase=CRYPTO_DTLS_CLIENT_HELLO; return SALTS_CRYPTO_OK;
}
static int fragments(crypto_dtls_client *s,const uint8_t *p,size_t size,bool encrypted) {
  size_t at=0u;
  while (at<size) {
    crypto_dtls_fragment f; int status=crypto_dtls_fragment_parse(p+at,size-at,&f);
    if (status) return status;
    if (encrypted) {
      if (f.type!=20u || f.sequence!=(uint32_t)s->server_done_sequence+1u) return SALTS_CRYPTO_EVERIFY;
      if (s->phase==CRYPTO_DTLS_CLIENT_READY || s->phase==CRYPTO_DTLS_CLIENT_CLOSING) return CRYPTO_DTLS_CLIENT_DROP;
      if (s->phase!=CRYPTO_DTLS_CLIENT_FINISHED) return SALTS_CRYPTO_EVERIFY;
    } else {
      /* Never let epoch-zero bytes occupy an authenticated Finished slot. */
      if (f.type==20u) return CRYPTO_DTLS_CLIENT_DROP;
      if (f.type!=2u && f.type!=11u && f.type!=12u && f.type!=13u && f.type!=14u) return SALTS_CRYPTO_EVERIFY;
      if (f.sequence<s->server_first || f.sequence>s->server_first+4u) return CRYPTO_DTLS_CLIENT_DROP;
      if (s->phase>=CRYPTO_DTLS_CLIENT_READY) return CRYPTO_DTLS_CLIENT_DROP;
      /* Empty ServerHelloDone is the complete last message of the previous
       * peer flight. Partial old fragments alone never reset a timer. */
      if (s->phase==CRYPTO_DTLS_CLIENT_FINISHED && f.type==14u &&
          f.sequence==s->server_done_sequence && !f.total && !f.offset && !f.size) return repeat_flight(s);
    }
    size_t consumed=0u;
    status=crypto_dtls_reassembly_feed(&s->messages,p+at,size-at,&consumed);
    if (status!=0 && status!=CRYPTO_DTLS_HANDSHAKE_OLD && status!=CRYPTO_DTLS_HANDSHAKE_NEED) return status;
    if (!consumed || consumed>size-at) return SALTS_CRYPTO_ESTATE;
    at+=consumed;
    status=completed_messages(s); if (status) return status;
    if (s->phase==CRYPTO_DTLS_CLIENT_READY || s->flight_index<s->flight_count) return SALTS_CRYPTO_OK;
  }
  return SALTS_CRYPTO_OK;
}
static int queued_alert(crypto_dtls_client *s) {
  crypto_dtls_secrets_forget_master(&s->secrets);
  salts_crypto_secure_zero(s->flight,sizeof(s->flight));
  s->flight_count=1u; s->flight_index=s->flight_offset=0u; s->flight[0].type=21u; s->flight[0].encrypted=true;
  s->flight[0].size=2u; s->flight[0].data[0]=1u; s->flight[0].data[1]=0u;
  s->phase=CRYPTO_DTLS_CLIENT_CLOSING; crypto_dtls_flight_timer_clear(&s->timer);
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_receive(crypto_dtls_client *s,uint64_t now,const void *wire,size_t size) {
  if (!s || !wire || salts_crypto_overlap(s,sizeof(*s),wire,size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase==CRYPTO_DTLS_CLIENT_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase==CRYPTO_DTLS_CLIENT_FAILED) return s->failure;
  if (s->phase==CRYPTO_DTLS_CLIENT_CLOSED) return CRYPTO_DTLS_CLIENT_DROP;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_CLIENT_BUSY;
  int status=sample(s,now); if (status) return status;
  if (!size || size>CRYPTO_DTLS_MAX_PLAINTEXT+CRYPTO_DTLS_RECORD_OVERHEAD) return CRYPTO_DTLS_CLIENT_DROP;
  const uint8_t *bytes=wire;
  /* Validate every outer frame before publishing callbacks from a prefix. */
  for (size_t at=0u;at<size;) {
    crypto_dtls_record_view v;
    if (!crypto_dtls_wire_record(bytes+at,size-at,&v)) return CRYPTO_DTLS_CLIENT_DROP;
    at+=v.record_size;
  }
  for (size_t at=0u;at<size;) {
    crypto_dtls_record_view v;
    if (!crypto_dtls_wire_record(bytes+at,size-at,&v)) return fail(s,SALTS_CRYPTO_ESTATE);
    const uint8_t *record=bytes+at; at+=v.record_size;
    if (!v.epoch) {
      if (v.type==22u) {
        if (v.payload_size && v.payload[0]==3u &&
            (s->phase==CRYPTO_DTLS_CLIENT_COOKIE || s->phase==CRYPTO_DTLS_CLIENT_HELLO)) {
          status=challenge(s,v.payload,v.payload_size);
        } else if (record[2]==0xff || s->phase==CRYPTO_DTLS_CLIENT_COOKIE) status=CRYPTO_DTLS_CLIENT_DROP;
        else status=fragments(s,v.payload,v.payload_size,false);
      } else if (v.type==20u && s->phase==CRYPTO_DTLS_CLIENT_FINISHED) {
        if (v.payload_size!=1u || v.payload[0]!=1u) { s->fatal.description=TLS_alert_decode_error; return reject(s,SALTS_CRYPTO_EVERIFY); }
        s->saw_ccs=s->read_epoch=true; status=admit_ready(s);
      } else if (v.type==21u && !s->read_epoch) {
        if (v.payload_size!=2u || (v.payload[0]!=1u && v.payload[0]!=2u)) {
          s->fatal.description=TLS_alert_decode_error; return reject(s,SALTS_CRYPTO_EVERIFY);
        }
        s->fatal.peer_description=v.payload[1]; return fail(s,SALTS_CRYPTO_EVERIFY);
      }
      else status=CRYPTO_DTLS_CLIENT_DROP;
    } else {
      if (!s->secrets.ready || v.epoch!=1u) continue;
      size_t plain_size=0u; uint8_t type=0u;
      status=crypto_dtls_record_open(&s->secrets.server_write,record,v.record_size,s->scratch,sizeof(s->scratch),&plain_size,&type);
      if (status==SALTS_CRYPTO_EVERIFY || status==CRYPTO_DTLS_RECORD_DROP) continue;
      if (status) return fail(s,status);
      s->read_epoch=true;
      if (type==22u) status=fragments(s,s->scratch,plain_size,true);
      else if (type==21u) {
        if (plain_size!=2u || (s->scratch[0]!=1u && s->scratch[0]!=2u)) {
          s->fatal.description=TLS_alert_decode_error; status=SALTS_CRYPTO_EVERIFY;
        } else if (s->scratch[0]==2u || s->scratch[1]!=0u) {
          s->fatal.peer_description=s->scratch[1]; return fail(s,SALTS_CRYPTO_EVERIFY);
        }
        else if (s->phase==CRYPTO_DTLS_CLIENT_READY) status=queued_alert(s);
        else if (s->phase==CRYPTO_DTLS_CLIENT_CLOSING) status=SALTS_CRYPTO_OK;
        else status=SALTS_CRYPTO_EVERIFY;
      } else if (type==23u && s->phase==CRYPTO_DTLS_CLIENT_READY) {
        s->in_callback=true; status=s->on_data(s->data_context,s->scratch,plain_size); s->in_callback=false;
        if (status) { s->fatal.description=TLS_alert_internal_error; status=SALTS_CRYPTO_EVERIFY; }
      } else status=CRYPTO_DTLS_CLIENT_DROP;
      salts_crypto_secure_zero(s->scratch,sizeof(s->scratch));
    }
    if (status<0) return reject(s,status);
    if (s->flight_index<s->flight_count) break;
  }
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_next(crypto_dtls_client *s,uint64_t now,const uint8_t **wire,size_t *size) {
  if (!s || !wire || !size || salts_crypto_overlap(s,sizeof(*s),wire,sizeof(*wire)) ||
      salts_crypto_overlap(s,sizeof(*s),size,sizeof(*size)) || salts_crypto_overlap(wire,sizeof(*wire),size,sizeof(*size)))
    return SALTS_CRYPTO_EINVAL;
  *wire=NULL; *size=0u;
  if (s->in_callback || s->phase==CRYPTO_DTLS_CLIENT_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase==CRYPTO_DTLS_CLIENT_FAILED) {
    if (s->pending) return CRYPTO_DTLS_CLIENT_BUSY;
    if (!s->fatal.size) return s->failure;
    memcpy(s->pending_wire,s->fatal.wire,s->fatal.size); s->pending_size=s->fatal.size;
    salts_crypto_secure_zero(s->fatal.wire,sizeof(s->fatal.wire)); s->fatal.size=0u;
    s->pending=true; *wire=s->pending_wire; *size=s->pending_size; return SALTS_CRYPTO_OK;
  }
  if (s->phase==CRYPTO_DTLS_CLIENT_CLOSED) return CRYPTO_DTLS_CLIENT_IDLE;
  int status=sample(s,now); if (status) return status;
  if (s->pending) return CRYPTO_DTLS_CLIENT_BUSY;
  if (s->flight_index==s->flight_count) {
    if (s->phase>=CRYPTO_DTLS_CLIENT_READY) return CRYPTO_DTLS_CLIENT_IDLE;
    bool due=false; status=crypto_dtls_flight_timer_poll(&s->timer,now,&due);
    if (status) return fail(s,SALTS_CRYPTO_ESTATE);
    if (!due) return CRYPTO_DTLS_CLIENT_IDLE;
    s->flight_index=s->flight_offset=0u;
  }
  crypto_dtls_client_flight *f=&s->flight[s->flight_index];
  const uint8_t *plain=f->data; size_t n=f->size;
  if (f->handshake_type) {
    const size_t limit=CRYPTO_DTLS_CLIENT_MTU-(f->encrypted ? CRYPTO_DTLS_RECORD_OVERHEAD : CRYPTO_DTLS_HEADER_SIZE)-12u;
    size_t fragment=f->size-s->flight_offset; if (fragment>limit) fragment=limit;
    status=crypto_dtls_fragment_write(f->handshake_type,f->sequence,f->data,f->size,s->flight_offset,fragment,
      s->scratch,sizeof(s->scratch),&n); if (status) return fail(s,status);
    plain=s->scratch; s->pending_advance=fragment;
  } else s->pending_advance=f->size;
  if (f->encrypted) {
    status=crypto_dtls_record_seal(&s->secrets.client_write,f->type,plain,n,
        s->pending_wire,sizeof(s->pending_wire),&s->pending_size);
  } else {
    if (s->plain_sequence>CRYPTO_DTLS_MAX_SEQUENCE || n>sizeof(s->pending_wire)-13u) return fail(s,SALTS_CRYPTO_ESTATE);
    uint8_t *p=s->pending_wire; p[0]=f->type; p[1]=0xfe; p[2]=0xfd; p[3]=p[4]=0u;
    uint64_t seq=s->plain_sequence++;
    for (size_t i=11u;i>5u;) { p[--i]=(uint8_t)seq; seq>>=8u; }
    put16(p+11u,n); memcpy(p+13u,plain,n); s->pending_size=13u+n;
  }
  salts_crypto_secure_zero(s->scratch,sizeof(s->scratch));
  if (status) return fail(s,status);
  s->pending=true; *wire=s->pending_wire; *size=s->pending_size; return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_sent(crypto_dtls_client *s,uint64_t now,bool success) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || !s->pending) return SALTS_CRYPTO_ESTATE;
  s->pending=false; s->pending_size=0u; salts_crypto_secure_zero(s->pending_wire,sizeof(s->pending_wire));
  if (s->phase==CRYPTO_DTLS_CLIENT_FAILED) { if (!success && s->fatal.description) s->fatal.error=SALTS_CRYPTO_ECRYPTO; return s->failure; }
  if (!success) return fail(s,SALTS_CRYPTO_ECRYPTO);
  int status=sample(s,now); if (status) return status;
  if (s->flight[s->flight_index].type==20u) s->write_epoch=true;
  s->flight_offset+=s->pending_advance;
  if (s->flight_offset>=s->flight[s->flight_index].size) { ++s->flight_index; s->flight_offset=0u; }
  if (s->flight_index==s->flight_count) {
    if (s->phase==CRYPTO_DTLS_CLIENT_CLOSING) {
      s->phase=CRYPTO_DTLS_CLIENT_CLOSED; crypto_dtls_secrets_clear(&s->secrets);
      salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=s->flight_index=0u;
    } else if (s->phase==CRYPTO_DTLS_CLIENT_READY) {
      salts_crypto_secure_zero(s->flight,sizeof(s->flight)); s->flight_count=s->flight_index=0u;
    } else {
      status=crypto_dtls_flight_timer_sent(&s->timer,now); if (status) return fail(s,status);
    }
  }
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_write(crypto_dtls_client *s,const void *data,size_t size) {
  if (!s || (!data && size) || size>CRYPTO_DTLS_CLIENT_MTU-CRYPTO_DTLS_RECORD_OVERHEAD ||
      salts_crypto_overlap(s,sizeof(*s),data,size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_CLIENT_READY) return SALTS_CRYPTO_ESTATE;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_CLIENT_BUSY;
  s->flight_count=1u; s->flight_index=s->flight_offset=0u;
  if (size) memcpy(s->flight[0].data,data,size);
  s->flight[0].size=size; s->flight[0].type=23u; s->flight[0].encrypted=true;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_close(crypto_dtls_client *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_CLIENT_READY) return SALTS_CRYPTO_ESTATE;
  if (s->pending || s->flight_index<s->flight_count) return CRYPTO_DTLS_CLIENT_BUSY;
  return queued_alert(s);
}
int crypto_dtls_client_export(const crypto_dtls_client *s,const crypto_dtls_export_request *r,void *out,size_t n) {
  if (!s || !r || salts_crypto_overlap(s,sizeof(*s),r,sizeof(*r))) return SALTS_CRYPTO_EINVAL;
  if (salts_crypto_overlap(s,sizeof(*s),out,n) || salts_crypto_overlap(s,sizeof(*s),r->label,r->label_size) ||
      salts_crypto_overlap(s,sizeof(*s),r->context,r->context_size)) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase!=CRYPTO_DTLS_CLIENT_READY || !s->exporter_enabled) return SALTS_CRYPTO_ESTATE;
  return crypto_dtls_exporter(&s->secrets,s->client_random,s->server_random,r,out,n);
}
int crypto_dtls_client_abort(crypto_dtls_client *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback || s->phase==CRYPTO_DTLS_CLIENT_ZERO) return SALTS_CRYPTO_ESTATE;
  if (s->phase!=CRYPTO_DTLS_CLIENT_FAILED && s->phase!=CRYPTO_DTLS_CLIENT_CLOSED) (void)fail(s,SALTS_CRYPTO_ESTATE);
  salts_crypto_secure_zero(s->fatal.wire,sizeof(s->fatal.wire)); s->fatal.size=0u;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_client_clear(crypto_dtls_client *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->in_callback) return SALTS_CRYPTO_ESTATE;
  if (s->pending) return CRYPTO_DTLS_CLIENT_BUSY;
  const crypto_tls_stream_peer_policy policy=s->policy; const bool retained=s->policy_retained;
  clear_identity(s);
  salts_crypto_secure_zero(s,sizeof(*s));
  if (retained) policy.release(policy.context);
  return SALTS_CRYPTO_OK;
}
