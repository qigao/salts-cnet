#include "crypto_dtls_wire.h"
#include <crypto/x509_der.h>
#include <gmssl/x509.h>
#include <gmssl/mem.h>
#include <string.h>

int crypto_dtls_dns_name(const char *p,size_t n) {
  if (!p || !n || n>CRYPTO_DTLS_WIRE_DNS_BYTES) return 0;
  size_t label=0; bool alpha=false;
  for (size_t i=0;i<n;++i) {
    const unsigned char ch=(unsigned char)p[i];
    if (ch=='.') { if (!label || p[i-1]=='-') return 0; label=0; continue; }
    const bool letter=(ch>='a' && ch<='z') || (ch>='A' && ch<='Z');
    if (!letter && !(ch>='0' && ch<='9') && ch!='-') return 0;
    if ((!label && ch=='-') || ++label>63u) return 0;
    alpha|=letter;
  }
  return label && p[n-1]!='-' && alpha;
}
int crypto_dtls_chain_views(const uint8_t *der,size_t size,crypto_tls_stream_peer_certificate_chain *out) {
  *out=(crypto_tls_stream_peer_certificate_chain){0};
  if (!size || size>CRYPTO_DTLS_WIRE_CHAIN_BYTES) return SALTS_CRYPTO_EVERIFY;
  const uint8_t *p=der; size_t remaining=size;
  while (remaining) {
    const uint8_t *cert; size_t n; crypto_x509_der_view view;
    if (out->count==CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES ||
        x509_cert_from_der(&cert,&n,&p,&remaining)!=1 ||
        crypto_x509_der_inspect(cert,n,&view)!=SALTS_ASN1_OK) return SALTS_CRYPTO_EVERIFY;
    out->certificates[out->count++]=(crypto_tls_stream_peer_certificate){cert,n};
  }
  out->total_bytes=size; return SALTS_CRYPTO_OK;
}
int crypto_dtls_wire_record(const uint8_t *p,size_t size,crypto_dtls_record_view *v) {
  if (size<13u || p[0]<20u || p[0]>23u || p[1]!=0xfe || (p[2]!=0xfd && p[2]!=0xff)) return 0;
  const size_t n=(size_t)p[11]*256u+p[12]; const uint16_t epoch=(uint16_t)((unsigned)p[3]*256u+p[4]);
  if (n>CRYPTO_DTLS_MAX_PLAINTEXT+(epoch ? CRYPTO_DTLS_AEAD_OVERHEAD : 0u) || n>size-13u ||
      (p[2]==0xff && (epoch || p[0]!=22u))) return 0;
  *v=(crypto_dtls_record_view){.payload=p+13u,.payload_size=n,.record_size=n+13u,.epoch=epoch,.type=p[0]};
  for (size_t i=5u;i<11u;++i) v->sequence=(v->sequence<<8u)|p[i];
  return 1;
}
void crypto_dtls_fatal_prepare(crypto_dtls_fatal *f,crypto_dtls_record_epoch *write,bool encrypted,
    uint64_t *sequence,uint8_t description) {
  f->description=description; f->size=0u; f->error=SALTS_CRYPTO_OK;
  gmssl_secure_clear(f->wire,sizeof(f->wire));
  const uint8_t body[]={2u,description};
  if (encrypted) {
    f->error=crypto_dtls_record_seal(write,21u,body,sizeof(body),f->wire,sizeof(f->wire),&f->size);
    return;
  }
  if (*sequence>CRYPTO_DTLS_MAX_SEQUENCE) { f->error=SALTS_CRYPTO_ESTATE; return; }
  uint8_t *p=f->wire; p[0]=21u; p[1]=0xfe; p[2]=0xfd; p[3]=p[4]=0;
  uint64_t n=(*sequence)++; for(size_t i=11u;i>5u;) {p[--i]=(uint8_t)n;n>>=8u;}
  p[11]=0u; p[12]=2u; memcpy(p+13u,body,sizeof(body)); f->size=15u;
}
