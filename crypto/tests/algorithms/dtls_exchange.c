#include "../../src/crypto_dtls_exchange.h"
#include "../../src/crypto_dtls_secrets.h"
#include <crypto/tls_cipher.h>
#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zero_bytes(const void *data,size_t size) {
  const uint8_t *p=data; unsigned combined=0; while (size--) combined|=*p++; return !combined;
}
static size_t read_fixture(const char *name,void *out,size_t capacity) {
  const char *path=getenv(name); check_true(path!=NULL); if (!path) return 0;
  FILE *file=fopen(path,"rb"); check_true(file!=NULL); if (!file) return 0;
  size_t n=fread(out,1u,capacity,file); check_true(!ferror(file)); check_equal(fgetc(file),EOF);
  check_equal(fclose(file),0); return n;
}
static void random_fixture(uint8_t client[32],uint8_t server[32]) {
  for (size_t i=0;i<32u;++i) { client[i]=(uint8_t)(32u+i); server[i]=(uint8_t)(64u+i); }
}

spec("Private DTLS ephemeral P256 ownership") {
  it("rejects invalid points and erases the private key on every admitted exchange") {
    const uint8_t prime[32]={0xff,0xff,0xff,0xff,0,0,0,1,0,0,0,0,0,0,0,0,
      0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    for (unsigned failure=0;failure<5u;++failure) {
      crypto_dtls_ephemeral s={0}; uint8_t point[65]={4},shared[32];
      check_equal(crypto_dtls_ephemeral_init(&s),0);
      if (failure==1u) point[0]=2u; /* compressed format */
      if (failure==2u) { memcpy(point+1u,prime,32u); point[64]=1u; }
      if (failure==3u) { point[32]=1u; memcpy(point+33u,prime,32u); }
      memset(shared,0xa5,sizeof(shared));
      check_equal(crypto_dtls_ephemeral_exchange(&s,failure==4u ? NULL : point,failure==4u ? 0u : sizeof(point),shared),SALTS_CRYPTO_EVERIFY);
      check_true(s.failed && !s.ready && !s.consumed); check_true(zero_bytes(&s.key,sizeof(s.key)));
      check_true(zero_bytes(shared,sizeof(shared))); check_equal(crypto_dtls_ephemeral_init(&s),SALTS_CRYPTO_ESTATE);
      check_equal(crypto_dtls_ephemeral_exchange(&s,point,sizeof(point),shared),SALTS_CRYPTO_ESTATE);
      crypto_dtls_ephemeral_clear(&s); check_true(zero_bytes(&s,sizeof(s)));
    }
  }
  it("preserves live keys on alias rejection and exports stable owned public bytes") {
    crypto_dtls_ephemeral s={0},before; uint8_t point[65],again[65],shared[32];
    check_equal(crypto_dtls_ephemeral_init(&s),0); before=s;
    check_equal(crypto_dtls_ephemeral_public(&s,point),0); check_equal(point[0],4u);
    check_equal(crypto_dtls_ephemeral_public(&s,again),0); check_equal(point,again,65u);
    check_equal(crypto_dtls_ephemeral_public(&s,(uint8_t *)&s),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_ephemeral_exchange(&s,&s,sizeof(s),shared),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_ephemeral_exchange(&s,point,65u,point),SALTS_CRYPTO_EINVAL);
    check_equal(&s,&before,sizeof(s)); check_equal(crypto_dtls_ephemeral_init(&s),SALTS_CRYPTO_ESTATE);
    crypto_dtls_ephemeral_clear(&s); crypto_dtls_ephemeral_clear(&before);
  }
}

spec("Independent DTLS ServerKeyExchange and ECDH oracle") {
  it("binds signed parameters and both randoms with exactly the negotiated scheme") {
    uint8_t certs[2][4096],bodies[2][1024],client[32],server[32],peer[65],bad[4097],copy[1024];
    size_t cert_size[2],body_size[2]; random_fixture(client,server);
    const char *cert_names[]={"SALTS_DTLS_EC_CERT","SALTS_DTLS_RSA_CERT"};
    const char *body_names[]={"SALTS_DTLS_EC_EXCHANGE","SALTS_DTLS_RSA_EXCHANGE"};
    const uint16_t ciphers[]={CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256,CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256};
    for (unsigned i=0;i<2u;++i) {
      cert_size[i]=read_fixture(cert_names[i],certs[i],sizeof(certs[i]));
      body_size[i]=read_fixture(body_names[i],bodies[i],sizeof(bodies[i]));
    }
    for (unsigned i=0;i<2u;++i) {
      const size_t n=body_size[i]; check_true(n>73u && n<sizeof(bodies[i])); if (n<=73u || n>=sizeof(bodies[i])) continue;
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],n,peer),0);
      check_equal(peer,bodies[i]+4u,65u);
      for (size_t short_size=0u;short_size<=73u;++short_size) {
        memset(peer,0xa5,sizeof(peer));
        check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],short_size,peer),SALTS_CRYPTO_EVERIFY);
        check_true(zero_bytes(peer,sizeof(peer)));
      }
      const size_t fields[]={0u,2u,3u,4u,69u,70u,71u,72u,n-1u};
      for (size_t k=0;k<sizeof(fields)/sizeof(fields[0]);++k) {
        memcpy(copy,bodies[i],n); copy[fields[k]]^=1u; memset(peer,0xa5,sizeof(peer));
        check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,copy,n,peer),SALTS_CRYPTO_EVERIFY);
        check_true(zero_bytes(peer,sizeof(peer)));
      }
      client[0]^=1u;
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],n,peer),SALTS_CRYPTO_EVERIFY);
      client[0]^=1u; server[31]^=1u;
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],n,peer),SALTS_CRYPTO_EVERIFY);
      server[31]^=1u;
      check_equal(crypto_dtls_server_exchange_verify(certs[1u-i],cert_size[1u-i],ciphers[i],client,server,bodies[i],n,peer),SALTS_CRYPTO_EVERIFY);
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[1u-i],client,server,bodies[i],n,peer),SALTS_CRYPTO_EVERIFY);
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],n-1u,peer),SALTS_CRYPTO_EVERIFY);
      memcpy(copy,bodies[i],n); copy[n]=0;
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,copy,n+1u,peer),SALTS_CRYPTO_EVERIFY);
      /* An exact outer vector must not make a signature's trailing junk legal. */
      copy[71]=(uint8_t)((n-72u)>>8u); copy[72]=(uint8_t)(n-72u);
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,copy,n+1u,peer),SALTS_CRYPTO_EVERIFY);
      memcpy(bad,certs[i],cert_size[i]); bad[cert_size[i]]=0;
      check_equal(crypto_dtls_server_exchange_verify(bad,cert_size[i]+1u,ciphers[i],client,server,bodies[i],n,peer),SALTS_CRYPTO_EVERIFY);
      memcpy(copy,bodies[i],n);
      check_equal(crypto_dtls_server_exchange_verify(certs[i],cert_size[i],ciphers[i],client,server,bodies[i],n,bodies[i]),SALTS_CRYPTO_EINVAL);
      check_equal(copy,bodies[i],n);
    }
  }
  it("derives fresh one-use ECDH keys and EMS records from independently signed peer parameters") {
    uint8_t cert[4096],body[1024],peer[65],client[32],server[32],hash[32],output[378],shared[32];
    size_t cert_size=read_fixture("SALTS_DTLS_EC_CERT",cert,sizeof(cert));
    size_t body_size=read_fixture("SALTS_DTLS_EC_EXCHANGE",body,sizeof(body)),at=0;
    random_fixture(client,server); memset(hash,0x11,sizeof(hash));
    check_equal(crypto_dtls_server_exchange_verify(cert,cert_size,CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256,
        client,server,body,body_size,peer),0);
    for (unsigned run=0;run<2u;++run) {
      crypto_dtls_ephemeral ephemeral={0}; crypto_dtls_secrets secrets={0}; uint8_t pub[65],wire[64]; size_t n;
      check_equal(crypto_dtls_ephemeral_init(&ephemeral),0); check_equal(crypto_dtls_ephemeral_public(&ephemeral,pub),0);
      check_equal(crypto_dtls_ephemeral_exchange(&ephemeral,peer,sizeof(peer),shared),0);
      check_true(ephemeral.consumed && !ephemeral.ready && !ephemeral.failed); check_true(zero_bytes(&ephemeral.key,sizeof(ephemeral.key)));
      check_equal(crypto_dtls_secrets_derive(&secrets,shared,hash,client,server),0);
      memcpy(output+at,pub,sizeof(pub)); at+=sizeof(pub); memcpy(output+at,shared,32u); at+=32u;
      memcpy(output+at,secrets.master,48u); at+=48u;
      check_equal(crypto_dtls_record_seal(&secrets.client_write,23u,"client!",7u,wire,sizeof(wire),&n),0);
      check_equal(n,44u); memcpy(output+at,wire,n); at+=n;
      check_equal(crypto_dtls_ephemeral_exchange(&ephemeral,peer,sizeof(peer),shared),SALTS_CRYPTO_ESTATE);
      check_true(zero_bytes(shared,sizeof(shared)));
      check_equal(crypto_dtls_ephemeral_public(&ephemeral,pub),SALTS_CRYPTO_ESTATE); check_true(zero_bytes(pub,sizeof(pub)));
      crypto_dtls_ephemeral_clear(&ephemeral); crypto_dtls_secrets_clear(&secrets);
    }
    check_equal(at,sizeof(output));
    const char *path=getenv("SALTS_DTLS_EXCHANGE_OUTPUT"); check_true(path!=NULL);
    FILE *file=path ? fopen(path,"wb") : NULL; check_true(file!=NULL);
    if (file) { check_equal(fwrite(output,1u,at,file),at); check_equal(fclose(file),0); }
  }
}
