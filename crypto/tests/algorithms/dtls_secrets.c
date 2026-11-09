#include "../../src/crypto_dtls_secrets.h"
#include "../../src/crypto_dtls_client.h"
#include "../../src/crypto_dtls_server.h"
#include <gmssl/tls.h>
#include <tinytest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int all_zero(const void *data,size_t size) {
  const uint8_t *p=data; unsigned combined=0; while (size--) combined|=*p++; return combined==0;
}
static void inputs(uint8_t shared[32],uint8_t client[32],uint8_t server[32]) {
  for (size_t i=0;i<32u;++i) { shared[i]=(uint8_t)i; client[i]=(uint8_t)(i+32u); server[i]=(uint8_t)(i+64u); }
}
/* Synthetic bodies exercise canonical framing and cryptographic derivation;
 * they are deliberately not a certificate, ECDHE proof or network handshake. */
static void transcript_fixture(crypto_dtls_transcript *t) {
  const crypto_dtls_message messages[]={
    {.body=(const uint8_t *)"client hello",.size=12,.sequence=1,.type=1},
    {.body=(const uint8_t *)"server hello",.size=12,.sequence=1,.type=2},
    {.body=(const uint8_t *)"certificate",.size=11,.sequence=2,.type=11},
    {.body=(const uint8_t *)"key exchange",.size=12,.sequence=3,.type=12},
    {.sequence=4,.type=14},
    {.body=(const uint8_t *)"key",.size=3,.sequence=2,.type=16}
  };
  check_equal(crypto_dtls_transcript_init(t,1u,1u),0);
  for (size_t i=0;i<sizeof(messages)/sizeof(messages[0]);++i)
    check_equal(crypto_dtls_transcript_append(t,i==0u || i==5u ? CRYPTO_DTLS_CLIENT : CRYPTO_DTLS_SERVER,&messages[i]),0);
}
static void append_proof(crypto_dtls_transcript *t) {
  const crypto_dtls_message message={.body=(const uint8_t *)"proof",.size=5,.sequence=3,.type=15};
  check_equal(crypto_dtls_transcript_append(t,CRYPTO_DTLS_CLIENT,&message),0);
}

spec("Private DTLS fatal alert construction and send terminals") {
  it("uses actual write epoch, reserves one nonce and refuses plaintext fallback on encryption failure") {
    crypto_dtls_fatal f={0}; crypto_dtls_record_epoch epoch={0}; uint64_t plain=7u;
    const uint8_t key[16]={1},salt[4]={2};
    crypto_dtls_fatal_prepare(&f,&epoch,false,&plain,TLS_alert_handshake_failure);
    check_equal(f.error,0);check_equal(f.size,15u);check_equal(plain,8u);
    const uint8_t expected[]={21,0xfe,0xfd,0,0,0,0,0,0,0,7,0,2,2,40};check_equal(f.wire,expected,sizeof(expected));
    check_equal(crypto_dtls_record_init(&epoch,1u,key,salt),0);
    crypto_dtls_fatal_prepare(&f,&epoch,true,&plain,TLS_alert_decrypt_error);
    check_equal(f.error,0);check_equal(f.size,39u);check_equal(epoch.next_send,1u);check_equal(plain,8u);
    crypto_dtls_record_epoch peer={0};check_equal(crypto_dtls_record_init(&peer,1u,key,salt),0);
    uint8_t body[2],type;size_t n;
    check_equal(crypto_dtls_record_open(&peer,f.wire,f.size,body,sizeof(body),&n,&type),0);
    check_equal(type,21u);check_equal(n,2u);check_equal(body[0],2u);check_equal(body[1],51u);
    epoch.next_send=CRYPTO_DTLS_MAX_SEQUENCE+1u;
    crypto_dtls_fatal_prepare(&f,&epoch,true,&plain,TLS_alert_decrypt_error);
    check_true(f.error<0);check_equal(f.size,0u);check_equal(plain,8u);check_true(all_zero(f.wire,sizeof(f.wire)));
    plain=CRYPTO_DTLS_MAX_SEQUENCE+1u;
    crypto_dtls_fatal_prepare(&f,&epoch,false,&plain,TLS_alert_decode_error);
    check_equal(f.error,SALTS_CRYPTO_ESTATE);check_equal(f.size,0u);check_true(all_zero(f.wire,sizeof(f.wire)));
    crypto_dtls_record_clear(&epoch);crypto_dtls_record_clear(&peer);
  }
  it("keeps a failed owner's prepared fatal stable until its real terminal and never retries it") {
    /* Synthetic FAILED states test ownership only, not handshake admission. */
    static crypto_dtls_client client;static crypto_dtls_server server;uint8_t saved[39];
    memset(&client,0,sizeof(client));memset(&server,0,sizeof(server));
    client.phase=CRYPTO_DTLS_CLIENT_FAILED;client.failure=SALTS_CRYPTO_EVERIFY;
    server.phase=CRYPTO_DTLS_SERVER_FAILED;server.failure=SALTS_CRYPTO_EVERIFY;
    crypto_dtls_fatal_prepare(&client.fatal,&client.secrets.client_write,false,&client.plain_sequence,40u);
    crypto_dtls_fatal_prepare(&server.fatal,&server.secrets.server_write,false,&server.plain_sequence,40u);
    const uint8_t *wire,*other;size_t n,m;
    check_equal(crypto_dtls_client_next(&client,0u,&wire,&n),0);memcpy(saved,wire,n);
    check_equal(crypto_dtls_client_next(&client,0u,&other,&m),CRYPTO_DTLS_CLIENT_BUSY);check_true(!other);check_equal(m,0u);
    check_equal(crypto_dtls_client_clear(&client),CRYPTO_DTLS_CLIENT_BUSY);check_equal(crypto_dtls_client_abort(&client),0);check_equal(wire,saved,n);
    check_equal(crypto_dtls_client_sent(&client,0u,false),SALTS_CRYPTO_EVERIFY);check_equal(client.fatal.error,SALTS_CRYPTO_ECRYPTO);
    check_equal(crypto_dtls_client_next(&client,100000u,&wire,&n),SALTS_CRYPTO_EVERIFY);check_equal(n,0u);check_equal(crypto_dtls_client_clear(&client),0);
    check_equal(crypto_dtls_server_next(&server,0u,&wire,&n),0);memcpy(saved,wire,n);
    check_equal(crypto_dtls_server_next(&server,0u,&other,&m),CRYPTO_DTLS_SERVER_BUSY);
    check_equal(crypto_dtls_server_clear(&server),CRYPTO_DTLS_SERVER_BUSY);check_equal(crypto_dtls_server_abort(&server),0);check_equal(wire,saved,n);
    check_equal(crypto_dtls_server_sent(&server,0u,true),SALTS_CRYPTO_EVERIFY);
    check_equal(crypto_dtls_server_next(&server,100000u,&wire,&n),SALTS_CRYPTO_EVERIFY);check_equal(n,0u);check_equal(crypto_dtls_server_clear(&server),0);
  }
  it("preserves the protocol failure when alert sealing exhausts a nonce and never emits plaintext instead") {
    static crypto_dtls_client client;memset(&client,0,sizeof(client));
    const uint8_t key[16]={1},salt[4]={2},bad_alert[3]={2,40,0};uint8_t wire[64];size_t n;
    crypto_dtls_record_epoch peer={0};check_equal(crypto_dtls_record_init(&peer,1u,key,salt),0);
    check_equal(crypto_dtls_record_seal(&peer,21u,bad_alert,sizeof(bad_alert),wire,sizeof(wire),&n),0);
    check_equal(crypto_dtls_record_init(&client.secrets.server_write,1u,key,salt),0);
    check_equal(crypto_dtls_record_init(&client.secrets.client_write,1u,key,salt),0);
    client.phase=CRYPTO_DTLS_CLIENT_READY;client.cookie_size=1u;client.write_epoch=client.read_epoch=true;client.secrets.ready=true;
    client.secrets.client_write.next_send=CRYPTO_DTLS_MAX_SEQUENCE+1u;
    check_equal(crypto_dtls_client_receive(&client,0u,wire,n),SALTS_CRYPTO_EVERIFY);
    check_equal(client.failure,SALTS_CRYPTO_EVERIFY);check_equal(client.fatal.error,SALTS_CRYPTO_ESTATE);
    check_equal(client.fatal.size,0u);check_true(all_zero(client.fatal.wire,sizeof(client.fatal.wire)));
    check_true(all_zero(&client.secrets,sizeof(client.secrets)));check_true(all_zero(client.scratch,sizeof(client.scratch)));
    const uint8_t *out;check_equal(crypto_dtls_client_next(&client,0u,&out,&n),SALTS_CRYPTO_EVERIFY);check_true(!out);check_equal(n,0u);
    check_equal(crypto_dtls_client_clear(&client),0);crypto_dtls_record_clear(&peer);
  }
}

spec("Private DTLS exporter primitive and admission boundaries") {
  it("separates absent and empty context and forgets the master without damaging traffic epochs") {
    crypto_dtls_secrets s={0},before; uint8_t shared[32],client[32],server[32],hash[32]={0},a[65],b[65];
    inputs(shared,client,server); check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),0); before=s;
    crypto_dtls_export_request r={"EXPERIMENTAL-test",17u,NULL,0u,false};
    check_equal(crypto_dtls_exporter(&s,client,server,&r,a,sizeof(a)),0);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,b,sizeof(b)),0); check_true(!memcmp(a,b,sizeof(a)));
    check_equal(&s,&before,sizeof(s)); r.use_context=true;
    check_equal(crypto_dtls_exporter(&s,client,server,&r,b,sizeof(b)),0); check_true(memcmp(a,b,sizeof(a))!=0);
    crypto_dtls_secrets_forget_master(&s); check_true(all_zero(s.master,sizeof(s.master))); check_false(s.master_live);
    check_equal(&s.client_write,&before.client_write,sizeof(s.client_write)); check_equal(&s.server_write,&before.server_write,sizeof(s.server_write));
    memset(a,0xa5,sizeof(a)); check_equal(crypto_dtls_exporter(&s,client,server,&r,a,sizeof(a)),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_finished_verify(&s,CRYPTO_DTLS_CLIENT,hash,a,12u),SALTS_CRYPTO_ESTATE);
    check_equal(&s.client_write,&before.client_write,sizeof(s.client_write)); check_true(s.ready && !s.failed);
    for(size_t i=0;i<sizeof(a);++i) check_equal(a[i],0xa5u);
    crypto_dtls_secrets_clear(&s); crypto_dtls_secrets_clear(&before);
    memset(a,0,sizeof(a)); memset(b,0,sizeof(b));
  }
  it("rejects reserved labels, invalid bounds and aliases without writing or changing admitted secrets") {
    crypto_dtls_secrets s={0},before; uint8_t shared[32],client[32],server[32],hash[32]={0},output[1026],context[1025]={0};
    char label[256]; memset(label,'x',sizeof(label)); inputs(shared,client,server);
    check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),0); before=s;
    crypto_dtls_export_request r={label,255u,context,1024u,true}; memset(output,0xa5,sizeof(output));
    check_equal(crypto_dtls_exporter(&s,client,server,&r,output+1u,1024u),0);
    check_equal(output[0],0xa5u); check_equal(output[1025],0xa5u);
    r.label_size=256u; check_equal(crypto_dtls_exporter(&s,client,server,&r,output,32u),SALTS_CRYPTO_EINVAL); r.label_size=255u;
    r.context_size=1025u; check_equal(crypto_dtls_exporter(&s,client,server,&r,output,32u),SALTS_CRYPTO_EINVAL); r.context_size=1024u;
    r.use_context=false; check_equal(crypto_dtls_exporter(&s,client,server,&r,output,32u),SALTS_CRYPTO_EINVAL); r.use_context=true;
    check_equal(crypto_dtls_exporter(&s,client,server,&r,output,1025u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,output,0u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,s.master,32u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,client,32u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,&r,32u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_exporter(&s,client,server,&r,context,32u),SALTS_CRYPTO_EINVAL);
    r.label=s.master; r.label_size=32u; check_equal(crypto_dtls_exporter(&s,client,server,&r,output,32u),SALTS_CRYPTO_EINVAL);
    const char *bad[]={"client finished","server finished","master secret","key expansion","extended master secret","key","master secretary",""};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
      r.label=bad[i];r.label_size=strlen(bad[i]);memset(output,0xa5,sizeof(output));
      check_equal(crypto_dtls_exporter(&s,client,server,&r,output,32u),SALTS_CRYPTO_EINVAL);
      bool intact=true; for(size_t j=0;j<sizeof(output);++j) intact&=output[j]==0xa5u; check_true(intact);
    }
    check_equal(&s,&before,sizeof(s)); crypto_dtls_secrets_clear(&s); crypto_dtls_secrets_clear(&before); memset(output,0,sizeof(output));
  }
  it("rejects owner callback reentry and owner or listener storage aliases") {
    static crypto_dtls_client client; static crypto_dtls_server server; static crypto_dtls_server_context context;
    memset(&client,0,sizeof(client)); memset(&server,0,sizeof(server)); memset(&context,0,sizeof(context));
    crypto_dtls_export_request r={"EXPERIMENTAL-owner",18u,NULL,0u,false}; uint8_t output[32]; memset(output,0xa5,sizeof(output));
    client.phase=CRYPTO_DTLS_CLIENT_READY; client.exporter_enabled=true; client.in_callback=true;
    server.phase=CRYPTO_DTLS_SERVER_READY; server.context=&context; context.exporter_enabled=true; server.in_callback=true;
    check_equal(crypto_dtls_client_export(&client,&r,output,sizeof(output)),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_server_export(&server,&r,output,sizeof(output)),SALTS_CRYPTO_ESTATE);
    client.in_callback=server.in_callback=false;
    check_equal(crypto_dtls_client_export(&client,&r,client.pending_wire,32u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_server_export(&server,&r,server.pending_wire,32u),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_server_export(&server,&r,&context,32u),SALTS_CRYPTO_EINVAL);
    r.label=client.pending_wire; check_equal(crypto_dtls_client_export(&client,&r,output,sizeof(output)),SALTS_CRYPTO_EINVAL);
    r.label=context.server_name; check_equal(crypto_dtls_server_export(&server,&r,output,sizeof(output)),SALTS_CRYPTO_EINVAL);
    for(size_t i=0;i<sizeof(output);++i) check_equal(output[i],0xa5u);
    memset(&client,0,sizeof(client));memset(&server,0,sizeof(server));memset(&context,0,sizeof(context));
  }
}

spec("Private DTLS EMS transcript and Finished lifecycle") {
  it("takes stable snapshots and rejects duplicate, pre-cookie and overflowing transcripts transactionally") {
    crypto_dtls_transcript t={0},before; uint8_t first[32],second[32];
    check_equal(crypto_dtls_transcript_hash(&t,first),SALTS_CRYPTO_ESTATE); check_true(all_zero(first,sizeof(first)));
    check_equal(crypto_dtls_transcript_init(&t,1u,1u),0); before=t;
    crypto_dtls_message m={.body=(const uint8_t *)"client hello",.size=12,.sequence=0,.type=1};
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_CLIENT,&m),SALTS_CRYPTO_EVERIFY);
    check_equal(&t,&before,sizeof(t)); m.sequence=1;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),SALTS_CRYPTO_EVERIFY);
    check_equal(&t,&before,sizeof(t));
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_CLIENT,&m),0); before=t;
    check_equal(crypto_dtls_transcript_hash(&t,first),0); check_equal(crypto_dtls_transcript_hash(&t,second),0);
    check_equal(first,second,sizeof(first)); check_equal(&t,&before,sizeof(t));
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_CLIENT,&m),SALTS_CRYPTO_EVERIFY);
    check_equal(&t,&before,sizeof(t)); m.type=3;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),SALTS_CRYPTO_EVERIFY);
    check_equal(&t,&before,sizeof(t)); m.type=2; m.body=(const uint8_t *)&t;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),SALTS_CRYPTO_EINVAL);
    check_equal(&t,&before,sizeof(t));
    check_equal(crypto_dtls_transcript_hash(&t,(uint8_t *)&t),SALTS_CRYPTO_EINVAL);
    m.body=NULL; m.size=0; m.type=14; m.sequence=UINT16_MAX; t.next[1]=UINT16_MAX;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),0); check_equal(t.next[1],65536u); before=t;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),SALTS_CRYPTO_ESTATE);
    check_equal(&t,&before,sizeof(t)); t.next[1]=1; m.sequence=1;
    t.bytes=CRYPTO_DTLS_TRANSCRIPT_MAX_BYTES-12u;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),0); before=t; m.sequence=2;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_SERVER,&m),SALTS_CRYPTO_ESTATE);
    check_equal(&t,&before,sizeof(t)); crypto_dtls_transcript_clear(&t); check_true(all_zero(&t,sizeof(t)));
  }
  it("starts at the admitted post-cookie sequences after a renewed challenge") {
    crypto_dtls_transcript t={0},before; uint8_t actual[32],expected[32],canonical[24];
    check_equal(crypto_dtls_transcript_init(&t,0u,1u),SALTS_CRYPTO_EINVAL); check_true(all_zero(&t,sizeof(t)));
    check_equal(crypto_dtls_transcript_init(&t,2u,1u),0); before=t;
    crypto_dtls_message m={.body=(const uint8_t *)"client hello",.size=12u,.type=1u,.sequence=1u};
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_CLIENT,&m),SALTS_CRYPTO_EVERIFY);
    check_equal(&t,&before,sizeof(t)); m.sequence=2u;
    check_equal(crypto_dtls_transcript_append(&t,CRYPTO_DTLS_CLIENT,&m),0);
    const uint8_t header[]={1,0,0,12,0,2,0,0,0,0,0,12};
    memcpy(canonical,header,12u); memcpy(canonical+12u,m.body,12u);
    SHA256_CTX digest; sha256_init(&digest); sha256_update(&digest,canonical,sizeof(canonical)); sha256_finish(&digest,expected);
    check_equal(crypto_dtls_transcript_hash(&t,actual),0); check_equal(actual,expected,sizeof(actual));
    check_equal(t.next[0],3u); check_equal(t.next[1],1u); crypto_dtls_transcript_clear(&t);
  }
  it("erases both directional epochs and the master on wrong role, hash, body or Finished length") {
    uint8_t shared[32],client[32],server[32],hash[32],claimed[13]={0}; inputs(shared,client,server);
    crypto_dtls_transcript t={0}; transcript_fixture(&t); check_equal(crypto_dtls_transcript_hash(&t,hash),0);
    for (unsigned failure=0;failure<6;++failure) {
      crypto_dtls_secrets s={0},before;
      check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),0); check_true(s.ready && !s.failed); before=s;
      check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),SALTS_CRYPTO_ESTATE);
      check_equal(crypto_dtls_finished(&s,CRYPTO_DTLS_CLIENT,hash,claimed),0);
      check_equal(crypto_dtls_finished_verify(&s,CRYPTO_DTLS_CLIENT,hash,claimed,12u),0);
      check_equal(&s,&before,sizeof(s));
      uint8_t wrong_hash[32]; memcpy(wrong_hash,hash,32u); wrong_hash[0]^=1u;
      if (failure==2u) claimed[11]^=1u;
      check_equal(crypto_dtls_finished_check(&s,failure==0u ? CRYPTO_DTLS_SERVER : CRYPTO_DTLS_CLIENT,
          failure==1u ? wrong_hash : hash,failure==4u ? NULL : claimed,
          failure==3u || failure==4u ? 0u : failure==5u ? 13u : 12u),SALTS_CRYPTO_EVERIFY);
      check_equal(&s,&before,sizeof(s));
      check_equal(crypto_dtls_finished_verify(&s,failure==0u ? CRYPTO_DTLS_SERVER : CRYPTO_DTLS_CLIENT,
          failure==1u ? wrong_hash : hash,failure==4u ? NULL : claimed,
          failure==3u || failure==4u ? 0u : failure==5u ? 13u : 12u),SALTS_CRYPTO_EVERIFY);
      check_true(s.failed && !s.ready); s.failed=false; check_true(all_zero(&s,sizeof(s))); s.failed=true;
      check_equal(crypto_dtls_finished(&s,CRYPTO_DTLS_CLIENT,hash,claimed),SALTS_CRYPTO_ESTATE);
      check_true(all_zero(claimed,sizeof(claimed)));
      check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),SALTS_CRYPTO_ESTATE);
      uint8_t wire[64]; size_t n=1;
      check_equal(crypto_dtls_record_seal(&s.client_write,23u,"x",1u,wire,sizeof(wire),&n),SALTS_CRYPTO_ESTATE);
      check_equal(n,0u); crypto_dtls_secrets_clear(&s); check_true(all_zero(&s,sizeof(s)));
    }
    crypto_dtls_transcript_clear(&t);
  }
  it("rejects aliases without damaging admitted keys or borrowed inputs") {
    crypto_dtls_secrets s={0},before; uint8_t shared[32],client[32],server[32],hash[32]={0}; inputs(shared,client,server);
    check_equal(crypto_dtls_secrets_derive(&s,s.master,hash,client,server),SALTS_CRYPTO_EINVAL);
    check_true(all_zero(&s,sizeof(s))); check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),0); before=s;
    check_equal(crypto_dtls_finished(&s,CRYPTO_DTLS_CLIENT,hash,s.master),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_finished_verify(&s,CRYPTO_DTLS_CLIENT,hash,s.master,12u),SALTS_CRYPTO_EINVAL);
    check_equal(&s,&before,sizeof(s)); crypto_dtls_secrets_clear(&s); crypto_dtls_secrets_clear(&before);
  }
}

/* Native provider callbacks allow failures inside each HMAC stage without a
 * replacement PRF or production test switch. This fixture has one thread. */
static unsigned digest_calls[3],fail_kind,fail_at;
static int fault_init(DIGEST_CTX *c) {
  if (++digest_calls[0]==fail_at && fail_kind==0u) return -1;
  return DIGEST_sha256()->init(c);
}
static int fault_update(DIGEST_CTX *c,const uint8_t *data,size_t size) {
  if (++digest_calls[1]==fail_at && fail_kind==1u) return -1;
  return DIGEST_sha256()->update(c,data,size);
}
static int fault_finish(DIGEST_CTX *c,uint8_t *out) {
  if (++digest_calls[2]==fail_at && fail_kind==2u) return -1;
  return DIGEST_sha256()->finish(c,out);
}
spec("GmSSL PRF fail-fast provider contract") {
  it("propagates every digest callback failure and clears all requested output including partial blocks") {
    DIGEST digest=*DIGEST_sha256(); digest.init=fault_init; digest.update=fault_update; digest.finish=fault_finish;
    const uint8_t shared[32]={1},seed[32]={2},more[32]={3}; uint8_t out[67]; unsigned totals[3];
    memset(digest_calls,0,sizeof(digest_calls)); fail_at=0;
    check_equal(tls_prf(&digest,shared,sizeof(shared),"oracle",seed,sizeof(seed),more,sizeof(more),65u,out+1u),1);
    memcpy(totals,digest_calls,sizeof(totals));
    for (fail_kind=0;fail_kind<3u;++fail_kind) {
      check_true(totals[fail_kind]>0u);
      for (fail_at=1;fail_at<=totals[fail_kind];++fail_at) {
        memset(digest_calls,0,sizeof(digest_calls)); memset(out,0xa5,sizeof(out));
        check_equal(tls_prf(&digest,shared,sizeof(shared),"oracle",seed,sizeof(seed),more,sizeof(more),65u,out+1u),-1);
        check_equal(digest_calls[fail_kind],fail_at); check_true(all_zero(out+1u,65u));
        check_equal(out[0],0xa5u); check_equal(out[66],0xa5u);
      }
    }
    fail_at=0; memset(out,0xa5,sizeof(out));
    check_equal(tls_prf(DIGEST_sha256(),shared,32u,"oracle",NULL,32u,NULL,0u,65u,out+1u),-1);
    for (size_t i=0;i<sizeof(out);++i) check_equal(out[i],0xa5u);
  }
}

spec("Independent Python EMS key expansion and Finished oracle") {
  it("verifies Python Finished proofs and exports test-only keys and directional records") {
    const char *path=getenv("SALTS_DTLS_SECRETS"),*proofs=getenv("SALTS_DTLS_PROOFS"); check_true(path && proofs);
    if (path && proofs) {
      crypto_dtls_transcript t={0}; crypto_dtls_secrets s={0}; uint8_t shared[32],client[32],server[32],hash[32];
      uint8_t output[257],expected[25],prf[65],wire[64]; size_t at=0,n; inputs(shared,client,server);
      transcript_fixture(&t); check_equal(crypto_dtls_transcript_hash(&t,hash),0);
      check_equal(crypto_dtls_secrets_derive(&s,shared,hash,client,server),0); append_proof(&t);
      check_equal(crypto_dtls_transcript_hash(&t,hash),0);
      memcpy(output+at,s.master,48u); at+=48u; memcpy(output+at,hash,32u); at+=32u;
      FILE *file=fopen(proofs,"rb"); check_true(file!=NULL); n=0;
      if (file) { n=fread(expected,1u,sizeof(expected),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
      check_equal(n,24u);
      for (unsigned sender=0;sender<2u;++sender) {
        check_equal(crypto_dtls_finished(&s,(crypto_dtls_sender)sender,hash,output+at),0); at+=12u;
        if (n==24u) check_equal(crypto_dtls_finished_verify(&s,(crypto_dtls_sender)sender,hash,expected+12u*sender,12u),0);
      }
      check_equal(tls_prf(DIGEST_sha256(),shared,32u,"oracle",client,32u,server,32u,sizeof(prf),prf),1);
      memcpy(output+at,prf,sizeof(prf)); at+=sizeof(prf);
      check_equal(crypto_dtls_record_seal(&s.client_write,23u,"client!",7u,wire,sizeof(wire),&n),0);
      check_equal(n,44u); memcpy(output+at,wire,n); at+=n;
      check_equal(crypto_dtls_record_seal(&s.server_write,23u,"server!",7u,wire,sizeof(wire),&n),0);
      check_equal(n,44u); memcpy(output+at,wire,n); at+=n; check_equal(at,sizeof(output));
      file=fopen(path,"wb"); check_true(file!=NULL);
      if (file) { check_equal(fwrite(output,1u,at,file),at); check_equal(fclose(file),0); }
      crypto_dtls_secrets_clear(&s); crypto_dtls_transcript_clear(&t);
    }
  }
}
