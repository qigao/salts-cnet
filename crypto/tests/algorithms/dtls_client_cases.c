#include "../../src/crypto_dtls_client.h"
#include <tinytest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fixture_policy { int references,checks,reentry;crypto_dtls_stream *public_stream; } fixture_policy;
static void retain_policy(void *p) { ++((fixture_policy *)p)->references; }
static void release_policy(void *p) {
  fixture_policy *policy=p;--policy->references;
  if(policy->public_stream){policy->reentry=crypto_dtls_stream_destroy(policy->public_stream);policy->public_stream=NULL;}
}
static int check_policy(void *p,const crypto_tls_stream_peer_certificate_chain *chain,bool server,crypto_tls_stream_security_profile profile) {
  ++((fixture_policy *)p)->checks; return !chain->count || !server || profile!=CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD;
}
static int unused_data(void *p,const uint8_t *data,size_t size) { (void)p; (void)data; (void)size; return 0; }
static int opaque_data(void *p,crypto_dtls_stream *stream,const uint8_t *data,size_t size) { (void)p;(void)stream;(void)data;(void)size;return 0; }
static int zero_memory(const void *p,size_t n) { const uint8_t *v=p; unsigned all=0; while (n--) all|=*v++; return !all; }
static size_t read_key(const char *name,uint8_t *out,size_t capacity) {
  const char *path=getenv(name); check_true(path!=NULL);
  FILE *file=path ? fopen(path,"rb") : NULL; check_true(file!=NULL); size_t n=0;
  if (file) { n=fread(out,1u,capacity,file); check_true(!ferror(file)); check_equal(fgetc(file),EOF); check_equal(fclose(file),0); }
  return n;
}
spec("Private DTLS client owner admission and send terminals") {
  static crypto_dtls_client state;
  static uint8_t roots[4096],saved[CRYPTO_DTLS_CLIENT_MTU];
  static size_t roots_size;
  static fixture_policy policy_state;
  static crypto_tls_stream_peer_policy policy;
  static crypto_dtls_client_config config;
  before_each() {
    memset(&state,0,sizeof(state)); policy_state=(fixture_policy){0};
    policy=(crypto_tls_stream_peer_policy){check_policy,retain_policy,release_policy,&policy_state,
      CRYPTO_TLS_PEER_POLICY_STANDARD,CRYPTO_TLS_PEER_POLICY_SERVER};
    const char *path=getenv("SALTS_DTLS_EC_CERT"); check_true(path!=NULL);
    FILE *file=path ? fopen(path,"rb") : NULL; check_true(file!=NULL); roots_size=0;
    if (file) { roots_size=fread(roots,1u,sizeof(roots),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
    config=(crypto_dtls_client_config){roots,roots_size,"localhost",9u,"test",4u,&policy,unused_data,NULL};
  }
  after_each() {
    if (state.pending) { check_equal(crypto_dtls_client_abort(&state),0); check_equal(crypto_dtls_client_sent(&state,state.last_now,true),SALTS_CRYPTO_ESTATE); }
    check_equal(crypto_dtls_client_clear(&state),0);
    if(policy_state.public_stream){
      crypto_dtls_stream *stream=policy_state.public_stream;crypto_dtls_stream_info info;
      check_equal(crypto_dtls_stream_get_info(stream,&info),0);check_equal(crypto_dtls_stream_abort(stream),0);
      if(info.pending_send)check_true(crypto_dtls_stream_sent(stream,0u,false)<0);
      check_equal(crypto_dtls_stream_destroy(stream),0);
    }
    check_equal(policy_state.references,0);
  }
  it("fails invalid roots, DNS, ALPN and unsupported policy before retain or network admission") {
    const char *names[]={"127.0.0.1","-host","host..test","host-","host.","bad_host"};
    for (size_t i=0;i<sizeof(names)/sizeof(names[0]);++i) {
      config.server_name=names[i]; config.server_name_size=strlen(names[i]);
      check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL);
      check_true(zero_memory(&state,sizeof(state))); check_equal(policy_state.references,0);
    }
    config.server_name="localhost"; config.server_name_size=9u; config.alpn_size=256u;
    check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); config.alpn_size=4u;
    policy.supported_profiles=CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13;
    check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); policy.supported_profiles=CRYPTO_TLS_PEER_POLICY_STANDARD;
    policy.retain=NULL; check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); policy.retain=retain_policy;
    config.roots_size=1u; check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL);
    check_true(zero_memory(&state,sizeof(state))); check_equal(policy_state.references,0);
  }
  it("keeps native output stable through BUSY and abort until its actual terminal") {
    check_equal(crypto_dtls_client_init(&state,&config),0); check_equal(policy_state.references,1);
    check_equal(state.roots,roots,roots_size); roots[0]^=1u; check_not_equal(state.roots[0],roots[0]); roots[0]^=1u;
    const uint8_t *wire; size_t n; check_equal(crypto_dtls_client_next(&state,100u,&wire,&n),0);
    const size_t first_size=n; check_true(n>60u && n<=sizeof(saved)); memcpy(saved,wire,n);
    check_equal(state.timer.phase,CRYPTO_DTLS_TIMER_IDLE);
    check_equal(crypto_dtls_client_clear(&state),CRYPTO_DTLS_CLIENT_BUSY);
    const uint8_t *again=(const uint8_t *)1; n=1u;
    check_equal(crypto_dtls_client_next(&state,101u,&again,&n),CRYPTO_DTLS_CLIENT_BUSY); check_true(!again); check_equal(n,0u);
    check_equal(crypto_dtls_client_receive(&state,101u,saved,first_size),CRYPTO_DTLS_CLIENT_BUSY);
    check_equal(wire,saved,first_size); check_equal(crypto_dtls_client_write(&state,"x",1u),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_client_abort(&state),0); check_equal(state.phase,CRYPTO_DTLS_CLIENT_FAILED);
    check_true(zero_memory(&state.secrets,sizeof(state.secrets))); check_equal(wire,saved,first_size);
    check_equal(crypto_dtls_client_clear(&state),CRYPTO_DTLS_CLIENT_BUSY); check_equal(policy_state.references,1);
    check_equal(crypto_dtls_client_sent(&state,102u,true),SALTS_CRYPTO_ESTATE); check_true(!state.pending);
    check_true(zero_memory(state.pending_wire,sizeof(state.pending_wire)));
    check_equal(crypto_dtls_client_sent(&state,102u,true),SALTS_CRYPTO_ESTATE);
  }
  it("imports an independent client identity and erases it on abort while preserving the pending wire") {
    uint8_t key[4096]; const size_t n=read_key("SALTS_DTLS_EC_KEY",key,sizeof(key));
    crypto_tls_credentials credentials={.size=sizeof(credentials),.certificate_chain={roots,roots_size,CRYPTO_TLS_ENCODING_DER},
      .private_key={key,n,CRYPTO_TLS_ENCODING_DER}};
    config.credentials=&credentials;
    check_equal(crypto_dtls_client_init(&state,&config),0); check_equal(policy_state.references,1);
    check_equal(state.identity.x509_keys_cnt,1u);
    check_false(zero_memory(state.identity.x509_keys[0].u.secp256r1_key.private_key,
      sizeof(state.identity.x509_keys[0].u.secp256r1_key.private_key)));
    check_true(state.identity.cert_chains+3u!=roots);
    check_equal(state.identity.cert_chains+3u,roots,roots_size);
    memset(key,0,sizeof(key)); memset(&credentials,0,sizeof(credentials));
    const uint8_t *wire; size_t size; check_equal(crypto_dtls_client_next(&state,0u,&wire,&size),0);
    memcpy(saved,wire,size); check_equal(crypto_dtls_client_abort(&state),0);
    check_true(zero_memory(&state.identity,sizeof(state.identity))); check_equal(wire,saved,size);
    check_equal(crypto_dtls_client_clear(&state),CRYPTO_DTLS_CLIENT_BUSY);
    check_equal(policy_state.references,1); check_equal(crypto_dtls_client_sent(&state,1u,true),SALTS_CRYPTO_ESTATE);
  }
  it("rejects invalid, aliased and mismatched client credentials before retaining policy or sending") {
    uint8_t key[4096]; size_t n=read_key("SALTS_DTLS_RSA_KEY",key,sizeof(key));
    crypto_tls_credentials credentials={.size=sizeof(credentials),.certificate_chain={roots,roots_size,CRYPTO_TLS_ENCODING_DER},
      .private_key={key,n,CRYPTO_TLS_ENCODING_DER}};
    config.credentials=&credentials;
    check_true(crypto_dtls_client_init(&state,&config)<0); check_true(zero_memory(&state,sizeof(state)));
    check_equal(policy_state.references,0); credentials.size=0u;
    check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); check_true(zero_memory(&state,sizeof(state)));
    credentials.size=sizeof(credentials); credentials.private_key.data=state.pending_wire;
    check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); check_true(zero_memory(&state,sizeof(state)));
    config.credentials=(const crypto_tls_credentials *)&state;
    check_equal(crypto_dtls_client_init(&state,&config),SALTS_CRYPTO_EINVAL); check_true(zero_memory(&state,sizeof(state)));
    memset(key,0,sizeof(key)); check_equal(policy_state.references,0);
  }
  it("owns opaque client inputs and rejects destruction during send or policy-release reentry") {
    crypto_dtls_stream_config c={.roots={roots,roots_size,CRYPTO_TLS_ENCODING_DER},.server_name="localhost",.server_name_size=9u,
      .peer_policy=&policy,.on_data=NULL};
    crypto_dtls_stream *stream=(crypto_dtls_stream *)1;
    check_equal(crypto_dtls_stream_create(NULL,&stream),SALTS_CRYPTO_EINVAL);check_true(!stream);
    check_equal(crypto_dtls_stream_create(&c,&stream),SALTS_CRYPTO_EINVAL);check_true(!stream);check_equal(policy_state.references,0);
    /* Same callback shape, opaque owner never reaches this fixture during hello. */
    c.on_data=opaque_data;
    check_equal(crypto_dtls_stream_create(&c,&stream),0);check_true(stream!=NULL);check_equal(policy_state.references,1);
    policy_state.public_stream=stream;const uint8_t *wire;size_t n;
    uint8_t proof[32],unchanged[32];memset(proof,0x5a,sizeof(proof));memcpy(unchanged,proof,sizeof(proof));
    const crypto_dtls_export_request request={"EXPERIMENTAL-unit",17u,NULL,0u,false};
    check_equal(crypto_dtls_stream_hmac(stream,&request,"test",4u,proof),SALTS_CRYPTO_ESTATE);
    check_equal(proof,unchanged,sizeof(proof));
    check_equal(crypto_dtls_stream_hmac(stream,&request,proof,sizeof(proof),proof),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_stream_hmac(stream,&request,"test",CRYPTO_DTLS_MAC_INPUT_BYTES+1u,proof),SALTS_CRYPTO_EINVAL);
    check_equal(proof,unchanged,sizeof(proof));
    roots[0]^=1u;check_equal(crypto_dtls_stream_next(stream,0u,&wire,&n),0);roots[0]^=1u;
    check_true(n>60u);memcpy(saved,wire,n);
    crypto_dtls_stream_info info;check_equal(crypto_dtls_stream_get_info(stream,&info),0);check_equal(info.state,CRYPTO_DTLS_HANDSHAKING);check_true(info.pending_send);
    check_equal(crypto_dtls_stream_destroy(stream),CRYPTO_DTLS_BUSY);check_equal(wire,saved,n);
    check_equal(crypto_dtls_stream_abort(stream),0);check_equal(crypto_dtls_stream_sent(stream,0u,false),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_stream_destroy(stream),0);check_equal(policy_state.references,0);check_equal(policy_state.reentry,SALTS_CRYPTO_ESTATE);
  }
  it("retransmits logical messages with a fresh record sequence and arms after actual whole-flight send") {
    const uint8_t *wire; size_t n; check_equal(crypto_dtls_client_init(&state,&config),0);
    check_equal(crypto_dtls_client_next(&state,0u,&wire,&n),0); const size_t first=n; memcpy(saved,wire,n);
    check_equal(crypto_dtls_client_sent(&state,100u,true),0); check_equal(state.timer.deadline,1100u);
    check_equal(crypto_dtls_client_next(&state,1099u,&wire,&n),CRYPTO_DTLS_CLIENT_IDLE);
    check_equal(crypto_dtls_client_next(&state,1100u,&wire,&n),0); check_equal(n,first);
    check_not_equal(wire+5u,saved+5u,6u); check_equal(wire+13u,saved+13u,n-13u);
    check_equal(crypto_dtls_client_next(&state,2000u,&wire,&n),CRYPTO_DTLS_CLIENT_BUSY);
    check_equal(crypto_dtls_client_sent(&state,2000u,true),0); check_equal(state.timer.deadline,4000u);
  }
  it("preserves terminal failure on exhausted retries, failed sends and backward clocks") {
    const uint8_t *wire; size_t n; check_equal(crypto_dtls_client_init(&state,&config),0);
    uint64_t now=0;
    for (unsigned i=0;i<=6u;++i) {
      check_equal(crypto_dtls_client_next(&state,now,&wire,&n),0);
      check_equal(crypto_dtls_client_sent(&state,now,true),0); now=state.timer.deadline;
    }
    check_equal(crypto_dtls_client_next(&state,now,&wire,&n),SALTS_CRYPTO_ESTATE);
    check_equal(state.phase,CRYPTO_DTLS_CLIENT_FAILED); check_true(zero_memory(&state.secrets,sizeof(state.secrets)));
    check_equal(crypto_dtls_client_clear(&state),0); check_equal(policy_state.references,0);
    check_equal(crypto_dtls_client_init(&state,&config),0); check_equal(crypto_dtls_client_next(&state,100u,&wire,&n),0);
    check_equal(crypto_dtls_client_sent(&state,99u,true),SALTS_CRYPTO_ESTATE); check_true(!state.pending);
    check_equal(crypto_dtls_client_clear(&state),0);
    check_equal(crypto_dtls_client_init(&state,&config),0); check_equal(crypto_dtls_client_next(&state,100u,&wire,&n),0);
    check_equal(crypto_dtls_client_sent(&state,101u,false),SALTS_CRYPTO_ECRYPTO); check_true(!state.pending);
    check_equal(state.phase,CRYPTO_DTLS_CLIENT_FAILED);
  }
}
