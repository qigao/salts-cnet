#ifndef CRYPTO_DTLS_SECRETS_INTERNAL_H
#define CRYPTO_DTLS_SECRETS_INTERNAL_H
#include "crypto_dtls_handshake.h"
#include "crypto_dtls_record.h"
#include <gmssl/sha2.h>
#include <crypto/dtls_stream.h>

enum { CRYPTO_DTLS_TRANSCRIPT_MAX_BYTES=131072, CRYPTO_DTLS_FINISHED_BYTES=12 };
typedef enum crypto_dtls_sender { CRYPTO_DTLS_CLIENT=0, CRYPTO_DTLS_SERVER=1 } crypto_dtls_sender;
typedef struct crypto_dtls_transcript {
  SHA256_CTX hash;
  size_t bytes;
  uint32_t next[2];
  bool ready, started;
} crypto_dtls_transcript;
typedef struct crypto_dtls_secrets {
  uint8_t master[48];
  crypto_dtls_record_epoch client_write,server_write;
  bool ready, failed,master_live;
} crypto_dtls_secrets;

/* Private RFC5705 SHA256 primitive; the owner separately enforces authenticated
 * READY and explicit enablement. Printable ASCII label, nonempty bounded output.
 * No input/output/state overlap; invalid arguments/state leave output unchanged.
 * Success writes exactly size bytes; PRF failure clears those bytes. No retain,
 * logging or state mutation. Exported bytes belong to caller, who erases them. */
int crypto_dtls_exporter(const crypto_dtls_secrets *,const uint8_t client_random[32],
    const uint8_t server_random[32],const crypto_dtls_export_request *,void *output,size_t size);
void crypto_dtls_secrets_forget_master(crypto_dtls_secrets *);

/* Private cookie-required DTLS1.2 profile. Semantic message order, signatures
 * and certificate trust are validated by the handshake owner BEFORE append.
 * Complete canonical messages only. The owner supplies each side's first
 * post-cookie sequence (normally one, possibly higher after new challenges).
 * Excluded CH/HVR messages never append. No public SHA context cloning. */
int crypto_dtls_transcript_init(crypto_dtls_transcript *state,uint16_t first_client,uint16_t first_server);
void crypto_dtls_transcript_clear(crypto_dtls_transcript *state);
int crypto_dtls_transcript_append(crypto_dtls_transcript *state,crypto_dtls_sender sender,
    const crypto_dtls_message *message);
int crypto_dtls_transcript_hash(const crypto_dtls_transcript *state,uint8_t hash[32]);

/* Validated P256 ECDH input and SHA256 session_hash through ClientKeyExchange.
 * EMS only. Distinct directional epoch-one keys are committed atomically;
 * no key-block or shared-secret pointer is retained. Zero/cleared state only.
 * Inputs are disjoint from state. Admitted derivation failure is terminal. */
int crypto_dtls_secrets_derive(crypto_dtls_secrets *state,const uint8_t shared[32],
    const uint8_t session_hash[32],const uint8_t client_random[32],const uint8_t server_random[32]);
void crypto_dtls_secrets_clear(crypto_dtls_secrets *state);
int crypto_dtls_finished(const crypto_dtls_secrets *state,crypto_dtls_sender sender,
    const uint8_t transcript_hash[32],uint8_t out[CRYPTO_DTLS_FINISHED_BYTES]);
/* Caller supplies an already AEAD-authenticated Finished body. A wrong body,
 * role or transcript proof erases keys/master and permanently fails this state.
 * Header order and committing a successful Finished into the transcript remain
 * the handshake owner's responsibility; this is not a READY decision. */
int crypto_dtls_finished_verify(crypto_dtls_secrets *state,crypto_dtls_sender sender,
    const uint8_t transcript_hash[32],const void *claimed,size_t size);
/* Pure proof check for an owner that must seal a fatal BEFORE immediate key
 * erasure on failure. It never grants READY; owner must terminate on error. */
int crypto_dtls_finished_check(const crypto_dtls_secrets *,crypto_dtls_sender,
    const uint8_t transcript_hash[32],const void *claimed,size_t size);
#endif
