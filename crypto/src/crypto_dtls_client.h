#ifndef CRYPTO_DTLS_CLIENT_INTERNAL_H
#define CRYPTO_DTLS_CLIENT_INTERNAL_H
#include "crypto_dtls_exchange.h"
#include "crypto_dtls_secrets.h"
#include "crypto_dtls_wire.h"
#include <crypto/tls_peer_policy.h>
#include <crypto/tls_credentials.h>
#include <gmssl/tls.h>

enum { CRYPTO_DTLS_CLIENT_IDLE=1, CRYPTO_DTLS_CLIENT_BUSY=2, CRYPTO_DTLS_CLIENT_DROP=3,
       CRYPTO_DTLS_CLIENT_MTU=1200, CRYPTO_DTLS_CLIENT_CHAIN_BYTES=CRYPTO_DTLS_WIRE_CHAIN_BYTES,
       CRYPTO_DTLS_CLIENT_MAX_CHALLENGES=8, CRYPTO_DTLS_CLIENT_DNS_BYTES=CRYPTO_DTLS_WIRE_DNS_BYTES };
typedef enum crypto_dtls_client_phase {
  CRYPTO_DTLS_CLIENT_ZERO, CRYPTO_DTLS_CLIENT_COOKIE, CRYPTO_DTLS_CLIENT_HELLO,
  CRYPTO_DTLS_CLIENT_CERTIFICATE, CRYPTO_DTLS_CLIENT_KEY, CRYPTO_DTLS_CLIENT_DONE,
  CRYPTO_DTLS_CLIENT_FINISHED, CRYPTO_DTLS_CLIENT_READY, CRYPTO_DTLS_CLIENT_CLOSING,
  CRYPTO_DTLS_CLIENT_CLOSED, CRYPTO_DTLS_CLIENT_FAILED
} crypto_dtls_client_phase;
typedef struct crypto_dtls_client_config {
  const void *roots; size_t roots_size;
  const char *server_name; size_t server_name_size;
  const void *alpn; size_t alpn_size;
  const crypto_tls_stream_peer_policy *peer_policy;
  int (*on_data)(void *context,const uint8_t *data,size_t size);
  void *data_context; /* Caller keeps alive until successful clear; no reentry. */
  const crypto_tls_credentials *credentials; /* Optional sole client identity. */
  bool enable_exporter; /* Retains master until close/abort/clear; default false. */
} crypto_dtls_client_config;
typedef struct crypto_dtls_client_flight {
  uint8_t data[CRYPTO_DTLS_CLIENT_CHAIN_BYTES+18];
  size_t size;
  uint16_t sequence; uint8_t type,handshake_type; bool encrypted;
} crypto_dtls_client_flight;
typedef struct crypto_dtls_client {
  crypto_dtls_reassembly messages;
  crypto_dtls_transcript transcript;
  crypto_dtls_ephemeral ephemeral;
  crypto_dtls_secrets secrets;
  crypto_dtls_flight_timer timer;
  crypto_dtls_fatal fatal;
  crypto_dtls_client_flight flight[5];
  TLS_CTX identity;
  uint8_t roots[CRYPTO_DTLS_CLIENT_CHAIN_BYTES],chain[CRYPTO_DTLS_CLIENT_CHAIN_BYTES];
  uint8_t pending_wire[CRYPTO_DTLS_CLIENT_MTU],scratch[CRYPTO_DTLS_MAX_PLAINTEXT];
  uint8_t client_random[32],server_random[32],peer_point[65],server_finished[12];
  uint8_t cookie[255],alpn[255]; char server_name[CRYPTO_DTLS_CLIENT_DNS_BYTES+1];
  size_t roots_size,chain_size,chain_count,alpn_size,server_name_size,cookie_size;
  size_t flight_count,flight_index,flight_offset,pending_size,pending_advance,identity_chain_size;
  uint64_t plain_sequence,last_now;
  uint32_t client_sequence,server_first;
  unsigned challenges;
  uint16_t cipher,signature,server_done_sequence;
  crypto_dtls_client_phase phase;
  int failure,verify_result; size_t verify_index;
  crypto_tls_stream_peer_policy policy;
  int (*on_data)(void *context,const uint8_t *data,size_t size); void *data_context;
  bool pending,clock_sampled,policy_retained,in_callback,saw_ccs,verified_finished;
  bool requested_certificate,selected_identity,exporter_enabled;
  bool write_epoch,read_epoch;
} crypto_dtls_client;

/* PRIVATE staged client owner, no public DTLS/provider capability. Exclusive
 * zero/cleared state; config DER roots/DNS/ALPN copied, policy retained on success.
 * Optional identity imported at init; input/object/password borrows end there.
 * Key erased after final-flight construction or failure; cached proof permits
 * retransmission without signing again. No tickets, downgrade or worker. */
int crypto_dtls_client_init(crypto_dtls_client *state,const crypto_dtls_client_config *config);
/* Output borrows until EXACTLY ONE sent terminal; BUSY publishes no new view.
 * Always report the actual native terminal, including after abort. After a
 * protocol error next may publish ONE prepared fatal alert while phase remains
 * FAILED. sent still returns the original failure. Alerts are never retried. */
int crypto_dtls_client_next(crypto_dtls_client *state,uint64_t now,const uint8_t **wire,size_t *size);
int crypto_dtls_client_sent(crypto_dtls_client *state,uint64_t now,bool success);
/* Whole peer datagram, immutable until return including during data callbacks;
 * BUSY consumes nothing while output is pending/unsent. Caller's input and all
 * output descriptors must not overlap state. */
int crypto_dtls_client_receive(crypto_dtls_client *state,uint64_t now,const void *wire,size_t size);
int crypto_dtls_client_write(crypto_dtls_client *state,const void *plain,size_t size);
int crypto_dtls_client_close(crypto_dtls_client *state);
/* Exclusive owner, authenticated READY only, including during a pending send.
 * Rejects callback reentry and all input/output overlap with owner storage. */
int crypto_dtls_client_export(const crypto_dtls_client *,const crypto_dtls_export_request *,void *,size_t);
int crypto_dtls_client_abort(crypto_dtls_client *state);
int crypto_dtls_client_data_failed(crypto_dtls_client *);
/* Requires actual terminal of every prepared send; BUSY leaves storage alive. */
int crypto_dtls_client_clear(crypto_dtls_client *state);
#endif
