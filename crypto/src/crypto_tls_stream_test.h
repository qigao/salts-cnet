/* Private formal-test diagnostics; not installed. */
#ifndef CRYPTO_TLS_STREAM_TEST_H
#define CRYPTO_TLS_STREAM_TEST_H
#include <crypto/tls_stream.h>
int crypto_tls_stream_test_der_bundle_required_size(size_t current, size_t appended, size_t *out_required);
int crypto_tls_stream_test_receive_record_gate(unsigned phase, const uint8_t *cipher, size_t size, bool *out_ready);
int crypto_tls_stream_diagnostic_send_stats(const crypto_tls_stream *state, size_t *calls, size_t *requested, size_t *accepted, size_t *queued);
#endif
