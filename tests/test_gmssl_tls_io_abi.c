/* Provider ABI, paired CipherBIO TLS close and direct NativeIO qualification.
 * CNet and independent-peer conformance have separate formal tests.
 * This executable links the actual pinned GmSSL provider. */
#include <tinytest.h>
#include <crypto/tls_close.h>
#include <crypto/cipher_bio.h>
#include <crypto/tls_stream.h>
#include <gmssl/tls.h>
#include <gmssl/pem.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_cer.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <native_io.h>
#include <clock.h>
#include <cmeta_buffer.h>
#include <error_codes.h>
#include <thread.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET native_tls_socket;
#define NATIVE_TLS_INVALID INVALID_SOCKET
static void native_tls_socket_close(native_tls_socket s) { if (s != INVALID_SOCKET) (void)closesocket(s); }
static int native_tls_nonblocking(native_tls_socket s) { u_long on = 1u; return ioctlsocket(s, FIONBIO, &on); }
static bool native_tls_would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>
typedef int native_tls_socket;
#define NATIVE_TLS_INVALID (-1)
static void native_tls_socket_close(native_tls_socket s) { if (s >= 0) (void)close(s); }
static int native_tls_nonblocking(native_tls_socket s) {
  const int flags = fcntl(s, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(s, F_SETFL, flags | O_NONBLOCK);
}
static bool native_tls_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif
#include "tls_mixed_workload.h"

static crypto_tls_stream_context *stream_context[2];
static crypto_tls_stream *stream_pair[2];

#include "tls_memory_credentials_cases.h"
#include "tls_hrr_padding_cases.h"

spec("GmSSL purpose diagnostics preserve parsing and prior results") {
  it("missing extensions and other constraints keep their original categories") {
    uint8_t extensions[128];
    size_t size = 0u;
    int result = X509_verify_err_expired;
    check_equal(x509_exts_check_ex(NULL, 0u, X509_cert_server_auth, &result), 1);
    check_equal(result, X509_verify_err_expired);
    check_equal(x509_exts_add_basic_constraints(extensions, &size, sizeof(extensions), 1, 1, -1), 1);
    check_equal(x509_exts_check_ex(extensions, size, X509_cert_server_auth, &result), -1);
    check_equal(result, X509_verify_err_expired);
  }
  for (unsigned eku = 0u; eku < 2u; ++eku) {
    for (unsigned invalid = 0u; invalid < 2u; ++invalid) {
      it("decoded %s role %u preserves the original verifier result contract", eku ? "EKU" : "KU", invalid) {
        uint8_t extensions[128];
        size_t size = 0u;
        int result = X509_verify_err_expired;
        const int purpose = invalid ? OID_kp_client_auth : OID_kp_server_auth;
        if (eku)
          check_equal(x509_exts_add_ext_key_usage(extensions, &size, sizeof(extensions), 0, &purpose, 1u), 1);
        else
          check_equal(x509_exts_add_key_usage(extensions, &size, sizeof(extensions), 1,
              invalid ? X509_KU_KEY_ENCIPHERMENT : X509_KU_DIGITAL_SIGNATURE), 1);
        check_equal(x509_exts_check_ex(extensions, size, X509_cert_server_auth, &result), invalid ? -1 : 1);
        check_equal(result, invalid ? X509_verify_err_purpose : X509_verify_err_expired);
        check_equal(x509_exts_check(extensions, size, X509_cert_server_auth), invalid ? -1 : 1);
        result = X509_verify_err_expired;
        check_equal(x509_exts_check_ex(extensions, size - 1u, X509_cert_server_auth, &result), -1);
        check_equal(result, X509_verify_err_expired);
      }
    }
  }
}

static void transfer_stream_cipher(unsigned from, unsigned to) {
  uint8_t wire[32768];
  size_t size = 0u;
  int result = crypto_tls_stream_take_cipher(stream_pair[from], wire, sizeof(wire), &size);
  check(result == CRYPTO_TLS_STREAM_OK || result == CRYPTO_TLS_STREAM_ENOENT);
  if (size != 0u)
    check_equal(crypto_tls_stream_feed_cipher(stream_pair[to], wire, size),
                CRYPTO_TLS_STREAM_OK);
}

static void establish_stream_pair(crypto_tls_stream_protocol_version protocol) {
  crypto_tls_stream_client_config client = {sizeof(client)};
  crypto_tls_stream_server_config server = {sizeof(server)};
  bool complete[2] = {false, false};
  crypto_tls_cipher_suite suites[] = {CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256,
      CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256};
  client.cipher_suites = server.cipher_suites = suites;
  client.cipher_suite_count = server.cipher_suite_count = 2u;
  crypto_tls_signature_scheme signatures[] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256,
      CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256};
  client.signature_algorithms = server.signature_algorithms = signatures;
  client.signature_algorithm_count = server.signature_algorithm_count = 2u;
  client.ca_file = CRYPTO_CLOSE_TEST_CA;
  server.cert_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
  server.key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
  check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]), CRYPTO_TLS_STREAM_OK);
  check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]), CRYPTO_TLS_STREAM_OK);
  memset(suites, 0, sizeof(suites));
  memset(signatures, 0, sizeof(signatures));
  for (unsigned i = 0u; i < 2u; ++i) {
    check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
                  i == 0u ? "localhost" : NULL, 32768u, &stream_pair[i]), CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol), CRYPTO_TLS_STREAM_OK);
  }
  for (unsigned step = 0u; step < 128u && !(complete[0] && complete[1]); ++step) {
    for (unsigned i = 0u; i < 2u; ++i) {
      check_equal(crypto_tls_stream_handshake(stream_pair[i], &complete[i]), CRYPTO_TLS_STREAM_OK);
      transfer_stream_cipher(i, 1u - i);
    }
  }
  check(complete[0] && complete[1]);
}

spec("Opaque Crypto streams retain policy and bounded storage") {
  before_each() {
    memset(stream_context, 0, sizeof(stream_context));
    memset(stream_pair, 0, sizeof(stream_pair));
  }
  after_each() {
    for (unsigned i = 0; i < 2u; ++i) {
      crypto_tls_stream_destroy(stream_pair[i]);
      crypto_tls_stream_context_release(stream_context[i]);
    }
  }
  for (unsigned scenario = 0u; scenario < 15u; ++scenario) {
    it("TLS13 HRR admits only permitted ClientHello2 padding changes, case %u", scenario) {
      tls_test_hrr_padding(scenario);
    }
  }
  it("TLS13 range server rejects a ClientHello offering only TLS12 suites before ServerHello") {
    crypto_tls_stream_client_config client = {.size = sizeof(client), .ca_file = CRYPTO_CLOSE_TEST_CA};
    crypto_tls_stream_server_config server = {.size = sizeof(server),
        .cert_file = CRYPTO_CLOSE_TEST_SERVER_CERT, .key_file = CRYPTO_CLOSE_TEST_SERVER_KEY};
    check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]), CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]), CRYPTO_TLS_STREAM_OK);
    for (unsigned i = 0u; i < 2u; ++i)
      check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
          i ? NULL : "localhost", 32768u, &stream_pair[i]), CRYPTO_TLS_STREAM_OK);
    bool complete = false;
    unsigned char hello[32768]; size_t size = 0u;
    check_equal(crypto_tls_stream_handshake(stream_pair[0], &complete), CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_take_cipher(stream_pair[0], hello, sizeof(hello), &size), CRYPTO_TLS_STREAM_OK);
    check(size > 44u && hello[0] == 22u && hello[5] == 1u);
    size_t offset = 44u + hello[43]; /* Record, handshake, legacy version/random, session ID. */
    check(offset + 2u <= size);
    size_t length = ((size_t)hello[offset] << 8u) | hello[offset + 1u]; offset += 2u;
    check(length > 0u && length % 2u == 0u && offset + length <= size);
    unsigned replaced = 0u;
    for (size_t i = offset; i < offset + length; i += 2u) {
      if (hello[i] == 0x13u && hello[i + 1u] == 1u) {
        hello[i] = 0xc0u; hello[i + 1u] = 0x2fu; ++replaced;
      }
    }
    check_equal(replaced, 1u);
    check_equal(crypto_tls_stream_feed_cipher(stream_pair[1], hello, size), CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_handshake(stream_pair[1], &complete), CRYPTO_TLS_STREAM_ECONNABORTED);
    check_false(complete);
    check_equal(crypto_tls_stream_take_cipher(stream_pair[1], hello, sizeof(hello), &size), CRYPTO_TLS_STREAM_OK);
    check(size >= 7u && hello[0] == 21u); /* Fatal alert, never a ServerHello. */
  }
  for (unsigned version = 12u; version <= 13u; ++version) {
    it("TLS %u peer alert does not invent a certificate verification result", version) {
      tls_memory_contexts(CRYPTO_TLS_ENCODING_DER, 0u, version, 0u);
      check_equal(crypto_tls_stream_create(stream_context[0], false, "localhost", 32768u,
          &stream_pair[0]), CRYPTO_TLS_STREAM_OK);
      bool complete = false;
      check_equal(crypto_tls_stream_handshake(stream_pair[0], &complete), CRYPTO_TLS_STREAM_OK);
      const unsigned char alert[] = {21, 3, 3, 0, 2, 2, 40};
      check_equal(crypto_tls_stream_feed_cipher(stream_pair[0], alert, sizeof(alert)), CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_stream_handshake(stream_pair[0], &complete), CRYPTO_TLS_STREAM_ECONNABORTED);
      crypto_tls_diagnostic diagnostic;
      check_equal(crypto_tls_stream_get_diagnostic(stream_pair[0], &diagnostic), CRYPTO_TLS_STREAM_OK);
      check_equal(diagnostic.reason, CRYPTO_TLS_FAILURE_HANDSHAKE);
      check_equal(diagnostic.certificate_index, SIZE_MAX);
    }
    it("TLS %u retains its first identity diagnostic across rejected retries", version) {
      crypto_tls_diagnostic diagnostic = {CRYPTO_TLS_FAILURE_CERTIFICATE, 99u};
      check_equal(crypto_tls_stream_get_diagnostic(NULL, &diagnostic), CRYPTO_TLS_STREAM_EINVAL);
      check_equal(diagnostic.reason, CRYPTO_TLS_FAILURE_NONE);
      tls_memory_contexts(CRYPTO_TLS_ENCODING_DER, 0u, version, 0u);
      for (unsigned i = 0u; i < 2u; ++i) {
        check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
            i ? NULL : "127.0.0.2", 32768u, &stream_pair[i]), CRYPTO_TLS_STREAM_OK);
        check_equal(crypto_tls_stream_get_diagnostic(stream_pair[i], &diagnostic), CRYPTO_TLS_STREAM_ENOENT);
        check_equal(diagnostic.reason, CRYPTO_TLS_FAILURE_NONE);
      }
      bool complete[2] = {false, false};
      int failure = CRYPTO_TLS_STREAM_OK;
      for (unsigned step = 0u; step < 128u && failure == CRYPTO_TLS_STREAM_OK; ++step) {
        failure = crypto_tls_stream_handshake(stream_pair[0], &complete[0]);
        if (failure != CRYPTO_TLS_STREAM_OK) break;
        transfer_stream_cipher(0u, 1u);
        check_equal(crypto_tls_stream_handshake(stream_pair[1], &complete[1]), CRYPTO_TLS_STREAM_OK);
        transfer_stream_cipher(1u, 0u);
      }
      check_equal(failure, CRYPTO_TLS_STREAM_ECONNABORTED);
      check_false(complete[0]);
      check_equal(crypto_tls_stream_get_diagnostic(stream_pair[0], NULL), CRYPTO_TLS_STREAM_EINVAL);
      for (unsigned retry = 0u; retry < 3u; ++retry) {
        complete[0] = true;
        check_equal(crypto_tls_stream_handshake(stream_pair[0], &complete[0]), failure);
        check_false(complete[0]);
        check_equal(crypto_tls_stream_get_diagnostic(stream_pair[0], &diagnostic), CRYPTO_TLS_STREAM_OK);
        check_equal(diagnostic.reason, CRYPTO_TLS_FAILURE_IDENTITY);
        check_equal(diagnostic.certificate_index, (size_t)0u);
      }
    }
  }
  for (unsigned encoding = 1u; encoding <= 2u; ++encoding) {
    for (unsigned bad = 0u; bad < 4u; ++bad) {
      it("server identity set encoding %u admits all four or rejects atomically, case %u", encoding, bad) {
        tls_memory_identity_bounds(encoding, bad);
      }
    }
    for (unsigned bad = 1u; bad <= 19u; ++bad) {
      it("memory credentials encoding %u reject invalid input %u without a context", encoding, bad) {
        tls_memory_contexts(encoding, bad, 0u, 0u);
      }
    }
    for (unsigned encrypted = 2u; encrypted <= 18u; ++encrypted) {
      if (encrypted == 17u) continue; /* Empty-password positive below. */
      it("encrypted memory credentials encoding %u reject invalid input %u", encoding, encrypted) {
        tls_memory_contexts(encoding, 0u, 0u, encrypted);
      }
    }
    for (unsigned password_case = 0u; password_case <= 2u; ++password_case) {
      unsigned encrypted = password_case == 2u ? 17u : password_case;
      for (unsigned version = 12u; version <= 13u; ++version) {
        it("memory credentials encoding %u encrypted %u survive source erasure for TLS %u", encoding, encrypted, version) {
          tls_memory_contexts(encoding, 0u, version, encrypted);
          bool complete[2] = {false, false};
          for (unsigned i = 0u; i < 2u; ++i) {
            check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
                i ? NULL : "localhost", 32768u, &stream_pair[i]), CRYPTO_TLS_STREAM_OK);
            crypto_tls_stream_context_release(stream_context[i]); stream_context[i] = NULL;
            check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], 12, 13), CRYPTO_TLS_STREAM_ENOTSUP);
            check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], 0, 0), CRYPTO_TLS_STREAM_OK);
            check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], version, version), CRYPTO_TLS_STREAM_OK);
          }
          for (unsigned step = 0u; step < 128u && !(complete[0] && complete[1]); ++step) {
            for (unsigned i = 0u; i < 2u; ++i) {
              check_equal(crypto_tls_stream_handshake(stream_pair[i], &complete[i]), CRYPTO_TLS_STREAM_OK);
              transfer_stream_cipher(i, 1u - i);
            }
          }
          check(complete[0] && complete[1]);
          bool written = false, closed = false;
          char byte = 0; size_t size = 0u;
          check_equal(crypto_tls_stream_write(stream_pair[0], "M", 1u, &written), CRYPTO_TLS_STREAM_OK);
          check_true(written); transfer_stream_cipher(0u, 1u);
          check_equal(crypto_tls_stream_read(stream_pair[1], &byte, 1u, &size, &closed), CRYPTO_TLS_STREAM_OK);
          check_equal(size, (size_t)1u); check_equal(byte, 'M'); check_false(closed);
        }
      }
    }
  }
  for (unsigned version = 0; version < 2u; ++version) {
    for (unsigned scenario = 0u; scenario < 4u; ++scenario) {
      it("TLS1.%u permanently rejects cross-API progress after AEAD failure, scenario %u", version + 2u, scenario) {
        uint8_t wire[32768], byte = 0x5a;
        size_t size = 0u;
        bool complete = false, closed = false, pending = false;
        const unsigned receiver = scenario / 2u, sender = 1u - receiver;
        establish_stream_pair(version ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3
                                            : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2);
        check_equal(crypto_tls_stream_write(stream_pair[sender], NULL, 1u, &complete), CRYPTO_TLS_STREAM_EINVAL);
        check_equal(crypto_tls_stream_write(stream_pair[sender], "X", 1u, &complete), CRYPTO_TLS_STREAM_OK);
        check_true(complete);
        check_equal(crypto_tls_stream_take_cipher(stream_pair[sender], wire, sizeof(wire), &size), CRYPTO_TLS_STREAM_OK);
        check(size > 5u);
        wire[size - 1u] ^= 1u;
        check_equal(crypto_tls_stream_feed_cipher(stream_pair[receiver], wire, size), CRYPTO_TLS_STREAM_OK);
        const int status = scenario % 2u ? crypto_tls_stream_probe_peer_close(stream_pair[receiver], &closed, &pending) :
            crypto_tls_stream_read(stream_pair[receiver], &byte, 1u, &size, &closed);
        check_equal(status, CRYPTO_TLS_STREAM_EPROTO);
        int drain = crypto_tls_stream_take_cipher(stream_pair[receiver], wire, sizeof(wire), &size);
        check(drain == CRYPTO_TLS_STREAM_OK || drain == CRYPTO_TLS_STREAM_ENOENT);
        for (unsigned retry = 0u; retry < 3u; ++retry) {
          complete = true;
          check_equal(crypto_tls_stream_write(stream_pair[receiver], "X", 1u, &complete), status);
          check_false(complete);
          byte = 0x5a; size = 99u; closed = true;
          check_equal(crypto_tls_stream_read(stream_pair[receiver], &byte, 1u, &size, &closed), status);
          check_equal(size, (size_t)0u); check_equal(byte, (uint8_t)0x5a); check_false(closed);
          closed = pending = true;
          check_equal(crypto_tls_stream_probe_peer_close(stream_pair[receiver], &closed, &pending), status);
          check_false(closed); check_false(pending);
          complete = closed = true;
          check_equal(crypto_tls_stream_shutdown(stream_pair[receiver], &complete, &closed), status);
          check_false(complete); check_false(closed);
          complete = true;
          check_equal(crypto_tls_stream_handshake(stream_pair[receiver], &complete), status);
          check_false(complete); check_false(crypto_tls_stream_handshake_complete(stream_pair[receiver]));
          check_true(crypto_tls_stream_cipher_output_empty(stream_pair[receiver]));
        }
      }
    }
    it("TLS1.%u server endpoint binding agrees at both endpoints", version + 2u) {
      uint8_t client_binding[CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES];
      uint8_t server_binding[CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES];
      size_t client_size = 0u, server_size = 0u;
      establish_stream_pair(version ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3
                                          : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2);
      check_equal(crypto_tls_stream_server_end_point_binding(stream_pair[0],
                    client_binding, sizeof(client_binding), &client_size), CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_stream_server_end_point_binding(stream_pair[1],
                    server_binding, sizeof(server_binding), &server_size), CRYPTO_TLS_STREAM_OK);
      check_equal(server_size, client_size);
      check_equal(server_binding, client_binding, client_size);
    }
    it("TLS1.%u shutdown rejects an incomplete application write without losing data", version + 2u) {
      uint8_t payload[32768] = {0};
      uint8_t received[32768];
      size_t size = 0u, total = 0u;
      bool complete = true, generated = false, peer = false;
      bool pending = false;
      establish_stream_pair(version ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3
                                          : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2);
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &complete), CRYPTO_TLS_STREAM_OK);
      check_false(complete);
      transfer_stream_cipher(0u, 1u);
      /* The provider still owns the partially emitted second application
       * record. Shutdown must not relabel that record as close_notify. */
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_EBUSY);
      check_false(generated);
      check_false(peer);
      check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer), CRYPTO_TLS_STREAM_OK);
      total += size;
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &complete), CRYPTO_TLS_STREAM_OK);
      check_true(complete);
      transfer_stream_cipher(0u, 1u);
      for (unsigned step = 0u; step < 16u && total < sizeof(payload); ++step) {
        check_equal(crypto_tls_stream_read(stream_pair[1], received + total,
                      sizeof(received) - total, &size, &peer), CRYPTO_TLS_STREAM_OK);
        check_false(peer);
        total += size;
      }
      check_equal(total, sizeof(payload));
      check_equal(received, payload, total);
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      check_true(generated);
      transfer_stream_cipher(0u, 1u);
      check_equal(crypto_tls_stream_probe_peer_close(stream_pair[1], &peer, &pending), CRYPTO_TLS_STREAM_OK);
      check_true(peer);
      check_false(pending);
      check_equal(crypto_tls_stream_shutdown(stream_pair[1], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      transfer_stream_cipher(1u, 0u);
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      check_true(peer);
    }
    it("TLS1.%u shutdown seals writes even when no alert byte fits", version + 2u) {
      uint8_t payload[16384] = {0}, wire[32768], received[16384];
      size_t size = 0u, wire_size = 0u, second_size;
      bool complete = false, generated = true, peer = false, pending = false;
      establish_stream_pair(version ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3
                                    : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2);
      check_false(crypto_tls_stream_cipher_output_empty(NULL));
      check_true(crypto_tls_stream_cipher_output_empty(stream_pair[0]));
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, 1u, &complete), CRYPTO_TLS_STREAM_OK);
      check_true(complete);
      check_false(crypto_tls_stream_cipher_output_empty(stream_pair[0]));
      check_equal(crypto_tls_stream_take_cipher(stream_pair[0], wire, sizeof(wire), &wire_size), CRYPTO_TLS_STREAM_OK);
      check_true(crypto_tls_stream_cipher_output_empty(stream_pair[0]));
      check_greater(wire_size, 1u);
      check_less(wire_size, 128u);
      check_equal(crypto_tls_stream_feed_cipher(stream_pair[1], wire, wire_size), CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer), CRYPTO_TLS_STREAM_OK);
      check_equal(size, 1u);
      /* Measure the negotiated record overhead, then exactly fill the output
       * ring with two complete application records (no pending write). */
      second_size = sizeof(wire) - sizeof(payload) - 2u * (wire_size - 1u);
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &complete), CRYPTO_TLS_STREAM_OK);
      check_true(complete);
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, second_size, &complete), CRYPTO_TLS_STREAM_OK);
      check_true(complete);
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      check_false(generated);
      check_equal(crypto_tls_stream_write(stream_pair[0], payload, 1u, &complete), CRYPTO_TLS_STREAM_ENOTCONN);
      transfer_stream_cipher(0u, 1u);
      check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer), CRYPTO_TLS_STREAM_OK);
      check_equal(size, sizeof(payload));
      check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer), CRYPTO_TLS_STREAM_OK);
      check_equal(size, second_size);
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      check_true(generated);
      transfer_stream_cipher(0u, 1u);
      check_equal(crypto_tls_stream_probe_peer_close(stream_pair[1], &peer, &pending), CRYPTO_TLS_STREAM_OK);
      check_true(peer);
      check_equal(crypto_tls_stream_shutdown(stream_pair[1], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      transfer_stream_cipher(1u, 0u);
      check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
      check_true(peer);
    }
    it("TLS1.%u survives creator release and preserves authenticated shutdown", version + 2u) {
      char alpn_name[] = "stream-test";
      const char *alpn[] = {alpn_name};
      crypto_tls_stream_client_config client = {sizeof(client)};
      crypto_tls_stream_server_config server = {sizeof(server)};
      crypto_tls_stream_protocol_version protocol = version
          ? CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3 : CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2;
      bool complete[2] = {false, false};
      client.ca_file = CRYPTO_CLOSE_TEST_CA;
      client.server_name = "localhost";
      client.alpn_protocols = alpn;
      client.alpn_protocol_count = 1u;
      server.cert_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
      server.key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
      server.alpn_protocols = alpn;
      server.alpn_protocol_count = 1u;
      check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]),
                  CRYPTO_TLS_STREAM_OK);
      check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]),
                  CRYPTO_TLS_STREAM_OK);
      memset(alpn_name, 'x', sizeof(alpn_name) - 1u); /* policy must own its copy */
      check_equal(crypto_tls_stream_create(stream_context[0], true, "localhost",
                    32768u, &stream_pair[0]), CRYPTO_TLS_STREAM_EINVAL);
      check_null(stream_pair[0]);
      check_equal(crypto_tls_stream_create(stream_context[0], false, "localhost",
                    SIZE_MAX, &stream_pair[0]), CRYPTO_TLS_STREAM_ERANGE);
      check_null(stream_pair[0]);
      for (unsigned i = 0; i < 2u; ++i) {
        check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
                      i == 0u ? "localhost" : NULL, 32768u, &stream_pair[i]),
                    CRYPTO_TLS_STREAM_OK);
        crypto_tls_stream_context_release(stream_context[i]);
        stream_context[i] = NULL; /* stream's retained context is now the only owner */
        check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                    CRYPTO_TLS_STREAM_OK);
        check_not_null(crypto_tls_stream_read_buffer(stream_pair[i]));
        check_not_null(crypto_tls_stream_write_buffer(stream_pair[i]));
        check_not_equal(crypto_tls_stream_read_buffer(stream_pair[i]),
                        crypto_tls_stream_write_buffer(stream_pair[i]));
      }
      for (unsigned step = 0; step < 128u && !(complete[0] && complete[1]); ++step) {
        for (unsigned i = 0; i < 2u; ++i) {
          check_equal(crypto_tls_stream_handshake(stream_pair[i], &complete[i]), CRYPTO_TLS_STREAM_OK);
          if (step == 0u)
            check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                        CRYPTO_TLS_STREAM_EINVAL);
          transfer_stream_cipher(i, 1u - i);
        }
      }
      check(complete[0] && complete[1]);
      for (unsigned i = 0; i < 2u; ++i) {
        const unsigned char *selected = NULL;
        size_t size = 0u;
        check_equal(crypto_tls_stream_set_protocol_range(stream_pair[i], protocol, protocol),
                    CRYPTO_TLS_STREAM_EINVAL);
        check_equal(crypto_tls_stream_get_negotiated_alpn(stream_pair[i], &selected, &size),
                    CRYPTO_TLS_STREAM_OK);
        check_equal(size, sizeof("stream-test") - 1u);
        check_equal(selected, "stream-test", size);
      }
      {
        uint8_t overflow[32769] = {0};
        crypto_tls_test_memory_stats before, after, delta;
        check_true(crypto_tls_stream_test_memory_snapshot(&before));
        size_t capacity = crypto_tls_stream_cipher_input_capacity(stream_pair[1]);
        check_equal(crypto_tls_stream_feed_cipher(stream_pair[1], overflow, sizeof(overflow)),
                    CRYPTO_TLS_STREAM_ENOBUFS);
        check_equal(crypto_tls_stream_cipher_input_capacity(stream_pair[1]), capacity);
        check_true(crypto_tls_stream_test_memory_snapshot(&after));
        check_equal(tls_mixed_memory_delta(&before, &after, &delta), SALTS_OK);
        check_equal(delta.copied_bytes[CRYPTO_TLS_TEST_COPY_CIPHER_INPUT], UINT64_C(0));
        check_equal(delta.copy_calls[CRYPTO_TLS_TEST_COPY_CIPHER_INPUT], UINT64_C(0));
        for (size_t i = 0u; i < CRYPTO_GMSSL_COPY_BUCKETS; ++i)
          for (size_t j = 0u; j < CRYPTO_GMSSL_COPY_OPERATIONS; ++j) {
            check_equal(delta.provider.calls[i][j], UINT64_C(0));
            check_equal(delta.provider.bytes[i][j], UINT64_C(0));
          }
      }
      {
        const uint8_t payload[] = "retained-policy";
        uint8_t received[32] = {0};
        size_t size = 0u;
        bool written = false, peer_closed = false;
        crypto_tls_test_memory_stats before, after, delta;
        check_true(crypto_tls_stream_test_memory_snapshot(&before));
        check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &written),
                    CRYPTO_TLS_STREAM_OK);
        check_true(written);
        transfer_stream_cipher(0, 1);
        check_equal(crypto_tls_stream_read(stream_pair[1], received, sizeof(received), &size, &peer_closed),
                    CRYPTO_TLS_STREAM_OK);
        check_false(peer_closed);
        check_equal(size, sizeof(payload));
        check_equal(received, payload, size);
        check_true(crypto_tls_stream_test_memory_snapshot(&after));
        check_equal(tls_mixed_memory_delta(&before, &after, &delta), SALTS_OK);
        check_equal(tls_mixed_memory_check(&delta, sizeof(payload)), SALTS_OK);
        check_equal(tls_mixed_provider_check(&delta, protocol == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3,
                                             sizeof(payload)), SALTS_OK);
        if (delta.provider_copy_profile) {
          const bool tls13 = protocol == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3;
          check_equal(delta.provider.calls[CRYPTO_GMSSL_COPY_ENCRYPT][CRYPTO_GMSSL_MEMCPY],
                      tls13 ? UINT64_C(2) : UINT64_C(0));
          check_equal(delta.provider.bytes[CRYPTO_GMSSL_COPY_ENCRYPT][CRYPTO_GMSSL_MEMCPY],
                      tls13 ? (uint64_t)sizeof(payload) + 8u : UINT64_C(0));
          check_equal(delta.provider.calls[CRYPTO_GMSSL_COPY_DECRYPT][CRYPTO_GMSSL_MEMCPY],
                      tls13 ? UINT64_C(1) : UINT64_C(0));
          check_equal(delta.provider.bytes[CRYPTO_GMSSL_COPY_DECRYPT][CRYPTO_GMSSL_MEMCPY],
                      tls13 ? UINT64_C(8) : UINT64_C(0));
        }
        /* A second record forces real pending-plaintext delivery, including
         * the short final remainder, in both TLS versions. */
        check_true(crypto_tls_stream_test_memory_snapshot(&before));
        written = false;
        check_equal(crypto_tls_stream_write(stream_pair[0], payload, sizeof(payload), &written), CRYPTO_TLS_STREAM_OK);
        check_true(written);
        transfer_stream_cipher(0, 1);
        size_t total = 0u;
        for (unsigned step = 0u; total < sizeof(payload) && step < 32u; ++step) {
          size = 0u;
          check_equal(crypto_tls_stream_read(stream_pair[1], received + total, 3u, &size, &peer_closed), CRYPTO_TLS_STREAM_OK);
          check_false(peer_closed);
          check_less_equal(size, 3u);
          total += size;
        }
        check_equal(total, sizeof(payload));
        check_equal(received, payload, total);
        check_true(crypto_tls_stream_test_memory_snapshot(&after));
        check_equal(tls_mixed_memory_delta(&before, &after, &delta), SALTS_OK);
        check_equal(tls_mixed_memory_check(&delta, sizeof(payload)), SALTS_OK);
        check_equal(delta.copied_bytes[CRYPTO_TLS_TEST_COPY_PLAINTEXT], UINT64_C(3));
        check_equal(delta.copied_bytes[CRYPTO_TLS_TEST_COPY_PENDING_PLAINTEXT], (uint64_t)sizeof(payload) - 3u);
        check_equal(tls_mixed_provider_check(&delta, protocol == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3,
                                             sizeof(payload)), SALTS_OK);
      }
      {
        bool generated = false, peer = false, pending = false;
        check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(generated);
        check_false(peer);
        transfer_stream_cipher(0, 1);
        check_equal(crypto_tls_stream_probe_peer_close(stream_pair[1], &peer, &pending), CRYPTO_TLS_STREAM_OK);
        check_true(peer);
        check_false(pending);
        check_equal(crypto_tls_stream_shutdown(stream_pair[1], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(generated);
        check_true(peer);
        transfer_stream_cipher(1, 0);
        check_equal(crypto_tls_stream_shutdown(stream_pair[0], &generated, &peer), CRYPTO_TLS_STREAM_OK);
        check_true(peer);
      }
    }
  }
}

typedef struct tls_memory_worker {
  crypto_tls_test_memory_stats before, after;
  int status;
} tls_memory_worker;
static void tls_memory_on_worker(void *user) {
  tls_memory_worker *state = user;
  crypto_tls_stream_context *context = NULL;
  crypto_tls_stream *stream = NULL;
  crypto_tls_stream_client_config config = {sizeof(config)};
  config.ca_file = CRYPTO_NATIVE_BENCH_CA;
  if (!crypto_tls_stream_test_memory_snapshot(&state->before)) { state->status = SALTS_EIO; return; }
  state->status = crypto_tls_stream_client_context_create(&config, &context);
  if (state->status == CRYPTO_TLS_STREAM_OK)
    state->status = crypto_tls_stream_create(context, false, "localhost", CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES, &stream);
  crypto_tls_stream_destroy(stream);
  crypto_tls_stream_context_release(context);
  if (!crypto_tls_stream_test_memory_snapshot(&state->after)) state->status = SALTS_EIO;
}
spec("TLS adapter memory diagnostics") {
  it("isolates real TLS construction and destruction on another owner thread") {
    cmeta_thread_t thread;
    tls_memory_worker state = {0};
    crypto_tls_test_memory_stats before, after, delta;
    check_false(crypto_tls_stream_test_memory_snapshot(NULL));
    check_true(crypto_tls_stream_test_memory_snapshot(&before));
    check_equal(cmeta_thread_create(&thread, tls_memory_on_worker, &state), SALTS_OK);
    check_equal(cmeta_thread_join(&thread), SALTS_OK);
    check_equal(state.status, CRYPTO_TLS_STREAM_OK);
    check_equal(state.before.allocation_calls, UINT64_C(0));
    check_equal(state.before.releases, UINT64_C(0));
    check_equal(tls_mixed_memory_delta(&state.before, &state.after, &delta), SALTS_OK);
    check_greater(delta.allocation_calls, UINT64_C(0));
    check_greater(delta.successful_bytes, UINT64_C(0));
    check_greater(delta.releases, UINT64_C(0));
    check_equal(delta.failures, UINT64_C(0));
    if (delta.provider_copy_profile) {
      check_equal(state.before.provider.calls[CRYPTO_GMSSL_COPY_OTHER][CRYPTO_GMSSL_MEMCPY], UINT64_C(0));
      check_greater(delta.provider.calls[CRYPTO_GMSSL_COPY_OTHER][CRYPTO_GMSSL_MEMCPY], UINT64_C(0));
    }
    check_true(crypto_tls_stream_test_memory_snapshot(&after));
    check_equal(tls_mixed_memory_delta(&before, &after, &delta), SALTS_OK);
    check_equal(tls_mixed_memory_check(&delta, 0u), SALTS_OK);
    for (size_t i = 0u; i < CRYPTO_TLS_TEST_COPY_COUNT; ++i) {
      check_equal(delta.copy_calls[i], UINT64_C(0));
      check_equal(delta.copied_bytes[i], UINT64_C(0));
    }
    for (size_t i = 0u; i < CRYPTO_GMSSL_COPY_BUCKETS; ++i)
      for (size_t j = 0u; j < CRYPTO_GMSSL_COPY_OPERATIONS; ++j) {
        check_equal(delta.provider.calls[i][j], UINT64_C(0));
        check_equal(delta.provider.bytes[i][j], UINT64_C(0));
      }
  }
}

typedef struct tls_io_probe {
  size_t sent;
  size_t received;
} tls_io_probe;

static tls_ret_t reject_send(void *ctx, const void *data, size_t length, int flags) {
  tls_io_probe *p = (tls_io_probe *)ctx;
  (void)data;
  (void)length;
  (void)flags;
  if (!p) return TLS_ERROR_SYSCALL;
  ++p->sent;
  return TLS_ERROR_SEND_AGAIN;
}
static tls_ret_t reject_receive(void *ctx, void *data, size_t length, int flags) {
  tls_io_probe *p = (tls_io_probe *)ctx;
  (void)data;
  (void)length;
  (void)flags;
  if (!p) return TLS_ERROR_SYSCALL;
  ++p->received;
  return TLS_ERROR_RECV_AGAIN;
}
static int saltscore_legacy_entry_test_gmssl_tls_io_abi_c(void) {
  TLS_CONNECT connection = {0};
  TLS_IO io = {0};
  tls_io_probe probe = {0};
  unsigned char payload = 0x5au;

  if (sizeof(TLS_CTX) != tls_ctx_sizeof() ||
      sizeof(TLS_CONNECT) != tls_connect_sizeof()) {
    fprintf(stderr, "GmSSL provider public TLS structures differ from runtime ABI\n");
    return 1;
  }
  io.user = &probe;
  io.send = reject_send;
  io.recv = reject_receive;
  if (tls_set_io(&connection, &io) != 1) {
    fprintf(stderr, "Pinned GmSSL external I/O setter failed\n");
    return 2;
  }
  if (tls_io_send(&connection, &payload, sizeof payload, 0) >= 0 ||
      tls_io_recv(&connection, &payload, sizeof payload, 0) >= 0 ||
      probe.sent != 1u || probe.received != 1u) {
    fprintf(stderr, "GmSSL external I/O did not preserve send/recv retry\n");
    return 3;
  }
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("GmSSL TLS IO callback ABI") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_gmssl_tls_io_abi_c();
    check(result == 0, "original native contract returned %d", result);
  }
}

typedef struct key_update_wire {
  uint8_t bytes[2048];
  size_t size;
  size_t budget;
  size_t read_offset, read_budget;
} key_update_wire;

static tls_ret_t key_update_capture(void *user, const void *data, size_t size, int flags) {
  key_update_wire *wire = (key_update_wire *)user;
  (void)flags;
  if (wire->budget == 0u) return TLS_ERROR_SEND_AGAIN;
  if (size > wire->budget) size = wire->budget;
  if (size > sizeof(wire->bytes) - wire->size) return TLS_ERROR_SYSCALL;
  memcpy(wire->bytes + wire->size, data, size);
  wire->size += size;
  wire->budget -= size;
  return (tls_ret_t)size;
}

static tls_ret_t key_update_no_receive(void *user, void *data, size_t size, int flags) {
  (void)user; (void)data; (void)size; (void)flags;
  return TLS_ERROR_SYSCALL;
}

static tls_ret_t key_update_fragmented_receive(void *user, void *data, size_t size, int flags) {
  key_update_wire *wire = user;
  (void)flags;
  if (wire->read_budget == 0u || wire->read_offset == wire->size) return TLS_ERROR_RECV_AGAIN;
  if (size > wire->read_budget) size = wire->read_budget;
  if (size > wire->size - wire->read_offset) size = wire->size - wire->read_offset;
  memcpy(data, wire->bytes + wire->read_offset, size);
  wire->read_offset += size;
  wire->read_budget -= size;
  return (tls_ret_t)size;
}

spec("GmSSL authenticated peer update budget across fragmented reads") {
  for (unsigned scenario = 0u; scenario < 4u; ++scenario) {
    it("role and AEAD scenario %u rejects before the excess key derivation", scenario) {
      TLS_CTX ctx[2] = {0};
      TLS_CONNECT conn[2] = {0};
      key_update_wire wire = {0};
      wire.budget = sizeof(wire.bytes);
      TLS_IO io = {.user = &wire, .send = key_update_capture, .recv = key_update_fragmented_receive};
      for (unsigned endpoint = 0u; endpoint < 2u; ++endpoint) {
        ctx[endpoint].protocol = TLS_protocol_tls13;
        conn[endpoint].ctx = &ctx[endpoint];
        conn[endpoint].protocol = TLS_protocol_tls13;
        conn[endpoint].is_client = (scenario % 2u) != endpoint;
        conn[endpoint].cipher_suite = scenario < 2u ? TLS_cipher_sm4_gcm_sm3 : TLS_cipher_aes_128_gcm_sha256;
        tls_record_set_protocol(conn[endpoint].plain_record, TLS_protocol_tls12);
        tls_record_set_protocol(conn[endpoint].record, TLS_protocol_tls12);
        check_equal(tls_cipher_suite_get(conn[endpoint].cipher_suite, &conn[endpoint].cipher, &conn[endpoint].digest), 1);
        memset(conn[endpoint].client_application_traffic_secret, 0x35, 32u);
        memset(conn[endpoint].server_application_traffic_secret, 0x59, 32u);
        for (unsigned role = 0u; role < 2u; ++role) {
          uint8_t key[16];
          const uint8_t *secret = role ? conn[endpoint].client_application_traffic_secret : conn[endpoint].server_application_traffic_secret;
          uint8_t *iv = role ? conn[endpoint].client_write_iv : conn[endpoint].server_write_iv;
          BLOCK_CIPHER_KEY *cipher = role ? &conn[endpoint].client_write_key : &conn[endpoint].server_write_key;
          check_equal(tls13_hkdf_expand_label(conn[endpoint].digest, secret, "key", NULL, 0u, sizeof(key), key), 1);
          check_equal(tls13_hkdf_expand_label(conn[endpoint].digest, secret, "iv", NULL, 0u, 12u, iv), 1);
          check_equal(block_cipher_set_encrypt_key(cipher, conn[endpoint].cipher, key), 1);
        }
        check_equal(tls_set_io(&conn[endpoint], &io), 1);
      }
      check_equal(tls13_ctx_set_peer_key_update_limit(&ctx[1], 2u), 1);
      for (unsigned update = 0u; update < 3u; ++update) {
        uint8_t previous_secret[32], byte = 0x5a;
        uint8_t *secret = conn[1].is_client ? conn[1].server_application_traffic_secret : conn[1].client_application_traffic_secret;
        memcpy(previous_secret, secret, sizeof(previous_secret));
        check_equal(conn[0].is_client ? tls13_send_client_key_update(&conn[0], (int)(update % 2u)) :
                                      tls13_send_server_key_update(&conn[0], (int)(update % 2u)), 1);
        int status = TLS_ERROR_RECV_AGAIN;
        for (unsigned step = 0u; step < sizeof(wire.bytes) && wire.read_offset < wire.size; ++step) {
          size_t received = 99u;
          wire.read_budget = 1u;
          status = tls13_recv(&conn[1], &byte, 1u, &received);
          check_equal(received, (size_t)0u); check_equal(byte, (uint8_t)0x5a);
          if (status != TLS_ERROR_RECV_AGAIN) break;
        }
        check_equal(wire.read_offset, wire.size);
        check_equal(conn[1].consecutive_peer_key_updates, update < 2u ? (size_t)update + 1u : (size_t)2u);
        if (update < 2u) {
          check_equal(status, TLS_ERROR_RECV_AGAIN);
          check_not_equal(previous_secret, secret, sizeof(previous_secret));
        } else {
          check_equal(status, -1);
          check_equal(previous_secret, secret, sizeof(previous_secret));
        }
      }
    }
  }
}

spec("GmSSL TLS 1.3 KeyUpdate under bounded external writes") {
  it("admits byte budgets independently and preserves rejected context state") {
    TLS_CTX ctx = {0};
    check_equal(tls13_ctx_set_key_update_byte_limit(NULL, 1u), -1);
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 1u), -1);
    ctx.protocol = TLS_protocol_tls13;
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, TLS13_MAX_KEY_UPDATE_BYTE_LIMIT), 1);
    check_equal(ctx.key_update_byte_limit, CRYPTO_TLS_STREAM_KEY_UPDATE_BYTE_LIMIT_MAX);
    check_equal(ctx.key_update, 0);
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, TLS13_MAX_KEY_UPDATE_BYTE_LIMIT + 1u), -1);
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, UINT64_MAX), -1);
    check_equal(ctx.key_update_byte_limit, TLS13_MAX_KEY_UPDATE_BYTE_LIMIT);
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 0u), 1);
    check_equal(ctx.key_update_byte_limit, UINT64_C(0));
  }
  it("rejects corrupted budget state before subtraction or ciphertext generation") {
    TLS_CTX ctx = {0};
    TLS_CONNECT conn = {0};
    key_update_wire wire = {0};
    TLS_IO io = {.user = &wire, .send = key_update_capture, .recv = key_update_no_receive};
    const uint8_t payload = 0x46;
    uint8_t key[16];
    size_t sent = 99u;
    ctx.protocol = TLS_protocol_tls13;
    check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 1u), 1);
    conn.ctx = &ctx;
    conn.protocol = TLS_protocol_tls13;
    conn.cipher_suite = TLS_cipher_sm4_gcm_sm3;
    tls_record_set_protocol(conn.plain_record, TLS_protocol_tls12);
    tls_record_set_protocol(conn.record, TLS_protocol_tls12);
    check_equal(tls_cipher_suite_get(conn.cipher_suite, &conn.cipher, &conn.digest), 1);
    check_equal(tls13_hkdf_expand_label(conn.digest, conn.server_application_traffic_secret,
        "key", NULL, 0u, sizeof(key), key), 1);
    check_equal(tls13_hkdf_expand_label(conn.digest, conn.server_application_traffic_secret,
        "iv", NULL, 0u, sizeof(conn.server_write_iv), conn.server_write_iv), 1);
    check_equal(block_cipher_set_encrypt_key(&conn.server_write_key, conn.cipher, key), 1);
    conn.server_seq_num[7] = 1u;
    check_equal(tls_set_io(&conn, &io), 1);
    wire.budget = sizeof(wire.bytes);
    conn.local_key_plaintext_bytes = 2u;
    check_equal(tls13_send(&conn, &payload, 1u, &sent), -1);
    check_equal(sent, (size_t)0u);
    check_equal(conn.recordlen, (size_t)0u);
    check_equal(wire.size, (size_t)0u);
    check_equal(conn.local_key_plaintext_bytes, UINT64_C(2));
  }
  for (unsigned role = 0u; role < 2u; ++role) {
    for (unsigned suite_index = 0u; suite_index < 2u; ++suite_index) {
      for (unsigned automatic = 0u; automatic < 6u; ++automatic) {
      it("role %u suite %u automatic %u retries control ciphertext without application completion", role, suite_index, automatic) {
        TLS_CTX ctx = {0};
        TLS_CONNECT conn = {0};
        key_update_wire wire = {0};
        TLS_IO io = {0};
        BLOCK_CIPHER_KEY old_key;
        uint8_t old_iv[12], zero_seq[8] = {0}, old_seq[8] = {0}, plain[1024];
        const uint8_t payload[] = {0x46, 0x47, 0x48, 0x49, 0x50};
        const bool byte_budget = automatic >= 2u;
        const size_t expected_sent = byte_budget ? 2u : sizeof(payload);
        const uint8_t request = automatic != 0u && automatic != 4u;
        size_t sent = 0u, plain_size = 0u;
        int result = TLS_ERROR_SEND_AGAIN;
        conn.ctx = &ctx;
        ctx.protocol = TLS_protocol_tls13;
        conn.is_client = (int)role;
        conn.protocol = TLS_protocol_tls13;
        tls_record_set_protocol(conn.plain_record, TLS_protocol_tls12);
        tls_record_set_protocol(conn.record, TLS_protocol_tls12);
        conn.cipher_suite = suite_index ? TLS_cipher_aes_128_gcm_sha256 : TLS_cipher_sm4_gcm_sm3;
        check_equal(tls_cipher_suite_get(conn.cipher_suite, &conn.cipher, &conn.digest), 1);
        memset(conn.client_application_traffic_secret, 0x35, 32u);
        memset(conn.server_application_traffic_secret, 0x59, 32u);
        for (unsigned key_role = 0u; key_role < 2u; ++key_role) {
          uint8_t key[16];
          const uint8_t *secret = key_role ? conn.client_application_traffic_secret : conn.server_application_traffic_secret;
          uint8_t *iv = key_role ? conn.client_write_iv : conn.server_write_iv;
          BLOCK_CIPHER_KEY *cipher_key = key_role ? &conn.client_write_key : &conn.server_write_key;
          check_equal(tls13_hkdf_expand_label(conn.digest, secret, "key", NULL, 0u, sizeof(key), key), 1);
          check_equal(tls13_hkdf_expand_label(conn.digest, secret, "iv", NULL, 0u, 12u, iv), 1);
          check_equal(block_cipher_set_encrypt_key(cipher_key, conn.cipher, key), 1);
        }
        old_key = role ? conn.client_write_key : conn.server_write_key;
        memcpy(old_iv, role ? conn.client_write_iv : conn.server_write_iv, sizeof(old_iv));
        io.user = &wire;
        io.send = key_update_capture;
        io.recv = key_update_no_receive;
        check_equal(tls_set_io(&conn, &io), 1);
        if (automatic == 1u || automatic == 3u) {
          check_equal(tls13_ctx_enable_key_update(&ctx, 1), 1);
          check_equal(tls13_ctx_set_key_update_seq_num_limit(&ctx, 1u), 1);
          (role ? conn.client_seq_num : conn.server_seq_num)[7] = old_seq[7] = 1u;
        }
        if (byte_budget) {
          check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 2u), 1);
          conn.local_key_plaintext_bytes = 2u;
          (role ? conn.client_seq_num : conn.server_seq_num)[7] = old_seq[7] = 1u;
        }
        if (automatic == 0u || automatic == 4u) conn.key_update = 1;
        if (automatic == 5u) {
          /* Encryption uses the prepared AEAD key; derivation must reject the
           * absent digest before any control ciphertext reaches the transport. */
          conn.digest = NULL;
          wire.budget = 1u;
          sent = 99u;
          check_equal(tls13_send(&conn, payload, sizeof(payload), &sent), -1);
          check_equal(sent, (size_t)0u);
          check_equal(wire.size, (size_t)0u);
          check_equal(conn.local_key_plaintext_bytes, UINT64_C(2));
        } else {
        conn.sentlen = 7u; /* stale prior application count must never escape */
        for (unsigned step = 0u; step < sizeof(wire.bytes) && result != 1; ++step) {
          wire.budget = 1u;
          sent = 99u;
          result = tls13_send(&conn, payload, sizeof(payload), &sent);
          check(result == 1 || result == TLS_ERROR_SEND_AGAIN);
          check_equal(sent, result == 1 ? expected_sent : (size_t)0u);
        }
        check_equal(result, 1);
        check_equal(conn.local_key_plaintext_bytes, byte_budget ? UINT64_C(2) : UINT64_C(0));
        check(wire.size >= 10u);
        const size_t first = 5u + ((size_t)wire.bytes[3] << 8) + wire.bytes[4];
        check(first + 5u < wire.size);
        check_equal(tls13_record_decrypt(conn.cipher_suite, &old_key, old_iv, old_seq,
            wire.bytes, first, plain, &plain_size), 1);
        check_equal(plain_size, (size_t)10u);
        const uint8_t expected_update[] = {24, 0, 0, 1, request};
        check_equal(plain[0], (uint8_t)22);
        check_equal(plain + 5u, expected_update, sizeof(expected_update));
        const size_t second = 5u + ((size_t)wire.bytes[first + 3u] << 8) + wire.bytes[first + 4u];
        check_equal(first + second, wire.size);
        check_equal(tls13_record_decrypt(conn.cipher_suite,
            role ? &conn.client_write_key : &conn.server_write_key,
            role ? conn.client_write_iv : conn.server_write_iv, zero_seq,
            wire.bytes + first, second, plain, &plain_size), 1);
        check_equal(plain_size, 5u + expected_sent);
        check_equal(plain[0], (uint8_t)23);
        check_equal(plain + 5u, payload, expected_sent);
        }
      }
      }
    }
  }
}

typedef struct key_update_clock {
  uint64_t now;
  unsigned calls, fail_call;
} key_update_clock;

static int key_update_clock_sample(void *user, uint64_t *now) {
  key_update_clock *clock = user;
  ++clock->calls;
  if (clock->calls == clock->fail_call) return -1;
  *now = clock->now;
  return 1;
}

static void timed_key_prepare(TLS_CTX *ctx, TLS_CONNECT *conn,
    key_update_wire *wire, key_update_clock *clock, unsigned role, unsigned suite_index,
    uint32_t interval) {
  memset(ctx, 0, sizeof(*ctx));
  memset(conn, 0, sizeof(*conn));
  memset(wire, 0, sizeof(*wire));
  ctx->protocol = TLS_protocol_tls13;
  conn->ctx = ctx;
  conn->is_client = (int)role;
  conn->protocol = TLS_protocol_tls13;
  conn->handshake_state = TLS_state_handshake_over;
  conn->cipher_suite = suite_index ? TLS_cipher_aes_128_gcm_sha256 : TLS_cipher_sm4_gcm_sm3;
  check_equal(tls_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest), 1);
  tls_record_set_protocol(conn->plain_record, TLS_protocol_tls12);
  tls_record_set_protocol(conn->record, TLS_protocol_tls12);
  memset(conn->client_application_traffic_secret, 0x35, 32u);
  memset(conn->server_application_traffic_secret, 0x59, 32u);
  for (unsigned key_role = 0u; key_role < 2u; ++key_role) {
    uint8_t key[16];
    const uint8_t *secret = key_role ? conn->client_application_traffic_secret : conn->server_application_traffic_secret;
    uint8_t *iv = key_role ? conn->client_write_iv : conn->server_write_iv;
    BLOCK_CIPHER_KEY *cipher = key_role ? &conn->client_write_key : &conn->server_write_key;
    check_equal(tls13_hkdf_expand_label(conn->digest, secret, "key", NULL, 0u, sizeof(key), key), 1);
    check_equal(tls13_hkdf_expand_label(conn->digest, secret, "iv", NULL, 0u, 12u, iv), 1);
    check_equal(block_cipher_set_encrypt_key(cipher, conn->cipher, key), 1);
  }
  TLS_IO io = {.user = wire, .send = key_update_capture, .recv = key_update_no_receive};
  check_equal(tls_set_io(conn, &io), 1);
  check_equal(tls13_ctx_set_key_update_interval(ctx, interval, key_update_clock_sample, clock), 1);
}

static void timed_key_send(TLS_CONNECT *conn, key_update_wire *wire, uint8_t payload) {
  int result = TLS_ERROR_SEND_AGAIN;
  for (unsigned step = 0u; step < sizeof(wire->bytes) && result != 1; ++step) {
    size_t sent = 99u;
    wire->budget = 1u;
    result = tls13_send(conn, &payload, 1u, &sent);
    check(result == 1 || result == TLS_ERROR_SEND_AGAIN);
    check_equal(sent, result == 1 ? (size_t)1u : (size_t)0u);
  }
  check_equal(result, 1);
}

static void timed_key_expect_update(TLS_CONNECT *conn, key_update_wire *wire,
    const BLOCK_CIPHER_KEY *old_key, const uint8_t *old_iv, const uint8_t *old_seq,
    uint8_t request, uint8_t payload) {
  uint8_t plain[1024], zero_seq[8] = {0};
  size_t plain_size = 0u;
  check(wire->size >= 10u);
  const size_t first = 5u + ((size_t)wire->bytes[3] << 8) + wire->bytes[4];
  check(first + 5u < wire->size);
  check_equal(tls13_record_decrypt(conn->cipher_suite, old_key, old_iv, old_seq,
      wire->bytes, first, plain, &plain_size), 1);
  const uint8_t expected[] = {24, 0, 0, 1, request};
  check_equal(plain_size, (size_t)10u);
  check_equal(plain[0], (uint8_t)22);
  check_equal(plain + 5u, expected, sizeof(expected));
  const size_t second = 5u + ((size_t)wire->bytes[first + 3u] << 8) + wire->bytes[first + 4u];
  check_equal(first + second, wire->size);
  check_equal(tls13_record_decrypt(conn->cipher_suite,
      conn->is_client ? &conn->client_write_key : &conn->server_write_key,
      conn->is_client ? conn->client_write_iv : conn->server_write_iv, zero_seq,
      wire->bytes + first, second, plain, &plain_size), 1);
  check_equal(plain_size, (size_t)6u);
  check_equal(plain[0], (uint8_t)23);
  check_equal(plain[5], payload);
}

spec("GmSSL local sending-key monotonic intervals") {
  it("admits intervals without enabling record rotation or retaining a disabled clock") {
    TLS_CTX ctx = {0};
    key_update_clock clock = {0};
    check_equal(tls13_ctx_set_key_update_interval(NULL, 1u, key_update_clock_sample, &clock), -1);
    check_equal(tls13_ctx_set_key_update_interval(&ctx, 1u, key_update_clock_sample, &clock), -1);
    ctx.protocol = TLS_protocol_tls13;
    check_equal(tls13_ctx_set_key_update_interval(&ctx, 1u, key_update_clock_sample, &clock), 1);
    check_equal(ctx.key_update_interval_ms, 1u);
    check_equal(tls13_ctx_set_key_update_interval(&ctx, UINT32_MAX, key_update_clock_sample, &clock), 1);
    check_equal(ctx.key_update_interval_ms, UINT32_MAX);
    check_equal(ctx.key_update, 0);
    check_equal(tls13_ctx_set_key_update_interval(&ctx, 1u, NULL, NULL), -1);
    check_equal(ctx.key_update_interval_ms, UINT32_MAX);
    check_equal(ctx.key_update_clock_user, (void *)&clock);
    check_equal(clock.calls, 0u);
    check_equal(tls13_ctx_set_key_update_interval(&ctx, 0u, key_update_clock_sample, &clock), 1);
    check_equal(ctx.key_update_interval_ms, 0u);
    check(ctx.key_update_clock_ms == NULL && ctx.key_update_clock_user == NULL);
  }
  for (unsigned role = 0u; role < 2u; ++role) {
    for (unsigned suite_index = 0u; suite_index < 2u; ++suite_index) {
      it("role %u suite %u starts once and expires exactly between new records", role, suite_index) {
        TLS_CTX ctx;
        TLS_CONNECT conn;
        key_update_wire wire;
        key_update_clock clock = {.now = 100u};
        timed_key_prepare(&ctx, &conn, &wire, &clock, role, suite_index, 10u);
        check_equal(tls13_ctx_enable_key_update(&ctx, 1), 1);
        check_equal(tls13_ctx_set_key_update_seq_num_limit(&ctx, 1u), 1);
        check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 1u), 1);
        check_equal(tls_do_handshake(&conn), 1);
        check_equal(conn.local_key_started_ms, UINT64_C(100));
        check_equal(clock.calls, 1u);
        clock.fail_call = 2u;
        check_equal(tls_do_handshake(&conn), 1); /* An inspection cannot restart age. */
        check_equal(clock.calls, 1u);
        clock.fail_call = 0u;
        clock.now = 109u;
        const uint8_t payload = 0x46;
        size_t sent = 99u;
        wire.budget = 1u;
        check_equal(tls13_send(&conn, &payload, 1u, &sent), TLS_ERROR_SEND_AGAIN);
        check_equal(sent, (size_t)0u);
        check_equal(clock.calls, 2u);
        clock.now = 110u; /* Expiry must not replace pending application ciphertext. */
        timed_key_send(&conn, &wire, payload);
        check_equal(clock.calls, 2u);
        check_equal(conn.local_key_started_ms, UINT64_C(100));
        const size_t application = 5u + ((size_t)wire.bytes[3] << 8) + wire.bytes[4];
        check_equal(application, wire.size);
        wire.size = 0u;
        BLOCK_CIPHER_KEY old_key = role ? conn.client_write_key : conn.server_write_key;
        uint8_t old_iv[12], old_seq[8];
        memcpy(old_iv, role ? conn.client_write_iv : conn.server_write_iv, sizeof(old_iv));
        memcpy(old_seq, role ? conn.client_seq_num : conn.server_seq_num, sizeof(old_seq));
        wire.budget = 1u;
        check_equal(tls13_send(&conn, &payload, 1u, &sent), TLS_ERROR_SEND_AGAIN);
        check_equal(conn.key_update_sending, 1);
        check_equal(conn.local_key_started_ms, UINT64_C(110));
        clock.now = 111u; /* Pending control writes cannot sample/reset age again. */
        timed_key_send(&conn, &wire, payload);
        timed_key_expect_update(&conn, &wire, &old_key, old_iv, old_seq, 1u, payload);
        check_equal(conn.local_key_started_ms, UINT64_C(110));
        check_equal(clock.calls, 5u); /* boundary, one update, next application */
      }
      it("role %u suite %u resets age on mandatory responses and preserves byte policy", role, suite_index) {
        TLS_CTX ctx;
        TLS_CONNECT conn;
        key_update_wire wire;
        key_update_clock clock = {.now = 0u};
        timed_key_prepare(&ctx, &conn, &wire, &clock, role, suite_index, 10u);
        check_equal(tls_do_handshake(&conn), 1);
        check_equal(conn.key_update_timer_started, 1); /* Epoch zero is valid. */
        check_equal(tls13_ctx_set_key_update_byte_limit(&ctx, 2u), 1);
        conn.local_key_plaintext_bytes = 2u;
        conn.key_update = 1;
        clock.now = 5u;
        BLOCK_CIPHER_KEY old_key = role ? conn.client_write_key : conn.server_write_key;
        uint8_t old_iv[12], seq[8] = {0};
        memcpy(old_iv, role ? conn.client_write_iv : conn.server_write_iv, sizeof(old_iv));
        timed_key_send(&conn, &wire, 0x47);
        timed_key_expect_update(&conn, &wire, &old_key, old_iv, seq, 0u, 0x47);
        check_equal(conn.local_key_started_ms, UINT64_C(5));
        check_equal(conn.local_key_plaintext_bytes, UINT64_C(1));
        clock.now = 14u;
        wire.size = 0u;
        timed_key_send(&conn, &wire, 0x47);
        check_equal(wire.size, 5u + ((size_t)wire.bytes[3] << 8) + wire.bytes[4]);
        check_equal(conn.local_key_started_ms, UINT64_C(5));
      }
      it("role %u suite %u rejects the initial clock failure before timer publication", role, suite_index) {
        TLS_CTX ctx;
        TLS_CONNECT conn;
        key_update_wire wire;
        key_update_clock clock = {.now = 100u, .fail_call = 1u};
        timed_key_prepare(&ctx, &conn, &wire, &clock, role, suite_index, 10u);
        check_equal(tls_do_handshake(&conn), -1);
        check_equal(conn.key_update_timer_started, 0);
        check_equal(conn.local_key_started_ms, UINT64_C(0));
        check_equal(wire.size, (size_t)0u);
      }
      for (unsigned coalesced = 0u; coalesced < 2u; ++coalesced) {
      it("role %u suite %u peer update/coalesced %u preserves independent local age", role, suite_index, coalesced) {
        TLS_CTX ctx[2];
        TLS_CONNECT conn[2];
        key_update_wire unused, wire;
        key_update_clock clock = {.now = 100u};
        timed_key_prepare(&ctx[0], &conn[0], &wire, &clock, !role, suite_index, 0u);
        timed_key_prepare(&ctx[1], &conn[1], &unused, &clock, role, suite_index, 10u);
        check_equal(tls_do_handshake(&conn[1]), 1);
        TLS_IO io = {.user = &wire, .send = key_update_capture, .recv = key_update_fragmented_receive};
        check_equal(tls_set_io(&conn[1], &io), 1);
        wire.budget = sizeof(wire.bytes);
        check_equal(role ? tls13_send_server_key_update(&conn[0], 0) :
            tls13_send_client_key_update(&conn[0], 0), 1);
        const uint8_t payload = 0x46;
        size_t sent = 0u;
        if (coalesced) {
          check_equal(tls13_send(&conn[0], &payload, 1u, &sent), 1);
          check_equal(sent, (size_t)1u);
        }
        uint8_t before[32];
        memcpy(before, role ? conn[1].server_application_traffic_secret : conn[1].client_application_traffic_secret, sizeof(before));
        clock.now = 105u;
        wire.read_budget = wire.size;
        uint8_t byte = 0x5a;
        size_t received = 99u;
        check_equal(tls13_recv(&conn[1], &byte, 1u, &received), coalesced ? 1 : TLS_ERROR_RECV_AGAIN);
        check_equal(received, coalesced ? (size_t)1u : (size_t)0u);
        check_equal(byte, coalesced ? payload : (uint8_t)0x5a);
        check_equal(wire.read_offset, wire.size);
        check_not_equal(before, role ? conn[1].server_application_traffic_secret : conn[1].client_application_traffic_secret, sizeof(before));
        check_equal(conn[1].local_key_started_ms, UINT64_C(100));
        check_equal(conn[1].key_update_last_clock_ms, UINT64_C(100));
        check_equal(clock.calls, 1u);
        clock.now = 110u;
        wire.size = wire.read_offset = 0u;
        BLOCK_CIPHER_KEY old_key = role ? conn[1].client_write_key : conn[1].server_write_key;
        uint8_t old_iv[12], seq[8] = {0};
        memcpy(old_iv, role ? conn[1].client_write_iv : conn[1].server_write_iv, sizeof(old_iv));
        timed_key_send(&conn[1], &wire, 0x49);
        timed_key_expect_update(&conn[1], &wire, &old_key, old_iv, seq, 1u, 0x49);
      }
      }
      for (unsigned failure = 0u; failure < 6u; ++failure) {
        it("role %u suite %u rejects clock failure %u before ciphertext or key change", role, suite_index, failure) {
          TLS_CTX ctx;
          TLS_CONNECT conn;
          key_update_wire wire;
          key_update_clock clock = {.now = 100u};
          timed_key_prepare(&ctx, &conn, &wire, &clock, role, suite_index, 10u);
          if (failure != 2u) check_equal(tls_do_handshake(&conn), 1);
          if (failure == 0u) clock.fail_call = 2u;
          if (failure == 1u) clock.now = 99u;
          if (failure == 3u) { clock.now = 110u; clock.fail_call = 3u; }
          if (failure == 4u) {
            clock.now = 105u;
            timed_key_send(&conn, &wire, 0x46);
            wire.size = 0u;
            clock.now = 104u; /* Still after origin, but before the last sample. */
          }
          if (failure == 5u) { clock.now = 110u; conn.digest = NULL; }
          uint8_t before[32];
          memcpy(before, role ? conn.client_application_traffic_secret : conn.server_application_traffic_secret, sizeof(before));
          const uint8_t payload = 0x46;
          size_t sent = 99u;
          wire.budget = sizeof(wire.bytes);
          check_equal(tls13_send(&conn, &payload, 1u, &sent), -1);
          check_equal(sent, (size_t)0u);
          check_equal(wire.size, (size_t)0u);
          if (failure != 5u) check_equal(conn.recordlen, (size_t)0u);
          check_equal(conn.local_key_started_ms, failure == 2u ? UINT64_C(0) : UINT64_C(100));
          check_equal(before, role ? conn.client_application_traffic_secret : conn.server_application_traffic_secret, sizeof(before));
        }
      }
      it("role %u suite %u uses subtraction at maximum interval and clock value", role, suite_index) {
        TLS_CTX ctx;
        TLS_CONNECT conn;
        key_update_wire wire;
        key_update_clock clock = {.now = UINT64_MAX - UINT32_MAX};
        timed_key_prepare(&ctx, &conn, &wire, &clock, role, suite_index, UINT32_MAX);
        check_equal(tls_do_handshake(&conn), 1);
        clock.now = UINT64_MAX;
        BLOCK_CIPHER_KEY old_key = role ? conn.client_write_key : conn.server_write_key;
        uint8_t old_iv[12], seq[8] = {0};
        memcpy(old_iv, role ? conn.client_write_iv : conn.server_write_iv, sizeof(old_iv));
        timed_key_send(&conn, &wire, 0x48);
        timed_key_expect_update(&conn, &wire, &old_key, old_iv, seq, 1u, 0x48);
        check_equal(conn.local_key_started_ms, UINT64_MAX);
      }
    }
  }
}

typedef struct tls_duplex_wire {
  key_update_wire incoming, outgoing;
} tls_duplex_wire;

static tls_ret_t duplex_send(void *user, const void *data, size_t size, int flags) {
  return key_update_capture(&((tls_duplex_wire *)user)->outgoing, data, size, flags);
}
static tls_ret_t duplex_receive(void *user, void *data, size_t size, int flags) {
  return key_update_fragmented_receive(&((tls_duplex_wire *)user)->incoming, data, size, flags);
}

static void duplex_expect_application(TLS_CONNECT *conn, key_update_wire *wire,
    const uint8_t *payload, size_t size) {
  uint8_t plain[1024], seq[8] = {0};
  size_t plain_size = 0u;
  check(wire->size >= 5u);
  check_equal(wire->size, 5u + ((size_t)wire->bytes[3] << 8) + wire->bytes[4]);
  check_equal(tls13_record_decrypt(conn->cipher_suite,
      conn->is_client ? &conn->client_write_key : &conn->server_write_key,
      conn->is_client ? conn->client_write_iv : conn->server_write_iv, seq,
      wire->bytes, wire->size, plain, &plain_size), 1);
  check_equal(plain_size, 5u + size);
  check_equal(plain[0], (uint8_t)23);
  check_equal(plain + 5u, payload, size);
}

spec("GmSSL established TLS 1.3 independent receive and send storage") {
  for (unsigned role = 0u; role < 2u; ++role) {
    for (unsigned suite_index = 0u; suite_index < 2u; ++suite_index) {
      for (unsigned mode = 0u; mode < 7u; ++mode) {
        it("role %u suite %u duplex boundary %u retains exact authenticated bytes", role, suite_index, mode) {
          TLS_CTX ctx[2];
          TLS_CONNECT conn[2];
          tls_duplex_wire wire = {0};
          key_update_wire unused;
          key_update_clock clock = {0};
          timed_key_prepare(&ctx[0], &conn[0], &wire.incoming, &clock, !role, suite_index, 0u);
          timed_key_prepare(&ctx[1], &conn[1], &unused, &clock, role, suite_index, 0u);
          TLS_IO io = {.user = &wire, .send = duplex_send, .recv = duplex_receive};
          check_equal(tls_set_io(&conn[1], &io), 1);
          const uint8_t incoming[] = {0x46, 0x47, 0x48};
          const uint8_t outgoing = 0x58;
          size_t sent = 99u, received = 99u;
          uint8_t plain[3] = {0};
          wire.incoming.budget = sizeof(wire.incoming.bytes);
          check_equal(tls13_send(&conn[0], incoming, sizeof(incoming), &sent), 1);
          check_equal(sent, sizeof(incoming));
          if (mode < 5u) {
            const size_t prefixes[] = {1u, 4u, 5u, 6u, wire.incoming.size - 1u};
            wire.incoming.read_budget = prefixes[mode];
            check_equal(tls13_recv(&conn[1], plain, sizeof(plain), &received), TLS_ERROR_RECV_AGAIN);
            check_equal(received, (size_t)0u);
            check_equal(wire.incoming.read_offset, prefixes[mode]);
            timed_key_send(&conn[1], &wire.outgoing, outgoing);
            duplex_expect_application(&conn[1], &wire.outgoing, &outgoing, 1u);
            wire.incoming.read_budget = wire.incoming.size;
            check_equal(tls13_recv(&conn[1], plain, sizeof(plain), &received), 1);
            check_equal(received, sizeof(incoming));
            check_equal(plain, incoming, sizeof(incoming));
            check_equal(wire.incoming.read_offset, wire.incoming.size);
          } else if (mode == 5u) {
            wire.outgoing.budget = 1u;
            check_equal(tls13_send(&conn[1], &outgoing, 1u, &sent), TLS_ERROR_SEND_AGAIN);
            check_equal(sent, (size_t)0u);
            size_t remaining = conn[1].recordlen, offset = conn[1].record_offset;
            uint8_t encrypted[TLS_MAX_RECORD_SIZE];
            memcpy(encrypted, conn[1].record, remaining + offset);
            wire.incoming.read_budget = wire.incoming.size;
            check_equal(tls13_recv(&conn[1], plain, sizeof(plain), &received), 1);
            check_equal(received, sizeof(incoming));
            check_equal(plain, incoming, sizeof(incoming));
            check_equal(conn[1].recordlen, remaining);
            check_equal(conn[1].record_offset, offset);
            check_equal(conn[1].record, encrypted, remaining + offset);
            timed_key_send(&conn[1], &wire.outgoing, outgoing);
            duplex_expect_application(&conn[1], &wire.outgoing, &outgoing, 1u);
          } else {
            wire.incoming.read_budget = wire.incoming.size;
            check_equal(tls13_recv(&conn[1], plain, 1u, &received), 1);
            check_equal(received, (size_t)1u);
            check_equal(plain[0], incoming[0]);
            check_equal(conn[1].datalen, (size_t)2u);
            timed_key_send(&conn[1], &wire.outgoing, outgoing);
            duplex_expect_application(&conn[1], &wire.outgoing, &outgoing, 1u);
            check_equal(tls13_recv(&conn[1], plain, sizeof(plain), &received), 1);
            check_equal(received, (size_t)2u);
            check_equal(plain, incoming + 1u, 2u);
            check_equal(wire.incoming.read_offset, wire.incoming.size);
          }
        }
      }
    }
  }
}

spec("Crypto versioned peer close_notify facade") {
  it("rejects absent and malformed output without falsifying evidence") {
    uint32_t peer = UINT32_C(0xfeedbeef);
    check(crypto_tls_close_abi_version() == CRYPTO_TLS_CLOSE_ABI_VERSION,
          "close extension API version changed");
    check(crypto_tls_session_peer_close_notify_v1_4(NULL, &peer)
          == CRYPTO_TLS_INVALID_ARGUMENT,
          "NULL TLS session must be rejected");
    check(peer == UINT32_C(0xfeedbeef),
          "invalid session must not modify peer-alert evidence");
    check(crypto_tls_session_peer_close_notify_v1_4(NULL, NULL)
          == CRYPTO_TLS_INVALID_ARGUMENT,
          "NULL peer-alert output must be rejected");
  }
}

static int64_t would_block_write(
    void *user, const uint8_t *bytes, size_t length)
{
  (void)user;
  (void)bytes;
  (void)length;
  return CRYPTO_TLS_IO_AGAIN;
}

static int64_t would_block_read(
    void *user, uint8_t *bytes, size_t capacity)
{
  (void)user;
  (void)bytes;
  (void)capacity;
  return CRYPTO_TLS_IO_AGAIN;
}

spec("Crypto close_notify read-only ownership") {
  it("does not forge peer alerts before handshake or on cancel") {
    crypto_tls_provider *provider = NULL;
    crypto_tls_session *session = NULL;
    crypto_tls_session_options options = {0};
    crypto_tls_io io = {0};
    crypto_tls_result create_result;
    uint32_t observed = UINT32_C(0xfeedbeef);
    uint32_t count = 0u;

    options.struct_size = (uint32_t)sizeof(options);
    options.protocol = CRYPTO_TLS_1_3;
    options.role = CRYPTO_TLS_SERVER;
    options.certificate_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
    options.private_key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
    io.struct_size = (uint32_t)sizeof(io);
    io.read = would_block_read;
    io.write = would_block_write;
    check(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION, &provider)
          == CRYPTO_TLS_OK && provider != NULL,
          "cannot create real Crypto TLS provider");
    if (provider != NULL) {
      create_result = crypto_tls_session_create(
          provider, &options, &io, &session);
      check(create_result == CRYPTO_TLS_OK && session != NULL,
            "cannot create real pinned TLS server association: %d",
            (int)create_result);
      if (session != NULL) {
        check(crypto_tls_session_peer_close_notify_v1_4(session, &observed)
              == CRYPTO_TLS_AGAIN && observed == UINT32_C(0xfeedbeef),
              "uncompleted handshake must leave peer evidence unchanged");
        check(crypto_tls_provider_session_count(provider, &count)
              == CRYPTO_TLS_OK && count == 1u,
              "provider must retain its live session");
        check(crypto_tls_provider_destroy(&provider) == CRYPTO_TLS_BUSY
              && provider != NULL,
              "cannot destroy provider while its native session is live");
        check(crypto_tls_session_cancel(session) == CRYPTO_TLS_OK,
              "session cancel failed");
        check(crypto_tls_session_peer_close_notify_v1_4(session, &observed)
              == CRYPTO_TLS_CANCELLED
              && observed == UINT32_C(0xfeedbeef),
              "cancel must not create authenticated peer alert");
        check(crypto_tls_session_destroy(&session) == CRYPTO_TLS_OK
              && session == NULL,
              "destroy must wait for a quiescent session");
      }
      check(crypto_tls_provider_destroy(&provider) == CRYPTO_TLS_OK
            && provider == NULL,
            "provider cleanup failed after session teardown");
    }
  }
}

static crypto_tls_provider *close_provider;
static crypto_tls_session *close_session[2];
static crypto_tls_cipher_bio *close_bio[2];
static bool close_io_leased[2];

static void transfer_close_cipher(unsigned from, unsigned to) {
  uint8_t wire[32768];
  size_t size = 0u;
  crypto_tls_result result = crypto_tls_cipher_bio_take_cipher(
      close_bio[from], wire, sizeof(wire), &size);
  check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
  if (size != 0u)
    check_equal(crypto_tls_cipher_bio_feed_cipher(close_bio[to], wire, size),
                CRYPTO_TLS_OK);
}

static void establish_close_pair(crypto_tls_protocol protocol) {
  bool complete[2] = {false, false};
  for (unsigned i = 0u; i < 2u; ++i) {
    crypto_tls_session_options options = {0};
    crypto_tls_io io = {0};
    options.struct_size = sizeof(options);
    options.protocol = protocol;
    options.role = i == 0u ? CRYPTO_TLS_CLIENT : CRYPTO_TLS_SERVER;
    if (i == 0u) {
      options.hostname = "localhost";
      options.ca_file = CRYPTO_CLOSE_TEST_CA;
    } else {
      options.certificate_file = CRYPTO_CLOSE_TEST_SERVER_CERT;
      options.private_key_file = CRYPTO_CLOSE_TEST_SERVER_KEY;
    }
    check_equal(crypto_tls_cipher_bio_create(32768u, &close_bio[i]), CRYPTO_TLS_OK);
    io.struct_size = sizeof(io);
    check_equal(crypto_tls_cipher_bio_acquire_io(close_bio[i], &io), CRYPTO_TLS_OK);
    close_io_leased[i] = true;
    check_equal(crypto_tls_session_create(close_provider, &options, &io,
                                         &close_session[i]), CRYPTO_TLS_OK);
  }
  for (unsigned step = 0u; step < 128u && !(complete[0] && complete[1]); ++step) {
    for (unsigned i = 0u; i < 2u; ++i) {
      if (!complete[i]) {
        crypto_tls_result result = crypto_tls_session_handshake(close_session[i]);
        check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
        complete[i] = result == CRYPTO_TLS_OK;
      }
      transfer_close_cipher(i, 1u - i);
    }
  }
  check(complete[0] && complete[1], "real paired TLS handshake must finish");
}

spec("Crypto authenticated close evidence after real handshake") {
  before_each() {
    close_provider = NULL;
    memset(close_session, 0, sizeof(close_session));
    memset(close_bio, 0, sizeof(close_bio));
    memset(close_io_leased, 0, sizeof(close_io_leased));
    check_equal(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION,
                                          &close_provider), CRYPTO_TLS_OK);
  }
  after_each() {
    for (unsigned i = 0u; i < 2u; ++i) {
      if (close_session[i])
        check_equal(crypto_tls_session_destroy(&close_session[i]), CRYPTO_TLS_OK);
      if (close_io_leased[i])
        check_equal(crypto_tls_cipher_bio_release_io(close_bio[i]), CRYPTO_TLS_OK);
      if (close_bio[i])
        check_equal(crypto_tls_cipher_bio_destroy(&close_bio[i]), CRYPTO_TLS_OK);
    }
    if (close_provider)
      check_equal(crypto_tls_provider_destroy(&close_provider), CRYPTO_TLS_OK);
  }
  for (unsigned version = 0u; version < 2u; ++version) {
    const crypto_tls_protocol protocol = version ? CRYPTO_TLS_1_3 : CRYPTO_TLS_1_2;
    it("TLS1.%u conflicting operations preserve a pending send record", version + 2u) {
      uint8_t payload[16384] = {0};
      uint8_t received[16384];
      size_t sent = 0u, size = 0u, total = 0u;
      crypto_tls_result result;
      establish_close_pair(protocol);
      check_equal(crypto_tls_session_send(close_session[0], payload, sizeof(payload), &sent), CRYPTO_TLS_OK);
      check_equal(sent, sizeof(payload));
      check_equal(crypto_tls_session_send(close_session[0], payload, sizeof(payload), &sent), CRYPTO_TLS_AGAIN);
      check_equal(sent, 0u);
      check_equal(crypto_tls_session_send(close_session[0], payload + 1u, sizeof(payload) - 1u, &sent), CRYPTO_TLS_BUSY);
      check_equal(sent, 0u);
      check_equal(crypto_tls_session_send(close_session[0], payload, sizeof(payload) - 1u, &sent), CRYPTO_TLS_BUSY);
      check_equal(sent, 0u);
      check_equal(crypto_tls_session_shutdown(close_session[0]), CRYPTO_TLS_BUSY);
      /* Sequential entry is not permission to overwrite pending ciphertext. */
      result = crypto_tls_session_receive(close_session[0], received, sizeof(received), &size);
      check_equal(result, CRYPTO_TLS_BUSY);
      check_equal(size, 0u);
      transfer_close_cipher(0u, 1u);
      check_equal(crypto_tls_session_receive(close_session[1], received, sizeof(received), &size), CRYPTO_TLS_OK);
      check_equal(size, sizeof(payload));
      check_equal(crypto_tls_session_receive(close_session[1], received, sizeof(received), &size), CRYPTO_TLS_AGAIN);
      check_equal(crypto_tls_session_send(close_session[0], payload, sizeof(payload), &sent), CRYPTO_TLS_OK);
      check_equal(sent, sizeof(payload));
      transfer_close_cipher(0u, 1u);
      for (unsigned step = 0u; step < 16u && total < sizeof(payload); ++step) {
        result = crypto_tls_session_receive(close_session[1], received + total, sizeof(received) - total, &size);
        check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
        total += size;
      }
      check_equal(total, sizeof(payload));
      check_equal(received, payload, sizeof(payload));
    }
    const char *modes[] = {"reciprocal", "EOF", "truncated", "corrupted", "cancelled"};
    for (unsigned mode = 0u; mode < 5u; ++mode) {
      it("TLS1.%u %s cannot forge peer consent", version + 2u, modes[mode]) {
        uint8_t wire[32768], plaintext[32];
        size_t wire_size = 0u, size = 0u;
        uint32_t received = 99u;
        crypto_tls_result result;
        establish_close_pair(protocol);
        result = crypto_tls_session_shutdown(close_session[0]);
        check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
        check_equal(crypto_tls_session_send(close_session[0], plaintext, 1u, &size), CRYPTO_TLS_CLOSED);
        check_equal(size, 0u);
        check_equal(crypto_tls_session_peer_close_notify_v1_4(
                        close_session[0], &received), CRYPTO_TLS_OK);
        check_equal(received, 0u); /* Local alert is not peer evidence. */
        check_equal(crypto_tls_cipher_bio_take_cipher(
                        close_bio[0], wire, sizeof(wire), &wire_size), CRYPTO_TLS_OK);
        check(wire_size > 5u);
        if (mode != 1u) {
          if (mode == 2u) --wire_size;
          if (mode == 3u) wire[wire_size - 1u] ^= 1u;
          check_equal(crypto_tls_cipher_bio_feed_cipher(
                          close_bio[1], wire, wire_size), CRYPTO_TLS_OK);
        }
        if (mode == 1u || mode == 2u)
          check_equal(crypto_tls_cipher_bio_end_input(close_bio[1]), CRYPTO_TLS_OK);
        if (mode == 4u)
          check_equal(crypto_tls_session_cancel(close_session[1]), CRYPTO_TLS_OK);
        result = crypto_tls_session_receive(close_session[1], plaintext,
                                             sizeof(plaintext), &size);
        check_equal(size, 0u);
        received = 99u;
        check_equal(crypto_tls_session_peer_close_notify_v1_4(
                        close_session[1], &received),
                    mode == 4u ? CRYPTO_TLS_CANCELLED : CRYPTO_TLS_OK);
        check_equal(received, mode == 4u ? 99u : mode == 0u ? 1u : 0u);
        if (mode == 0u) {
          result = crypto_tls_session_shutdown(close_session[1]);
          check(result == CRYPTO_TLS_OK || result == CRYPTO_TLS_AGAIN);
          transfer_close_cipher(1u, 0u);
          result = crypto_tls_session_shutdown(close_session[0]);
          check_equal(result, CRYPTO_TLS_OK);
          check_equal(crypto_tls_session_peer_close_notify_v1_4(
                          close_session[0], &received), CRYPTO_TLS_OK);
          check_equal(received, 1u);
        } else {
          check(result < CRYPTO_TLS_OK, "invalid closure must terminate");
          check_equal(crypto_tls_session_receive(close_session[1], plaintext,
                          sizeof(plaintext), &size), result);
          check_equal(crypto_tls_session_shutdown(close_session[1]), result);
        }
      }
    }
  }
}

/* Same production primitives as CNet, in this separate formal executable.
 * See docs/CNET-NATIVE-TLS-BENCHMARK.md. No CNet linkage or application FIFO. */
enum { NATIVE_TLS_BYTES = 32768, NATIVE_TLS_WRITES = 2048,
       NATIVE_TLS_IO = CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES };
typedef struct native_tls_end {
  native_io_backend backend;
  native_io_endpoint endpoint;
  native_io_request read, write, connect;
  native_tls_socket socket;
  crypto_tls_stream_context *context;
  crypto_tls_stream *stream;
  size_t read_size, wire_size, wire_offset, submitted;
  bool connected, ready, peer_closed, notify_generated, drained;
  mem_buffer_t *mixed_payload;
  bool mixed_accepted;
  char version[24], cipher[128];
} native_tls_end;
typedef struct native_tls_fixture {
  tls_mixed_lane *mixed; /* Borrowed from parent until full native disposal. */
  native_tls_end ends[2];
  native_tls_socket listener;
  struct sockaddr_in address;
  mem_buffer_t *source;
  size_t chunk, offered, completed, received, receive_offset, target;
  size_t mixed_plaintext_capacity;
  size_t continuations;
  bool retained, accepted, closing, stopping;
  unsigned char plaintext[NATIVE_TLS_BYTES];
  uint64_t starts[NATIVE_TLS_WRITES], latency[NATIVE_TLS_WRITES];
} native_tls_fixture;
typedef struct native_tls_result {
  uint64_t elapsed, cpu, p50, p95, p99, submissions;
  size_t bytes, peak_bytes, peak_backing, continuations;
} native_tls_result;
static size_t native_tls_size(size_t index) { return index % 8u == 0u ? 1u : NATIVE_TLS_BYTES; }
static native_io_backend_kind native_tls_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}
static int native_tls_cpu(uint64_t *out) {
#if defined(_WIN32)
  FILETIME created, exited, kernel, user;
  if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return SALTS_EIO;
  *out = ((((uint64_t)kernel.dwHighDateTime << 32u) | kernel.dwLowDateTime) +
          (((uint64_t)user.dwHighDateTime << 32u) | user.dwLowDateTime)) * UINT64_C(100);
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) return SALTS_EIO;
  *out = ((uint64_t)usage.ru_utime.tv_sec + (uint64_t)usage.ru_stime.tv_sec) * UINT64_C(1000000000) +
         ((uint64_t)usage.ru_utime.tv_usec + (uint64_t)usage.ru_stime.tv_usec) * UINT64_C(1000);
#endif
  return SALTS_OK;
}
static int native_tls_compare(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static bool native_tls_matches(native_io_request a, native_io_request b) {
  return native_io_request_valid(a) && a.slot == b.slot && a.generation == b.generation;
}
static int native_tls_offer(native_tls_fixture *f) {
  if (f->retained) return SALTS_ENOBUFS;
  if (f->closing || !f->ends[0].ready || !f->ends[1].ready) return SALTS_EBUSY;
  if (f->offered >= f->target) return SALTS_EINVAL;
  mem_buffer_retain(f->source);
  f->retained = true;
  f->accepted = false;
  ++f->offered;
  return SALTS_OK;
}
static int native_tls_flush(native_tls_fixture *f, native_tls_end *end) {
  end->drained = false;
  if (native_io_request_valid(end->write)) return SALTS_OK;
  if (end->wire_offset == end->wire_size) {
    end->wire_offset = end->wire_size = 0u;
    const int status = crypto_tls_stream_take_cipher(end->stream,
        crypto_tls_stream_write_buffer(end->stream), NATIVE_TLS_IO, &end->wire_size);
    if (status == CRYPTO_TLS_STREAM_ENOENT) { end->drained = true; return SALTS_OK; }
    if (status != CRYPTO_TLS_STREAM_OK || end->wire_size == 0u) return SALTS_EPROTO;
  }
  const size_t remaining = end->wire_size - end->wire_offset;
  end->submitted = remaining < f->chunk ? remaining : f->chunk;
  const native_io_operation operation = {.kind = NATIVE_IO_OPERATION_STREAM_SEND,
      .endpoint = end->endpoint,
      .buffer = (unsigned char *)crypto_tls_stream_write_buffer(end->stream) + end->wire_offset,
      .length = end->submitted, .user_data = 2u};
  return native_io_backend_submit(&end->backend, &operation, &end->write);
}
static int native_tls_pump(native_tls_fixture *f, size_t index) {
  native_tls_end *end = &f->ends[index];
  if (!end->stream || f->stopping) return SALTS_OK;
  int status;
  if (!end->ready) {
    status = crypto_tls_stream_handshake(end->stream, &end->ready);
    if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
  } else if (f->closing) {
    if (index == 1u && !end->peer_closed) {
      bool plaintext_pending = false;
      status = crypto_tls_stream_probe_peer_close(end->stream, &end->peer_closed, &plaintext_pending);
      if (status != CRYPTO_TLS_STREAM_OK || plaintext_pending) return SALTS_EPROTO;
    }
    if (index == 0u || end->peer_closed) {
      bool generated = false, received = false;
      status = crypto_tls_stream_shutdown(end->stream, &generated, &received);
      if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
      end->notify_generated |= generated;
      end->peer_closed |= received;
    }
  } else if (f->mixed) {
    if (end->mixed_payload && !end->mixed_accepted) {
      status = crypto_tls_stream_write(end->stream, mem_buffer_data(end->mixed_payload),
          mem_buffer_used(end->mixed_payload), &end->mixed_accepted);
      if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
    }
    if (f->mixed->credit[index]) {
      size_t bytes = 0u;
      bool peer_closed = false;
      status = crypto_tls_stream_read(end->stream, f->plaintext,
          f->mixed_plaintext_capacity ? f->mixed_plaintext_capacity : sizeof(f->plaintext), &bytes, &peer_closed);
      if (status != CRYPTO_TLS_STREAM_OK || peer_closed) return SALTS_EPROTO;
      if (bytes != 0u) tls_mixed_received(f->mixed, index, f->plaintext, bytes);
    }
  } else {
    if (index == 0u && f->retained && !f->accepted) {
      status = crypto_tls_stream_write(end->stream, mem_buffer_data(f->source),
          native_tls_size(f->completed), &f->accepted);
      if (status != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
    }
    if (index == 1u && f->received < f->target) {
      size_t bytes = 0u;
      bool peer_closed = false;
      status = crypto_tls_stream_read(end->stream, f->plaintext, sizeof(f->plaintext), &bytes, &peer_closed);
      if (status != CRYPTO_TLS_STREAM_OK || peer_closed) return SALTS_EPROTO;
      for (size_t i = 0u; i < bytes; ++i) {
        if (f->received >= f->target || f->plaintext[i] !=
            (unsigned char)((0x5au + f->receive_offset * 29u) & 0xffu)) return SALTS_EPROTO;
        if (++f->receive_offset == native_tls_size(f->received)) {
          ++f->received;
          f->receive_offset = 0u;
        }
      }
    }
  }
  status = native_tls_flush(f, end);
  if (status != SALTS_OK) return status;
  if (f->mixed && end->mixed_payload && end->mixed_accepted && end->drained) {
    mem_buffer_t *source = end->mixed_payload;
    const size_t bytes = mem_buffer_used(source);
    end->mixed_payload = NULL;
    end->mixed_accepted = false;
    mem_buffer_release(source);
    tls_mixed_sent(f->mixed, index, bytes);
  }
  if (index == 0u && f->retained && f->accepted && end->drained) {
    if (f->completed >= f->offered || mem_buffer_ref_count(f->source) != 2u) return SALTS_EPROTO;
    f->latency[f->completed] = cmeta_hrtime() - f->starts[f->completed];
    ++f->completed;
    f->retained = false;
    mem_buffer_release(f->source);
  }
  if (!native_io_request_valid(end->read) && !(f->closing && end->peer_closed)) {
    const size_t capacity = crypto_tls_stream_cipher_input_capacity(end->stream);
    if (capacity != 0u) {
      end->read_size = capacity < NATIVE_TLS_IO ? capacity : NATIVE_TLS_IO;
      const native_io_operation operation = {.kind = NATIVE_IO_OPERATION_STREAM_RECV,
          .endpoint = end->endpoint, .buffer = crypto_tls_stream_read_buffer(end->stream),
          .length = end->read_size, .user_data = 1u};
      return native_io_backend_submit(&end->backend, &operation, &end->read);
    }
  }
  return SALTS_OK;
}
static int native_tls_route(native_tls_fixture *f, native_tls_end *end, const native_io_completion *c) {
  if (c->endpoint.slot != end->endpoint.slot || c->endpoint.generation != end->endpoint.generation)
    return SALTS_EPROTO;
  if (native_tls_matches(end->connect, c->request)) {
    end->connect = (native_io_request){0};
    if (f->stopping) return c->user_data == 3u ? SALTS_OK : SALTS_EPROTO;
    if (c->user_data != 3u || c->kind != NATIVE_IO_COMPLETION_OK || c->status != SALTS_OK)
      return SALTS_EIO;
    end->connected = true;
    return SALTS_OK;
  }
  const bool read = native_tls_matches(end->read, c->request);
  if (!read && !native_tls_matches(end->write, c->request)) return SALTS_EPROTO;
  if (read) end->read = (native_io_request){0};
  else end->write = (native_io_request){0};
  if (c->user_data != (read ? 1u : 2u)) return SALTS_EPROTO;
  if (f->stopping) return SALTS_OK; /* Actual observation retired the borrow. */
  if (c->kind != NATIVE_IO_COMPLETION_OK || c->status != SALTS_OK || c->bytes == 0u)
    return SALTS_EIO;
  if (read) {
    if (c->bytes > end->read_size || crypto_tls_stream_feed_cipher(end->stream,
          crypto_tls_stream_read_buffer(end->stream), c->bytes) != CRYPTO_TLS_STREAM_OK) return SALTS_EPROTO;
  } else {
    if (c->bytes > end->submitted || c->bytes > end->wire_size - end->wire_offset) return SALTS_EPROTO;
    end->wire_offset += c->bytes;
    if (end->wire_offset < end->wire_size) ++f->continuations;
  }
  return SALTS_OK;
}
static int native_tls_progress(native_tls_fixture *f) {
  int first = SALTS_OK;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    if (end->backend.impl == NULL) continue;
    int status = native_tls_pump(f, i);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
    native_io_completion completions[4];
    size_t count = 0u;
    status = native_io_backend_observe(&end->backend, completions, 4u, 0u, &count);
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT && first == SALTS_OK) first = status;
    for (size_t j = 0u; j < count; ++j) {
      status = native_tls_route(f, end, &completions[j]);
      if (status != SALTS_OK && first == SALTS_OK) first = status;
    }
  }
  return first;
}
static int native_tls_transfer(native_tls_fixture *f, size_t operations, bool check_full, native_tls_result *out) {
  native_io_backend_stats before[2], after[2];
  uint64_t cpu_start, cpu_end;
  const size_t continuations = f->continuations;
  if (operations == 0u || operations > NATIVE_TLS_WRITES || operations % 8u != 0u || f->retained)
    return SALTS_EINVAL;
  *out = (native_tls_result){0};
  f->target = operations;
  f->offered = f->completed = f->received = f->receive_offset = 0u;
  for (size_t i = 0u; i < 2u; ++i)
    if (!native_io_backend_get_stats(&f->ends[i].backend, &before[i])) return SALTS_EIO;
  if (native_tls_cpu(&cpu_start) != SALTS_OK) return SALTS_EIO;
  const uint64_t start = cmeta_hrtime(), deadline = start + UINT64_C(20000000000);
  while ((f->completed != operations || f->received != operations) && cmeta_hrtime() < deadline) {
    if (!f->retained && f->offered < operations) {
      f->starts[f->offered] = cmeta_hrtime();
      if (native_tls_offer(f) != SALTS_OK) return SALTS_EPROTO;
      if (check_full && (native_tls_offer(f) != SALTS_ENOBUFS ||
          mem_buffer_ref_count(f->source) != 2u)) return SALTS_EPROTO;
    }
    if (f->retained) {
      const size_t bytes = native_tls_size(f->completed);
      if (bytes > out->peak_bytes) out->peak_bytes = bytes;
      out->peak_backing = mem_buffer_capacity(f->source);
    }
    const int status = native_tls_progress(f);
    if (status != SALTS_OK) return status;
  }
  out->elapsed = cmeta_hrtime() - start;
  if (native_tls_cpu(&cpu_end) != SALTS_OK || cpu_end < cpu_start) return SALTS_EIO;
  out->cpu = cpu_end - cpu_start;
  out->continuations = f->continuations - continuations;
  if (f->completed != operations || f->received != operations || f->receive_offset || f->retained ||
      mem_buffer_ref_count(f->source) != 1u) return SALTS_EPROTO;
  for (size_t i = 0u; i < 2u; ++i) {
    if (!native_io_backend_get_stats(&f->ends[i].backend, &after[i])) return SALTS_EIO;
    out->submissions += after[i].submitted - before[i].submitted;
  }
  out->bytes = operations / 8u * (7u * NATIVE_TLS_BYTES + 1u);
  qsort(f->latency, operations, sizeof(f->latency[0]), native_tls_compare);
  out->p50 = f->latency[(operations * 50u + 99u) / 100u - 1u];
  out->p95 = f->latency[(operations * 95u + 99u) / 100u - 1u];
  out->p99 = f->latency[(operations * 99u + 99u) / 100u - 1u];
  return SALTS_OK;
}
static bool native_tls_pending(native_tls_fixture *f) {
  for (size_t i = 0u; i < 2u; ++i)
    if (native_io_request_valid(f->ends[i].read) || native_io_request_valid(f->ends[i].write) ||
        native_io_request_valid(f->ends[i].connect)) return true;
  return false;
}
static int native_tls_drain(native_tls_fixture *f) {
  f->stopping = true;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    if (native_io_request_valid(end->read)) (void)native_io_backend_cancel(&end->backend, end->read);
    if (native_io_request_valid(end->write)) (void)native_io_backend_cancel(&end->backend, end->write);
    if (native_io_request_valid(end->connect)) (void)native_io_backend_cancel(&end->backend, end->connect);
  }
  const uint64_t deadline = cmeta_monotonic_ms() + 3000u;
  int first = SALTS_OK;
  while (native_tls_pending(f) && cmeta_monotonic_ms() < deadline) {
    const int status = native_tls_progress(f);
    if (status != SALTS_OK && first == SALTS_OK) first = status;
  }
  return native_tls_pending(f) ? SALTS_ETIMEDOUT : first;
}
#define NATIVE_TLS_REQUIRE(expr) do { if (!(expr)) { \
  fprintf(stderr, "Native TLS benchmark failed at %d: %s\n", __LINE__, #expr); \
  result = __LINE__; goto cleanup; } } while (0)

static int native_tls_setup(native_tls_fixture *f, size_t chunk, uint64_t *handshake_ns) {
  int result = 0;
  f->listener = NATIVE_TLS_INVALID;
  for (size_t i = 0u; i < 2u; ++i) f->ends[i].socket = NATIVE_TLS_INVALID;
  f->chunk = chunk;
  const native_io_backend_config cfg = {native_tls_backend(), 2u, 8u, 4u};
  const crypto_tls_stream_client_config client_cfg = {
      .size = sizeof(crypto_tls_stream_client_config), .ca_file = CRYPTO_NATIVE_BENCH_CA,
      .server_name = "localhost"};
  const crypto_tls_stream_server_config server_cfg = {
      .size = sizeof(crypto_tls_stream_server_config), .cert_file = CRYPTO_NATIVE_BENCH_CERT,
      .key_file = CRYPTO_NATIVE_BENCH_KEY};
  NATIVE_TLS_REQUIRE(chunk > 0u && chunk <= NATIVE_TLS_IO);
  for (size_t i = 0u; i < 2u; ++i)
    NATIVE_TLS_REQUIRE(native_io_backend_init(&f->ends[i].backend, &cfg) == SALTS_OK);
  f->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  NATIVE_TLS_REQUIRE(f->listener != NATIVE_TLS_INVALID && native_tls_nonblocking(f->listener) == 0);
  f->address.sin_family = AF_INET;
  f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  NATIVE_TLS_REQUIRE(bind(f->listener, (const struct sockaddr *)&f->address, sizeof(f->address)) == 0);
  NATIVE_TLS_REQUIRE(listen(f->listener, 2) == 0);
#if defined(_WIN32)
  int address_size = sizeof(f->address);
#else
  socklen_t address_size = sizeof(f->address);
#endif
  NATIVE_TLS_REQUIRE(getsockname(f->listener, (struct sockaddr *)&f->address, &address_size) == 0);
  f->ends[0].socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  NATIVE_TLS_REQUIRE(f->ends[0].socket != NATIVE_TLS_INVALID && native_tls_nonblocking(f->ends[0].socket) == 0);
  NATIVE_TLS_REQUIRE(native_io_backend_attach_socket(&f->ends[0].backend,
      (uintptr_t)f->ends[0].socket, &f->ends[0].endpoint) == SALTS_OK);
  const native_io_operation connect = {.kind = NATIVE_IO_OPERATION_STREAM_CONNECT,
      .endpoint = f->ends[0].endpoint, .address = &f->address,
      .address_capacity = sizeof(f->address), .address_length = sizeof(f->address), .user_data = 3u};
  NATIVE_TLS_REQUIRE(native_io_backend_submit(&f->ends[0].backend, &connect, &f->ends[0].connect) == SALTS_OK);
  uint64_t deadline = cmeta_monotonic_ms() + 5000u;
  while ((!f->ends[0].connected || !f->ends[1].connected) && cmeta_monotonic_ms() < deadline) {
    if (!f->ends[1].connected) {
      f->ends[1].socket = accept(f->listener, NULL, NULL);
      if (f->ends[1].socket != NATIVE_TLS_INVALID) {
        NATIVE_TLS_REQUIRE(native_tls_nonblocking(f->ends[1].socket) == 0);
        NATIVE_TLS_REQUIRE(native_io_backend_attach_socket(&f->ends[1].backend,
            (uintptr_t)f->ends[1].socket, &f->ends[1].endpoint) == SALTS_OK);
        f->ends[1].connected = true;
      } else NATIVE_TLS_REQUIRE(native_tls_would_block());
    }
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  }
  NATIVE_TLS_REQUIRE(f->ends[0].connected && f->ends[1].connected);
  native_tls_socket_close(f->listener);
  f->listener = NATIVE_TLS_INVALID;
  NATIVE_TLS_REQUIRE(crypto_tls_stream_client_context_create(&client_cfg, &f->ends[0].context) == CRYPTO_TLS_STREAM_OK);
  NATIVE_TLS_REQUIRE(crypto_tls_stream_server_context_create(&server_cfg, &f->ends[1].context) == CRYPTO_TLS_STREAM_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    const int enabled = 1;
    NATIVE_TLS_REQUIRE(setsockopt(f->ends[i].socket, IPPROTO_TCP, TCP_NODELAY,
                                  (const char *)&enabled, sizeof(enabled)) == 0);
    NATIVE_TLS_REQUIRE(crypto_tls_stream_create(f->ends[i].context, i == 1u,
        i == 0u ? "localhost" : NULL, NATIVE_TLS_IO, &f->ends[i].stream) == CRYPTO_TLS_STREAM_OK);
  }
  f->source = f->mixed ? f->mixed->source[0] : mem_get_buffer(mem_global(), NATIVE_TLS_BYTES);
  NATIVE_TLS_REQUIRE(f->source != NULL);
  if (!f->mixed) {
    for (size_t i = 0u; i < NATIVE_TLS_BYTES; ++i)
      mem_buffer_data(f->source)[i] = (char)((0x5au + i * 29u) & 0xffu);
    mem_set_used(f->source, NATIVE_TLS_BYTES);
  }
  NATIVE_TLS_REQUIRE(native_tls_offer(f) == SALTS_EBUSY && mem_buffer_ref_count(f->source) == 1u);
  const uint64_t handshake_start = cmeta_hrtime();
  deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].ready || !f->ends[1].ready || !f->ends[0].drained || !f->ends[1].drained) &&
         cmeta_monotonic_ms() < deadline)
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  *handshake_ns = cmeta_hrtime() - handshake_start;
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    size_t size;
    NATIVE_TLS_REQUIRE(end->ready && end->drained && crypto_tls_stream_handshake_complete(end->stream));
    NATIVE_TLS_REQUIRE(crypto_tls_stream_negotiated_version(end->stream, end->version,
                        sizeof(end->version), &size) == CRYPTO_TLS_STREAM_OK);
    NATIVE_TLS_REQUIRE(crypto_tls_stream_negotiated_cipher(end->stream, end->cipher,
                        sizeof(end->cipher), &size) == CRYPTO_TLS_STREAM_OK);
    NATIVE_TLS_REQUIRE(strcmp(end->version, "TLSv1.3") == 0 || strcmp(end->version, "TLSv1.2") == 0);
    NATIVE_TLS_REQUIRE(end->cipher[0] != '\0');
  }
  NATIVE_TLS_REQUIRE(strcmp(f->ends[0].version, f->ends[1].version) == 0 &&
                     strcmp(f->ends[0].cipher, f->ends[1].cipher) == 0);
  return SALTS_OK;
cleanup:
  return result;
}

static int native_tls_close(native_tls_fixture *f, uint64_t *close_ns) {
  int result = 0;
  uint64_t deadline;
  const uint64_t close_start = cmeta_hrtime();
  f->closing = true;
  deadline = cmeta_monotonic_ms() + 7000u;
  while ((!f->ends[0].peer_closed || !f->ends[1].peer_closed || !f->ends[0].notify_generated ||
          !f->ends[1].notify_generated || !f->ends[0].drained || !f->ends[1].drained) &&
         cmeta_monotonic_ms() < deadline)
    NATIVE_TLS_REQUIRE(native_tls_progress(f) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i)
    NATIVE_TLS_REQUIRE(f->ends[i].peer_closed && f->ends[i].notify_generated && f->ends[i].drained);
  NATIVE_TLS_REQUIRE(native_tls_drain(f) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    native_tls_end *end = &f->ends[i];
    native_io_backend_stats stats;
    NATIVE_TLS_REQUIRE(native_io_backend_get_stats(&end->backend, &stats) && stats.active_requests == 0u);
    native_tls_socket_close(end->socket);
    end->socket = NATIVE_TLS_INVALID;
    NATIVE_TLS_REQUIRE(native_io_backend_release_socket(&end->backend, end->endpoint) == SALTS_OK);
    end->endpoint = (native_io_endpoint){0};
    NATIVE_TLS_REQUIRE(native_io_backend_get_stats(&end->backend, &stats) && stats.endpoint_count == 0u);
  }
  *close_ns = cmeta_hrtime() - close_start;
  return SALTS_OK;
cleanup:
  return result;
}

static bool native_tls_dispose(native_tls_fixture *f) {
  native_tls_socket_close(f->listener);
  if (native_tls_drain(f) == SALTS_OK) {
    bool released = true;
    for (size_t i = 0u; i < 2u; ++i) {
      native_tls_end *end = &f->ends[i];
      native_tls_socket_close(end->socket);
      end->socket = NATIVE_TLS_INVALID;
      if (native_io_endpoint_valid(end->endpoint)) {
        if (native_io_backend_release_socket(&end->backend, end->endpoint) != SALTS_OK) released = false;
        else end->endpoint = (native_io_endpoint){0};
      }
      (void)native_io_backend_close(&end->backend);
      if (native_io_backend_destroy(&end->backend) != SALTS_OK && end->backend.impl != NULL) released = false;
    }
    if (released) {
      for (size_t i = 0u; i < 2u; ++i) {
        crypto_tls_stream_destroy(f->ends[i].stream);
        crypto_tls_stream_context_release(f->ends[i].context);
        f->ends[i].stream = NULL;
        f->ends[i].context = NULL;
        if (f->ends[i].mixed_payload) {
          mem_buffer_release(f->ends[i].mixed_payload);
          f->ends[i].mixed_payload = NULL;
        }
      }
      if (f->retained) mem_buffer_release(f->source);
      if (f->source && !f->mixed) mem_buffer_release(f->source);
      f->source = NULL;
      f->retained = false;
      return true;
    }
  }
  return false; /* Keep live stream/native backing. */
}

static int native_tls_sample(bool report, unsigned repetition, size_t chunk) {
  native_tls_fixture *f = calloc(1u, sizeof(*f));
  int result = 0, transfer_status = SALTS_EIO;
  native_tls_result warm, measured;
  const size_t operations = report ? NATIVE_TLS_WRITES : 16u;
  uint64_t handshake_ns = 0u, close_ns = 0u;
  if (!f) return __LINE__;
  NATIVE_TLS_REQUIRE(native_tls_setup(f, chunk, &handshake_ns) == SALTS_OK);
  NATIVE_TLS_REQUIRE(native_tls_transfer(f, report ? 64u : 8u, !report, &warm) == SALTS_OK);
  if (report) {
    benchmark_io("direct NativeIO retained TLS transfer", 1, operations,
                 operations / 8u * (7u * NATIVE_TLS_BYTES + 1u)) {
      transfer_status = native_tls_transfer(f, operations, false, &measured);
    }
  } else transfer_status = native_tls_transfer(f, operations, true, &measured);
  NATIVE_TLS_REQUIRE(transfer_status == SALTS_OK && measured.elapsed != 0u && measured.submissions > 0u);
  if (chunk < NATIVE_TLS_IO) NATIVE_TLS_REQUIRE(measured.continuations > 0u);
  NATIVE_TLS_REQUIRE(native_tls_close(f, &close_ns) == SALTS_OK);
  if (report) printf("CNET_TLS_CSV,nativeio,%u,1,%zu,%s,%s,%llu,%zu,%llu,%llu,%llu,%llu,%llu,0,0,0,0,%zu,%zu,%zu,%llu,%llu\n",
      repetition, operations, f->ends[0].version, f->ends[0].cipher, (unsigned long long)handshake_ns,
      measured.bytes, (unsigned long long)measured.elapsed, (unsigned long long)measured.cpu,
      (unsigned long long)measured.p50, (unsigned long long)measured.p95, (unsigned long long)measured.p99,
      measured.peak_bytes, measured.peak_backing, mem_buffer_capacity(f->source),
      (unsigned long long)measured.submissions, (unsigned long long)close_ns);
cleanup:
  if (native_tls_dispose(f)) { free(f); return result; }
  return result ? result : __LINE__;
}

typedef struct tls_mixed_native_fixture {
  tls_mixed_state state;
  native_tls_fixture pair[2];
  size_t initialized;
} tls_mixed_native_fixture;
static int tls_mixed_native_send(void *user, size_t lane, size_t index, mem_buffer_t *source) {
  native_tls_fixture *f = &((tls_mixed_native_fixture *)user)->pair[lane];
  native_tls_end *end = &f->ends[index];
  if (f->closing || f->stopping || !f->ends[0].ready || !f->ends[1].ready) return SALTS_EBUSY;
  if (end->mixed_payload) return SALTS_ENOBUFS;
  if (!source || source != f->mixed->source[index]) return SALTS_EINVAL;
  end->mixed_payload = mem_buffer_retain(source);
  end->mixed_accepted = false;
  return SALTS_OK;
}
static int tls_mixed_native_receive(void *user, size_t lane, size_t end) {
  (void)user; (void)lane; (void)end;
  return SALTS_OK; /* Shared caller grants the credit consumed by the pump. */
}
static int tls_mixed_native_progress(void *user, size_t lane) {
  return native_tls_progress(&((tls_mixed_native_fixture *)user)->pair[lane]);
}
static int tls_mixed_native_snapshot(void *user, tls_mixed_stats *out) {
  tls_mixed_native_fixture *f = user;
  *out = (tls_mixed_stats){0};
  for (size_t i = 0u; i < 2u; ++i) {
    for (size_t e = 0u; e < 2u; ++e) {
      native_tls_end *end = &f->pair[i].ends[e];
      native_io_backend_stats stats;
      if (!native_io_backend_get_stats(&end->backend, &stats)) return SALTS_EIO;
      out->native_submissions[i] += stats.submitted;
      if (end->mixed_payload) out->usage[i][e] = (tls_mixed_usage){1u,
          mem_buffer_used(end->mixed_payload), mem_buffer_capacity(end->mixed_payload)};
    }
  }
  return SALTS_OK;
}
static int tls_mixed_native_sample(bool report, unsigned repetition, size_t chunk) {
  tls_mixed_native_fixture *f = calloc(1u, sizeof(*f));
  int result = 0, phase_status = SALTS_EIO;
  uint64_t handshake_ns, close_ns[2] = {0};
  tls_mixed_result warm, measured;
  crypto_tls_test_memory_stats start_memory, setup_memory, closing_memory, end_memory, setup_delta, close_delta;
  const size_t exchanges = report ? TLS_MIXED_EXCHANGES : 8u;
  if (!f) return __LINE__;
  NATIVE_TLS_REQUIRE(crypto_tls_stream_test_memory_snapshot(&start_memory));
  NATIVE_TLS_REQUIRE(tls_mixed_init(&f->state, 1u) == SALTS_OK);
  for (size_t i = 0u; i < 2u; ++i) {
    f->pair[i].mixed = &f->state.lane[i];
    if (chunk < NATIVE_TLS_IO) f->pair[i].mixed_plaintext_capacity = 1023u;
    ++f->initialized;
    NATIVE_TLS_REQUIRE(native_tls_setup(&f->pair[i], chunk, &handshake_ns) == SALTS_OK);
  }
  NATIVE_TLS_REQUIRE(strcmp(f->pair[0].ends[0].version, f->pair[1].ends[0].version) == 0);
  NATIVE_TLS_REQUIRE(strcmp(f->pair[0].ends[0].cipher, f->pair[1].ends[0].cipher) == 0);
  f->state.tls13 = strcmp(f->pair[0].ends[0].version, "TLSv1.3") == 0;
  NATIVE_TLS_REQUIRE(crypto_tls_stream_test_memory_snapshot(&setup_memory));
  NATIVE_TLS_REQUIRE(tls_mixed_memory_delta(&start_memory, &setup_memory, &setup_delta) == SALTS_OK);
  NATIVE_TLS_REQUIRE(setup_delta.allocation_calls > 0u && setup_delta.requested_bytes > 0u && setup_delta.failures == 0u);
  const tls_mixed_ops ops = {f, tls_mixed_native_send, tls_mixed_native_receive,
      tls_mixed_native_progress, tls_mixed_native_snapshot, crypto_tls_stream_test_memory_snapshot};
  NATIVE_TLS_REQUIRE(tls_mixed_phase(&f->state, &ops, 8u, &warm) == SALTS_OK);
  const size_t before_continuations = f->pair[0].continuations + f->pair[1].continuations;
  if (report) {
    benchmark_ops("independent direct TLS control RTT under bulk", 1, exchanges) {
      phase_status = tls_mixed_phase(&f->state, &ops, exchanges, &measured);
    }
  } else phase_status = tls_mixed_phase(&f->state, &ops, exchanges, &measured);
  if (phase_status != SALTS_OK) fprintf(stderr, "direct TLS mixed phase status=%d chunk=%zu\n", phase_status, chunk);
  NATIVE_TLS_REQUIRE(phase_status == SALTS_OK && measured.calls == 0u);
  if (chunk < NATIVE_TLS_IO)
    NATIVE_TLS_REQUIRE(f->pair[0].continuations + f->pair[1].continuations > before_continuations &&
        measured.memory.copied_bytes[CRYPTO_TLS_TEST_COPY_PENDING_PLAINTEXT] +
        measured.drain_memory.copied_bytes[CRYPTO_TLS_TEST_COPY_PENDING_PLAINTEXT] > 0u);
  NATIVE_TLS_REQUIRE(crypto_tls_stream_test_memory_snapshot(&closing_memory));
  for (size_t i = 0u; i < 2u; ++i) NATIVE_TLS_REQUIRE(native_tls_close(&f->pair[i], &close_ns[i]) == SALTS_OK);
  if (report) tls_mixed_print("nativeio", repetition, &f->state, &measured, close_ns[0] + close_ns[1],
                             f->pair[0].ends[0].version, f->pair[0].ends[0].cipher);
cleanup:;
  bool quiet = true;
  for (size_t i = 0u; i < f->initialized; ++i) if (!native_tls_dispose(&f->pair[i])) quiet = false;
  if (quiet && result == 0) {
    if (!crypto_tls_stream_test_memory_snapshot(&end_memory) ||
        tls_mixed_memory_delta(&closing_memory, &end_memory, &close_delta) != SALTS_OK ||
        close_delta.failures || close_delta.releases == 0u) result = __LINE__;
    else if (report) {
      tls_mixed_memory_print("nativeio", repetition, 1u, "setup", &setup_delta);
      tls_mixed_memory_print("nativeio", repetition, 1u, "warm", &warm.memory);
      tls_mixed_memory_print("nativeio", repetition, 1u, "warm_drain", &warm.drain_memory);
      tls_mixed_memory_print("nativeio", repetition, 1u, "transfer", &measured.memory);
      tls_mixed_memory_print("nativeio", repetition, 1u, "drain", &measured.drain_memory);
      tls_mixed_memory_print("nativeio", repetition, 1u, "close_destroy", &close_delta);
    }
  }
  if (quiet) { tls_mixed_release(&f->state); free(f); return result; }
  return result ? result : __LINE__; /* Retain the whole live parent/transport fixture. */
}
#undef NATIVE_TLS_REQUIRE

spec("Production Crypto TLS over direct NativeIO") {
  for (unsigned bound = 0u; bound < 2u; ++bound) {
    it("drains independent direct TLS bulk/control with native bound %u", bound ? 4096u : NATIVE_TLS_IO) {
      const int result = tls_mixed_native_sample(false, 0u, bound ? 4096u : NATIVE_TLS_IO);
      check(result == 0, "direct TLS mixed correctness returned %d", result);
    }
  }
  const char *mixed_measure = getenv("SALTSCORE_NATIVE_TLS_MIXED_BENCHMARK");
  if (mixed_measure != NULL) {
    it("uses the explicit native TLS mixed benchmark switch") { check_equal(mixed_measure, "1"); }
    if (strcmp(mixed_measure, "1") == 0)
      for (unsigned repetition = 0u; repetition < 5u; ++repetition) {
        it("measures direct mixed TLS control, repetition %u", repetition) {
          const int result = tls_mixed_native_sample(true, repetition, NATIVE_TLS_IO);
          check(result == 0, "direct TLS mixed sample returned %d", result);
        }
      }
  }
  for (unsigned bound = 0u; bound < 2u; ++bound) {
    it("drains direct TLS with native write bound %u", bound ? 4096u : NATIVE_TLS_IO) {
      const int result = native_tls_sample(false, 0u, bound ? 4096u : NATIVE_TLS_IO);
      check(result == 0, "direct TLS transfer returned %d", result);
    }
  }
  if (getenv("SALTSCORE_NATIVE_TLS_BENCHMARK") != NULL) {
    it("uses the explicit direct TLS benchmark switch") {
      check_equal(getenv("SALTSCORE_NATIVE_TLS_BENCHMARK"), "1");
    }
    if (strcmp(getenv("SALTSCORE_NATIVE_TLS_BENCHMARK"), "1") == 0)
    for (unsigned repetition = 0u; repetition < 5u; ++repetition) {
      it("measures direct NativeIO TLS transfer repetition %u", repetition) {
        const int result = native_tls_sample(true, repetition, NATIVE_TLS_IO);
        check(result == 0, "direct TLS benchmark returned %d", result);
      }
    }
  }
}
