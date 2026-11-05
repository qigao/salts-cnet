/* Drive the production opaque server to ClientHello2 with a generated P-256
 * share. These parser-boundary cases stop at ServerHello; independent Python
 * clients separately verify the complete authenticated HRR transcript. */
static const unsigned char tls_test_hrr_random[32] = {
    0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
    0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};

static size_t tls_test_hrr_hello(const unsigned char *original, unsigned char *out,
    bool first, unsigned scenario) {
  int protocol, suites[32];
  const unsigned char *random, *sid, *ciphers, *extensions;
  size_t sid_size, ciphers_size, extensions_size, size = 0u;
  unsigned char encoded[4096], *p = encoded;
  check_equal(tls_record_get_handshake_client_hello(original, &protocol, &random,
      &sid, &sid_size, &ciphers, &ciphers_size, &extensions, &extensions_size), 1);
  check(ciphers_size <= sizeof(suites) / sizeof(suites[0]) * 2u && ciphers_size % 2u == 0u);
  for (size_t i = 0u; i < ciphers_size / 2u; ++i)
    suites[i] = (ciphers[2u*i] << 8u) | ciphers[2u*i+1u];
  check(extensions_size + 128u < sizeof(encoded));
  while (extensions_size) {
    int type; const unsigned char *data; size_t length;
    check_equal(tls_ext_from_bytes(&type, &data, &length, &extensions, &extensions_size), 1);
    if (type == TLS_extension_padding) continue;
    if (scenario == 9u && type == TLS_extension_post_handshake_auth) continue;
    if (!first && ((scenario == 10u && type == TLS_extension_server_name) ||
        (scenario == 12u && type == TLS_extension_signature_algorithms))) continue;
    const unsigned char empty_share[2] = {0, 0};
    if (first && type == TLS_extension_key_share) { data = empty_share; length = sizeof(empty_share); }
    check_equal(tls_ext_to_bytes(type, data, length, &p, &size), 1);
    if (!first && scenario == 11u && type == TLS_extension_server_name) {
      check(length > 0u); p[-1] ^= 1u;
    }
  }
  int padding = -1;
  if (first) {
    if (scenario == 1u || scenario == 2u || scenario == 6u || scenario == 13u) padding = 8;
    if (scenario == 3u) padding = 32;
    if (scenario == 5u) padding = 0;
  } else {
    if (scenario == 0u || scenario == 3u || scenario >= 6u) padding = 8;
    if (scenario == 2u) padding = 32;
    if (scenario == 4u) padding = 0;
  }
  if (padding >= 0) {
    unsigned char zeros[32] = {0};
    if (!first && scenario == 7u) zeros[0] = 1u;
    check_equal(tls_ext_to_bytes(TLS_extension_padding, zeros, (size_t)padding, &p, &size), 1);
    if (!first && scenario == 8u)
      check_equal(tls_ext_to_bytes(TLS_extension_padding, zeros, (size_t)padding, &p, &size), 1);
  }
  if (!first && scenario == 9u)
    check_equal(tls_ext_to_bytes(TLS_extension_post_handshake_auth, NULL, 0u, &p, &size), 1);
  if (!first && scenario == 14u) --size; /* Truncated extension payload. */
  unsigned char chosen_random[32]; memcpy(chosen_random, random, sizeof(chosen_random));
  if (!first && scenario == 13u) chosen_random[0] ^= 1u;
  size_t record_size = 0u;
  tls_record_set_protocol(out, TLS_protocol_tls12);
  check_equal(tls_record_set_handshake_client_hello(out, &record_size, protocol, chosen_random,
      sid, sid_size, suites, ciphers_size / 2u, encoded, size), 1);
  return record_size;
}

static void tls_test_hrr_padding(unsigned scenario) {
  tls_memory_contexts(CRYPTO_TLS_ENCODING_DER, 0u, 13u, 0u);
  for (unsigned i = 0u; i < 2u; ++i)
    check_equal(crypto_tls_stream_create(stream_context[i], i != 0u,
        i ? NULL : "localhost", 32768u, &stream_pair[i]), CRYPTO_TLS_STREAM_OK);
  bool complete = false;
  unsigned char original[32768], hello[32768], flight[32768];
  size_t size = 0u;
  check_equal(crypto_tls_stream_handshake(stream_pair[0], &complete), CRYPTO_TLS_STREAM_OK);
  check_equal(crypto_tls_stream_take_cipher(stream_pair[0], original, sizeof(original), &size), CRYPTO_TLS_STREAM_OK);
  check(size > 44u);
  for (unsigned round = 0u; round < 2u; ++round) {
    size = tls_test_hrr_hello(original, hello, round == 0u, scenario);
    check_equal(crypto_tls_stream_feed_cipher(stream_pair[1], hello, size), CRYPTO_TLS_STREAM_OK);
    int status = crypto_tls_stream_handshake(stream_pair[1], &complete);
    check_false(complete);
    check_equal(status, round && scenario >= 7u ? CRYPTO_TLS_STREAM_ECONNABORTED : CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_take_cipher(stream_pair[1], flight, sizeof(flight), &size), CRYPTO_TLS_STREAM_OK);
    if (round && scenario >= 7u) {
      check(size >= 7u && flight[0] == 21u && flight[5] == 2u); /* Fatal alert, no ServerHello. */
      check_equal(flight[6], scenario == 14u ? TLS_alert_decode_error : TLS_alert_illegal_parameter);
      check_equal(crypto_tls_stream_handshake(stream_pair[1], &complete), CRYPTO_TLS_STREAM_ECONNABORTED);
      check_false(complete);
    } else {
      int protocol, suite; const unsigned char *random, *sid, *exts; size_t sid_size, exts_size;
      check_equal(tls_record_get_handshake_server_hello(flight, &protocol, &random,
          &sid, &sid_size, &suite, &exts, &exts_size), 1);
      if (round == 0u) check_equal(random, tls_test_hrr_random, sizeof(tls_test_hrr_random));
      else check(memcmp(random, tls_test_hrr_random, sizeof(tls_test_hrr_random)) != 0);
    }
  }
}
