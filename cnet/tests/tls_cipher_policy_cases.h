/* Formal production CNet admission and real encrypted transport cases. */
static int run_cipher_policy_cases(void) {
  const char *label = "immutable cipher policy";
  cnet_tls_client client = {0};
  cnet_tls_server server = {0};
  int result = 0;
  for (unsigned bad = 0u; bad < 14u; ++bad) {
    cnet_tls_cipher_suite suites[] = {CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256,
        CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256,
        CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256};
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-cipher-ca.pem",
        .cipher_suites = suites, .cipher_suite_count = 3u};
    cnet_tls_server_config sc = {.size = sizeof(sc),
        .cert_file = "absent-cipher-cert.pem", .key_file = "absent-cipher-key.pem"};
    switch (bad) {
      case 0: cc.cipher_suites = NULL; break;
      case 1: cc.cipher_suite_count = 0u; break;
      case 2: cc.cipher_suite_count = 4u; break;
      case 3: cc.cipher_suite_count = SIZE_MAX; break;
      case 4: suites[2] = suites[1]; break;
      case 5: suites[2] = (cnet_tls_cipher_suite)0x1302; break; /* Unqualified AES256. */
      case 6: suites[2] = (cnet_tls_cipher_suite)0xffff; break;
      case 7: suites[2] = CRYPTO_TLS_CIPHER_SM4_GCM_SM3; break;
      case 8: cc.cipher_suite_count = 1u; break; /* TLS12 has no suite. */
      case 9: cc.cipher_suites = suites + 1u; cc.cipher_suite_count = 2u; break;
      case 10: cc.maximum_version = CNET_TLS_PROTOCOL_VERSION_1_2; break;
      case 11: cc.minimum_version = CNET_TLS_PROTOCOL_VERSION_1_3; break;
      case 12: cc.security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13; break;
      case 13: cc.security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11; break;
    }
    sc.cipher_suites = cc.cipher_suites; sc.cipher_suite_count = cc.cipher_suite_count;
    sc.minimum_version = cc.minimum_version; sc.maximum_version = cc.maximum_version;
    sc.security_profile = cc.security_profile;
    const int expected = bad < 5u ? SALTS_EINVAL : SALTS_ENOTSUP;
    REQUIRE(cnet_tls_client_init(&client, &cc) == expected);
    REQUIRE(cnet_tls_server_init(&server, &sc) == expected);
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  for (unsigned version = 0u; version < 3u; ++version) {
    for (unsigned endpoint = 0u; endpoint < 3u; ++endpoint) {
      const cnet_tls_cipher_suite suites[] = {CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256,
          CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256};
      const cnet_tls_cipher_suite *selected = suites + (version == 2u ? 1u : 0u);
      const size_t count = version ? 1u : 2u;
      tls_case_options options = {.label = "explicit cipher intersection and source erasure",
          .ca_file = CORE_TLS_TEST_P384_CA, .verified_hostname = "localhost", .expect_success = true,
          .client_minimum = version == 2u ? 13 : 0, .client_maximum = version == 1u ? 12 : 0,
          .server_minimum = version == 2u ? 13 : 0, .server_maximum = version == 1u ? 12 : 0,
          .client_ciphers = endpoint != 1u ? selected : NULL, .client_cipher_count = endpoint != 1u ? count : 0u,
          .server_ciphers = endpoint != 0u ? selected : NULL, .server_cipher_count = endpoint != 0u ? count : 0u,
          .expected_version = version == 1u ? "TLSv1.2" : "TLSv1.3",
          .expected_cipher = version == 1u ? "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" : "TLS_AES_128_GCM_SHA256",
          .release_tls_context_early = true};
      REQUIRE(run_case(&options) == 0);
    }
  }
  for (unsigned reverse = 0u; reverse < 2u; ++reverse) {
    const cnet_tls_cipher_suite rsa = CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256;
    const cnet_tls_cipher_suite ecdsa = CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256;
    tls_case_options options = {.label = "disjoint cipher policies never connect or send plaintext",
        .ca_file = CORE_TLS_TEST_P384_CA, .verified_hostname = "localhost",
        .client_minimum = 12, .client_maximum = 12, .server_minimum = 12, .server_maximum = 12,
        .client_ciphers = reverse ? &ecdsa : &rsa, .server_ciphers = reverse ? &rsa : &ecdsa,
        .client_cipher_count = 1u, .server_cipher_count = 1u,
        .expect_server_rejection = true, .expected_failure = CRYPTO_TLS_FAILURE_HANDSHAKE};
    REQUIRE(run_case(&options) == 0);
  }
cleanup:
  (void)cnet_tls_client_destroy(&client);
  (void)cnet_tls_server_destroy(&server);
  return result;
}
