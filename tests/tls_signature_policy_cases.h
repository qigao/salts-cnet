static int run_signature_policy_cases(void) {
  const char *label = "immutable signature policy";
  cnet_tls_client client = {0};
  cnet_tls_server server = {0};
  int result = 0;
  for (unsigned bad = 0u; bad < 13u; ++bad) {
    cnet_tls_signature_scheme schemes[] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256,
        CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
        CRYPTO_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384};
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-signature-ca.pem",
        .signature_algorithms = schemes, .signature_algorithm_count = 4u};
    cnet_tls_server_config sc = {.size = sizeof(sc), .cert_file = "absent-signature-cert.pem",
        .key_file = "absent-signature-key.pem"};
    switch (bad) {
      case 0: cc.signature_algorithms = NULL; break;
      case 1: cc.signature_algorithm_count = 0u; break;
      case 2: cc.signature_algorithm_count = 5u; break;
      case 3: cc.signature_algorithm_count = SIZE_MAX; break;
      case 4: schemes[3] = schemes[2]; break;
      case 5: schemes[3] = (cnet_tls_signature_scheme)0x0807; break;
      case 6: schemes[3] = (cnet_tls_signature_scheme)0xffff; break;
      case 7: schemes[3] = CRYPTO_TLS_SIGNATURE_SM2_SM3; break;
      case 8: cc.signature_algorithm_count = 1u; cc.minimum_version = 13; break;
      case 9: cc.signature_algorithms = schemes + 1u; cc.signature_algorithm_count = 1u; break;
      case 10: cc.maximum_version = 12; break;
      case 11: cc.security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13; break;
      case 12: cc.security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11; break;
    }
    sc.signature_algorithms = cc.signature_algorithms; sc.signature_algorithm_count = cc.signature_algorithm_count;
    sc.minimum_version = cc.minimum_version; sc.maximum_version = cc.maximum_version;
    sc.security_profile = cc.security_profile;
    int expected = bad < 5u ? SALTS_EINVAL : SALTS_ENOTSUP;
    REQUIRE(cnet_tls_client_init(&client, &cc) == expected);
    REQUIRE(cnet_tls_server_init(&server, &sc) == expected);
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  /* P256 leaf signed by P384 CA: handshake and chain signatures need different
   * schemes. Excluding the issuer scheme must not permit a verified channel. */
  for (unsigned version = 0u; version < 3u; ++version) {
    for (unsigned scenario = 0u; scenario < 4u; ++scenario) {
      const cnet_tls_signature_scheme schemes[] = {CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
          CRYPTO_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384};
      tls_case_options options = {.label = "signature admission, source erasure and certificate signatures",
          .ca_file = CORE_TLS_TEST_P384_CA, .verified_hostname = "localhost", .expect_success = scenario < 3u,
          .client_minimum = version == 2u ? 13 : 0, .client_maximum = version == 1u ? 12 : 0,
          .server_minimum = version == 2u ? 13 : 0, .server_maximum = version == 1u ? 12 : 0,
          .client_signatures = scenario != 1u ? schemes : NULL,
          .client_signature_count = scenario == 3u ? 1u : scenario != 1u ? 2u : 0u,
          .server_signatures = scenario != 0u && scenario != 3u ? schemes : NULL,
          .server_signature_count = scenario != 0u && scenario != 3u ? 2u : 0u,
          .expected_version = version == 1u ? "TLSv1.2" : "TLSv1.3",
          .release_tls_context_early = true, .expect_server_rejection = false};
      REQUIRE(run_case(&options) == 0);
    }
  }
cleanup:
  (void)cnet_tls_client_destroy(&client);
  (void)cnet_tls_server_destroy(&server);
  return result;
}
