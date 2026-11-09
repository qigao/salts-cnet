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
  {
    const cnet_tls_signature_scheme handshake = CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    const cnet_tls_signature_scheme certificate = CRYPTO_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384;
    for (unsigned version = 0; version < 5; ++version) {
      for (unsigned side = 0; side < 5; ++side) {
        tls_case_options options = {.label = "separate handshake and certificate signatures",
            .ca_file = CORE_TLS_TEST_P384_CA, .verified_hostname = "localhost", .expect_success = true,
            .client_minimum = 13, .client_maximum = 13, .server_minimum = 13, .server_maximum = 13,
            .client_signatures = &handshake, .client_signature_count = 1,
            .server_signatures = &handshake, .server_signature_count = 1,
            .client_certificate_signatures = &certificate, .client_certificate_signature_count = 1,
            .server_certificate_signatures = &certificate, .server_certificate_signature_count = 1,
            .expected_version = "TLSv1.3", .release_tls_context_early = true};
        if (side == 1) { options.client_certificate_signatures = &handshake; options.expect_success = false; }
        if (side == 2) { options.server_certificate_signatures = &handshake; options.expect_success = false; options.expect_server_rejection = true; }
        const cnet_tls_signature_scheme shared[] = {handshake, certificate};
        if (side >= 3) {
          options.client_certificate_signatures = NULL; options.client_certificate_signature_count = 0;
          if (side == 3) { options.client_signatures = shared; options.client_signature_count = 2; }
          else { options.expect_success = false; options.expect_server_rejection = true; }
        }
        if (version != 0) {
          options.client_minimum = version == 1 || version == 4 ? 12 : 0;
          options.client_maximum = version == 1 || version == 4 ? 12 : 0;
          options.server_minimum = version == 1 || version == 3 ? 12 : 0;
          options.server_maximum = version == 1 || version == 3 ? 12 : 0;
          options.expected_version = version == 2 ? "TLSv1.3" : "TLSv1.2";
        }
        REQUIRE(run_case(&options) == 0);
      }
    }
  }
  for (unsigned bad = 0; bad < 9; ++bad) {
    cnet_tls_signature_scheme certs[2] = {CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256, CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256};
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "missing.pem", .minimum_version = 13,
        .maximum_version = 13, .certificate_signature_algorithms = certs, .certificate_signature_algorithm_count = 2};
    switch (bad) {
      case 0: cc.certificate_signature_algorithms = NULL; break;
      case 1: cc.certificate_signature_algorithm_count = 0; break;
      case 2: cc.certificate_signature_algorithm_count = 5; break;
      case 3: certs[1] = certs[0]; break;
      case 4: certs[1] = CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256; break;
      case 5: certs[1] = CRYPTO_TLS_SIGNATURE_SM2_SM3; break;
      case 6: cc.security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11; cc.minimum_version = cc.maximum_version = 0; break;
      case 7: cc.security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13; break;
      case 8: certs[1] = (cnet_tls_signature_scheme)0xffff; break;
    }
    REQUIRE(cnet_tls_client_init(&client, &cc) == (bad < 4 ? SALTS_EINVAL : SALTS_ENOTSUP));
    REQUIRE(client.impl == NULL);
    cnet_tls_server_config sc = {.size = sizeof(sc), .cert_file = "missing-cert.pem", .key_file = "missing-key.pem",
        .security_profile = cc.security_profile, .minimum_version = cc.minimum_version, .maximum_version = cc.maximum_version,
        .certificate_signature_algorithms = cc.certificate_signature_algorithms,
        .certificate_signature_algorithm_count = cc.certificate_signature_algorithm_count};
    REQUIRE(cnet_tls_server_init(&server, &sc) == (bad < 4 ? SALTS_EINVAL : SALTS_ENOTSUP));
    REQUIRE(server.impl == NULL);
  }
cleanup:
  (void)cnet_tls_client_destroy(&client);
  (void)cnet_tls_server_destroy(&server);
  return result;
}
