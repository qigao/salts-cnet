cmake_add_executable(saltscore_gmssl_tls_io_abi_test SOURCES test_gmssl_tls_io_abi.c
  FOLDER "crypto/tests/tls")
target_link_libraries(saltscore_gmssl_tls_io_abi_test PRIVATE
  Salts::Crypto Salts::Core Salts::NativeIO Salts::TinyTest)
target_include_directories(saltscore_gmssl_tls_io_abi_test PRIVATE
  "${_salts_crypto_source_dir}/src"
  "$<TARGET_PROPERTY:GmSSL::GmSSL,INTERFACE_INCLUDE_DIRECTORIES>")
target_compile_definitions(saltscore_gmssl_tls_io_abi_test PRIVATE
  SALTSCORE_EXPECT_PROVIDER_COPIES=0
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES
  "CRYPTO_NATIVE_BENCH_CA=\"${_salts_crypto_source_dir}/tests/fixtures/p384-test-root-cert.pem\""
  "CRYPTO_NATIVE_BENCH_CERT=\"${_salts_crypto_source_dir}/tests/fixtures/p384-test-server-cert.pem\""
  "CRYPTO_NATIVE_BENCH_KEY=\"${_salts_crypto_source_dir}/tests/fixtures/p384-test-server-key.pem\""
  "CRYPTO_CLOSE_TEST_CA=\"${_salts_crypto_source_dir}/tests/fixtures/external-io-ca-cert.pem\""
  "CRYPTO_CLOSE_TEST_SERVER_CERT=\"${_salts_crypto_source_dir}/tests/fixtures/external-io-server-cert.pem\""
  "CRYPTO_CLOSE_TEST_SERVER_KEY=\"${_salts_crypto_source_dir}/tests/fixtures/external-io-server-key.pem\"")
add_test(NAME saltscore.gmssl_tls_io_abi COMMAND saltscore_gmssl_tls_io_abi_test)

cmake_add_executable(saltscore_gmssl_shangmi_provider_test SOURCES test_gmssl_shangmi_provider.c
  FOLDER "crypto/tests/tls")
target_link_libraries(saltscore_gmssl_shangmi_provider_test PRIVATE Salts::Crypto Salts::TinyTest)
target_include_directories(saltscore_gmssl_shangmi_provider_test PRIVATE
  "$<TARGET_PROPERTY:GmSSL::GmSSL,INTERFACE_INCLUDE_DIRECTORIES>")
target_compile_definitions(saltscore_gmssl_shangmi_provider_test PRIVATE
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
add_test(NAME saltscore.gmssl_shangmi_provider
  COMMAND saltscore_gmssl_shangmi_provider_test)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_CRYPTO_TEST_GO go REQUIRED)
  # Separate image: one Crypto/GmSSL owner, never also Salts::CNet.
  add_executable(saltscore_crypto_tls_peer_policy_test test_crypto_tls_peer_policy.c)
  target_link_libraries(saltscore_crypto_tls_peer_policy_test PRIVATE Salts::Crypto)
  if(MSVC)
    # The peer-policy fixture owns C11 atomic retain/release counters.
    target_compile_options(saltscore_crypto_tls_peer_policy_test PRIVATE /experimental:c11atomics)
  endif()
  set_target_properties(saltscore_crypto_tls_peer_policy_test PROPERTIES FOLDER "crypto/tests/tls")
  add_test(NAME saltscore.crypto_tls_shangmi_revocation
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiRevocation$"
      -args -native "$<TARGET_FILE:saltscore_crypto_tls_peer_policy_test>")
  set_tests_properties(saltscore.crypto_tls_shangmi_revocation PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/cnet/tests/independent/shangmi"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
endif()
