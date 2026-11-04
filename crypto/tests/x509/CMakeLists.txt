# Strict X.509 structural DER inspection based only on sibling ASN1.
# TLS handshake/certificate authentication stays GmSSL-owned.
# Compile the actual inspector in the formal tests with only ASN1/TinyTest.
# This preserves the provider-free link boundary of the retired standalone
# project while TinyTest owns the original DER and negative assertions.
set_source_files_properties(test_x509_der.c PROPERTIES
  COMPILE_DEFINITIONS "main=crypto_x509_real_legacy_entry")
add_executable(crypto_x509_der_conformance
  test_x509_der.c real_der_tinytest.c ../../src/crypto_x509_der.c)
target_include_directories(crypto_x509_der_conformance PRIVATE ../../include)
target_compile_features(crypto_x509_der_conformance PRIVATE c_std_11)
set_target_properties(crypto_x509_der_conformance PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_compile_definitions(crypto_x509_der_conformance PRIVATE
  "CRYPTO_X509_TEST_P256_PEM=\"${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/p256-leaf-sha384.pem\""
  "CRYPTO_X509_TEST_P384_PEM=\"${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/p384-leaf-sha384.pem\"")
target_link_libraries(crypto_x509_der_conformance PRIVATE Salts::ASN1 Salts::TinyTest)
add_test(NAME crypto.x509.real_der_and_negative
  COMMAND crypto_x509_der_conformance)
set_tests_properties(crypto.x509.real_der_and_negative PROPERTIES TIMEOUT 120)

# Retain the exact historical SaltsNet 951-byte X.509 DER regression,
# but execute it only against the Crypto-owned strict inspector.
set_source_files_properties(test_saltsnet_x509_der.c PROPERTIES
  COMPILE_DEFINITIONS "main=crypto_x509_saltsnet_legacy_entry")
add_executable(crypto_x509_moved_saltsnet_fixture
  test_saltsnet_x509_der.c saltsnet_der_tinytest.c ../../src/crypto_x509_der.c)
target_include_directories(crypto_x509_moved_saltsnet_fixture PRIVATE ../../include)
target_compile_features(crypto_x509_moved_saltsnet_fixture PRIVATE c_std_11)
target_link_libraries(crypto_x509_moved_saltsnet_fixture PRIVATE Salts::ASN1 Salts::TinyTest)
add_test(NAME crypto.x509.migrated_saltsnet_fixture
         COMMAND crypto_x509_moved_saltsnet_fixture)
