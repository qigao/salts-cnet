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

add_executable(crypto_sm2_x509_test sm2_x509.c)
target_link_libraries(crypto_sm2_x509_test PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
set_target_properties(crypto_sm2_x509_test PROPERTIES FOLDER "Crypto/tests/x509")
add_test(NAME crypto.x509.sm2_signatures COMMAND crypto_sm2_x509_test)
set_tests_properties(crypto.x509.sm2_signatures PROPERTIES TIMEOUT 120)

add_executable(crypto_sm2_trust_admission sm2_trust_admission.c)
target_link_libraries(crypto_sm2_trust_admission PRIVATE Salts::Crypto Salts::TinyTest)
set_target_properties(crypto_sm2_trust_admission PROPERTIES FOLDER "Crypto/tests/x509")
add_test(NAME crypto.x509.sm2_trust_admission COMMAND crypto_sm2_trust_admission)

add_executable(crypto_sm2_crl_admission sm2_crl_admission.c)
target_link_libraries(crypto_sm2_crl_admission PRIVATE Salts::Crypto Salts::TinyTest)
set_target_properties(crypto_sm2_crl_admission PROPERTIES FOLDER "Crypto/tests/x509")
add_test(NAME crypto.x509.sm2_crl_admission COMMAND crypto_sm2_crl_admission)

add_executable(crypto_sm2_cms_admission sm2_cms_admission.c)
target_link_libraries(crypto_sm2_cms_admission PRIVATE Salts::Crypto Salts::TinyTest)
set_target_properties(crypto_sm2_cms_admission PROPERTIES FOLDER "Crypto/tests/x509")
add_test(NAME crypto.x509.sm2_cms_admission COMMAND crypto_sm2_cms_admission)

add_executable(crypto_sm2_ocsp_admission sm2_ocsp_admission.c)
target_link_libraries(crypto_sm2_ocsp_admission PRIVATE Salts::Crypto Salts::TinyTest)
set_target_properties(crypto_sm2_ocsp_admission PROPERTIES FOLDER "Crypto/tests/x509")
add_test(NAME crypto.x509.sm2_ocsp_admission COMMAND crypto_sm2_ocsp_admission)

# Formal independent certificate generation/verification, never a consumer project.
# Android is build-only in the established CI; Go is a host test peer.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_CRYPTO_TEST_GO go REQUIRED)
  add_executable(crypto_sm2_ocsp_peer sm2_ocsp_peer.c)
  target_link_libraries(crypto_sm2_ocsp_peer PRIVATE Salts::Crypto)
  set_target_properties(crypto_sm2_ocsp_peer PROPERTIES FOLDER "Crypto/tests/x509")
  add_test(NAME crypto.x509.sm2_ocsp_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2OCSP$"
      -args -ocsp-peer "$<TARGET_FILE:crypto_sm2_ocsp_peer>")
  set_tests_properties(crypto.x509.sm2_ocsp_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_test(NAME crypto.x509.sm2_ocsp_delegation
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2OCSPDelegation$"
      -args -ocsp-peer "$<TARGET_FILE:crypto_sm2_ocsp_peer>")
  set_tests_properties(crypto.x509.sm2_ocsp_delegation PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_executable(crypto_sm2_cms_peer sm2_cms_peer.c)
  target_link_libraries(crypto_sm2_cms_peer PRIVATE Salts::Crypto)
  set_target_properties(crypto_sm2_cms_peer PROPERTIES FOLDER "Crypto/tests/x509")
  add_test(NAME crypto.x509.sm2_cms_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2CMS$"
      -args -cms-peer "$<TARGET_FILE:crypto_sm2_cms_peer>")
  set_tests_properties(crypto.x509.sm2_cms_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_test(NAME crypto.x509.sm2_cms_envelope_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2CMSEnvelope$"
      -args -cms-peer "$<TARGET_FILE:crypto_sm2_cms_peer>")
  set_tests_properties(crypto.x509.sm2_cms_envelope_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_executable(crypto_sm2_x509_peer sm2_peer.c)
  target_link_libraries(crypto_sm2_x509_peer PRIVATE Salts::Crypto)
  set_target_properties(crypto_sm2_x509_peer PROPERTIES FOLDER "Crypto/tests/x509")
  add_test(NAME crypto.x509.sm2_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2Certificates$"
      -args -peer "$<TARGET_FILE:crypto_sm2_x509_peer>")
  set_tests_properties(crypto.x509.sm2_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_executable(crypto_sm2_trust_peer sm2_trust_peer.c)
  target_link_libraries(crypto_sm2_trust_peer PRIVATE Salts::Crypto)
  set_target_properties(crypto_sm2_trust_peer PROPERTIES FOLDER "Crypto/tests/x509")
  add_test(NAME crypto.x509.sm2_pinned_trust
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestPinnedChain$"
      -args -trust-peer "$<TARGET_FILE:crypto_sm2_trust_peer>")
  set_tests_properties(crypto.x509.sm2_pinned_trust PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  add_executable(crypto_sm2_crl_peer sm2_crl_peer.c)
  target_link_libraries(crypto_sm2_crl_peer PRIVATE Salts::Crypto)
  set_target_properties(crypto_sm2_crl_peer PROPERTIES FOLDER "Crypto/tests/x509")
  add_test(NAME crypto.x509.sm2_crl_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestSM2CRL$"
      -args -crl-peer "$<TARGET_FILE:crypto_sm2_crl_peer>")
  set_tests_properties(crypto.x509.sm2_crl_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
endif()
