find_program(SALTS_CRYPTO_TEST_GO go REQUIRED)
add_executable(crypto_sm2_keys_peer sm2_keys_peer.c)
target_link_libraries(crypto_sm2_keys_peer PRIVATE Salts::Crypto)
cmake_config_target(crypto_sm2_keys_peer FOLDER "crypto/tests/e2e")
add_executable(crypto_pkcs12_peer pkcs12_peer.c)
target_link_libraries(crypto_pkcs12_peer PRIVATE Salts::Crypto)
cmake_config_target(crypto_pkcs12_peer FOLDER "crypto/tests/e2e")

foreach(test_case IN ITEMS "sm2_keys;TestSM2KeyInterop" "pkcs12;TestPKCS12Interop")
  list(GET test_case 0 name)
  list(GET test_case 1 function)
  add_test(NAME crypto.asn1.${name}_independent
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -timeout=110s
      -run "^${function}$" -args
      -sm2-keys-peer "$<TARGET_FILE:crypto_sm2_keys_peer>"
      -pkcs12-peer "$<TARGET_FILE:crypto_pkcs12_peer>")
  set_tests_properties(crypto.asn1.${name}_independent PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
endforeach()
