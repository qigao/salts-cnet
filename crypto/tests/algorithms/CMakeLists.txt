cmake_add_executable(salts_crypto_sha_ed448_vectors SOURCES sha_ed448_vectors.c
  FOLDER "crypto/tests/algorithms")
# Source-tree tests use the pinned installed vcpkg GmSSL headers;
# never access a locally copied native implementation.
target_link_libraries(salts_crypto_sha_ed448_vectors PRIVATE
  Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sha256_sm3_ed448_rfc8032 COMMAND salts_crypto_sha_ed448_vectors)
set_tests_properties(crypto.algorithms.sha256_sm3_ed448_rfc8032 PROPERTIES TIMEOUT 120)

cmake_add_executable(crypto_algorithms_cpp_header SOURCES header_cpp.cpp
  FOLDER "crypto/tests/algorithms")
target_link_libraries(crypto_algorithms_cpp_header PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.cpp17_header COMMAND crypto_algorithms_cpp_header)

add_executable(crypto_tls_session_cache_test tls_session_cache.c)
if(MSVC)
  target_compile_options(crypto_tls_session_cache_test PRIVATE /experimental:c11atomics)
endif()
target_link_libraries(crypto_tls_session_cache_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.tls_session_cache COMMAND crypto_tls_session_cache_test)
set_tests_properties(crypto.algorithms.tls_session_cache PROPERTIES TIMEOUT 30)

add_executable(crypto_dtls_record_test dtls_record.c)
target_link_libraries(crypto_dtls_record_test PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
set_target_properties(crypto_dtls_record_test PROPERTIES FOLDER "Crypto/tests/algorithms")
# Each C suite owns its TinyTest main and constructor table. Keep the suites
# separate so MSVC registration symbols cannot collide across translation units.
foreach(_suite IN ITEMS handshake secrets exchange client_cases server_cases)
  add_executable(crypto_dtls_${_suite}_test dtls_${_suite}.c)
  target_link_libraries(crypto_dtls_${_suite}_test PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
  set_target_properties(crypto_dtls_${_suite}_test PROPERTIES FOLDER "Crypto/tests/algorithms")
  if(MSVC)
    target_compile_options(crypto_dtls_${_suite}_test PRIVATE /experimental:c11atomics)
  endif()
endforeach()
add_executable(crypto_dtls_client_endpoint dtls_client_endpoint.c)
target_link_libraries(crypto_dtls_client_endpoint PRIVATE Salts::Crypto GmSSL::GmSSL)
set_target_properties(crypto_dtls_client_endpoint PROPERTIES FOLDER "Crypto/tests/algorithms")
add_executable(crypto_dtls_server_endpoint dtls_server_endpoint.c)
target_link_libraries(crypto_dtls_server_endpoint PRIVATE Salts::Crypto GmSSL::GmSSL)
set_target_properties(crypto_dtls_server_endpoint PROPERTIES FOLDER "Crypto/tests/algorithms")
if(MSVC)
  # These private C fixtures include the context's atomic lease counter, like
  # the Crypto implementation, and require MSVC's C11 atomics admission.
  target_compile_options(crypto_dtls_server_endpoint PRIVATE /experimental:c11atomics)
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME crypto.algorithms.dtls_record
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/dtls_record_peer.py"
      "$<TARGET_FILE:crypto_dtls_record_test>")
  set_tests_properties(crypto.algorithms.dtls_record PROPERTIES TIMEOUT 60)
  add_test(NAME crypto.algorithms.dtls_handshake
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/dtls_handshake_peer.py"
      "$<TARGET_FILE:crypto_dtls_handshake_test>"
      "$<TARGET_FILE:crypto_dtls_secrets_test>"
      "$<TARGET_FILE:crypto_dtls_exchange_test>"
      "$<TARGET_FILE:crypto_dtls_client_cases_test>"
      "$<TARGET_FILE:crypto_dtls_server_cases_test>")
  set_tests_properties(crypto.algorithms.dtls_handshake PROPERTIES TIMEOUT 60)
  add_test(NAME crypto.algorithms.dtls_client_independent
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/dtls_client_peer.py"
      "$<TARGET_FILE:crypto_dtls_client_endpoint>")
  set_tests_properties(crypto.algorithms.dtls_client_independent PROPERTIES TIMEOUT 90)
  add_test(NAME crypto.algorithms.dtls_server_independent
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/dtls_server_peer.py"
      "$<TARGET_FILE:crypto_dtls_server_endpoint>")
  set_tests_properties(crypto.algorithms.dtls_server_independent PROPERTIES TIMEOUT 90)
  find_program(SALTS_CRYPTO_TEST_GO go REQUIRED)
  add_test(NAME crypto.algorithms.dtls_client_pion
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -failfast -v -timeout=60s -run "^TestDTLSClientAgainstPion$"
      -args -dtls-client "$<TARGET_FILE:crypto_dtls_client_endpoint>")
  set_tests_properties(crypto.algorithms.dtls_client_pion PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
  add_test(NAME crypto.algorithms.dtls_server_pion
    COMMAND "${SALTS_CRYPTO_TEST_GO}" test -mod=readonly -count=1 -failfast -v -timeout=90s -run "^TestDTLSServerAgainstPion$"
      -args -dtls-server "$<TARGET_FILE:crypto_dtls_server_endpoint>")
  set_tests_properties(crypto.algorithms.dtls_server_pion PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
endif()

add_executable(salts_crypto_shangmi_vectors shangmi_vectors.c)
target_link_libraries(salts_crypto_shangmi_vectors PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.shangmi_public COMMAND salts_crypto_shangmi_vectors)
set_tests_properties(crypto.algorithms.shangmi_public PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_vectors sm9_vectors.c)
target_link_libraries(salts_crypto_sm9_vectors PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm9_public COMMAND salts_crypto_sm9_vectors)
set_tests_properties(crypto.algorithms.sm9_public PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_provider_failure sm9_provider_failure.c)
target_link_libraries(salts_crypto_sm9_provider_failure PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sm9_provider_failure COMMAND salts_crypto_sm9_provider_failure)
set_tests_properties(crypto.algorithms.sm9_provider_failure PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_exchange_test sm9_exchange_test.c)
target_link_libraries(salts_crypto_sm9_exchange_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm9_exchange COMMAND salts_crypto_sm9_exchange_test)
set_tests_properties(crypto.algorithms.sm9_exchange PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm2_exchange_test sm2_exchange_test.c)
target_link_libraries(salts_crypto_sm2_exchange_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm2_exchange COMMAND salts_crypto_sm2_exchange_test)
set_tests_properties(crypto.algorithms.sm2_exchange PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm2_exchange_vectors sm2_exchange_vectors.c)
target_link_libraries(salts_crypto_sm2_exchange_vectors PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sm2_exchange_vectors COMMAND salts_crypto_sm2_exchange_vectors)
set_tests_properties(crypto.algorithms.sm2_exchange_vectors PROPERTIES TIMEOUT 120)
