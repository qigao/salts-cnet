find_package(Python3 COMPONENTS Interpreter REQUIRED)

# TinyTest is required for native runtime tests; migrate source-owned suites in
# batches while retaining all original behavior and CTest registrations.
if(NOT TARGET Salts::TinyTest)
  message(FATAL_ERROR "Native runtime tests require Salts::TinyTest")
endif()

if(UNIX)
  add_executable(saltscore_readiness_race_test test_readiness_race.c)
  target_compile_features(saltscore_readiness_race_test PRIVATE c_std_11)
  target_link_libraries(saltscore_readiness_race_test PRIVATE Salts::Platform Salts::TinyTest)
  set_target_properties(saltscore_readiness_race_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  add_test(NAME saltscore.readiness_close_race COMMAND saltscore_readiness_race_test)
  set_tests_properties(saltscore.readiness_close_race PROPERTIES TIMEOUT 35)
endif()

# Real copied readiness state machine with test-only injection of native
# backend hook failures: register, arm, unarm, close, shutdown, stale events.
add_executable(saltscore_readiness_faults_test test_readiness_faults.c)
target_compile_features(saltscore_readiness_faults_test PRIVATE c_std_11)
target_link_libraries(saltscore_readiness_faults_test PRIVATE Salts::Platform Salts::TinyTest)
set_target_properties(saltscore_readiness_faults_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.readiness_faults COMMAND saltscore_readiness_faults_test)
set_tests_properties(saltscore.readiness_faults PROPERTIES TIMEOUT 20)

add_executable(saltscore_readiness_test test_readiness.c)
target_compile_features(saltscore_readiness_test PRIVATE c_std_11)
target_link_libraries(saltscore_readiness_test PRIVATE Salts::Platform Salts::TinyTest)
set_target_properties(saltscore_readiness_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.readiness_owner COMMAND saltscore_readiness_test)
set_tests_properties(saltscore.readiness_owner PROPERTIES TIMEOUT 15)

add_executable(saltscore_utf8_test test_utf8.c)
target_link_libraries(saltscore_utf8_test PRIVATE Salts::Core Salts::TinyTest)
target_compile_features(saltscore_utf8_test PRIVATE c_std_11)
set_target_properties(saltscore_utf8_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.utf8_strict COMMAND saltscore_utf8_test)

add_executable(saltscore_runtime_abi_test test_runtime_abi.c)
target_compile_features(saltscore_runtime_abi_test PRIVATE c_std_11)
target_link_libraries(saltscore_runtime_abi_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_runtime_abi_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.runtime_abi_0_1 COMMAND saltscore_runtime_abi_test)

# Plain C11 borrowed string view: no reflection headers, allocator or ABI shim.
add_executable(saltscore_vstr_contract_test test_vstr_contract.c)
target_link_libraries(saltscore_vstr_contract_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_vstr_contract_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.vstr_c11 COMMAND saltscore_vstr_contract_test)

# Base64 must remain one installed native owner, no unrelated vendor codec.
add_executable(saltscore_base64_test test_base64_utils.c)
target_compile_features(saltscore_base64_test PRIVATE c_std_11)
target_link_libraries(saltscore_base64_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_base64_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(saltscore_base64_test PRIVATE /W4 /WX)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(saltscore_base64_test PRIVATE -Wall -Wextra -Wpedantic
    -Wconversion -Wsign-conversion -Werror)
endif()
add_test(NAME saltscore.base64_unique_owner COMMAND saltscore_base64_test)

add_executable(saltscore_bytes_test test_bytes.c)
target_link_libraries(saltscore_bytes_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_bytes_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.bytes COMMAND saltscore_bytes_test)

# Preserve the original error registry and borrowed diagnostic lifetimes.
# The native contract includes INT_MIN decoding and concurrent registration.
add_executable(saltscore_error_contract error_native_contract.c)
target_compile_features(saltscore_error_contract PRIVATE c_std_11)
target_link_libraries(saltscore_error_contract PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_error_contract PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.error_native_contract COMMAND saltscore_error_contract)
set_tests_properties(saltscore.error_native_contract PROPERTIES TIMEOUT 30)
add_executable(saltscore_original_error_test test_cmeta_error.c)
target_compile_features(saltscore_original_error_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_error_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_error COMMAND saltscore_original_error_test)

# Core Platform is the sole owner of native fast-key state; no CMeta ABI.
add_executable(saltscore_fastpath_test test_fastpath.c)
target_compile_features(saltscore_fastpath_test PRIVATE c_std_11)
target_link_libraries(saltscore_fastpath_test PRIVATE Salts::Platform Salts::TinyTest)
set_target_properties(saltscore_fastpath_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.fastpath COMMAND saltscore_fastpath_test)

add_executable(saltscore_platform_test test_platform.c)
target_link_libraries(saltscore_platform_test PRIVATE Salts::Platform Salts::TinyTest)
set_target_properties(saltscore_platform_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.platform COMMAND saltscore_platform_test)

add_executable(saltscore_original_platform_cpp_test test_platform_original_cpp.cpp)
target_compile_features(saltscore_original_platform_cpp_test PRIVATE cxx_std_17)
target_link_libraries(saltscore_original_platform_cpp_test PRIVATE Salts::Platform Salts::TinyTest)
set_target_properties(saltscore_original_platform_cpp_test PROPERTIES
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
add_test(NAME saltscore.original_platform_cpp17
  COMMAND saltscore_original_platform_cpp_test)
set_tests_properties(saltscore.platform saltscore.original_platform_cpp17
  PROPERTIES TIMEOUT 30)

add_executable(saltscore_concurrency_test test_concurrency.c)
target_link_libraries(saltscore_concurrency_test PRIVATE Salts::Concurrency Salts::TinyTest)
set_target_properties(saltscore_concurrency_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.concurrency COMMAND saltscore_concurrency_test)

add_executable(saltscore_coroutine_test test_coroutine.c)
target_link_libraries(saltscore_coroutine_test PRIVATE Salts::Coroutine Salts::TinyTest)
set_target_properties(saltscore_coroutine_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.coroutine COMMAND saltscore_coroutine_test)
set_tests_properties(saltscore.coroutine PROPERTIES TIMEOUT 30)

add_executable(saltscore_native_io_test test_native_io.c)
target_link_libraries(saltscore_native_io_test PRIVATE Salts::NativeIO Salts::TinyTest)
set_target_properties(saltscore_native_io_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.native_io COMMAND saltscore_native_io_test)

add_executable(saltscore_buffer_test test_buffer.c)
target_link_libraries(saltscore_buffer_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_buffer_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.buffer COMMAND saltscore_buffer_test)

if(TARGET Salts::URI)
  add_executable(saltscore_uri_test test_uri.c)
  target_link_libraries(saltscore_uri_test PRIVATE Salts::URI Salts::TinyTest)
  set_target_properties(saltscore_uri_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  add_test(NAME saltscore.uri COMMAND saltscore_uri_test)
endif()

add_executable(saltscore_ring_test test_ring.c)
target_link_libraries(saltscore_ring_test PRIVATE Salts::Core Salts::TinyTest)
set_target_properties(saltscore_ring_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME saltscore.ring COMMAND saltscore_ring_test)

# Parser-only C11 gate with no TLS, CNet, re2c, CMeta or CFlow provider.
if(TARGET saltscore_wsparser)
  add_executable(saltscore_wsparser_test test_wsparser.c)
  target_compile_features(saltscore_wsparser_test PRIVATE c_std_11)
  set_target_properties(saltscore_wsparser_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(saltscore_wsparser_test PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/src/wsparser")
  target_link_libraries(saltscore_wsparser_test PRIVATE saltscore_wsparser Salts::TinyTest)
  add_test(NAME saltscore.wsparser COMMAND saltscore_wsparser_test)
endif()

# Use the one production CNet DSO, not duplicate compiled policy sources.
# Existing TinyTest/CTest target now tests real URI, TLS and UDP/KCP admission.
# No consumer project, extra runtime/Owner, installer or new test workflow.
add_executable(saltscore_cnet_policy_test test_cnet_policy.c)
target_compile_features(saltscore_cnet_policy_test PRIVATE c_std_11)
set_target_properties(saltscore_cnet_policy_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_cnet_policy_test PRIVATE
  Salts::CNet Salts::TinyTest)
if(MSVC)
  target_compile_options(saltscore_cnet_policy_test PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
endif()
add_test(NAME saltscore.cnet_policy COMMAND saltscore_cnet_policy_test)

# Native ABI and ShangMi tests use the source-built Salts::Crypto archive.
# No external provider package or second implementation is assembled here.

if(TARGET Salts::CNet)
  # A separate loadable module checks process-global pool and thread identity
  # across DSO/DLL boundaries. Never resolve these through a static archive.
  add_library(saltscore_runtime_owner_probe SHARED runtime_owner_module.c)
  target_compile_features(saltscore_runtime_owner_probe PRIVATE c_std_11)
  set_target_properties(saltscore_runtime_owner_probe PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF WINDOWS_EXPORT_ALL_SYMBOLS ON)
  target_link_libraries(saltscore_runtime_owner_probe PRIVATE
    Salts::Core Salts::Platform)
  # Genuine loopback TCP acceptance + borrowed/retained ownership + stop drain.
  add_executable(saltscore_cnet_tcp_loopback_test test_cnet_tcp_loopback.c)
  target_compile_features(saltscore_cnet_tcp_loopback_test PRIVATE c_std_11)
  set_target_properties(saltscore_cnet_tcp_loopback_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_cnet_tcp_loopback_test PRIVATE
    Salts::CNet saltscore_runtime_owner_probe Salts::TinyTest)
  if(WIN32)
    target_link_libraries(saltscore_cnet_tcp_loopback_test PRIVATE ws2_32)
  endif()
  if(MSVC)
    target_compile_options(saltscore_cnet_tcp_loopback_test PRIVATE
      $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
  endif()
  add_test(NAME saltscore.cnet_tcp_loopback
    COMMAND saltscore_cnet_tcp_loopback_test)
  set_tests_properties(saltscore.cnet_tcp_loopback PROPERTIES TIMEOUT 20)

  # Load two independent CNet consumers through the native dynamic loader.
  # No CNet library is linked into the executable itself.
  foreach(_plugin IN ITEMS a b)
    add_library(saltscore_runtime_plugin_${_plugin} MODULE runtime_loaded_plugin.c)
    target_compile_features(saltscore_runtime_plugin_${_plugin} PRIVATE c_std_11)
    set_target_properties(saltscore_runtime_plugin_${_plugin} PROPERTIES
      C_STANDARD_REQUIRED ON C_EXTENSIONS OFF WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_link_libraries(saltscore_runtime_plugin_${_plugin} PRIVATE
      Salts::CNet)
    saltscore_cnet_owner_link_map(saltscore_runtime_plugin_${_plugin})
  endforeach()
  add_executable(saltscore_two_plugins_test test_runtime_plugins.c)
  target_compile_features(saltscore_two_plugins_test PRIVATE c_std_11)
  set_target_properties(saltscore_two_plugins_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_two_plugins_test PRIVATE
    Salts::Core Salts::Platform ${CMAKE_DL_LIBS} Salts::TinyTest)
  saltscore_cnet_owner_link_map(saltscore_two_plugins_test)
  add_dependencies(saltscore_two_plugins_test
    saltscore_runtime_plugin_a saltscore_runtime_plugin_b)
  add_test(NAME saltscore.two_cnet_plugins
    COMMAND saltscore_two_plugins_test
      "$<TARGET_FILE:saltscore_runtime_plugin_a>"
      "$<TARGET_FILE:saltscore_runtime_plugin_b>")
  set_tests_properties(saltscore.two_cnet_plugins PROPERTIES TIMEOUT 30)
endif()

if(TARGET Salts::CNet)
  add_executable(saltscore_gmssl_tls_io_abi_test test_gmssl_tls_io_abi.c)
  target_compile_features(saltscore_gmssl_tls_io_abi_test PRIVATE c_std_11)
  set_target_properties(saltscore_gmssl_tls_io_abi_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_gmssl_tls_io_abi_test PRIVATE
    Salts::Crypto Salts::Core Salts::NativeIO Salts::TinyTest)
  target_include_directories(saltscore_gmssl_tls_io_abi_test PRIVATE
    "${PROJECT_SOURCE_DIR}/crypto/src"
    "$<TARGET_PROPERTY:GmSSL::GmSSL,INTERFACE_INCLUDE_DIRECTORIES>")
  target_compile_definitions(saltscore_gmssl_tls_io_abi_test PRIVATE
    "SALTSCORE_EXPECT_PROVIDER_COPIES=$<BOOL:${SALTSCORE_GMSSL_COPY_PROFILE}>"
    ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES
    "CRYPTO_NATIVE_BENCH_CA=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-root-cert.pem\""
    "CRYPTO_NATIVE_BENCH_CERT=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-server-cert.pem\""
    "CRYPTO_NATIVE_BENCH_KEY=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-server-key.pem\""
    "CRYPTO_CLOSE_TEST_CA=\"${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-ca-cert.pem\""
    "CRYPTO_CLOSE_TEST_SERVER_CERT=\"${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-server-cert.pem\""
    "CRYPTO_CLOSE_TEST_SERVER_KEY=\"${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-server-key.pem\"")
  add_test(NAME saltscore.gmssl_tls_io_abi COMMAND saltscore_gmssl_tls_io_abi_test)

  add_executable(saltscore_gmssl_shangmi_provider_test
    test_gmssl_shangmi_provider.c)
  target_compile_features(saltscore_gmssl_shangmi_provider_test PRIVATE c_std_11)
  set_target_properties(saltscore_gmssl_shangmi_provider_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_gmssl_shangmi_provider_test PRIVATE Salts::Crypto Salts::TinyTest)
  target_include_directories(saltscore_gmssl_shangmi_provider_test PRIVATE
    "$<TARGET_PROPERTY:GmSSL::GmSSL,INTERFACE_INCLUDE_DIRECTORIES>")
  target_compile_definitions(saltscore_gmssl_shangmi_provider_test PRIVATE
    ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
  add_test(NAME saltscore.gmssl_shangmi_provider
    COMMAND saltscore_gmssl_shangmi_provider_test)
endif()

if(TARGET Salts::CNet)
  # Real TLS over NativeIO TCP: trusted issuer + correct SAN must connect;
  # wrong root and wrong DNS identity must fail without authenticated callback.
  add_executable(saltscore_cnet_tls_ca_san_test test_cnet_tls_ca_san.c)
  target_compile_features(saltscore_cnet_tls_ca_san_test PRIVATE c_std_11)
  set_target_properties(saltscore_cnet_tls_ca_san_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_cnet_tls_ca_san_test PRIVATE Salts::CNet Salts::Crypto Salts::TinyTest)
  target_include_directories(saltscore_cnet_tls_ca_san_test PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/src" "${PROJECT_SOURCE_DIR}/crypto/src")
  if(MSVC)
    target_compile_options(saltscore_cnet_tls_ca_san_test PRIVATE
      $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
  endif()
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-root-cert.pem"
       _cnet_test_root_ca)
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-wrong-root-cert.pem"
       _cnet_test_wrong_ca)
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-server-cert.pem"
       _cnet_test_cert)
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/p384-test-server-key.pem"
       _cnet_test_key)
  target_compile_definitions(saltscore_cnet_tls_ca_san_test PRIVATE
    "SALTSCORE_EXPECT_PROVIDER_COPIES=$<BOOL:${SALTSCORE_GMSSL_COPY_PROFILE}>"
    "CORE_TLS_TEST_P384_CA=\"${_cnet_test_root_ca}\""
    "CORE_TLS_TEST_P384_WRONG_CA=\"${_cnet_test_wrong_ca}\""
    "CORE_TLS_TEST_P384_LEAF=\"${_cnet_test_cert}\""
    "CORE_TLS_TEST_P384_KEY=\"${_cnet_test_key}\""
    "CORE_TLS_TEST_EXTERNAL_CA=\"${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-ca-cert.pem\"")
  target_compile_definitions(saltscore_cnet_tcp_loopback_test PRIVATE
    "CORE_TLS_TEST_P384_LEAF=\"${_cnet_test_cert}\""
    "CORE_TLS_TEST_P384_KEY=\"${_cnet_test_key}\"")
  add_test(NAME saltscore.cnet_tls_ca_san
    COMMAND saltscore_cnet_tls_ca_san_test)
  set_tests_properties(saltscore.cnet_tls_ca_san PROPERTIES TIMEOUT 65)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    find_program(SALTS_CNET_TEST_GO go REQUIRED)
    add_test(NAME saltscore.cnet_tls_session_resumption
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=60s
        -run ^TestTLS13SessionResumption$
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_tls_session_resumption PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tls"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
    # Each capability owns its existing Go/CTest time budget. Running every
    # unrelated TLS test under the client-identities budget made elapsed work
    # from earlier capabilities time out a later, otherwise healthy handshake.
    foreach(salts_tls_test IN ITEMS
        "client_identities;TestClientIdentities"
        "encrypted_credentials;TestEncryptedCredentials"
        "certificate_signature_positions;TestCertificateSignaturePositions"
        "purpose_diagnostics;TestPurposeDiagnostics"
        "validity_diagnostics;TestValidityDiagnostics"
        "verification_time;TestVerificationTime"
        "server_verification_time;TestServerVerificationTime")
      list(GET salts_tls_test 0 salts_tls_name)
      list(GET salts_tls_test 1 salts_tls_case)
      add_test(NAME saltscore.cnet_tls_${salts_tls_name}
        COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s
          -run "^${salts_tls_case}$"
          -args -python "${Python3_EXECUTABLE}" -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
      set_tests_properties(saltscore.cnet_tls_${salts_tls_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tls"
        ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    endforeach()
    add_test(NAME saltscore.cnet_tlcp_independent
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s
        -args -python "${Python3_EXECUTABLE}" -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_tlcp_independent PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tlcp"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_tlcp_crl_policy
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestTLCPCRLPolicy$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_tlcp_crl_policy PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tlcp"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_tlcp_certificate_policy
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestTLCPCertificatePolicy$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_tlcp_certificate_policy PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tlcp"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_tlcp_ocsp_policy
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestTLCPOCSPPolicy$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_tlcp_ocsp_policy PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/tlcp"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_session_resumption
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestShangMiSessionResumption$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_session_resumption PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
    add_test(NAME saltscore.cnet_shangmi_tls13_independent
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMi$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_tls13_independent PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_required_mtls
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiMutual$"
        -args -python "${Python3_EXECUTABLE}" -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_required_mtls PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_mtls_independent
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiMutualIndependent$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_mtls_independent PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_mtls_native_client
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiMutualNativeClient$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_mtls_native_client PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_key_update
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiKeyUpdate$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_key_update PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    # Separate image: one Crypto/GmSSL owner, never also Salts::CNet.
    add_executable(saltscore_crypto_tls_peer_policy_test test_crypto_tls_peer_policy.c)
    target_link_libraries(saltscore_crypto_tls_peer_policy_test PRIVATE Salts::Crypto)
    set_target_properties(saltscore_crypto_tls_peer_policy_test PROPERTIES
      C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF FOLDER "Core/tests")
    add_test(NAME saltscore.crypto_tls_shangmi_revocation
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiRevocation$"
        -args -native "$<TARGET_FILE:saltscore_crypto_tls_peer_policy_test>")
    set_tests_properties(saltscore.crypto_tls_shangmi_revocation PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_crl_policy
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiCNetCRLPolicy$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_crl_policy PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
    add_test(NAME saltscore.cnet_shangmi_ocsp_policy
      COMMAND "${SALTS_CNET_TEST_GO}" test -mod=readonly -count=1 -timeout=150s -run "^TestShangMiCNetOCSPPolicy$"
        -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
    set_tests_properties(saltscore.cnet_shangmi_ocsp_policy PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/independent/shangmi"
      ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 180)
  endif()

  # Reuse the actual opt-in TinyTest cases, one fresh process per sample. The
  # dependency chain rotates all five modes and preserves order with ctest -j.
  if(SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS)
    # Compiler provenance belongs to the configured graph, not the shell PATH.
    file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-compiler.txt" CONTENT
      "compiler=${CMAKE_C_COMPILER}\ncompiler-id=${CMAKE_C_COMPILER_ID}\ncompiler-version=${CMAKE_C_COMPILER_VERSION}\ncompiler-target=${CMAKE_C_COMPILER_TARGET}\nbuild-type=${CMAKE_BUILD_TYPE}\ngenerator=${CMAKE_GENERATOR}\n")
    if(SALTSCORE_CNET_TLS_MIXED_HEAPTRACK)
      find_program(SALTSCORE_HEAPTRACK_EXECUTABLE NAMES heaptrack REQUIRED)
      file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-heaptrack")
    endif()
    if(SALTSCORE_CNET_TLS_MIXED_PERF)
      find_program(SALTSCORE_PERF_EXECUTABLE NAMES perf REQUIRED)
      file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-perf")
    endif()
    set(_tls_mixed_previous "")
    foreach(_repeat RANGE 0 4)
      foreach(_position RANGE 0 4)
        math(EXPR _mode "(${_repeat} + ${_position}) % 5")
        set(_case "saltscore.cnet_tls_mixed_r${_repeat}_p${_position}")
        if(_mode EQUAL 0)
          set(_binary "$<TARGET_FILE:saltscore_gmssl_tls_io_abi_test>")
          set(_filter "measures direct mixed TLS control, repetition ${_repeat}")
          set(_switch "SALTSCORE_NATIVE_TLS_MIXED_BENCHMARK=1")
        else()
          math(EXPR _scenario "${_mode} - 1")
          set(_binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
          set(_filter "measures mixed TLS control, repetition ${_repeat} scenario ${_scenario}")
          set(_switch "SALTSCORE_CNET_TLS_MIXED_BENCHMARK=1")
        endif()
        set(_launcher)
        if(SALTSCORE_CNET_TLS_MIXED_HEAPTRACK)
          set(_launcher "${SALTSCORE_HEAPTRACK_EXECUTABLE}" --record-only --output
            "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-heaptrack/r${_repeat}-p${_position}")
        elseif(SALTSCORE_CNET_TLS_MIXED_PERF)
          set(_launcher "${SALTSCORE_PERF_EXECUTABLE}" record --event cpu-clock:u
            --freq 4000 --strict-freq --call-graph dwarf,8192 --output
            "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-perf/r${_repeat}-p${_position}.data" --)
        endif()
        add_test(NAME "${_case}" COMMAND ${_launcher} "${_binary}" --filter "${_filter}")
        set_tests_properties("${_case}" PROPERTIES
          ENVIRONMENT "${_switch}" TIMEOUT 65 RUN_SERIAL TRUE
          LABELS "cnet_tls_mixed_measurements")
        if(_tls_mixed_previous)
          set_tests_properties("${_case}" PROPERTIES DEPENDS "${_tls_mixed_previous}")
        endif()
        set(_tls_mixed_previous "${_case}")
      endforeach()
    endforeach()
  endif()

  # This is the exact production Salts::CNet target, never the retired
  # second test-only CNet Owner / Crypto adapter.
  if(SALTSCORE_CNET_PRODUCTION_REQUIRED_MTLS_TEST)
    add_test(NAME saltscore.cnet_production_required_mtls
      COMMAND "${Python3_EXECUTABLE}" -B
        "${PROJECT_SOURCE_DIR}/tests/test_cnet_tls_required_mtls.py"
        --binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>"
        --fixture-generator
          "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
        --work "${PROJECT_BINARY_DIR}/native-required-mtls")
    set_tests_properties(saltscore.cnet_production_required_mtls
      PROPERTIES TIMEOUT 180 RESOURCE_LOCK cnet_native_required_mtls)

    # CNet *production* client linked once to independent Python stdlib ssl
    # server. Each peer pins exactly one TLS version; positive DNS SAN must
    # transfer application bytes, and wrong DNS SAN must reject at handshake.
    foreach(_protocol IN ITEMS tls12 tls13)
      add_test(NAME saltscore.cnet_python_ssl_peer_${_protocol}
        COMMAND "${Python3_EXECUTABLE}" -B
          "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/external_san_peer.py"
          --binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>"
          --cert "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-server-cert.pem"
          --key "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/external-io-server-key.pem"
          --protocol "${_protocol}")
      set_tests_properties(saltscore.cnet_python_ssl_peer_${_protocol}
        PROPERTIES TIMEOUT 95 RESOURCE_LOCK cnet_native_python_ssl_peer)
    endforeach()

    # Inverse interop: Python's own ssl TLS client uses exact TLS1.2 or
    # TLS1.3 against the ONE production CNet listener, with REQUIRED mTLS.
    # No duplicate CNet owner, test-only provider, installed SDK or consumer.
    add_test(NAME saltscore.cnet_python_ssl_client_required_mtls
      COMMAND "${Python3_EXECUTABLE}" -B
        "${PROJECT_SOURCE_DIR}/tests/test_cnet_tls_python_client.py"
        --binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>"
        --fixture-generator "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
        --work "${PROJECT_BINARY_DIR}/native-python-client-mtls")
    set_tests_properties(saltscore.cnet_python_ssl_client_required_mtls
      PROPERTIES TIMEOUT 300 RESOURCE_LOCK cnet_native_required_mtls)
    add_test(NAME saltscore.cnet_tls_sni_identities
      COMMAND "${Python3_EXECUTABLE}" -B
        "${PROJECT_SOURCE_DIR}/tests/test_cnet_tls_sni.py"
        --binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>"
        --fixture-generator "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
        --work "${PROJECT_BINARY_DIR}/native-sni-identities")
    set_tests_properties(saltscore.cnet_tls_sni_identities
      PROPERTIES TIMEOUT 180 RESOURCE_LOCK cnet_native_required_mtls)
  endif()
endif()

# Cross-compiler-compatible Atomic/Thread runtime; no consumer-native _Atomic.
add_executable(saltscore_portable_concurrency_test test_portable_concurrency.c)
target_compile_features(saltscore_portable_concurrency_test PRIVATE c_std_11)
set_target_properties(saltscore_portable_concurrency_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_portable_concurrency_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.portable_concurrency COMMAND saltscore_portable_concurrency_test)
set_tests_properties(saltscore.portable_concurrency PROPERTIES TIMEOUT 45)

# M1: relative monotonic timed wait / sleep, same C ABI across compilers.
add_executable(saltscore_portable_timing_test test_portable_timing.c)
target_compile_features(saltscore_portable_timing_test PRIVATE c_std_11)
target_link_libraries(saltscore_portable_timing_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.portable_timing COMMAND saltscore_portable_timing_test)
set_tests_properties(saltscore.portable_timing PROPERTIES TIMEOUT 30)

# M1: provider-owned thread-specific keys and destructor lifetime barriers.
add_executable(saltscore_portable_tss_test test_portable_tss.c)
target_compile_features(saltscore_portable_tss_test PRIVATE c_std_11)
target_link_libraries(saltscore_portable_tss_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.portable_tss COMMAND saltscore_portable_tss_test)
set_tests_properties(saltscore.portable_tss PROPERTIES TIMEOUT 30)


# Monotonic relative timed mutex (MSVC / Clang / TinyCC C ABI).
add_executable(saltscore_portable_timed_mutex_test test_portable_timed_mutex.c)
target_compile_features(saltscore_portable_timed_mutex_test PRIVATE c_std_11)
target_link_libraries(saltscore_portable_timed_mutex_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.portable_timed_mutex COMMAND saltscore_portable_timed_mutex_test)
set_tests_properties(saltscore.portable_timed_mutex PROPERTIES TIMEOUT 35)


# Explicit C11 threads.h source-compatibility admission (not a global CRT override).
add_executable(saltscore_c11_threads_test test_c11_threads.c)
target_include_directories(saltscore_c11_threads_test BEFORE PRIVATE
  "${PROJECT_SOURCE_DIR}/platform/include/c11")
target_compile_definitions(saltscore_c11_threads_test PRIVATE
  SALTS_C11_THREADS_EXPERIMENTAL=1)
set_target_properties(saltscore_c11_threads_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_c11_threads_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.c11_threads_facade COMMAND saltscore_c11_threads_test)
set_tests_properties(saltscore.c11_threads_facade PROPERTIES TIMEOUT 35)


# Regression for Windows cmeta_hrtime once-atomic QPC frequency publication.
add_executable(saltscore_clock_atomic_owner_test test_clock_atomic_owner.c)
target_compile_features(saltscore_clock_atomic_owner_test PRIVATE c_std_11)
target_link_libraries(saltscore_clock_atomic_owner_test PRIVATE Salts::Platform Salts::TinyTest)
add_test(NAME saltscore.clock_atomic_owner COMMAND saltscore_clock_atomic_owner_test)
set_tests_properties(saltscore.clock_atomic_owner PROPERTIES TIMEOUT 30)

# Test-only native Crypto Owner, never part of the production CNet target.
if(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION)
  add_subdirectory(cnet-crypto-static)
endif()

# Restore original tstr/vstr/memory-pool behavior, not just public headers.
add_executable(saltscore_original_string_parity_test test_original_string_parity.c)
target_compile_features(saltscore_original_string_parity_test PRIVATE c_std_11)
set_target_properties(saltscore_original_string_parity_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_original_string_parity_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_utils_string_parity
  COMMAND saltscore_original_string_parity_test)
set_tests_properties(saltscore.original_utils_string_parity PROPERTIES TIMEOUT 20)

# Literal copy of the original TinyTest tstr v2 contract from Salts utils.
# Optional TinyTest profile runs source-parity expectations; never a stub.
add_executable(saltscore_original_tstr_v2_contract test_tstr_v2_contract.c)
target_compile_features(saltscore_original_tstr_v2_contract PRIVATE c_std_11)
target_link_libraries(saltscore_original_tstr_v2_contract PRIVATE
  Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_tstr_v2_contract
  COMMAND saltscore_original_tstr_v2_contract)

# Original object_pool source and TinyTest contract, not a new allocator
# provider. The C11 smoke test also runs when TinyTest is disabled.
add_executable(saltscore_original_object_pool_smoke test_original_object_pool_smoke.c)
target_compile_features(saltscore_original_object_pool_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_original_object_pool_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_object_pool_smoke
  COMMAND saltscore_original_object_pool_smoke)
add_executable(saltscore_original_object_pool_contract test_object_pool.c)
target_compile_features(saltscore_original_object_pool_contract PRIVATE c_std_11)
target_link_libraries(saltscore_original_object_pool_contract PRIVATE
  Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_object_pool_contract
  COMMAND saltscore_original_object_pool_contract)
set_tests_properties(saltscore.original_object_pool_contract PROPERTIES TIMEOUT 45)

# The original single-owner priority queue: FIFO within a priority and
# critical/high/normal/low ordering, with strict bounded storage.
add_executable(saltscore_original_priority_queue_smoke test_original_priority_queue_smoke.c)
target_compile_features(saltscore_original_priority_queue_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_original_priority_queue_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_priority_queue_smoke COMMAND saltscore_original_priority_queue_smoke)
add_executable(saltscore_original_priority_queue_contract test_bucket_priority_queue.c)
target_compile_features(saltscore_original_priority_queue_contract PRIVATE c_std_11)
target_link_libraries(saltscore_original_priority_queue_contract PRIVATE
  Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_priority_queue_contract
  COMMAND saltscore_original_priority_queue_contract)

# Original native SPSC ring and bounded multi-priority SPSC queue. Their
# behavior is exercised by the original TinyTest suites, not a mock backend.
add_executable(saltscore_original_ring_spsc_test test_ring_buffer_spsc.c)
target_compile_features(saltscore_original_ring_spsc_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_ring_spsc_test PRIVATE Salts::Concurrency Salts::TinyTest)
add_test(NAME saltscore.original_ring_spsc COMMAND saltscore_original_ring_spsc_test)

add_executable(saltscore_original_bucket_spsc_test test_bucket_priority_queue_spsc.c)
target_compile_features(saltscore_original_bucket_spsc_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_bucket_spsc_test PRIVATE
  Salts::Concurrency Salts::TinyTest)
add_test(NAME saltscore.original_bucket_priority_spsc
  COMMAND saltscore_original_bucket_spsc_test)
set_tests_properties(saltscore.original_bucket_priority_spsc PROPERTIES TIMEOUT 50)

add_executable(saltscore_original_spsc_smoke test_original_spsc_smoke.c)
target_compile_features(saltscore_original_spsc_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_original_spsc_smoke PRIVATE Salts::Concurrency Salts::TinyTest)
add_test(NAME saltscore.original_spsc_smoke COMMAND saltscore_original_spsc_smoke)

# The original seven-function MPMC API is owned by the existing concurrency
# module. The original native TinyTest contract exercises that canonical owner.
add_executable(saltscore_original_bucket_mpmc_test test_bucket_priority_queue_mpmc.c)
target_compile_features(saltscore_original_bucket_mpmc_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_bucket_mpmc_test PRIVATE
  Salts::Concurrency Salts::TinyTest)
add_test(NAME saltscore.original_bucket_mpmc COMMAND saltscore_original_bucket_mpmc_test)
set_tests_properties(saltscore.original_bucket_mpmc PROPERTIES TIMEOUT 30)

# Original formatter lexer and C11 smoke both execute through TinyTest.
add_executable(saltscore_fmt_lexer_smoke test_fmt_lexer_smoke.c)
target_compile_features(saltscore_fmt_lexer_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_fmt_lexer_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_lexer_smoke COMMAND saltscore_fmt_lexer_smoke)
add_executable(saltscore_original_fmt_lexer_test test_fmt_re2c.c)
target_compile_features(saltscore_original_fmt_lexer_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_fmt_lexer_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_lexer_contract COMMAND saltscore_original_fmt_lexer_test)

# Original formatter implementation: typed C11 and C++17 metadata, bounded
# rendering, invalid specifier rejection, time formatting, dynamic tstr and views.
add_executable(saltscore_original_fmt_test test_fmt.c)
target_compile_features(saltscore_original_fmt_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_fmt_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_c11 COMMAND saltscore_original_fmt_test)

add_executable(saltscore_original_fmt_cpp_test test_fmt_cpp.cpp)
target_compile_features(saltscore_original_fmt_cpp_test PRIVATE cxx_std_17)
target_link_libraries(saltscore_original_fmt_cpp_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_cpp17 COMMAND saltscore_original_fmt_cpp_test)

add_executable(saltscore_original_fmt_view_test test_fmt_vstr_pattern.c)
target_compile_features(saltscore_original_fmt_view_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_fmt_view_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_bounded_vstr COMMAND saltscore_original_fmt_view_test)
# Original formatter contract: TinyTest is the mandatory source assertion runner.
add_executable(saltscore_fmt_smoke test_fmt_smoke.c)
target_compile_features(saltscore_fmt_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_fmt_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_fmt_smoke COMMAND saltscore_fmt_smoke)

# Original log pattern lexer tokens, C11 parser/format ownership.
add_executable(saltscore_log_pattern_lexer_test test_log_pattern_lexer.c)
target_compile_features(saltscore_log_pattern_lexer_test PRIVATE c_std_11)
target_link_libraries(saltscore_log_pattern_lexer_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_log_pattern_lexer
  COMMAND saltscore_log_pattern_lexer_test)

# Original async logger: the original TinyTest and native callback exercise
# real Disruptor/FS providers, thread drain, shutdown, not a logger mock.
add_executable(saltscore_tlog_smoke test_tlog_smoke.c)
target_compile_features(saltscore_tlog_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_tlog_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_tlog_smoke COMMAND saltscore_tlog_smoke)
set_tests_properties(saltscore.original_tlog_smoke PROPERTIES TIMEOUT 40)
foreach(_tlog_suite IN ITEMS tlog tlog_vstr_abi tlog_header_collision)
  add_executable(saltscore_original_${_tlog_suite}_test test_${_tlog_suite}.c)
  target_compile_features(saltscore_original_${_tlog_suite}_test PRIVATE c_std_11)
  target_link_libraries(saltscore_original_${_tlog_suite}_test PRIVATE
    Salts::Core Salts::TinyTest)
  add_test(NAME saltscore.original_${_tlog_suite}
    COMMAND saltscore_original_${_tlog_suite}_test)
  set_tests_properties(saltscore.original_${_tlog_suite} PROPERTIES TIMEOUT 120)
endforeach()
add_executable(saltscore_original_tlog_cpp_test test_tlog_cpp.cpp)
target_compile_features(saltscore_original_tlog_cpp_test PRIVATE cxx_std_17)
target_link_libraries(saltscore_original_tlog_cpp_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_tlog_cpp COMMAND saltscore_original_tlog_cpp_test)
set_tests_properties(saltscore.original_tlog_cpp PROPERTIES TIMEOUT 120)

# Original RFC 4122/9562 UUID v4/v7 and canonical parse/format.
add_executable(saltscore_uuid_smoke test_uuid_smoke.c)
target_compile_features(saltscore_uuid_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_uuid_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_uuid_smoke COMMAND saltscore_uuid_smoke)
add_executable(saltscore_original_uuid_test test_cmeta_uuid.c)
target_compile_features(saltscore_original_uuid_test PRIVATE c_std_11)
target_link_libraries(saltscore_original_uuid_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_uuid_c11 COMMAND saltscore_original_uuid_test)
add_executable(saltscore_original_uuid_cpp_test test_cmeta_uuid_cpp.cpp)
target_compile_features(saltscore_original_uuid_cpp_test PRIVATE cxx_std_17)
target_link_libraries(saltscore_original_uuid_cpp_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_uuid_cpp17 COMMAND saltscore_original_uuid_cpp_test)

# Restore the original single-owner, hard-capped byte accumulator. This is not
# the borrowed-only salts_core_bytes_view/slice contract.
add_executable(saltscore_cmeta_bytes_smoke test_cmeta_bytes_smoke.c)
target_compile_features(saltscore_cmeta_bytes_smoke PRIVATE c_std_11)
target_link_libraries(saltscore_cmeta_bytes_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_bytes_accumulator_smoke COMMAND saltscore_cmeta_bytes_smoke)
add_executable(saltscore_original_bytes_accumulator test_cmeta_bytes.c)
target_compile_features(saltscore_original_bytes_accumulator PRIVATE c_std_11)
target_link_libraries(saltscore_original_bytes_accumulator PRIVATE
  Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_bytes_accumulator_contract
  COMMAND saltscore_original_bytes_accumulator)

# Original seven-function bounded byte scan contract. This is the canonical
# portable C11 implementation; SIMD throughput parity is tracked separately.
add_executable(saltscore_simd_scan_contract test_simd_scan_contract.c)
target_compile_features(saltscore_simd_scan_contract PRIVATE c_std_11)
target_link_libraries(saltscore_simd_scan_contract PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_simd_scan_contract COMMAND saltscore_simd_scan_contract)


# Actual original qigao/salts utils native memory mapping, not a mock
# and not a CMeta/CFlow runtime. Real file page / range / write / group.
add_executable(saltscore_original_native_mmap_test test_original_native_mmap.c)
target_compile_features(saltscore_original_native_mmap_test PRIVATE c_std_11)
set_target_properties(saltscore_original_native_mmap_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_original_native_mmap_test PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_native_mmap
  COMMAND saltscore_original_native_mmap_test)
set_tests_properties(saltscore.original_native_mmap PROPERTIES TIMEOUT 30)

# Frozen source/accounting policies run once in the Migration gate.
# Native CTest below remains executable behavior only.

# qigao/salts original utils native byte regex, 10 owned public C11 functions.
# Always-on compiled source/runtime; TinyTest retains all 25 donor test cases.
add_executable(saltscore_original_re_smoke test_re_smoke.c)
target_compile_features(saltscore_original_re_smoke PRIVATE c_std_11)
set_target_properties(saltscore_original_re_smoke PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_original_re_smoke PRIVATE Salts::Core Salts::TinyTest)
add_test(NAME saltscore.original_re_smoke COMMAND saltscore_original_re_smoke)
set_tests_properties(saltscore.original_re_smoke PROPERTIES TIMEOUT 25)

add_executable(saltscore_original_re_contract test_re.c)
target_compile_features(saltscore_original_re_contract PRIVATE c_std_11)
target_link_libraries(saltscore_original_re_contract PRIVATE
  Salts::Core Salts::TinyTest)
# The first-byte scan is PRIVATE. Only the original tests may inspect it.
target_include_directories(saltscore_original_re_contract PRIVATE
  "${PROJECT_SOURCE_DIR}/core/src")
add_test(NAME saltscore.original_re_25_case_contract
  COMMAND saltscore_original_re_contract)
set_tests_properties(saltscore.original_re_25_case_contract
  PROPERTIES TIMEOUT 60)


# Regex/SIMD/Error source provenance also runs once in the Migration gate.
# The release-only migration-receipt harness is intentionally not part of PR CI.

# Downstream CMeta uses the pinned Core auditor to verify physical shared-image
# ownership. Keep its cross-platform parser behavior in the formal CTest graph.
add_test(NAME saltscore.audit_runtime_owner_parser
  COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover
    -s tests -p test_audit_runtime_owner.py)
set_tests_properties(saltscore.audit_runtime_owner_parser PROPERTIES
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}" TIMEOUT 30)
