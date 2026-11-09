find_package(Python3 COMPONENTS Interpreter REQUIRED)

cmake_add_test(saltscore_cnet_resources_test SOURCES test_cnet_resources.c
  INCLUDES "${PROJECT_SOURCE_DIR}/cnet/src"
  LIBS Salts::CNet Salts::TinyTest FOLDER "cnet/tests")

# Parser-only C11 gate with no TLS, CNet, re2c, CMeta or CFlow provider.
cmake_add_executable(saltscore_wsparser_test SOURCES test_wsparser.c
  FOLDER "cnet/tests")
target_compile_features(saltscore_wsparser_test PRIVATE c_std_11)
set_target_properties(saltscore_wsparser_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(saltscore_wsparser_test PRIVATE
  "${PROJECT_SOURCE_DIR}/cnet/src/wsparser")
target_link_libraries(saltscore_wsparser_test PRIVATE saltscore_wsparser Salts::TinyTest)
add_test(NAME saltscore.wsparser COMMAND saltscore_wsparser_test)

# Use the one production CNet DSO, not duplicate compiled policy sources.
# Existing TinyTest/CTest target now tests real URI, TLS and UDP/KCP admission.
# No consumer project, extra runtime/Owner, installer or new test workflow.
cmake_add_executable(saltscore_cnet_policy_test SOURCES test_cnet_policy.c
  FOLDER "cnet/tests")
target_compile_features(saltscore_cnet_policy_test PRIVATE c_std_11)
set_target_properties(saltscore_cnet_policy_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_cnet_policy_test PRIVATE
  Salts::CNet Salts::Crypto Salts::TinyTest)
if(MSVC)
  target_compile_options(saltscore_cnet_policy_test PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
endif()
add_test(NAME saltscore.cnet_policy COMMAND saltscore_cnet_policy_test)

# Native ABI and ShangMi tests use the source-built Salts::Crypto archive.
# No external provider package or second implementation is assembled here.

# A separate loadable module checks process-global pool and thread identity
# across DSO/DLL boundaries. Never resolve these through a static archive.
add_library(saltscore_runtime_owner_probe SHARED runtime_owner_module.c)
target_compile_features(saltscore_runtime_owner_probe PRIVATE c_std_11)
set_target_properties(saltscore_runtime_owner_probe PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF WINDOWS_EXPORT_ALL_SYMBOLS ON)
target_link_libraries(saltscore_runtime_owner_probe PRIVATE
  Salts::Core)
# Genuine loopback TCP acceptance + borrowed/retained ownership + stop drain.
cmake_add_executable(saltscore_cnet_tcp_loopback_test SOURCES test_cnet_tcp_loopback.c
  FOLDER "cnet/tests")
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
cmake_add_executable(saltscore_two_plugins_test SOURCES test_runtime_plugins.c
  FOLDER "cnet/tests")
target_compile_features(saltscore_two_plugins_test PRIVATE c_std_11)
set_target_properties(saltscore_two_plugins_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_two_plugins_test PRIVATE
  Salts::Core ${CMAKE_DL_LIBS} Salts::TinyTest)
saltscore_cnet_owner_link_map(saltscore_two_plugins_test)
add_dependencies(saltscore_two_plugins_test
  saltscore_runtime_plugin_a saltscore_runtime_plugin_b)
add_test(NAME saltscore.two_cnet_plugins
  COMMAND saltscore_two_plugins_test
    "$<TARGET_FILE:saltscore_runtime_plugin_a>"
    "$<TARGET_FILE:saltscore_runtime_plugin_b>")
set_tests_properties(saltscore.two_cnet_plugins PROPERTIES TIMEOUT 30)

# Real TLS over NativeIO TCP: trusted issuer + correct SAN must connect;
# wrong root and wrong DNS identity must fail without authenticated callback.
cmake_add_executable(saltscore_cnet_tls_ca_san_test SOURCES test_cnet_tls_ca_san.c
  FOLDER "cnet/tests")
target_compile_features(saltscore_cnet_tls_ca_san_test PRIVATE c_std_11)
set_target_properties(saltscore_cnet_tls_ca_san_test PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(saltscore_cnet_tls_ca_san_test PRIVATE Salts::CNet Salts::Crypto Salts::TinyTest)
target_include_directories(saltscore_cnet_tls_ca_san_test PRIVATE
  "${PROJECT_SOURCE_DIR}/cnet/src" "${PROJECT_SOURCE_DIR}/crypto/src"
  "${PROJECT_SOURCE_DIR}/crypto/tests/tls")
if(MSVC)
  target_compile_options(saltscore_cnet_tls_ca_san_test PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
endif()
file(TO_CMAKE_PATH "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/p384-test-root-cert.pem"
     _cnet_test_root_ca)
file(TO_CMAKE_PATH "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/p384-test-wrong-root-cert.pem"
     _cnet_test_wrong_ca)
file(TO_CMAKE_PATH "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/p384-test-server-cert.pem"
     _cnet_test_cert)
file(TO_CMAKE_PATH "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/p384-test-server-key.pem"
     _cnet_test_key)
target_compile_definitions(saltscore_cnet_tls_ca_san_test PRIVATE
  SALTSCORE_EXPECT_PROVIDER_COPIES=0
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

if(BUILD_BENCHMARK)
# Reuse the actual opt-in TinyTest cases, one fresh process per sample. The
# dependency chain rotates all five modes and preserves order with ctest -j.
# Compiler provenance belongs to the configured graph, not the shell PATH.
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/tls-mixed-compiler.txt" CONTENT
  "compiler=${CMAKE_C_COMPILER}\ncompiler-id=${CMAKE_C_COMPILER_ID}\ncompiler-version=${CMAKE_C_COMPILER_VERSION}\ncompiler-target=${CMAKE_C_COMPILER_TARGET}\nbuild-type=${CMAKE_BUILD_TYPE}\ngenerator=${CMAKE_GENERATOR}\n")
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
    add_test(NAME "${_case}" COMMAND "${_binary}" --filter "${_filter}")
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
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME saltscore.cnet_production_required_mtls
  COMMAND "${Python3_EXECUTABLE}" -B
    "${PROJECT_SOURCE_DIR}/cnet/tests/test_cnet_tls_required_mtls.py"
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
      "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/external_san_peer.py"
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
    "${PROJECT_SOURCE_DIR}/cnet/tests/test_cnet_tls_python_client.py"
    --binary "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>"
    --fixture-generator "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
    --work "${PROJECT_BINARY_DIR}/native-python-client-mtls")
set_tests_properties(saltscore.cnet_python_ssl_client_required_mtls
  PROPERTIES TIMEOUT 300 RESOURCE_LOCK cnet_native_required_mtls)

# Test-only native Crypto Owner, never part of the production CNet target.
add_subdirectory(crypto-static)

add_subdirectory(owner)

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

add_executable(cnet_tls_server_ticket_peer tls_server_tickets.c)
file(GLOB _cnet_dtls_test_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_native_*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_cnet_dtls_test_sources})
add_executable(cnet_dtls_native_peer ${_cnet_dtls_test_sources})
target_link_libraries(cnet_dtls_native_peer PRIVATE Salts::CNet Salts::Core)
set_target_properties(cnet_dtls_native_peer PROPERTIES FOLDER "CNet/tests")
file(GLOB _cnet_dtls_cpp_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_header_*.cpp")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_cnet_dtls_cpp_sources})
add_executable(cnet_dtls_header_cpp ${_cnet_dtls_cpp_sources})
target_compile_features(cnet_dtls_header_cpp PRIVATE cxx_std_17)
target_link_libraries(cnet_dtls_header_cpp PRIVATE Salts::CNet Salts::Crypto Salts::TinyTest)
set_target_properties(cnet_dtls_header_cpp PROPERTIES FOLDER "CNet/tests")
add_test(NAME saltscore.cnet_dtls_cpp17 COMMAND cnet_dtls_header_cpp)
set_tests_properties(saltscore.cnet_dtls_cpp17 PROPERTIES TIMEOUT 60)
target_link_libraries(cnet_tls_server_ticket_peer PRIVATE Salts::CNet Salts::Crypto Salts::TinyTest)
if(MSVC)
  target_compile_options(cnet_tls_server_ticket_peer PRIVATE /experimental:c11atomics)
endif()
set_target_properties(cnet_tls_server_ticket_peer PROPERTIES FOLDER "CNet/tests")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_CNET_TICKET_GO go REQUIRED)
  add_test(NAME saltscore.cnet_dtls_native
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -failfast -v -timeout=90s -run "^TestDTLSNative"
      -args -dtls-native "$<TARGET_FILE:cnet_dtls_native_peer>")
  set_tests_properties(saltscore.cnet_dtls_native PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
  add_test(NAME saltscore.cnet_tls_server_tickets
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestServerTickets$"
      -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_tls_server_tickets PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
  add_test(NAME saltscore.cnet_pkix_name_constraints
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestNameConstraints$" -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_pkix_name_constraints PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
  add_test(NAME saltscore.cnet_tlcp_anchor_constraints
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestTLCPAnchorConstraints$" -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
  set_tests_properties(saltscore.cnet_tlcp_anchor_constraints PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/cnet/tests/independent/tlcp"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
  add_test(NAME saltscore.cnet_shangmi_server_tickets
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestShangMiServerTickets$" -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_shangmi_server_tickets PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/cnet/tests/independent/shangmi"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
endif()

cmake_add_test(saltscore_websocket_utf8_test
  SOURCES websocket_utf8_test.c
  LIBS Salts::CNet Salts::TinyTest FOLDER "cnet/tests")

if(BUILD_BENCHMARK)
  cmake_add_test(saltscore_websocket_utf8_benchmark
    SOURCES websocket_utf8_benchmark.c
    LIBS Salts::CNet Salts::TinyTest FOLDER "cnet/tests")
  set_tests_properties(saltscore_websocket_utf8_benchmark PROPERTIES
    LABELS benchmark TIMEOUT 120)
endif()
