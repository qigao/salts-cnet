cmake_minimum_required(VERSION 3.20)
# Optional SaltsCore SCTP implementation; no separate package or compatibility ABI.
# Standalone direct builds are only for C11 conformance.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(SaltsCoreSCTP VERSION 0.1.0 LANGUAGES C)
  include(CTest)
  include(GNUInstallDirs)
endif()

# An isolated, C-only research target, not the production Salts::CNet library.
add_library(cnet_sctp_wire STATIC src/sctp_wire.c)
add_library(Salts::SCTPWire ALIAS cnet_sctp_wire)

# M2 research only: not part of installed C11 ABI or Salts targets.
add_library(cnet_sctp_assoc_proto STATIC
  src/sctp_assoc.c src/sctp_init_params.c src/sctp_collision.c)

# M2/M3 DATA sub-engine: independent static C11 target, not installed/exported.
add_library(cnet_sctp_data_proto STATIC src/sctp_data.c)

# RFC 8832 DCEP codec is private until PR-SCTP, complete stream reset and full
# peer interoperability qualify a complete public WebRTC DataChannel API.
add_library(cnet_sctp_dcep_proto STATIC src/sctp_dcep.c)

# Stateless RFC8831 PPID 51/53/56/57 adapter, no external transport or SDK.
add_library(cnet_sctp_webrtc_proto STATIC src/sctp_webrtc.c)

# Private-layout M3 ULP test target. The separately compiled installed Session
# target below exports the same behavior only through an opaque public handle.
add_library(cnet_sctp_session_proto STATIC src/sctp_session.c)
target_include_directories(cnet_sctp_session_proto PRIVATE src)
target_link_libraries(cnet_sctp_session_proto PUBLIC
  cnet_sctp_assoc_proto cnet_sctp_dcep_proto cnet_sctp_webrtc_proto)
set_target_properties(cnet_sctp_session_proto PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(cnet_sctp_session_proto PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_session_proto PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
endif()

# Installed opaque C11 Owner/session ABI. Internal Association, DATA, DCEP and
# WebRTC layouts remain private implementation details of this static library.
add_library(cnet_sctp_session STATIC
  src/sctp_session.c
  src/sctp_assoc.c
  src/sctp_init_params.c
  src/sctp_collision.c
  src/sctp_data.c
  src/sctp_dcep.c
  src/sctp_webrtc.c)
add_library(Salts::SCTP ALIAS cnet_sctp_session)
target_link_libraries(cnet_sctp_session PUBLIC cnet_sctp_wire)
target_include_directories(cnet_sctp_session
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE src)
set_target_properties(cnet_sctp_session PROPERTIES
  EXPORT_NAME SCTP
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  target_compile_options(cnet_sctp_session PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_session PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
endif()
target_include_directories(cnet_sctp_webrtc_proto PRIVATE src)
set_target_properties(cnet_sctp_webrtc_proto PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(cnet_sctp_webrtc_proto PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_webrtc_proto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_include_directories(cnet_sctp_dcep_proto PRIVATE src)
set_target_properties(cnet_sctp_dcep_proto PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(cnet_sctp_dcep_proto PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_dcep_proto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(cnet_sctp_data_proto PUBLIC cnet_sctp_wire)
# Existing private Association now admits DATA/SACK only after Cookie ACK.
target_link_libraries(cnet_sctp_assoc_proto PUBLIC cnet_sctp_data_proto)
target_include_directories(cnet_sctp_data_proto PRIVATE src)
set_target_properties(cnet_sctp_data_proto PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(cnet_sctp_data_proto PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_data_proto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(cnet_sctp_assoc_proto PUBLIC cnet_sctp_wire)
target_include_directories(cnet_sctp_assoc_proto PRIVATE src)
set_target_properties(cnet_sctp_assoc_proto PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(cnet_sctp_assoc_proto PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_assoc_proto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
set_target_properties(cnet_sctp_wire PROPERTIES
  EXPORT_NAME SCTPWire
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)
target_include_directories(cnet_sctp_wire PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(MSVC)
  target_compile_options(cnet_sctp_wire PRIVATE /W4 /WX)
else()
  target_compile_options(cnet_sctp_wire PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Only SaltsCore exports this ABI, never an old standalone package.
if(PROJECT_NAME STREQUAL "SaltsCore")
  install(TARGETS cnet_sctp_wire cnet_sctp_session
    EXPORT SaltsCoreTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(FILES include/cnet/sctp_wire.h include/cnet/sctp_session.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cnet)
endif()

if(BUILD_TESTING)
  add_executable(cnet_sctp_wire_test tests/wire_test.c)
  target_link_libraries(cnet_sctp_wire_test PRIVATE Salts::SCTPWire Salts::TinyTest)
  set_target_properties(cnet_sctp_wire_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_wire_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_wire_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_wire_test COMMAND cnet_sctp_wire_test)

  add_executable(cnet_sctp_assoc_test tests/assoc_test.c)
  target_link_libraries(cnet_sctp_assoc_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_assoc_test PRIVATE src)
  set_target_properties(cnet_sctp_assoc_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_assoc_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_assoc_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_assoc_test COMMAND cnet_sctp_assoc_test)

  add_executable(cnet_sctp_init_params_test tests/init_params_test.c)
  target_link_libraries(cnet_sctp_init_params_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_init_params_test PRIVATE src)
  set_target_properties(cnet_sctp_init_params_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_init_params_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_init_params_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_init_params_test COMMAND cnet_sctp_init_params_test)

  # Table 12 classifiers are decision-only: no side effects or production cutover.
  add_executable(cnet_sctp_collision_test tests/collision_test.c)
  target_link_libraries(cnet_sctp_collision_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_collision_test PRIVATE src)
  set_target_properties(cnet_sctp_collision_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_collision_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_collision_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_collision_test COMMAND cnet_sctp_collision_test)

  add_executable(cnet_sctp_data_test tests/data_test.c)
  target_link_libraries(cnet_sctp_data_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_data_test PRIVATE src)
  set_target_properties(cnet_sctp_data_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_data_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_data_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_data_test COMMAND cnet_sctp_data_test)

  add_executable(cnet_sctp_sack_recovery_test tests/sack_recovery_test.c)
  target_link_libraries(cnet_sctp_sack_recovery_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_sack_recovery_test PRIVATE src)
  set_target_properties(cnet_sctp_sack_recovery_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_sack_recovery_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_sack_recovery_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_sack_recovery_test COMMAND cnet_sctp_sack_recovery_test)

  add_executable(cnet_sctp_fast_recovery_test tests/fast_recovery_test.c)
  target_link_libraries(cnet_sctp_fast_recovery_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_fast_recovery_test PRIVATE src)
  set_target_properties(cnet_sctp_fast_recovery_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_fast_recovery_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_fast_recovery_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_fast_recovery_test COMMAND cnet_sctp_fast_recovery_test)

  add_executable(cnet_sctp_congestion_test tests/congestion_test.c)
  target_link_libraries(cnet_sctp_congestion_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_congestion_test PRIVATE src)
  set_target_properties(cnet_sctp_congestion_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_congestion_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_congestion_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_congestion_test COMMAND cnet_sctp_congestion_test)

  add_executable(cnet_sctp_zero_window_test tests/zero_window_test.c)
  target_link_libraries(cnet_sctp_zero_window_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_zero_window_test PRIVATE src)
  set_target_properties(cnet_sctp_zero_window_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_zero_window_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_zero_window_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_zero_window_test COMMAND cnet_sctp_zero_window_test)

  add_executable(cnet_sctp_pr_sctp_test tests/pr_sctp_test.c)
  target_link_libraries(cnet_sctp_pr_sctp_test PRIVATE
    cnet_sctp_data_proto cnet_sctp_wire Salts::TinyTest)
  target_include_directories(cnet_sctp_pr_sctp_test PRIVATE src)
  set_target_properties(cnet_sctp_pr_sctp_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_pr_sctp_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_pr_sctp_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_pr_sctp_test COMMAND cnet_sctp_pr_sctp_test)

  add_executable(cnet_sctp_interleaving_test tests/interleaving_test.c)
  target_link_libraries(cnet_sctp_interleaving_test PRIVATE
    cnet_sctp_data_proto cnet_sctp_wire Salts::TinyTest)
  target_include_directories(cnet_sctp_interleaving_test PRIVATE src)
  set_target_properties(cnet_sctp_interleaving_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_interleaving_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_interleaving_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_interleaving_test
    COMMAND cnet_sctp_interleaving_test)

  add_executable(cnet_sctp_bundle_test tests/bundle_test.c)
  target_link_libraries(cnet_sctp_bundle_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_bundle_test PRIVATE src)
  set_target_properties(cnet_sctp_bundle_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_bundle_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_bundle_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_bundle_test COMMAND cnet_sctp_bundle_test)

  add_executable(cnet_sctp_fragment_test tests/fragment_test.c)
  target_link_libraries(cnet_sctp_fragment_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_fragment_test PRIVATE src)
  set_target_properties(cnet_sctp_fragment_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_fragment_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_fragment_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_fragment_test COMMAND cnet_sctp_fragment_test)

  add_executable(cnet_sctp_assoc_data_test tests/assoc_data_test.c)
  target_link_libraries(cnet_sctp_assoc_data_test PRIVATE
    cnet_sctp_assoc_proto cnet_sctp_dcep_proto cnet_sctp_webrtc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_assoc_data_test PRIVATE src)
  set_target_properties(cnet_sctp_assoc_data_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_assoc_data_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_assoc_data_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_assoc_data_test COMMAND cnet_sctp_assoc_data_test)

  add_executable(cnet_sctp_dcep_test tests/dcep_test.c)
  target_link_libraries(cnet_sctp_dcep_test PRIVATE cnet_sctp_dcep_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_dcep_test PRIVATE src)
  set_target_properties(cnet_sctp_dcep_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_dcep_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_dcep_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_dcep_test COMMAND cnet_sctp_dcep_test)

  add_executable(cnet_sctp_session_test tests/session_test.c)
  target_link_libraries(cnet_sctp_session_test PRIVATE cnet_sctp_session_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_session_test PRIVATE src)
  set_target_properties(cnet_sctp_session_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_session_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_session_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_session_test COMMAND cnet_sctp_session_test)

  # Public opaque Session behavior remains a source-tree formal test. It is
  # deliberately not configured as a second installed-consumer project.
  add_executable(cnet_sctp_public_api_test tests/public_api_test.c)
  target_link_libraries(cnet_sctp_public_api_test PRIVATE Salts::SCTP Salts::TinyTest)
  set_target_properties(cnet_sctp_public_api_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_public_api_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_public_api_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_public_api_test COMMAND cnet_sctp_public_api_test)

endif()

# M5: actual POSIX-thread handoff test with external single-Owner lease.
# Opt-in only. This test does not authorize unsynchronized concurrent API
# calls and never enters the installed Wire-only SDK.
option(CNET_SCTP_TEST_OWNER_THREADS "Build private POSIX Owner-handoff test" OFF)
if(CNET_SCTP_TEST_OWNER_THREADS)
  if(WIN32)
    message(FATAL_ERROR "Private Owner thread gate needs POSIX Threads")
  endif()
  if(NOT BUILD_TESTING)
    message(FATAL_ERROR "Owner thread gate requires BUILD_TESTING=ON")
  endif()
  find_package(Threads REQUIRED)
  add_executable(cnet_sctp_owner_thread_test tests/owner_thread_test.c)
  target_include_directories(cnet_sctp_owner_thread_test PRIVATE src)
  target_link_libraries(cnet_sctp_owner_thread_test PRIVATE
    cnet_sctp_assoc_proto Threads::Threads Salts::TinyTest)
  set_target_properties(cnet_sctp_owner_thread_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_owner_thread_test PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME cnet_sctp_owner_thread_test
    COMMAND cnet_sctp_owner_thread_test)
  set_tests_properties(cnet_sctp_owner_thread_test PROPERTIES TIMEOUT 60)
  # Actual dlopen/dlclose validation is POSIX only and never installed.
  # Keep the provider and host as independently compiled C11 code: a future
  # DSO unload must wait until the last borrowed callback has settled.
  add_library(cnet_sctp_test_provider_dso MODULE
    tests/provider_dso_fixture.c)
  target_include_directories(cnet_sctp_test_provider_dso PRIVATE tests)
  target_link_libraries(cnet_sctp_test_provider_dso PRIVATE Threads::Threads)
  set_target_properties(cnet_sctp_test_provider_dso PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_test_provider_dso PRIVATE
    -Wall -Wextra -Wpedantic -Werror)

  add_executable(cnet_sctp_provider_dso_test tests/provider_dso_test.c)
  target_include_directories(cnet_sctp_provider_dso_test PRIVATE src tests)
  target_link_libraries(cnet_sctp_provider_dso_test PRIVATE
    cnet_sctp_assoc_proto Threads::Threads ${CMAKE_DL_LIBS} Salts::TinyTest)
  set_target_properties(cnet_sctp_provider_dso_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_provider_dso_test PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  add_dependencies(cnet_sctp_provider_dso_test
    cnet_sctp_test_provider_dso)
  add_test(NAME cnet_sctp_provider_dso_test
    COMMAND cnet_sctp_provider_dso_test
      $<TARGET_FILE:cnet_sctp_test_provider_dso>)
  set_tests_properties(cnet_sctp_provider_dso_test PROPERTIES TIMEOUT 90)

  # Test-only public opaque Session + real DSO cancellation/Owner/drain.
  # The existing private Association DSO gate remains separate.
  add_executable(cnet_sctp_session_provider_dso_test
    tests/session_provider_dso_test.c)
  target_include_directories(cnet_sctp_session_provider_dso_test
    PRIVATE tests)
  target_link_libraries(cnet_sctp_session_provider_dso_test PRIVATE
    Salts::SCTP Threads::Threads ${CMAKE_DL_LIBS} Salts::TinyTest)
  set_target_properties(cnet_sctp_session_provider_dso_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_session_provider_dso_test PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  add_dependencies(cnet_sctp_session_provider_dso_test
    cnet_sctp_test_provider_dso)
  add_test(NAME cnet_sctp_session_provider_dso_test
    COMMAND cnet_sctp_session_provider_dso_test
      $<TARGET_FILE:cnet_sctp_test_provider_dso>)
  set_tests_properties(cnet_sctp_session_provider_dso_test PROPERTIES TIMEOUT 90)
endif()

# Test-only independent Pion SCTP oracle. Real UDP datagrams to an external
# Go implementation of SCTP (RFC8260); no DTLS in this deliberately isolated
# first oracle slice. NEVER export, install or link this adapter into Salts.
option(CNET_SCTP_TEST_PION_ORACLE
  "Build separate Pion SCTP RFC8260 test-only UDP packet peer" OFF)
if(CNET_SCTP_TEST_PION_ORACLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Independent Pion SCTP oracle is Linux-only")
  endif()
  find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
  add_executable(cnet_sctp_pion_oracle_peer
    tests/independent/pion_peer.c
    tests/independent/pion_dtls_transport.c)
  target_link_libraries(cnet_sctp_pion_oracle_peer PRIVATE
    Salts::SCTP OpenSSL::SSL OpenSSL::Crypto)
  set_target_properties(cnet_sctp_pion_oracle_peer PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_pion_oracle_peer PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
endif()

# Cookie-MAC cryptography belongs to qigao/crypto. CNet/SCTP remains
# provider-neutral through explicit callback admission; no GmSSL fallback.
