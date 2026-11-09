# Private engines expose internal layouts only to this module's tests.
add_library(cnet_sctp_data_proto STATIC ../src/sctp_data.c)
add_library(cnet_sctp_assoc_proto STATIC
  ../src/sctp_assoc.c ../src/sctp_init_params.c ../src/sctp_collision.c)
add_library(cnet_sctp_dcep_proto STATIC ../src/sctp_dcep.c)
add_library(cnet_sctp_webrtc_proto STATIC ../src/sctp_webrtc.c)
add_library(cnet_sctp_session_proto STATIC ../src/sctp_session.c)
target_link_libraries(cnet_sctp_data_proto PUBLIC Salts::SCTPWire)
target_link_libraries(cnet_sctp_assoc_proto PUBLIC cnet_sctp_data_proto Salts::SCTPWire)
target_link_libraries(cnet_sctp_session_proto PUBLIC
  cnet_sctp_assoc_proto cnet_sctp_dcep_proto cnet_sctp_webrtc_proto)
foreach(target IN ITEMS cnet_sctp_data_proto cnet_sctp_assoc_proto
    cnet_sctp_dcep_proto cnet_sctp_webrtc_proto cnet_sctp_session_proto)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  cmake_config_target(${target} FOLDER "sctp/tests")
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()

if(BUILD_TESTS)
  cmake_add_executable(cnet_sctp_wire_test SOURCES wire_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_wire_test PRIVATE Salts::SCTPWire Salts::TinyTest)
  set_target_properties(cnet_sctp_wire_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_wire_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_wire_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_wire_test COMMAND cnet_sctp_wire_test)

  cmake_add_executable(cnet_sctp_assoc_test SOURCES assoc_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_assoc_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_assoc_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_assoc_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_assoc_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_assoc_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_assoc_test COMMAND cnet_sctp_assoc_test)

  cmake_add_executable(cnet_sctp_init_params_test SOURCES init_params_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_init_params_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_init_params_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_init_params_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_init_params_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_init_params_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_init_params_test COMMAND cnet_sctp_init_params_test)

  # Table 12 classifiers are decision-only: no side effects or production cutover.
  cmake_add_executable(cnet_sctp_collision_test SOURCES collision_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_collision_test PRIVATE cnet_sctp_assoc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_collision_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_collision_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_collision_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_collision_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_collision_test COMMAND cnet_sctp_collision_test)

  cmake_add_executable(cnet_sctp_data_test SOURCES data_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_data_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_data_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_data_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_data_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_data_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_data_test COMMAND cnet_sctp_data_test)

  cmake_add_executable(cnet_sctp_sack_recovery_test SOURCES sack_recovery_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_sack_recovery_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_sack_recovery_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_sack_recovery_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_sack_recovery_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_sack_recovery_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_sack_recovery_test COMMAND cnet_sctp_sack_recovery_test)

  cmake_add_executable(cnet_sctp_fast_recovery_test SOURCES fast_recovery_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_fast_recovery_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_fast_recovery_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_fast_recovery_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_fast_recovery_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_fast_recovery_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_fast_recovery_test COMMAND cnet_sctp_fast_recovery_test)

  cmake_add_executable(cnet_sctp_congestion_test SOURCES congestion_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_congestion_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_congestion_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_congestion_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_congestion_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_congestion_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_congestion_test COMMAND cnet_sctp_congestion_test)

  cmake_add_executable(cnet_sctp_zero_window_test SOURCES zero_window_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_zero_window_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_zero_window_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_zero_window_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_zero_window_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_zero_window_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_zero_window_test COMMAND cnet_sctp_zero_window_test)

  cmake_add_executable(cnet_sctp_pr_sctp_test SOURCES pr_sctp_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_pr_sctp_test PRIVATE
    cnet_sctp_data_proto cnet_sctp_wire Salts::TinyTest)
  target_include_directories(cnet_sctp_pr_sctp_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_pr_sctp_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_pr_sctp_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_pr_sctp_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_pr_sctp_test COMMAND cnet_sctp_pr_sctp_test)

  cmake_add_executable(cnet_sctp_interleaving_test SOURCES interleaving_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_interleaving_test PRIVATE
    cnet_sctp_data_proto cnet_sctp_wire Salts::TinyTest)
  target_include_directories(cnet_sctp_interleaving_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
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

  cmake_add_executable(cnet_sctp_bundle_test SOURCES bundle_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_bundle_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_bundle_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_bundle_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_bundle_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_bundle_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_bundle_test COMMAND cnet_sctp_bundle_test)

  cmake_add_executable(cnet_sctp_fragment_test SOURCES fragment_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_fragment_test PRIVATE cnet_sctp_data_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_fragment_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_fragment_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_fragment_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_fragment_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_fragment_test COMMAND cnet_sctp_fragment_test)

  cmake_add_executable(cnet_sctp_assoc_data_test SOURCES assoc_data_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_assoc_data_test PRIVATE
    cnet_sctp_assoc_proto cnet_sctp_dcep_proto cnet_sctp_webrtc_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_assoc_data_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_assoc_data_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_assoc_data_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_assoc_data_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_assoc_data_test COMMAND cnet_sctp_assoc_data_test)

  cmake_add_executable(cnet_sctp_dcep_test SOURCES dcep_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_dcep_test PRIVATE cnet_sctp_dcep_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_dcep_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  set_target_properties(cnet_sctp_dcep_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(cnet_sctp_dcep_test PRIVATE /W4 /WX)
  else()
    target_compile_options(cnet_sctp_dcep_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cnet_sctp_dcep_test COMMAND cnet_sctp_dcep_test)

  cmake_add_executable(cnet_sctp_session_test SOURCES session_test.c
    FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_session_test PRIVATE cnet_sctp_session_proto Salts::TinyTest)
  target_include_directories(cnet_sctp_session_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
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
  cmake_add_executable(cnet_sctp_public_api_test SOURCES public_api_test.c
    FOLDER "sctp/tests")
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
# This test does not authorize unsynchronized concurrent API
# calls and never enters the installed Wire-only SDK.
if(BUILD_TESTS AND UNIX)
  if(WIN32)
    message(FATAL_ERROR "Private Owner thread gate needs POSIX Threads")
  endif()
  find_package(Threads REQUIRED)
  cmake_add_executable(cnet_sctp_owner_thread_test SOURCES owner_thread_test.c
    FOLDER "sctp/tests")
  target_include_directories(cnet_sctp_owner_thread_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
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
    provider_dso_fixture.c)
  target_include_directories(cnet_sctp_test_provider_dso PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(cnet_sctp_test_provider_dso PRIVATE Threads::Threads)
  set_target_properties(cnet_sctp_test_provider_dso PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_test_provider_dso PRIVATE
    -Wall -Wextra -Wpedantic -Werror)

  cmake_add_executable(cnet_sctp_provider_dso_test SOURCES provider_dso_test.c
    FOLDER "sctp/tests")
  target_include_directories(cnet_sctp_provider_dso_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src" "${CMAKE_CURRENT_SOURCE_DIR}")
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
  cmake_add_executable(cnet_sctp_session_provider_dso_test SOURCES session_provider_dso_test.c
    FOLDER "sctp/tests")
  target_include_directories(cnet_sctp_session_provider_dso_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
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
if(BUILD_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  cmake_add_executable(cnet_sctp_pion_oracle_peer SOURCES independent/pion_peer.c
  FOLDER "sctp/tests")
  target_link_libraries(cnet_sctp_pion_oracle_peer PRIVATE
    Salts::SCTP)
  set_target_properties(cnet_sctp_pion_oracle_peer PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(cnet_sctp_pion_oracle_peer PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
endif()

# Cookie-MAC cryptography belongs to qigao/crypto. CNet/SCTP remains
# provider-neutral through explicit callback admission; no GmSSL fallback.

file(GLOB _dtls_native_tests CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_native_*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_dtls_native_tests})
add_executable(cnet_sctp_dtls_native_peer ${_dtls_native_tests})
target_link_libraries(cnet_sctp_dtls_native_peer PRIVATE Salts::SCTPDTLS Salts::Core)
set_target_properties(cnet_sctp_dtls_native_peer PROPERTIES FOLDER "SCTP/tests")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_SCTP_DTLS_GO go REQUIRED)
  add_test(NAME saltscore.sctp_dtls_native
    COMMAND "${SALTS_SCTP_DTLS_GO}" test -mod=readonly -count=1 -failfast -v -timeout=120s
      -args -native "$<TARGET_FILE:cnet_sctp_dtls_native_peer>")
  set_tests_properties(saltscore.sctp_dtls_native PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/secure"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 150)
endif()
