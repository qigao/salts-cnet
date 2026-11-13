# Original CNet tests use the same pinned vcpkg GmSSL/Crypto dependency
# graph as production, in a separate executable that never loads Salts::CNet.
# Discover only the transport dependencies in this sibling CMake scope.

# CNet test-only link closure: same real CNet implementation as the
# installed shared target, compiled as a PRIVATE owner only for this test image.
# The executable links exactly one CNet state machine, never Salts::CNet.
get_target_property(_core_owner_native_sources cnet SOURCES)
add_library(cnet_original_test_owner STATIC
  ${_core_owner_native_sources})
target_compile_features(cnet_original_test_owner PUBLIC c_std_11)
# Match the original first-party CNet test-profile flags exactly.
# None are installed, exported or applied to the real Salts::CNet DSO.
target_compile_definitions(cnet_original_test_owner PUBLIC
  CNET_INTERNAL_PROFILING=1 CNET_INTERNAL_MULTI_OWNER_POC=1
  CNET_INTERNAL_TESTING=1)
set_target_properties(cnet_original_test_owner PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_include_directories(cnet_original_test_owner
  PUBLIC "${PROJECT_SOURCE_DIR}/crypto/include"
  PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/include"
    "${PROJECT_SOURCE_DIR}/cnet/src"
    "${PROJECT_SOURCE_DIR}/cnet/src/wsparser"
    "${PROJECT_SOURCE_DIR}/vendor/monocypher"
    "${PROJECT_SOURCE_DIR}/vendor/reed"
    "${PROJECT_SOURCE_DIR}/crypto/src")
target_link_libraries(cnet_original_test_owner
  PUBLIC Salts::Core Salts::NativeIO
  PRIVATE Salts::URI Salts::SIMD monocypher
    reed c-ares::cares kcp::kcp Salts::Crypto)

cmake_add_executable(cnet_owner_original_test SOURCES cnet_owner_test.c
  FOLDER "cnet/tests/owner")
target_compile_definitions(cnet_owner_original_test PRIVATE
  CNET_INTERNAL_TESTING=1)
target_include_directories(cnet_owner_original_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/cnet/include"
  "${PROJECT_SOURCE_DIR}/cnet/src")
target_link_libraries(cnet_owner_original_test PRIVATE
  cnet_original_test_owner Salts::TinyTest)
if(WIN32)
  target_link_libraries(cnet_owner_original_test PRIVATE ws2_32)
endif()
add_test(NAME saltscore.cnet_owner_original
  COMMAND cnet_owner_original_test)
set_tests_properties(saltscore.cnet_owner_original PROPERTIES TIMEOUT 180)

# Issue #64: test exactly one original numeric-host resolve -> IOCP OPEN case.
# The CMake script enforces BOTH process exit status and TinyTest case counts.
# PASS_REGULAR_EXPRESSION is forbidden: it masks a nonzero process exit.
if(WIN32)
  add_test(NAME saltscore.cnet_owner_original_numeric_host
    COMMAND "${CMAKE_COMMAND}"
      "-DCNET_NUMERIC_HOST_COMMAND=$<TARGET_FILE:cnet_owner_original_test>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/verify_numeric_host_case.cmake")
  set_tests_properties(saltscore.cnet_owner_original_numeric_host
    PROPERTIES TIMEOUT 15)

  # The negative contract catches the historical false-green case: a test
  # prints the matching case name and success-looking summary but exits 1.
  add_test(NAME saltscore.cnet_owner_numeric_host_gate_contract
    COMMAND "${CMAKE_COMMAND}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/numeric_host_gate_contract.cmake")
  set_tests_properties(saltscore.cnet_owner_numeric_host_gate_contract
    PROPERTIES TIMEOUT 15)
endif()
