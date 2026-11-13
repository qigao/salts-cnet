# SPDX-License-Identifier: Apache-2.0
# Test-only original real CNet Owner in ONE executable, no second static Crypto.
# M5 must use this exact source tree, not find_package(Crypto) or
# imported qigao/crypto ASN1. Salts::CNet is built separately for parity,
# but the candidate image links only this local static Crypto owner.
if(APPLE)
  find_library(cnet_COREFOUNDATION CoreFoundation REQUIRED)
  find_library(cnet_SECURITY Security REQUIRED)
endif()
get_target_property(_static_owner_sources cnet SOURCES)
list(REMOVE_ITEM _static_owner_sources "${PROJECT_SOURCE_DIR}/cnet/src/cnet_tls.c")
list(APPEND _static_owner_sources
  "${PROJECT_SOURCE_DIR}/cnet/src/cnet_tls_crypto_qualification.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cnet_crypto_owner_admission.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/public_context.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/owner.c")
foreach(_fixture IN ITEMS
    external-io-ca-cert.pem external-io-server-cert.pem
    external-io-server-key.pem)
  if(NOT EXISTS "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures/${_fixture}")
    message(FATAL_ERROR "Missing pinned Crypto TLS fixture: ${_fixture}")
  endif()
endforeach()
file(TO_CMAKE_PATH "${PROJECT_SOURCE_DIR}/crypto/tests/fixtures" _owner_fixtures)
# The original CNet private Owner is also built into the M6 shared image.
# Rename only its CLI entry symbol; never add a TinyTest main to the DSO.
set_source_files_properties(
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/owner.c"
  PROPERTIES COMPILE_DEFINITIONS
    "main=cnet_crypto_legacy_main")
cmake_add_executable(cnet_crypto_static_original_owner SOURCES ${_static_owner_sources}
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/owner_tinytest.c"
  FOLDER "cnet/tests/crypto-static")
target_include_directories(cnet_crypto_static_original_owner PRIVATE
  "${PROJECT_SOURCE_DIR}/cnet/include"
  "${PROJECT_SOURCE_DIR}/cnet/src"
  "${PROJECT_SOURCE_DIR}/cnet/src/wsparser"
  "${PROJECT_SOURCE_DIR}/native-io/src"
  "${PROJECT_SOURCE_DIR}/vendor/monocypher"
  "${PROJECT_SOURCE_DIR}/vendor/reed"
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static")
target_compile_definitions(cnet_crypto_static_original_owner PRIVATE
  "SDK_CA_FILE=\"${_owner_fixtures}/external-io-ca-cert.pem\""
  "SDK_SERVER_CERT_FILE=\"${_owner_fixtures}/external-io-server-cert.pem\""
  "SDK_SERVER_KEY_FILE=\"${_owner_fixtures}/external-io-server-key.pem\"")
target_link_libraries(cnet_crypto_static_original_owner PRIVATE
  Salts::Core Salts::NativeIO Salts::Core
  Salts::URI Salts::Core Salts::Crypto Salts::TinyTest
  monocypher reed
  c-ares::cares kcp::kcp
  $<$<PLATFORM_ID:Windows>:crypt32>)
# Original CNet resolver uses POSIX strnlen. Preserve strict C11 and
# explicit system feature admission, never suppress implicit prototypes.
if(APPLE)
  target_compile_definitions(cnet_crypto_static_original_owner
    PRIVATE _DARWIN_C_SOURCE=1)
elseif(UNIX)
  target_compile_definitions(cnet_crypto_static_original_owner
    PRIVATE _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L)
endif()
# Production Salts::CNet is NOT linked here. This remains a separate
# qualification image with narrower facade admission and behavior.
if(APPLE)
  target_link_libraries(cnet_crypto_static_original_owner PRIVATE
    "${cnet_COREFOUNDATION}"
    "${cnet_SECURITY}")
endif()
if(MSVC)
  target_compile_options(cnet_crypto_static_original_owner
    PRIVATE /experimental:c11atomics)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(cnet_crypto_static_original_owner PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types -Werror=return-type)
endif()
add_test(NAME saltscore.cnet_crypto_static_original_owner_tls12_tls13
  COMMAND cnet_crypto_static_original_owner)
set_tests_properties(saltscore.cnet_crypto_static_original_owner_tls12_tls13
  PROPERTIES TIMEOUT 120)

# M5: real original CNet epoll/kqueue/IOCP Owner, not an adapter-only
# socket. TLS12/TLS13 REQUIRED mTLS uses exact-head Crypto Python X.509
# fixtures and a single physical static Crypto instance in the process.
add_test(NAME saltscore.cnet_crypto_static_original_owner_python_mtls
  COMMAND "${Python3_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/python_original_owner_mtls.py"
    --binary "$<TARGET_FILE:cnet_crypto_static_original_owner>"
    --crypto-python-fixtures "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
    --work "${CMAKE_CURRENT_BINARY_DIR}/m5-private-python-fixtures")
set_tests_properties(saltscore.cnet_crypto_static_original_owner_python_mtls
  PROPERTIES TIMEOUT 360 RESOURCE_LOCK cnet_m5_original_owner)

# True client SAN mismatch requires SNI-neutral independent Python ssl server:
# pinned GmSSL refuses unrecognized SNI *on the server* first.
foreach(_protocol IN ITEMS tls12 tls13)
  add_test(NAME saltscore.cnet_crypto_static_python_san_${_protocol}
    COMMAND "${Python3_EXECUTABLE}" -B
      "${CMAKE_CURRENT_SOURCE_DIR}/static_owner_san_peer.py"
      --binary "$<TARGET_FILE:cnet_crypto_static_original_owner>"
      --cert "${_owner_fixtures}/external-io-server-cert.pem"
      --key "${_owner_fixtures}/external-io-server-key.pem"
      --protocol "${_protocol}")
  set_tests_properties(saltscore.cnet_crypto_static_python_san_${_protocol}
    PROPERTIES TIMEOUT 75)
endforeach()

# M6: the original CNet Owner linked once as a TEST-ONLY SHARED image.
# The sole Salts::Crypto STATIC archive belongs exclusively to that image.
# Two independently loaded plugins refer to this image, not separate static
# Crypto copies. Production Salts::CNet uses the complete original native
# TLS implementation and is not linked into this qualification image.
set(_m6_dso_sources ${_static_owner_sources})
# Link the existing M5 original CNet handshake acceptance source into
# the same shared candidate. CNET_M6_BUILD_SHARED excludes its CLI main.
list(APPEND _m6_dso_sources
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/m6_shared_owner.c")
add_library(cnet_crypto_m6_shared SHARED ${_m6_dso_sources})
target_compile_features(cnet_crypto_m6_shared PUBLIC c_std_11)
target_compile_definitions(cnet_crypto_m6_shared
  PRIVATE CNET_M6_BUILD_SHARED=1)
set_target_properties(cnet_crypto_m6_shared PROPERTIES
  WINDOWS_EXPORT_ALL_SYMBOLS ON
  OUTPUT_NAME cnet_m6_static_crypto)
target_compile_definitions(cnet_crypto_m6_shared PRIVATE
  "SDK_CA_FILE=\"${_owner_fixtures}/external-io-ca-cert.pem\""
  "SDK_SERVER_CERT_FILE=\"${_owner_fixtures}/external-io-server-cert.pem\""
  "SDK_SERVER_KEY_FILE=\"${_owner_fixtures}/external-io-server-key.pem\"")
target_include_directories(cnet_crypto_m6_shared
  PUBLIC
    "${PROJECT_SOURCE_DIR}/cnet/include"
  PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/src"
    "${PROJECT_SOURCE_DIR}/cnet/src/wsparser"
    "${PROJECT_SOURCE_DIR}/native-io/src"
    "${PROJECT_SOURCE_DIR}/vendor/monocypher"
    "${PROJECT_SOURCE_DIR}/vendor/reed"
    "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static")
target_link_libraries(cnet_crypto_m6_shared
  PUBLIC Salts::Core Salts::NativeIO Salts::Core
  PRIVATE Salts::Crypto Salts::URI Salts::Core
    monocypher reed
    c-ares::cares kcp::kcp
    $<$<PLATFORM_ID:Windows>:crypt32>)
if(APPLE)
  target_compile_definitions(cnet_crypto_m6_shared
    PRIVATE _DARWIN_C_SOURCE=1)
  target_link_libraries(cnet_crypto_m6_shared PRIVATE
    "${cnet_COREFOUNDATION}"
    "${cnet_SECURITY}")
elseif(UNIX)
  target_compile_definitions(cnet_crypto_m6_shared
    PRIVATE _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L)
endif()
if(MSVC)
  target_compile_options(cnet_crypto_m6_shared
    PRIVATE /experimental:c11atomics)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(cnet_crypto_m6_shared PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types -Werror=return-type)
endif()

# Both plugin modules link the SHARED candidate, not Salts::Crypto.
foreach(_module IN ITEMS a b)
  add_library(cnet_m6_plugin_${_module} MODULE
    "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/m6_plugin.c")
  set_target_properties(cnet_m6_plugin_${_module} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
  target_include_directories(cnet_m6_plugin_${_module} PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static")
  target_link_libraries(cnet_m6_plugin_${_module}
    PRIVATE cnet_crypto_m6_shared Salts::Core)
  if(MSVC)
    target_compile_options(cnet_m6_plugin_${_module}
      PRIVATE /experimental:c11atomics)
  endif()
endforeach()

# The loader never links Salts::CNet nor Salts::Crypto, and must
# unload plugin A while a Provider lease from A is still outstanding.
set_source_files_properties(
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/m6_loader.c"
  PROPERTIES COMPILE_DEFINITIONS "main=cnet_m6_legacy_main")
cmake_add_executable(cnet_m6_two_plugin_loader SOURCES "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/m6_loader.c"
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/m6_loader_tinytest.c"
  FOLDER "cnet/tests/crypto-static")
target_include_directories(cnet_m6_two_plugin_loader PRIVATE
  "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static")
target_link_libraries(cnet_m6_two_plugin_loader PRIVATE
  Salts::Core Salts::TinyTest ${CMAKE_DL_LIBS})
add_dependencies(cnet_m6_two_plugin_loader
  cnet_m6_plugin_a cnet_m6_plugin_b)
if(MSVC)
  target_compile_options(cnet_m6_two_plugin_loader
    PRIVATE /experimental:c11atomics)
endif()
add_test(NAME saltscore.cnet_crypto_m6_two_plugin_shared_owner
  COMMAND cnet_m6_two_plugin_loader
    "$<TARGET_FILE:cnet_m6_plugin_a>"
    "$<TARGET_FILE:cnet_m6_plugin_b>")
set_tests_properties(saltscore.cnet_crypto_m6_two_plugin_shared_owner
  PROPERTIES TIMEOUT 120 RESOURCE_LOCK cnet_m6_shared_owner)

add_test(NAME saltscore.cnet_crypto_m6_two_plugin_concurrent_mtls
  COMMAND "${Python3_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/cnet/tests/crypto-static/python_m6_two_plugin_mtls.py"
    --loader "$<TARGET_FILE:cnet_m6_two_plugin_loader>"
    --plugin-a "$<TARGET_FILE:cnet_m6_plugin_a>"
    --plugin-b "$<TARGET_FILE:cnet_m6_plugin_b>"
    --crypto-python-fixtures "${PROJECT_SOURCE_DIR}/crypto/tests/sdk/python_mtls.py"
    --work "${CMAKE_CURRENT_BINARY_DIR}/m6-private-concurrent-fixtures")
set_tests_properties(saltscore.cnet_crypto_m6_two_plugin_concurrent_mtls
  PROPERTIES TIMEOUT 480 RESOURCE_LOCK cnet_m6_shared_owner)
