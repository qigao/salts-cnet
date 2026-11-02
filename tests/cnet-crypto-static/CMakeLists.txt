# SPDX-License-Identifier: Apache-2.0
# Test-only original real CNet Owner in ONE executable, no second static Crypto.
option(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION
  "Run test-only CNet qualification through the bounded Crypto facade" OFF)
if(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION)
  if(NOT BUILD_TESTING OR NOT TARGET saltscore_cnet)
    message(FATAL_ERROR "CNet Crypto qualification requires BUILD_TESTING and the actual CNet graph")
  endif()
  if(NOT TARGET Salts::TinyTest)
    message(FATAL_ERROR "CNet Crypto native tests require canonical Salts::TinyTest")
  endif()
  if(NOT DEFINED SALTSCORE_CRYPTO_TEST_FIXTURES)
    message(FATAL_ERROR "Exact pinned static Crypto TLS fixtures required")
  endif()
  # M5 must use this exact source tree, not find_package(Crypto) or
  # imported qigao/crypto ASN1. Salts::CNet is built separately for parity,
  # but the candidate image links only this local static Crypto owner.
  find_package(c-ares CONFIG REQUIRED)
  find_package(kcp CONFIG REQUIRED)
  if(APPLE)
    find_library(SALTSCORE_CNET_COREFOUNDATION CoreFoundation REQUIRED)
    find_library(SALTSCORE_CNET_SECURITY Security REQUIRED)
  endif()
  if(NOT TARGET salts_asn1 OR NOT TARGET Salts::ASN1 OR
     NOT TARGET salts_crypto OR NOT TARGET Salts::Crypto)
    message(FATAL_ERROR "M5 requires one local Salts::ASN1 and Salts::Crypto target")
  endif()
  get_target_property(_asn1_alias Salts::ASN1 ALIASED_TARGET)
  get_target_property(_crypto_alias Salts::Crypto ALIASED_TARGET)
  get_target_property(_asn1_type salts_asn1 TYPE)
  get_target_property(_static_kind salts_crypto TYPE)
  get_target_property(_asn1_imported salts_asn1 IMPORTED)
  get_target_property(_static_imported salts_crypto IMPORTED)
  if(NOT _asn1_alias STREQUAL "salts_asn1" OR
     NOT _crypto_alias STREQUAL "salts_crypto" OR
     NOT _asn1_type STREQUAL "STATIC_LIBRARY" OR
     NOT _static_kind STREQUAL "STATIC_LIBRARY" OR
     _asn1_imported OR _static_imported)
    message(FATAL_ERROR "M5 requires precisely one local, non-imported STATIC ASN1/Crypto graph")
  endif()
  foreach(_forbidden IN ITEMS
      Salts::TLS Salts::TLSCipherBIO Salts::CryptoProvider
      Crypto::TLS Crypto::TLSCipherBIO Crypto::Provider)
    if(TARGET ${_forbidden})
      message(FATAL_ERROR "Second native Crypto owner forbidden: ${_forbidden}")
    endif()
  endforeach()
  set(_static_owner_sources ${_saltscore_cnet_sources})
  list(FIND _static_owner_sources cnet/src/cnet_tls.c _old_tls_index)
  list(FIND _static_owner_sources cnet/src/cnet_owner.c _original_owner_index)
  if(_old_tls_index LESS 0 OR _original_owner_index LESS 0)
    message(FATAL_ERROR "Canonical original CNet Owner/TLS source unavailable")
  endif()
  list(REMOVE_ITEM _static_owner_sources cnet/src/cnet_tls.c)
  list(APPEND _static_owner_sources
    cnet/src/cnet_tls_crypto_qualification.c
    tests/cnet-crypto-static/cnet_crypto_owner_admission.c
    tests/cnet-crypto-static/public_context.c
    tests/cnet-crypto-static/owner.c)

  # Source parity: original relative CNet manifest, never local test paths.
  set(_static_owner_abs_sources)
  foreach(_unit IN LISTS _static_owner_sources)
    if(_unit MATCHES "^\\$<TARGET_OBJECTS:")
      list(APPEND _static_owner_abs_sources "${_unit}")
    else()
      list(APPEND _static_owner_abs_sources "${PROJECT_SOURCE_DIR}/${_unit}")
    endif()
  endforeach()
  set(_static_owner_sources ${_static_owner_abs_sources})
  foreach(_fixture IN ITEMS
      external-io-ca-cert.pem external-io-server-cert.pem
      external-io-server-key.pem)
    if(NOT EXISTS "${SALTSCORE_CRYPTO_TEST_FIXTURES}/${_fixture}")
      message(FATAL_ERROR "Missing pinned Crypto TLS fixture: ${_fixture}")
    endif()
  endforeach()
  file(TO_CMAKE_PATH "${SALTSCORE_CRYPTO_TEST_FIXTURES}" _owner_fixtures)
  # The original CNet private Owner is also built into the M6 shared image.
  # Rename only its CLI entry symbol; never add a TinyTest main to the DSO.
  set_source_files_properties(
    "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/owner.c"
    PROPERTIES COMPILE_DEFINITIONS
      "main=saltscore_cnet_crypto_legacy_main")
  add_executable(saltscore_cnet_crypto_static_original_owner
    ${_static_owner_sources}
    "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/owner_tinytest.c")
  target_compile_features(saltscore_cnet_crypto_static_original_owner
    PRIVATE c_std_11)
  set_target_properties(saltscore_cnet_crypto_static_original_owner PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(saltscore_cnet_crypto_static_original_owner PRIVATE
    "${PROJECT_SOURCE_DIR}/cnet/include"
    "${PROJECT_SOURCE_DIR}/cnet/src"
    "${PROJECT_SOURCE_DIR}/cnet/src/wsparser"
    "${PROJECT_SOURCE_DIR}/native-io/src"
    "${PROJECT_SOURCE_DIR}/vendor/monocypher"
    "${PROJECT_SOURCE_DIR}/vendor/reed"
    "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static")
  target_compile_definitions(saltscore_cnet_crypto_static_original_owner PRIVATE
    "SDK_CA_FILE=\"${_owner_fixtures}/external-io-ca-cert.pem\""
    "SDK_SERVER_CERT_FILE=\"${_owner_fixtures}/external-io-server-cert.pem\""
    "SDK_SERVER_KEY_FILE=\"${_owner_fixtures}/external-io-server-key.pem\"")
  target_link_libraries(saltscore_cnet_crypto_static_original_owner PRIVATE
    Salts::Core Salts::NativeIO Salts::Concurrency
    Salts::URI Salts::Platform Salts::Crypto Salts::TinyTest
    saltscore_cnet_monocypher saltscore_cnet_reed
    c-ares::cares kcp::kcp
    $<$<PLATFORM_ID:Windows>:crypt32>)
  # Original CNet resolver uses POSIX strnlen. Preserve strict C11 and
  # explicit system feature admission, never suppress implicit prototypes.
  if(APPLE)
    target_compile_definitions(saltscore_cnet_crypto_static_original_owner
      PRIVATE _DARWIN_C_SOURCE=1)
  elseif(UNIX)
    target_compile_definitions(saltscore_cnet_crypto_static_original_owner
      PRIVATE _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L)
  endif()
  # Production Salts::CNet is NOT linked here. This remains a separate
  # qualification image with narrower facade admission and behavior.
  if(APPLE)
    target_link_libraries(saltscore_cnet_crypto_static_original_owner PRIVATE
      "${SALTSCORE_CNET_COREFOUNDATION}"
      "${SALTSCORE_CNET_SECURITY}")
  endif()
  if(MSVC)
    target_compile_options(saltscore_cnet_crypto_static_original_owner
      PRIVATE /experimental:c11atomics)
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(saltscore_cnet_crypto_static_original_owner PRIVATE
      -Werror=implicit-function-declaration
      -Werror=incompatible-pointer-types -Werror=return-type)
  endif()
  add_test(NAME saltscore.cnet_crypto_static_original_owner_tls12_tls13
    COMMAND saltscore_cnet_crypto_static_original_owner)
  set_tests_properties(saltscore.cnet_crypto_static_original_owner_tls12_tls13
    PROPERTIES TIMEOUT 120)

  # M5: real original CNet epoll/kqueue/IOCP Owner, not an adapter-only
  # socket. TLS12/TLS13 REQUIRED mTLS uses exact-head Crypto Python X.509
  # fixtures and a single physical static Crypto instance in the process.
  option(SALTSCORE_CNET_M5_PYTHON_MTLS_TEST
    "Run true original NativeIO Owner REQUIRED mTLS with Python cert fixtures" OFF)
  if(SALTSCORE_CNET_M5_PYTHON_MTLS_TEST)
    if(NOT SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE OR
        NOT EXISTS "${SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE}")
      message(FATAL_ERROR "Exact-head Crypto Python mTLS fixture module required")
    endif()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME saltscore.cnet_crypto_static_original_owner_python_mtls
      COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/python_original_owner_mtls.py"
        --binary "$<TARGET_FILE:saltscore_cnet_crypto_static_original_owner>"
        --crypto-python-fixtures "${SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE}"
        --work "${CMAKE_CURRENT_BINARY_DIR}/m5-private-python-fixtures")
    set_tests_properties(saltscore.cnet_crypto_static_original_owner_python_mtls
      PROPERTIES TIMEOUT 360 RESOURCE_LOCK cnet_m5_original_owner)
  endif()

  # True client SAN mismatch requires SNI-neutral independent Python ssl server:
  # pinned GmSSL refuses unrecognized SNI *on the server* first.
  option(SALTSCORE_CNET_STATIC_CRYPTO_OPENSSL_SAN_TEST
    "Qualify static CNet client DNS SAN against independent OpenSSL peer" OFF)
  if(SALTSCORE_CNET_STATIC_CRYPTO_OPENSSL_SAN_TEST)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    foreach(_protocol IN ITEMS tls12 tls13)
      add_test(NAME saltscore.cnet_crypto_static_python_san_${_protocol}
        COMMAND "${Python3_EXECUTABLE}"
          "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/external_san_peer.py"
          --binary "$<TARGET_FILE:saltscore_cnet_crypto_static_original_owner>"
          --cert "${_owner_fixtures}/external-io-server-cert.pem"
          --key "${_owner_fixtures}/external-io-server-key.pem"
          --protocol "${_protocol}")
      set_tests_properties(saltscore.cnet_crypto_static_python_san_${_protocol}
        PROPERTIES TIMEOUT 75)
    endforeach()
  endif()

  # M6: the original CNet Owner linked once as a TEST-ONLY SHARED image.
  # The sole Salts::Crypto STATIC archive belongs exclusively to that image.
  # Two independently loaded plugins refer to this image, not separate static
  # Crypto copies. Production Salts::CNet uses the complete original native
  # TLS implementation and is not linked into this qualification image.
  option(SALTSCORE_CNET_M6_SHARED_DSO_TEST
    "Qualify one physical STATIC Crypto owner across two CNet plugin DSOs" OFF)
  if(SALTSCORE_CNET_M6_SHARED_DSO_TEST)
    set(_m6_dso_sources ${_static_owner_sources})
    # Link the existing M5 original CNet handshake acceptance source into
    # the same shared candidate. CNET_M6_BUILD_SHARED excludes its CLI main.
    list(APPEND _m6_dso_sources
      "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/m6_shared_owner.c")
    add_library(saltscore_cnet_crypto_m6_shared SHARED ${_m6_dso_sources})
    target_compile_features(saltscore_cnet_crypto_m6_shared PUBLIC c_std_11)
    target_compile_definitions(saltscore_cnet_crypto_m6_shared
      PRIVATE CNET_M6_BUILD_SHARED=1)
    set_target_properties(saltscore_cnet_crypto_m6_shared PROPERTIES
      C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
      WINDOWS_EXPORT_ALL_SYMBOLS ON
      OUTPUT_NAME saltscore_cnet_m6_static_crypto)
    target_compile_definitions(saltscore_cnet_crypto_m6_shared PRIVATE
      "SDK_CA_FILE=\"${_owner_fixtures}/external-io-ca-cert.pem\""
      "SDK_SERVER_CERT_FILE=\"${_owner_fixtures}/external-io-server-cert.pem\""
      "SDK_SERVER_KEY_FILE=\"${_owner_fixtures}/external-io-server-key.pem\"")
    target_include_directories(saltscore_cnet_crypto_m6_shared
      PUBLIC
        "${PROJECT_SOURCE_DIR}/cnet/include"
      PRIVATE
        "${PROJECT_SOURCE_DIR}/cnet/src"
        "${PROJECT_SOURCE_DIR}/cnet/src/wsparser"
        "${PROJECT_SOURCE_DIR}/native-io/src"
        "${PROJECT_SOURCE_DIR}/vendor/monocypher"
        "${PROJECT_SOURCE_DIR}/vendor/reed"
        "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static")
    target_link_libraries(saltscore_cnet_crypto_m6_shared
      PUBLIC Salts::Core Salts::NativeIO Salts::Concurrency
      PRIVATE Salts::Crypto Salts::URI Salts::Platform
        saltscore_cnet_monocypher saltscore_cnet_reed
        c-ares::cares kcp::kcp
        $<$<PLATFORM_ID:Windows>:crypt32>)
    if(APPLE)
      target_compile_definitions(saltscore_cnet_crypto_m6_shared
        PRIVATE _DARWIN_C_SOURCE=1)
      target_link_libraries(saltscore_cnet_crypto_m6_shared PRIVATE
        "${SALTSCORE_CNET_COREFOUNDATION}"
        "${SALTSCORE_CNET_SECURITY}")
    elseif(UNIX)
      target_compile_definitions(saltscore_cnet_crypto_m6_shared
        PRIVATE _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L)
    endif()
    if(MSVC)
      target_compile_options(saltscore_cnet_crypto_m6_shared
        PRIVATE /experimental:c11atomics)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
      target_compile_options(saltscore_cnet_crypto_m6_shared PRIVATE
        -Werror=implicit-function-declaration
        -Werror=incompatible-pointer-types -Werror=return-type)
    endif()

    # Both plugin modules link the SHARED candidate, not Salts::Crypto.
    foreach(_module IN ITEMS a b)
      add_library(saltscore_cnet_m6_plugin_${_module} MODULE
        "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/m6_plugin.c")
      target_compile_features(saltscore_cnet_m6_plugin_${_module}
        PRIVATE c_std_11)
      set_target_properties(saltscore_cnet_m6_plugin_${_module} PROPERTIES
        C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        WINDOWS_EXPORT_ALL_SYMBOLS ON)
      target_include_directories(saltscore_cnet_m6_plugin_${_module} PRIVATE
        "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static")
      target_link_libraries(saltscore_cnet_m6_plugin_${_module}
        PRIVATE saltscore_cnet_crypto_m6_shared Salts::Core Salts::Platform)
      if(MSVC)
        target_compile_options(saltscore_cnet_m6_plugin_${_module}
          PRIVATE /experimental:c11atomics)
      endif()
    endforeach()

    # The loader never links Salts::CNet nor Salts::Crypto, and must
    # unload plugin A while a Provider lease from A is still outstanding.
    set_source_files_properties(
      "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/m6_loader.c"
      PROPERTIES COMPILE_DEFINITIONS "main=saltscore_cnet_m6_legacy_main")
    add_executable(saltscore_cnet_m6_two_plugin_loader
      "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/m6_loader.c"
      "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/m6_loader_tinytest.c")
    target_compile_features(saltscore_cnet_m6_two_plugin_loader
      PRIVATE c_std_11)
    set_target_properties(saltscore_cnet_m6_two_plugin_loader PROPERTIES
      C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_include_directories(saltscore_cnet_m6_two_plugin_loader PRIVATE
      "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static")
    target_link_libraries(saltscore_cnet_m6_two_plugin_loader PRIVATE
      Salts::Core Salts::Platform Salts::TinyTest ${CMAKE_DL_LIBS})
    add_dependencies(saltscore_cnet_m6_two_plugin_loader
      saltscore_cnet_m6_plugin_a saltscore_cnet_m6_plugin_b)
    if(MSVC)
      target_compile_options(saltscore_cnet_m6_two_plugin_loader
        PRIVATE /experimental:c11atomics)
    endif()
    add_test(NAME saltscore.cnet_crypto_m6_two_plugin_shared_owner
      COMMAND saltscore_cnet_m6_two_plugin_loader
        "$<TARGET_FILE:saltscore_cnet_m6_plugin_a>"
        "$<TARGET_FILE:saltscore_cnet_m6_plugin_b>")
    set_tests_properties(saltscore.cnet_crypto_m6_two_plugin_shared_owner
      PROPERTIES TIMEOUT 120 RESOURCE_LOCK cnet_m6_shared_owner)

    option(SALTSCORE_CNET_M6_CONCURRENT_MTLS_TEST
      "Run real parallel CNet TLS1.2/1.3 from two plugins and ONE Crypto DSO" OFF)
    if(SALTSCORE_CNET_M6_CONCURRENT_MTLS_TEST)
      if(NOT SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE OR
          NOT EXISTS "${SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE}")
        message(FATAL_ERROR "M6 needs exact-head Crypto Python certificate fixture source")
      endif()
      find_package(Python3 COMPONENTS Interpreter REQUIRED)
      add_test(NAME saltscore.cnet_crypto_m6_two_plugin_concurrent_mtls
        COMMAND "${Python3_EXECUTABLE}"
          "${PROJECT_SOURCE_DIR}/tests/cnet-crypto-static/python_m6_two_plugin_mtls.py"
          --loader "$<TARGET_FILE:saltscore_cnet_m6_two_plugin_loader>"
          --plugin-a "$<TARGET_FILE:saltscore_cnet_m6_plugin_a>"
          --plugin-b "$<TARGET_FILE:saltscore_cnet_m6_plugin_b>"
          --crypto-python-fixtures "${SALTSCORE_CRYPTO_PYTHON_FIXTURE_SOURCE}"
          --work "${CMAKE_CURRENT_BINARY_DIR}/m6-private-concurrent-fixtures")
      set_tests_properties(saltscore.cnet_crypto_m6_two_plugin_concurrent_mtls
        PROPERTIES TIMEOUT 480 RESOURCE_LOCK cnet_m6_shared_owner)
    endif()
  endif()

endif()
