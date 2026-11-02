cmake_minimum_required(VERSION 3.21)
project(SaltsCrypto VERSION 0.1.0 LANGUAGES C)

# One Crypto API archive links the pinned vcpkg GmSSL static dependency.
# GmSSL native C/H sources belong to the external package, not a local mirror.
# Original Ed448 libecc sources remain private first-party objects.
if(DEFINED CRYPTO_GMSSL_ROOT)
  message(FATAL_ERROR "CRYPTO_GMSSL_ROOT was removed; Crypto imports pinned vcpkg GmSSL::GmSSL")
endif()
if(TARGET gmssl OR TARGET salts_crypto)
  message(FATAL_ERROR "Duplicate in-tree Crypto/GmSSL implementation")
endif()
find_package(GmSSL CONFIG REQUIRED)
if(NOT TARGET GmSSL::GmSSL)
  message(FATAL_ERROR "Pinned vcpkg GmSSL target not available")
endif()
get_target_property(_crypto_native_include GmSSL::GmSSL INTERFACE_INCLUDE_DIRECTORIES)
if(NOT _crypto_native_include OR
    NOT EXISTS "${_crypto_native_include}/gmssl/tls.h")
  message(FATAL_ERROR "Pinned vcpkg GmSSL TLS headers unavailable")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ed448 libecc source uses the reviewed 64-bit WORDSIZE ABI")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
find_package(Threads REQUIRED)
# The parent project owns ASN1 first; standalone Crypto consumes its installed SDK.
if(NOT TARGET Salts::ASN1)
  find_package(ASN1 0.1 CONFIG REQUIRED)
endif()
if(NOT TARGET Salts::ASN1)
  message(FATAL_ERROR "Crypto requires canonical Salts::ASN1")
endif()

set(_libecc "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libecc")
# Compile libecc's reviewed Ed448 subset in its own internal OBJECT target.
# Fold these objects directly into the sole installed Salts::Crypto archive.
add_subdirectory(vendor/libecc)

# No separate libecc archive; only its required Ed448 code is compiled.
# SHA256 is the pinned local native implementation, not a duplicate libecc SHA.
# Generic ASN.1 BER/DER now comes solely from imported Salts::ASN1.
# Crypto retains only ECDSA DER and RFC 8410 key-format functions.
add_library(salts_crypto STATIC
  src/crypto_tls_gmssl.c
  src/crypto_tls_cipher_bio.c
  src/crypto_ed448.c
  src/crypto_sha256.c
  src/crypto_random.c
  src/asn1/crypto.c
  src/crypto_x509_der.c
  $<TARGET_OBJECTS:crypto_libecc_ed448_objects>)
add_library(Salts::Crypto ALIAS salts_crypto)
set_target_properties(salts_crypto PROPERTIES
  OUTPUT_NAME salts_crypto EXPORT_NAME Crypto
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_compile_features(salts_crypto PUBLIC c_std_11)
target_link_libraries(salts_crypto PUBLIC Threads::Threads Salts::ASN1
  PRIVATE GmSSL::GmSSL)
target_include_directories(salts_crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE "${_crypto_native_include}"
          "${_libecc}/include")
target_compile_definitions(salts_crypto PRIVATE
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1
  ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
# Private, metadata-only TLS handshake trace for test failure localization.
# NEVER built into normal SDK/release; no transcript, cert or secrets emitted.
option(CRYPTO_TLS_TEST_HANDSHAKE_DIAGNOSTICS
  "Enable metadata-only TLS handshake state trace in isolated test jobs" OFF)
if(BUILD_TESTING AND CRYPTO_TLS_TEST_HANDSHAKE_DIAGNOSTICS)
  target_compile_definitions(salts_crypto PRIVATE
    CRYPTO_TLS_PRIVATE_TEST_HANDSHAKE_TRACE)
endif()

# Keep the Ed448 facade's configuration consistent with the private object
# target. No SHA256/SM3 libecc implementation or alternate RNG is built.
set_source_files_properties(src/crypto_ed448.c
  PROPERTIES COMPILE_DEFINITIONS
  "WITH_STDLIB;WITH_LIBECC_CONFIG_OVERRIDE;WITH_CURVE_WEI448;WITH_HASH_SHAKE256;WITH_SIG_EDDSA448;WORDSIZE=64")

if(MSVC)
  target_compile_options(salts_crypto PRIVATE /experimental:c11atomics)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32)
elseif(WIN32)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32)
elseif(APPLE)
  target_link_libraries(salts_crypto PUBLIC "-framework Security")
elseif(UNIX)
  target_link_libraries(salts_crypto PUBLIC m "${CMAKE_DL_LIBS}")
endif()

# GmSSL's vcpkg archive is an explicit imported, transitive dependency.
# Never duplicate its implementation objects into Salts::Crypto.

install(TARGETS salts_crypto EXPORT SaltsCryptoTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/crypto
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h")
# GmSSL headers and Apache-2.0 copyright are owned by its pinned vcpkg SDK;
# do not install a second private copy into the Salts::Crypto SDK.
install(FILES "${_libecc}/LICENSE"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Crypto/libecc)

set(_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/Crypto")
install(EXPORT SaltsCryptoTargets FILE CryptoTargets.cmake
  NAMESPACE Salts:: DESTINATION "${_package_dir}")
configure_package_config_file(cmake/CryptoConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  INSTALL_DESTINATION "${_package_dir}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake"
  DESTINATION "${_package_dir}")

if(BUILD_TESTING)
  enable_language(CXX)
  add_subdirectory(tests/algorithms)
  add_subdirectory(tests/asn1)
  add_subdirectory(tests/x509)
endif()
