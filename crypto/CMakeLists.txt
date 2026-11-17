# One shared Crypto library privately links its selected static backend. GmSSL
# native C/H sources belong to the external package, not a local mirror.
# Vendored curve/signature sources remain private implementation objects. The
# SaltsCNet root owns package discovery, language setup and SDK exports.
set(_salts_crypto_source_dir "${CMAKE_CURRENT_SOURCE_DIR}")
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(
    FATAL_ERROR "Ed448 libecc source uses the reviewed 64-bit WORDSIZE ABI")
endif()

set(_libecc "${PROJECT_SOURCE_DIR}/vendor/libecc")
# The vendored curve/signature archive is a private link dependency.

# Native backend contexts remain inside Crypto. Public key imports copy into
# immutable opaque handles; hash/AES/signature operations borrow call buffers.
cmake_add_source(
  crypto_sources
  DIRS
  src
  src/asn1
  include/crypto
  EXCLUDES
  src/crypto_gmssl_copy_test.c)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${crypto_sources})
add_library(salts_crypto SHARED ${crypto_sources})
cmake_config_target(
  salts_crypto
  ALIAS
  Salts::Crypto
  FOLDER
  "crypto"
  EXPORT_NAME
  Crypto)
set_target_properties(salts_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON
                                              C_VISIBILITY_PRESET default)
target_compile_features(salts_crypto PUBLIC c_std_11)
target_link_libraries(salts_crypto
  PUBLIC Threads::Threads Salts::ASN1
  PRIVATE GmSSL::GmSSL crypto_libecc)
cmake_export_symbols(salts_crypto crypto_ salts_crypto_)

target_include_directories(
  salts_crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE "${_libecc}/include")
target_compile_definitions(
  salts_crypto PRIVATE ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1
                       ENABLE_SHA2 ENABLE_AES)
if(BUILD_TESTS)
  target_compile_definitions(salts_crypto PRIVATE CRYPTO_TLS_STREAM_TESTING)
endif()

# Match the archive's structure layout, curve set and private hash symbols.
set_source_files_properties(
  src/crypto_ed448.c src/crypto_ed25519.c src/crypto_ecdsa.c
  PROPERTIES COMPILE_DEFINITIONS "$<TARGET_PROPERTY:crypto_libecc,COMPILE_DEFINITIONS>")

if(MSVC)
  target_compile_options(salts_crypto PRIVATE /experimental:c11atomics)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32 crypt32)
elseif(WIN32)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32 crypt32)
elseif(APPLE)
  target_link_libraries(salts_crypto PUBLIC "-framework Security"
                                            "-framework CoreFoundation")
elseif(UNIX)
  target_link_libraries(salts_crypto PUBLIC m "${CMAKE_DL_LIBS}")
endif()

# The SDK exports no provider target or separate backend archive.

install(
  TARGETS salts_crypto
  EXPORT SaltsCNetTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(
  DIRECTORY include/crypto
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING
  PATTERN "*.h")
# GmSSL headers and Apache-2.0 copyright are owned by its pinned vcpkg SDK; do
# not install a second private copy into the Salts::Crypto SDK.
install(FILES "${_libecc}/LICENSE"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Crypto/libecc)
install(FILES "${SALTS_DEPENDENCY_PREFIX}/share/gmssl/copyright"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Crypto/gmssl)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
