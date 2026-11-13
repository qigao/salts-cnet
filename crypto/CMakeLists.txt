# One Crypto API archive links the pinned vcpkg GmSSL static dependency.
# GmSSL native C/H sources belong to the external package, not a local mirror.
# Original Ed448 libecc sources remain private first-party objects.
# The SaltsCNet root owns package discovery, language setup and SDK exports.
set(_salts_crypto_source_dir "${CMAKE_CURRENT_SOURCE_DIR}")
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ed448 libecc source uses the reviewed 64-bit WORDSIZE ABI")
endif()

set(_libecc "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libecc")
# Compile libecc's reviewed Ed448 subset in its own internal OBJECT target.
# Fold these objects directly into the sole installed Salts::Crypto archive.
add_subdirectory(vendor/libecc)

# No separate libecc archive; only its required Ed448 code is compiled.
# SHA256 is the pinned local native implementation, not a duplicate libecc SHA.
# Generic ASN.1 BER/DER comes solely from the sibling Salts::ASN1 owner.
# Crypto retains only ECDSA DER and RFC 8410 key-format functions.
cmake_add_source(crypto_sources DIRS src src/asn1 include/crypto
  EXCLUDES src/crypto_gmssl_copy_test.c)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${crypto_sources})
add_library(salts_crypto STATIC ${crypto_sources}
  $<TARGET_OBJECTS:crypto_libecc_ed448_objects>)
cmake_config_target(salts_crypto ALIAS Salts::Crypto FOLDER "crypto"
  EXPORT_NAME Crypto)
set_target_properties(salts_crypto PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_compile_features(salts_crypto PUBLIC c_std_11)
target_link_libraries(salts_crypto PUBLIC Threads::Threads Salts::ASN1
  PRIVATE GmSSL::GmSSL)
target_include_directories(salts_crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE "${_libecc}/include")
target_compile_definitions(salts_crypto PRIVATE
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1
  ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
if(BUILD_TESTS)
  target_compile_definitions(salts_crypto PRIVATE CRYPTO_TLS_STREAM_TESTING)
endif()

# Keep the Ed448 facade's configuration consistent with the private object
# target. No SHA256/SM3 libecc implementation or alternate RNG is built.
set_source_files_properties(src/crypto_ed448.c
  PROPERTIES COMPILE_DEFINITIONS
  "WITH_STDLIB;WITH_LIBECC_CONFIG_OVERRIDE;WITH_CURVE_WEI448;WITH_HASH_SHAKE256;WITH_SIG_EDDSA448;WORDSIZE=64")

if(MSVC)
  target_compile_options(salts_crypto PRIVATE /experimental:c11atomics)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32 crypt32)
elseif(WIN32)
  target_link_libraries(salts_crypto PUBLIC bcrypt ws2_32 crypt32)
elseif(APPLE)
  target_link_libraries(salts_crypto PUBLIC "-framework Security" "-framework CoreFoundation")
elseif(UNIX)
  target_link_libraries(salts_crypto PUBLIC m "${CMAKE_DL_LIBS}")
endif()

# GmSSL's vcpkg archive is an explicit imported, transitive dependency.
# Never duplicate its implementation objects into Salts::Crypto.

install(TARGETS salts_crypto EXPORT SaltsCNetTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/crypto
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h")
# GmSSL headers and Apache-2.0 copyright are owned by its pinned vcpkg SDK;
# do not install a second private copy into the Salts::Crypto SDK.
install(FILES "${_libecc}/LICENSE"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Crypto/libecc)

if(BUILD_TESTS)
  add_subdirectory(tests/tls)
  add_subdirectory(tests/algorithms)
  add_subdirectory(tests/asn1)
  add_subdirectory(tests/x509)
endif()
