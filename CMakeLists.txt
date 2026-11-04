cmake_minimum_required(VERSION 3.20)
include(CMakeOptions.cmake)
project(SaltsCore VERSION 0.1.2 LANGUAGES C)
# Pre-stable ABI epoch: 0.2 must not silently satisfy an installed 0.1 DLL/DSO.
set(SALTSCORE_NATIVE_SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")

# All test executables and runtime DLLs share a directory on multi-config Windows.
# This is DLL discovery, not a copy of the runtime or a static fallback.
if(WIN32)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
  # Keep the published DLL identity independent of the selected LLVM driver.
  # llvm-mingw otherwise adds a Unix-style `lib` prefix that differs from the
  # MSVC ABI name and from the fail-closed installed-owner audit.
  set(CMAKE_SHARED_LIBRARY_PREFIX "")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
include(cmake/Sanitizers.cmake)
if(SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS AND NOT BUILD_TESTING)
  message(FATAL_ERROR "TLS measurements require BUILD_TESTING=ON")
endif()
if(SALTSCORE_CNET_TLS_MIXED_HEAPTRACK)
  if(NOT SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "TLS heaptrack requires Linux and SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS=ON")
  endif()
  if(SALTSCORE_ENABLE_ASAN OR SALTSCORE_ENABLE_UBSAN OR SALTSCORE_ENABLE_TSAN)
    message(FATAL_ERROR "TLS heaptrack uses the native unsanitized graph")
  endif()
endif()
if(SALTSCORE_GMSSL_COPY_PROFILE)
  if(NOT BUILD_TESTING OR NOT SALTSCORE_BUILD_CNET OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux"
      OR NOT VCPKG_TARGET_TRIPLET STREQUAL "salts-gmssl-copy-x64-linux")
    message(FATAL_ERROR "GmSSL copy profiling requires Linux tests, CNet and the salts-gmssl-copy-x64-linux triplet")
  endif()
  if(SALTSCORE_ENABLE_ASAN OR SALTSCORE_ENABLE_UBSAN OR SALTSCORE_ENABLE_TSAN
      OR SALTSCORE_CNET_TLS_MIXED_HEAPTRACK)
    message(FATAL_ERROR "GmSSL copy profiling uses a separate unsanitized, non-heaptrack graph")
  endif()
elseif(VCPKG_TARGET_TRIPLET STREQUAL "salts-gmssl-copy-x64-linux")
  message(FATAL_ERROR "The diagnostic GmSSL triplet requires SALTSCORE_GMSSL_COPY_PROFILE=ON")
endif()
if(SALTSCORE_CNET_TLS_MIXED_PERF)
  if(NOT SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "TLS perf requires Linux and SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS=ON")
  endif()
  if(SALTSCORE_ENABLE_ASAN OR SALTSCORE_ENABLE_UBSAN OR SALTSCORE_ENABLE_TSAN
      OR SALTSCORE_CNET_TLS_MIXED_HEAPTRACK OR SALTSCORE_GMSSL_COPY_PROFILE)
    message(FATAL_ERROR "TLS perf uses a separate unsanitized graph without heaptrack/copy instrumentation")
  endif()
endif()
# Crypto's C++17 header tests are siblings of the other Core source tests.
# Enable the language at the package root so all test subdirectories see it.
if(BUILD_TESTING)
  enable_language(CXX)
endif()
find_package(Threads REQUIRED)

# TinyTest is the canonical native C11/C++17 test framework.
# Make it available before source-owned module test declarations.
if(BUILD_TESTING AND NOT SALTSCORE_BUILD_TINYTEST)
  message(FATAL_ERROR "BUILD_TESTING=ON requires SALTSCORE_BUILD_TINYTEST=ON")
endif()
if(SALTSCORE_BUILD_TINYTEST)
  add_subdirectory(tinytest)
endif()

# Package root assembles canonical modules; modules own sources and installs.
# Original logging uses existing FS and Concurrency implementations;
# compile those single owners first, without a second logger provider.
add_subdirectory(platform)
add_subdirectory(concurrency)
add_subdirectory(fs)
add_subdirectory(core)
add_subdirectory(coroutine)
add_subdirectory(native-io)
# Original formal concurrency/ownership models, source-owned and retained.
add_subdirectory(verification)

# ASN1 is an always-assembled, first-party, provider-neutral codec.
# Never import a second ASN1 implementation or an external source repository.
if(TARGET Salts::ASN1)
  message(FATAL_ERROR "Duplicate ASN1 owner: never import and build twice")
endif()
add_subdirectory(asn1)

# ASN1, Crypto, URI and CNet are fixed local modules of the Core SDK.
# Retired inputs are errors so an old OFF or foreign prefix cannot silently
# select a different dependency graph.
if(DEFINED SALTSCORE_BUILD_CNET AND NOT SALTSCORE_BUILD_CNET)
  message(FATAL_ERROR "SALTSCORE_BUILD_CNET=OFF was removed; Core builds local Crypto and CNet unconditionally")
endif()
if(DEFINED CRYPTO_GMSSL_ROOT OR DEFINED SALTSCORE_CNET_STATIC_CRYPTO_ORIGINAL_OWNER_TEST)
  message(FATAL_ERROR "External or test-only Crypto owner inputs were removed")
endif()
if(TARGET Salts::Crypto)
  message(FATAL_ERROR "Duplicate Crypto owner: use exactly one static archive")
endif()
# Imported CMake targets are directory-scoped unless made GLOBAL. Both the
# sibling crypto/ and cnet/ modules consume this exact vcpkg static provider.
# Resolve it at the common parent so they see the *same* GmSSL::GmSSL target.
find_package(GmSSL CONFIG REQUIRED)
if(NOT TARGET GmSSL::GmSSL)
  message(FATAL_ERROR "Canonical vcpkg GmSSL::GmSSL import is required")
endif()
add_subdirectory(crypto)
# Keep explicit URI=ON callers compatible; disabling a mandatory dependency
# must fail rather than omit source or silently change parsing behavior.
if(DEFINED SALTSCORE_BUILD_URI AND NOT SALTSCORE_BUILD_URI)
  message(FATAL_ERROR "Core CNet requires its local URI parser")
endif()
add_subdirectory(uri)
add_subdirectory(vendor)
add_subdirectory(cnet)

option(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION
  "Run additional test-only Crypto facade and original Owner qualification" OFF)
if(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION AND NOT BUILD_TESTING)
  message(FATAL_ERROR "Crypto facade qualification requires BUILD_TESTING")
endif()

if(SALTSCORE_BUILD_CSERDE)
  add_subdirectory(cserde)
endif()
if(SALTSCORE_BUILD_USB)
  add_subdirectory(usb)
endif()
if(SALTSCORE_BUILD_SERIAL)
  add_subdirectory(serial)
endif()
if(DEFINED SALTSCORE_BUILD_CAPTURE OR DEFINED SALTSCORE_BUILD_PLAYBACK)
  message(FATAL_ERROR "Retired Capture/Playback switches: select SALTSCORE_BUILD_MEDIA")
endif()
if(SALTSCORE_BUILD_MEDIA)
  add_subdirectory(media)
endif()
if(SALTSCORE_BUILD_IDNA AND NOT SALTSCORE_BUILD_UNICODE)
  message(FATAL_ERROR "Salts::IDNA requires explicit SALTSCORE_BUILD_UNICODE=ON")
endif()
if(SALTSCORE_BUILD_UNICODE)
  add_subdirectory(unicode)
endif()
if(SALTSCORE_BUILD_IDNA)
  add_subdirectory(idna)
endif()
# Salts::FS is an unconditional Core logger dependency, not a fallback.
# A caller cannot silently disable the real file sink while preserving TLog.
if(DEFINED SALTSCORE_BUILD_FS AND NOT SALTSCORE_BUILD_FS)
  message(FATAL_ERROR "Restored Core/TLog requires canonical Salts::FS")
endif()
if(SALTSCORE_BUILD_PROCESS)
  add_subdirectory(process)
endif()

if(SALTSCORE_CNET_OWNER_SOURCE_TESTS)
  if(NOT BUILD_TESTING OR NOT SALTSCORE_BUILD_TINYTEST OR
     NOT TARGET Salts::TinyTest)
    message(FATAL_ERROR
      "CNet original source tests require BUILD_TESTING and Core TinyTest")
  endif()
  add_subdirectory(tests/cnet-owner)
endif()
if(SALTSCORE_BUILD_SCTP)
  add_subdirectory(sctp)
endif()

# Package config/version and export assembly are global concerns.
set(_saltscore_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/SaltsCore")
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SaltsCoreConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfig.cmake"
  INSTALL_DESTINATION "${_saltscore_package_dir}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfigVersion.cmake"
  DESTINATION "${_saltscore_package_dir}")
install(EXPORT SaltsCoreTargets FILE SaltsCoreTargets.cmake
  NAMESPACE Salts:: DESTINATION "${_saltscore_package_dir}")

if(BUILD_TESTING)
  # TinyTest is already required at the package root; never silently omit
  # real native modules or framework regression coverage.
  add_subdirectory(tests)
  add_subdirectory(concurrency/tests)
  add_subdirectory(tests/native-modules)
endif()
