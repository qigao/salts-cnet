include("$ENV{VCPKG_ROOT}/triplets/x64-linux.cmake")
list(APPEND VCPKG_HASH_ADDITIONAL_FILES "$ENV{VCPKG_ROOT}/triplets/x64-linux.cmake")
if(PORT STREQUAL "gmssl")
  list(APPEND VCPKG_HASH_ADDITIONAL_FILES
    "${CMAKE_CURRENT_LIST_DIR}/../instrument-gmssl.cmake"
    "${CMAKE_CURRENT_LIST_DIR}/../../../src/crypto_gmssl_copy_test.h"
    "${CMAKE_CURRENT_LIST_DIR}/../../../src/crypto_gmssl_copy_test.c")
  list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
    "-DCMAKE_PROJECT_GmSSL_INCLUDE=${CMAKE_CURRENT_LIST_DIR}/../instrument-gmssl.cmake")
endif()
