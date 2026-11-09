option(BUILD_TESTS "Enable TESTS" OFF)
option(BUILD_BENCHMARK "Build benchmark cases" OFF)
option(SALTSCORE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(SALTSCORE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(SALTSCORE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

# Presets require explicit profile identities; empty values must not select a
# default host ABI or install into CMake's default system prefix.
foreach(_saltscore_profile_input IN ITEMS
    CMAKE_INSTALL_PREFIX VCPKG_TARGET_TRIPLET VCPKG_INSTALLED_DIR)
  if(NOT DEFINED ${_saltscore_profile_input} OR
     "${${_saltscore_profile_input}}" STREQUAL "")
    message(FATAL_ERROR "Required preset input is empty: ${_saltscore_profile_input}")
  endif()
endforeach()
unset(_saltscore_profile_input)
if("${CMAKE_C_COMPILER}" STREQUAL "" AND
   "${CMAKE_ANDROID_NDK}" STREQUAL "")
  message(FATAL_ERROR "The selected preset must provide a compiler or Android NDK")
endif()

if(BUILD_BENCHMARK AND NOT BUILD_TESTS)
  message(FATAL_ERROR "The existing benchmark cases require BUILD_TESTS")
endif()
