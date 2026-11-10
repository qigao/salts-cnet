cmake_minimum_required(VERSION 3.25)
include(CMakeOptions.cmake)
project(
  SaltsNet
  VERSION 0.1.4
  LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  # Core's own shared SDK must match Base's supported 4 KiB/16 KiB loaders.
  add_link_options("LINKER:-z,max-page-size=16384" "LINKER:-z,common-page-size=16384")
endif()

if(WIN32)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
  # Keep the published DLL identity independent of the selected LLVM driver.
  # llvm-mingw otherwise adds a Unix-style `lib` prefix that differs from the
  # MSVC ABI name and from the fail-closed installed-owner audit.
  set(CMAKE_SHARED_LIBRARY_PREFIX "")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
if(BUILD_TESTS)
  enable_testing()
endif()
include(cmake/CmakeUtils.cmake)
include(cmake/Sanitizers.cmake)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(SALTS_DEPENDENCY_PREFIX "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
list(PREPEND CMAKE_PREFIX_PATH
     "${SALTS_DEPENDENCY_PREFIX}/$ENV{VCPKG_CONFIGURATION_SUBDIR}"
     "${SALTS_DEPENDENCY_PREFIX}")
find_package(Threads REQUIRED)
unset(SaltsBase_DIR CACHE)
if(NOT "$ENV{SALTS_BASE_VERSION}" MATCHES "^[0-9]+[.][0-9]+[.][0-9]+$")
  message(FATAL_ERROR "SALTS_BASE_VERSION must select an exact SDK version without the v prefix")
endif()
# This is the API compatibility floor, not the selected upstream version.
set(SALTS_BASE_REQUIRED_VERSION 0.1.1)
if("$ENV{SALTS_BASE_VERSION}" VERSION_LESS "${SALTS_BASE_REQUIRED_VERSION}")
  message(FATAL_ERROR "SaltsBase ${SALTS_BASE_REQUIRED_VERSION} or newer is required")
endif()
find_package(
  SaltsBase
  $ENV{SALTS_BASE_VERSION}
  EXACT
  CONFIG
  REQUIRED
  PATHS
  "$ENV{SALTS_BASE_ROOT}"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH)
find_package(
  GmSSL
  CONFIG
  REQUIRED
  PATHS
  "${SALTS_DEPENDENCY_PREFIX}/share/gmssl"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH)

add_subdirectory(vendor)
add_subdirectory(crypto)
add_subdirectory(cnet)
add_subdirectory(sctp)

set(_saltscore_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/SaltsCore")
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SaltsCoreConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfig.cmake"
  INSTALL_DESTINATION "${_saltscore_package_dir}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMinorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/SaltsCoreConfigVersion.cmake"
        DESTINATION "${_saltscore_package_dir}")
install(
  EXPORT SaltsCoreTargets
  FILE SaltsCoreTargets.cmake
  NAMESPACE Salts::
  DESTINATION "${_saltscore_package_dir}")
