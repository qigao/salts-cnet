cmake_minimum_required(VERSION 3.21)
project(SaltsASN1 VERSION 0.1.0 LANGUAGES C)
# Standalone provider-neutral codec: no Core/CMeta/GmSSL.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
add_library(salts_asn1 STATIC src/reader.c src/value.c)
add_library(Salts::ASN1 ALIAS salts_asn1)
set_target_properties(salts_asn1 PROPERTIES
  OUTPUT_NAME salts_asn1 EXPORT_NAME ASN1
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)
target_compile_features(salts_asn1 PUBLIC c_std_11)
target_include_directories(salts_asn1 PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
install(TARGETS salts_asn1 EXPORT SaltsASN1Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "asn1*.h"
  PATTERN "salts" EXCLUDE)
set(_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/ASN1")
install(EXPORT SaltsASN1Targets FILE ASN1Targets.cmake
  NAMESPACE Salts:: DESTINATION "${_package_dir}")
configure_package_config_file(cmake/ASN1Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/ASN1Config.cmake"
  INSTALL_DESTINATION "${_package_dir}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ASN1ConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ASN1Config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ASN1ConfigVersion.cmake"
  DESTINATION "${_package_dir}")
install(FILES LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/ASN1")
# Exercise the actual source-owned ASN.1 cases in the parent Core native
# test graph. A standalone ASN1 build must provide TinyTest explicitly rather
# than silently using an unrelated local test macro implementation.
if(BUILD_TESTING)
  if(NOT TARGET Salts::TinyTest)
    message(FATAL_ERROR "ASN1 runtime tests require Salts::TinyTest")
  endif()
  enable_language(CXX)
  add_subdirectory(tests)
endif()
