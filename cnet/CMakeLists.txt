# Provider-free C11 WebSocket frame parser. This is a private component of the
# always-assembled CNet owner, not a separately exported SDK target.
cmake_add_source(wsparser_sources DIRS src/wsparser)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${wsparser_sources})
add_library(saltscore_wsparser OBJECT ${wsparser_sources})
cmake_config_target(saltscore_wsparser FOLDER "cnet")

target_compile_features(saltscore_wsparser PUBLIC c_std_11)
set_target_properties(saltscore_wsparser PROPERTIES POSITION_INDEPENDENT_CODE ON
                                                    C_VISIBILITY_PRESET hidden)
target_include_directories(saltscore_wsparser
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser")

# Production CNet drives the opaque Crypto stream API. Backend protocol state,
# certificates and platform trust stores belong to Crypto.
find_package(
  c-ares
  CONFIG
  REQUIRED
  PATHS
  "${SALTS_DEPENDENCY_PREFIX}/share/c-ares"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH)
find_package(
  kcp
  CONFIG
  REQUIRED
  PATHS
  "${SALTS_DEPENDENCY_PREFIX}/share/kcp"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH)
# Salts source at refactor/cnet-ipc-name-native: native C11 FIFO, indexed peers,
# and caller-owned IPC path. Keep the entire CNet DSO in one ownership domain.
cmake_add_source(cnet_sources DIRS src include/cnet EXCLUDES
                 src/cnet_tls_crypto_qualification.c)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${cnet_sources})
add_library(cnet SHARED ${cnet_sources} $<TARGET_OBJECTS:saltscore_wsparser>)
cmake_config_target(
  cnet
  ALIAS
  Salts::CNet
  FOLDER
  "cnet"
  EXPORT_NAME
  CNet)

target_compile_features(cnet PUBLIC c_std_11)
cmake_export_symbols(cnet cnet_)

target_include_directories(
  cnet
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/crypto/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
          "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser"
          "${PROJECT_SOURCE_DIR}/vendor/monocypher"
          "${PROJECT_SOURCE_DIR}/vendor/reed")
target_link_libraries(
  cnet
  PUBLIC Salts::NativeIO
  PRIVATE Salts::URI
          Salts::SIMD
          Salts::Core
          monocypher
          reed
          c-ares::cares
          kcp::kcp
          Salts::Crypto)

install(
  TARGETS cnet
  EXPORT SaltsCNetTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(
  DIRECTORY include/cnet
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING
  PATTERN "*.h")

if(BUILD_TESTS)
  target_compile_definitions(cnet PRIVATE CNET_TLS_MEMORY_TESTING)
  target_include_directories(cnet PRIVATE "${PROJECT_SOURCE_DIR}/crypto/src")
  add_subdirectory(tests)
endif()
