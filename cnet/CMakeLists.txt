# Provider-free C11 WebSocket frame parser. This is a private component of
# the always-assembled CNet owner, not a separately exported SDK target.
cmake_add_source(wsparser_sources DIRS src/wsparser)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${wsparser_sources})
add_library(saltscore_wsparser OBJECT ${wsparser_sources})
cmake_config_target(saltscore_wsparser FOLDER "cnet")

target_compile_features(saltscore_wsparser PUBLIC c_std_11)
set_target_properties(saltscore_wsparser PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_include_directories(saltscore_wsparser PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser")

# Production CNet drives the opaque Crypto stream API. Backend protocol state,
# certificates and platform trust stores belong to Crypto.
find_package(c-ares CONFIG REQUIRED
  PATHS "${SALTS_DEPENDENCY_PREFIX}/share/c-ares"
  NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
find_package(kcp CONFIG REQUIRED
  PATHS "${SALTS_DEPENDENCY_PREFIX}/share/kcp"
  NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
# Salts source at refactor/cnet-ipc-name-native: native C11 FIFO, indexed peers,
# and caller-owned IPC path. Keep the entire CNet DSO in one ownership domain.
cmake_add_source(cnet_sources DIRS src include/cnet
  EXCLUDES src/cnet_tls_crypto_qualification.c)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${cnet_sources})
add_library(cnet SHARED ${cnet_sources} $<TARGET_OBJECTS:saltscore_wsparser>)
cmake_config_target(cnet
  ALIAS Salts::CNet FOLDER "cnet" EXPORT_NAME CNet)

target_compile_features(cnet PUBLIC c_std_11)
set_target_properties(cnet PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

target_include_directories(cnet
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/crypto/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser"
    "${PROJECT_SOURCE_DIR}/vendor/monocypher"
    "${PROJECT_SOURCE_DIR}/vendor/reed")
target_link_libraries(cnet
  PUBLIC
    Salts::NativeIO

  PRIVATE
    Salts::URI
    Salts::SIMD
    Salts::Core
    monocypher
    reed
    c-ares::cares
    kcp::kcp
    Salts::Crypto)

install(TARGETS cnet EXPORT SaltsCoreTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/cnet
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h")

if(BUILD_TESTS)
  # Private counters in the same production Crypto instance; no extra runtime.
  target_compile_definitions(cnet PRIVATE CNET_TLS_MEMORY_TESTING)
  target_include_directories(cnet PRIVATE "${PROJECT_SOURCE_DIR}/crypto/src")
  # Link maps retain physical GmSSL and Crypto archive members even when symbols
  # are hidden or stripped from a PE export table. They are test evidence,
  # never an additional library or an installed SDK artifact.
  function(cnet_owner_link_map target)
    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/cnet-owner-maps")
    set(_map "${PROJECT_BINARY_DIR}/cnet-owner-maps/${target}-$<CONFIG>.map")
    if(MSVC)
      target_link_options(${target} PRIVATE "/MAP:${_map}")
    elseif(APPLE)
      target_link_options(${target} PRIVATE "LINKER:-map,${_map}")
    else()
      target_link_options(${target} PRIVATE "LINKER:-Map,${_map}")
    endif()
  endfunction()
  cnet_owner_link_map(cnet)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  if(MSVC)
    get_filename_component(_cnet_owner_linker_dir "${CMAKE_LINKER}" DIRECTORY)
    if(NOT IS_ABSOLUTE "${CMAKE_LINKER}" OR NOT EXISTS "${CMAKE_LINKER}")
      message(FATAL_ERROR "CNet native owner audit requires the configured MSVC linker path")
    endif()
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      find_program(_cnet_owner_symbol_reader NAMES llvm-nm.exe llvm-nm
        PATHS "${_cnet_owner_linker_dir}"
        NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH REQUIRED)
      find_program(_cnet_owner_object_reader NAMES llvm-readobj.exe llvm-readobj
        PATHS "${_cnet_owner_linker_dir}"
        NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    else()
      # A Visual Studio generator can build without a developer-shell PATH.
      # Use dumpbin from the configured linker toolset, never a PATH fallback.
      find_program(_cnet_owner_symbol_reader NAMES dumpbin.exe dumpbin
        PATHS "${_cnet_owner_linker_dir}"
        NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH REQUIRED)
      set(_cnet_owner_object_reader "${_cnet_owner_symbol_reader}")
    endif()
  else()
    set(_cnet_owner_symbol_reader "${CMAKE_NM}")
    set(_cnet_owner_object_reader "${CMAKE_READELF}")
  endif()
  add_test(NAME saltscore.cnet_native_crypto_owner
    COMMAND "${Python3_EXECUTABLE}" -B
      "${PROJECT_SOURCE_DIR}/cnet/tests/owner/audit_native_crypto_owner.py"
      --archive "$<TARGET_FILE:salts_crypto>"
      --gmssl-archive "$<TARGET_FILE:GmSSL::GmSSL>"
      --runtime "$<TARGET_FILE:cnet>"
      --map "${PROJECT_BINARY_DIR}/cnet-owner-maps/cnet-$<CONFIG>.map"
      --system "${CMAKE_SYSTEM_NAME}"
      --nm "${_cnet_owner_symbol_reader}" --readelf "${CMAKE_READELF}"
      --readobj "${_cnet_owner_object_reader}"
      --peer "$<TARGET_FILE:saltscore_runtime_plugin_a>"
      --peer "$<TARGET_FILE:saltscore_runtime_plugin_b>"
      --peer "$<TARGET_FILE:saltscore_two_plugins_test>"
      --peer-map "${PROJECT_BINARY_DIR}/cnet-owner-maps/saltscore_runtime_plugin_a-$<CONFIG>.map"
      --peer-map "${PROJECT_BINARY_DIR}/cnet-owner-maps/saltscore_runtime_plugin_b-$<CONFIG>.map"
      --peer-map "${PROJECT_BINARY_DIR}/cnet-owner-maps/saltscore_two_plugins_test-$<CONFIG>.map")
  set_tests_properties(saltscore.cnet_native_crypto_owner PROPERTIES TIMEOUT 60)
  add_test(NAME saltscore.cnet_native_crypto_owner_negative
    COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover
      -s "${PROJECT_SOURCE_DIR}/cnet/tests/owner"
      -p test_native_crypto_owner_audit.py -v)
  add_subdirectory(tests)
endif()
