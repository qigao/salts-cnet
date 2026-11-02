# Original CNet transport target is owned here; SCTP is independent.
# Provider-free C11 WebSocket frame parser. This is a private component of
# the always-assembled CNet owner, not a separately exported SDK target.
add_library(saltscore_wsparser OBJECT
  src/wsparser/websocket_frame_parser.c)
target_compile_features(saltscore_wsparser PUBLIC c_std_11)
set_target_properties(saltscore_wsparser PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_include_directories(saltscore_wsparser PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser")

# Production CNet retains its complete original TLS implementation. Its
# private GmSSL C headers/library are imported from the pinned vcpkg package.
# The narrower qualification facade is never substituted for production TLS.
if(NOT TARGET Salts::URI OR NOT TARGET saltscore_wsparser)
  message(FATAL_ERROR "CNet requires native Core URI and WebSocket parser targets")
endif()
find_package(c-ares CONFIG REQUIRED)
find_package(kcp CONFIG REQUIRED)
if(NOT TARGET c-ares::cares OR NOT TARGET kcp::kcp)
  message(FATAL_ERROR "CNet requires c-ares::cares and kcp::kcp")
endif()
if(NOT TARGET salts_crypto OR NOT TARGET Salts::Crypto)
  message(FATAL_ERROR "CNet requires the local Salts::Crypto owner")
endif()
get_target_property(_cnet_crypto_alias Salts::Crypto ALIASED_TARGET)
get_target_property(_cnet_crypto_type salts_crypto TYPE)
get_target_property(_cnet_crypto_imported salts_crypto IMPORTED)
get_target_property(_cnet_native_include GmSSL::GmSSL INTERFACE_INCLUDE_DIRECTORIES)
if(NOT _cnet_crypto_alias STREQUAL "salts_crypto" OR
   NOT _cnet_crypto_type STREQUAL "STATIC_LIBRARY" OR _cnet_crypto_imported)
  message(FATAL_ERROR "CNet requires exactly one local non-imported STATIC Crypto owner")
endif()
if(NOT _cnet_native_include OR
   NOT EXISTS "${_cnet_native_include}/gmssl/tls.h")
  message(FATAL_ERROR "Pinned vcpkg GmSSL native TLS headers are missing")
endif()

# Never fold a second copy of any stateful runtime into CNet. Core/Platform/
# Concurrency/Coroutine/NativeIO are one installed shared owner each.
foreach(_owner IN ITEMS saltscore_core saltscore_platform saltscore_concurrency
                        saltscore_coroutine saltscore_native_io)
  get_target_property(_owner_kind ${_owner} TYPE)
  if(NOT _owner_kind STREQUAL "SHARED_LIBRARY")
    message(FATAL_ERROR "CNet requires shared foundation owner: ${_owner}")
  endif()
endforeach()
# The stateless URI parser may remain an independent PIC archive.
set_target_properties(saltscore_uri PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Both private code libraries are built exactly once in vendor/CMakeLists.txt.
# No alternate crypto/erasure implementation or target alias is permitted.
if(NOT TARGET saltscore_cnet_monocypher OR NOT TARGET saltscore_cnet_reed)
  message(FATAL_ERROR "CNet requires its vendor-owned Monocypher and Reed targets")
endif()

# Salts source at refactor/cnet-ipc-name-native: native C11 FIFO, indexed peers,
# and caller-owned IPC path. Keep the entire CNet DSO in one ownership domain.
set(_saltscore_cnet_sources
  cnet/src/cnet_client.c
  cnet/src/cnet_command.c
  cnet/src/cnet_datagram.c
  cnet/src/cnet_kcp.c
  cnet/src/cnet_kcp_fec.c
  cnet/src/cnet_kcp_secure.c
  cnet/src/cnet_secure_kcp.c
  cnet/src/cnet_packet_endpoint.c
  cnet/src/cnet_dispatcher.c
  cnet/src/cnet_event.c
  cnet/src/cnet_listener.c
  cnet/src/cnet_module.c
  cnet/src/cnet_owner.c
  cnet/src/cnet_owner_strategy.c
  cnet/src/cnet_destination_policy.c
  cnet/src/cnet_client_pool.c
  cnet/src/cnet_recovery_policy.c
  cnet/src/cnet_managed_dial.c
  cnet/src/cnet_sg_host.c
  cnet/src/cnet_resolver.c
  cnet/src/cnet_session.c
  cnet/src/cnet_shards.c
  cnet/src/cnet_tls.c
  cnet/src/cnet_transport.c
  cnet/src/cnet_transport_pipe.c
  cnet/src/cnet_transport_ipc.c
  cnet/src/cnet_ipc.c
  cnet/src/cnet_transport_vsock.c
  cnet/src/cnet_uri.c
  cnet/src/cnet_write_queue.c
  cnet/src/cnet_websocket.c
  cnet/src/cnet_manager.c
  cnet/src/cnet_handoff.c
  $<TARGET_OBJECTS:saltscore_wsparser>)

# Keep exact original Owner test inputs repo-relative; make module library
# sources absolute so its CMakeLists owns the target from cnet/.
set(_saltscore_cnet_sources "${_saltscore_cnet_sources}" PARENT_SCOPE)
set(_saltscore_cnet_local_sources)
foreach(_unit IN LISTS _saltscore_cnet_sources)
  if(_unit MATCHES "^\\$<TARGET_OBJECTS:")
    list(APPEND _saltscore_cnet_local_sources "${_unit}")
  else()
    list(APPEND _saltscore_cnet_local_sources "${PROJECT_SOURCE_DIR}/${_unit}")
  endif()
endforeach()
add_library(saltscore_cnet SHARED ${_saltscore_cnet_local_sources})
add_library(Salts::CNet ALIAS saltscore_cnet)
target_compile_features(saltscore_cnet PUBLIC c_std_11)
# These native header switches previously came from the imported provider.
# They remain private, but must match the local Crypto object ABI exactly.
target_compile_definitions(saltscore_cnet PRIVATE
  ENABLE_TLS ENABLE_SECP256R1 ENABLE_SECP384R1 ENABLE_SHA1 ENABLE_SHA2 ENABLE_AES)
set_target_properties(saltscore_cnet PROPERTIES
  VERSION "${PROJECT_VERSION}" SOVERSION "${SALTSCORE_NATIVE_SOVERSION}"
  EXPORT_NAME CNet C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  WINDOWS_EXPORT_ALL_SYMBOLS ON)
if(WIN32)
  set_target_properties(saltscore_cnet PROPERTIES
    OUTPUT_NAME "saltscore_cnet-${SALTSCORE_NATIVE_SOVERSION}")
endif()
target_include_directories(saltscore_cnet
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/wsparser"
    "${PROJECT_SOURCE_DIR}/native-io/src"
    "${PROJECT_SOURCE_DIR}/vendor/monocypher"
    "${PROJECT_SOURCE_DIR}/vendor/reed"
    "${_cnet_native_include}")
target_link_libraries(saltscore_cnet
  PUBLIC
    Salts::Core
    Salts::NativeIO
    Salts::Concurrency
  PRIVATE
    Salts::URI
    Salts::Platform
    saltscore_cnet_monocypher
    saltscore_cnet_reed
    c-ares::cares
    kcp::kcp
    Salts::Crypto
    GmSSL::GmSSL
    $<$<PLATFORM_ID:Windows>:crypt32>)
if(APPLE)
  find_library(SALTSCORE_CNET_COREFOUNDATION CoreFoundation REQUIRED)
  find_library(SALTSCORE_CNET_SECURITY Security REQUIRED)
  target_link_libraries(saltscore_cnet PRIVATE
    "${SALTSCORE_CNET_COREFOUNDATION}"
    "${SALTSCORE_CNET_SECURITY}")
endif()

install(TARGETS saltscore_cnet EXPORT SaltsCoreTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/cnet
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h")

if(BUILD_TESTING)
  # Link maps retain physical GmSSL and Crypto archive members even when symbols
  # are hidden or stripped from a PE export table. They are test evidence,
  # never an additional library or an installed SDK artifact.
  function(saltscore_cnet_owner_link_map target)
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
  saltscore_cnet_owner_link_map(saltscore_cnet)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  set(_cnet_owner_symbol_reader "${CMAKE_NM}")
  set(_cnet_owner_object_reader "${CMAKE_READELF}")
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
  endif()
  add_test(NAME saltscore.cnet_native_crypto_owner
    COMMAND "${Python3_EXECUTABLE}" -B
      "${PROJECT_SOURCE_DIR}/tests/cnet-owner/audit_native_crypto_owner.py"
      --archive "$<TARGET_FILE:salts_crypto>"
      --gmssl-archive "$<TARGET_FILE:GmSSL::GmSSL>"
      --runtime "$<TARGET_FILE:saltscore_cnet>"
      --map "${PROJECT_BINARY_DIR}/cnet-owner-maps/saltscore_cnet-$<CONFIG>.map"
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
      -s "${PROJECT_SOURCE_DIR}/tests/cnet-owner"
      -p test_native_crypto_owner_audit.py -v)
endif()
