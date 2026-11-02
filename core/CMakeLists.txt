# Keep the minimal foundation target usable without platform/transport providers.
add_library(saltscore_core SHARED src/bytes.c)
add_library(Salts::Core ALIAS saltscore_core)
target_compile_features(saltscore_core PUBLIC c_std_11)
set_target_properties(saltscore_core PROPERTIES
  EXPORT_NAME Core C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  C_VISIBILITY_PRESET default WINDOWS_EXPORT_ALL_SYMBOLS ON
  VERSION "${PROJECT_VERSION}" SOVERSION "${SALTSCORE_NATIVE_SOVERSION}")
target_include_directories(saltscore_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# Public mem_pool_t and mem_buffer_t contain C11 atomic fields on MSVC.
# Consumers including cmeta_buffer.h require the same C compiler setting.
if(MSVC)
  target_compile_options(saltscore_core PUBLIC
    $<$<COMPILE_LANG_AND_ID:C,MSVC>:-experimental:c11atomics>)
endif()

# Core-owned buffer/pool, byte utility and sole native Base64 implementation.
# No third-party Base64 DSO, vcpkg port or alternate codec is required.
target_sources(saltscore_core PRIVATE
  src/cmeta_buffer.c src/ring_buffer.c src/base64_utils.c
  src/runtime_abi.c src/utf8.c src/cmeta_error.c
  # Original utils/Core ownership restored; no CMeta provider or second core.
  src/vstr.c src/tstr.c src/memory_pool.c src/object_pool.c
  src/bucket_priority_queue.c src/fmt.c src/tlog.c src/cmeta_uuid.c src/cmeta_bytes.c src/cmeta_simd_scan.c
  src/cmeta_mmap.c src/re.c src/sds/sds.c)
# SDS is original private C string storage, not an exported provider target.
target_include_directories(saltscore_core PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/sds")
if(APPLE)
  target_compile_definitions(saltscore_core PRIVATE _DARWIN_C_SOURCE=1)
elseif(UNIX)
  target_compile_definitions(saltscore_core PRIVATE _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L)
endif()
# Original TLog owns real file and async queue operations, using canonical
# module implementations rather than replacing these features with stubs.
target_link_libraries(saltscore_core PUBLIC
  Salts::Platform Salts::Concurrency Salts::FS)

# Original one-shot Zstd ABI remains in the sole Core owner. The registry pins
# its exact source revision; never substitute the system codec or a second DSO.
option(SALTSCORE_BUILD_ZSTD "Build the original Core Zstd API with its pinned static provider" OFF)
if(SALTSCORE_BUILD_ZSTD)
  find_package(zstd 1.6.0 EXACT CONFIG REQUIRED)
  if(NOT TARGET zstd::libzstd_static)
    message(FATAL_ERROR "Core Zstd requires the pinned static zstd::libzstd_static provider")
  endif()
  get_target_property(_saltscore_zstd_type zstd::libzstd_static TYPE)
  if(NOT _saltscore_zstd_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "Core Zstd provider must be the original static archive")
  endif()
  file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/zstd-provider-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:zstd::libzstd_static>\n")
  target_sources(saltscore_core PRIVATE src/cmeta_zstd.c)
  target_link_libraries(saltscore_core PRIVATE zstd::libzstd_static)
  if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
    # PRIVATE alone does not hide archive symbols. Bind the pinned provider
    # inside Core so another process-level Zstd cannot interpose its calls.
    target_link_options(saltscore_core PRIVATE
      "LINKER:--exclude-libs,$<TARGET_FILE_NAME:zstd::libzstd_static>")
  endif()
  target_compile_definitions(saltscore_core PUBLIC SALTSCORE_HAS_ZSTD=1)
  install(FILES include/cmeta_zstd.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(FILES licenses/zstd.LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/zstd RENAME LICENSE)

  if(BUILD_TESTING)
    if(NOT SALTSCORE_BUILD_TINYTEST)
      message(FATAL_ERROR "Zstd original conformance requires SALTSCORE_BUILD_TINYTEST=ON")
    endif()
    # TinyTest is assembled later by the package root and resolved at generation.
    add_executable(saltscore_original_zstd_test ../tests/test_cmeta_zstd.c)
    target_compile_features(saltscore_original_zstd_test PRIVATE c_std_11)
    set_target_properties(saltscore_original_zstd_test PROPERTIES
      C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_link_libraries(saltscore_original_zstd_test PRIVATE Salts::Core Salts::TinyTest)
    add_test(NAME saltscore.original_zstd COMMAND saltscore_original_zstd_test)

    add_executable(saltscore_zstd_contract ../tests/zstd_native_contract.c)
    target_compile_features(saltscore_zstd_contract PRIVATE c_std_11)
    set_target_properties(saltscore_zstd_contract PROPERTIES
      C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_link_libraries(saltscore_zstd_contract PRIVATE Salts::Core Salts::TinyTest)
    add_test(NAME saltscore.zstd_native_contract COMMAND saltscore_zstd_contract)

    if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
      find_package(Python3 COMPONENTS Interpreter REQUIRED)
      add_test(NAME saltscore.zstd_private_archive
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/test_zstd_binary_owner.py"
          --library "$<TARGET_FILE:saltscore_core>"
          --nm "${CMAKE_NM}" --readelf "${CMAKE_READELF}")
      set_tests_properties(saltscore.zstd_private_archive PROPERTIES TIMEOUT 60)
    endif()
    set_tests_properties(saltscore.original_zstd saltscore.zstd_native_contract
      PROPERTIES TIMEOUT 60)
  endif()
endif()

if(WIN32)
  set_target_properties(saltscore_core PROPERTIES
    OUTPUT_NAME "saltscore_core-${SALTSCORE_NATIVE_SOVERSION}")
endif()
install(TARGETS saltscore_core EXPORT SaltsCoreTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES
  include/bytes.h include/runtime_abi.h include/utf8.h
  include/base64_utils.h include/vstr.h include/cmeta_api.h
  include/cmeta_buffer.h include/ring_buffer.h include/cmeta_error.h
  include/tstr.h include/str.h include/memory_pool.h include/object_pool.h
  include/bucket_priority_queue.h
  include/fmt.h include/fmt_pp.h include/tlog.h include/tlog_helper.h
  include/cmeta_uuid.h include/cmeta_bytes.h include/cmeta_simd_scan.h include/cmeta_mmap.h include/re.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Original upstream SDS BSD license is mandatory for this private source.
install(FILES src/sds/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/sds)

# Keep the original formatter lexer grammar in its own nested module.
add_subdirectory(parser)
