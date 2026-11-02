add_library(saltscore_process SHARED src/process.c)
add_library(Salts::Process ALIAS saltscore_process)
target_compile_features(saltscore_process PUBLIC c_std_11)
set_target_properties(saltscore_process PROPERTIES
  EXPORT_NAME Process C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  C_VISIBILITY_PRESET default WINDOWS_EXPORT_ALL_SYMBOLS ON
  VERSION "${PROJECT_VERSION}" SOVERSION "${SALTSCORE_NATIVE_SOVERSION}")
target_include_directories(saltscore_process PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(saltscore_process PUBLIC Salts::Platform)
if(MSVC)
  target_compile_options(saltscore_process PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-experimental:c11atomics>)
  target_compile_definitions(saltscore_process PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  set_target_properties(saltscore_process PROPERTIES
    OUTPUT_NAME "saltscore_process-${SALTSCORE_NATIVE_SOVERSION}")
elseif(APPLE)
  target_compile_definitions(saltscore_process PRIVATE _DARWIN_C_SOURCE=1)
elseif(UNIX)
  target_compile_definitions(saltscore_process PRIVATE
    _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
endif()
install(TARGETS saltscore_process EXPORT SaltsCoreTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/process.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_TESTING)
  add_executable(saltscore_process_test ${PROJECT_SOURCE_DIR}/tests/test_process.c)
  target_compile_features(saltscore_process_test PRIVATE c_std_11)
  set_target_properties(saltscore_process_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_process_test PRIVATE Salts::Process Salts::TinyTest)
  add_test(NAME saltscore.process_spawn_reap COMMAND saltscore_process_test)
  set_tests_properties(saltscore.process_spawn_reap PROPERTIES TIMEOUT 30)
endif()
