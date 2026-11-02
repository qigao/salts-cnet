# One native C11 filesystem owner; no CMeta/CFlow/old Salts references.
add_library(saltscore_fs SHARED src/fs.c src/fs_root.c)
add_library(Salts::FS ALIAS saltscore_fs)
target_compile_features(saltscore_fs PUBLIC c_std_11)
set_target_properties(saltscore_fs PROPERTIES
  EXPORT_NAME FS C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  C_VISIBILITY_PRESET default WINDOWS_EXPORT_ALL_SYMBOLS ON
  VERSION "${PROJECT_VERSION}" SOVERSION "${SALTSCORE_NATIVE_SOVERSION}")
target_include_directories(saltscore_fs PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(saltscore_fs PUBLIC Salts::Platform)
if(WIN32)
  target_compile_definitions(saltscore_fs PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  set_target_properties(saltscore_fs PROPERTIES
    OUTPUT_NAME "saltscore_fs-${SALTSCORE_NATIVE_SOVERSION}")
elseif(APPLE)
  target_compile_definitions(saltscore_fs PRIVATE _DARWIN_C_SOURCE=1)
elseif(UNIX)
  target_compile_definitions(saltscore_fs PRIVATE
    _DEFAULT_SOURCE=1 _POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
endif()
install(TARGETS saltscore_fs EXPORT SaltsCoreTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/fs.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_TESTING)
  add_executable(saltscore_fs_test ${PROJECT_SOURCE_DIR}/tests/test_fs.c)
  target_compile_features(saltscore_fs_test PRIVATE c_std_11)
  set_target_properties(saltscore_fs_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(saltscore_fs_test PRIVATE Salts::FS Salts::TinyTest)
  add_test(NAME saltscore.fs_owner_and_root COMMAND saltscore_fs_test)
  set_tests_properties(saltscore.fs_owner_and_root PROPERTIES TIMEOUT 25)
endif()
