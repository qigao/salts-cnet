function(salts_capture_original_test target source)
  add_executable(${target} ${source})
  target_compile_features(${target} PRIVATE c_std_11)
  set_target_properties(${target} PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF FOLDER "media/capture/tests")
  target_link_libraries(${target} PRIVATE Salts::Media Salts::TinyTest)
  add_test(NAME ${target} COMMAND ${target})
  set_tests_properties(${target} PROPERTIES TIMEOUT 60)
endfunction()

if(WIN32)
  # Original fake-COM control test compiles the exact Windows backend body.
  # This is an isolated regression, not a replacement production provider.
  add_executable(capture_exposure_windows_test
    test_capture_exposure_windows.c
    capture_exposure_destroy_stub.c)
  target_compile_features(capture_exposure_windows_test PRIVATE c_std_11)
  target_include_directories(capture_exposure_windows_test PRIVATE
    "${PROJECT_SOURCE_DIR}/media/capture/include")
  # Keep the exact production backend in the fake-COM test. Some MF helper
  # references remain live under MSVC even with function-level dead stripping.
  # Resolve those references through their native libraries, but delay-load
  # MF DLLs so the control-only cases cannot initialize real capture services
  # through a process-start import.
  target_link_libraries(capture_exposure_windows_test PRIVATE
    Salts::Core Salts::TinyTest yuv
    mfplat mf mfuuid mfreadwrite strmiids ole32 oleaut32)
  add_test(NAME capture_exposure_windows_test COMMAND capture_exposure_windows_test)
  set_target_properties(capture_exposure_windows_test PROPERTIES FOLDER "media/capture/tests")
  # The test links the native vcpkg libyuv/JPEG import libraries.
  # Admit their exact binary-cache runtime DLLs without staging a package or
  # depending on any installed consumer project.
  set_tests_properties(capture_exposure_windows_test PROPERTIES
    TIMEOUT 15
    ENVIRONMENT_MODIFICATION
      "PATH=path_list_prepend:${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin")
  # This executable enumerates physical audio/video/screen/GPU devices and may
  # open camera modes. Build it on Windows to protect the API/ABI, but do not
  # register it in generic hosted-runner CTest. Device-backed qualification
  # belongs on an explicit hardware environment.
  add_executable(capture_windows_test test_capture_windows.c)
  target_compile_features(capture_windows_test PRIVATE c_std_11)
  set_target_properties(capture_windows_test PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF FOLDER "media/capture/tests")
  target_link_libraries(capture_windows_test PRIVATE Salts::Media Salts::TinyTest)
endif()

if(ANDROID)
  salts_capture_original_test(capture_android_test test_capture_android.c)
endif()

if(UNIX AND NOT ANDROID AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
  salts_capture_original_test(capture_posix_test test_capture_posix.c)
endif()

