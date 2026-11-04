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
    test_capture_exposure_windows.c)
  target_compile_features(capture_exposure_windows_test PRIVATE c_std_11)
  target_include_directories(capture_exposure_windows_test PRIVATE
    "${PROJECT_SOURCE_DIR}/media/capture/include")
  # Test the actual single static Media archive alongside the source-owned
  # Windows MF control implementation. The native playback invalid-owner
  # assertions now also resolve from the same Salts::Media archive.
  target_link_libraries(capture_exposure_windows_test PRIVATE
    Salts::Media Salts::TinyTest yuv
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

if(SALTSCORE_ENABLE_TSAN)
  # The root sanitizer preset instruments the one Media archive, including
  # miniaudio. The private null monitor never opens a physical audio device.
  find_program(SALTS_CAPTURE_BASH bash REQUIRED)
  find_program(SALTS_CAPTURE_PULSEAUDIO pulseaudio REQUIRED)
  find_program(SALTS_CAPTURE_PACTL pactl REQUIRED)
  find_program(SALTS_CAPTURE_PACAT pacat REQUIRED)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_executable(salts_capture_native_tsan_regression native_tsan/test_native_capture_tsan.c)
  target_link_libraries(salts_capture_native_tsan_regression PRIVATE
    Salts::Media Salts::TinyTest Threads::Threads)
  set_target_properties(salts_capture_native_tsan_regression PROPERTIES
    C_STANDARD_REQUIRED ON C_EXTENSIONS OFF FOLDER "media/capture/tests")
  add_test(NAME salts_capture_native_tsan_virtual_monitor
    COMMAND "${SALTS_CAPTURE_BASH}" "${CMAKE_CURRENT_SOURCE_DIR}/native_tsan/run_private_pulse.sh"
      $<TARGET_FILE:salts_capture_native_tsan_regression> "${Python3_EXECUTABLE}")
  set_tests_properties(salts_capture_native_tsan_virtual_monitor PROPERTIES TIMEOUT 60)
endif()

