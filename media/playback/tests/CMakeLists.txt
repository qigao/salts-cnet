add_executable(playback_buffer_test test_playback_buffer.c ../src/playback_buffer.c)
target_compile_features(playback_buffer_test PRIVATE c_std_11)
target_link_libraries(playback_buffer_test PRIVATE Salts::Concurrency Salts::TinyTest)
target_include_directories(playback_buffer_test PRIVATE ../src)
add_test(NAME saltscore.playback_original_buffer COMMAND playback_buffer_test)

add_library(
  playback_null_test_impl STATIC
  ../../capture/src/miniaudio_impl.c
  ../src/playback_buffer.c
  ../src/salts_playback.c)
# This is the original deterministic test device. It is never installed or
# linked into the production Playback owner and does not replace its backend.
set_target_properties(playback_null_test_impl PROPERTIES
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(APPLE)
  set_source_files_properties(../../capture/src/miniaudio_impl.c PROPERTIES LANGUAGE OBJC)
  target_link_libraries(playback_null_test_impl PRIVATE
    ${SALTS_MEDIA_AudioToolbox_FRAMEWORK}
    ${SALTS_MEDIA_CoreAudio_FRAMEWORK}
    ${SALTS_MEDIA_CoreFoundation_FRAMEWORK}
    ${SALTS_MEDIA_Foundation_FRAMEWORK}
    ${SALTS_MEDIA_AVFoundation_FRAMEWORK})
endif()
target_compile_features(playback_null_test_impl PUBLIC c_std_11)
target_compile_definitions(
  playback_null_test_impl PRIVATE SALTS_PLAYBACK_TEST_NULL_BACKEND=1)
set_target_properties(playback_null_test_impl PROPERTIES C_VISIBILITY_PRESET hidden)
target_include_directories(
  playback_null_test_impl
  PUBLIC ../include
  PRIVATE ../src ${SALTS_MEDIA_MINIAUDIO_INCLUDE_DIR})
target_link_libraries(
  playback_null_test_impl PRIVATE Salts::Concurrency Salts::Platform)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(playback_null_test_impl PRIVATE m)
endif()

add_executable(playback_lifecycle_test test_playback_lifecycle.c)
target_compile_features(playback_lifecycle_test PRIVATE c_std_11)
target_link_libraries(playback_lifecycle_test PRIVATE playback_null_test_impl Salts::TinyTest)
add_test(NAME saltscore.playback_original_lifecycle COMMAND playback_lifecycle_test)
set_tests_properties(saltscore.playback_original_buffer
  saltscore.playback_original_lifecycle PROPERTIES TIMEOUT 30)
