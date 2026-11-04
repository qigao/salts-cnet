# The Media module owns capture and playback through one C11 static archive.
# Explicit, required providers only; no compatibility shared-library targets.
if(NOT WIN32 AND NOT ANDROID AND NOT APPLE AND
   NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Salts::Media requires Windows, Linux, macOS, Android or iOS")
endif()

if(APPLE)
  enable_language(OBJC)
endif()

add_library(salts_media STATIC
  capture/src/capture_video.c
  capture/src/miniaudio_impl.c
  playback/src/playback_buffer.c
  playback/src/salts_playback.c)
add_library(Salts::Media ALIAS salts_media)
set_target_properties(salts_media PROPERTIES
  EXPORT_NAME Media
  OUTPUT_NAME saltscore_media
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)
target_compile_features(salts_media PUBLIC c_std_11)
target_include_directories(salts_media
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/capture/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/playback/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/capture/src
    ${CMAKE_CURRENT_SOURCE_DIR}/playback/src)
target_link_libraries(salts_media PUBLIC
  Salts::Core Salts::Platform Salts::Concurrency)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
  target_compile_definitions(salts_media PRIVATE _GNU_SOURCE=1)
endif()

# One miniaudio implementation for Capture and Playback. Its C symbols are
# compiled only once into the Media archive, including on iOS.
find_path(SALTS_MEDIA_MINIAUDIO_INCLUDE_DIR NAMES miniaudio.h REQUIRED)
find_file(SALTS_MEDIA_MINIAUDIO_LICENSE NAMES copyright LICENSE
  PATHS "${SALTS_MEDIA_MINIAUDIO_INCLUDE_DIR}"
        "${SALTS_MEDIA_MINIAUDIO_INCLUDE_DIR}/../share/miniaudio"
  NO_DEFAULT_PATH REQUIRED)
target_include_directories(salts_media PRIVATE
  ${SALTS_MEDIA_MINIAUDIO_INCLUDE_DIR})
set_source_files_properties(capture/src/miniaudio_impl.c
  PROPERTIES COMPILE_OPTIONS "-w")
if(APPLE)
  set_source_files_properties(capture/src/miniaudio_impl.c PROPERTIES LANGUAGE OBJC)
endif()
install(FILES "${SALTS_MEDIA_MINIAUDIO_LICENSE}"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/miniaudio"
  RENAME LICENSE)

# The static owner publishes actual link dependencies. The installed package
# resolves them explicitly rather than serializing build-machine archive paths.
if(WIN32 OR ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(libyuv CONFIG REQUIRED)
  if(NOT TARGET yuv OR NOT TARGET JPEG::JPEG)
    message(FATAL_ERROR "Media requires the pinned yuv and JPEG::JPEG targets")
  endif()
  target_link_libraries(salts_media PRIVATE yuv JPEG::JPEG)
  find_file(SALTS_MEDIA_LIBYUV_LICENSE NAMES copyright LICENSE
    PATHS "${libyuv_DIR}" "${libyuv_DIR}/../../../share/libyuv"
    NO_DEFAULT_PATH REQUIRED)
  install(FILES "${SALTS_MEDIA_LIBYUV_LICENSE}"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/libyuv"
    RENAME LICENSE)
endif()
if(WIN32)
  find_package(libjpeg-turbo CONFIG REQUIRED)
  find_file(SALTS_MEDIA_JPEG_LICENSE NAMES copyright LICENSE
    PATHS "${libjpeg-turbo_DIR}" NO_DEFAULT_PATH REQUIRED)
  install(FILES "${SALTS_MEDIA_JPEG_LICENSE}"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/libjpeg-turbo"
    RENAME LICENSE)
endif()

if(ANDROID)
  target_sources(salts_media PRIVATE
    capture/src/android/capture_android.c
    capture/src/android/capture_audio_android.c
    capture/src/android/capture_video_android.c
    capture/src/android/capture_screen_android.c)
  find_library(SALTS_MEDIA_ANDROID_LIBRARY android REQUIRED)
  find_library(SALTS_MEDIA_OPENSL_LIBRARY OpenSLES REQUIRED)
  find_library(SALTS_MEDIA_MEDIANDK_LIBRARY mediandk REQUIRED)
  find_library(SALTS_MEDIA_CAMERA2_LIBRARY camera2ndk REQUIRED)
  target_compile_definitions(salts_media PRIVATE SALTS_CAPTURE_ANDROID=1)
  target_link_libraries(salts_media PRIVATE
    ${SALTS_MEDIA_ANDROID_LIBRARY}
    ${SALTS_MEDIA_OPENSL_LIBRARY}
    ${SALTS_MEDIA_MEDIANDK_LIBRARY}
    ${SALTS_MEDIA_CAMERA2_LIBRARY}
    ${CMAKE_DL_LIBS})
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  target_sources(salts_media PRIVATE
    capture/src/ios/capture_ios.m
    capture/src/ios/capture_ios_guard.m
    capture/src/ios/capture_audio_ios.m
    capture/src/ios/capture_video_ios.m
    capture/src/ios/capture_screen_ios.m)
  target_include_directories(salts_media PRIVATE capture/src/ios)
  target_compile_definitions(salts_media PRIVATE SALTS_CAPTURE_IOS=1)
  target_compile_options(salts_media PRIVATE "$<$<COMPILE_LANGUAGE:OBJC>:-fobjc-arc>")
  foreach(framework IN ITEMS Foundation AVFoundation CoreMedia CoreVideo
      AudioToolbox CoreAudio ReplayKit UIKit)
    find_library(SALTS_MEDIA_${framework}_FRAMEWORK ${framework} REQUIRED)
    target_link_libraries(salts_media PRIVATE
      ${SALTS_MEDIA_${framework}_FRAMEWORK})
  endforeach()
  set_target_properties(salts_media PROPERTIES
    XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "14.0"
    XCODE_ATTRIBUTE_ENABLE_BITCODE "NO")
elseif(WIN32)
  target_sources(salts_media PRIVATE
    capture/src/capture_audio_miniaudio.c
    capture/src/capture_win32.c
    capture/src/capture_video_win32.c
    capture/src/capture_screen_win32.c)
  target_link_libraries(salts_media PRIVATE
    mfplat mf mfuuid mfreadwrite strmiids ole32 oleaut32 d3d11 dxgi dxguid)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PIPEWIRE REQUIRED libpipewire-0.3)
  find_package(X11 REQUIRED COMPONENTS Xext)
  target_sources(salts_media PRIVATE
    capture/src/capture_audio_miniaudio.c
    capture/src/capture_linux.c
    capture/src/capture_video_linux.c
    capture/src/capture_screen_linux.c)
  target_compile_definitions(salts_media PRIVATE SALTS_HAS_PIPEWIRE SALTS_HAS_X11)
  target_include_directories(salts_media SYSTEM PRIVATE
    ${PIPEWIRE_INCLUDE_DIRS} ${X11_INCLUDE_DIR})
  target_compile_options(salts_media PRIVATE ${PIPEWIRE_CFLAGS_OTHER})
  target_link_directories(salts_media PRIVATE ${PIPEWIRE_LIBRARY_DIRS})
  target_link_options(salts_media PRIVATE ${PIPEWIRE_LDFLAGS_OTHER})
  target_link_libraries(salts_media PRIVATE
    Threads::Threads ${PIPEWIRE_LINK_LIBRARIES}
    ${X11_LIBRARIES} ${X11_Xext_LIB} ${CMAKE_DL_LIBS} m)
elseif(APPLE)
  target_sources(salts_media PRIVATE
    capture/src/capture_audio_miniaudio.c
    capture/src/capture_macos.c
    capture/src/capture_video_macos.m
    capture/src/capture_screen_macos.m)
  foreach(framework IN ITEMS Foundation AVFoundation CoreAudio AudioToolbox
      CoreFoundation CoreGraphics CoreMedia CoreVideo ScreenCaptureKit)
    find_library(SALTS_MEDIA_${framework}_FRAMEWORK ${framework} REQUIRED)
    target_link_libraries(salts_media PRIVATE
      ${SALTS_MEDIA_${framework}_FRAMEWORK})
  endforeach()
endif()

install(TARGETS salts_media
  EXPORT SaltsCoreTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY
  "${CMAKE_CURRENT_SOURCE_DIR}/capture/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/playback/include/"
  DESTINATION include
  FILES_MATCHING PATTERN "*.h")

if(BUILD_TESTING)
  if(NOT TARGET Salts::TinyTest)
    message(FATAL_ERROR "Media native tests require Salts::TinyTest")
  endif()
  add_subdirectory(capture/tests)
  add_subdirectory(playback/tests)
endif()
