option(SALTSCORE_BUILD_URI "Build standalone re2c-generated URI parser" OFF)
option(SALTSCORE_BUILD_CNET "Build canonical local Crypto/CNet owners" ON)
option(SALTSCORE_BUILD_WEBSOCKET_PARSER
  "Qualify CNet-private WebSocket frame parser" OFF)
option(SALTSCORE_BUILD_CSERDE "Build standalone C11 CSerde owner" OFF)
option(SALTSCORE_BUILD_TINYTEST "Build standalone C11 TinyTest owner (mandatory for native tests)" ON)
option(SALTSCORE_BUILD_UNICODE "Build original pinned Unicode 17 owner" OFF)
option(SALTSCORE_BUILD_IDNA "Build original pinned Unicode 17 IDNA owner" OFF)
option(SALTSCORE_NATIVE_CPP_CONFORMANCE
  "Compile original native C++17 source contract against standalone Core" OFF)
option(SALTSCORE_BUILD_FS "Build canonical native FS owner" ON)
option(SALTSCORE_BUILD_PROCESS "Build standalone Process owner" OFF)
option(SALTSCORE_CNET_OWNER_SOURCE_TESTS
  "Qualify original CNet Owner and actual retained NativeIO terminal" OFF)
option(SALTSCORE_BUILD_SCTP "Build standalone C11 SCTP Wire and Session" OFF)
option(SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION
  "Run additional test-only Crypto facade and original Owner qualification" OFF)
option(SALTSCORE_BUILD_USB "Build the native libusb USB owner" OFF)
option(SALTSCORE_BUILD_PLAYBACK "Build the native PCM Playback owner" OFF)
option(SALTSCORE_BUILD_SERIAL "Build the native Serial owner" OFF)
option(SALTSCORE_BUILD_CAPTURE "Build the native audio/video/screen Capture owner" OFF)

option(SALTSCORE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(SALTSCORE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(SALTSCORE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
