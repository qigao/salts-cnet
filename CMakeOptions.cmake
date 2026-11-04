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
option(SALTSCORE_CNET_PRODUCTION_REQUIRED_MTLS_TEST
  "Exercise public NativeIO CNet REQUIRED client-certificate auth" OFF)
option(SALTSCORE_CNET_TLS_MIXED_MEASUREMENTS
  "Register the 25 existing fresh-process TLS bulk/control measurement cases" OFF)
option(SALTSCORE_CNET_TLS_MIXED_HEAPTRACK
  "Profile the formal TLS measurement cases with Linux heaptrack" OFF)
option(SALTSCORE_CNET_TLS_MIXED_PERF
  "Sample CPU callchains of the formal Linux TLS measurement cases" OFF)
option(SALTSCORE_GMSSL_COPY_PROFILE
  "Count explicit provider copies with the diagnostic GmSSL triplet" OFF)
option(SALTSCORE_BUILD_USB "Build the native libusb USB owner" OFF)
option(SALTSCORE_BUILD_SERIAL "Build the native Serial owner" OFF)
option(SALTSCORE_BUILD_MEDIA "Build combined static Capture/Playback Media owner" OFF)

option(SALTSCORE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(SALTSCORE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(SALTSCORE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
