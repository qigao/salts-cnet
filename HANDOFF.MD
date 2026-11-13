# Root CMake and Media dependency isolation

- The old SaltsBase 0.1.7 SDK previously selected by `.env` called
  `find_dependency(JPEG)` and `find_dependency(libyuv)` unconditionally. A CNet
  configure can therefore fail in JPEG discovery even though CNet never uses
  Media. Adding a global dependency search prefix makes that discovery succeed
  but does not repair the ownership error. The SaltsBase source package config
  in commit `fe1e96c` already removes those global lookups.
- CNet now resolves only its directly used GmSSL, c-ares and KCP packages from
  the selected vcpkg triplet. Reed resolves its SIMDe headers from that same
  installation. Keep Media's JPEG/libyuv discovery out of this consumer.
- Local verification uses an independent SaltsBase installation at
  `C:/projects/cpp/turbonet/salts-base/build/local-sdk-0.1.7-fe1e96c`, produced
  through SaltsBase's existing configure/build/install presets. This is a local
  qualification SDK, not a published release or a consumer fallback. The
  original released SDK and both repositories' `.env` files were unchanged
  during that qualification. Set `SALTS_BASE_ROOT` in the verification process and configure with
  `cmake --fresh --preset llvm-mingw-x64-release-user -DBUILD_TESTS=ON`.
  Release preparation now selects the published SaltsBase 0.1.8 SDK. Its
  manifest, CI source, Windows LLVM-MinGW archive size and SHA-256 were verified;
  the original TAR was restored through the existing CI download/extraction
  entry. `build/release-0.1.12/base-sdk-receipt.json` records its root and digest.
  Only `SALTS_BASE_VERSION` and `SALTS_BASE_ROOT` changed in local `.env`;
  the corresponding repository CI variable is 0.1.8. The old SDK is preserved.
- The fresh configure's JSON command trace has zero JPEG/libyuv package
  lookups, and its new cache has no JPEG/libyuv entries. Evidence:
  `build/cmake-cleanup-no-media-fixed-trace.jsonl` and
  `build/cmake-cleanup-no-media-check.log`. The earlier failed released-SDK
  configure remains in `build/cmake-cleanup-baseline-configure.log`.
- The complete CNet build also passes with that local SDK. Its DLL import
  table contains neither JPEG nor libyuv
  (`build/cmake-cleanup-no-media-imports.log`). The complete formal CTest run
  passes 103/103 in 262.83 seconds (`build/cmake-cleanup-no-media-ctest.log`).
  Other target platforms were not executed in this local verification.
- Before the SDK change, the cleanup preserved all 299 compilation commands,
  both SDK export files and all 103 CTest registrations, commands and properties
  (`build/cmake-cleanup-generation-check.log`). The extra SCTP consumer project
  was unused and referenced the missing `dtls_records.c`; the root-owned native
  DTLS/Go suite remains registered. No independent validation project is added.
