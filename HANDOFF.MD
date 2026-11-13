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

# SaltsCNet package identity and release validation

- The root project and installed package are `SaltsCNet`, with configuration
  and export files under `lib/cmake/SaltsCNet`. Consumers migrate
  `find_package(SaltsCore ...)` to `find_package(SaltsCNet ...)`. All imported
  targets keep the `Salts::` namespace and their existing names.
- A local shared build cache was reconfigured with `BUILD_TESTS=OFF` while
  stale CTest registrations and test executables remained. The resulting
  Windows loader error was a missing `cnet_test_tls_memory_snapshot` export
  from the tests-disabled CNet DLL, not a missing SaltsBase SDK symbol. Use a
  task-owned worktree and the same formal presets/SDK for release validation
  so unrelated reconfiguration cannot replace the DLL during the run.
- CI run `43391486509` failed GCC's resumed intermediate-expiry case at
  `NotAfter + 1.000s`; the server handshake finished within 5 ms. The verifier
  uses C `time()`, which glibc documents as sharing the coarse realtime clock:
  https://www.sourceware.org/glibc/manual/2.38/html_node/Getting-the-Time.html.
  A stale second at this boundary is consistent with the observed acceptance;
  the log does not prove the exact verifier clock sample. The Go fixture now
  waits until `NotAfter + 2s`, crossing a complete expired second while the
  native handshake is already in flight. All expiry/index, no-READY/data and
  prompt-rejection assertions remain unchanged. TLS code is unchanged.
