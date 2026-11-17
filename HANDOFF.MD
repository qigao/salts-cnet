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
- The renamed package passed local LLVM-MinGW configure/build, the focused
  resumption test, all 103 formal CTest cases (248.52 s), and installation.
  CI run `43394647730` at `a29cea5465b5423e512cb63a17d5e76b84f2fdad`
  passed all ten profiles: six POSIX native profiles with 104 tests each,
  two Windows profiles with 103 each, and two Android cross-build/install/
  16 KiB alignment profiles without device execution. The original SDK TARs
  were published as v0.1.12 with their manifest and SHA256SUMS; uploaded bytes
  were checked against GitHub's asset sizes/digests before publication.
- For `llvm-mingw-x64-release-user`, set
  `LLVM_MINGW_X64_INSTALL_PREFIX`, not only `INSTALL_PREFIX`: the user-preset
  environment replaces the latter with the former. A missing x64 value yielded
  an empty CMAKE_INSTALL_PREFIX during local validation, so installation wrote
  `/bin`, `/lib`, `/include` and `/share` on the current Windows drive. The
  corrected install used an explicit task stage and passed. Local `.env` now
  supplies the proper x64 input, and `.env.example` documents both presets.
  Existing root directories were present before this task; their files were
  preserved because a pre-install snapshot was unavailable. The affected-file
  list is `build/release-0.1.12/unintended-root-install-manifest.txt`; the local
  validation receipt and corrected stage manifest are beside it.

# Crypto backend encapsulation review (2026-11-17)

- Load only the existing nonsecret `.env` build inputs into the parent process.
  The selected vcpkg-cache checkout is exactly v0.1.3; fresh configuration
  resolves SaltsBase 0.1.8 and GmSSL from the selected LLVM-MinGW triplet.
  No upstream selectors or SDK contents were changed. The complete
  `native-release-user` configure/build and all 103 formal CTest cases pass
  (276.50 seconds). Logs are `build/review-upstream-{configure,build,ctest}.log`.
- HIGH: `PRIVATE GmSSL::GmSSL` on a static Crypto library still produces
  `$<LINK_ONLY:GmSSL::GmSSL>` in the installed target interface. The package
  config imports only Threads, leaving both that backend target and external
  SaltsBase targets unresolved unless a consumer loads them beforehand.
  Resolve the SDK's required link closure internally from the existing selected
  roots; downstream applications must only use the Salts public targets/API.
- HIGH: the freshly built Windows `cnet.dll` exports backend names including
  `gmssl_secure_clear`, `digest_init` and `sm2_sign`. A private link dependency
  does not itself seal the runtime ABI. Evidence is the real COFF export table
  in `build/review-upstream-exports.log`; existing owner audits do not reject
  these public exports. An explicit public export boundary and an assertion in
  the existing owner suite are needed, retaining all required CNet/Crypto APIs.
- The 53 public module headers contain no includes of GmSSL, libecc or
  Monocypher. The SDK export set contains no standalone libecc/Monocypher
  targets or their build macros. The checked CNet DLL has no renamed Monocypher
  or libecc prefix exports; their archives contain COFF exclude-symbols
  directives. This is Windows LLVM-MinGW evidence, not cross-platform ABI
  qualification. Monocypher currently belongs to the private CNet source owner.
- HTTPS credentials already admit RSA and EC P-256 identities with PKCS#8
  private keys. STANDARD supports TLS 1.2 ECDHE-RSA/ECDHE-ECDSA and TLS 1.3
  RSA-PSS/ECDSA handshake signatures; RSA-PSS-signed certificates remain outside
  the published contract. This review ran the formal TLS suite, not an HTTP
  application interoperability test. MySQL's standalone SHA-1 use still needs
  a public Crypto facade before its direct GmSSL header can be removed.
