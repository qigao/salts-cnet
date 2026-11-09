# Original Zstd API in the Core owner

## Source and provider

The seven `cmeta_zstd_*` functions remain part of `Salts::Core`. The optional
`SALTSCORE_BUILD_ZSTD=ON` configuration adds their original implementation to
that shared owner and links the original provider as a private static archive.
The default foundation build does not require the provider or install a header
whose functions are unavailable.

The source donor is [`qigao/salts` at
`386f81328c656f416d61a6d2ef662f05443e1b4a`](https://github.com/qigao/salts/tree/386f81328c656f416d61a6d2ef662f05443e1b4a/utils).
The bounded source mapping is:

| Frozen input | Native owner/test path | Treatment |
| --- | --- | --- |
| `utils/include/cmeta_zstd.h` | `core/include/cmeta_zstd.h` | Replace only `<platform.h>` with `"cmeta_api.h"` |
| `utils/src/cmeta_zstd.c` | `core/src/cmeta_zstd.c` | Exact original bytes |
| `utils/tests/test_cmeta_zstd.c` | `core/tests/test_cmeta_zstd.c` | Exact original bytes; all six original cases run |

`core/tests/test_original_zstd_provenance.py` reverses that single header include
change and compares all three Git blobs/sizes to the frozen manifest. It also
checks all seven public declarations, rejects source drift or a missing
original test, and checks the retained provider registry and license. It does
not change the original migration inventories or accept pending work.

The donor selects the custom registry
[`qigao/vcpkg-cache@b8bcce436838b716522bb2c8b35438b47ac1830b`](https://github.com/qigao/vcpkg-cache/tree/b8bcce436838b716522bb2c8b35438b47ac1830b/ports/zstd).
Its Zstd port is `1.6.0-dev.20260701#0`, with upstream source pinned to
[`facebook/zstd@5c7b7bad26808e6b40ac3b3d0075466e27738a9d`](https://github.com/facebook/zstd/tree/5c7b7bad26808e6b40ac3b3d0075466e27738a9d).
The port's source-archive SHA512 is
`2dcc3b4a7d9af46d70aa560cbfa2a24919b039b847f9ffbf183548e26093d2c288afa2aaccc1a5d90237fc1b31ae5e1fa4e132d2c656f0a65a2faeb5d09f775c`.
It builds the static library with legacy-format and multithreading support;
shared libraries, programs, upstream tests and contrib programs are disabled.
The same registry selection already exists in SaltsCore. The `zstd` manifest
feature enables that port without changing its revision.

The CMake package version exposed by this development snapshot is `1.6.0`.
Configuration requires that exact version and a real
`zstd::libzstd_static` target. Version metadata alone does not identify the
development commit: release builds must also use the pinned registry, and
manual validation must record its exact source revision. The local system
Zstd 1.5.5 was not used as a substitute.

The original provider's BSD license is retained at
`core/licenses/zstd.LICENSE` and installed under
`share/licenses/SaltsCore/zstd/LICENSE` when the feature is enabled. Its
upstream Git blob is `75800288cc243f164b9d130f125e2ffae28f8e39`.

## Build and installed use

The source profile requires:

```sh
cmake -S . -B build-zstd \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=ON \
  -DSALTSCORE_BUILD_ZSTD=ON \
  -DSALTSCORE_BUILD_TINYTEST=ON \
  -DCMAKE_TOOLCHAIN_FILE=<pinned-vcpkg-toolchain> \
  -DVCPKG_MANIFEST_FEATURES=zstd \
  -DCMAKE_INSTALL_PREFIX=<sdk-prefix>
cmake --build build-zstd --config Release
ctest --test-dir build-zstd -C Release --output-on-failure \
  --no-tests=error -R '^saltscore[.](original_zstd|zstd_native_contract|original_zstd_source_provenance|zstd_private_archive)$'
cmake --install build-zstd --config Release
```

Use the platform's pinned target/host triplets with that toolchain. A manual
provider build can instead supply its verified installation through
`CMAKE_PREFIX_PATH`; the actual pinned source and port settings must be
recorded. Missing providers and missing TinyTest in an enabled conformance
build fail configuration. `BUILD_TESTS=OFF` builds the production owner.

Installed clients use `find_package(SaltsCore 0.1 CONFIG REQUIRED)`, link only
`Salts::Core`, and include `<cmeta_zstd.h>`. `<cmeta_error.h>` provides the
existing `SALTS_*` result vocabulary. `SALTSCORE_HAS_ZSTD=1` advertises that
this optional API was built into the imported Core target. Clients need no
provider header, static library or Zstd package discovery.

`tests/zstd-installed` is an independent C11/C++17 project. It rejects an SDK
without the feature, explicitly disables `find_package(zstd)`, checks all
seven signatures and calls every original function through the installed
Core library. Its only library dependency is `Salts::Core`; normal Core native
dependencies arrive through that target.

## Preserved byte, error and ownership semantics

The wrapper performs one-shot byte compression and decompression into
caller-owned destination storage. It never applies UTF-8 decoding, string
termination or text normalization. Source memory is borrowed for the call;
the caller retains both buffers. There is no returned handle, retained input
pointer or cross-owner allocation to release.

Compression level 0 selects the provider default. Other accepted values come
from the original minimum/maximum level queries. A NULL compression source is
valid only with zero source length, and compression always requires a non-NULL
destination. Empty-frame decompression permits a NULL destination only with
zero destination capacity; the source must still contain a frame.

The original mapping remains byte-identical:

| Outcome | Existing result |
| --- | --- |
| Invalid pointer/size combination or unsupported compression level | `SALTS_EINVAL` |
| Compression bound or declared frame size outside `size_t` | `SALTS_ERANGE` |
| Insufficient destination capacity | `SALTS_ENOSPC` |
| Malformed, truncated or unsupported frame, including mapped dictionary/checksum errors | `SALTS_EPROTO` |
| Content-size query on a frame with no declared content size | `SALTS_ENOTSUP` |
| Provider allocation failure | `SALTS_ENOMEM` |
| Other provider errors | Original `SALTS_EIO` fallback |

Every failed public call preserves its output-size scalar. Destination buffer
contents are not promised to remain unchanged after a failed provider call.
The adapter continues to forward the original provider behavior: the content
size query reads the frame header without validating the whole body, while
decompression requires valid frame data. The decompressor also accepts
concatenated frames; the size query reports the first frame's declared size.
The migration does not add a stricter single-frame validator or streaming API.

## Private archive boundary

The first local binary inspection found that a CMake `PRIVATE` link alone left
the archive's `ZSTD_*` symbols exported by Core on ELF. That allowed process
symbol interposition despite the intended private provider. The Core ELF link
now applies `--exclude-libs` to this archive's exact filename. This does not
change the original adapter or provider source, algorithms, ISA requirements,
or other Core exports. The
[GNU linker documentation](https://sourceware.org/binutils/docs/ld/Options.html)
defines these archive symbols as hidden on ELF.

`saltscore.zstd_private_archive` inspects the actual ELF artifact. It requires
exactly the seven original adapter exports, no escaped Zstd implementation
symbols and no shared Zstd dependency. A temporary real relink with that one
option removed was rejected by the check, demonstrating its failure case.
Windows/macOS execution and their actual symbol surfaces still require their
own platform evidence; the ELF result is not extended to them.

## Validation and remaining admission

The 2026-10-29 local worktree was based on
`6c8b5b91fda1adc09038964472cbeab2520b201e` with uncommitted migration changes.
GNU C/C++ 13.3.0 built the exact provider commit with the original port settings
and PIC, then built the complete configured Core graph. The sanitizer profile
also rebuilt that same provider with ASan/UBSan; it did not use the local
system codec or an uninstrumented provider for those local results.

| Check | Observed local result |
| --- | --- |
| `saltscore.original_zstd` | All six original cases passed |
| `saltscore.zstd_native_contract` | Standard raw frames, unknown content length, truncation, concatenated frames, bounded output and 64-bit declared-size path passed |
| `saltscore.original_zstd_source_provenance` | All four source/API/registry/license and negative checks passed |
| `saltscore.zstd_private_archive` | Seven adapter exports; private archive and no Zstd DSO dependency |
| `sdk.zstd_c11`, `sdk.zstd_cpp17` | Both installed consumers passed; all seven functions called |
| ASan + UBSan + leak detection | All four native/source/binary CTests and both installed consumers passed, with the provider also instrumented |
| Negative configuration | Missing provider, missing TinyTest and missing installed Core feature all rejected |
| Actual binary negative check | A relink without archive hiding was rejected |

The extra native contract uses independent standard raw-block frames based on
the pinned provider's format specification. It validates NUL and non-UTF-8
payload bytes and checks guard bytes outside the advertised destination.
Installed clients additionally round-trip every possible byte value, mutate
their original source after compression, and exercise the original
error/output-size and empty-content behavior.

Leak detection ran with normal local `/proc` access. No sanitizer was disabled
and no production or test behavior was changed for instrumentation. These are
working-tree results, not a completed exact-commit release qualification.

`.github/workflows/zstd-native.yml` defines exact-revision Linux Release,
Linux ASan/UBSan/leak-check, Windows and macOS runs. It builds the complete
configured graph, runs the original and added tests, installs the SDK and runs
the independent consumers. The workflow records the selected archive SHA256
and candidate revision. Its sanitizer job instruments Core and clients while
using the pinned cached provider; this scope is recorded explicitly. The
workflow was syntax-checked locally and has not yet produced remote results.

Windows, macOS, mobile and 32-bit execution remain pending. Provider allocation
failure and every legacy-format/error-code branch have not all been driven by
these tests; preserving their source and provider settings is not a claim of
exhaustive runtime coverage. The frozen 2,975-file and 610-function obligations
remain unchanged, and this candidate migration does not mark them complete or
clear the deferred AC/Levenshtein work. Existing Draft decisions are unchanged.
