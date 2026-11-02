# Historical local Crypto and CNet build (2026-10-29)

> **Historical snapshot only, NOT the current vcpkg migration architecture or
> current CI qualification evidence.** The archived measurements below were
> made while GmSSL native sources were locally compiled into Crypto.
> Current PR #149 instead imports a separate **GmSSL 3.2.0#17** static archive,
> retains first-party `Salts::Crypto`, and audits both physical archives and
> production CNet plugin/DSO ownership. See
> [current ownership contract](../crypto/docs/STATIC-SINGLE-OWNER.md).
>
> Do not reuse any success figures below to qualify the current HEAD.

Date: 2026-10-29. Status: Draft source/build repair, not release admission.

## Change

Core now always assembles ASN1, Crypto, URI, the existing private CNet helpers,
and the complete production CNet target. `SALTSCORE_BUILD_CNET` and
`CRYPTO_GMSSL_ROOT` are retired inputs. Supplying either produces an explicit
configuration error, including an attempted `SALTSCORE_BUILD_CNET=OFF`.
There is no replacement external TLS prefix or provider selection flag.

`Salts::Crypto` is the single public static Crypto archive. It contains its
seven existing facade translation units, the existing 33-unit private
libecc Ed448 subset, and 84 locally compiled native units. The native source,
headers and license come from pinned vcpkg GmSSL; its imported STATIC target is not
exported or installed independently. No GmSSL package lookup, imported native
archive, post-build archive merge, provider DSO or duplicate public target is
part of this build.

Production `cnet/src/cnet_tls.c` remains unchanged. Its private native calls
link the local Crypto archive. It keeps the existing version/range handling,
standard and ShangMi profiles, CA/SAN checks, ALPN, certificate inspection,
close handling and original Owner/NativeIO lifetimes. This does not promote
the narrower `cnet_tls_crypto_qualification.c` adapter into production.
The renamed `SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION` option enables only the
additional isolated qualification tests and defaults to OFF.

The SDK exports Crypto and CNet by default and requires its own sibling ASN1
and Crypto packages. Crypto/ASN1/URI remain STATIC; CNet and the stateful
foundation modules remain SHARED. Installed C11 and C++17 Crypto, URI, CNet
and ABI-owner consumers cannot silently disappear when a target is missing.

## Inputs and behavior boundary

The native implementation retains its GmSSL ancestry and Apache-2.0 license.
The complete input and derivation record is in `source-lock.json` and
`upstream-to-local.patch`. The 166 source/header/license inputs reproduce
byte-for-byte from the fixed upstream source. The Core-owned native CMake
recipe has a separate reviewed blob identity; its actual common/platform
source lists and feature definitions must match the recorded profile.

The former production CNet registry selected `gmssl 3.2.0#13`. The shared
local owner uses the existing Crypto qualification's #14 hardening plus
Core's existing mTLS/record corrections. This difference is recorded
explicitly; the new backend is not claimed to be byte-identical to #13.

Full implementation instrumentation found one additional SM4 issue: an
S-box byte was promoted to signed `int` before shifting left by 24. The local
correction casts to `uint32_t` before the shift. It preserves the 32-bit
substitution and known-answer output while removing undefined behavior.
The original blob, corrected blob and reason are recorded separately as
`local_hardening`; the reproduction patch includes the actual change.

An additional optional-client-certificate probe exposed two TLS 1.2 failure
modes: the server requests a certificate but allows its omission, while the
client has no certificate and receives a nonempty CA-name list. The original
#13 implementation was rebuilt in an isolated temporary directory and tested
with the same unchanged external-I/O source and fixtures. Both before and
after implementations fail in the same issuer-certificate check. The other
six tested TLS 1.2/1.3 modes pass on both sides. The 16 raw executions remain
12 PASS / 4 FAIL / 0 skip; no `WILL_FAIL` or success reclassification was used.
These two specific behaviors are pre-existing. They are not silently fixed,
and this bounded comparison is not evidence of universal TLS equivalence.

## Build

Use CMake 3.21 or newer, a C11 compiler, and a C++17 compiler when testing.
The normal networking dependencies remain the canonical pinned static
c-ares and KCP libraries and SIMDe headers. URI uses the real host re2c tool.
The manifest now makes these networking dependencies part of the base SDK;
the empty `cnet` feature is retained only for existing manifest callers.

```sh
python3 -B crypto/tools/check_local_native_source.py
cmake -S . -B build -DBUILD_TESTING=ON \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/verified-vcpkg-toolchain.cmake
cmake --build build --parallel
ctest --test-dir build --output-on-failure --no-tests=error
cmake --install build --prefix /path/to/sdk
```

The active CI workflows share the pinned non-crypto prerequisite setup. All
23 workflows retain their existing 35 jobs and runner/matrix strategy,
native tests, sanitizer repetitions, installed/relocated consumers and
runtime ownership audits. Each call must explicitly select its dependency
mode; an omitted or unknown mode fails before setup. Original source-build
jobs compile the locked manifest with the original fixed vcpkg scripts
`04a9d8e5212d01ee1dd9478eadd9caade4f8b0d4`. Original binary-cache rows continue
to require every exact package, without a source fallback. Expanding the
28 helper calls gives 86 matrix rows: 31 binary and 55 source, matching the
previous `c9103694` cache-step conditions row by row. Capture's standalone
iOS row uses source mode; the full SDK candidate iOS row remains binary.
Workflow syntax checking is not platform runtime qualification.

## Local verification

| Check | Observed result |
|---|---|
| Default Linux Core build with neither retired input | Complete build and install succeeded |
| Repaired CI source mode, using its fixed vcpkg scripts and actual root manifest | All eight dependency packages built from source; default Core build/install and 61/61 CTest checks PASS |
| Default SDK installed C11/C++17 consumers | 47/47 PASS |
| Full Linux Core source graph, including existing optional modules and M5/M6 | 164/164 PASS |
| Full SDK installed consumers | 53/53 PASS |
| Full SDK consumers after moving the installation and removing its original path | 53/53 PASS |
| Instrumented local native Crypto/CNet, original Owner and M5/M6 | 100/100 PASS with ASan, UBSan and leak detection; initial SM4 failure retained separately |
| Separate two-archive Crypto/ASN1 installation audit | PASS, unique static symbols and no provider export |
| Original installed Crypto C11/C++17 consumers | 2/2 PASS |
| Original installed Crypto ASN1 C11/C++17 consumers | 2/2 PASS |
| Installed TLS 1.2/1.3, auth, independent Python mTLS, cancellation and CipherBIO | 6/6 PASS |
| Original native #14 contract programs linked to local Crypto | 29/29 default contracts PASS; extra optional modes remain separately recorded as 33/35 PASS |
| Real production CNet archive/link-map/dynamic-import ownership | PASS; 12 audited native TLS entry points come from the local Crypto archive; both original plugins and loader contain no second Crypto archive |
| COFF owner-audit classification and negative obligations | Nine unit tests PASS; Linux real archive/map/import and two-plugin regression checks PASS; actual Windows result requires new CI |
| Native source derivation and compiled-profile admission | 166 inputs reproduced; five negative/positive admission tests PASS |
| Crypto PR43 handoff | 18/18 obligations preserved; eight negative/positive tests PASS |
| Core Python unit modules and negative source/owner gates | 119/119 PASS; the separate Zstd binary CLI is exercised by full CTest |
| SDK packaging Python checks | 29/29 PASS |
| Android arm64 API 24 default build/install and installed consumer linkage | 220 translation units, including 84 native Crypto units, and 47 real AArch64 ELF consumers; no device execution claimed |

The Linux installed consumers use an explicit SDK library search path.
Full-module consumers also use the verified existing non-crypto dependency
prefixes. These checks do not claim clean-machine runtime closure or trusted
release receipts. The Android check is cross compilation and linkage only.
The source-mode check first exposed missing host `pkg-config` and a missing
re2c `PATH` entry in the local minimal environment. Both failed configure
logs were retained. Providing the existing host tools completed the check;
no package version, implementation or manifest was changed to make it pass.

The historical PR43 CMake input is preserved in
`crypto/tests/migration/CMakeLists.original.txt`. Its change to local assembly
has an independently reviewed diff. Historical workflow/input snapshots and
all original source inventories retain their original bytes.

## Remote CI integration follow-up

The first remote runs of `dfbe182f` identified two mistakes in the new CI
integration. The unified prerequisite helper had imposed binary-cache
admission on jobs that previously built dependencies from source or did not
need those dependencies. For example, URI stopped before Core compilation
because all eight exact packages were absent. The explicit source/binary
selection above restores the original admission boundaries; it does not
reinterpret a cache miss as success.

Windows compiled and linked the default local implementation, but the new
physical-owner audit treated every COFF `External` symbol in a section as a
strong definition. This incorrectly counted coalescible CRT inline functions
and string constants as duplicate implementations. The standalone, SCTP,
native-module and CNet provider jobs respectively passed 59/60, 75/76,
113/114 and 94/95 tests; each failed only that audit. These are failed runs,
not accepted Windows qualification. The audit repair reads each archive
member's section-selection metadata, keeps all required native/facade symbols
under exact-once checks, and retains the production link-map and dynamic
dependency checks. It does not allow symbols by their CRT or string names.

On the same `dfbe182f` implementation, the Linux and macOS production CNet jobs,
Linux ASan/UBSan and TSan jobs, and all three Linux/macOS/Windows original
Owner/mTLS jobs completed successfully. Those results remain associated
with that commit. Follow-up source or audit changes require their own CI;
neither these results nor local checks are relabeled as trusted release
receipts for a different commit.

## Exact re2c host package

The shared CI prerequisite now uses the canonical curl-only action at
`qigao/vcpkg-cache@4864033d4e4bc70d182df6a33695582ec6fcc968`, with explicit
`Qigao.Re2c.Binary` version `4.6.5` and package SHA-256
`dfdcf77dfd36e60500532a3fcc8a1bd32dc2232edeb63e053267a712bc4489ed`.
The action verifies the archive digest, package identity and complete host
payload before extraction or execution. It does not select the latest version,
substitute a system tool or export a successful environment after a failure.

The original `4.6.4` Linux x64 package required `GLIBCXX_3.4.32`, which stopped
the existing Ubuntu 22.04 TinyCC and sanitizer jobs before their full Core
build steps. Pinning the old action commit had not pinned its NuGet package.
The upstream repair keeps re2c 4.6 and the same Unicode 17 data, while building
Linux x64 with GCC 11 on Ubuntu 22.04. Its actual maximum requirements are
`GLIBC_2.34`, `GLIBCXX_3.4.29` and `CXXABI_1.3.8`.

[Publication run 40852170873](https://github.com/qigao/vcpkg-cache/actions/runs/40852170873)
verified the same package on real Ubuntu 22.04 and 24.04, including Unicode
source generation, C11 compilation and execution, then published those exact
bytes. Core retains its original runners, source/binary dependency selection,
test commands and separate strict cache ABI pin. Package qualification does
not replace fresh Core CI or the final migration evidence gates.

## Remaining release gates

This repair does not mark the original 2,975 files or 610 explicitly public
functions as fully migrated. The strict final completeness command still
fails on unresolved source/installed-runtime evidence. AC/Levenshtein remain
out of implementation scope, with their original obligations still pending.
New source changes also require new current-commit platform qualification;
old SIMD receipts are not relabeled as evidence for this tree.

The existing platform/provider, clean-runtime closure, trusted receipt and
NuGet qualification blockers remain independent. No downstream repository was
read or tested for this repair. PRs #72 and #94 remain Draft and unmerged.
Version 0.1.000 remains unpublished because release admission is incomplete.
