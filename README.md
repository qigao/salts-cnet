# SaltsCore network SDK

This checkout builds the `SaltsNet` CMake project. It owns Crypto, CNet and
SCTP. The installed package remains `SaltsCore` with the existing `Salts::*`
targets. The integration branch is `chore-housing-keeping`.

The foundation modules now belong to [SaltsBase](https://github.com/qigao/salts-base).
They are consumed as an installed SDK; this repository does not rebuild or copy
Core, NativeIO, ASN1, URI, TinyTest, Media or their implementations.

| Module | Public targets | Tests and support files |
| --- | --- | --- |
| `crypto/` | `Salts::Crypto` | `crypto/tests/{algorithms,asn1,tls,x509}` |
| `cnet/` | `Salts::CNet` | `cnet/tests/`, including owner, independent peers and static-owner fixtures |
| `sctp/` | `Salts::SCTPWire`, `Salts::SCTP`, `Salts::SCTPDTLS` | `sctp/tests/`, including private engines, independent peers and secure DTLS tests |

Each module adds its own test graph with `BUILD_TESTS`. `BUILD_BENCHMARK`
selects the existing optional measurement cases and requires `BUILD_TESTS`.
There is no root test aggregator or module-subset switch. Private SCTP engines
are built only with their module's tests. The SCTP public headers are
`<sctp_wire.h>`, `<sctp_session.h>` and `<sctp_dtls.h>`.

## Dependencies and ownership

Set `SALTS_BASE_ROOT` to a matching released SaltsBase SDK (0.1.0 or newer). Configuration
uses only that root and fails if the package or its required components are
missing. Core thread, memory and IPC calls use SaltsBase's current public names
and headers; no compatibility aliases or private source paths are added.
CNet listener composition uses SaltsBase's installed `<native_io_accept.h>`.

Crypto links the required vcpkg `GmSSL::GmSSL` provider (`3.2.0#44`), including
the reviewed extensions pinned by `crypto/gmssl-extensions/source-lock.json`.
The GmSSL registry baseline is recorded in `vcpkg-configuration.json`; the
remaining dependency registry keeps its own baseline. The configured cache
checkout's overlay ports must agree with these requirements. An older local
GmSSL overlay cannot supply the merged DTLS/TLS/ShangMi APIs.

CNet remains the shared runtime owner of its linked Crypto/GmSSL implementation.
SCTP stays provider-independent; the explicit `SCTPDTLS` target composes it with
CNet. TLS verification, retained buffers, completion ownership, cancel/drain
and exact mode semantics are preserved. See [Crypto coverage](crypto/docs/SHANGMI-COVERAGE.md)
for the finite supported profiles and remaining qualification gates.

SaltsBase's package also resolves its Media archive's JPEG/libyuv dependencies;
the manifest supplies those imports without adding a Media implementation here.
Runtime paths include the selected vcpkg prefix, SaltsBase's runtime and, for
Windows llvm-mingw, the selected compiler's runtime directory.

## Build and test

Use the versioned `CMakeUserPresets.json`. Populate the required environment
inputs from [.env.example](.env.example); CMake does not load `.env` itself.
On Windows, enter the configured Visual Studio developer environment, or use
`cmake/WithVs.cmd` after setting `VSDEVCMD_BAT`.

```powershell
cmake/WithVs.cmd cmake --preset native-release-user
cmake/WithVs.cmd cmake --build --preset native-release-user
cmake/WithVs.cmd ctest --preset native-release-user --output-on-failure
cmake/WithVs.cmd cmake --build --preset install-native-release-user
```

POSIX LLVM uses `llvm-native-release-user`; existing sanitizer and Android
profiles remain in the user presets. CI configures the complete graph, builds
it without target filtering, and runs the formal tests through CTest. Android
is build-only unless an explicit device runner is provided.

CI resolves the latest stable [SaltsBase release](https://github.com/qigao/salts-base/releases/latest).
It checks the release API's manifest digest, selects the exact platform/compiler
entry, checks the archive SHA-256 and extracts the SDK with Python's safe data
filter. The manifest records source and producer-CI provenance. It does not
require a build of moving master or consume expiring workflow artifacts.

Release 0.1.0 provides Windows x64 MSVC/LLVM-MinGW, Linux x64 Clang/GCC,
macOS ARM64, and Android arm64/x64 SDKs. It includes the public accept header
and the retained startup repairs. Its Core headers use `<core/...>`, ASN1 uses
`<asn1.h>` and `<asn1_value.h>`, and coroutine headers use `<salts/coro_*.h>`.
Consumers use these public headers directly without draft-layout aliases.

The existing Windows ARM64, Linux ARM64 and macOS x64 qualification lanes have
no matching SDK in 0.1.0. They fail with an explicit missing-platform error;
they do not select another architecture or skip tests. The sanitizer lanes use
the released Linux x64 Clang foundation and instrument this network graph;
that does not qualify the prebuilt foundation itself under sanitizers.

## Integration and rollback

This branch retains the module split while carrying forward the Crypto/CNet/
DTLS/SCTP changes through merged master `ffade4c280286e247ea67733432b6fd9226fb5e1`,
including #274/#275/#277 and their formal regression cases. Tests, fixtures and
registration move together; the independent Go peers require Go 1.26.10.
Shared fixtures retain one owner: Crypto owns direct TLS helpers and PKCS12
creation; CNet owns the independent protocol peers reused by policy tests.

Media/#197 is a reference-only draft in its separate branch. Its Frame V2/GPU
proposal is not integrated into this network SDK and has no release or device
qualification claim. Issues #188/#219/#276 retain their independent gates.

Rollback the repository split as a coordinated SDK/configuration change, with
separate installation prefixes. Do not restore removed modules beside their
SaltsBase owners or install parallel compatibility implementations.
