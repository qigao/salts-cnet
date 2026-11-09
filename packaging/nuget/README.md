# SaltsCore.Native

Immutable LLVM-built SaltsCore SDK install trees for Windows, Linux, macOS and
Android, each in x64 and arm64 variants. Release `v0.1.002` maps to NuGet and
CMake version `0.1.2`.

Select `sdk/<rid>` for the target platform and configure CMake with that prefix
as `SALTSCORE_ROOT`.

The network-only SDK imports its foundation from a separate matching SaltsBase
installation. Set `SALTS_BASE_ROOT` to that SDK in addition to `SALTSCORE_ROOT`.
SaltsBase must provide `<native_io_accept.h>`. No Core/NativeIO/Media copy is
bundled back into this package after the repository split. Build/install success
is not release qualification of this new layout.
