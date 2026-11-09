# Housekeeping integration — 2026-11-09

- `chore-housing-keeping` is the network integration branch. Preserve the
  existing split into separately installed SaltsBase and module-owned tests.
  Carry Crypto/CNet/DTLS/SCTP source and formal cases through merged master
  `ffade4c280286e247ea67733432b6fd9226fb5e1`; #197's separate reference PR
  stays draft and is not part of this integration.
- SaltsBase now owns ASN1 names (`asn1_*`), Core sync (`sync_*`), clock/IPC
  and namespaced headers. Fix calls at their owner; do not copy the removed
  implementations or add old-name shims. CNet's two existing accept functions
  require the authorized public SaltsBase `native_io_accept.h` contract.
- Use a matching installed SDK via `SALTS_BASE_ROOT`. The formerly configured
  local cache overlay had GmSSL #18; the merged crypto APIs require #44.
  The GmSSL registry baseline and configured overlay must agree. The local
  environment was updated to the already qualified #44 contract checkout;
  no provider fallback was added. Credentials remain only in ignored `.env`.
- The moved Go peers are one directory deeper: their shared Crypto PKCS12
  fixture path needs four parent components. Three initial formal tests
  failed at that path; after correcting it all affected cases passed.
- Windows C++ tests also require the selected llvm-mingw runtime directory.
  Missing runtime DLLs produced 0xc0000135 or a loader wait. Correct the user
  preset's runtime PATH; do not copy runtime DLLs or replace the compiler.
  The task-owned loader wait was terminated and its original failure retained.
- Final validation: `cmake/WithVs.cmd cmake --build --preset native-release-user`,
  then `cmake/WithVs.cmd ctest --preset native-release-user --parallel 4
  --output-on-failure`: complete C11/C++17 graph built; 101/101 CTests passed
  in 62.99s. Logs: TEMP/salts-housekeeping-final-build.log and
  TEMP/salts-housekeeping-final-tests.log. Initial failures are retained in
  TEMP/salts-housekeeping-tests.log; six corrected cases also passed separately.
- NativeIO's public accept declarations preserve symbols and behavior. SaltsBase
  built the complete `ci-llvm-mingw-x64-release-user` graph; its native-I/O and
  C++ process-API CTests passed 2/2, then the normal install preset succeeded.
  Local acceptance exercised no physical camera or Android device. Linux,
  macOS, ARM64, Android and sanitizer execution on this split remain CI gates.
- CI requires a qualified SaltsBase producer artifact for its current master
  and the selected RID. No older artifact, missing module/test skip or automatic
  retry is allowed. This workflow has not been executed for the local split.

- The extracted foundation also retains strong Disruptor registration CAS and
  NativeIO bootstrap cancellation status publication, with the Core regression.
  Base commits 055e879/1b1a029 contain the public accept surface and these
  extraction repairs. The Media TSan fixture follows its owner independently
  of #197. Base's selected NativeIO/Disruptor/coroutine tests passed 3/3 (0.12s),
  and its SDK was installed before the final network run (101/101, 62.99s).
  The bootstrap callback follows the executor skill's accepted-task run-or-cancel
  and borrowed-argument lifetime contract. Initial failures remain in TEMP.
