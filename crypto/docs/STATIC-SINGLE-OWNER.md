# Canonical static archive and runtime ownership (GmSSL vcpkg migration)

**Status:** Draft; exact-HEAD CI is required. This document describes source and
link ownership, not a claim that platform and runtime gates already passed.

| Owner | CMake target | Physical archive | Purpose |
| --- | --- | --- | --- |
| `qigao/salts-base` ASN1 | `Salts::ASN1` | `libasn1.a` / `asn1.lib` | One BER/DER/OID, TLV and owned Value Tree implementation |
| `crypto/` | `Salts::Crypto` | `libsalts_crypto.a` / `salts_crypto.lib` | First-party TLS/CipherBIO facade, SHA/Ed448 and certificate format helpers |
| `qigao/vcpkg-cache` | `GmSSL::GmSSL` | **separate** `libgmssl.a` / `gmssl.lib` | Native TLS/TLCP and GmSSL algorithm provider, including source-pinned extensions |

Monocypher remains independently owned as `vendor/monocypher/` and Reed
GF(256) FEC as `vendor/reed/`. Neither is merged into the Crypto archive.
The original 170-file GmSSL source mirror is **not** in the SaltsCore tree.
Fifteen original extension inputs under `crypto/gmssl-extensions/` keep
immutable source-blob hashes, while the vcpkg port compiles them exactly once.

The GmSSL port is pinned through `vcpkg.json`, `vcpkg-configuration.json`
and the shared `setup-vcpkg-cache` action; the migration's current version
is **GmSSL 3.2.0#44**, as recorded by the GmSSL registry baseline and
`crypto/gmssl-extensions/source-lock.json`.
The port restores the previously qualified RFC 5746 TLS12/TLS13
range secure-hello guard without admitting TLS13-only/TLCP renegotiation.

## CMake ownership and SDK graph

The common project parent imports `GmSSL::GmSSL` before creating Crypto and
CNet subdirectories, so both see the same imported static provider. Crypto
links it privately as a static-library dependency, which becomes a transitive
link-only requirement for downstream consumers. The installed SaltsCore config
uses `find_dependency(GmSSL CONFIG REQUIRED)` and imports `Salts::ASN1`
from the separate SaltsBase SDK. It exports only its own Crypto/network targets. Do not install a second GmSSL
copy in the SaltsCore SDK or export an invented GmSSL implementation.

The ASN1 target itself does not link GmSSL; the unified SDK package discovers
GmSSL for its exported Crypto target. Crypto users consume
`Salts::Crypto` and its dependency closure via the pinned package manager;
they must not manually merge archives or provide an alternate TLS engine.

## Production CNet DSO and plugin evidence

`Salts::CNet` is the **single shared runtime owner** that extracts native
GmSSL TLS symbols and required Crypto facade symbols as linked. The real
`saltscore.cnet_native_crypto_owner` CTest invokes
`cnet/tests/owner/audit_native_crypto_owner.py` with both
`--archive <libsalts_crypto.a>` and `--gmssl-archive <libgmssl.a>`.
It enforces:

- Required native TLS entry points appear once in GmSSL, never in Crypto.
- Required first-party facade entries appear once in Crypto, never in GmSSL.
- No duplicate strong definitions across physical archives; no private native
  TLS/TLCP second engine in Crypto.
- The CNet production link-map attributes native members to GmSSL and any
  selected facade members to Crypto; Windows LLVM-MinGW uses matching physical
  COFF member metadata as well as the linker map.
- MSVC may discard the unused session-level `tls_get_peer_certificate_sha256`
  helper: CNet's stream facade hashes its parsed peer certificate directly.
  The archive audit still requires one physical definition in GmSSL; when the
  linker retains it, the runtime audit still requires that same GmSSL ownership.
- Two real CNet plugins import the production CNet DSO; neither plugin nor
  its native loader may extract independent Crypto/GmSSL static copies.
- No extra dynamic GmSSL/OpenSSL/Crypto runtime dependency is accepted.

The older `crypto/tools/audit_static_crypto.py` driver targets the retired
split Crypto/ASN1 SDK layout. It is not installed or used by the unified
SaltsCore graph. Current ownership qualification uses the production CNet
DSO/peer link-map tests described above.

**Release gates:** exact-HEAD Linux/Windows/macOS/Android builds, real TLS1.2,
TLS1.3, TLS12/13 range, CA/SAN, mTLS, ShangMi/TLCP, X.509 and digest tests,
sanitizers and the real cross-DSO ownership tests. No installer/consumer/probe
CI project is added. PR #149 remains Draft until all mandatory gates pass.
