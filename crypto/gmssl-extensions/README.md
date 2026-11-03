# GmSSL extension source ownership

The Crypto-owned extension source directory preserves the original additional C11 source inputs:
MD5 (legacy protocol
interoperability only), DES-CBC (legacy protocol interoperability only),
AES Key Wrap (RFC 3394), bounded RSA encodings/private operations and
P-384 signature verification. The private TLS1.3 handshake reader is a
source-inclusion header, not an installed public interface.

The exact 13 original Git blobs were moved from
`qigao/vcpkg-cache/ports/gmssl`, preserving their original bytes. All
sources are Apache-2.0 as previously distributed with the GmSSL port.
The original upstream of the P-384 verifier is
`guanzhi/GmSSL@24ae482701a7b124826c382fffc55c19f76d475d`.

**Current integration boundary:** `qigao/vcpkg-cache/ports/gmssl` downloads
the pinned upstream source, applies these inputs from an immutable SaltsCore
commit, and packages the separate GmSSL static archive. The root manifest and
registry baseline select `gmssl 3.2.0#18`. Crypto uses
`find_package(GmSSL CONFIG REQUIRED)` and privately links `GmSSL::GmSSL`;
it does not compile a local `crypto/native/gmssl` mirror or merge provider
objects into its own archive.

[source-lock.json](source-lock.json) records the upstream commit, registry
commit, port tree, extension checkout and original input Git blob hashes.
The input sources and recipes remain unchanged. This directory supplies
provenance and port inputs; it is not another active compilation path or
standalone build system. Installed Crypto configuration imports the same
external GmSSL dependency explicitly.

Production CNet calls the opaque Crypto stream API. Crypto owns the private
GmSSL protocol state and identity verification; CNet owns NativeIO progress,
cancellation, deadlines and completion leases. The provider is linked
transitively into the single CNet shared runtime. Independent Monocypher and
Reed libraries remain under `vendor/`, outside Crypto.

Source/package integrity, authenticated peer shutdown, TLS/CA/SAN behavior,
sanitizers and physical DSO ownership have separate formal test coverage.
Neither package import nor a successful local close proves that a peer's
close_notify was authenticated.
