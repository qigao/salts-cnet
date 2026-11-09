# qigao/crypto repository retirement — native source ownership

SaltsCore is the canonical source home for the module-local `asn1/` and
`crypto/` interfaces, implementation, CI and package configuration. The former
`qigao/crypto` repository is a historical donor. Its read-only archival was
recorded in [the migration audit](https://github.com/qigao/salts-core/issues/147#issuecomment-6562099755)
on 2026-11-02; preserve its source history and outstanding retirement records.

`Salts::ASN1` owns the independent BER/DER C11 codec. The root graph assembles
and installs it, and Crypto consumes that target. It is not a TLS engine.

`Salts::Crypto` produces one first-party static facade archive, including its
private Ed448 libecc objects. The TLS provider is the **separate imported
`GmSSL::GmSSL` static archive** installed by the pinned vcpkg port. The old
full source mirror and OBJECT build under `crypto/native/gmssl/` were removed
by [PR #149](https://github.com/qigao/salts-core/pull/149). There is no provider
archive merge or second local GmSSL compilation.

The root `vcpkg.json` declares GmSSL, and `vcpkg-configuration.json` selects
its custom registry baseline. Crypto uses plain required CMake package
resolution; the unified SaltsCore installed configuration imports GmSSL and
ASN1 and exports `Salts::Crypto` with the other SDK targets. Direct Crypto
consumers use `find_package(SaltsCore CONFIG REQUIRED)`; the separate Crypto
package configuration is retired, while its archive/header interfaces remain.
Missing dependencies fail configuration. The extension sources and recipes
belong to `crypto/gmssl-extensions/`; its
[source lock](../crypto/gmssl-extensions/source-lock.json) records upstream,
registry, port-tree, extension-checkout and original blob identities. The
active package is `gmssl 3.2.0#18`, including the TLS corrections qualified
in [PR #172](https://github.com/qigao/salts-core/pull/172).

Production CNet calls only the opaque `<crypto/tls_stream.h>` interface after
[PR #173](https://github.com/qigao/salts-core/pull/173). Crypto owns private
provider state, TLS/TLCP and certificate verification. CNet owns transport
progress, NativeIO buffer leases, cancellation and deadline/terminal routing.
Crypto and its external GmSSL archive link transitively into the single CNet
shared runtime. CNet consumers link `Salts::CNet`. Independent Monocypher
(Secure KCP) and Reed (GF256 FEC) remain separate libraries under `vendor/`.

Preserve the migration's original source and patch records, including the
unmerged donor work from qigao/crypto PR #43. Source relocation and package
ownership do not establish a new TLS engine, release qualification, or one
physical owner across arbitrary independently linked DSOs.

The existing LLVM CTest matrix exercises native Linux/macOS/Windows x64 and
ARM64, Linux sanitizers, TLS1.2/1.3, ShangMi/TLCP, CA/SAN/mTLS, algorithm and
X.509 contracts, Secure KCP/FEC, and real CNet/DSO ownership. Android jobs
compile the graph; they do not provide device runtime evidence. Tests use the
project's formal registrations and user presets, without extra consumer,
installer or probe projects.

Authenticated peer shutdown remains distinct from local output flushing and
TCP EOF. [Issue #152](https://github.com/qigao/salts-core/issues/152) tracks
that semantic gate and its observed-completion cancellation regression;
source architecture completion alone cannot close a failing runtime gate.
[Issue #153](https://github.com/qigao/salts-core/issues/153) separately tracks
the remaining standalone test-driver disposition. Historical donor retirement
records remain under [Crypto #45](https://github.com/qigao/crypto/issues/45).
