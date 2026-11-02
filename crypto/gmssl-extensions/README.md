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

**Current integration boundary:** Core owns the complete native source in
`crypto/native/gmssl`. That directory includes the staged outputs of these
inputs, the pinned base source and the recorded TLS/X.509/algorithm patches.
It compiles one private OBJECT target, folded directly into the sole
`Salts::Crypto` static archive. No external GmSSL package is imported and no
post-build archive merge is performed. Production CNet privately links the
same local Crypto archive while retaining its complete original TLS source.

The original input blobs here remain unchanged and are checked against
`crypto/native/gmssl/source-lock.json`. They are provenance inputs, not a
second active compilation path. Do not compile both these inputs and their
staged native outputs, which would create duplicate definitions.

No generic Provider/DSO, second GmSSL library, public Crypto target
alias, or `providers/gmssl/` is added. This directory is an immutable
source record, not a separate build system.

The former external-port integration is historical: it staged these inputs
into its separately pinned GmSSL checkout and produced the static package
that Crypto then merged. The local source record preserves the exact
3.2.0#14 recipe identity and ordered derivation, including Core's already
owned mTLS/record corrections. It does not accept the later #15 port or a
different implementation implicitly. Source integrity, original contract,
sanitizer and TLS/CA/SAN qualification remain independent requirements.
