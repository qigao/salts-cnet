# DTLS interoperability test dependencies

The Go modules in `crypto/tests/algorithms/independent`, `cnet/tests/tickets`
and `sctp/tests/secure` use the following packages exclusively for formal
independent DTLS/SCTP peers. Versions and checksums are recorded in each module's
`go.mod` and `go.sum`. These packages are restored from their
upstream modules, with no vendored source or local modifications. The production
cryptographic provider remains GmSSL.

| Package | Version | Upstream license |
| --- | --- | --- |
| github.com/pion/dtls/v3 | v3.1.15 | [MIT](https://github.com/pion/dtls/blob/v3.1.15/LICENSE) |
| github.com/pion/logging | v0.2.4 | [MIT](https://github.com/pion/logging/blob/v0.2.4/LICENSE) |
| github.com/pion/sctp | v1.10.0 | [MIT](https://github.com/pion/sctp/blob/v1.10.0/LICENSE) |
| github.com/pion/randutil | v0.1.0 | [MIT](https://github.com/pion/randutil/blob/v0.1.0/LICENSE) |
| github.com/pion/transport/v4 | v4.0.1 | [MIT](https://github.com/pion/transport/blob/v4.0.1/LICENSE) |
| github.com/pion/transport/v5 | v5.0.0 | [MIT](https://github.com/pion/transport/blob/v5.0.0/LICENSE) |
| golang.org/x/crypto | v0.48.0 | [BSD 3-Clause](https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.48.0:LICENSE) |
| golang.org/x/sys | v0.41.0 | [BSD 3-Clause](https://cs.opensource.google/go/x/sys/+/refs/tags/v0.41.0:LICENSE) |
| golang.org/x/time | v0.14.0 graph constraint, matching the existing SCTP oracle | [BSD 3-Clause](https://cs.opensource.google/go/x/time/+/refs/tags/v0.14.0:LICENSE) |

## Pion MIT license

Pion DTLS and transport: Copyright (c) 2026 The Pion community <https://pion.ly>

Pion logging: Copyright (c) 2023 The Pion community <https://pion.ly>

Pion SCTP: Copyright (c) 2026 The Pion community <https://pion.ly>

Pion transport v4: Copyright (c) 2023 The Pion community <https://pion.ly>

Pion randutil: Copyright (c) 2020 Pion

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Go supplementary packages BSD license

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Google LLC nor the names of its contributors may be used
  to endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
