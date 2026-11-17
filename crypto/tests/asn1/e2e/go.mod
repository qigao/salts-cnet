module github.com/qigao/salts-core/crypto/tests/asn1/e2e

go 1.24.0

require (
	github.com/emmansun/gmsm v0.41.1
	github.com/qigao/salts-core/crypto/tests/e2e/fixtures v0.0.0
	golang.org/x/crypto v0.48.0
)

replace github.com/qigao/salts-core/crypto/tests/e2e/fixtures => ../../e2e/fixtures
