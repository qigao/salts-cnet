module saltscore-independent-tls-tests

go 1.26.10

require github.com/qigao/salts-core/crypto/tests/e2e/fixtures v0.0.0

require (
	github.com/emmansun/gmsm v0.41.1 // indirect
	golang.org/x/crypto v0.48.0 // indirect
)

replace github.com/qigao/salts-core/crypto/tests/e2e/fixtures => ../../../../crypto/tests/e2e/fixtures
