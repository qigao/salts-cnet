module github.com/qigao/salts-core/tests/independent/shangmi

go 1.26.10

require (
	github.com/emmansun/gmsm v0.44.0
	github.com/iuboy/pollux-go v0.5.0
	github.com/qigao/salts-core/crypto/tests/e2e/fixtures v0.0.0
	golang.org/x/crypto v0.54.0
)

replace github.com/qigao/salts-core/crypto/tests/e2e/fixtures => ../../../../crypto/tests/e2e/fixtures
