module github.com/qigao/salts-core/tests/independent/tlcp

go 1.24.0

require (
	gitee.com/Trisia/gotlcp v1.4.3
	github.com/emmansun/gmsm v0.41.1
)

require (
	github.com/qigao/salts-core/crypto/tests/e2e/fixtures v0.0.0
	golang.org/x/crypto v0.48.0 // indirect
)

replace github.com/qigao/salts-core/crypto/tests/e2e/fixtures => ../../../../crypto/tests/e2e/fixtures
