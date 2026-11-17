package shangmiinterop

import (
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func damageChainSignature(t *testing.T, f fixture, index int) {
	t.Helper()
	data, err := os.ReadFile(f.certPath)
	if err != nil {
		t.Fatal(err)
	}
	var chain []byte
	count := 0
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("invalid independent certificate chain")
		}
		if count == index {
			block.Bytes[len(block.Bytes)-1] ^= 1
		}
		chain = append(chain, pem.EncodeToMemory(block)...)
		data = rest
		count++
	}
	if index < 0 || index >= count {
		t.Fatal("signature target outside independent chain")
	}
	if err = os.WriteFile(f.certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	// Regenerate the formal memory inputs from the actual modified PEM chain.
	memoryFixtures(t, f.caPath, f.certPath, f.keyPath)
}

func testMutualCertificateSignaturePositions(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, profile := range []struct{ id, version int }{{0, 12}, {0, 13}, {1, 0}} {
		for _, rejectClient := range []bool{false, true} {
			for target := -1; target < 3; target++ {
				server := depthFixture(t, profile.id == 1, false, 2, true)
				client := depthFixture(t, profile.id == 1, true, 2, true)
				outcome := "accept"
				if target >= 0 {
					bad := server
					outcome = "reject-client"
					if rejectClient {
						bad, outcome = client, "reject-server"
					}
					damageChainSignature(t, bad, target)
				}
				for _, mode := range []string{"file", "pem", "der"} {
					t.Run(fmt.Sprintf("profile_%d/tls%d/client_%t/index_%d/%s", profile.id, profile.version, rejectClient, target, mode), func(t *testing.T) {
						if mode != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						}
						if target >= 0 {
							t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "signature")
							t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", fmt.Sprint(target))
						}
						configuredMutualCase(t, "--chain-signature-mtls", server, client, profile.id, profile.version, 0, 0, outcome)
					})
				}
			}
		}
	}
}
