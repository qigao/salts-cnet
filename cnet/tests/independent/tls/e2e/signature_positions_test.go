package tls_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func TestCertificateSignaturePositions(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		f, chain := validityIdentity(t, ec, "upper_intermediate", func(*x509.Certificate) {}, false)
		rootPEM, err := os.ReadFile(f.ca)
		if err != nil {
			t.Fatal(err)
		}
		root, rest := pem.Decode(rootPEM)
		if root == nil || root.Type != "CERTIFICATE" || len(rest) != 0 {
			t.Fatal("expected one independent root")
		}
		// Present the issuer of every deliberately damaged certificate. Root
		// discovery has a different result when no candidate verifies the top CA.
		chain = append(chain, root.Bytes)
		for target := 0; target < 3; target++ {
			for _, accept := range []bool{false, true} {
				wire := append([][]byte(nil), chain...)
				if !accept {
					wire[target] = append([]byte(nil), wire[target]...)
					wire[target][len(wire[target])-1] ^= 1
				}
				for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
					for _, mode := range []string{"file", "pem", "der"} {
						t.Run(fmt.Sprintf("ec_%t/index_%d/tls%d/%s/accept_%t", ec, target, version, mode, accept), func(t *testing.T) {
							if mode != "file" {
								t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
							}
							if !accept {
								t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "signature")
								t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", fmt.Sprint(target))
							}
							runValidityPeer(t, f, wire, version, accept, "localhost")
						})
					}
				}
			}
		}
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("ec_%t/unverifiable_top_without_presented_issuer/tls%d", ec, version), func(t *testing.T) {
				wire := append([][]byte(nil), chain[:3]...)
				wire[2] = append([]byte(nil), wire[2]...)
				wire[2][len(wire[2])-1] ^= 1
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "anchor")
				runValidityPeer(t, f, wire, version, false, "localhost")
			})
		}
	}
}
