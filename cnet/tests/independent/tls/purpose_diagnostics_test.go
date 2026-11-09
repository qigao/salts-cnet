package tls_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func runNativeMutualPeer(t *testing.T, server, client identity, version int, ec, accept bool) {
	t.Helper()
	outcome, scheme := "reject-server", "2"
	if accept {
		outcome = "accept"
	}
	if ec {
		scheme = "1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, *native, "--signature-mtls", server.ca, client.ca, server.cert, server.keyFile, client.cert, client.keyFile, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)), fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw)), "-", "0", fmt.Sprint(version), scheme, scheme).CombinedOutput()
	if err != nil {
		t.Fatalf("native mTLS: %v\n%s", err, out)
	}
}

func TestPurposeDiagnostics(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		for _, failure := range []string{"expired_before_usage", "basic_constraints"} {
			f, chain := validityIdentity(t, ec, "leaf", func(c *x509.Certificate) {
				if failure == "expired_before_usage" {
					c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
					c.KeyUsage = x509.KeyUsageKeyEncipherment
				} else {
					c.IsCA = true
				}
			}, false)
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(fmt.Sprintf("ec_%t/%s/tls%d", ec, failure, version), func(t *testing.T) {
					reason := "certificate"
					if failure == "expired_before_usage" {
						reason = "expired"
						t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
					}
					t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
					runValidityPeer(t, f, chain, version, false, "localhost")
				})
			}
		}
		for _, target := range []string{"leaf", "intermediate", "upper_intermediate", "anchor"} {
			for _, usage := range []string{"ku", "eku"} {
				for _, accept := range []bool{false, true} {
					f, chain := validityIdentity(t, ec, target, func(c *x509.Certificate) {
						if usage == "eku" {
							c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
							if accept {
								c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
							}
						} else if target == "leaf" {
							c.KeyUsage = x509.KeyUsageKeyEncipherment
							if accept {
								c.KeyUsage = x509.KeyUsageDigitalSignature
							}
						} else {
							c.KeyUsage = x509.KeyUsageCRLSign
							if accept {
								c.KeyUsage |= x509.KeyUsageCertSign
							}
						}
					}, false)
					for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
						for _, mode := range []string{"file", "pem", "der"} {
							t.Run(fmt.Sprintf("ec_%t/%s/%s/tls%d/%s/accept_%t", ec, target, usage, version, mode, accept), func(t *testing.T) {
								if mode != "file" {
									t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
								}
								if !accept {
									t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "purpose")
									if target != "anchor" {
										t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", map[string]string{"leaf": "0", "intermediate": "1", "upper_intermediate": "2"}[target])
									}
								}
								runValidityPeer(t, f, chain, version, accept, "localhost")
							})
						}
					}
				}
			}
		}
		server := makeIdentity(t, "purpose server", ec, nil)
		for _, usage := range []string{"ku", "eku"} {
			client := makeIdentity(t, "purpose client", ec, nil, func(c *x509.Certificate) {
				if usage == "ku" {
					c.KeyUsage = x509.KeyUsageKeyEncipherment
				} else {
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
			})
			for _, version := range []int{12, 13} {
				for _, mode := range []string{"file", "pem", "der"} {
					t.Run(fmt.Sprintf("server/ec_%t/%s/tls%d/%s", ec, usage, version, mode), func(t *testing.T) {
						if mode != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						}
						t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "purpose")
						t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
						runNativeMutualPeer(t, server, client, version, ec, false)
					})
				}
			}
		}
	}
}
