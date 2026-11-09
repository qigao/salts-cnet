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

func TestVerificationTime(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		for _, target := range []string{"leaf", "intermediate", "anchor"} {
			for _, reason := range []string{"expired", "future"} {
				now := time.Now()
				fixed := now.Add(-36 * time.Hour)
				if reason == "future" {
					fixed = now.Add(36 * time.Hour)
				}
				f, chain := validityIdentity(t, ec, target, func(c *x509.Certificate) {
					if reason == "expired" {
						c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
					} else {
						c.NotBefore, c.NotAfter = now.Add(24*time.Hour), now.Add(48*time.Hour)
					}
				}, true)
				for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
					for _, mode := range []string{"file", "pem", "der"} {
						for _, explicit := range []bool{false, true} {
							t.Run(fmt.Sprintf("ec_%t/%s/%s/tls%d/%s/fixed_%t", ec, target, reason, version, mode, explicit), func(t *testing.T) {
								if mode != "file" {
									t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
								}
								if explicit {
									t.Setenv("SALTS_TEST_TLS_VERIFICATION_TIME", fmt.Sprint(fixed.Unix()))
								} else {
									t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
									if target != "anchor" {
										t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", map[string]string{"leaf": "0", "intermediate": "1"}[target])
									}
								}
								runValidityPeer(t, f, chain, version, explicit, "localhost")
							})
						}
					}
				}
			}
		}
	}
	f, chain := validityIdentity(t, true, "leaf", func(*x509.Certificate) {}, true)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, boundary := range []string{"epoch", "maximum", "not_before", "not_after", "wrong_name", "range"} {
			t.Run(fmt.Sprintf("tls%d/%s", version, boundary), func(t *testing.T) {
				value := time.Now().Unix()
				accept, name := true, "localhost"
				if boundary == "epoch" || boundary == "maximum" {
					accept = false
					reason := "future"
					value = 0
					if boundary == "maximum" {
						value, reason = 253402300799, "expired"
					}
					t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
					t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
				} else if boundary == "not_before" {
					value = f.leaf.NotBefore.Unix()
				} else if boundary == "not_after" {
					value = f.leaf.NotAfter.Unix()
				} else if boundary == "wrong_name" {
					accept, name = false, "wrong.example"
				} else if boundary == "range" {
					t.Setenv("SALTS_TEST_TLS_CLIENT_RANGE", "1")
				}
				t.Setenv("SALTS_TEST_TLS_VERIFICATION_TIME", fmt.Sprint(value))
				runValidityPeer(t, f, chain, version, accept, name)
			})
		}
	}
}

func TestServerVerificationTime(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		server := makeIdentity(t, "time server", ec, nil)
		for _, reason := range []string{"expired", "future"} {
			now := time.Now()
			fixed := now.Add(-36 * time.Hour)
			if reason == "future" {
				fixed = now.Add(36 * time.Hour)
			}
			client, _ := validityIdentity(t, ec, "leaf", func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
				if reason == "future" {
					c.NotBefore, c.NotAfter = now.Add(24*time.Hour), now.Add(48*time.Hour)
				}
			}, true)
			for _, version := range []int{12, 13} {
				for _, mode := range []string{"file", "pem", "der"} {
					for _, explicit := range []bool{false, true} {
						t.Run(fmt.Sprintf("ec_%t/%s/tls%d/%s/fixed_%t", ec, reason, version, mode, explicit), func(t *testing.T) {
							if mode != "file" {
								t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
							}
							outcome := "reject-server"
							if explicit {
								outcome = "accept"
								t.Setenv("SALTS_TEST_TLS_SERVER_VERIFICATION_TIME", fmt.Sprint(fixed.Unix()))
							} else {
								t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
								t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
							}
							scheme := "2"
							if ec {
								scheme = "1"
							}
							ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
							defer cancel()
							out, err := exec.CommandContext(ctx, *native, "--signature-mtls", server.ca, client.ca, server.cert, server.keyFile, client.cert, client.keyFile, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)), fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw)), "-", "0", fmt.Sprint(version), scheme, scheme).CombinedOutput()
							if err != nil {
								t.Fatalf("native mTLS: %v\n%s", err, out)
							}
						})
					}
				}
			}
		}
	}
}
