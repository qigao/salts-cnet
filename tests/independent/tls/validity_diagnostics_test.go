package tls_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestValidityDiagnostics(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		for _, reason := range []string{"expired", "future", "certificate"} {
			change := func(c *x509.Certificate) {
				if reason == "expired" {
					c.NotBefore = time.Now().Add(-48 * time.Hour)
					c.NotAfter = time.Now().Add(-24 * time.Hour)
				} else if reason == "certificate" {
					c.NotBefore = time.Now().Add(time.Hour)
					c.NotAfter = time.Now().Add(-time.Hour)
				} else {
					c.NotBefore = time.Now().Add(time.Hour)
					c.NotAfter = time.Now().Add(24 * time.Hour)
				}
			}
			targets := []string{"leaf", "anchor"}
			if reason == "certificate" {
				targets = []string{"leaf"}
			}
			for _, target := range targets {
				var f identity
				if target == "leaf" {
					f = makeIdentity(t, "validity", ec, nil, change)
				} else {
					f = makeIdentity(t, "validity", ec, nil)
					root := *f.root
					change(&root)
					der, err := x509.CreateCertificate(rand.Reader, &root, &root, f.key.Public(), f.key)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(f.ca+".der", der, 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
					for _, mode := range []string{"file", "pem", "der"} {
						t.Run(fmt.Sprintf("ec_%t/%s/%s/tls%d/%s", ec, target, reason, version, mode), func(t *testing.T) {
							expected := reason
							// TLS1.2 rejects the reversed interval while decoding Certificate,
							// before its verifier produces a certificate-specific result.
							if reason == "certificate" && version == tls.VersionTLS12 {
								expected = "handshake"
							}
							t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", expected)
							if mode != "file" {
								t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
							}
							listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
							if err != nil {
								t.Fatal(err)
							}
							defer listener.Close()
							if err = listener.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
								t.Fatal(err)
							}
							done := make(chan error, 1)
							go func() {
								raw, e := listener.Accept()
								if e != nil {
									done <- e
									return
								}
								defer raw.Close()
								if e = raw.SetDeadline(time.Now().Add(10 * time.Second)); e != nil {
									done <- e
									return
								}
								conn := tls.Server(raw, &tls.Config{MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, Certificates: []tls.Certificate{{Certificate: [][]byte{f.leaf.Raw}, PrivateKey: f.key}}})
								done <- conn.Handshake()
							}()
							protocol := "tls13"
							if version == tls.VersionTLS12 {
								protocol = "tls12"
							}
							ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
							defer cancel()
							out, runErr := exec.CommandContext(ctx, *native, "--external-ip-san", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), protocol, "localhost", f.ca, "reject").CombinedOutput()
							peerErr := <-done
							if runErr != nil || peerErr == nil {
								t.Fatalf("native: %v; peer: %v\n%s", runErr, peerErr, out)
							}
						})
					}
				}
			}
		}
	}
}
