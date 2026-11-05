package tls_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Return the real transmitted chain separately from the local trust anchor.
func validityIdentity(t *testing.T, ec bool, target string, change func(*x509.Certificate), wide bool) (identity, [][]byte) {
	t.Helper()
	root := makeIdentity(t, "validity root", ec, nil)
	template := *root.root
	setWindow := func(c *x509.Certificate) {
		if wide {
			c.NotBefore = time.Now().Add(-96 * time.Hour)
			c.NotAfter = time.Now().Add(96 * time.Hour)
		}
	}
	setWindow(&template)
	if wide {
		template.NotBefore = time.Now().Add(-192 * time.Hour)
		template.NotAfter = time.Now().Add(192 * time.Hour)
	}
	template.MaxPathLenZero = false
	template.MaxPathLen = 2
	if target == "anchor" {
		change(&template)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, root.key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	root.root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{root.ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), root.ca + ".der": der} {
		if err = os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	issuer := root
	var intermediates [][]byte
	depth := 0
	if target == "intermediate" {
		depth = 1
	} else if target == "upper_intermediate" {
		depth = 2
	}
	for i := 0; i < depth; i++ {
		ca := makeIdentity(t, fmt.Sprintf("validity CA %d", i), ec, &issuer, func(c *x509.Certificate) {
			setWindow(c)
			c.IsCA = true
			c.KeyUsage = x509.KeyUsageCertSign
			c.MaxPathLen = depth - i - 1
			c.MaxPathLenZero = c.MaxPathLen == 0
			if i == 0 {
				change(c)
			}
		})
		ca.root = ca.leaf // The next certificate is issued by this CA's key.
		issuer = ca
		intermediates = append([][]byte{ca.leaf.Raw}, intermediates...)
	}
	f := makeIdentity(t, "validity leaf", ec, &issuer, func(c *x509.Certificate) {
		setWindow(c)
		if target == "leaf" {
			change(c)
		}
	})
	f.ca = root.ca
	return f, append([][]byte{f.leaf.Raw}, intermediates...)
}

func runValidityPeer(t *testing.T, f identity, chain [][]byte, version uint16, accept bool, hostname string) {
	t.Helper()
	outcome := "reject"
	if accept {
		outcome = "accept"
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
		conn := tls.Server(raw, &tls.Config{MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: f.key}}})
		e = conn.Handshake()
		if !accept || e != nil {
			done <- e
			return
		}
		var payload [1]byte
		if _, e = io.ReadFull(conn, payload[:]); e == nil && payload[0] != 'F' {
			e = fmt.Errorf("unexpected application request %x", payload)
		}
		if e == nil {
			_, e = conn.Write([]byte("ok"))
		}
		if e == nil {
			var extra [1]byte
			if n, closeErr := conn.Read(extra[:]); n != 0 || closeErr != io.EOF {
				e = fmt.Errorf("expected close_notify: %d %v", n, closeErr)
			}
		}
		if e == nil {
			e = conn.Close()
		}
		done <- e
	}()
	protocol := "tls13"
	if version == tls.VersionTLS12 {
		protocol = "tls12"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, *native, "--external-ip-san", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), protocol, hostname, f.ca, outcome).CombinedOutput()
	peerErr := <-done
	if runErr != nil || (accept && peerErr != nil) || (!accept && peerErr == nil) {
		t.Fatalf("native: %v; peer: %v\n%s", runErr, peerErr, out)
	}
}

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
			targets := []string{"leaf", "intermediate", "upper_intermediate", "anchor"}
			if reason == "certificate" {
				targets = []string{"leaf"}
			}
			for _, target := range targets {
				f, chain := validityIdentity(t, ec, target, change, false)
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
							if reason != "certificate" && target != "anchor" {
								index := map[string]string{"leaf": "0", "intermediate": "1", "upper_intermediate": "2"}[target]
								t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", index)
							}
							if mode != "file" {
								t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
							}
							runValidityPeer(t, f, chain, version, false, "localhost")
						})
					}
				}
			}
		}
	}
}
