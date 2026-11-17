package tls_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Each native connection has a new CNet owner, while the immutable TLS client
// context and the server's ticket keys survive all three authenticated closes.
func TestTLS13SessionResumption(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	id := makeIdentity(t, "resumption", true, nil)
	cert, err := tls.LoadX509KeyPair(id.cert, id.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enabled", "disabled", "server-refuses", "policy", "alpn", "expired", "expired-intermediate", "expired-anchor"} {
		t.Run(mode, func(t *testing.T) {
			id, cert := id, cert
			expired := strings.HasPrefix(mode, "expired")
			var expires time.Time
			nativeMode := mode
			if expired {
				expires = time.Now().Add(8 * time.Second).Truncate(time.Second)
				target := "leaf"
				index := "0"
				if mode == "expired-intermediate" {
					target, index = "intermediate", "1"
				} else if mode == "expired-anchor" {
					target, index = "anchor", ""
				}
				var chain [][]byte
				id, chain = validityIdentity(t, true, target, func(c *x509.Certificate) { c.NotAfter = expires }, false)
				cert, err = tls.LoadX509KeyPair(id.cert, id.keyFile)
				if err != nil {
					t.Fatal(err)
				}
				cert.Certificate = chain
				// Independently prove the same supplied chain is valid now and
				// fails at the selected certificate after this expiry boundary.
				roots := x509.NewCertPool()
				rootPEM, err := os.ReadFile(id.ca)
				if err != nil || !roots.AppendCertsFromPEM(rootPEM) {
					t.Fatalf("expiry trust fixture: %v", err)
				}
				intermediates := x509.NewCertPool()
				for _, der := range chain[1:] {
					issuer, err := x509.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					intermediates.AddCert(issuer)
				}
				verify := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "localhost", CurrentTime: time.Now()}
				verified, err := id.leaf.Verify(verify)
				if err != nil || len(verified) != 1 {
					t.Fatalf("initial expiry chain: chains=%d error=%v", len(verified), err)
				}
				selected := 0
				if target == "intermediate" {
					selected = 1
				} else if target == "anchor" {
					selected = len(verified[0]) - 1
				}
				verify.CurrentTime = expires.Add(time.Second)
				_, err = id.leaf.Verify(verify)
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.Expired ||
					!bytes.Equal(invalid.Cert.Raw, verified[0][selected].Raw) {
					t.Fatalf("selected %s expiry was not independently rejected: %v", target, err)
				}
				t.Setenv("SALTS_TEST_TLS_RESUMPTION_EXPIRY_INDEX", index)
				nativeMode = "expired"
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
			// Initialize ticket keys once, including before concurrent use.
			var key [32]byte
			if _, err := rand.Read(key[:]); err != nil {
				t.Fatal(err)
			}
			config.SetSessionTicketKeys([][32]byte{key})
			rounds := 3
			if mode == "policy" || mode == "alpn" || expired {
				rounds = 2
			}
			finished := make(chan error, 1)
			go func() {
				for i := 0; i < rounds; i++ {
					raw, err := listener.Accept()
					if err != nil {
						finished <- err
						return
					}
					err = func() error {
						defer raw.Close()
						if err := raw.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
							return err
						}
						if mode == "server-refuses" && i != 0 {
							if _, err := rand.Read(key[:]); err != nil {
								return err
							}
							config.SetSessionTicketKeys([][32]byte{key})
						}
						selectedConfig := config
						if mode == "alpn" && i != 0 {
							selectedConfig = config.Clone()
							selectedConfig.NextProtos = []string{"http/1.1"}
						}
						conn := tls.Server(raw, selectedConfig)
						if expired && i != 0 {
							// The verifier uses C time(), which can read the previous
							// second at a fresh Go clock boundary (glibc's coarse
							// realtime clock). Cross one complete expired second
							// before completing this already-started handshake.
							time.Sleep(time.Until(expires.Add(2 * time.Second)))
							started := time.Now()
							if !started.After(expires) {
								return fmt.Errorf("expiry gate not crossed: now=%s not_after=%s", started, expires)
							}
							t.Logf("expiry boundary: profile=%s not_after=%s handshake_start=%s", mode, expires.UTC().Format(time.RFC3339Nano), started.UTC().Format(time.RFC3339Nano))
						}
						handshakeErr := conn.Handshake()
						if expired && i != 0 {
							t.Logf("expiry handshake end=%s error=%v", time.Now().UTC().Format(time.RFC3339Nano), handshakeErr)
						}
						want := i != 0 && mode != "disabled" && mode != "server-refuses"
						if state := conn.ConnectionState(); state.DidResume != want {
							return fmt.Errorf("connection %d reused=%v want=%v handshake=%v", i, state.DidResume, want, handshakeErr)
						}
						if i != 0 && (mode == "policy" || mode == "alpn" || expired) {
							var b [1]byte
							readErr := handshakeErr
							if readErr == nil {
								n, err := conn.Read(b[:])
								if n != 0 {
									return errors.New("rejected session sent application data")
								}
								readErr = err
							}
							var timeout net.Error
							if readErr == nil || errors.As(readErr, &timeout) && timeout.Timeout() {
								return fmt.Errorf("missing prompt policy rejection: %v", readErr)
							}
							return nil
						}
						if handshakeErr != nil {
							return fmt.Errorf("connection %d handshake: %w", i, handshakeErr)
						}
						if state := conn.ConnectionState(); state.DidResume != want || state.NegotiatedProtocol != "h2" {
							return fmt.Errorf("connection %d reused=%v want=%v ALPN=%q", i, state.DidResume, want, state.NegotiatedProtocol)
						}
						var b [1]byte
						if _, err := io.ReadFull(conn, b[:]); err != nil {
							return err
						}
						if b[0] != 'F' {
							return fmt.Errorf("unexpected application byte %x", b[0])
						}
						if _, err := conn.Write([]byte("ok")); err != nil {
							return err
						}
						if n, err := conn.Read(b[:]); n != 0 || err != io.EOF {
							return fmt.Errorf("close notify: n=%d err=%v", n, err)
						}
						return conn.CloseWrite()
					}()
					if err != nil {
						finished <- err
						return
					}
				}
				finished <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
			output, runErr := exec.CommandContext(ctx, *native, "--tls-resumption", port, "tls13", "localhost", id.ca, nativeMode).CombinedOutput()
			listener.Close()
			peerErr := <-finished
			if runErr != nil || peerErr != nil {
				t.Fatalf("native=%v peer=%v\n%s", runErr, peerErr, output)
			}
		})
	}
}
