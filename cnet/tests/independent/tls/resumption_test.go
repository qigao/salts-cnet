package tls_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
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
	for _, mode := range []string{"enabled", "disabled", "server-refuses", "policy", "alpn", "expired"} {
		t.Run(mode, func(t *testing.T) {
			id, cert := id, cert
			if mode == "expired" {
				id = makeIdentity(t, "resumption-expiry", true, nil, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(8 * time.Second).Truncate(time.Second) })
				cert, err = tls.LoadX509KeyPair(id.cert, id.keyFile)
				if err != nil {
					t.Fatal(err)
				}
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
			if mode == "policy" || mode == "alpn" || mode == "expired" {
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
						if mode == "expired" && i != 0 {
							time.Sleep(time.Until(id.leaf.NotAfter.Add(time.Second)))
							t.Logf("expiry boundary: not_after=%s handshake_start=%s", id.leaf.NotAfter.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
						}
						handshakeErr := conn.Handshake()
						if mode == "expired" && i != 0 {
							t.Logf("expiry handshake end=%s error=%v", time.Now().UTC().Format(time.RFC3339Nano), handshakeErr)
						}
						want := i != 0 && mode != "disabled" && mode != "server-refuses"
						if state := conn.ConnectionState(); state.DidResume != want {
							return fmt.Errorf("connection %d reused=%v want=%v handshake=%v", i, state.DidResume, want, handshakeErr)
						}
						if i != 0 && (mode == "policy" || mode == "alpn" || mode == "expired") {
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
			output, runErr := exec.CommandContext(ctx, *native, "--tls-resumption", port, "tls13", "localhost", id.ca, mode).CombinedOutput()
			listener.Close()
			peerErr := <-finished
			if runErr != nil || peerErr != nil {
				t.Fatalf("native=%v peer=%v\n%s", runErr, peerErr, output)
			}
		})
	}
}
