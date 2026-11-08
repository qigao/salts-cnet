package tickets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var native = flag.String("native", "", "production CNet server ticket peer")

type identity struct {
	cert                      tls.Certificate
	roots                     *x509.CertPool
	certFile, keyFile, caFile string
	expires                   time.Time
	leaf                      *x509.Certificate
	intermediates             *x509.CertPool
}

func credentials(t *testing.T, expires bool, constraints string) identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ticket root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 2}
	if strings.HasPrefix(constraints, "root-constraints-") {
		root.PermittedDNSDomainsCritical = true
		root.PermittedDNSDomains = []string{"localhost", "other.local"}
		if strings.HasPrefix(constraints, "root-constraints-invalid") {
			root.PermittedDNSDomains = []string{"allowed.example"}
		}
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, issuerKey := root, rootKey
	var issuerDER []byte
	intermediates := x509.NewCertPool()
	if constraints != "" {
		issuerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		issuer = &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "ticket intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
		if constraints == "constraints-valid" || constraints == "constraints-invalid" {
			issuer.PermittedDNSDomainsCritical = true
			issuer.PermittedDNSDomains = []string{"localhost", "other.local"}
			if constraints == "constraints-invalid" {
				issuer.PermittedDNSDomains = []string{"allowed.example"}
			}
		}
		issuerDER, err = x509.CreateCertificate(rand.Reader, issuer, root, &issuerKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		issuer, err = x509.ParseCertificate(issuerDER)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(issuer)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ticket peer"}, DNSNames: []string{"localhost", "other.local"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if expires {
		leaf.NotAfter = now.Add(8 * time.Second).Truncate(time.Second)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := identity{certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem"), caFile: filepath.Join(dir, "ca.pem"), roots: x509.NewCertPool(), expires: leaf.NotAfter, leaf: leaf, intermediates: intermediates}
	for name, block := range map[string]*pem.Block{f.certFile: {Type: "CERTIFICATE", Bytes: der}, f.keyFile: {Type: "PRIVATE KEY", Bytes: keyDER}, f.caFile: {Type: "CERTIFICATE", Bytes: rootDER}} {
		if err := os.WriteFile(name, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if len(issuerDER) != 0 {
		file, err := os.OpenFile(f.certFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		writeErr := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("intermediate fixture: %v / %v", writeErr, closeErr)
		}
	}
	if strings.HasSuffix(constraints, "-presented") {
		file, err := os.OpenFile(f.certFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		writeErr := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("presented root fixture: %v / %v", writeErr, closeErr)
		}
	}
	f.roots.AddCert(root)
	f.cert, err = tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Deliberately bypass hostname cache partitioning, but keep Go's mandatory
// certificate/name verification. The leaf covers both names. This proves the
// production server declines cross-SNI tickets independently of client policy.
type forcedCache struct{ state *tls.ClientSessionState }

func (c *forcedCache) Get(string) (*tls.ClientSessionState, bool) { return c.state, c.state != nil }
func (c *forcedCache) Put(_ string, s *tls.ClientSessionState)    { c.state = s }

func TestServerTickets(t *testing.T) {
	runStandardCases(t, []string{"enabled", "disabled", "client-disabled", "mtls", "alpn", "sni", "capacity", "policy", "expired"})
}
func TestNameConstraints(t *testing.T) {
	runStandardCases(t, []string{"constraints-valid", "constraints-invalid", "root-constraints-valid", "root-constraints-invalid", "root-constraints-valid-presented", "root-constraints-invalid-presented"})
}
func runStandardCases(t *testing.T, modes []string) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	server := credentials(t, false, "")
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			constraints := ""
			if strings.Contains(mode, "constraints") {
				constraints = mode
			}
			client := credentials(t, mode == "expired", constraints)
			invalidConstraints := strings.Contains(mode, "constraints-invalid")
			if constraints != "" {
				_, err := client.leaf.Verify(x509.VerifyOptions{Roots: client.roots, Intermediates: client.intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				if (err != nil) != invalidConstraints {
					t.Fatalf("independent path oracle: %v", err)
				}
			}
			expected := "011"
			if mode == "disabled" || mode == "client-disabled" || mode == "alpn" || mode == "sni" || mode == "capacity" {
				expected = "000"
			}
			if mode == "policy" || mode == "expired" {
				expected = "01"
			}
			if constraints != "" {
				expected = "0"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			ready := filepath.Join(t.TempDir(), "ready")
			cmd := exec.CommandContext(ctx, *native)
			cmd.Env = append(os.Environ(), "SALTS_TICKET_READY="+ready, "SALTS_TICKET_CERT="+server.certFile, "SALTS_TICKET_KEY="+server.keyFile, "SALTS_TICKET_MODE="+mode, "SALTS_TICKET_EXPECTED="+expected, "SALTS_TICKET_PROFILE=tls13")
			if mode == "mtls" || mode == "policy" || mode == "expired" || constraints != "" {
				cmd.Env = append(cmd.Env, "SALTS_TICKET_CLIENT_CA="+client.caFile)
			}
			var output strings.Builder
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			complete := false
			defer func() {
				if !complete {
					cancel()
				}
				if err := cmd.Wait(); err != nil {
					t.Errorf("native=%v\n%s", err, output.String())
				}
				cancel()
			}()
			var address string
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				data, err := os.ReadFile(ready)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if strings.HasSuffix(string(data), "\n") {
					port, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 16)
					if err != nil || port == 0 {
						t.Fatalf("invalid ready port: %v", err)
					}
					address = net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
					break
				}
				time.Sleep(time.Millisecond)
			}
			if address == "" {
				t.Fatal("server did not publish port")
			}
			cache := &forcedCache{}
			var first *tls.ClientSessionState
			for round := range len(expected) {
				if mode == "expired" && round != 0 {
					time.Sleep(time.Until(client.expires.Add(time.Second)))
				}
				config := &tls.Config{RootCAs: server.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ClientSessionCache: cache, Certificates: []tls.Certificate{client.cert}}
				if mode == "client-disabled" {
					config.ClientSessionCache = nil
				}
				if mode == "alpn" && round == 1 {
					config.NextProtos = []string{"http/1.1"}
				}
				if (mode == "sni" || mode == "capacity") && round == 1 {
					config.ServerName = "other.local"
				}
				if mode == "capacity" && round == 2 {
					cache.state = first
				}
				raw, err := net.DialTimeout("tcp", address, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				err = func() error {
					defer raw.Close()
					if err := raw.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
						return err
					}
					conn := tls.Client(raw, config)
					handshakeErr := conn.Handshake()
					if handshakeErr != nil && !invalidConstraints {
						return handshakeErr
					}
					if conn.ConnectionState().DidResume != (expected[round] == '1') {
						return fmt.Errorf("round %d reused=%v want=%c", round, conn.ConnectionState().DidResume, expected[round])
					}
					var b [1]byte
					if (round != 0 && (mode == "policy" || mode == "expired")) || invalidConstraints {
						var n int
						err := handshakeErr
						if err == nil {
							n, err = conn.Read(b[:])
						}
						var timeout net.Error
						if n != 0 || err == nil || errors.As(err, &timeout) && timeout.Timeout() {
							return fmt.Errorf("missing authenticated admission rejection: n=%d err=%v", n, err)
						}
						return nil
					}
					if _, err := conn.Write([]byte{'F'}); err != nil {
						return err
					}
					if _, err := io.ReadFull(conn, b[:]); err != nil {
						return err
					}
					if b[0] != 'G' {
						return fmt.Errorf("invalid reply %x", b[0])
					}
					if mode != "disabled" && mode != "client-disabled" && cache.state == nil {
						return errors.New("server did not issue a usable ticket")
					}
					if round == 0 {
						first = cache.state
					}
					if err := conn.CloseWrite(); err != nil {
						return err
					}
					if n, err := conn.Read(b[:]); n != 0 || err != io.EOF {
						return fmt.Errorf("close: n=%d err=%v", n, err)
					}
					return nil
				}()
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
			}
			complete = true
		})
	}
}
