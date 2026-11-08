// Independent standard-library TLS peer. Exercise production CNet, including
// selection by CertificateRequest CA hints and exact leaf identity on the wire.
package tls_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var native = flag.String("native", "", "production CNet test executable")
var python = flag.String("python", "", "configured formal fixture interpreter")

type identity struct {
	leaf, root        *x509.Certificate
	key               crypto.Signer
	ca, cert, keyFile string
}

func makeIdentity(t *testing.T, name string, ec bool, issuer *identity, change ...func(*x509.Certificate)) identity {
	t.Helper()
	var key crypto.Signer
	var err error
	if ec {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	rootKey := key
	var rootDER []byte
	if issuer != nil {
		root = issuer.root
		rootKey = issuer.key
		rootDER = root.Raw
	} else {
		rootDER, err = x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		root, err = x509.ParseCertificate(rootDER)
		if err != nil {
			t.Fatal(err)
		}
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if len(change) != 0 {
		change[0](leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := identity{leaf: leaf, root: root, key: key, ca: filepath.Join(dir, "ca.pem"), cert: filepath.Join(dir, "leaf.pem"), keyFile: filepath.Join(dir, "key.pem")}
	for path, block := range map[string]*pem.Block{f.ca: {Type: "CERTIFICATE", Bytes: rootDER}, f.cert: {Type: "CERTIFICATE", Bytes: der}, f.keyFile: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path+".der", block.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func TestClientIdentities(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	server := makeIdentity(t, "server", false, nil)
	first := makeIdentity(t, "first", false, nil)
	second := makeIdentity(t, "second", false, nil)
	for _, f := range []identity{first, second} {
		writeAESFixture(t, f, "binary", "")
	}
	for _, f := range []identity{first, second} {
		if *python == "" {
			t.Fatal("-python is required for PFX fixtures")
		}
		script := filepath.Join("..", "..", "..", "crypto", "tests", "asn1", "pkcs12_peer.py")
		if out, err := exec.Command(*python, script, "--fixture", f.cert+".pfx", f.cert, f.keyFile).CombinedOutput(); err != nil {
			t.Fatalf("PFX fixture: %v\n%s", err, out)
		}
	}
	emptyFirst, emptySecond := first, second
	emptyFirst.keyFile = filepath.Join(t.TempDir(), "key.pem")
	emptySecond.keyFile = filepath.Join(t.TempDir(), "key.pem")
	writeAESFixtureFrom(t, first, emptyFirst, "empty", "")
	writeAESFixtureFrom(t, second, emptySecond, "empty", "")
	extra := map[string][2]identity{}
	for _, bits := range []int{128, 192} {
		for _, password := range []string{"binary", "empty"} {
			pair := [2]identity{first, second}
			for i, source := range []identity{first, second} {
				pair[i].keyFile = filepath.Join(t.TempDir(), "key.pem")
				writeAESFixtureFrom(t, source, pair[i], password, "", bits)
			}
			extra[fmt.Sprintf("encrypted_%s%d", password, bits)] = pair
		}
	}
	for _, prf := range aesFixturePRFs {
		hash := prf.name
		for _, bits := range []int{128, 192, 256} {
			for _, password := range []string{"binary", "empty"} {
				pair := [2]identity{first, second}
				for i, source := range []identity{first, second} {
					pair[i].keyFile = filepath.Join(t.TempDir(), "key.pem")
					writeAESFixtureFrom(t, source, pair[i], password, hash+":valid", bits)
				}
				extra[fmt.Sprintf("encrypted_%s%d_%s", password, bits, hash)] = pair
			}
		}
	}
	// ECDSA leaf under an RSA issuer: only the leaf scheme excludes this identity.
	ec := makeIdentity(t, "ec", true, &first)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, mode := range []string{"file", "pem", "der"} {
			scenarios := []string{"first_ca", "second_ca", "range_second_ca", "ordered", "empty_ca", "signature", "no_match", "no_request"}
			scenarios = append(scenarios, "separate_certificate", "range_separate_certificate")
			if mode != "file" {
				scenarios = append(scenarios, "pkcs12", "object", "object_encrypted", "encrypted_binary", "encrypted_empty", "encrypted_binary128", "encrypted_empty128", "encrypted_binary192", "encrypted_empty192")
				for _, prf := range aesFixturePRFs {
					hash := prf.name
					for _, bits := range []int{128, 192, 256} {
						for _, password := range []string{"binary", "empty"} {
							scenarios = append(scenarios, fmt.Sprintf("encrypted_%s%d_%s", password, bits, hash))
						}
					}
				}
			}
			for _, scenario := range scenarios {
				t.Run(fmt.Sprintf("tls%d/%s/%s", version, mode, scenario), func(t *testing.T) {
					a, b := first, second
					want := first.leaf
					hints := x509.NewCertPool()
					auth := tls.RequireAndVerifyClientCert
					if strings.HasPrefix(scenario, "object") {
						t.Setenv("SALTS_TEST_TLS_OBJECT", "1")
						t.Setenv("SALTS_TEST_TLS_GROUP", "1")
					}
					switch {
					case scenario == "pkcs12":
						t.Setenv("SALTS_TEST_TLS_PKCS12", "1")
						hints.AddCert(second.root)
						want = second.leaf
					case scenario == "object" || scenario == "object_encrypted":
						hints.AddCert(second.root)
						want = second.leaf
						if scenario == "object_encrypted" {
							t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
						}
					case strings.HasPrefix(scenario, "encrypted_"):
						t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
						if pair, ok := extra[scenario]; ok {
							a, b = pair[0], pair[1]
						} else if scenario != "encrypted_binary" && scenario != "encrypted_empty" {
							t.Fatalf("missing encrypted fixture for %s", scenario)
						}
						if strings.HasPrefix(scenario, "encrypted_empty") {
							if scenario == "encrypted_empty" {
								a, b = emptyFirst, emptySecond
							}
							t.Setenv("SALTS_TEST_TLS_EMPTY_PASSWORD", "1")
						}
						hints.AddCert(second.root)
						want = second.leaf
					case scenario == "separate_certificate" || scenario == "range_separate_certificate":
						t.Setenv("SALTS_TEST_TLS_SEPARATE_CERT_SIGNATURES", "1")
						if scenario == "range_separate_certificate" {
							t.Setenv("SALTS_TEST_TLS_CLIENT_RANGE", "1")
						}
						hints.AddCert(first.root)
					case scenario == "first_ca":
						hints.AddCert(first.root)
					case scenario == "range_second_ca":
						t.Setenv("SALTS_TEST_TLS_CLIENT_RANGE", "1")
						fallthrough
					case scenario == "second_ca":
						hints.AddCert(second.root)
						want = second.leaf
					case scenario == "ordered":
						hints.AddCert(second.root)
						hints.AddCert(first.root)
					case scenario == "empty_ca":
						auth = tls.RequestClientCert
					case scenario == "signature":
						a, b = ec, first
						hints.AddCert(first.root)
						t.Setenv("SALTS_TEST_TLS_CLIENT_RSA_ONLY", "1")
					case scenario == "no_match":
						hints.AddCert(server.root)
						auth = tls.RequestClientCert
						want = nil
					case scenario == "no_request":
						auth = tls.NoClientCert
						want = nil
					}
					if mode != "file" {
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
					}
					t.Setenv("SALTS_TEST_TLS_CLIENT_ALT_CERT", b.cert)
					t.Setenv("SALTS_TEST_TLS_CLIENT_ALT_KEY", b.keyFile)
					listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					if err = listener.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
						t.Fatal(err)
					}
					finished := make(chan error, 1)
					go func() {
						raw, e := listener.Accept()
						if e != nil {
							finished <- e
							return
						}
						defer raw.Close()
						if e = raw.SetDeadline(time.Now().Add(10 * time.Second)); e != nil {
							finished <- e
							return
						}
						conn := tls.Server(raw, &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{{Certificate: [][]byte{server.leaf.Raw}, PrivateKey: server.key}}, ClientAuth: auth, ClientCAs: hints, CurvePreferences: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}})
						if e = conn.Handshake(); e != nil {
							finished <- e
							return
						}
						peer := conn.ConnectionState().PeerCertificates
						if want == nil {
							if len(peer) != 0 {
								finished <- fmt.Errorf("unrequested/unmatched identity disclosed")
								return
							}
						} else {
							if len(peer) == 0 || !bytes.Equal(peer[0].Raw, want.Raw) {
								finished <- fmt.Errorf("wrong selected client leaf")
								return
							}
							roots := x509.NewCertPool()
							roots.AddCert(first.root)
							roots.AddCert(second.root)
							if _, e = peer[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
								finished <- e
								return
							}
						}
						var payload [1]byte
						if _, e = io.ReadFull(conn, payload[:]); e != nil {
							finished <- e
							return
						}
						if payload[0] != 'F' {
							finished <- fmt.Errorf("unexpected application data %x", payload)
							return
						}
						if _, e = conn.Write([]byte("ok")); e != nil {
							finished <- e
							return
						}
						// Wait for authenticated native shutdown before closing TCP.
						var extra [1]byte
						if n, e := conn.Read(extra[:]); n != 0 || e != io.EOF {
							finished <- fmt.Errorf("expected close_notify, got n=%d err=%v", n, e)
							return
						}
						finished <- conn.Close()
					}()
					protocol := "tls13"
					if version == tls.VersionTLS12 {
						protocol = "tls12"
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, *native, "--tls-client-identities", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), protocol, "localhost", server.ca, a.cert, a.keyFile, "accept", fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)))
					output, runErr := cmd.CombinedOutput()
					peerErr := <-finished
					if runErr != nil || peerErr != nil {
						t.Fatalf("native: %v; peer: %v\n%s", runErr, peerErr, output)
					}
				})
			}
		}
	}
}
