package tickets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/pion/dtls/v3"
	curve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dtlsPKIXDNSConstraints(c *x509.Certificate, variant, owner string) {
	switch variant {
	case owner + "-permitted", owner + "-permitted-altname", owner + "-permitted-mixed":
		c.PermittedDNSDomainsCritical = true
		c.PermittedDNSDomains = []string{"localhost"}
	case owner + "-excluded":
		c.PermittedDNSDomainsCritical = true
		c.ExcludedDNSDomains = []string{"localhost"}
	case owner + "-excluded-altname":
		c.PermittedDNSDomainsCritical = true
		c.ExcludedDNSDomains = []string{"blocked.example"}
	}
}

// Go signs/parses/verifies this chain independently of the native verifier.
func dtlsPKIXIdentity(t *testing.T, variant string, server bool) (identity, bool) {
	t.Helper()
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey := key()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PKIX root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 3}
	if variant == "path-length" {
		root.MaxPathLen = 0
		root.MaxPathLenZero = true
	}
	if variant == "root-constraints" {
		root.PermittedDNSDomainsCritical = true
		root.PermittedDNSDomains = []string{"allowed.example"}
	}
	dtlsPKIXDNSConstraints(root, variant, "root")
	if variant == "expired-root" {
		root.NotBefore, root.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	} else if variant == "future-root" {
		root.NotBefore, root.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
	}
	sign := func(c, p *x509.Certificate, k, issuer *ecdsa.PrivateKey) ([]byte, *x509.Certificate) {
		d, e := x509.CreateCertificate(rand.Reader, c, p, &k.PublicKey, issuer)
		if e != nil {
			t.Fatal(e)
		}
		v, e := x509.ParseCertificate(d)
		if e != nil {
			t.Fatal(e)
		}
		return d, v
	}
	rd, root := sign(root, root, rootKey, rootKey)
	rootDER := [][]byte{rd}
	if variant == "same-name-anchors" {
		rootKey = key()
		r := *root
		r.Raw = nil
		r.RawTBSCertificate = nil
		r.PublicKey = &rootKey.PublicKey
		r.SerialNumber = big.NewInt(9)
		rd, root = sign(&r, &r, rootKey, rootKey)
		rootDER = append(rootDER, rd)
	}
	parent, issuer := root, rootKey
	var intermediates [][]byte
	wanted := x509.ExtKeyUsageClientAuth
	if server {
		wanted = x509.ExtKeyUsageServerAuth
	}
	opposite := x509.ExtKeyUsageServerAuth
	if server {
		opposite = x509.ExtKeyUsageClientAuth
	}
	for depth := 0; depth < 2; depth++ {
		k := key()
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(20 + depth)), Subject: pkix.Name{CommonName: fmt.Sprintf("PKIX CA %d", depth)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1 - depth, MaxPathLenZero: depth == 1}
		switch variant {
		case fmt.Sprintf("expired-ca%d", depth):
			c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
		case fmt.Sprintf("future-ca%d", depth):
			c.NotBefore, c.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
		case fmt.Sprintf("unknown-critical-ca%d", depth):
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 444}, Critical: true, Value: []byte{5, 0}}}
		}
		if depth == 0 {
			dtlsPKIXDNSConstraints(c, variant, "ca")
			switch variant {
			case "not-ca":
				c.IsCA = false
				c.MaxPathLen = -1
				c.MaxPathLenZero = false
			case "ca-key-usage":
				c.KeyUsage = x509.KeyUsageDigitalSignature
			case "ca-purpose":
				c.ExtKeyUsage = []x509.ExtKeyUsage{opposite}
			case "ca-constraints":
				c.PermittedDNSDomainsCritical = true
				c.PermittedDNSDomains = []string{"allowed.example"}
			case "policy-required":
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 36}, Critical: true, Value: []byte{0x30, 3, 0x80, 1, 0}}}
			}
		}
		d, p := sign(c, parent, k, issuer)
		intermediates = append(intermediates, d)
		parent = p
		issuer = k
	}
	leafKey := key()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "PKIX peer"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{wanted}}
	switch variant {
	case "ca-permitted-altname", "root-permitted-altname":
		leaf.DNSNames = append(leaf.DNSNames, "preview.localhost")
	case "ca-permitted-mixed", "root-permitted-mixed", "ca-excluded-altname", "root-excluded-altname":
		// The connection still authenticates localhost; a different SAN must not
		// escape the issuer's constraints merely because it was not requested.
		leaf.DNSNames = append(leaf.DNSNames, "blocked.example")
	}
	switch variant {
	case "expired":
		leaf.NotBefore = now.Add(-2 * time.Hour)
		leaf.NotAfter = now.Add(-time.Hour)
	case "future":
		leaf.NotBefore = now.Add(time.Hour)
		leaf.NotAfter = now.Add(2 * time.Hour)
	case "leaf-key-usage":
		leaf.KeyUsage = x509.KeyUsageKeyEncipherment
	case "leaf-purpose":
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{opposite}
	case "unknown-critical":
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 444}, Critical: true, Value: []byte{5, 0}}}
	}
	der, parsed := sign(leaf, parent, leafKey, issuer)
	if variant == "signature" {
		der[len(der)-1] ^= 1
		var e error
		parsed, e = x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
	}
	chain := [][]byte{der}
	for i := len(intermediates) - 1; i >= 0; i-- {
		chain = append(chain, intermediates[i])
	}
	pool := x509.NewCertPool()
	ca := []byte{}
	for _, d := range rootDER {
		v, e := x509.ParseCertificate(d)
		if e != nil {
			t.Fatal(e)
		}
		pool.AddCert(v)
		ca = append(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	mid := x509.NewCertPool()
	for _, d := range intermediates {
		v, e := x509.ParseCertificate(d)
		if e != nil {
			t.Fatal(e)
		}
		mid.AddCert(v)
	}
	opts := x509.VerifyOptions{Roots: pool, Intermediates: mid, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{wanted}}
	if server {
		opts.DNSName = "localhost"
	}
	_, verifyError := parsed.Verify(opts)
	valid := variant == "valid" || variant == "same-name-anchors" ||
		variant == "ca-permitted" || variant == "root-permitted" ||
		variant == "ca-permitted-altname" || variant == "root-permitted-altname"
	// Go's path oracle checks EKU; the protocol's signing-KeyUsage admission is
	// a separate native TLS requirement, not claimed as a Go path rejection.
	if (verifyError == nil) != (valid || variant == "leaf-key-usage") {
		t.Fatalf("independent PKIX fixture %s: %v", variant, verifyError)
	}
	// Prove each new negative fixture fails at the intended boundary rather
	// than accepting any unrelated signing or construction error as evidence.
	if strings.HasPrefix(variant, "expired-") || strings.HasPrefix(variant, "future-") {
		var invalid x509.CertificateInvalidError
		if !errors.As(verifyError, &invalid) || invalid.Reason != x509.Expired {
			t.Fatalf("expected certificate time rejection for %s: %v", variant, verifyError)
		}
	} else if strings.Contains(variant, "-excluded") || strings.HasSuffix(variant, "-permitted-mixed") {
		var invalid x509.CertificateInvalidError
		if !errors.As(verifyError, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("expected DNS constraint rejection for %s: %v", variant, verifyError)
		}
	} else if strings.HasPrefix(variant, "unknown-critical-ca") {
		var critical x509.UnhandledCriticalExtension
		if !errors.As(verifyError, &critical) {
			t.Fatalf("expected issuer critical-extension rejection for %s: %v", variant, verifyError)
		}
	}
	dir := t.TempDir()
	id := identity{roots: pool, cert: tls.Certificate{Certificate: chain, PrivateKey: leafKey}, caFile: filepath.Join(dir, "ca.pem"), certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem")}
	cert := []byte{}
	for _, d := range chain {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	private, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	for path, data := range map[string][]byte{id.caFile: ca, id.certFile: cert, id.keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	clear(private)
	return id, valid
}
func TestDTLSNativePKIX(t *testing.T) {
	variants := []string{"valid", "same-name-anchors", "expired", "future", "path-length", "not-ca", "ca-key-usage", "ca-purpose", "ca-constraints", "root-constraints", "leaf-key-usage", "leaf-purpose", "unknown-critical", "signature", "policy-required"}
	variants = append(variants, "expired-ca0", "future-ca0", "expired-ca1", "future-ca1", "expired-root", "future-root",
		"ca-permitted", "root-permitted", "ca-excluded", "root-excluded", "ca-permitted-altname", "root-permitted-altname",
		"ca-permitted-mixed", "root-permitted-mixed", "ca-excluded-altname", "root-excluded-altname",
		"unknown-critical-ca0", "unknown-critical-ca1")
	for _, mode := range []string{"owned", "external"} {
		for _, role := range []string{"client", "server"} {
			for _, variant := range variants {
				t.Run(mode+"/"+role+"/"+variant, func(t *testing.T) {
					tested, valid := dtlsPKIXIdentity(t, variant, role == "client")
					good := credentials(t, false, "")
					cfg := &dtls.Config{CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, EllipticCurves: []curve.Curve{curve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, SupportedProtocols: []string{"test"}, MTU: 512, FlightInterval: 150 * time.Millisecond}
					ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
					defer cancel()
					type result struct {
						conn *dtls.Conn
						err  error
					}
					peer := make(chan result, 1)
					var n *dtlsProcess
					var listener net.Listener
					var client *dtls.Conn
					if role == "client" {
						cfg.Certificates = []tls.Certificate{tested.cert}
						var err error
						listener, err = dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer listener.Close()
						n = startDTLS(t, listener.Addr().(*net.UDPAddr).Port, mode, "accept", tested, nil)
						go func() {
							c, e := listener.Accept()
							if e != nil {
								peer <- result{nil, e}
								return
							}
							conn := c.(*dtls.Conn)
							e = conn.HandshakeContext(ctx)
							peer <- result{conn, e}
						}()
					} else {
						udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
						if err != nil {
							t.Fatal(err)
						}
						defer udp.Close()
						n = startDTLS(t, udp.LocalAddr().(*net.UDPAddr).Port, mode, "server-pkix", tested, &good)
						if st, _ := n.rpc('I', nil); st != 0 {
							t.Fatal(st)
						}
						cfg.Certificates = []tls.Certificate{tested.cert}
						cfg.RootCAs = good.roots
						cfg.ServerName = "localhost"
						client, err = dtls.Client(udp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(n.port)}, cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer client.Close()
						go func() { peer <- result{client, client.HandshakeContext(ctx)} }()
					}
					var outcome *result
					t.Cleanup(func() {
						cancel()
						if listener != nil {
							_ = listener.Close()
						}
						if client != nil {
							_ = client.Close()
						}
						if outcome != nil && outcome.conn != nil {
							_ = outcome.conn.Close()
						}
						if outcome == nil {
							select {
							case r := <-peer:
								if r.conn != nil {
									_ = r.conn.Close()
								}
							case <-time.After(time.Second):
								t.Error("PKIX peer did not drain")
							}
						}
					})
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						st, _ := n.rpc('P', nil)
						if valid && st < 0 {
							t.Fatalf("valid path refused %d state=%d alert=%d", st, n.state, n.localAlert)
						}
						if !valid && n.state == 2 {
							t.Fatal("invalid PKIX path reached READY")
						}
						if (valid && n.state == 2) || (!valid && n.state == 5 && n.flags&3 == 0 && n.localAlert == 46) {
							break
						}
					}
					if valid {
						if n.state != 2 || n.checks != 1 {
							t.Fatalf("valid path incomplete state=%d policy=%d", n.state, n.checks)
						}
					} else {
						if n.state != 5 || n.localAlert != 46 || n.flags&3 != 0 || n.checks != 0 {
							t.Fatalf("invalid path not rejected state=%d alert=%d flags=%x policy=%d", n.state, n.localAlert, n.flags, n.checks)
						}
					}
					select {
					case r := <-peer:
						outcome = &r
					case <-time.After(time.Second):
						t.Fatal("no independent handshake result")
					}
					if valid && outcome.err != nil {
						t.Fatal(outcome.err)
					}
					if !valid && (outcome.err == nil || !strings.Contains(outcome.err.Error(), "CertificateUnknown")) {
						t.Fatalf("missing peer certificate alert: %v", outcome.err)
					}
					st, _ := n.rpc('A', nil)
					if st != 0 && st != dtlsBusy {
						t.Fatal(st)
					}
					for i := 0; i < 10 && n.flags&3 != 0; i++ {
						_, _ = n.rpc('P', nil)
					}
					if st, _ = n.rpc('C', nil); st != 0 {
						t.Fatal("drain/destroy", st)
					}
					if role == "server" {
						if st, _ = n.rpc('K', nil); st != 0 || n.refs != 0 {
							t.Fatal("listener policy leak", st)
						}
					}
				})
			}
		}
	}
}
