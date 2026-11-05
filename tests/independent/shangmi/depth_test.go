package shangmiinterop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
	peerx509 "github.com/iuboy/pollux-go/smx509"
)

// Independently signed chains exercise production validation on both endpoints.
// Transmitted root inclusion is intentional: it counts toward the public bound.
func depthFixture(t *testing.T, shangmi, client bool, intermediates int, sendRoot bool, p384Issuer ...bool) fixture {
	t.Helper()
	newKey := func() crypto.Signer {
		var key crypto.Signer
		var err error
		if shangmi {
			key, err = sm2.GenerateKey(rand.Reader)
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	now := time.Now().UTC()
	rootKey := newKey()
	if len(p384Issuer) != 0 && p384Issuer[0] {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rootKey = key
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Depth root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: intermediates, MaxPathLenZero: intermediates == 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := peerx509.CreateCertificate(root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, issuerKey := root, rootKey
	var issuers [][]byte
	for i := 0; i < intermediates; i++ {
		key := newKey()
		ca := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: fmt.Sprintf("Depth CA %d", i)},
			NotBefore: root.NotBefore, NotAfter: root.NotAfter, IsCA: true, BasicConstraintsValid: true,
			MaxPathLen: intermediates - i - 1, MaxPathLenZero: i == intermediates-1, KeyUsage: root.KeyUsage}
		der, err := peerx509.CreateCertificate(ca, issuer, key.Public(), issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		issuers = append(issuers, der)
		issuer, issuerKey = ca, key
	}
	key := newKey()
	purpose := x509.ExtKeyUsageServerAuth
	if client {
		purpose = x509.ExtKeyUsageClientAuth
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}}
	der, err := peerx509.CreateCertificate(leaf, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf.Raw = der
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for i := len(issuers) - 1; i >= 0; i-- {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuers[i]})...)
	}
	if sendRoot {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := fixture{leaf: leaf, caPath: filepath.Join(dir, "root.pem"), certPath: filepath.Join(dir, "chain.pem"), keyPath: filepath.Join(dir, "key.pem")}
	for path, data := range map[string][]byte{f.caPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		f.certPath: chain, f.keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	memoryFixtures(t, f.caPath, f.certPath, f.keyPath)
	return f
}

func depthCase(t *testing.T, server, client fixture, profile, version, clientDepth, serverDepth int, outcome string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	args := []string{"--depth-mtls", server.caPath, client.caPath, server.certPath, server.keyPath,
		client.certPath, client.keyPath, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)),
		fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw)), fmt.Sprintf("%x", sm3.Sum(server.leaf.Raw)),
		fmt.Sprint(profile), fmt.Sprint(version), fmt.Sprint(clientDepth), fmt.Sprint(serverDepth)}
	if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
		t.Fatalf("depth admission: %v\n%s", err, out)
	}
}

func testVerificationDepth(t *testing.T) {
	for _, profile := range []struct {
		name        string
		id, version int
	}{{"tls12", 0, 12}, {"tls13", 0, 13}, {"shangmi", 1, 0}} {
		t.Run(profile.name, func(t *testing.T) {
			server := depthFixture(t, profile.id == 1, false, 2, false)
			client := depthFixture(t, profile.id == 1, true, 2, false)
			for _, mode := range []string{"file", "pem", "der"} {
				t.Run(mode, func(t *testing.T) {
					if mode != "file" {
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
					}
					depthCase(t, server, client, profile.id, profile.version, 2, 2, "accept")
					depthCase(t, server, client, profile.id, profile.version, 1, 2, "reject-client")
					depthCase(t, server, client, profile.id, profile.version, 2, 1, "reject-server")
				})
			}
			depthCase(t, server, client, profile.id, profile.version, 0, 5, "accept")
			rootIncluded := depthFixture(t, profile.id == 1, false, 1, true)
			depthCase(t, rootIncluded, client, profile.id, profile.version, 2, 2, "accept")
			depthCase(t, rootIncluded, client, profile.id, profile.version, 1, 2, "reject-client")
		})
	}
}
