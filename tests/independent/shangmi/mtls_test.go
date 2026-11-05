package shangmiinterop

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

// Both endpoints are production CNet/NativeIO/GmSSL here. Certificates and
// fingerprint expectations are independent; this is not a second TLS engine.
func mutual(t *testing.T, server, client fixture, outcome string) {
	t.Helper()
	cert, key := client.certPath, client.keyPath
	if cert == "" {
		cert, key = "-", "-"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	clientHash := "-"
	if client.leaf != nil {
		clientHash = fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw))
	}
	args := []string{"--shangmi-mtls", server.caPath, client.caPath, server.certPath, server.keyPath,
		cert, key, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)), clientHash,
		fmt.Sprintf("%x", sm3.Sum(server.leaf.Raw))}
	if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
		t.Fatalf("native ShangMi mTLS: %v\n%s", err, out)
	}
}

func clientCredentials(t *testing.T, change func(*x509.Certificate)) fixture {
	t.Helper()
	return credentials(t, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if change != nil {
			change(c)
		}
	})
}

func corruptCertificate(t *testing.T, f fixture) fixture {
	t.Helper()
	f.leaf.Raw[len(f.leaf.Raw)-1] ^= 1
	if err := os.WriteFile(f.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestShangMiMutual(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	server, client := credentials(t, nil), clientCredentials(t, nil)
	t.Run("verified_distinct_trust_roots", func(t *testing.T) { mutual(t, server, client, "accept") })
	t.Run("reject_missing_client", func(t *testing.T) {
		missing := client
		missing.certPath, missing.keyPath, missing.leaf = "", "", nil
		mutual(t, server, missing, "reject-server")
	})
	t.Run("reject_client_unknown_ca", func(t *testing.T) {
		bad := client
		bad.caPath = credentials(t, nil).caPath
		mutual(t, server, bad, "reject-server")
	})
	t.Run("reject_server_unknown_ca", func(t *testing.T) {
		bad := server
		bad.caPath = credentials(t, nil).caPath
		mutual(t, bad, client, "reject-client")
	})
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		},
		"future":          func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"key_usage":       func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"server_only_eku": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
	} {
		t.Run("reject_client_"+name, func(t *testing.T) { mutual(t, server, clientCredentials(t, change), "reject-server") })
	}
	t.Run("reject_client_certificate_signature", func(t *testing.T) {
		mutual(t, server, corruptCertificate(t, clientCredentials(t, nil)), "reject-server")
	})
	t.Run("reject_server_certificate_signature", func(t *testing.T) {
		mutual(t, corruptCertificate(t, credentials(t, nil)), client, "reject-client")
	})
}
