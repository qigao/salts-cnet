package shangmiinterop

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	peerx509 "github.com/iuboy/pollux-go/smx509"
)

// Production Crypto streams with independently signed certificates and CRLs.
// This qualifies admission ordering, not TCP or an independent TLS engine.
func TestShangMiRevocation(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, side := range []string{"client", "server"} {
		for _, scenario := range []string{"valid", "revoked", "stale", "bad-signature", "rollback", "wrong-issuer", "malformed", "future"} {
			t.Run(side+"/"+scenario, func(t *testing.T) {
				server, client := credentials(t, nil), clientCredentials(t, nil)
				peer := server
				if side == "server" {
					peer = client
				}
				now := time.Now().UTC().Truncate(time.Second)
				template := &x509.RevocationList{Number: big.NewInt(42), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
				signer := peer
				switch scenario {
				case "revoked":
					template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: peer.leaf.SerialNumber, RevocationTime: now.Add(-time.Minute), ReasonCode: 1}}
				case "stale":
					template.ThisUpdate, template.NextUpdate = now.Add(-3*time.Hour), now.Add(-time.Hour)
				case "rollback":
					template.Number = big.NewInt(41)
				case "wrong-issuer":
					signer = credentials(t, nil)
				case "future":
					template.ThisUpdate = now.Add(time.Minute)
				}
				der, err := peerx509.CreateRevocationList(template, signer.root, signer.rootKey)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "bad-signature" {
					der[len(der)-1] ^= 1
				} else if scenario == "malformed" {
					der = der[:len(der)-1]
				}
				dir := t.TempDir()
				issuerPath, crlPath := filepath.Join(dir, "issuer.der"), filepath.Join(dir, "revocations.der")
				for path, data := range map[string][]byte{issuerPath: peer.root.Raw, crlPath: der} {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				outcome := "reject"
				if scenario == "valid" {
					outcome = "accept"
				}
				run := func(outcome, mode string) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
					defer cancel()
					args := []string{"--shangmi-revocation", server.caPath, client.caPath,
						server.certPath, server.keyPath, client.certPath, client.keyPath,
						side, issuerPath, crlPath, fmt.Sprint(now.Unix()), outcome, mode}
					if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
						t.Fatalf("native revocation: %v\n%s", err, out)
					}
				}
				run(outcome, "normal")
				if side == "client" && scenario == "valid" {
					// Even a valid current CRL cannot override mandatory identity.
					run("reject", "wrong-name")
				}
			})
		}
	}
}
