package shangmiinterop

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	revocationSuite(t, false)
}

func TestShangMiCNetCRLPolicy(t *testing.T) {
	revocationSuite(t, true)
}

func revocationSuite(t *testing.T, factory bool) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	scenarios := []string{"valid", "revoked", "stale", "bad-signature", "rollback", "wrong-issuer", "malformed", "future"}
	if factory {
		scenarios = append(scenarios, "substituted-issuer", "leaf-and-issuer", "age-limit")
	}
	for _, side := range []string{"client", "server"} {
		for _, scenario := range scenarios {
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
				case "wrong-issuer", "substituted-issuer":
					signer = credentials(t, nil)
				case "future":
					template.ThisUpdate = now.Add(time.Minute)
				case "age-limit":
					template.ThisUpdate = now.Add(-2 * time.Hour)
				case "leaf-and-issuer":
					chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.leaf.Raw}),
						pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.root.Raw})...)
					if err := os.WriteFile(peer.certPath, chain, 0600); err != nil {
						t.Fatal(err)
					}
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
				issuerDER := peer.root.Raw
				if scenario == "substituted-issuer" {
					// Same issuer name, valid foreign CRL: leaf signature binding must reject.
					issuerDER = signer.root.Raw
				}
				for path, data := range map[string][]byte{issuerPath: issuerDER, crlPath: der} {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				outcome := "reject"
				if scenario == "valid" || scenario == "leaf-and-issuer" {
					outcome = "accept"
				}
				run := func(outcome, mode string) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
					defer cancel()
					args := []string{"--shangmi-revocation", server.caPath, client.caPath,
						server.certPath, server.keyPath, client.certPath, client.keyPath,
						side, issuerPath, crlPath, fmt.Sprint(now.Unix()), outcome, mode}
					if factory {
						args[0] = "--shangmi-crl-policy"
					}
					if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
						t.Fatalf("native revocation: %v\n%s", err, out)
					}
				}
				mode := "normal"
				if factory && scenario != "valid" && scenario != "revoked" && scenario != "substituted-issuer" && scenario != "leaf-and-issuer" {
					mode = "factory-reject"
				}
				run(outcome, mode)
				if factory && scenario == "valid" {
					for _, mode := range []string{"wrong-cert-id", "wrong-crl-id", "wrong-role"} {
						run("reject", mode)
					}
				}
				if side == "client" && scenario == "valid" {
					// Even a valid current CRL cannot override mandatory identity.
					run("reject", "wrong-name")
				}
			})
		}
	}
}
