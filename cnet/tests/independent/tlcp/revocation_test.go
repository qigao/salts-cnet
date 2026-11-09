package tlcpinterop

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

func TestTLCPCRLPolicy(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	for _, scenario := range []string{"valid", "revoked-signing", "revoked-encryption", "revoked-both",
		"unrelated-serial", "with-issuer", "wrong-cert-id", "wrong-profile", "substituted-issuer", "wrong-identity",
		"stale", "bad-signature", "rollback", "future", "unsupported-client-auth"} {
		t.Run(scenario, func(t *testing.T) {
			f := credentials(t, nil)
			signer := f
			if scenario == "substituted-issuer" {
				signer = credentials(t, nil)
			}
			now := time.Now().UTC().Truncate(time.Second)
			template := &x509.RevocationList{Number: big.NewInt(42), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
			addRevoked := func(serial int64) {
				template.RevokedCertificateEntries = append(template.RevokedCertificateEntries,
					x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: now.Add(-time.Minute), ReasonCode: 1})
			}
			switch scenario {
			case "revoked-signing":
				addRevoked(2)
			case "revoked-encryption":
				addRevoked(3)
			case "revoked-both":
				addRevoked(2)
				addRevoked(3)
			case "unrelated-serial":
				addRevoked(4)
			case "with-issuer":
				f.certificates[0].Certificate = append(f.certificates[0].Certificate, f.root.Raw)
			case "stale":
				template.ThisUpdate, template.NextUpdate = now.Add(-3*time.Hour), now.Add(-time.Hour)
			case "rollback":
				template.Number = big.NewInt(41)
			case "future":
				template.ThisUpdate = now.Add(time.Hour)
				template.NextUpdate = now.Add(2 * time.Hour)
			}
			der, err := smx509.CreateRevocationList(rand.Reader, template, signer.root, signer.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "bad-signature" {
				der[len(der)-1] ^= 1
			}
			dir := t.TempDir()
			issuerPath, crlPath := filepath.Join(dir, "issuer.der"), filepath.Join(dir, "crl.der")
			for path, data := range map[string][]byte{issuerPath: signer.root.Raw, crlPath: der} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			mode := "normal"
			if scenario == "wrong-cert-id" || scenario == "wrong-profile" || scenario == "with-issuer" {
				mode = scenario
			}
			if scenario == "stale" || scenario == "bad-signature" || scenario == "rollback" || scenario == "future" {
				mode = "factory-reject"
			}
			if scenario == "unsupported-client-auth" {
				mode = scenario
			}
			if mode == "factory-reject" || mode == "unsupported-client-auth" || mode == "wrong-profile" {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, *native, "--tlcp-crl-policy", "1", "localhost", f.caPath,
					issuerPath, crlPath, "reject", mode).CombinedOutput()
				if err != nil {
					t.Fatalf("TLCP policy admission: %v\n%s", err, out)
				}
				return
			}
			identity := "localhost"
			if scenario == "wrong-identity" {
				identity = "127.0.0.2"
			}
			accept := scenario == "valid" || scenario == "unrelated-serial" || scenario == "with-issuer"
			runNativeClient(t, f, identity, accept, []uint16{tlcp.ECC_SM4_GCM_SM3}, issuerPath, crlPath, mode)
		})
	}
}
