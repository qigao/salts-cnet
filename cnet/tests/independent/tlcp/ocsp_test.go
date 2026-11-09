package tlcpinterop

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// CNet-owned fixtures use an independent ASN.1/SM2 producer and the actual
// NativeIO/transport owner. This is separate from the Crypto primitive suite.
type statusCertID struct {
	Algorithm         pkix.AlgorithmIdentifier
	NameHash, KeyHash []byte
	Serial            *big.Int
}
type statusSingle struct {
	ID         statusCertID
	Status     asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"generalized,explicit,tag:0"`
}
type statusBody struct {
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []statusSingle
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

func statusDER(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func statusResponse(t *testing.T, target, signer fixture, now time.Time, scenario string, responder ...fixture) []byte {
	t.Helper()
	signingCert, signingKey := signer.root, signer.rootKey
	if len(responder) != 0 {
		if len(responder) != 1 {
			t.Fatal("ambiguous responder fixture")
		}
		signingCert, signingKey = responder[0].root, responder[0].rootKey
	}
	name := sm3.Sum(signer.root.RawSubject)
	key := sm3.Sum(elliptic.Marshal(signer.rootKey.Curve, signer.rootKey.X, signer.rootKey.Y))
	body := statusBody{Responder: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: signingCert.RawSubject},
		ProducedAt: now.Add(-30 * time.Second), Responses: []statusSingle{{
			statusCertID{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}}, name[:], key[:], big.NewInt(2)},
			asn1.RawValue{Class: 2, Tag: 0}, now.Add(-time.Minute), now.Add(time.Hour)}}}
	second := body.Responses[0]
	second.ID.Serial = big.NewInt(3)
	body.Responses = append(body.Responses, second)
	switch scenario {
	case "unknown-encryption":
		body.Responses[1].Status.Tag = 2
	case "revoked-signing", "revoked-encryption", "revoked-both":
		der := statusDER(t, struct {
			Time time.Time `asn1:"generalized"`
		}{now.Add(-2 * time.Minute)})
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			t.Fatal(err)
		}
		for i := range body.Responses {
			if scenario == "revoked-both" || (i == 0 && scenario == "revoked-signing") || (i == 1 && scenario == "revoked-encryption") {
				body.Responses[i].Status = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: raw.Bytes}
			}
		}
	case "missing-encryption":
		body.Responses = body.Responses[:1]
	case "duplicate":
		body.Responses = append(body.Responses, body.Responses[1])
	case "stale":
		body.Responses[0].ThisUpdate = now.Add(-3 * time.Hour)
		body.Responses[0].NextUpdate = now.Add(-time.Hour)
		body.ProducedAt = now.Add(-2 * time.Hour)
	case "age-limit":
		body.Responses[0].ThisUpdate = now.Add(-2 * time.Hour)
	case "future":
		body.Responses[0].ThisUpdate, body.ProducedAt = now.Add(time.Minute), now.Add(61*time.Second)
	case "nonce":
		body.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}, Value: statusDER(t, make([]byte, 32))}}
	}
	tbs := statusDER(t, body)
	sig, err := signingKey.Sign(rand.Reader, tbs, sm2.NewSM2SignerOption(true, []byte("1234567812345678")))
	if err != nil {
		t.Fatal(err)
	}
	basic := statusDER(t, struct {
		Body      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}}, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	return statusDER(t, struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type asn1.ObjectIdentifier
			DER  []byte
		} `asn1:"explicit,tag:0"`
	}{0, struct {
		Type asn1.ObjectIdentifier
		DER  []byte
	}{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}, basic}})
}
func tlcpStatusDelegate(t *testing.T, f fixture, now time.Time, scenario string) fixture {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "TLCP status delegate"},
		BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
	if scenario == "delegated-missing-nocheck" {
		c.ExtraExtensions = nil
	}
	if scenario == "delegated-expired" {
		c.NotAfter = now.Add(-time.Second)
	}
	der, err := smx509.CreateCertificate(rand.Reader, c, f.root, &key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{root: parsed, rootKey: key}
}
func TestTLCPOCSPPolicy(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	for _, scenario := range []string{"valid", "with-issuer", "revoked-signing", "revoked-encryption", "revoked-both",
		"unknown-encryption", "missing-encryption", "duplicate", "wrong-cert-id", "wrong-profile", "wrong-identity",
		"substituted-issuer", "stale", "future", "age-limit", "bad-signature", "malformed", "nonce", "unsupported-client-auth", "delegated", "delegated-revoked-encryption", "delegated-unknown-encryption", "delegated-missing-encryption", "delegated-missing-nocheck", "delegated-expired", "delegated-wrong-issuer-id"} {
		t.Run(scenario, func(t *testing.T) {
			f := credentials(t, nil)
			signer := f
			if scenario == "substituted-issuer" {
				signer = credentials(t, nil)
			}
			now := time.Now().UTC().Truncate(time.Second)
			der := statusResponse(t, f, signer, now, scenario)
			responderPath := ""
			if strings.HasPrefix(scenario, "delegated") {
				delegate := tlcpStatusDelegate(t, f, now, scenario)
				responderPath = filepath.Join(t.TempDir(), "responder.der")
				if err := os.WriteFile(responderPath, delegate.root.Raw, 0600); err != nil {
					t.Fatal(err)
				}
				der = statusResponse(t, f, signer, now, strings.TrimPrefix(scenario, "delegated-"), delegate)
			}
			if scenario == "bad-signature" {
				der[len(der)-1] ^= 1
			}
			if scenario == "malformed" {
				der = der[:len(der)-1]
			}
			if scenario == "with-issuer" {
				f.certificates[0].Certificate = append(f.certificates[0].Certificate, f.root.Raw)
			}
			dir := t.TempDir()
			issuerPath, responsePath := filepath.Join(dir, "issuer.der"), filepath.Join(dir, "status.der")
			for path, data := range map[string][]byte{issuerPath: signer.root.Raw, responsePath: der} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			mode := "normal"
			switch scenario {
			case "stale", "future", "age-limit", "bad-signature", "malformed", "nonce", "duplicate", "delegated-missing-nocheck", "delegated-expired", "delegated-wrong-issuer-id":
				mode = "factory-reject"
			case "wrong-cert-id", "wrong-profile", "with-issuer", "unsupported-client-auth":
				mode = scenario
			}
			if mode == "factory-reject" || mode == "unsupported-client-auth" || mode == "wrong-profile" {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				args := []string{"--tlcp-ocsp-policy", "1", "localhost", f.caPath, issuerPath, responsePath, "reject", mode}
				if responderPath != "" {
					issuerID := "1234567812345678"
					if scenario == "delegated-wrong-issuer-id" {
						issuerID = "wrong ID"
					}
					args = append(args, responderPath, issuerID)
				}
				out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput()
				if err != nil {
					t.Fatalf("TLCP OCSP admission: %v\n%s", err, out)
				}
				return
			}
			identity := "localhost"
			if scenario == "wrong-identity" {
				identity = "127.0.0.2"
			}
			policy := []string{issuerPath, responsePath, mode, "ocsp"}
			if responderPath != "" {
				policy = append(policy, responderPath, "1234567812345678")
			}
			runNativeClient(t, f, identity, scenario == "valid" || scenario == "with-issuer" || scenario == "delegated", []uint16{tlcp.ECC_SM4_GCM_SM3}, policy...)
		})
	}
}
