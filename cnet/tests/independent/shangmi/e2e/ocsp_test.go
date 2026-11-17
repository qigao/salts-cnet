package shangmiinterop

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	peerx509 "github.com/iuboy/pollux-go/smx509"
	"golang.org/x/crypto/ocsp"
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
func statusResponse(t *testing.T, target, signer fixture, now time.Time, scenario string) []byte {
	t.Helper()
	name := sm3.Sum(signer.root.RawSubject)
	key := sm3.Sum(elliptic.Marshal(signer.rootKey.Curve, signer.rootKey.X, signer.rootKey.Y))
	body := statusBody{Responder: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: signer.root.RawSubject},
		ProducedAt: now.Add(-30 * time.Second), Responses: []statusSingle{{
			statusCertID{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}}, name[:], key[:], target.leaf.SerialNumber},
			asn1.RawValue{Class: 2, Tag: 0}, now.Add(-time.Minute), now.Add(time.Hour)}}}
	switch scenario {
	case "unknown":
		body.Responses[0].Status.Tag = 2
	case "revoked":
		der := statusDER(t, struct {
			Time time.Time `asn1:"generalized"`
		}{now.Add(-2 * time.Minute)})
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			t.Fatal(err)
		}
		body.Responses[0].Status = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: raw.Bytes}
	case "missing-target":
		body.Responses[0].ID.Serial = big.NewInt(999999)
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
	sig, err := signer.rootKey.Sign(rand.Reader, tbs, sm2.NewSM2SignerOption(true, []byte("1234567812345678")))
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
func delegatedStatusResponse(t *testing.T, peer fixture, now time.Time, scenario string) ([]byte, []byte) {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "status delegate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
	if scenario == "delegated-missing-nocheck" {
		cert.ExtraExtensions = nil
	}
	if scenario == "delegated-expired" {
		cert.NotAfter = now.Add(-time.Second)
	}
	der, err := peerx509.CreateCertificate(cert, peer.root, &key.PublicKey, peer.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := peerx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	template := &ocsp.Response{Status: ocsp.Good, SerialNumber: peer.leaf.SerialNumber, IssuerHash: crypto.SHA256,
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if scenario == "delegated-embedded" {
		template.Certificate = parsed
	}
	if scenario == "delegated-unknown" {
		template.Status = ocsp.Unknown
	}
	response, err := peerx509.CreateOCSPResponse(peer.root, parsed, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return response, der
}
func TestShangMiCNetOCSPPolicy(t *testing.T) {
	if *native == "" {
		t.Fatal("-native required")
	}
	for _, side := range []string{"client", "server"} {
		for _, scenario := range []string{"valid", "independent-producer", "leaf-and-issuer", "revoked", "unknown", "missing-target", "stale", "future", "age-limit", "rollback", "wrong-issuer", "substituted-issuer", "bad-signature", "malformed", "nonce", "delegated", "delegated-embedded", "delegated-unknown", "delegated-missing-nocheck", "delegated-expired", "delegated-wrong-issuer-id"} {
			t.Run(side+"/"+scenario, func(t *testing.T) {
				server, client := credentials(t, nil), clientCredentials(t, nil)
				peer := server
				if side == "server" {
					peer = client
				}
				signer := peer
				if scenario == "wrong-issuer" || scenario == "substituted-issuer" {
					signer = credentials(t, nil)
				}
				now := time.Now().UTC().Truncate(time.Second)
				floor := now.Add(-2 * time.Minute).Unix()
				if scenario == "rollback" {
					floor = now.Add(-30 * time.Second).Unix()
				}
				der := statusResponse(t, peer, signer, now, scenario)
				var responder []byte
				if strings.HasPrefix(scenario, "delegated") {
					der, responder = delegatedStatusResponse(t, peer, now, scenario)
				}
				if scenario == "independent-producer" {
					var err error
					der, err = peerx509.CreateOCSPResponse(peer.root, peer.root, &ocsp.Response{
						Status: ocsp.Good, SerialNumber: peer.leaf.SerialNumber,
						IssuerHash: crypto.SHA256, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, peer.rootKey)
					if err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "valid" || scenario == "independent-producer" {
					parsed, err := peerx509.ParseOCSPResponseWithIssuerAt(der, peer.root, now)
					if err != nil {
						t.Fatal(err)
					}
					if parsed.Status != ocsp.Good || parsed.SerialNumber.Cmp(peer.leaf.SerialNumber) != 0 {
						t.Fatal("independent OCSP oracle mismatch")
					}
				}
				if scenario == "bad-signature" {
					der[len(der)-1] ^= 1
				}
				if scenario == "malformed" {
					der = der[:len(der)-1]
				}
				issuer := peer.root.Raw
				if scenario == "substituted-issuer" {
					issuer = signer.root.Raw
				}
				if scenario == "leaf-and-issuer" {
					chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.root.Raw})...)
					if err := os.WriteFile(peer.certPath, chain, 0600); err != nil {
						t.Fatal(err)
					}
				}
				issuerPath, responsePath := filepath.Join(t.TempDir(), "issuer.der"), filepath.Join(t.TempDir(), "status.der")
				for path, value := range map[string][]byte{issuerPath: issuer, responsePath: der} {
					if err := os.WriteFile(path, value, 0600); err != nil {
						t.Fatal(err)
					}
				}
				responderPath := ""
				if responder != nil {
					responderPath = filepath.Join(t.TempDir(), "responder.der")
					if err := os.WriteFile(responderPath, responder, 0600); err != nil {
						t.Fatal(err)
					}
				}
				outcome, mode := "reject", "factory-reject"
				switch scenario {
				case "valid", "independent-producer", "leaf-and-issuer", "delegated", "delegated-embedded":
					outcome, mode = "accept", "normal"
				case "revoked", "unknown", "missing-target", "substituted-issuer", "delegated-unknown":
					mode = "normal"
				}
				run := func(outcome, mode string) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					args := []string{"--shangmi-ocsp-policy", server.caPath, client.caPath, server.certPath, server.keyPath,
						client.certPath, client.keyPath, side, issuerPath, responsePath, fmt.Sprint(floor), outcome, mode}
					if responderPath != "" {
						issuerID := "1234567812345678"
						if scenario == "delegated-wrong-issuer-id" {
							issuerID = "wrong ID"
						}
						args = append(args, responderPath, issuerID)
					}
					if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
						t.Fatalf("CNet OCSP: %v\n%s", err, out)
					}
				}
				run(outcome, mode)
				if scenario == "valid" {
					for _, negative := range []string{"wrong-cert-id", "wrong-response-id", "wrong-role"} {
						run("reject", negative)
					}
					if side == "client" {
						run("reject", "wrong-name")
					}
				}
			})
		}
	}
}
