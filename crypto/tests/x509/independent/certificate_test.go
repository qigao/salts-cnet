package independent

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"flag"
	"math/big"
	"os/exec"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var peer = flag.String("peer", "", "formal native certificate endpoint")

func TestSM2Certificates(t *testing.T) {
	if *peer == "" {
		t.Fatal("missing native peer")
	}
	issuer, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "independent subject"},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: "explicit issuer"}, PublicKey: &issuer.PublicKey}
	encoded, err := smx509.CreateCertificate(rand.Reader, template, parent, &subject.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := smx509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	expected := elliptic.Marshal(subject.Curve, subject.X, subject.Y)
	issuerPublic := elliptic.Marshal(issuer.Curve, issuer.X, issuer.Y)
	invoke := func(t *testing.T, cert, id, pub []byte, wantSuccess bool) {
		t.Helper()
		var input bytes.Buffer
		input.Write(pub)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(id)))
		input.Write(length[:])
		input.Write(id)
		input.Write(cert)
		cmd := exec.Command(*peer)
		cmd.Stdin = &input
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		result, err := cmd.Output()
		if wantSuccess {
			if err != nil {
				t.Fatalf("native peer: %v, %s", err, stderr.String())
			}
			if !bytes.Equal(result, expected) {
				t.Fatal("subject key mismatch")
			}
		} else {
			failure, ok := err.(*exec.ExitError)
			if !ok || failure.ExitCode() != 3 || len(result) != 0 {
				t.Fatalf("expected signature rejection without output, got %v (%x)", err, result)
			}
		}
	}
	defaultID := []byte("1234567812345678")
	t.Run("default_ID", func(t *testing.T) { invoke(t, encoded, defaultID, issuerPublic, true) })
	t.Run("wrong_issuer", func(t *testing.T) { invoke(t, encoded, defaultID, expected, false) })
	t.Run("wrong_ID", func(t *testing.T) { invoke(t, encoded, []byte("wrong issuer"), issuerPublic, false) })
	t.Run("tamper", func(t *testing.T) {
		corrupt := bytes.Clone(encoded)
		corrupt[len(corrupt)-1] ^= 1
		invoke(t, corrupt, defaultID, issuerPublic, false)
	})
	for _, id := range [][]byte{{'c', 0, 'a'}, bytes.Repeat([]byte{'x'}, 8191)} {
		t.Run("explicit_ID", func(t *testing.T) {
			sig, err := issuer.Sign(rand.Reader, parsed.RawTBSCertificate, sm2.NewSM2SignerOption(true, id))
			if err != nil {
				t.Fatal(err)
			}
			// Preserve the exact independently encoded TBS while changing the
			// issuer's explicit signing identity. No production code is reused.
			signed, err := asn1.Marshal(struct {
				TBS       asn1.RawValue
				Algorithm pkix.AlgorithmIdentifier
				Signature asn1.BitString
			}{asn1.RawValue{FullBytes: parsed.RawTBSCertificate},
				pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}},
				asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
			if err != nil {
				t.Fatal(err)
			}
			invoke(t, signed, id, issuerPublic, true)
			invoke(t, signed, defaultID, issuerPublic, false)
		})
	}
}
