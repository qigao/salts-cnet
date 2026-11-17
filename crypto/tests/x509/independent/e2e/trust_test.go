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
	"fmt"
	"math/big"
	"os/exec"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var trustPeer = flag.String("trust-peer", "", "formal native pinned-trust endpoint")
var defaultSigningID = []byte("1234567812345678")

type pathFixture struct {
	der                                   [][]byte // leaf-first, including the independently supplied anchor last
	keys                                  []*sm2.PrivateKey
	ids                                   [][]byte
	pin                                   []byte
	now                                   int64
	role, revocation, failDepth, decision byte
}

func makePath(t *testing.T, count int, change func(int, *x509.Certificate)) pathFixture {
	t.Helper()
	f := pathFixture{der: make([][]byte, count+1), keys: make([]*sm2.PrivateKey, count+1), ids: make([][]byte, count),
		now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), role: 1, revocation: 2, failDepth: 255}
	templates := make([]*x509.Certificate, count+1)
	for i := 0; i <= count; i++ {
		var err error
		f.keys[i], err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		templates[i] = &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("identity-%d", i)},
			PublicKey: &f.keys[i].PublicKey, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter: time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC), BasicConstraintsValid: true}
		if i == 0 {
			templates[i].NotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			templates[i].NotAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			templates[i].KeyUsage = x509.KeyUsageDigitalSignature
			templates[i].ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			templates[i].IsCA = true
			templates[i].KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			templates[i].MaxPathLen = i - 1
			templates[i].MaxPathLenZero = i == 1
		}
		if change != nil {
			change(i, templates[i])
		}
	}
	for i := count; i >= 0; i-- {
		issuer := i + 1
		if issuer > count {
			issuer = count
		}
		var err error
		f.der[i], err = smx509.CreateCertificate(rand.Reader, templates[i], templates[issuer], &f.keys[i].PublicKey, f.keys[issuer])
		if err != nil {
			t.Fatal(err)
		}
		if i < count {
			f.ids[i] = bytes.Clone(defaultSigningID)
		}
	}
	f.pin = elliptic.Marshal(f.keys[0].Curve, f.keys[0].X, f.keys[0].Y)
	return f
}

func resign(t *testing.T, cert []byte, issuer *sm2.PrivateKey, id []byte, edit func([]byte) []byte) []byte {
	t.Helper()
	parsed, err := smx509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	tbs := parsed.RawTBSCertificate
	if edit != nil {
		tbs = edit(bytes.Clone(tbs))
	}
	sig, err := issuer.Sign(rand.Reader, tbs, sm2.NewSM2SignerOption(true, id))
	if err != nil {
		t.Fatal(err)
	}
	result, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}},
		asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func checkPath(t *testing.T, f pathFixture, status int8, calls byte) {
	t.Helper()
	var input bytes.Buffer
	if err := binary.Write(&input, binary.BigEndian, f.now); err != nil {
		t.Fatal(err)
	}
	input.Write([]byte{byte(len(f.der) - 1), f.role, f.revocation, f.failDepth, f.decision})
	input.Write(f.pin)
	writeSpan := func(data []byte) {
		if len(data) > 65535 {
			t.Fatal("oversized fixture")
		}
		if err := binary.Write(&input, binary.BigEndian, uint16(len(data))); err != nil {
			t.Fatal(err)
		}
		input.Write(data)
	}
	writeSpan(f.der[len(f.der)-1])
	for i := 0; i < len(f.der)-1; i++ {
		writeSpan(f.ids[i])
		writeSpan(f.der[i])
	}
	command := exec.Command(*trustPeer)
	command.Stdin = &input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		t.Fatalf("native peer: %v: %s", err, stderr.String())
	}
	if len(out) != 68 || int8(out[0]) != status || out[1] != calls || out[67] != 0xa5 {
		t.Fatalf("status/callback/boundary mismatch: %x, expected %d/%d", out, status, calls)
	}
	expected := make([]byte, 65)
	if status == 0 {
		expected = f.pin
	}
	if !bytes.Equal(out[2:67], expected) {
		t.Fatal("key release/erasure mismatch")
	}
}

func TestPinnedChain(t *testing.T) {
	if *trustPeer == "" {
		t.Fatal("missing native trust peer")
	}
	for depth := 1; depth <= 4; depth++ {
		t.Run(fmt.Sprintf("accepted_depth_%d", depth), func(t *testing.T) { checkPath(t, makePath(t, depth, nil), 0, 0) })
	}
	t.Run("client_purpose", func(t *testing.T) {
		f := makePath(t, 2, func(i int, c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
		f.role = 2
		checkPath(t, f, 0, 0)
		f.role = 1
		checkPath(t, f, -2, 0)
	})
	t.Run("different_explicit_signing_IDs", func(t *testing.T) {
		f := makePath(t, 2, nil)
		f.ids[0] = []byte{'c', 0, 'a'}
		f.ids[1] = []byte("parent-id")
		for i := 0; i < 2; i++ {
			f.der[i] = resign(t, f.der[i], f.keys[i+1], f.ids[i], nil)
		}
		checkPath(t, f, 0, 0)
		f.ids[1] = defaultSigningID
		checkPath(t, f, -2, 0)
	})
	t.Run("time_boundaries", func(t *testing.T) {
		f := makePath(t, 2, nil)
		for _, date := range []time.Time{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
			f.now = date.Unix()
			checkPath(t, f, 0, 0)
		}
		f.now = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix() - 1
		checkPath(t, f, -2, 0)
		f.now = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix() + 1
		checkPath(t, f, -2, 0)
	})
	for _, year := range []int{2024, 2049, 2050} {
		t.Run(fmt.Sprintf("calendar_%d", year), func(t *testing.T) {
			month, day := time.December, 31
			if year == 2024 {
				month, day = time.February, 29
			}
			when := time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
			f := makePath(t, 1, func(i int, c *x509.Certificate) {
				if i == 0 {
					c.NotBefore = when
					c.NotAfter = when.Add(time.Hour)
				}
			})
			f.now = when.Unix()
			checkPath(t, f, 0, 0)
		})
	}
	t.Run("invalid_Gregorian_day", func(t *testing.T) {
		f := makePath(t, 1, nil)
		f.der[0] = resign(t, f.der[0], f.keys[1], defaultSigningID, func(tbs []byte) []byte {
			return bytes.Replace(tbs, []byte("250101000000Z"), []byte("250230000000Z"), 1)
		})
		checkPath(t, f, -2, 0)
	})
	type badCase struct {
		name   string
		index  int
		change func(*x509.Certificate)
	}
	bad := []badCase{
		{"expired_anchor", 2, func(c *x509.Certificate) { c.NotAfter = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"future_intermediate", 1, func(c *x509.Certificate) { c.NotBefore = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"anchor_pathLen_zero", 2, func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = true }},
		{"non_CA_intermediate", 1, func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = 0; c.MaxPathLenZero = false }},
		{"CA_leaf", 0, func(c *x509.Certificate) { c.IsCA = true }},
		{"missing_leaf_KU", 0, func(c *x509.Certificate) { c.KeyUsage = 0 }},
		{"missing_leaf_EKU", 0, func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"any_EKU_only", 0, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{"wrong_leaf_EKU", 0, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"wrong_intermediate_EKU", 1, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"wrong_anchor_EKU", 2, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"missing_CA_KU", 1, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }},
		{"leaf_certSign", 0, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }},
		{"leaf_CRLSign", 0, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCRLSign }},
		{"empty_subject", 0, func(c *x509.Certificate) { c.Subject = pkix.Name{} }},
		{"empty_RDN", 0, func(c *x509.Certificate) { c.RawSubject = []byte{0x30, 2, 0x31, 0} }},
		{"empty_attribute_value", 0, func(c *x509.Certificate) {
			c.RawSubject = []byte{0x30, 11, 0x31, 9, 0x30, 7, 6, 3, 0x55, 4, 3, 0x0c, 0}
		}},
		{"unknown_critical", 1, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{"noncritical_CA_constraints", 1, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 1, 1, 0xff}}}
		}},
		{"path_without_CA", 0, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 2, 1, 0}}}
		}},
		{"explicit_default_false", 0, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 1, 1, 0}}}
		}},
		{"empty_KU", 0, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{3, 1, 0}}}
		}},
		{"nonminimal_KU", 0, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{3, 3, 7, 0x80, 0}}}
		}},
		{"encipher_without_agreement", 0, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageEncipherOnly }},
		{"critical_SAN", 0, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: []byte{0x30, 3, 0x82, 1, 'a'}}}
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			f := makePath(t, 2, func(i int, c *x509.Certificate) {
				if i == tc.index {
					tc.change(c)
				}
			})
			f.revocation = 1
			checkPath(t, f, -2, 0)
		})
	}
	for _, oid := range []int{30, 32, 33, 36, 54} {
		t.Run(fmt.Sprintf("unsupported_constraint_%d", oid), func(t *testing.T) {
			f := makePath(t, 2, func(i int, c *x509.Certificate) {
				if i == 1 {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, oid}, Value: []byte{0x30, 0}}}
				}
			})
			checkPath(t, f, -2, 0)
		})
	}
	t.Run("noncritical_metadata_is_not_identity", func(t *testing.T) {
		f := makePath(t, 1, func(i int, c *x509.Certificate) {
			if i == 0 {
				c.DNSNames = []string{"unrelated.example"}
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
			}
		})
		checkPath(t, f, 0, 0)
		f.pin = elliptic.Marshal(f.keys[1].Curve, f.keys[1].X, f.keys[1].Y)
		checkPath(t, f, -2, 0)
	})
	t.Run("revocation_callback_gate", func(t *testing.T) {
		f := makePath(t, 2, nil)
		f.revocation = 1
		checkPath(t, f, 0, 2)
		for _, decision := range []byte{254, 251, 1} {
			f.failDepth = 0
			f.decision = decision
			checkPath(t, f, -2, 1)
			f.failDepth = 1
			checkPath(t, f, -2, 2)
		}
	})
	t.Run("wrong_signature_anchor_order_or_names", func(t *testing.T) {
		f := makePath(t, 2, nil)
		f.revocation = 1
		f.der[0][len(f.der[0])-1] ^= 1
		checkPath(t, f, -2, 0)
		f.der[0][len(f.der[0])-1] ^= 1
		f.der[0], f.der[1] = f.der[1], f.der[0]
		checkPath(t, f, -2, 0)
		f.der[0], f.der[1] = f.der[1], f.der[0]
		f.der[0] = resign(t, f.der[0], f.keys[1], defaultSigningID, func(tbs []byte) []byte { return bytes.Replace(tbs, []byte("identity-1"), []byte("identity-X"), 1) })
		checkPath(t, f, -2, 0)
		f = makePath(t, 2, nil)
		other := makePath(t, 2, nil)
		f.der[2] = other.der[2]
		checkPath(t, f, -2, 0)
	})
	t.Run("anchor_self_signature_not_trust_source", func(t *testing.T) {
		f := makePath(t, 1, nil)
		f.der[1][len(f.der[1])-1] ^= 1
		checkPath(t, f, 0, 0)
	})
	t.Run("duplicate_and_self_issued_intermediate", func(t *testing.T) {
		f := makePath(t, 2, nil)
		f.der[1] = f.der[2]
		checkPath(t, f, -2, 0)
		f = makePath(t, 2, func(i int, c *x509.Certificate) {
			if i == 1 {
				c.Subject.CommonName = "identity-2"
			}
		})
		checkPath(t, f, -2, 0)
	})
}
