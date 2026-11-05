package independent

import (
	"bytes"
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

var crlPeer = flag.String("crl-peer", "", "formal native CRL and trust callback peer")

type crlFixture struct {
	path    pathFixture
	der, id []byte
	minimum uint64
	age     uint32
}
type crlBody struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time                 `asn1:"optional"`
	Revoked    []pkix.RevokedCertificate `asn1:"optional"`
	Extensions []pkix.Extension          `asn1:"tag:0,explicit,optional"`
}
type crlEnvelope struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

func marshalCRLValue(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func makeCRL(t *testing.T, p pathFixture, change func(*x509.RevocationList)) crlFixture {
	t.Helper()
	ca, err := smx509.ParseCertificate(p.der[1])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(p.now, 0).UTC()
	template := &x509.RevocationList{Number: big.NewInt(42), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if change != nil {
		change(template)
	}
	der, err := smx509.CreateRevocationList(rand.Reader, template, ca, p.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := smx509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err = parsed.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	return crlFixture{p, der, bytes.Clone(defaultSigningID), 42, 3600}
}
func (f crlFixture) edit(t *testing.T, mutate func(*crlBody)) crlFixture {
	t.Helper()
	var outer crlEnvelope
	var body crlBody
	if rest, err := asn1.Unmarshal(f.der, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("CRL envelope: %v", err)
	}
	if rest, err := asn1.Unmarshal(outer.TBS.FullBytes, &body); err != nil || len(rest) != 0 {
		t.Fatalf("CRL body: %v", err)
	}
	mutate(&body)
	return f.sign(t, marshalCRLValue(t, body), outer.Algorithm)
}
func (f crlFixture) sign(t *testing.T, tbs []byte, alg pkix.AlgorithmIdentifier) crlFixture {
	t.Helper()
	sig, err := f.path.keys[1].Sign(rand.Reader, tbs, sm2.NewSM2SignerOption(true, f.id))
	if err != nil {
		t.Fatal(err)
	}
	f.der = marshalCRLValue(t, crlEnvelope{asn1.RawValue{FullBytes: tbs}, alg, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	return f
}
func checkCRL(t *testing.T, f crlFixture, direct, path int8, calls byte) {
	t.Helper()
	var input bytes.Buffer
	for _, value := range []any{f.path.now, f.minimum, f.age} {
		if err := binary.Write(&input, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	input.Write(f.path.pin)
	for _, data := range [][]byte{f.path.der[0], f.path.der[1], f.id, f.der} {
		if err := binary.Write(&input, binary.BigEndian, uint32(len(data))); err != nil {
			t.Fatal(err)
		}
		input.Write(data)
	}
	command := exec.Command(*crlPeer)
	command.Stdin = &input
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	out, err := command.Output()
	if err != nil {
		t.Fatalf("native CRL peer: %v %s", err, diagnostics.String())
	}
	if len(out) != 69 || int8(out[0]) != direct || int8(out[1]) != path || out[2] != calls || out[68] != 0xa5 {
		t.Fatalf("CRL/path/callback/guard: %x want %d/%d/%d; %s", out, direct, path, calls, diagnostics.String())
	}
	want := make([]byte, 65)
	if path == 0 {
		want = f.path.pin
	}
	if !bytes.Equal(out[3:68], want) {
		t.Fatal("trust released or retained an incorrect key")
	}
}
func TestSM2CRL(t *testing.T) {
	if *crlPeer == "" {
		t.Fatal("missing native CRL peer")
	}
	base := makeCRL(t, makePath(t, 1, nil), nil)
	t.Run("fresh_empty_full_CRL_and_real_callback", func(t *testing.T) { checkCRL(t, base, 0, 0, 1) })
	for _, count := range []int{1, 256, 257} {
		t.Run(fmt.Sprintf("entry_bound_%d", count), func(t *testing.T) {
			f := makeCRL(t, base.path, func(c *x509.RevocationList) {
				for i := 0; i < count; i++ {
					c.RevokedCertificateEntries = append(c.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(int64(100 + i)), RevocationTime: c.ThisUpdate})
				}
			})
			status := int8(0)
			if count > 256 {
				status = -2
			}
			checkCRL(t, f, status, status, 1)
		})
	}
	for _, reason := range []int{0, 1, 2, 3, 4, 5, 6, 9, 10} {
		t.Run(fmt.Sprintf("revoked_reason_%d", reason), func(t *testing.T) {
			f := makeCRL(t, base.path, func(c *x509.RevocationList) {
				c.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(1), RevocationTime: c.ThisUpdate, ReasonCode: reason}}
			})
			checkCRL(t, f, -2, -2, 1)
		})
	}
	for _, reason := range []int{7, 8, 11} {
		t.Run(fmt.Sprintf("unsupported_reason_%d_on_unrelated_entry", reason), func(t *testing.T) {
			f := makeCRL(t, base.path, func(c *x509.RevocationList) {
				c.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate, ReasonCode: reason}}
			})
			checkCRL(t, f, -2, -2, 1)
		})
	}
	t.Run("freshness_and_rollback", func(t *testing.T) {
		f := base
		f.path.now = base.path.now - 60
		checkCRL(t, f, 0, 0, 1)
		f.path.now--
		checkCRL(t, f, -2, -2, 1)
		f = base
		f.path.now += 3599
		f.age = 3659
		checkCRL(t, f, 0, 0, 1)
		f.age--
		checkCRL(t, f, -2, -2, 1)
		f.age = 7200
		f.path.now++
		checkCRL(t, f, -2, -2, 1)
		f = base
		f.minimum = 43
		checkCRL(t, f, -2, -2, 1)
		f.minimum = 0
		checkCRL(t, f, 0, 0, 1)
		f = base
		f.age = 59
		checkCRL(t, f, -2, -2, 1)
		f.age = 60
		checkCRL(t, f, 0, 0, 1)
	})
	for _, year := range []int{2024, 2049, 2050} {
		t.Run(fmt.Sprintf("calendar_%d", year), func(t *testing.T) {
			when := time.Date(year, 2, 28, 12, 0, 0, 0, time.UTC)
			if year == 2024 {
				when = when.Add(24 * time.Hour)
			}
			p := makePath(t, 1, func(i int, c *x509.Certificate) {
				c.NotBefore = when.Add(-time.Hour)
				c.NotAfter = when.Add(24 * time.Hour)
			})
			p.now = when.Unix()
			checkCRL(t, makeCRL(t, p, nil), 0, 0, 1)
		})
	}
	t.Run("binary_and_maximum_CRL_signing_ID", func(t *testing.T) {
		for _, id := range [][]byte{{'c', 0, 'a'}, bytes.Repeat([]byte{0x61}, 8191)} {
			f := base
			f.id = id
			f = f.edit(t, func(c *crlBody) {})
			checkCRL(t, f, 0, 0, 1)
			f.id = defaultSigningID
			checkCRL(t, f, -2, -2, 1)
		}
	})
	t.Run("tamper_and_wrong_signature_key", func(t *testing.T) {
		f := base
		f.der = bytes.Clone(f.der)
		f.der[len(f.der)-1] ^= 1
		checkCRL(t, f, -2, -2, 1)
		f = base
		f.path.keys = append([]*sm2.PrivateKey(nil), f.path.keys...)
		f.path.keys[1] = makePath(t, 1, nil).keys[1]
		f = f.edit(t, func(c *crlBody) {})
		checkCRL(t, f, -2, -2, 1)
	})
	type invalidBody struct {
		name   string
		change func(*crlBody)
	}
	cases := []invalidBody{
		{"v1", func(c *crlBody) { c.Version = 0 }},
		{"inner_outer_algorithm_mismatch", func(c *crlBody) { c.Algorithm.Parameters = asn1.RawValue{Tag: 5} }},
		{"missing_nextUpdate", func(c *crlBody) { c.NextUpdate = time.Time{} }},
		{"nextUpdate_before_thisUpdate", func(c *crlBody) { c.NextUpdate = c.ThisUpdate.Add(-time.Second) }},
		{"missing_extensions", func(c *crlBody) { c.Extensions = nil }},
		{"missing_AKI", func(c *crlBody) { c.Extensions = c.Extensions[1:] }},
		{"missing_number", func(c *crlBody) { c.Extensions = c.Extensions[:1] }},
		{"wrong_AKI", func(c *crlBody) {
			c.Extensions[0].Value = bytes.Clone(c.Extensions[0].Value)
			c.Extensions[0].Value[len(c.Extensions[0].Value)-1] ^= 1
		}},
		{"critical_AKI", func(c *crlBody) { c.Extensions[0].Critical = true }},
		{"duplicate_number", func(c *crlBody) { c.Extensions = append(c.Extensions, c.Extensions[1]) }},
		{"negative_number", func(c *crlBody) { c.Extensions[1].Value = marshalCRLValue(t, big.NewInt(-1)) }},
		{"number_overflow", func(c *crlBody) { c.Extensions[1].Value = marshalCRLValue(t, new(big.Int).Lsh(big.NewInt(1), 64)) }},
		{"wrong_issuer_name", func(c *crlBody) {
			c.Issuer.FullBytes = bytes.Replace(c.Issuer.FullBytes, []byte("identity-1"), []byte("identity-9"), 1)
		}},
		{"empty_issuer", func(c *crlBody) { c.Issuer = asn1.RawValue{FullBytes: []byte{0x30, 0}} }},
		{"future_revocation", func(c *crlBody) {
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate.Add(time.Second)}}
		}},
		{"zero_serial", func(c *crlBody) {
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(0), RevocationTime: c.ThisUpdate}}
		}},
		{"negative_serial", func(c *crlBody) {
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(-1), RevocationTime: c.ThisUpdate}}
		}},
		{"oversized_serial", func(c *crlBody) {
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: new(big.Int).Lsh(big.NewInt(1), 160), RevocationTime: c.ThisUpdate}}
		}},
		{"duplicate_entry", func(c *crlBody) {
			e := pkix.RevokedCertificate{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate}
			c.Revoked = []pkix.RevokedCertificate{e, e}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkCRL(t, base.edit(t, tc.change), -2, -2, 1) })
	}
	t.Run("uint64_maximum_number", func(t *testing.T) {
		f := base.edit(t, func(c *crlBody) { c.Extensions[1].Value = marshalCRLValue(t, new(big.Int).SetUint64(^uint64(0))) })
		f.minimum = ^uint64(0)
		checkCRL(t, f, 0, 0, 1)
	})
	for _, kind := range []int{27, 28, 29, 46} {
		t.Run(fmt.Sprintf("unsupported_scope_%d_even_noncritical", kind), func(t *testing.T) {
			for _, critical := range []bool{false, true} {
				f := base.edit(t, func(c *crlBody) {
					c.Extensions = append(c.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, kind}, Critical: critical, Value: []byte{0x30, 0}})
				})
				checkCRL(t, f, -2, -2, 1)
			}
		})
	}
	t.Run("unknown_CRL_extension", func(t *testing.T) {
		for _, critical := range []bool{false, true} {
			f := base.edit(t, func(c *crlBody) {
				c.Extensions = append(c.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: critical, Value: []byte{5, 0}})
			})
			status := int8(0)
			if critical {
				status = -2
			}
			checkCRL(t, f, status, status, 1)
		}
	})
	for _, kind := range []int{24, 29, 99} {
		t.Run(fmt.Sprintf("unsupported_entry_%d", kind), func(t *testing.T) {
			f := base.edit(t, func(c *crlBody) {
				c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, kind}, Value: []byte{5, 0}}}}}
			})
			checkCRL(t, f, -2, -2, 1)
		})
	}
	t.Run("issuer_requires_CRLSign_and_SKI", func(t *testing.T) {
		for _, ext := range []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{3, 2, 2, 4}}, // keyCertSign only
			{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{4, 0}},
		} {
			f := base
			f.path.der = append([][]byte(nil), f.path.der...)
			// Preserve the issuer's key and subject; re-encode its extensions and self-sign.
			f.path.der[1] = resign(t, f.path.der[1], f.path.keys[1], defaultSigningID, func(tbs []byte) []byte { return replaceCertExtension(t, tbs, ext) })
			checkCRL(t, f, -2, -2, 1)
		}
	})
	t.Run("explicit_zero_freshness_and_ID_admission", func(t *testing.T) {
		f := base
		f.age = 0
		checkCRL(t, f, -1, -2, 1)
		f = base
		f.id = nil
		checkCRL(t, f, -1, -2, 1)
	})
	t.Run("malformed_DER_and_full_scan", func(t *testing.T) {
		for _, der := range [][]byte{append(bytes.Clone(base.der), 0), base.der[:len(base.der)-1], {0x30, 0}} {
			f := base
			f.der = der
			checkCRL(t, f, -2, -2, 1)
		}
		f := base.edit(t, func(c *crlBody) {
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate}, {SerialNumber: big.NewInt(100), RevocationTime: c.ThisUpdate, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: []byte{10, 1, 8}}}}}
		})
		checkCRL(t, f, -2, -2, 1)
	})
	t.Run("signature_algorithm_parameters", func(t *testing.T) {
		for _, parameters := range []asn1.RawValue{{Tag: 5}, {Tag: 4, Bytes: []byte{1}}} {
			f := base.edit(t, func(c *crlBody) { c.Algorithm.Parameters = parameters })
			var outer crlEnvelope
			if _, err := asn1.Unmarshal(f.der, &outer); err != nil {
				t.Fatal(err)
			}
			outer.Algorithm.Parameters = parameters
			f.der = marshalCRLValue(t, outer)
			status := int8(-2)
			if parameters.Tag == 5 {
				status = 0
			}
			checkCRL(t, f, status, status, 1)
		}
		f := base.edit(t, func(c *crlBody) { c.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4} })
		var outer crlEnvelope
		if _, err := asn1.Unmarshal(f.der, &outer); err != nil {
			t.Fatal(err)
		}
		outer.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
		f.der = marshalCRLValue(t, outer)
		checkCRL(t, f, -2, -2, 1)
	})
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprintf("extension_bound_%d", count), func(t *testing.T) {
			f := base.edit(t, func(c *crlBody) {
				for len(c.Extensions) < count {
					c.Extensions = append(c.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, len(c.Extensions)}, Value: []byte{5, 0}})
				}
			})
			status := int8(0)
			if count > 64 {
				status = -2
			}
			checkCRL(t, f, status, status, 1)
		})
	}
	t.Run("distribution_points_are_not_silently_ignored", func(t *testing.T) {
		for _, kind := range []int{31, 46} {
			p := makePath(t, 1, func(i int, c *x509.Certificate) {
				if i == 0 {
					c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, kind}, Value: []byte{0x30, 0}})
				}
			})
			checkCRL(t, makeCRL(t, p, nil), -2, -2, 1)
		}
	})
	t.Run("duplicate_entry_extension", func(t *testing.T) {
		f := base.edit(t, func(c *crlBody) {
			e := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: []byte{10, 1, 1}}
			c.Revoked = []pkix.RevokedCertificate{{SerialNumber: big.NewInt(99), RevocationTime: c.ThisUpdate, Extensions: []pkix.Extension{e, e}}}
		})
		checkCRL(t, f, -2, -2, 1)
	})
	t.Run("invalid_calendar", func(t *testing.T) {
		var outer crlEnvelope
		if _, err := asn1.Unmarshal(base.der, &outer); err != nil {
			t.Fatal(err)
		}
		bad := bytes.Replace(outer.TBS.FullBytes, []byte("251231235900Z"), []byte("250230235900Z"), 1)
		if bytes.Equal(bad, outer.TBS.FullBytes) {
			t.Fatal("missing time fixture")
		}
		checkCRL(t, base.sign(t, bad, outer.Algorithm), -2, -2, 1)
	})
	for _, mode := range []string{"empty_entries", "empty_extensions", "trailing_tbs_field", "noncanonical_number"} {
		t.Run(mode, func(t *testing.T) {
			var outer crlEnvelope
			var seq asn1.RawValue
			if _, err := asn1.Unmarshal(base.der, &outer); err != nil {
				t.Fatal(err)
			}
			if _, err := asn1.Unmarshal(outer.TBS.FullBytes, &seq); err != nil {
				t.Fatal(err)
			}
			remaining := seq.Bytes
			var fields []asn1.RawValue
			for len(remaining) > 0 {
				var field asn1.RawValue
				var err error
				remaining, err = asn1.Unmarshal(remaining, &field)
				if err != nil {
					t.Fatal(err)
				}
				fields = append(fields, field)
			}
			switch mode {
			case "empty_entries":
				fields = append(fields[:5], asn1.RawValue{FullBytes: []byte{0x30, 0}}, fields[5])
			case "empty_extensions":
				fields[5] = asn1.RawValue{FullBytes: []byte{0xa0, 2, 0x30, 0}}
			case "trailing_tbs_field":
				fields = append(fields, asn1.RawValue{Tag: 5})
			case "noncanonical_number":
				f := base.edit(t, func(c *crlBody) { c.Extensions[1].Value = []byte{2, 2, 0, 42} })
				checkCRL(t, f, -2, -2, 1)
				return
			}
			var content []byte
			for _, field := range fields {
				content = append(content, marshalCRLValue(t, field)...)
			}
			tbs := marshalCRLValue(t, asn1.RawValue{Tag: 16, IsCompound: true, Bytes: content})
			checkCRL(t, base.sign(t, tbs, outer.Algorithm), -2, -2, 1)
		})
	}
}

// Change a signed fixture's Extension value while preserving its key/name.
func replaceCertExtension(t *testing.T, tbs []byte, ext pkix.Extension) []byte {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &seq); err != nil {
		t.Fatal(err)
	}
	content := seq.Bytes
	var fields []asn1.RawValue
	for len(content) > 0 {
		var field asn1.RawValue
		var err error
		content, err = asn1.Unmarshal(content, &field)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
	for i := range fields {
		if fields[i].Class == 2 && fields[i].Tag == 3 {
			var exts []pkix.Extension
			if _, err := asn1.Unmarshal(fields[i].Bytes, &exts); err != nil {
				t.Fatal(err)
			}
			found := false
			for j := range exts {
				if exts[j].Id.Equal(ext.Id) {
					exts[j] = ext
					found = true
				}
			}
			if !found {
				exts = append(exts, ext)
			}
			fields[i] = asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: marshalCRLValue(t, exts)}
		}
	}
	var body []byte
	for _, field := range fields {
		body = append(body, marshalCRLValue(t, field)...)
	}
	return marshalCRLValue(t, asn1.RawValue{Tag: 16, IsCompound: true, Bytes: body})
}
