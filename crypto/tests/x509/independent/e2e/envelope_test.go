package independent

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

var authEnvelopeOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
var envelopeDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
var envelopeKeyOID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}
var envelopeCipherOID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}

type envelopeSID struct {
	Issuer asn1.RawValue
	Serial asn1.RawValue
}
type envelopeRecipient struct {
	Version   int
	SID       envelopeSID
	Algorithm pkix.AlgorithmIdentifier
	Wrapped   []byte
}
type envelopeECI struct {
	Type       asn1.ObjectIdentifier
	Algorithm  pkix.AlgorithmIdentifier
	Ciphertext asn1.RawValue
}
type envelopeBody struct {
	Version     int
	Originator  asn1.RawValue       `asn1:"optional,tag:0"`
	Recipients  []envelopeRecipient `asn1:"set"`
	Content     envelopeECI
	AuthAttrs   asn1.RawValue `asn1:"optional,tag:1"`
	Tag         []byte
	UnauthAttrs asn1.RawValue `asn1:"optional,tag:2"`
}
type envelopeOuter struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}
type envelopeGCM struct {
	Nonce   []byte
	TagSize int
}

func envelopeDER(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func envelopeDecode(t *testing.T, der []byte) (envelopeOuter, envelopeBody) {
	t.Helper()
	der = bytes.Clone(der) // Mutation cases must not corrupt another scenario's signed fixture.
	var outer envelopeOuter
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 {
		t.Fatalf("independent envelope wrapper: %v", err)
	}
	var body envelopeBody
	rest, err = asn1.Unmarshal(outer.Content.Bytes, &body)
	if err != nil || len(rest) != 0 {
		t.Fatalf("independent AuthEnvelopedData: %v", err)
	}
	return outer, body
}
func envelopeEncode(t *testing.T, outer envelopeOuter, body envelopeBody) []byte {
	t.Helper()
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: envelopeDER(t, body)}
	return envelopeDER(t, outer)
}
func envelopeParams(t *testing.T, body envelopeBody) envelopeGCM {
	t.Helper()
	var params envelopeGCM
	rest, err := asn1.Unmarshal(body.Content.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		t.Fatalf("GCM parameters: %v", err)
	}
	return params
}
func envelopeIndependent(t *testing.T, c cmsCase) []byte {
	t.Helper()
	leaf, err := smx509.ParseCertificate(c.path.der[0])
	if err != nil {
		t.Fatal(err)
	}
	cek, nonce := make([]byte, 16), make([]byte, 12)
	if _, err = rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	wrapped, err := sm2.EncryptASN1(rand.Reader, &c.path.keys[0].PublicKey, cek)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sm4.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nonce, c.content, nil)
	serial := asn1.RawValue{FullBytes: envelopeDER(t, leaf.SerialNumber)}
	body := envelopeBody{Recipients: []envelopeRecipient{{0,
		envelopeSID{asn1.RawValue{FullBytes: leaf.RawIssuer}, serial},
		pkix.AlgorithmIdentifier{Algorithm: envelopeKeyOID, Parameters: asn1.NullRawValue}, wrapped}},
		Content: envelopeECI{envelopeDataOID,
			pkix.AlgorithmIdentifier{Algorithm: envelopeCipherOID, Parameters: asn1.RawValue{FullBytes: envelopeDER(t, envelopeGCM{nonce, 16})}},
			asn1.RawValue{Class: 2, Tag: 0, Bytes: sealed[:len(sealed)-16]}}, Tag: sealed[len(sealed)-16:]}
	return envelopeEncode(t, envelopeOuter{Type: authEnvelopeOID}, body)
}
func envelopeIndependentOpen(t *testing.T, c cmsCase) ([]byte, []byte, []byte) {
	t.Helper()
	outer, body := envelopeDecode(t, c.encoded)
	params := envelopeParams(t, body)
	leaf, err := smx509.ParseCertificate(c.path.der[0])
	if err != nil {
		t.Fatal(err)
	}
	if !outer.Type.Equal(authEnvelopeOID) || body.Version != 0 || len(body.Recipients) != 1 ||
		body.Recipients[0].Version != 0 || !body.Content.Type.Equal(envelopeDataOID) ||
		!body.Content.Algorithm.Algorithm.Equal(envelopeCipherOID) || !body.Recipients[0].Algorithm.Algorithm.Equal(envelopeKeyOID) ||
		!bytes.Equal(body.Recipients[0].SID.Issuer.FullBytes, leaf.RawIssuer) ||
		!bytes.Equal(body.Recipients[0].SID.Serial.FullBytes, envelopeDER(t, leaf.SerialNumber)) ||
		len(params.Nonce) != 12 || params.TagSize != 16 || len(body.Tag) != 16 ||
		body.Content.Ciphertext.Class != 2 || body.Content.Ciphertext.Tag != 0 || body.Content.Ciphertext.IsCompound ||
		len(body.Originator.FullBytes) != 0 || len(body.AuthAttrs.FullBytes) != 0 || len(body.UnauthAttrs.FullBytes) != 0 {
		t.Fatal("independent finite envelope profile mismatch")
	}
	cek, err := c.path.keys[0].Decrypt(rand.Reader, body.Recipients[0].Wrapped, sm2.ASN1DecrypterOpts)
	if err != nil || len(cek) != 16 {
		t.Fatalf("independent SM2 unwrap: %v", err)
	}
	block, err := sm4.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := append(bytes.Clone(body.Content.Ciphertext.Bytes), body.Tag...)
	plain, err := gcm.Open(nil, params.Nonce, sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plain, cek, params.Nonce
}
func envelopePath(t *testing.T, depth int, change func(int, *x509.Certificate)) pathFixture {
	t.Helper()
	f := makePath(t, depth, func(i int, c *x509.Certificate) {
		if i == 0 {
			c.KeyUsage = x509.KeyUsageKeyEncipherment
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}
		if change != nil {
			change(i, c)
		}
	})
	f.role = 10
	return f
}
func TestSM2CMSEnvelope(t *testing.T) {
	for _, depth := range []int{1, 4} {
		path := envelopePath(t, depth, nil)
		for _, size := range []int{0, 1, 16, 65536, 88064} {
			t.Run(fmt.Sprintf("bidirectional_%d_%d", depth, size), func(t *testing.T) {
				c := cmsCase{path: path, content: bytes.Repeat([]byte{0, 0x81, 0xff, 0x13}, (size+3)/4)[:size]}
				c.path.revocation = 1
				c.encoded = cmsNativeOperation(t, c, 2, 0, byte(depth))
				plain, cek, nonce := envelopeIndependentOpen(t, c)
				if !bytes.Equal(plain, c.content) {
					t.Fatal("native encryption content mismatch")
				}
				if !bytes.Equal(cmsNativeOperation(t, c, 3, 0, 0), c.content) {
					t.Fatal("native decryption content mismatch")
				}
				second := c
				second.encoded = cmsNativeOperation(t, c, 2, 0, byte(depth))
				_, key2, nonce2 := envelopeIndependentOpen(t, second)
				if bytes.Equal(cek, key2) || bytes.Equal(nonce, nonce2) {
					t.Fatal("fresh content key/nonce not generated")
				}
				c.encoded = envelopeIndependent(t, c)
				if !bytes.Equal(cmsNativeOperation(t, c, 3, 0, 0), c.content) {
					t.Fatal("independent encryption content mismatch")
				}
			})
		}
	}
	base := cmsCase{path: envelopePath(t, 2, nil), content: []byte("private\x00CMS\xffpayload")}
	base.path.revocation = 1
	base.encoded = envelopeIndependent(t, base)
	for _, scenario := range []string{"tag", "ciphertext", "nonce", "wrapped", "short-key", "recipient-name", "recipient-serial", "recipient-version",
		"version", "no-recipient", "extra-recipient", "key-algorithm", "cipher-algorithm", "content-type", "outer-type", "short-nonce", "tag-length",
		"short-tag", "originator", "auth-attributes", "unauth-attributes", "wrong-private", "wrong-own-cert", "trailing", "truncated"} {
		t.Run("reject_"+scenario, func(t *testing.T) {
			c := base
			outer, body := envelopeDecode(t, c.encoded)
			params := envelopeParams(t, body)
			switch scenario {
			case "tag":
				body.Tag[0] ^= 1
			case "ciphertext":
				body.Content.Ciphertext.Bytes[0] ^= 1
				body.Content.Ciphertext.FullBytes = nil
			case "nonce":
				params.Nonce[0] ^= 1
			case "wrapped":
				body.Recipients[0].Wrapped[len(body.Recipients[0].Wrapped)-1] ^= 1
			case "short-key":
				var err error
				body.Recipients[0].Wrapped, err = sm2.EncryptASN1(rand.Reader, &c.path.keys[0].PublicKey, make([]byte, 8))
				if err != nil {
					t.Fatal(err)
				}
			case "recipient-name":
				body.Recipients[0].SID.Issuer = asn1.RawValue{FullBytes: envelopeDER(t, pkix.Name{CommonName: "foreign"}.ToRDNSequence())}
			case "recipient-serial":
				body.Recipients[0].SID.Serial = asn1.RawValue{FullBytes: []byte{2, 1, 99}}
			case "recipient-version":
				body.Recipients[0].Version = 2
			case "version":
				body.Version = 1
			case "no-recipient":
				body.Recipients = nil
			case "extra-recipient":
				body.Recipients = append(body.Recipients, body.Recipients[0])
			case "key-algorithm":
				body.Recipients[0].Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
			case "cipher-algorithm":
				body.Content.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
			case "content-type":
				body.Content.Type = asn1.ObjectIdentifier{1, 2, 3}
			case "outer-type":
				outer.Type = asn1.ObjectIdentifier{1, 2, 3}
			case "short-nonce":
				params.Nonce = params.Nonce[:11]
			case "tag-length":
				params.TagSize = 12
			case "short-tag":
				body.Tag = body.Tag[:15]
			case "originator":
				body.Originator = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0}}
			case "auth-attributes":
				body.AuthAttrs = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: []byte{0x30, 0}}
			case "unauth-attributes":
				body.UnauthAttrs = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: []byte{0x30, 0}}
			case "wrong-private":
				c.private = c.path.keys[1].D.FillBytes(make([]byte, 32))
			case "wrong-own-cert":
				c.path.der = append([][]byte{}, c.path.der...)
				c.path.der[0] = c.path.der[1]
			}
			body.Content.Algorithm.Parameters = asn1.RawValue{FullBytes: envelopeDER(t, params)}
			c.encoded = envelopeEncode(t, outer, body)
			if scenario == "trailing" {
				c.encoded = append(c.encoded, 0)
			}
			if scenario == "truncated" {
				c.encoded = c.encoded[:len(c.encoded)-1]
			}
			cmsNativeOperation(t, c, 3, -2, 0)
		})
	}
	for _, scenario := range []string{"pin", "expired", "signature", "issuer-id", "signing-only", "agreement-only", "wrong-eku", "ca-eku", "revocation"} {
		t.Run("recipient_trust_"+scenario, func(t *testing.T) {
			c := cmsCase{path: envelopePath(t, 2, func(i int, cert *x509.Certificate) {
				if i == 0 && scenario == "signing-only" {
					cert.KeyUsage = x509.KeyUsageDigitalSignature
				}
				if i == 0 && scenario == "agreement-only" {
					cert.KeyUsage = x509.KeyUsageKeyAgreement
				}
				if i == 0 && scenario == "wrong-eku" {
					cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
				if i == 1 && scenario == "ca-eku" {
					cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
				}
			}), content: base.content}
			c.path.revocation = 1
			switch scenario {
			case "pin":
				c.path.pin[1] ^= 1
			case "expired":
				c.path.now = 0
			case "signature":
				c.path.der[0][len(c.path.der[0])-1] ^= 1
			case "issuer-id":
				c.path.ids[0] = []byte("different")
			case "revocation":
				c.path.failDepth = 0
			}
			calls := byte(0)
			if scenario == "revocation" {
				calls = 1
			}
			cmsNativeOperation(t, c, 2, -2, calls)
		})
	}
	t.Run("long_issuer_name_and_explicit_certificate_IDs", func(t *testing.T) {
		c := cmsCase{path: envelopePath(t, 1, func(i int, cert *x509.Certificate) {
			if i == 1 {
				cert.Subject.CommonName = strings.Repeat("issuer", 250)
			}
		}), content: bytes.Repeat([]byte{0x9a}, 88064)}
		c.path.ids[0] = []byte{'i', 0, 'd'}
		c.path.der[0] = resign(t, c.path.der[0], c.path.keys[1], c.path.ids[0], nil)
		c.encoded = cmsNativeOperation(t, c, 2, 0, 0)
		plain, _, _ := envelopeIndependentOpen(t, c)
		if !bytes.Equal(plain, c.content) {
			t.Fatal("maximum content/long issuer mismatch")
		}
		if !bytes.Equal(cmsNativeOperation(t, c, 3, 0, 0), c.content) {
			t.Fatal("long issuer native unwrap mismatch")
		}
	})
	t.Run("signed_payload_composition", func(t *testing.T) {
		signed := cmsCase{path: cmsPath(t, 4, x509.ExtKeyUsageEmailProtection, 4), format: 1, id: defaultSigningID, content: bytes.Repeat([]byte("s"), 65536)}
		signed.encoded = cmsNative(t, signed, true, 0, 0)
		c := base
		c.content = signed.encoded
		c.encoded = cmsNativeOperation(t, c, 2, 0, 2)
		signed.encoded = cmsNativeOperation(t, c, 3, 0, 0)
		if !bytes.Equal(cmsNative(t, signed, false, 0, 0), signed.content) {
			t.Fatal("signed/encrypted composition mismatch")
		}
	})
}
