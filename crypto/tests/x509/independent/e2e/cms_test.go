package independent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"flag"
	"fmt"
	"os/exec"
	"sort"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var cmsPeer = flag.String("cms-peer", "", "formal native CMS endpoint")

type cmsCase struct {
	path                 pathFixture
	format               byte
	detached             bool
	id, content, encoded []byte
	private              []byte
}

func cmsPath(t *testing.T, depth int, purpose x509.ExtKeyUsage, role byte) pathFixture {
	f := makePath(t, depth, func(i int, c *x509.Certificate) {
		if i == 0 {
			c.ExtKeyUsage = []x509.ExtKeyUsage{purpose}
		}
	})
	f.role = role
	return f
}

func cmsNative(t *testing.T, c cmsCase, sign bool, status int8, calls byte) []byte {
	t.Helper()
	op := byte(1)
	if sign {
		op = 0
	}
	return cmsNativeOperation(t, c, op, status, calls)
}
func cmsNativeOperation(t *testing.T, c cmsCase, op byte, status int8, calls byte) []byte {
	t.Helper()
	if *cmsPeer == "" {
		t.Fatal("-cms-peer is required")
	}
	var input bytes.Buffer
	detached := byte(0)
	if c.detached {
		detached = 1
	}
	input.Write([]byte{op, c.format, detached, c.path.role, c.path.revocation, c.path.failDepth, byte(len(c.path.der) - 1)})
	if err := binary.Write(&input, binary.BigEndian, c.path.now); err != nil {
		t.Fatal(err)
	}
	input.Write(c.path.pin)
	key := c.private
	if key == nil {
		key = c.path.keys[0].D.FillBytes(make([]byte, 32))
	}
	input.Write(key)
	span := func(v []byte) {
		if len(v) > 65535 {
			t.Fatal("fixture span overflow")
		}
		if err := binary.Write(&input, binary.BigEndian, uint16(len(v))); err != nil {
			t.Fatal(err)
		}
		input.Write(v)
	}
	span(c.id)
	span(c.path.der[len(c.path.der)-1])
	for i := 0; i < len(c.path.der)-1; i++ {
		span(c.path.ids[i])
		span(c.path.der[i])
	}
	blob := func(v []byte) {
		if err := binary.Write(&input, binary.BigEndian, uint32(len(v))); err != nil {
			t.Fatal(err)
		}
		input.Write(v)
	}
	content := c.content
	if op == 1 && !c.detached {
		content = nil
	}
	blob(content)
	blob(c.encoded)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *cmsPeer)
	cmd.Stdin = &input
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("native CMS: %v: %s", err, stderr.String())
	}
	if len(out) < 9 || int8(out[0]) != status || out[1] != calls || out[3] != 0xa5 ||
		int(binary.BigEndian.Uint32(out[5:9])) != len(out)-9 {
		t.Fatalf("status/callback/output boundary mismatch: %x expected %d/%d\n%s", out[:min(len(out), 16)], status, calls, stderr.String())
	}
	if status != 0 && (out[2] != 1 || out[4] != 1 || len(out) != 9) {
		t.Fatalf("rejection exposed content or failed erasure: %x", out[:min(len(out), 16)])
	}
	return out[9:]
}

func cmsIndependent(t *testing.T, c cmsCase, change func(*pkcs7.SignedData)) []byte {
	t.Helper()
	var sd *pkcs7.SignedData
	var err error
	if c.format == 2 {
		sd, err = pkcs7.NewSMSignedData(c.content)
	} else {
		sd, err = pkcs7.NewSignedData(c.content)
		if err == nil {
			sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSM3)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := smx509.ParseCertificate(c.path.der[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = sd.AddSigner(leaf, c.path.keys[0], pkcs7.SignerInfoConfig{SkipCertificates: true}); err != nil {
		t.Fatal(err)
	}
	certs := append([][]byte{}, c.path.der[:len(c.path.der)-1]...)
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })
	for _, der := range certs {
		cert, e := smx509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		sd.AddCertificate(cert)
	}
	if c.detached {
		sd.Detach()
	}
	if change != nil {
		change(sd)
	}
	result, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func cmsIndependentAttributes(t *testing.T, c cmsCase, scenario string) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(c.content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSM3)
	leaf, err := smx509.ParseCertificate(c.path.der[0])
	if err != nil {
		t.Fatal(err)
	}
	attr := pkcs7.Attribute{Type: []int{1, 2, 3, 4}, Value: []byte("unknown")}
	switch scenario {
	case "duplicate_digest":
		attr = pkcs7.Attribute{Type: pkcs7.OIDAttributeMessageDigest, Value: bytes.Repeat([]byte{1}, 32)}
	case "duplicate_type":
		attr = pkcs7.Attribute{Type: pkcs7.OIDAttributeContentType, Value: pkcs7.OIDData}
	case "duplicate_time":
		attr = pkcs7.Attribute{Type: pkcs7.OIDAttributeSigningTime, Value: time.Now().UTC()}
	}
	if err = sd.AddSigner(leaf, c.path.keys[0], pkcs7.SignerInfoConfig{SkipCertificates: true, ExtraSignedAttributes: []pkcs7.Attribute{attr}}); err != nil {
		t.Fatal(err)
	}
	certs := append([][]byte{}, c.path.der[:len(c.path.der)-1]...)
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })
	for _, der := range certs {
		cert, e := smx509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		sd.AddCertificate(cert)
	}
	encoded, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cmsVerifyIndependent(t *testing.T, encoded, content []byte, detached bool) {
	t.Helper()
	p7, err := pkcs7.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if detached {
		p7.Content = content
	}
	if err = p7.Verify(); err != nil {
		t.Fatalf("independent CMS signature: %v", err)
	}
	if !bytes.Equal(p7.Content, content) {
		t.Fatal("independent attached/detached content mismatch")
	}
}

func marshalCMSAttributes[T any](attrs []T) ([]byte, error) {
	outer, err := asn1.Marshal(struct {
		Attributes []T `asn1:"set"`
	}{attrs})
	if err != nil {
		return nil, err
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(outer, &sequence)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("attribute DER: %v", err)
	}
	return sequence.Bytes, nil
}

func TestSM2CMS(t *testing.T) {
	base := cmsPath(t, 2, x509.ExtKeyUsageCodeSigning, 3)
	for _, format := range []byte{1, 2} {
		for _, detached := range []bool{false, true} {
			for _, content := range [][]byte{nil, []byte("CMS\x00content"), bytes.Repeat([]byte{0x81}, 65536)} {
				t.Run(fmt.Sprintf("format_%d/detached_%t/bytes_%d", format, detached, len(content)), func(t *testing.T) {
					c := cmsCase{path: base, format: format, detached: detached, id: defaultSigningID, content: content}
					c.encoded = cmsNative(t, c, true, 0, 0)
					cmsVerifyIndependent(t, c.encoded, content, detached)
					if result := cmsNative(t, c, false, 0, 0); !bytes.Equal(result, content) {
						t.Fatal("native content release mismatch")
					}
					c.encoded = cmsIndependent(t, c, nil)
					if result := cmsNative(t, c, false, 0, 0); !bytes.Equal(result, content) {
						t.Fatal("independent-to-native content release mismatch")
					}
				})
			}
		}
	}
	t.Run("SM2_with_SM3_signature_identifier", func(t *testing.T) {
		c := cmsCase{path: base, format: 1, id: defaultSigningID, content: []byte("same finite signature algorithm")}
		c.encoded = cmsIndependent(t, c, func(sd *pkcs7.SignedData) {
			sd.GetSignedData().SignerInfos[0].DigestEncryptionAlgorithm.Algorithm = []int{1, 2, 156, 10197, 1, 501}
		})
		cmsNative(t, c, false, 0, 0)
	})
	t.Run("maximum_path_and_explicit_issuer_IDs", func(t *testing.T) {
		f := cmsPath(t, 4, x509.ExtKeyUsageCodeSigning, 3)
		for i := range f.ids {
			f.ids[i] = []byte{byte('a' + i), 0, byte('A' + i)}
			f.der[i] = resign(t, f.der[i], f.keys[i+1], f.ids[i], nil)
		}
		f.revocation = 1
		f.failDepth = 255
		c := cmsCase{path: f, format: 2, id: []byte("message-signer"), content: []byte("all trust checks before content")}
		c.encoded = cmsNative(t, c, true, 0, 0)
		cmsNative(t, c, false, 0, 4)
		c.path.ids = append([][]byte{}, f.ids...)
		c.path.ids[2] = defaultSigningID
		cmsNative(t, c, false, -2, 0)
	})
	t.Run("CA_purpose_constraint", func(t *testing.T) {
		f := makePath(t, 2, func(i int, c *x509.Certificate) {
			if i == 0 {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			}
			if i == 1 {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			}
		})
		f.role = 3
		c := cmsCase{path: f, format: 1, id: defaultSigningID, content: []byte("CA purpose applies")}
		c.encoded = cmsIndependent(t, c, nil)
		cmsNative(t, c, false, -2, 0)
	})
	for _, entry := range []struct {
		purpose x509.ExtKeyUsage
		role    byte
	}{{x509.ExtKeyUsageEmailProtection, 4}, {x509.ExtKeyUsageTimeStamping, 8}, {x509.ExtKeyUsageOCSPSigning, 9}} {
		t.Run(fmt.Sprintf("purpose_%d", entry.role), func(t *testing.T) {
			c := cmsCase{path: cmsPath(t, 1, entry.purpose, entry.role), format: 1, id: defaultSigningID, content: []byte("purpose")}
			c.encoded = cmsIndependent(t, c, nil)
			cmsNative(t, c, false, 0, 0)
			c.path.role = 3
			cmsNative(t, c, false, -2, 0)
		})
	}
	for _, id := range [][]byte{{'c', 0, 'm', 's'}, bytes.Repeat([]byte{'i'}, 8191)} {
		t.Run(fmt.Sprintf("explicit_ID_%d", len(id)), func(t *testing.T) {
			c := cmsCase{path: base, format: 2, id: id, content: []byte("explicit identity")}
			c.encoded = cmsNative(t, c, true, 0, 0)
			cmsNative(t, c, false, 0, 0)
			p7, err := pkcs7.Parse(c.encoded)
			if err != nil {
				t.Fatal(err)
			}
			// Independent SM2 verification of the exact DER SET used as the
			// signature message; the library's CMS facade fixes the default ID.
			attrs := p7.Signers[0].AuthenticatedAttributes
			encoded, err := marshalCMSAttributes(attrs)
			if err != nil || !sm2.VerifyASN1WithSM2(&c.path.keys[0].PublicKey, id, encoded, p7.Signers[0].EncryptedDigest) {
				t.Fatalf("independent explicit-ID signature: %v", err)
			}
			c.id = defaultSigningID
			cmsNative(t, c, false, -2, 0)
		})
	}
	for _, scenario := range []string{"unknown", "duplicate_digest", "duplicate_type", "duplicate_time"} {
		t.Run("signed_attribute_"+scenario, func(t *testing.T) {
			c := cmsCase{path: base, format: 1, id: defaultSigningID, content: []byte("bounded attribute contract")}
			c.encoded = cmsIndependentAttributes(t, c, scenario)
			cmsNative(t, c, false, -2, 0)
		})
	}
	for _, scenario := range []string{"signature", "content", "signer_ID", "pin", "time", "issuer_ID", "purpose", "revocation", "missing_signer", "extra_signer", "digest_set", "unsigned_attribute", "wrong_serial", "extra_certificate", "no_attributes", "trailing", "truncated", "profile", "mode"} {
		t.Run("reject_"+scenario, func(t *testing.T) {
			c := cmsCase{path: base, format: 1, id: defaultSigningID, content: []byte("authenticated only")}
			c.path.revocation = 1
			c.path.failDepth = 255
			change := func(sd *pkcs7.SignedData) {
				switch scenario {
				case "missing_signer":
					sd.GetSignedData().SignerInfos = nil
				case "extra_signer":
					sd.GetSignedData().SignerInfos = append(sd.GetSignedData().SignerInfos, sd.GetSignedData().SignerInfos[0])
				case "digest_set":
					sd.GetSignedData().DigestAlgorithmIdentifiers = nil
				case "wrong_serial":
					sd.GetSignedData().SignerInfos[0].IssuerAndSerialNumber.SerialNumber.SetInt64(999)
				case "extra_certificate":
					cert, err := smx509.ParseCertificate(c.path.der[len(c.path.der)-1])
					if err != nil {
						t.Fatal(err)
					}
					sd.AddCertificate(cert)
				case "no_attributes":
					sd.RemoveAuthenticatedAttributes()
				case "unsigned_attribute":
					if err := sd.GetSignedData().SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{{Type: pkcs7.OIDAttributeSigningTime, Value: time.Now().UTC()}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if scenario == "content" {
				c.detached = true
			}
			c.encoded = cmsIndependent(t, c, change)
			calls := byte(0)
			switch scenario {
			case "signature":
				c.encoded[len(c.encoded)-1] ^= 1
			case "content":
				c.content = []byte("substitution")
			case "signer_ID":
				c.id = []byte("wrong")
			case "pin":
				c.path.pin = bytes.Repeat([]byte{1}, 65)
			case "time":
				c.path.now = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
			case "issuer_ID":
				c.path.ids = append([][]byte{}, base.ids...)
				c.path.ids[0] = []byte("wrong CA ID")
			case "purpose":
				c.path.role = 4
			case "revocation":
				c.path.failDepth = 1
				calls = 2
			case "trailing":
				c.encoded = append(c.encoded, 0)
			case "truncated":
				c.encoded = c.encoded[:len(c.encoded)-1]
			case "profile":
				c.format = 2
			case "mode":
				c.detached = true
			}
			cmsNative(t, c, false, -2, calls)
		})
	}
}
