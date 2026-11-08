package independent

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
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
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

var ocspPeer = flag.String("ocsp-peer", "", "formal native direct-issuer OCSP endpoint")
var basicOCSPOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
var nonceOCSPOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

type ocspCertID struct {
	Algorithm         pkix.AlgorithmIdentifier
	NameHash, KeyHash []byte
	Serial            *big.Int
}
type ocspSingle struct {
	CertID     ocspCertID
	Status     asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type ocspBody struct {
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []ocspSingle
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type ocspBasic struct {
	Body         asn1.RawValue
	Algorithm    pkix.AlgorithmIdentifier
	Signature    asn1.BitString
	Certificates []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type ocspFixture struct {
	path                   pathFixture
	id, nonce, response    []byte
	age, skew              uint32
	floor                  int64
	byKey, embed           bool
	hash                   string
	responder, responderID []byte
	responderKey           *sm2.PrivateKey
}

func ocspDER(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func ocspHash(name string, input []byte) []byte {
	switch name {
	case "sha1":
		h := sha1.Sum(input)
		return h[:]
	case "sha256":
		h := sha256.Sum256(input)
		return h[:]
	case "sm3":
		h := sm3.Sum(input)
		return h[:]
	default:
		panic("unsupported fixture hash")
	}
}
func (f ocspFixture) certID(t *testing.T, hash string) ocspCertID {
	t.Helper()
	ca, err := smx509.ParseCertificate(f.path.der[1])
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := smx509.ParseCertificate(f.path.der[0])
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.Marshal(f.path.keys[1].Curve, f.path.keys[1].X, f.path.keys[1].Y)
	oid := map[string]asn1.ObjectIdentifier{"sha1": {1, 3, 14, 3, 2, 26}, "sha256": {2, 16, 840, 1, 101, 3, 4, 2, 1}, "sm3": {1, 2, 156, 10197, 1, 401}}[hash]
	return ocspCertID{pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}, ocspHash(hash, ca.RawSubject), ocspHash(hash, pub), leaf.SerialNumber}
}
func (f ocspFixture) sign(t *testing.T, edit func(*ocspBody, *ocspBasic)) []byte {
	t.Helper()
	ca, err := smx509.ParseCertificate(f.path.der[1])
	if err != nil {
		t.Fatal(err)
	}
	signingKey := f.path.keys[1]
	if f.responder != nil {
		ca, err = smx509.ParseCertificate(f.responder)
		if err != nil {
			t.Fatal(err)
		}
		signingKey = f.responderKey
	}
	now := time.Unix(f.path.now, 0).UTC()
	body := ocspBody{
		Responder:  asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: ca.RawSubject},
		ProducedAt: now.Add(-30 * time.Second),
		Responses: []ocspSingle{{f.certID(t, f.hash), asn1.RawValue{Class: 2, Tag: 0},
			now.Add(-time.Minute), now.Add(time.Hour), nil}},
	}
	if f.byKey {
		pub := elliptic.Marshal(signingKey.Curve, signingKey.X, signingKey.Y)
		body.Responder = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: ocspDER(t, ocspHash("sha1", pub))}
	}
	if f.nonce != nil {
		body.Extensions = []pkix.Extension{{Id: nonceOCSPOID, Value: ocspDER(t, f.nonce)}}
	}
	response := ocspBasic{Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}}}
	if f.embed {
		if f.responder == nil {
			response.Certificates = []asn1.RawValue{{FullBytes: f.path.der[1]}}
		} else {
			response.Certificates = []asn1.RawValue{{FullBytes: f.responder}, {FullBytes: f.path.der[1]}}
		}
	}
	if edit != nil {
		edit(&body, &response)
	}
	tbs := ocspDER(t, body)
	signature, err := signingKey.Sign(rand.Reader, tbs, sm2.NewSM2SignerOption(true, f.id))
	if err != nil {
		t.Fatal(err)
	}
	response.Body = asn1.RawValue{FullBytes: tbs}
	response.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	basic := ocspDER(t, response)
	return ocspDER(t, struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type asn1.ObjectIdentifier
			DER  []byte
		} `asn1:"explicit,tag:0"`
	}{0, struct {
		Type asn1.ObjectIdentifier
		DER  []byte
	}{basicOCSPOID, basic}})
}
func checkOCSP(t *testing.T, f ocspFixture, integrated bool, status int8, calls byte) {
	t.Helper()
	mode := byte(0)
	if integrated {
		mode = 1
	}
	checkOCSPMode(t, f, mode, status, calls)
}
func checkOCSPMode(t *testing.T, f ocspFixture, mode byte, status int8, calls byte) {
	t.Helper()
	if *ocspPeer == "" {
		t.Fatal("-ocsp-peer required")
	}
	var input bytes.Buffer
	if f.responder != nil {
		mode += 3
	}
	input.WriteByte(mode)
	for _, value := range []any{f.path.now, f.age, f.skew, f.floor} {
		if err := binary.Write(&input, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	input.Write(f.path.pin)
	for _, value := range [][]byte{f.path.der[0], f.path.der[1], f.id, f.path.ids[0], f.nonce} {
		if err := binary.Write(&input, binary.BigEndian, uint16(len(value))); err != nil {
			t.Fatal(err)
		}
		input.Write(value)
	}
	if f.responder != nil {
		for _, value := range [][]byte{f.responder, f.responderID} {
			if err := binary.Write(&input, binary.BigEndian, uint16(len(value))); err != nil {
				t.Fatal(err)
			}
			input.Write(value)
		}
	}
	if err := binary.Write(&input, binary.BigEndian, uint32(len(f.response))); err != nil {
		t.Fatal(err)
	}
	input.Write(f.response)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *ocspPeer)
	cmd.Stdin = &input
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("OCSP peer: %v: %s", err, stderr.String())
	}
	if len(out) != 68 || int8(out[0]) != status || out[1] != calls || out[67] != 0xa5 {
		t.Fatalf("OCSP status/callback/boundary: %x wanted %d/%d\n%s", out[:min(len(out), 8)], status, calls, stderr.String())
	}
	expected := make([]byte, 65)
	if (mode == 1 || mode == 4) && status == 0 {
		expected = f.path.pin
	}
	if !bytes.Equal(out[2:67], expected) {
		t.Fatal("path key publication/erasure mismatch")
	}
}

func TestSM2OCSP(t *testing.T) {
	base := ocspFixture{path: makePath(t, 1, nil), id: defaultSigningID, age: 3600, hash: "sha256"}
	for _, hash := range []string{"sha1", "sha256", "sm3"} {
		for _, byKey := range []bool{false, true} {
			for _, nonceSize := range []int{0, 32, 128} {
				t.Run(fmt.Sprintf("%s/key_%t/nonce_%d", hash, byKey, nonceSize), func(t *testing.T) {
					f := base
					f.hash, f.byKey, f.embed = hash, byKey, true
					if nonceSize != 0 {
						f.nonce = bytes.Repeat([]byte{0x71}, nonceSize)
					}
					f.response = f.sign(t, nil)
					checkOCSP(t, f, false, 0, 0)
					checkOCSP(t, f, true, 0, 1)
				})
			}
		}
	}
	t.Run("snapshot_authentication_is_not_target_status", func(t *testing.T) {
		f := base
		f.response = f.sign(t, nil)
		checkOCSPMode(t, f, 2, 0, 0)
		f.response = f.sign(t, func(body *ocspBody, _ *ocspBasic) { body.Responses[0].Status.Tag = 2 })
		checkOCSPMode(t, f, 2, 0, 0)
		checkOCSP(t, f, false, -2, 0)
		f.response[len(f.response)-1] ^= 1
		checkOCSPMode(t, f, 2, -2, 0)
	})
	for _, id := range [][]byte{{'o', 0, 'c', 's', 'p'}, bytes.Repeat([]byte{'i'}, 8191)} {
		t.Run(fmt.Sprintf("signing_ID_%d", len(id)), func(t *testing.T) {
			f := base
			f.id = id
			f.response = f.sign(t, nil)
			checkOCSP(t, f, true, 0, 1)
			f.id = defaultSigningID
			checkOCSP(t, f, true, -2, 1)
		})
	}
	t.Run("age_and_rollback_boundaries", func(t *testing.T) {
		f := base
		f.response = f.sign(t, nil)
		f.age, f.floor = 60, f.path.now-60
		checkOCSP(t, f, false, 0, 0)
		f.age = 59
		checkOCSP(t, f, false, -2, 0)
		f.age = 60
		f.floor++
		checkOCSP(t, f, false, -2, 0)
	})
	t.Run("explicit_clock_skew", func(t *testing.T) {
		f := base
		f.response = f.sign(t, func(body *ocspBody, _ *ocspBasic) {
			body.Responses[0].ThisUpdate = time.Unix(f.path.now+1, 0).UTC()
			body.ProducedAt = time.Unix(f.path.now+2, 0).UTC()
		})
		checkOCSP(t, f, false, -2, 0)
		f.skew = 2
		checkOCSP(t, f, false, 0, 0)
	})
	t.Run("unrelated_entries_do_not_hide_target", func(t *testing.T) {
		f := base
		f.response = f.sign(t, func(body *ocspBody, _ *ocspBasic) {
			other := body.Responses[0]
			other.CertID.Serial = big.NewInt(999)
			other.Status.Tag = 2
			body.Responses = append([]ocspSingle{other}, body.Responses...)
		})
		checkOCSP(t, f, true, 0, 1)
	})
	t.Run("certificate_trust_precedes_revocation", func(t *testing.T) {
		f := base
		f.response = f.sign(t, nil)
		f.path.der = append([][]byte{}, f.path.der...)
		f.path.der[0] = bytes.Clone(f.path.der[0])
		f.path.der[0][len(f.path.der[0])-1] ^= 1
		// CertID status alone does not authenticate the certificate; this API
		// is deliberately called only after full path verification in a host.
		checkOCSP(t, f, false, 0, 0)
		checkOCSP(t, f, true, -2, 0)
	})
	for _, scenario := range []string{"revoked", "unknown", "serial", "name_hash", "key_hash", "hash_algorithm", "responder_name", "responder_key", "this_future", "produced_future", "produced_before_this", "expired", "missing_next", "next_before_produced", "duplicate_target", "duplicate_algorithms", "duplicate_after_target", "too_many", "empty_responses", "single_extension", "unknown_extension", "critical_extension", "duplicate_nonce", "missing_nonce", "raw_nonce", "foreign_certificate", "extra_certificate", "signature", "trailing", "truncated"} {
		t.Run("reject_"+scenario, func(t *testing.T) {
			f := base
			if scenario == "missing_nonce" || scenario == "raw_nonce" || scenario == "duplicate_nonce" {
				f.nonce = bytes.Repeat([]byte{1}, 32)
			}
			f.response = f.sign(t, func(body *ocspBody, basic *ocspBasic) {
				now := time.Unix(f.path.now, 0).UTC()
				switch scenario {
				case "revoked":
					encoded := ocspDER(t, struct {
						Time time.Time `asn1:"generalized"`
					}{now.Add(-2 * time.Minute)})
					var sequence asn1.RawValue
					if _, err := asn1.Unmarshal(encoded, &sequence); err != nil {
						t.Fatal(err)
					}
					body.Responses[0].Status = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: sequence.Bytes}
				case "unknown":
					body.Responses[0].Status.Tag = 2
				case "serial":
					body.Responses[0].CertID.Serial = big.NewInt(999)
				case "name_hash":
					body.Responses[0].CertID.NameHash[0] ^= 1
				case "key_hash":
					body.Responses[0].CertID.KeyHash[0] ^= 1
				case "hash_algorithm":
					body.Responses[0].CertID.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
				case "responder_name":
					body.Responder.Bytes = ocspDER(t, pkix.Name{CommonName: "substitute"}.ToRDNSequence())
				case "responder_key":
					body.Responder = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: ocspDER(t, bytes.Repeat([]byte{1}, 20))}
				case "this_future":
					body.Responses[0].ThisUpdate, body.ProducedAt = now.Add(time.Second), now.Add(time.Second)
				case "produced_future":
					body.ProducedAt = now.Add(time.Second)
				case "produced_before_this":
					body.ProducedAt = now.Add(-2 * time.Minute)
				case "expired":
					body.Responses[0].NextUpdate = now
				case "missing_next":
					body.Responses[0].NextUpdate = time.Time{}
				case "next_before_produced":
					body.Responses[0].NextUpdate = now.Add(-40 * time.Second)
				case "duplicate_target", "duplicate_after_target":
					body.Responses = append(body.Responses, body.Responses[0])
				case "duplicate_algorithms":
					other := body.Responses[0]
					other.CertID = f.certID(t, "sm3")
					body.Responses = append(body.Responses, other)
				case "too_many":
					for i := 0; i < 16; i++ {
						other := body.Responses[0]
						other.CertID.Serial = big.NewInt(int64(i + 100))
						body.Responses = append(body.Responses, other)
					}
				case "empty_responses":
					body.Responses = nil
				case "single_extension":
					body.Responses[0].Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{5, 0}}}
				case "unknown_extension", "critical_extension":
					body.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: scenario == "critical_extension", Value: []byte{5, 0}}}
				case "duplicate_nonce":
					body.Extensions = append(body.Extensions, body.Extensions[0])
				case "missing_nonce":
					body.Extensions = nil
				case "raw_nonce":
					body.Extensions[0].Value = f.nonce
				case "foreign_certificate":
					basic.Certificates = []asn1.RawValue{{FullBytes: f.path.der[0]}}
				case "extra_certificate":
					basic.Certificates = []asn1.RawValue{{FullBytes: f.path.der[1]}, {FullBytes: f.path.der[1]}}
				}
			})
			switch scenario {
			case "signature":
				f.response[len(f.response)-1] ^= 1
			case "trailing":
				f.response = append(f.response, 0)
			case "truncated":
				f.response = f.response[:len(f.response)-1]
			}
			checkOCSP(t, f, false, -2, 0)
			checkOCSP(t, f, true, -2, 1)
		})
	}
}

func delegatedOCSP(t *testing.T, scenario string) ocspFixture {
	t.Helper()
	f := ocspFixture{path: makePath(t, 1, nil), id: defaultSigningID, age: 3600, hash: "sha256", responderID: defaultSigningID}
	var err error
	f.responderKey, err = sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := smx509.ParseCertificate(f.path.der[1])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(f.path.now, 0).UTC()
	cert := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "delegated status"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
	switch scenario {
	case "missing_nocheck":
		cert.ExtraExtensions = nil
	case "critical_nocheck":
		cert.ExtraExtensions[0].Critical = true
	case "invalid_nocheck":
		cert.ExtraExtensions[0].Value = []byte{4, 0}
	case "wrong_eku":
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "missing_eku":
		cert.ExtKeyUsage = nil
	case "wrong_ku":
		cert.KeyUsage = x509.KeyUsageKeyEncipherment
	case "is_ca":
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign
	case "expired":
		cert.NotAfter = now.Add(-time.Second)
	case "future":
		cert.NotBefore = now.Add(time.Second)
	case "invalid_at_produced":
		cert.NotBefore = now.Add(-10 * time.Second)
	}
	f.responder, err = smx509.CreateCertificate(rand.Reader, cert, issuer, &f.responderKey.PublicKey, f.path.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	if scenario == "bad_certificate_signature" {
		f.responder[len(f.responder)-1] ^= 1
	}
	if scenario == "foreign_issuer" {
		foreign := makePath(t, 1, nil)
		foreignIssuer, err := smx509.ParseCertificate(foreign.der[1])
		if err != nil {
			t.Fatal(err)
		}
		f.responder, err = smx509.CreateCertificate(rand.Reader, cert, foreignIssuer, &f.responderKey.PublicKey, foreign.keys[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func TestSM2OCSPDelegation(t *testing.T) {
	for _, hash := range []string{"sha1", "sha256", "sm3"} {
		for _, byKey := range []bool{false, true} {
			for _, embed := range []bool{false, true} {
				t.Run(fmt.Sprintf("valid_%s_key_%t_embed_%t", hash, byKey, embed), func(t *testing.T) {
					f := delegatedOCSP(t, "")
					f.hash, f.byKey, f.embed = hash, byKey, embed
					f.response = f.sign(t, nil)
					checkOCSP(t, f, false, 0, 0)
					checkOCSP(t, f, true, 0, 1)
					checkOCSPMode(t, f, 2, 0, 0)
					// The direct-issuer API must never infer delegation from embedded bytes.
					f.responder = nil
					checkOCSP(t, f, false, -2, 0)
				})
			}
		}
	}
	for _, scenario := range []string{"missing_nocheck", "critical_nocheck", "invalid_nocheck", "wrong_eku", "missing_eku", "wrong_ku", "is_ca",
		"expired", "future", "invalid_at_produced", "bad_certificate_signature", "foreign_issuer", "wrong_certificate_ID", "wrong_response_ID",
		"wrong_responder_name", "wrong_responder_key", "embedded_issuer_only", "embedded_foreign", "extra_embedded", "revoked", "unknown", "bad_response_signature"} {
		t.Run("reject_"+scenario, func(t *testing.T) {
			f := delegatedOCSP(t, scenario)
			f.response = f.sign(t, func(body *ocspBody, basic *ocspBasic) {
				switch scenario {
				case "wrong_responder_name":
					body.Responder = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: ocspDER(t, pkix.Name{CommonName: "other"}.ToRDNSequence())}
				case "wrong_responder_key":
					body.Responder = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: ocspDER(t, make([]byte, 20))}
				case "embedded_issuer_only":
					basic.Certificates = []asn1.RawValue{{FullBytes: f.path.der[1]}}
				case "embedded_foreign":
					basic.Certificates = []asn1.RawValue{{FullBytes: f.path.der[0]}}
				case "extra_embedded":
					basic.Certificates = []asn1.RawValue{{FullBytes: f.responder}, {FullBytes: f.path.der[1]}, {FullBytes: f.path.der[1]}}
				case "revoked":
					der := ocspDER(t, struct {
						Time time.Time `asn1:"generalized"`
					}{time.Unix(f.path.now-120, 0).UTC()})
					var raw asn1.RawValue
					if _, err := asn1.Unmarshal(der, &raw); err != nil {
						t.Fatal(err)
					}
					body.Responses[0].Status = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: raw.Bytes}
				case "unknown":
					body.Responses[0].Status.Tag = 2
				}
			})
			if scenario == "wrong_certificate_ID" {
				f.responderID = []byte("wrong issuer ID")
			}
			if scenario == "wrong_response_ID" {
				f.id = []byte("wrong response ID")
			}
			if scenario == "bad_response_signature" {
				f.response[len(f.response)-1] ^= 1
			}
			checkOCSP(t, f, false, -2, 0)
			checkOCSP(t, f, true, -2, 1)
		})
	}
	t.Run("independent_binary_signing_IDs", func(t *testing.T) {
		f := delegatedOCSP(t, "")
		for _, id := range [][]byte{{'c', 0, 'i', 'd'}, bytes.Repeat([]byte{'c'}, 8191)} {
			f.responderID = id
			f.responder = resign(t, f.responder, f.path.keys[1], f.responderID, nil)
			f.id = append([]byte{'r', 0}, id[:len(id)-2]...)
			f.nonce = bytes.Repeat([]byte{0x4f}, 128)
			f.response = f.sign(t, nil)
			checkOCSP(t, f, true, 0, 1)
		}
	})
}
