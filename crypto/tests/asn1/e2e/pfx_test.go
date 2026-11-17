package e2e

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	f "github.com/qigao/salts-core/crypto/tests/e2e/fixtures"
)

type pfxIdentity struct{ key, leaf, root []byte }

func makePFXIdentity(t *testing.T, ec bool) pfxIdentity {
	t.Helper()
	var key crypto.Signer
	var err error
	if ec {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PFX test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pfxIdentity{keyDER, leafDER, rootDER}
}
func pfxStatus(t *testing.T, der, password []byte, ok bool, kind string) int {
	t.Helper()
	out := runPeer(t, *pfxPeer, der, 0, hex.EncodeToString(password), kind)
	status, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	if (status == 0) != ok {
		t.Fatalf("PFX status=%d success expected=%t", status, ok)
	}
	return status
}
func dataSafe(bags ...[]byte) []byte { return f.Content(f.Data, f.Octets(f.Seq(bags...))) }
func encryptedSafe(t *testing.T, body, password []byte, iterations int, sm bool) []byte {
	algorithm, ciphertext := f.Encrypt(t, body, password, iterations, sm)
	return f.Content(f.Encrypted, f.Seq(f.Integer(0), f.Seq(f.OID(f.Data), algorithm, f.TLV(0x80, ciphertext))))
}

func TestPKCS12Interop(t *testing.T) {
	ids := []pfxIdentity{makePFXIdentity(t, false), makePFXIdentity(t, true)}
	t.Run("independent_safes_and_passwords", func(t *testing.T) {
		for _, id := range ids {
			for _, pass := range [][]byte{nil, []byte("p\x00ass"), []byte("证书密钥")} {
				for _, privacy := range []bool{false, true} {
					for _, shrouded := range []bool{false, true} {
						bags := [][]byte{f.CertBag(id.root), f.KeyBag(t, id.key, pass, shrouded), f.CertBag(id.leaf)}
						safe := dataSafe(bags...)
						if privacy {
							safe = encryptedSafe(t, f.Seq(bags...), pass, 10000, false)
						}
						pfxStatus(t, f.Wrap(t, [][]byte{safe}, pass), pass, true, "single")
					}
				}
			}
		}
	})
	id := ids[0]
	pass := []byte("pass")
	safe := dataSafe(f.KeyBag(t, id.key, pass, true), f.CertBag(id.leaf), f.CertBag(id.root))
	t.Run("mac_profiles", func(t *testing.T) {
		for _, digest := range []string{"sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sm3"} {
			t.Run(digest, func(t *testing.T) {
				pfxStatus(t, f.WrapAuth(t, f.Seq(safe), pass, 10000, digest, nil), pass, true, "single")
			})
		}
	})
	t.Run("standard_asn1_producer_and_mac_policy", func(t *testing.T) {
		// A separate standard-library ASN.1 encoder writes the PFX outer object.
		// Preserve the independently encrypted safes and validate MAC work policy.
		for _, id := range ids {
			safe := dataSafe(f.KeyBag(t, id.key, pass, true), f.CertBag(id.leaf), f.CertBag(id.root))
			for _, rounds := range []int{2048, 10000} {
				der := f.WrapAuth(t, f.Seq(safe), pass, rounds, "sha256", nil)
				outer := sequence(t, der)
				value := struct {
					Version int
					Auth    asn1.RawValue
					MAC     asn1.RawValue
				}{3, outer[1], outer[2]}
				encoded, err := asn1.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				pfxStatus(t, encoded, pass, rounds >= 10000, "single")
				var decoded struct {
					Version int
					Auth    asn1.RawValue
					MAC     asn1.RawValue
				}
				rest, err := asn1.Unmarshal(encoded, &decoded)
				if err != nil || len(rest) != 0 || decoded.Version != 3 || !bytes.Equal(decoded.Auth.FullBytes, outer[1].FullBytes) {
					t.Fatal("standard ASN.1 round trip failed")
				}
			}
		}
	})
	t.Run("integrity_precedes_safe_algorithm", func(t *testing.T) {
		unsupported := f.Content(hx("2a864886f70d010703"), f.Seq())
		der := f.Wrap(t, [][]byte{unsupported}, pass)
		if pfxStatus(t, der, pass, false, "single") != -11 {
			t.Fatal("unsupported safe must report ENOTSUP")
		}
		if pfxStatus(t, der, []byte("wrong"), false, "single") != -5 {
			t.Fatal("wrong password must report EIO before content admission")
		}
	})
	t.Run("sm3_sm4_privacy", func(t *testing.T) {
		algorithm, ciphertext := f.Encrypt(t, id.key, pass, 10000, true)
		key := f.Seq(f.OID(append(bytes.Clone(f.Bags), 2)), f.TLV(0xa0, f.Seq(algorithm, f.Octets(ciphertext))))
		safe := encryptedSafe(t, f.Seq(key, f.CertBag(id.leaf)), pass, 10000, true)
		der := f.WrapAuth(t, f.Seq(safe), pass, 10000, "sm3", nil)
		pfxStatus(t, der, pass, true, "single")
		pfxStatus(t, der, []byte("wrong"), false, "single")
	})
	t.Run("aggregate_kdf_budget", func(t *testing.T) {
		identity := dataSafe(f.KeyBag(t, id.key, pass, false), f.CertBag(id.leaf))
		slow := encryptedSafe(t, f.Seq(), pass, 700000, false)
		pfxStatus(t, f.Wrap(t, [][]byte{identity, slow, slow, slow}, pass), pass, false, "single")
	})
	t.Run("unsupported_content_and_attributes", func(t *testing.T) {
		cert := f.CertBag(id.leaf)
		for _, bag := range [][]byte{f.Seq(f.OID(append(bytes.Clone(f.Bags), 6)), f.TLV(0xa0, f.Seq())),
			f.Seq(f.OID(append(bytes.Clone(f.Bags), 1)), f.TLV(0xa0, id.key), f.TLV(0x31, f.Seq(f.OID(hx("2a0304")), f.TLV(0x31, f.Integer(1)))))} {
			pfxStatus(t, f.Wrap(t, [][]byte{dataSafe(bag, cert)}, pass), pass, false, "single")
		}
		wrongKey := f.KeyBag(t, id.key, []byte("wrong"), true)
		pfxStatus(t, f.Wrap(t, [][]byte{dataSafe(wrongKey, cert)}, pass), pass, false, "single")
		pfxStatus(t, f.Wrap(t, [][]byte{encryptedSafe(t, []byte("not DER"), pass, 10000, false)}, pass), pass, false, "single")
	})
	t.Run("invalid_inputs", func(t *testing.T) {
		valid := f.Wrap(t, [][]byte{safe}, pass)
		pfxStatus(t, valid, []byte("wrong"), false, "single")
		for _, index := range []int{0, len(valid) / 2, len(valid) - 1} {
			bad := bytes.Clone(valid)
			bad[index] ^= 1
			pfxStatus(t, bad, pass, false, "single")
		}
		for _, bad := range [][]byte{valid[:len(valid)-1], append(bytes.Clone(valid), 0), nil, make([]byte, 65537)} {
			pfxStatus(t, bad, pass, false, "single")
		}
		for _, rounds := range []int{9999, 1000001} {
			pfxStatus(t, f.WrapAuth(t, f.Seq(safe), pass, rounds, "sha256", nil), pass, false, "single")
		}
		for _, salt := range [][]byte{[]byte("short"), make([]byte, 65)} {
			pfxStatus(t, f.WrapAuth(t, f.Seq(safe), pass, 10000, "sha256", salt), pass, false, "single")
		}
		for _, bad := range [][]byte{{255}, []byte("😀"), make([]byte, 1025)} {
			pfxStatus(t, valid, bad, false, "single")
		}
		pfxStatus(t, valid, pass, false, "tlcp")
		key, cert := f.KeyBag(t, id.key, pass, true), f.CertBag(id.leaf)
		for _, bags := range [][][]byte{{cert}, {key}, {key, cert, cert}, {f.KeyBag(t, ids[1].key, pass, true), cert}, {key, cert, f.CertBag(ids[1].root)}, {key, key, cert}} {
			pfxStatus(t, f.Wrap(t, [][]byte{dataSafe(bags...)}, pass), pass, false, "single")
		}
		pfxStatus(t, f.Seq(f.Integer(3), f.Content(f.Data, f.Octets(f.Seq(safe)))), pass, false, "single")
	})
}
