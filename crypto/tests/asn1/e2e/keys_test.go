package e2e

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os/exec"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	f "github.com/qigao/salts-core/crypto/tests/e2e/fixtures"
	"golang.org/x/crypto/pbkdf2"
)

var sm2Peer = flag.String("sm2-keys-peer", "", "native key-container executable")
var pfxPeer = flag.String("pkcs12-peer", "", "native PFX executable")
var password = []byte("p\x00ass")
var scalar = append(make([]byte, 31), 1)
var public = hx("0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
var ecOID = hx("2a8648ce3d0201")
var sm2OID = hx("2a811ccf5501822d")

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func sequence(t *testing.T, data []byte) []asn1.RawValue {
	t.Helper()
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) != 0 || outer.Tag != 16 {
		t.Fatalf("native DER sequence: %v", err)
	}
	return fields(t, outer.Bytes)
}
func fields(t *testing.T, data []byte) []asn1.RawValue {
	t.Helper()
	var values []asn1.RawValue
	for len(data) != 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(data, &v)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, v)
		data = rest
	}
	return values
}
func runPeer(t *testing.T, binary string, input []byte, status int, args ...string) []byte {
	t.Helper()
	if binary == "" {
		t.Fatal("native executable argument is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	actual := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			actual = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if actual != status {
		t.Fatalf("native exit %d, expected %d: %s", actual, status, stderr.String())
	}
	return out
}
func privateInfo(curve, point bool) []byte {
	inner := [][]byte{f.Integer(1), f.Octets(scalar)}
	if curve {
		inner = append(inner, f.TLV(0xa0, f.OID(sm2OID)))
	}
	if point {
		inner = append(inner, f.TLV(0xa1, f.TLV(3, append([]byte{0}, public...))))
	}
	return f.Seq(f.Integer(0), f.Seq(f.OID(ecOID), f.OID(sm2OID)), f.Octets(f.Seq(inner...)))
}

type keyOptions struct {
	aes, omitLength, nullPRF, noPRF       bool
	keyLength, iterations                 int
	prf, cipherOID, iv, padding, password []byte
}

func rangeBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
func encryptInfo(t *testing.T, plain, salt []byte, o keyOptions) []byte {
	t.Helper()
	width, prf, algorithm := 16, f.HMACSM3, f.SM4
	var newHash func() hash.Hash = sm3.New
	if o.aes {
		width, prf, algorithm, newHash = 32, f.PRF, f.AES256, sha256.New
	}
	iterations := o.iterations
	if iterations == 0 {
		iterations = 10000
	}
	pass := o.password
	if pass == nil {
		pass = password
	}
	key := pbkdf2.Key(pass, salt, iterations, width, newHash)
	var block cipher.Block
	var err error
	if o.aes {
		block, err = aes.NewCipher(key)
	} else {
		block, err = sm4.NewCipher(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	padding := o.padding
	if padding == nil {
		n := 16 - len(plain)%16
		padding = bytes.Repeat([]byte{byte(n)}, n)
	}
	plain = append(bytes.Clone(plain), padding...)
	sealed := make([]byte, len(plain))
	actualIV := rangeBytes(32)[16:]
	cipher.NewCBCEncrypter(block, actualIV).CryptBlocks(sealed, plain)
	iv := o.iv
	if iv == nil {
		iv = actualIV
	}
	params := [][]byte{f.Octets(salt), f.Integer(iterations)}
	if !o.omitLength {
		n := o.keyLength
		if n == 0 {
			n = width
		}
		params = append(params, f.Integer(n))
	}
	if o.prf != nil {
		prf = o.prf
	}
	if !o.noPRF {
		p := [][]byte{f.OID(prf)}
		if o.nullPRF {
			p = append(p, f.TLV(5))
		}
		params = append(params, f.Seq(p...))
	}
	if o.cipherOID != nil {
		algorithm = o.cipherOID
	}
	alg := f.Seq(f.OID(f.PBES2), f.Seq(f.Seq(f.OID(f.PBKDF2), f.Seq(params...)), f.Seq(f.OID(algorithm), f.Octets(iv))))
	return f.Seq(alg, f.Octets(sealed))
}
func keyResult(t *testing.T, der []byte, aesProfile, ok bool) {
	t.Helper()
	mode := "decrypt"
	if aesProfile {
		mode = "decrypt-aes256"
	}
	status := 3
	if ok {
		status = 0
	}
	out := runPeer(t, *sm2Peer, der, status, mode)
	expected := []byte(nil)
	if ok {
		expected = scalar
	}
	if !bytes.Equal(out, expected) {
		t.Fatalf("unexpected key publication: %x", out)
	}
}

func TestSM2KeyInterop(t *testing.T) {
	t.Run("independent_imports", func(t *testing.T) {
		for _, aesProfile := range []bool{false, true} {
			for _, curve := range []bool{false, true} {
				for _, point := range []bool{false, true} {
					for _, size := range []int{16, 32, 64} {
						for _, omit := range []bool{false, true} {
							for _, null := range []bool{false, true} {
								keyResult(t, encryptInfo(t, privateInfo(curve, point), rangeBytes(size), keyOptions{aes: aesProfile, omitLength: omit, nullPRF: null}), aesProfile, true)
							}
						}
					}
				}
			}
		}
	})
	t.Run("aes_policy_and_padding", func(t *testing.T) {
		cases := []keyOptions{{keyLength: 16}, {keyLength: 24}, {keyLength: 33}, {noPRF: true}, {prf: f.HMACSM3}, {prf: append(bytes.Clone(f.PRF[:len(f.PRF)-1]), 10)},
			{cipherOID: f.SM4}, {cipherOID: append(bytes.Clone(f.AES256[:len(f.AES256)-1]), 2)},
			{iterations: 9999}, {iterations: 10001}, {iterations: 16777216}, {password: []byte("wrong")}, {iv: make([]byte, 15)}, {iv: make([]byte, 17)},
			{padding: make([]byte, 10)}, {padding: bytes.Repeat([]byte{17}, 10)}, {padding: append([]byte{9}, bytes.Repeat([]byte{10}, 9)...)}}
		for i, o := range cases {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				o.aes = true
				keyResult(t, encryptInfo(t, privateInfo(true, true), rangeBytes(16), o), true, false)
			})
		}
		for _, size := range []int{15, 65} {
			keyResult(t, encryptInfo(t, privateInfo(true, true), rangeBytes(size), keyOptions{aes: true}), true, false)
		}
		wrong := privateInfo(true, true)
		wrong[67] = 2
		for _, plain := range [][]byte{wrong, append(privateInfo(true, true), 0)} {
			keyResult(t, encryptInfo(t, plain, rangeBytes(16), keyOptions{aes: true}), true, false)
		}
	})
	t.Run("invalid_plain_containers", func(t *testing.T) {
		wrongScalar, wrongCurve := privateInfo(true, true), privateInfo(true, true)
		wrongScalar[67] = 2
		wrongCurve[79] ^= 1
		attrs := f.Seq(f.Integer(0), f.Seq(f.OID(ecOID), f.OID(sm2OID)), f.Octets(f.Seq(f.Integer(1), f.Octets(scalar))), f.TLV(0xa0))
		noncanonical := f.Seq(f.Integer(0), f.Seq(f.OID(ecOID), f.OID(sm2OID)), f.Octets(append(hx("308125"), append(f.Integer(1), f.Octets(scalar)...)...)))
		for _, plain := range [][]byte{wrongScalar, wrongCurve, attrs, noncanonical, append(privateInfo(false, false), 0)} {
			keyResult(t, encryptInfo(t, plain, rangeBytes(16), keyOptions{}), false, false)
		}
	})
	t.Run("native_exports", func(t *testing.T) {
		for _, aesProfile := range []bool{false, true} {
			mode := "encrypt"
			if aesProfile {
				mode = "encrypt-aes256"
			}
			var previous []byte
			for repeat := 0; repeat < 2; repeat++ {
				der := runPeer(t, *sm2Peer, nil, 0, mode)
				outer := sequence(t, der)
				alg := fields(t, outer[0].Bytes)
				if !bytes.Equal(alg[0].Bytes, f.PBES2) {
					t.Fatal("wrong PBES2 OID")
				}
				kdfAndCipher := fields(t, alg[1].Bytes)
				kdf := fields(t, kdfAndCipher[0].Bytes)
				params := fields(t, kdf[1].Bytes)
				if !bytes.Equal(kdf[0].Bytes, f.PBKDF2) || len(params[0].Bytes) != 16 || !bytes.Equal(params[1].Bytes, hx("2710")) {
					t.Fatal("wrong KDF parameters")
				}
				var newHash func() hash.Hash = sm3.New
				size, oid, prf := 16, f.SM4, f.HMACSM3
				if aesProfile {
					newHash, size, oid, prf = sha256.New, 32, f.AES256, f.PRF
				}
				if !bytes.Equal(params[2].Bytes, []byte{byte(size)}) || !bytes.Equal(fields(t, params[3].Bytes)[0].Bytes, prf) {
					t.Fatal("wrong key length/PRF")
				}
				scheme := fields(t, kdfAndCipher[1].Bytes)
				if !bytes.Equal(scheme[0].Bytes, oid) || len(scheme[1].Bytes) != 16 {
					t.Fatal("wrong encryption scheme")
				}
				key := pbkdf2.Key(password, params[0].Bytes, 10000, size, newHash)
				var block cipher.Block
				var err error
				if aesProfile {
					block, err = aes.NewCipher(key)
				} else {
					block, err = sm4.NewCipher(key)
				}
				if err != nil {
					t.Fatal(err)
				}
				plain := make([]byte, len(outer[1].Bytes))
				cipher.NewCBCDecrypter(block, scheme[1].Bytes).CryptBlocks(plain, outer[1].Bytes)
				if !bytes.Equal(plain[len(plain)-10:], bytes.Repeat([]byte{10}, 10)) || !bytes.Equal(plain[:len(plain)-10], privateInfo(true, true)) {
					t.Fatal("native key encoding differs")
				}
				if previous != nil && bytes.Equal(previous, der) {
					t.Fatal("native exports reused randomness")
				}
				previous = der
				keyResult(t, der, !aesProfile, false)
			}
		}
	})
}
