package fixtures

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"os"
	"testing"
	"unicode/utf16"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/pbkdf2"
)

var (
	Data      = unhex("2a864886f70d010701")
	Encrypted = unhex("2a864886f70d010706")
	Bags      = unhex("2a864886f70d010c0a01")
	Cert      = unhex("2a864886f70d01091601")
	SHA256    = unhex("608648016503040201")
	PBES2     = unhex("2a864886f70d01050d")
	PBKDF2    = unhex("2a864886f70d01050c")
	PRF       = unhex("2a864886f70d0209")
	AES256    = unhex("60864801650304012a")
	SM3       = unhex("2a811ccf55018311")
	HMACSM3   = append(bytes.Clone(SM3), 2)
	SM4       = unhex("2a811ccf55016802")
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TLV(tag byte, parts ...[]byte) []byte {
	payload := bytes.Join(parts, nil)
	out := []byte{tag}
	if len(payload) < 128 {
		out = append(out, byte(len(payload)))
	} else {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
		n := bytes.TrimLeft(size[:], "\x00")
		out = append(out, 0x80|byte(len(n)))
		out = append(out, n...)
	}
	return append(out, payload...)
}

func Seq(parts ...[]byte) []byte { return TLV(0x30, parts...) }
func OID(value []byte) []byte    { return TLV(6, value) }
func Octets(value []byte) []byte { return TLV(4, value) }
func Integer(value int) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	b := bytes.TrimLeft(raw[:], "\x00")
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&128 != 0 {
		b = append([]byte{0}, b...)
	}
	return TLV(2, b)
}
func Content(kind, value []byte) []byte { return Seq(OID(kind), TLV(0xa0, value)) }

func random(t testing.TB, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func Encrypt(t testing.TB, plain, password []byte, iterations int, shangmi bool) ([]byte, []byte) {
	t.Helper()
	salt, iv := random(t, 16), random(t, 16)
	digest, keySize, prf, algorithm := sha256.New, 32, PRF, AES256
	if shangmi {
		digest, keySize, prf, algorithm = sm3.New, 16, HMACSM3, SM4
	}
	key := pbkdf2.Key(password, salt, iterations, keySize, digest)
	var block cipher.Block
	var err error
	if shangmi {
		block, err = sm4.NewCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	count := 16 - len(plain)%16
	padding := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(count)}, count)...)
	ciphertext := make([]byte, len(padding))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padding)
	params := Seq(Seq(OID(PBKDF2), Seq(Octets(salt), Integer(iterations), Seq(OID(prf), TLV(5)))), Seq(OID(algorithm), Octets(iv)))
	return Seq(OID(PBES2), params), ciphertext
}

func KeyBag(t testing.TB, key, password []byte, encrypted bool) []byte {
	if encrypted {
		algorithm, ciphertext := Encrypt(t, key, password, 10000, false)
		return Seq(OID(append(bytes.Clone(Bags), 2)), TLV(0xa0, Seq(algorithm, Octets(ciphertext))))
	}
	return Seq(OID(append(bytes.Clone(Bags), 1)), TLV(0xa0, key))
}
func CertBag(cert []byte) []byte {
	return Seq(OID(append(bytes.Clone(Bags), 3)), TLV(0xa0, Seq(OID(Cert), TLV(0xa0, Octets(cert)))))
}

func digest(name string) (func() hash.Hash, byte) {
	switch name {
	case "sm3":
		return sm3.New, 0
	case "sha224":
		return sha256.New224, 4
	case "sha256":
		return sha256.New, 1
	case "sha384":
		return sha512.New384, 2
	case "sha512":
		return sha512.New, 3
	case "sha512_224":
		return sha512.New512_224, 5
	case "sha512_256":
		return sha512.New512_256, 6
	default:
		panic("unknown fixture digest: " + name)
	}
}

func WrapAuth(t testing.TB, auth, password []byte, iterations int, name string, salt []byte) []byte {
	t.Helper()
	newHash, suffix := digest(name)
	if salt == nil {
		salt = random(t, 16)
	}
	units := append(utf16.Encode([]rune(string(password))), 0)
	bmp := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.BigEndian.PutUint16(bmp[2*i:], unit)
	}
	h := newHash()
	repeated := func(input []byte) []byte {
		if len(input) == 0 {
			return nil
		}
		size := h.BlockSize() * ((len(input) + h.BlockSize() - 1) / h.BlockSize())
		return bytes.Repeat(input, (size+len(input)-1)/len(input))[:size]
	}
	h.Write(bytes.Repeat([]byte{3}, h.BlockSize()))
	h.Write(repeated(salt))
	h.Write(repeated(bmp))
	key := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
	}
	mac := hmac.New(newHash, key)
	mac.Write(auth)
	oid := append(bytes.Clone(SHA256[:len(SHA256)-1]), suffix)
	if name == "sm3" {
		oid = SM3
	}
	return Seq(Integer(3), Content(Data, Octets(auth)), Seq(Seq(Seq(OID(oid), TLV(5)), Octets(mac.Sum(nil))), Octets(salt), Integer(iterations)))
}
func Wrap(t testing.TB, safes [][]byte, password []byte) []byte {
	return WrapAuth(t, Seq(safes...), password, 10000, "sha256", nil)
}

func WritePFX(t testing.TB, output, certificatePath string, keyPaths ...string) {
	t.Helper()
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var certs, keys [][]byte
	for rest := read(certificatePath); len(bytes.TrimSpace(rest)) != 0; {
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("invalid certificate fixture")
		}
		certs = append([][]byte{CertBag(block.Bytes)}, certs...)
		rest = tail
	}
	password := []byte("memory\x00sign")
	for _, path := range keyPaths {
		block, rest := pem.Decode(read(path))
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("fixture requires one plaintext PKCS8 key")
		}
		keys = append([][]byte{KeyBag(t, block.Bytes, password, true)}, keys...)
	}
	algorithm, ciphertext := Encrypt(t, Seq(certs...), password, 10000, false)
	safes := [][]byte{Content(Encrypted, Seq(Integer(0), Seq(OID(Data), algorithm, TLV(0x80, ciphertext)))), Content(Data, Octets(Seq(keys...)))}
	if err := os.WriteFile(output, Wrap(t, safes, password), 0600); err != nil {
		t.Fatal(err)
	}
}
