package tls_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var pbes2OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
var pbkdf2OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
var sha256PRFOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
var aes256CBCOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

var aesFixturePRFs = []struct {
	name    string
	oid     int
	newHash func() hash.Hash
}{
	{"sha224", 8, sha256.New224},
	{"sha384", 10, sha512.New384},
	{"sha512", 11, sha512.New},
	{"sha512_224", 12, sha512.New512_224},
	{"sha512_256", 13, sha512.New512_256},
}

func marshalDER(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func writeAESFixture(t *testing.T, f identity, password, scenario string) {
	t.Helper()
	writeAESFixtureFrom(t, f, f, password, scenario)
}
func writeAESFixtureFrom(t *testing.T, source, target identity, password, scenario string, bits ...int) {
	prfOID := append(asn1.ObjectIdentifier{}, sha256PRFOID...)
	derive := sha256.New
	if name, base, named := strings.Cut(scenario, ":"); named {
		found := false
		for _, prf := range aesFixturePRFs {
			if name == prf.name {
				derive = prf.newHash
				prfOID[len(prfOID)-1] = prf.oid
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unknown fixture PRF %s", name)
		}
		scenario = base
	}
	keyBytes := 32
	if len(bits) != 0 {
		keyBytes = bits[0] / 8
	}
	oid := append(asn1.ObjectIdentifier{}, aes256CBCOID...)
	switch keyBytes {
	case 16:
		oid[len(oid)-1] = 2
	case 24:
		oid[len(oid)-1] = 22
	case 32:
	default:
		t.Fatal("unsupported fixture key size")
	}
	t.Helper()
	plain, err := os.ReadFile(source.keyFile + ".der")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	pass := []byte("memory\x00sign")
	if password == "empty" {
		pass = []byte{}
	}
	if password == "wrong" {
		pass = []byte("wrong")
	}
	defer clear(pass)
	salt := make([]byte, 16)
	iv := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	iterations := 10000
	switch scenario {
	case "short_salt":
		salt = salt[:7]
	case "long_salt":
		salt = make([]byte, 65)
	case "minimum_salt":
		salt = salt[:8]
	case "maximum_salt":
		salt = make([]byte, 64)
	case "low_iterations":
		iterations = 9999
	case "high_iterations":
		iterations = 1000001
	case "maximum_iterations":
		iterations = 1000000
	case "plaintext":
		plain = []byte("not PKCS8")
	}
	// Invalid work-limit envelopes are encrypted at the minimum, so fixture
	// generation itself never performs unbounded work.
	work := iterations
	if work > 1000000 {
		work = 10000
	}
	key, err := pbkdf2.Key(derive, string(pass), salt, work, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append([]byte{}, plain...)
	for i := 0; i < padding; i++ {
		padded = append(padded, byte(padding))
	}
	defer clear(padded)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	prf := pkix.AlgorithmIdentifier{Algorithm: prfOID, Parameters: asn1.RawValue{FullBytes: []byte{5, 0}}}
	keyLength := keyBytes
	switch scenario {
	case "absent_length":
		keyLength = 0
	case "wrong_length":
		keyLength = keyBytes + 8
	case "absent_prf":
		prf = pkix.AlgorithmIdentifier{}
	case "unsupported_prf":
		prf.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	case "wrong_prf":
		prf.Algorithm = sha256PRFOID
	case "bad_prf_parameters":
		prf.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 0}}
	case "absent_prf_parameters":
		prf.Parameters = asn1.RawValue{}
	case "padding":
		ciphertext[len(ciphertext)-17] ^= 1
	case "unaligned":
		ciphertext = ciphertext[:len(ciphertext)-1]
	case "empty_ciphertext":
		ciphertext = nil
	case "oversized_ciphertext":
		ciphertext = make([]byte, 8208)
	}
	params := struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
	}{salt, iterations, keyLength, prf}
	enc := pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: marshalDER(t, iv)}}
	switch scenario {
	case "unsupported_cipher":
		enc.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	case "mixed_sm4":
		enc.Algorithm = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	case "short_iv":
		enc.Parameters = asn1.RawValue{FullBytes: marshalDER(t, iv[:15])}
	case "long_iv":
		enc.Parameters = asn1.RawValue{FullBytes: marshalDER(t, append(iv, 0))}
	}
	pbes := struct{ KDF, Encryption pkix.AlgorithmIdentifier }{
		pkix.AlgorithmIdentifier{Algorithm: pbkdf2OID, Parameters: asn1.RawValue{FullBytes: marshalDER(t, params)}}, enc}
	envelope := struct {
		Algorithm  pkix.AlgorithmIdentifier
		Ciphertext []byte
	}{
		pkix.AlgorithmIdentifier{Algorithm: pbes2OID, Parameters: asn1.RawValue{FullBytes: marshalDER(t, pbes)}}, ciphertext}
	der := marshalDER(t, envelope)
	if scenario == "trailing" {
		der = append(der, 0)
	}
	if scenario == "truncated" {
		der = der[:len(der)-1]
	}
	for path, data := range map[string][]byte{target.keyFile + ".encrypted.der": der, target.keyFile + ".encrypted": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestEncryptedCredentials(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	for _, ec := range []bool{false, true} {
		f := makeIdentity(t, "encrypted", ec, nil)
		other := makeIdentity(t, "other", ec, nil)
		for _, bits := range []int{128, 192, 256} {
			for _, mode := range []string{"pem", "der"} {
				scenarios := []string{"valid", "absent_length", "absent_prf_parameters", "minimum_salt", "maximum_salt", "empty_password", "wrong_password", "wrong_length", "absent_prf", "unsupported_prf", "bad_prf_parameters", "padding", "unaligned", "empty_ciphertext", "oversized_ciphertext", "unsupported_cipher", "mixed_sm4", "short_iv", "long_iv", "short_salt", "long_salt", "low_iterations", "high_iterations", "plaintext", "mismatched_key", "trailing", "truncated"}
				if bits == 256 {
					scenarios = append(scenarios, "maximum_iterations")
				}
				for _, prf := range aesFixturePRFs {
					for _, scenario := range []string{"valid", "absent_length", "absent_prf_parameters", "empty_password", "wrong_password", "wrong_prf"} {
						scenarios = append(scenarios, prf.name+":"+scenario)
					}
					if bits == 256 && !ec {
						for _, scenario := range []string{"bad_prf_parameters", "absent_prf", "unsupported_prf", "mixed_sm4", "wrong_length", "padding", "mismatched_key", "high_iterations", "short_salt", "trailing"} {
							scenarios = append(scenarios, prf.name+":"+scenario)
						}
					}
				}
				for _, scenario := range scenarios {
					base := scenario
					if _, value, named := strings.Cut(scenario, ":"); named {
						base = value
					}
					name := "rsa/"
					if ec {
						name = "p256/"
					}
					t.Run(fmt.Sprintf("%s%d/%s/%s", name, bits, mode, scenario), func(t *testing.T) {
						target := f
						target.keyFile = filepath.Join(t.TempDir(), "key.pem")
						password := "binary"
						expect := "reject"
						switch base {
						case "valid", "absent_length", "absent_prf_parameters", "minimum_salt", "maximum_salt", "maximum_iterations":
							expect = "accept"
						case "empty_password":
							password = "empty"
							expect = "accept"
							t.Setenv("SALTS_TEST_TLS_EMPTY_PASSWORD", "1")
						case "wrong_password":
							password = "wrong"
						case "oversized_ciphertext":
							expect = "range"
						}
						source := f
						if base == "mismatched_key" {
							source = other
						}
						writeAESFixtureFrom(t, source, target, password, scenario, bits)
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
						ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
						defer cancel()
						out, err := exec.CommandContext(ctx, *native, "--encrypted-credential-admission", f.ca, f.cert, target.keyFile, expect).CombinedOutput()
						if err != nil {
							t.Fatalf("native: %v\n%s", err, out)
						}
					})
				}
			}
		}
	}
}
