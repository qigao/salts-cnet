package shangmiinterop

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm3"
)

var python = flag.String("python", "", "configured formal fixture interpreter")

// Both endpoints are production CNet/NativeIO/GmSSL here. Certificates and
// fingerprint expectations are independent; this is not a second TLS engine.
func mutual(t *testing.T, server, client fixture, outcome string) {
	t.Helper()
	cert, key := client.certPath, client.keyPath
	if cert == "" {
		cert, key = "-", "-"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	clientHash := "-"
	if client.leaf != nil {
		clientHash = fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw))
	}
	args := []string{"--shangmi-mtls", server.caPath, client.caPath, server.certPath, server.keyPath,
		cert, key, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)), clientHash,
		fmt.Sprintf("%x", sm3.Sum(server.leaf.Raw))}
	if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
		t.Fatalf("native ShangMi mTLS: %v\n%s", err, out)
	}
}

func clientCredentials(t *testing.T, change func(*x509.Certificate)) fixture {
	t.Helper()
	return credentials(t, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if change != nil {
			change(c)
		}
	})
}

func corruptCertificate(t *testing.T, f fixture) fixture {
	t.Helper()
	f.leaf.Raw[len(f.leaf.Raw)-1] ^= 1
	if err := os.WriteFile(f.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestShangMiMutual(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	t.Run("verification_depth", testVerificationDepth)
	t.Run("certificate_signature_positions", testMutualCertificateSignaturePositions)
	t.Run("signature_policy", testSignaturePolicy)
	t.Run("separate_certificate_policy", testSeparateCertificatePolicy)
	server, client := credentials(t, nil), clientCredentials(t, nil)

	memoryFixtures(t, server.caPath, server.certPath, server.keyPath, client.caPath, client.certPath, client.keyPath)
	encryptedMemoryFixture(t, server.keyPath)
	encryptedMemoryFixture(t, client.keyPath)
	for _, bits := range []int{128, 192, 256} {
		encryptedMemoryFixture(t, server.keyPath, bits)
		encryptedMemoryFixture(t, client.keyPath, bits)
		for _, prf := range []int{224, 384, 512, 512224, 512256} {
			encryptedMemoryFixture(t, server.keyPath, bits, prf)
			encryptedMemoryFixture(t, client.keyPath, bits, prf)
		}
	}
	t.Run("pkcs12", func(t *testing.T) {
		if *python == "" {
			t.Fatal("-python is required for PFX fixtures")
		}
		script := filepath.Join("..", "..", "..", "crypto", "tests", "asn1", "pkcs12_peer.py")
		for _, f := range []fixture{server, client} {
			if out, err := exec.Command(*python, script, "--fixture", f.certPath+".pfx", f.certPath, f.keyPath).CombinedOutput(); err != nil {
				t.Fatalf("PFX fixture: %v\n%s", err, out)
			}
		}
		t.Setenv("SALTS_TEST_TLS_MEMORY", "der")
		t.Setenv("SALTS_TEST_TLS_PKCS12", "1")
		mutual(t, server, client, "accept")
		runNativeServerWithClient(t, server, &client, "close")
		runNativeClientWithIdentity(t, server, &client, "localhost", true, "")
	})
	for _, mode := range []string{"pem", "der"} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("credential_object_%s/%t", mode, encrypted), func(t *testing.T) {
				t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
				t.Setenv("SALTS_TEST_TLS_OBJECT", "1")
				t.Setenv("SALTS_TEST_TLS_GROUP", "1")
				if encrypted {
					t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
				}
				mutual(t, server, client, "accept")
				runNativeServerWithClient(t, server, &client, "close")
				runNativeClientWithIdentity(t, server, &client, "localhost", true, "")
			})
		}
		t.Run("memory_"+mode, func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
			mutual(t, server, client, "accept")
			runNativeServerWithClient(t, server, &client, "close")
			runNativeClientWithIdentity(t, server, &client, "localhost", true, "")
		})
		for _, hash := range []string{"", "sha224", "sha384", "sha512", "sha512_224", "sha512_256"} {
			for _, encryption := range []string{"aes128", "aes192", "aes"} {
				name := encryption + "_encrypted_memory_" + mode
				if hash != "" {
					name = hash + "_" + name
				}
				t.Run(name, func(t *testing.T) {
					t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
					t.Setenv("SALTS_TEST_TLS_ENCRYPTED", encryption)
					if hash != "" {
						t.Setenv("SALTS_TEST_TLS_PBKDF2", hash)
					}
					mutual(t, server, client, "accept")
					runNativeServerWithClient(t, server, &client, "close")
					runNativeClientWithIdentity(t, server, &client, "localhost", true, "")
				})
			}
		}
		t.Run("encrypted_memory_"+mode, func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
			t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
			mutual(t, server, client, "accept")
			runNativeServerWithClient(t, server, &client, "close")
			runNativeClientWithIdentity(t, server, &client, "localhost", true, "")
		})
	}
	t.Run("verified_distinct_trust_roots", func(t *testing.T) { mutual(t, server, client, "accept") })
	t.Run("reject_client_peer_policy", func(t *testing.T) { mutual(t, server, client, "reject-policy-client") })
	t.Run("reject_server_peer_policy", func(t *testing.T) { mutual(t, server, client, "reject-policy-server") })
	t.Run("reject_missing_client", func(t *testing.T) {
		missing := client
		missing.certPath, missing.keyPath, missing.leaf = "", "", nil
		mutual(t, server, missing, "reject-server")
	})
	t.Run("reject_client_unknown_ca", func(t *testing.T) {
		bad := client
		bad.caPath = credentials(t, nil).caPath
		mutual(t, server, bad, "reject-server")
	})
	t.Run("reject_server_unknown_ca", func(t *testing.T) {
		bad := server
		bad.caPath = credentials(t, nil).caPath
		mutual(t, bad, client, "reject-client")
	})
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		},
		"future":          func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"key_usage":       func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"server_only_eku": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
	} {
		t.Run("reject_client_"+name, func(t *testing.T) { mutual(t, server, clientCredentials(t, change), "reject-server") })
	}
	t.Run("reject_client_certificate_signature", func(t *testing.T) {
		mutual(t, server, corruptCertificate(t, clientCredentials(t, nil)), "reject-server")
	})
	t.Run("reject_server_certificate_signature", func(t *testing.T) {
		mutual(t, corruptCertificate(t, credentials(t, nil)), client, "reject-client")
	})
}

func encryptedMemoryFixture(t *testing.T, path string, aesBits ...int) {
	t.Helper()
	plain, err := os.ReadFile(path + ".der")
	if err != nil {
		t.Fatal(err)
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	suffix := ".encrypted"
	encrypter := pkcs.NewPBESEncrypter(pkcs.SM4CBC, pkcs.NewPBKDF2Opts(pkcs.SM3, 16, 10000))
	if len(aesBits) != 0 {
		suffix = ".aes"
		algorithm := pkcs.AES256CBC
		if aesBits[0] == 128 {
			suffix = ".aes128"
			algorithm = pkcs.AES128CBC
		}
		if aesBits[0] == 192 {
			suffix = ".aes192"
			algorithm = pkcs.AES192CBC
		}
		prf := pkcs.SHA256
		if len(aesBits) > 1 {
			switch aesBits[1] {
			case 224:
				prf = pkcs.SHA224
				suffix += ".sha224"
			case 512224:
				prf = pkcs.SHA512_224
				suffix += ".sha512_224"
			case 512256:
				prf = pkcs.SHA512_256
				suffix += ".sha512_256"
			case 384:
				prf = pkcs.SHA384
				suffix += ".sha384"
			case 512:
				prf = pkcs.SHA512
				suffix += ".sha512"
			default:
				t.Fatal("unsupported fixture PRF")
			}
		}
		encrypter = pkcs.NewPBESEncrypter(algorithm, pkcs.NewPBKDF2Opts(prf, 16, 10000))
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte("memory\x00sign"), encrypter)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+suffix+".der", der, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+suffix, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestShangMiMutualIndependent(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	server, client := credentials(t, nil), clientCredentials(t, nil)
	testCertificateTime(t, server, client, true)
	t.Run("verified_client", func(t *testing.T) { runNativeServerWithClient(t, server, &client, "close") })
	t.Run("certificate_signature_policy", func(t *testing.T) {
		t.Setenv("SALTS_TEST_TLS_SM2_CERT_POLICY", "1")
		runNativeServerWithClient(t, server, &client, "close")
	})
	t.Run("fragmented_client_flight", func(t *testing.T) { runNativeServerWithClient(t, server, &client, "close", "fragmented") })
	t.Run("reject_raw_eof", func(t *testing.T) { runNativeServerWithClient(t, server, &client, "eof") })
	for _, scenario := range []string{"missing", "certificate_verify", "server_context", "certificate_id", "tlcp_signature", "request_context", "finished"} {
		t.Run("reject_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, server, &client, "reject", scenario) })
	}
	t.Run("reject_unknown_client_ca", func(t *testing.T) {
		bad := client
		bad.caPath = credentials(t, nil).caPath
		runNativeServerWithClient(t, server, &bad, "reject")
	})
	t.Run("reject_client_certificate_signature", func(t *testing.T) {
		bad := corruptCertificate(t, clientCredentials(t, nil))
		runNativeServerWithClient(t, server, &bad, "reject")
	})
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		},
		"future":          func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"key_usage":       func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"server_only_eku": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
	} {
		t.Run("reject_client_"+name, func(t *testing.T) {
			if name == "expired" || name == "future" {
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", name)
				t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
			}
			if name == "key_usage" || name == "server_only_eku" {
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "purpose")
				t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
			}
			bad := clientCredentials(t, change)
			if name == "key_usage" || name == "server_only_eku" {
				memoryFixtures(t, server.certPath, server.keyPath, bad.caPath)
				for _, mode := range []string{"file", "pem", "der"} {
					t.Run(mode, func(t *testing.T) {
						if mode != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						}
						runNativeServerWithClient(t, server, &bad, "reject")
					})
				}
			} else {
				runNativeServerWithClient(t, server, &bad, "reject")
			}
		})
	}
}

func TestShangMiMutualNativeClient(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	server, client := credentials(t, nil), clientCredentials(t, nil)
	testCertificateTime(t, server, client, false)
	run := func(t *testing.T, f fixture, accept bool, scenario string) {
		t.Helper()
		runNativeClientWithIdentity(t, f, &client, "localhost", accept, scenario)
	}
	alternate := clientCredentials(t, nil)
	memoryFixtures(t, server.caPath, client.certPath, client.keyPath, alternate.certPath, alternate.keyPath)
	for _, mode := range []string{"file", "pem", "der"} {
		for _, chooseSecond := range []bool{false, true} {
			t.Run(fmt.Sprintf("identity_set_%s_second_%t", mode, chooseSecond), func(t *testing.T) {
				if mode != "file" {
					t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
				}
				t.Setenv("SALTS_TEST_TLS_CLIENT_ALT_CERT", alternate.certPath)
				t.Setenv("SALTS_TEST_TLS_CLIENT_ALT_KEY", alternate.keyPath)
				expected := &client
				if chooseSecond {
					expected = &alternate
				}
				runNativeClientIdentities(t, server, &client, expected, "localhost", true, "client_ca")
			})
		}
	}
	t.Run("verified_mutual_client", func(t *testing.T) { run(t, server, true, "") })
	t.Run("certificate_signature_policy", func(t *testing.T) {
		t.Setenv("SALTS_TEST_TLS_SM2_CERT_POLICY", "1")
		run(t, server, true, "")
	})
	t.Run("verified_ip_identity", func(t *testing.T) { runNativeClientWithIdentity(t, server, &client, "127.0.0.1", true, "") })
	for _, identity := range []string{"wrong.example", "127.0.0.2"} {
		t.Run("reject_identity_"+identity, func(t *testing.T) { runNativeClientWithIdentity(t, server, &client, identity, false, "") })
	}
	t.Run("fragmented_server_flight", func(t *testing.T) { run(t, server, true, "fragmented") })
	for _, scenario := range []string{"malformed_ca", "malformed_ca_no_signature_match", "malformed_ca_early_reject", "malformed_ca_no_signature_match_early_reject", "request_context", "missing_signature", "duplicate_signature", "client_context", "certificate_id", "certificate_verify", "tlcp_signature", "finished"} {
		t.Run("reject_"+scenario, func(t *testing.T) { run(t, server, false, scenario) })
	}
	t.Run("reject_server_unknown_ca", func(t *testing.T) {
		bad := server
		bad.caPath = credentials(t, nil).caPath
		run(t, bad, false, "")
	})
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		},
		"future":          func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"key_usage":       func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"client_only_eku": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
	} {
		t.Run("reject_server_"+name, func(t *testing.T) {
			if name == "expired" || name == "future" {
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", name)
				t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
			}
			if name == "key_usage" || name == "client_only_eku" {
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "purpose")
				t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
			}
			bad := credentials(t, change)
			if name == "key_usage" || name == "client_only_eku" {
				memoryFixtures(t, bad.caPath)
				for _, mode := range []string{"file", "pem", "der"} {
					t.Run(mode, func(t *testing.T) {
						if mode != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						}
						run(t, bad, false, "")
					})
				}
			} else {
				run(t, bad, false, "")
			}
		})
	}
	t.Run("reject_server_certificate_signature", func(t *testing.T) { run(t, corruptCertificate(t, credentials(t, nil)), false, "") })
}

// Write independent DER fixtures; the native adapter consumes and then erases
// memory inputs before handshake progress.
func memoryFixtures(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var der []byte
		for len(data) != 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				t.Fatal("invalid fixture PEM")
			}
			der = append(der, block.Bytes...)
			data = rest
		}
		if err := os.WriteFile(path+".der", der, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func testCertificateTime(t *testing.T, server, client fixture, nativeServer bool) {
	t.Helper()
	for _, reason := range []string{"expired", "future"} {
		now := time.Now()
		fixed := now.Add(-30 * time.Minute)
		change := func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = now.Add(-45*time.Minute), now.Add(-15*time.Minute)
			if reason == "future" {
				c.NotBefore, c.NotAfter = now.Add(15*time.Minute), now.Add(45*time.Minute)
			}
		}
		if reason == "future" {
			fixed = now.Add(30 * time.Minute)
		}
		bad := credentials(t, change)
		if nativeServer {
			bad = clientCredentials(t, change)
		}
		memoryFixtures(t, server.caPath, server.certPath, server.keyPath, client.caPath, client.certPath, client.keyPath, bad.caPath, bad.certPath, bad.keyPath)
		for _, mode := range []string{"file", "pem", "der"} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("certificate_time/%s/%s/fixed_%t", reason, mode, explicit), func(t *testing.T) {
					if mode != "file" {
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
					}
					outcome := "reject"
					if explicit {
						outcome = "close"
						t.Setenv("SALTS_TEST_TLS_VERIFICATION_TIME", fmt.Sprint(fixed.Unix()))
					} else {
						t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
						t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "0")
					}
					if nativeServer {
						runNativeServerWithClient(t, server, &bad, outcome)
					} else {
						runNativeClientWithIdentity(t, bad, &client, "localhost", explicit, "")
					}
				})
			}
		}
	}
}
