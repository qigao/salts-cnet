package tlcpinterop

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"os"
	"testing"
)

func TestTLCPCertificatePolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{"sm2", "rsa"} {
		var signer crypto.Signer
		if issuer == "rsa" {
			signer = key
		}
		f := credentialsWithIssuer(t, nil, signer)
		if err := os.WriteFile(f.caPath+".der", f.root.Raw, 0600); err != nil {
			t.Fatal(err)
		}
		for _, policy := range []string{"default", "sm2", "rsa", "tlcp-all"} {
			for _, memory := range []string{"file", "pem", "der"} {
				for _, includeIssuer := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/issuer_%t", issuer, policy, memory, includeIssuer), func(t *testing.T) {
						t.Setenv("SALTS_TEST_TLS_CLIENT_CERT_SIGNATURES", policy)
						if memory != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", memory)
						}
						peer := f
						if includeIssuer {
							peer.certificates = append([]tlcp.Certificate{}, f.certificates...)
							peer.certificates[0].Certificate = append(append([][]byte{}, f.certificates[0].Certificate...), f.root.Raw)
						}
						accept := issuer == policy || policy == "tlcp-all" || (policy == "default" && issuer == "sm2")
						runNativeClient(t, peer, "localhost", accept, []uint16{tlcp.ECC_SM4_GCM_SM3})
					})
				}
			}
		}
	}
}
