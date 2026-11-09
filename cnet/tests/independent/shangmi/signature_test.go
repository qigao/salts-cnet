package shangmiinterop

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

func testSignaturePolicy(t *testing.T) {
	for _, profile := range []struct {
		name              string
		id, version, mode int
	}{
		{"tls12", 0, 12, 1}, {"tls13", 0, 13, 1}, {"shangmi", 1, 0, 3},
	} {
		t.Run(profile.name, func(t *testing.T) {
			server := depthFixture(t, profile.id == 1, false, 1, false)
			client := depthFixture(t, profile.id == 1, true, 1, false)
			if profile.id == 0 {
				topSignedByP384 := depthFixture(t, false, true, 0, false, true)
				for _, memory := range []string{"file", "pem", "der"} {
					t.Run("client_issuer_"+memory, func(t *testing.T) {
						if memory != "file" {
							t.Setenv("SALTS_TEST_TLS_MEMORY", memory)
						}
						signatureCase(t, server, topSignedByP384, 0, profile.version, [2]int{0, 4}, "accept")
						signatureCase(t, server, topSignedByP384, 0, profile.version, [2]int{0, 1}, "reject-server")
					})
				}
			}
			for _, memory := range []string{"file", "pem", "der"} {
				t.Run(memory, func(t *testing.T) {
					if memory != "file" {
						t.Setenv("SALTS_TEST_TLS_MEMORY", memory)
					}
					scenarios := [][2]int{{profile.mode, 0}, {0, profile.mode}, {profile.mode, profile.mode}}
					if profile.id == 0 {
						scenarios = append(scenarios, [2]int{2, 1}, [2]int{1, 2})
					}
					for _, modes := range scenarios {
						outcome := "accept"
						if modes[0] == 2 || modes[1] == 2 {
							outcome = "reject-server"
						}
						signatureCase(t, server, client, profile.id, profile.version, modes, outcome)
					}
				})
			}
		})
	}
}

func signatureCase(t *testing.T, server, client fixture, profile, version int, modes [2]int, outcome string) {
	t.Helper()
	args := []string{"--signature-mtls", server.caPath, client.caPath, server.certPath, server.keyPath,
		client.certPath, client.keyPath, outcome, fmt.Sprintf("%x", sha256.Sum256(server.leaf.Raw)),
		fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw)), fmt.Sprintf("%x", sm3.Sum(server.leaf.Raw)),
		fmt.Sprint(profile), fmt.Sprint(version), fmt.Sprint(modes[0]), fmt.Sprint(modes[1])}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, *native, args...).CombinedOutput(); err != nil {
		t.Fatalf("signature modes %v: %v\n%s", modes, err, out)
	}
}

func testSeparateCertificatePolicy(t *testing.T) {
	server := depthFixture(t, false, false, 0, false, true)
	client := depthFixture(t, false, true, 0, false, true)
	clientP256 := depthFixture(t, false, true, 0, false)
	for _, version := range []int{12, 0, 13} {
		for _, mode := range []string{"file", "pem", "der"} {
			for _, scenario := range []string{"accept", "reject_remote_server", "reject_remote_client", "no_local_identity", "shared_request_constraint"} {
				t.Run(fmt.Sprintf("version_%d/%s/%s", version, mode, scenario), func(t *testing.T) {
					if mode != "file" {
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
					}
					t.Setenv("SALTS_TEST_TLS_CLIENT_CERT_SIGNATURES", "p384")
					t.Setenv("SALTS_TEST_TLS_SERVER_CERT_SIGNATURES", "p384")
					selected, outcome := client, "accept"
					modes := [2]int{1, 4}
					switch scenario {
					case "reject_remote_server":
						t.Setenv("SALTS_TEST_TLS_CLIENT_CERT_SIGNATURES", "p256")
						outcome = "reject-client"
					case "reject_remote_client":
						t.Setenv("SALTS_TEST_TLS_CLIENT_CERT_SIGNATURES", "all")
						selected, outcome = clientP256, "reject-server"
					case "no_local_identity":
						selected, outcome = clientP256, "reject-server"
					case "shared_request_constraint":
						modes[1] = 1
						if version == 12 {
							outcome = "reject-server"
						}
					}
					// TLS1.2 CertificateRequest's one list must also permit the
					// P384 certificate issuer; the client still signs with P256.
					signatureCase(t, server, selected, 0, version, modes, outcome)
				})
			}
		}
	}
}
