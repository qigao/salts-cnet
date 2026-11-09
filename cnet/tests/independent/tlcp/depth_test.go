package tlcpinterop

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"math/big"
	"os"
	"testing"
)

func tlcpDepthCredentials(t *testing.T, count int) fixture {
	return tlcpDepthCredentialsWithConstraints(t, count, nil, nil)
}
func tlcpDepthCredentialsWithConstraints(t *testing.T, count int, changeRoot func(*x509.Certificate), changeLeaf func(int, *x509.Certificate)) fixture {
	t.Helper()
	f := credentials(t, nil)
	root := f.root.ToX509()
	root.MaxPathLen = count
	root.MaxPathLenZero = false
	if changeRoot != nil {
		changeRoot(root)
	}
	der, err := smx509.CreateCertificate(rand.Reader, root, root, &f.rootKey.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.root, err = smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	parent, key := f.root, f.rootKey
	var issuers [][]byte
	for i := 0; i < count; i++ {
		next, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + i)), Subject: pkix.Name{CommonName: fmt.Sprintf("TLCP depth CA %d", i)},
			IsCA: true, BasicConstraintsValid: true, MaxPathLen: count - i - 1, MaxPathLenZero: i == count-1,
			NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		encoded, err := smx509.CreateCertificate(rand.Reader, template, parent.ToX509(), &next.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parent, err = smx509.ParseCertificate(encoded)
		if err != nil {
			t.Fatal(err)
		}
		key = next
		issuers = append(issuers, encoded)
	}
	var chain []byte
	for i := 0; i < 2; i++ {
		leaf, err := smx509.ParseCertificate(f.certificates[i].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		own := f.certificates[i].PrivateKey.(*sm2.PrivateKey)
		template := leaf.ToX509()
		if changeLeaf != nil {
			changeLeaf(i, template)
		}
		encoded, err := smx509.CreateCertificate(rand.Reader, template, parent.ToX509(), &own.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		f.certificates[i].Certificate = [][]byte{encoded}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})...)
	}
	for i := len(issuers) - 1; i >= 0; i-- {
		f.certificates[0].Certificate = append(f.certificates[0].Certificate, issuers[i])
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuers[i]})...)
	}
	if err := os.WriteFile(f.certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTLCPAnchorConstraints(t *testing.T) {
	for _, levels := range []int{0, 1} {
		for _, outside := range []int{-1, 0, 1, 2} {
			t.Run(fmt.Sprintf("issuers_%d/outside_%d", levels, outside), func(t *testing.T) {
				f := tlcpDepthCredentialsWithConstraints(t, levels, func(root *x509.Certificate) {
					root.PermittedDNSDomainsCritical = true
					root.PermittedDNSDomains = []string{"localhost"}
				}, func(role int, leaf *x509.Certificate) {
					if role == outside || outside == 2 {
						leaf.DNSNames = []string{"localhost", "outside.example"}
					}
				})
				if outside >= 0 {
					reason := "constraints"
					if outside < 2 {
						reason = "certificate"
					} // unequal SANs violate the TLCP entity-pair contract first
					t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", reason)
				}
				runNativeClient(t, f, "localhost", outside < 0, []uint16{tlcp.ECC_SM4_GCM_SM3})
			})
		}
	}
}
func TestTLCPDepthPositions(t *testing.T) {
	for _, count := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := tlcpDepthCredentials(t, count)
			if count > 1 {
				t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "depth")
				t.Setenv("SALTS_TEST_TLS_VALIDITY_INDEX", "3")
			}
			runNativeClient(t, f, "localhost", count == 1, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
	}
}
