package tls_test

import (
	"syscall"
	"testing"
	"unsafe"
)

func withIntermediateStore(t *testing.T, der []byte, run func()) {
	t.Helper()
	dll := syscall.NewLazyDLL("crypt32.dll")
	open := dll.NewProc("CertOpenSystemStoreW")
	add := dll.NewProc("CertAddEncodedCertificateToStore")
	remove := dll.NewProc("CertDeleteCertificateFromStore")
	closeStore := dll.NewProc("CertCloseStore")
	name, err := syscall.UTF16PtrFromString("CA")
	if err != nil {
		t.Fatal(err)
	}
	store, _, err := open.Call(0, uintptr(unsafe.Pointer(name)))
	if store == 0 {
		t.Fatal(err)
	}
	defer func() {
		if ok, _, err := closeStore.Call(store, 0); ok == 0 {
			t.Error(err)
		}
	}()
	var cert uintptr
	if ok, _, err := add.Call(store, 0x10001, uintptr(unsafe.Pointer(&der[0])), uintptr(len(der)), 1, uintptr(unsafe.Pointer(&cert))); ok == 0 {
		t.Fatal(err)
	}
	defer func() {
		if ok, _, err := remove.Call(cert); ok == 0 {
			t.Error(err)
		}
	}()
	run()
}

func TestSystemIntermediateTrust(t *testing.T) {
	f := makePeerFixtures(t)
	for _, proto := range []string{"tls12", "tls13"} {
		t.Run(proto, func(t *testing.T) {
			sanSession(t, *native, proto, "localhost", f.root.certPath, f.identities["server-chain"].tls, true)
			withIntermediateStore(t, f.intermediate.cert.Raw, func() { sanSession(t, *native, proto, "localhost", "-", f.identities["server-chain"].tls, false) })
		})
	}
}
