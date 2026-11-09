#!/usr/bin/env python3
"""Independent Python ssl server for production CNet DNS and IP SAN verification.

Reuse one production native CNet executable and the original two CTests per
TLS version. Independent Python ssl servers present real DNS SAN and RFC 5280
binary iPAddress SAN certificates; IP literals never go into SNI.
"""
import argparse
import ctypes
from contextlib import contextmanager
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


@contextmanager
def temporary_current_user_intermediate_in_ca(pem: pathlib.Path):
    """Insert only this unique intermediate in the current user's CA store.

    The process never edits ROOT or machine-wide trust. The certificate
    context is deleted even when native TLS validation fails.
    """
    if sys.platform != "win32":
        raise RuntimeError("Windows CurrentUser CA store test on non-Windows")
    from ctypes import wintypes
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_der = x509.load_pem_x509_certificate(pem.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertOpenSystemStoreW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR,
    ]
    crypt32.CertOpenSystemStoreW.restype = ctypes.c_void_p
    crypt32.CertAddEncodedCertificateToStore.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ]
    crypt32.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
    crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
    crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    store = crypt32.CertOpenSystemStoreW(None, "CA")
    if not store:
        raise OSError(ctypes.get_last_error(), "open CurrentUser CA store")
    cert_context = ctypes.c_void_p()
    encoded = ctypes.create_string_buffer(cert_der)
    try:
        # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_STORE_ADD_NEW.
        if not crypt32.CertAddEncodedCertificateToStore(
            store, 0x00010001, ctypes.cast(encoded, ctypes.c_void_p),
            len(cert_der), 1, ctypes.byref(cert_context),
        ):
            raise OSError(ctypes.get_last_error(), "add test intermediate to CA")
        try:
            yield
        finally:
            if not crypt32.CertDeleteCertificateFromStore(cert_context):
                raise OSError(ctypes.get_last_error(), "remove test CA entry")
    finally:
        if not crypt32.CertCloseStore(store, 0):
            raise OSError(ctypes.get_last_error(), "close test CA store")


def ssl_context(cert: pathlib.Path, key: pathlib.Path, protocol: str):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ver = ssl.TLSVersion.TLSv1_2 if protocol == "tls12" else ssl.TLSVersion.TLSv1_3
    ctx.minimum_version = tls_ver
    ctx.maximum_version = tls_ver
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    # Both protocols must use the sole Crypto facade's actual P-256 group;
    # no opportunistic X25519/other curve fallback is counted as acceptance.
    ctx.set_ecdh_curve("prime256v1")
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    return ctx


def one_session(ctx, binary, protocol, identity, *, ip_ca=None, expect_success=None):
    ip_mode = ip_ca is not None
    positive = identity == "localhost" if expect_success is None else expect_success
    observed = {"accepted": False, "sni": None, "completed": False, "version": None,
                "closed": False, "failure": None}

    def on_sni(_conn, requested, _context):
        observed["sni"] = requested  # evidence only; never reject/select cert

    ctx.set_servername_callback(on_sni)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(14.0)
        port = listener.getsockname()[1]

        def serve():
            try:
                conn, _addr = listener.accept()
                observed["accepted"] = True
                conn.settimeout(12.0)
                with conn:
                    with ctx.wrap_socket(conn, server_side=True, suppress_ragged_eofs=False) as tls:
                        observed["completed"] = True
                        observed["version"] = tls.version()
                        # This is a real authenticated Finished and app-data
                        # barrier; a client CONNECTED callback alone can
                        # precede the peer seeing the final TLS1.3 Finished.
                        tls.sendall(b"ok")
                        tls.settimeout(3.0)
                        if positive:
                            if tls.recv(1) != b"F":
                                raise ssl.SSLError("missing native application request")
                            # Keep this success peer alive until CNet has
                            # observed BOTH its send and the authenticated
                            # reply, then initiates close_notify. recv EOF
                            # must be authenticated: ragged EOFs raise above.
                            if tls.recv(1) != b"":
                                raise ssl.SSLError("unexpected application data before close")
                            raw = tls.unwrap()
                            observed["closed"] = True
                            raw.close()
                        else:
                            try:
                                tls.recv(1)
                            except (socket.timeout, ssl.SSLError, OSError):
                                pass
            except (ssl.SSLError, socket.timeout, OSError) as exc:
                observed["failure"] = type(exc).__name__ + ": " + str(exc)

        thread = threading.Thread(target=serve, name="openssl-independent-peer")
        thread.start()
        try:
            native_args = (
                [str(binary), "--external-ip-san", str(port), protocol,
                 identity, str(ip_ca), "accept" if positive else "reject"]
                if ip_mode else
                [str(binary), "--external-san", str(port), protocol, identity]
            )
            result = subprocess.run(
                native_args, capture_output=True, text=True,
                timeout=25, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            result = None
            observed["failure"] = "client timeout: " + str(exc)
        thread.join(timeout=15)
        if thread.is_alive():
            print("FAIL independent OpenSSL peer did not terminate", file=sys.stderr)
            return False

    expected_version = "TLSv1.2" if protocol == "tls12" else "TLSv1.3"
    # RFC 6066 host_name SNI excludes address literals, while the public
    # CNet verified identity still must be exactly the requested IPv4/IPv6.
    expected_sni = None if ip_mode and identity in (
        "127.0.0.1", "127.0.0.2", "::1", "::2"
    ) else identity
    passed = (result is not None and result.returncode == 0
              and observed["accepted"] and observed["sni"] == expected_sni)
    if positive:
        passed = (passed and observed["completed"]
                  and observed["version"] == expected_version
                  and observed["closed"] and observed["failure"] is None)
    # A wrong-SAN negative may trigger an alert before the server completes
    # its own handshake; the *client* must reject after observing the valid
    # unrelated SAN. We never accept absent TCP/SNI as negative evidence.
    if not passed:
        print(f"FAIL protocol={protocol} identity={identity} peer={observed}",
              file=sys.stderr)
        if result is not None:
            print("CNet returncode:", result.returncode, file=sys.stderr)
            print("CNet stderr:", result.stderr[-3000:], file=sys.stderr)
    else:
        print(f"PASS {protocol} independent Python ssl server "
              f"identity={identity} SNI={expected_sni} "
              f"expected={'accept' if positive else 'reject'}")
    return passed


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--cert", type=pathlib.Path, required=True)
    parser.add_argument("--key", type=pathlib.Path, required=True)
    parser.add_argument("--protocol", choices=("tls12", "tls13"), required=True)
    args = parser.parse_args()
    for path in (args.binary, args.cert, args.key):
        if not path.is_file():
            parser.error("exact fixture/binary missing: " + str(path))
    return args


def main():
    args = parse_args()
    ctx = ssl_context(args.cert, args.key, args.protocol)
    # A matching DNS SAN positive check guards against accepting unrelated
    # protocol, signature, network, trust or cipher failures as SAN rejection.
    if not one_session(ctx, args.binary, args.protocol, "localhost"):
        return 1
    if not one_session(ctx, args.binary, args.protocol, "wrong.example"):
        return 1

    # Reuse the already-pinned, test-only X.509 fixture generator that the
    # production REQUIRED-mTLS native CTest uses. No second test TLS engine,
    # provider, client binary, workflow, installer or consumer is created.
    sys.path.insert(0, str(
        pathlib.Path(__file__).resolve().parents[3] / "crypto" / "tests" / "sdk"
    ))
    import python_mtls

    with tempfile.TemporaryDirectory(prefix="cnet-ip-san-") as temp:
        private = pathlib.Path(temp)
        private.chmod(0o700)
        fixtures = python_mtls.make_fixtures(
            private, include_ip_san=True,
            include_windows_ca_anchor=sys.platform == "win32",
        )
        ip_ctx = ssl_context(
            fixtures["server-ip"], fixtures["server-ip-key"], args.protocol
        )
        # Native CNet connects over IPv4 loopback in every case; reference
        # identity is independent from the TCP endpoint and MUST be checked
        # against DER iPAddress SAN, not CN/DNSName or reverse DNS.
        for identity, should_accept in (
            ("127.0.0.1", True),
            ("::1", True),
            ("127.0.0.2", False),
            ("::2", False),
        ):
            if not one_session(
                ip_ctx, args.binary, args.protocol, identity,
                ip_ca=fixtures["ca"], expect_success=should_accept
            ):
                return 1

        # Both CN and DNS SAN spell an IP literal; only iPAddress SAN can
        # authenticate an IP-literal reference identity.
        spoof_ctx = ssl_context(
            fixtures["server-ip-dns"], fixtures["server-ip-dns-key"],
            args.protocol,
        )
        if not one_session(
            spoof_ctx, args.binary, args.protocol, "127.0.0.1",
            ip_ca=fixtures["ca"], expect_success=False
        ):
            return 1

        if sys.platform == "win32":
            chain_ctx = ssl_context(
                fixtures["server-chain"], fixtures["server-chain-key"],
                args.protocol,
            )
            # Positive control: a leaf + intermediate signed by the
            # separately trusted root must authenticate. A failed fixture
            # cannot masquerade as a system-trust rejection.
            if not one_session(
                chain_ctx, args.binary, args.protocol, "localhost",
                ip_ca=fixtures["ca"], expect_success=True,
            ):
                return 1

            # Negative control: an otherwise valid intermediate present
            # ONLY in CurrentUser CA must never become an anchor. The native
            # CNet client intentionally uses its production system roots.
            with temporary_current_user_intermediate_in_ca(
                fixtures["intermediate"]
            ):
                if not one_session(
                    chain_ctx, args.binary, args.protocol, "localhost",
                    ip_ca="-", expect_success=False,
                ):
                    return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
