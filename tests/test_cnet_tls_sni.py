"""Independent authenticated TLS clients exercise immutable CNet SNI identities."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from test_cnet_tls_python_client import wait_for_native_send


def exchange(ctx, raw, hostname, expected_der, native, port_file):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    peer = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)
    first = True

    def flush():
        nonlocal first
        while outgoing.pending:
            wire = outgoing.read()
            if first:
                # Split ClientHello transport delivery across record/header fields.
                offset = 0
                for size in (1, 2, 3, 5, 8, 13):
                    raw.sendall(wire[offset:offset + size])
                    offset += size
                raw.sendall(wire[offset:])
                first = False
            else:
                raw.sendall(wire)

    def receive():
        wire = raw.recv(16384)
        if not wire:
            raise EOFError("native TLS stream closed")
        incoming.write(wire)

    while True:
        try:
            peer.do_handshake()
            flush()
            break
        except ssl.SSLWantReadError:
            flush()
            receive()
    if expected_der is None:
        raise AssertionError("unmatched SNI reached authenticated handshake")
    if peer.getpeercert(binary_form=True) != expected_der:
        raise AssertionError("server selected a different identity")
    if peer.write(b"F") != 1:
        raise AssertionError("application write failed")
    flush()
    while True:
        try:
            if peer.read(1) != b"G":
                raise AssertionError("authenticated response missing")
            break
        except ssl.SSLWantReadError:
            flush()
            receive()
    wait_for_native_send(native, port_file)


def scenario(binary, work, certs, proto, mode, hostname, expected_label, index, primary="first"):
    expected_der = certs[expected_label][1] if expected_label else None
    outcome = "accept" if expected_der else "reject"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = (
        ssl.TLSVersion.TLSv1_2 if proto == "12" else ssl.TLSVersion.TLSv1_3)
    ctx.load_verify_locations(str(work / "ca.pem"))
    ctx.load_cert_chain(str(work / "client.pem"), str(work / "client-key.pem"))
    ctx.check_hostname = hostname is not None
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    # Use the same explicit P-256 profile as the existing independent peer.
    ctx.set_ecdh_curve("prime256v1")
    port_file = work / f"sni-{index}.port"
    env = os.environ.copy()
    env["SALTS_TEST_TLS_ALT_CERT"] = str(work / "second.pem")
    env["SALTS_TEST_TLS_ALT_KEY"] = str(work / "second-key.pem")
    env.pop("SALTS_TEST_TLS_ENCRYPTED", None)
    env.pop("SALTS_TEST_TLS_MEMORY", None)
    if mode != "file":
        env["SALTS_TEST_TLS_MEMORY"] = mode
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as out, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as err:
        native = subprocess.Popen([str(binary), "--python-ssl-client", str(port_file),
            str(work / "ca.pem"), str(work / f"{primary}.pem"), str(work / f"{primary}-key.pem"),
            proto, outcome, hashlib.sha256(certs["client"][1]).hexdigest()],
            env=env, stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 12
            while True:
                port = port_file.read_text() if port_file.exists() else ""
                if port.endswith("\n"):
                    break
                if native.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("native identity initialization/listen failed")
                time.sleep(0.01)
            with socket.create_connection(("127.0.0.1", int(port)), timeout=8) as raw:
                raw.settimeout(8)
                try:
                    exchange(ctx, raw, hostname, expected_der, native, port_file)
                except (ssl.SSLError, EOFError, ConnectionError):
                    if expected_der:
                        raise
            native.wait(timeout=12)
            out.seek(0)
            if native.returncode or f"PASS production NativeIO CNet server / TLS{proto} / {outcome}" not in out.read():
                raise AssertionError("native authentication/owner cleanup assertions failed")
        except BaseException:
            if native.poll() is None:
                native.kill()
                native.wait()
            err.seek(0)
            # Existing peer helper filters provider diagnostics; never print keys.
            import python_mtls
            print(python_mtls.safe_native_diagnostic(err.read().encode()), file=sys.stderr)
            raise
    print(f"PASS SNI TLS{proto} {mode} primary={primary} {hostname!r} -> {expected_label or 'rejected'}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture-generator", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.fixture_generator.parent))
    import python_mtls as crypto
    args.work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sni-", dir=args.work) as tmp:
        work = Path(tmp)
        work.chmod(0o700)
        root_key = crypto.rsa_identity()
        issuer = crypto.identity_name("SNI root")
        root = crypto.cert("SNI root", root_key.public_key(), issuer, root_key, ca=True)
        (work / "ca.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
        (work / "ca.pem.der").write_bytes(root.public_bytes(serialization.Encoding.DER))
        certs = {}
        for name, dns in (("first", ("alpha.test",)),
                          ("second", ("beta.test", "alias.test", "*.wild.test")),
                          ("ecdsa", ("beta.test",)),
                          ("client", None)):
            key = ec.generate_private_key(ec.SECP256R1()) if name == "ecdsa" else crypto.rsa_identity()
            certificate = crypto.cert("cn-only.test", key.public_key(), issuer, root_key,
                eku=ExtendedKeyUsageOID.CLIENT_AUTH if name == "client" else ExtendedKeyUsageOID.SERVER_AUTH,
                server_dns_names=dns)
            der = certificate.public_bytes(serialization.Encoding.DER)
            certs[name] = (certificate, der)
            (work / f"{name}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            (work / f"{name}.pem.der").write_bytes(der)
            for encoding, suffix in ((serialization.Encoding.PEM, ""), (serialization.Encoding.DER, ".der")):
                (work / f"{name}-key.pem{suffix}").write_bytes(key.private_bytes(
                    encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        index = 0
        for proto in ("12", "13"):
            for mode in ("file", "pem", "der"):
                for hostname, selected in (("alpha.test", "first"), ("beta.test", "second"),
                        ("ALIAS.TEST", "second"), ("one.wild.test", "second"),
                        (None, "first"), ("unknown.test", None), ("cn-only.test", None),
                        ("wild.test", None), ("two.one.wild.test", None)):
                    scenario(args.binary, work, certs, proto, mode, hostname, selected, index)
                    index += 1
                # The first identity matches the name but cannot satisfy the
                # server's RSA signature policy. Select the compatible second.
                for hostname in ("beta.test", None):
                    scenario(args.binary, work, certs, proto, mode, hostname, "second", index, "ecdsa")
                    index += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
