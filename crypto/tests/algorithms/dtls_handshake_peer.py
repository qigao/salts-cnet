"""Formal wire oracle for private DTLS preparation, not a network handshake."""
import argparse
import hashlib
import hmac
import datetime
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


def header(kind, sequence, size, offset, fragment):
    return bytes([kind]) + size.to_bytes(3, "big") + struct.pack("!H", sequence) + offset.to_bytes(3, "big") + fragment.to_bytes(3, "big")


def hello(cookie=b""):
    return b"\xfe\xfd" + bytes(range(32)) + b"\0" + bytes([len(cookie)]) + cookie + b"\0\x02\xc0\x2b\x01\0"


def packet(body, sequence):
    handshake = header(1, sequence, len(body), 0, len(body)) + body
    return b"\x16\xfe\xff\0\0" + bytes.fromhex("010203040506") + struct.pack("!H", len(handshake)) + handshake


def mac(issued, body):
    address = bytes.fromhex("047f00000101bb")
    framed = bytes([len(address)]) + len(body).to_bytes(3, "big")
    return hmac.new(bytes(range(32)), b"Salts DTLS1.2 cookie" + issued + framed + address + body, hashlib.sha256).digest()[:24]


def prf(secret, label, seed, size):
    combined = label + seed
    a = hmac.new(secret, combined, hashlib.sha256).digest()
    output = b""
    while len(output) < size:
        output += hmac.new(secret, a + combined, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return output[:size]


def secrets_fixture():
    # Synthetic message bodies, not a real ECDHE/certificate handshake.
    messages = [(1, 1, b"client hello"), (2, 1, b"server hello"), (11, 2, b"certificate"),
                (12, 3, b"key exchange"), (14, 4, b""), (16, 2, b"key")]
    canonical = b"".join(header(kind, sequence, len(body), 0, len(body)) + body
                         for kind, sequence, body in messages)
    session_hash = hashlib.sha256(canonical).digest()
    shared, client, server = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
    master = prf(shared, b"extended master secret", session_hash, 48)
    keys = prf(master, b"key expansion", server + client, 40)
    finished_hash = hashlib.sha256(canonical + header(15, 3, 5, 0, 5) + b"proof").digest()
    proofs = b"".join(prf(master, label, finished_hash, 12)
                      for label in (b"client finished", b"server finished"))
    return master, keys, finished_hash, proofs, prf(shared, b"oracle", client + server, 65)


def exchange_fixture(root):
    ephemeral = ec.derive_private_key(7, ec.SECP256R1())
    point = ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    params = b"\x03\x00\x17\x41" + point
    signed = bytes(range(32, 64)) + bytes(range(64, 96)) + params
    keys = (ec.derive_private_key(11, ec.SECP256R1()), rsa.generate_private_key(public_exponent=65537, key_size=2048))
    now = datetime.datetime.now(datetime.timezone.utc)
    for index, (kind, key) in enumerate(zip(("ec", "rsa"), keys)):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DTLS proof fixture " + kind)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(index+1).not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        (root / (kind + "-cert")).write_bytes(cert.public_bytes(serialization.Encoding.DER))
        (root / (kind + "-key")).write_bytes(key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if kind == "ec":
            signature, scheme = key.sign(signed, ec.ECDSA(hashes.SHA256())), b"\x04\x03"
        else:
            signature, scheme = key.sign(signed, padding.PKCS1v15(), hashes.SHA256()), b"\x04\x01"
        (root / (kind + "-exchange")).write_bytes(params + scheme + struct.pack("!H", len(signature)) + signature)
    return ephemeral


def verify_exchange(ephemeral, native):
    if len(native) != 378 or native[:65] == native[189:254]:
        raise AssertionError("invalid or reused ephemeral output")
    for index in range(2):
        result = native[index*189:(index+1)*189]
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), result[:65])
        shared = ephemeral.exchange(ec.ECDH(), public)
        master = prf(shared, b"extended master secret", b"\x11"*32, 48)
        keys = prf(master, b"key expansion", bytes(range(64, 96)) + bytes(range(32, 64)), 40)
        if not hmac.compare_digest(result[65:145], shared + master):
            raise AssertionError("independent P256 ECDH/EMS output differs")
        record = result[145:]
        if record[:13] != b"\x17\xfe\xfd\x00\x01" + bytes(6) + b"\x00\x1f":
            raise AssertionError("invalid ECDH-derived record header")
        aad = record[3:11] + record[:3] + struct.pack("!H", 7)
        opened = AESGCM(keys[:16]).decrypt(keys[32:36] + record[13:21], record[21:], aad)
        if opened != b"client!":
            raise AssertionError("ECDH-derived native record differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executables", nargs=5,
                        metavar="suite", help="handshake, secrets, exchange, client and server suite executables")
    args = parser.parse_args()
    first = packet(hello(), 0)
    issued = (100).to_bytes(8, "big")
    cookie = issued + mac(issued, hello())
    second = packet(hello(cookie), 1)
    body = bytes(i % 251 for i in range(4096))
    fragments = b"".join(header(11, 7, len(body), offset, size) + body[offset:offset+size]
                         for offset, size in [(2048, 2048), (0, 1024), (512, 2048)])
    with tempfile.TemporaryDirectory(prefix="salts-dtls-handshake-") as directory:
        root = Path(directory)
        (root / "first").write_bytes(first)
        (root / "second").write_bytes(second)
        (root / "fragments").write_bytes(fragments)
        master, keys, finished_hash, proofs, expansion = secrets_fixture()
        (root / "proofs").write_bytes(proofs)
        ephemeral = exchange_fixture(root)
        env = dict(os.environ, SALTS_DTLS_FIRST=str(root / "first"), SALTS_DTLS_SECOND=str(root / "second"),
                   SALTS_DTLS_REPLY=str(root / "reply"), SALTS_DTLS_FRAGMENTS=str(root / "fragments"),
                   SALTS_DTLS_CANONICAL=str(root / "canonical"), SALTS_DTLS_PROOFS=str(root / "proofs"),
                   SALTS_DTLS_SECRETS=str(root / "secrets"), SALTS_DTLS_EC_CERT=str(root / "ec-cert"),
                   SALTS_DTLS_EC_KEY=str(root / "ec-key"), SALTS_DTLS_RSA_KEY=str(root / "rsa-key"),
                   SALTS_DTLS_RSA_CERT=str(root / "rsa-cert"), SALTS_DTLS_EC_EXCHANGE=str(root / "ec-exchange"),
                   SALTS_DTLS_RSA_EXCHANGE=str(root / "rsa-exchange"), SALTS_DTLS_EXCHANGE_OUTPUT=str(root / "exchange-output"))
        for executable in args.executables:
            subprocess.run([executable], check=True, env=env, timeout=30)
        reply = (root / "reply").read_bytes()
        if len(reply) != 60 or len(reply) > len(first) or reply[5:11] != first[5:11]:
            raise AssertionError("invalid response length or mirrored record sequence")
        if reply[13:25] != header(3, 0, 35, 0, 35) or reply[25:28] != b"\xfe\xfd\x20":
            raise AssertionError("invalid HelloVerifyRequest")
        cookie = reply[28:]
        if int.from_bytes(cookie[:8], "big") != 200 or not hmac.compare_digest(cookie[8:], mac(cookie[:8], hello())):
            raise AssertionError("native cookie MAC differs")
        if (root / "canonical").read_bytes() != header(11, 7, len(body), 0, len(body)) + body:
            raise AssertionError("normalized handshake transcript differs")
        native = (root / "secrets").read_bytes()
        expected = master + finished_hash + proofs + expansion
        if len(native) != 257 or not hmac.compare_digest(native[:169], expected):
            raise AssertionError("EMS master, transcript, Finished or multi-block PRF differs")
        for index, plaintext in enumerate((b"client!", b"server!")):
            record = native[169 + 44*index:169 + 44*(index+1)]
            if record[:13] != b"\x17\xfe\xfd\x00\x01" + bytes(6) + b"\x00\x1f":
                raise AssertionError("invalid derived directional record header")
            aad = record[3:11] + record[:3] + struct.pack("!H", 7)
            nonce = keys[32+4*index:36+4*index] + record[13:21]
            opened = AESGCM(keys[16*index:16*(index+1)]).decrypt(nonce, record[21:], aad)
            if opened != plaintext:
                raise AssertionError("derived directional key/IV differs")
        verify_exchange(ephemeral, (root / "exchange-output").read_bytes())


if __name__ == "__main__":
    main()
