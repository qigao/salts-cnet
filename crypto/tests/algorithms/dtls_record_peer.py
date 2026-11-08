"""Formal private-record oracle; this does not exercise a DTLS handshake."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    key = bytes(range(16))
    salt = bytes.fromhex("a0a1a2a3")
    plaintext = b"independent DTLS record"
    sequence = struct.pack("!H", 1) + (17).to_bytes(6, "big")
    # RFC5288 does not require the receiver's explicit nonce to equal the record
    # sequence. The sequence is authenticated independently through the AAD.
    nonce_explicit = bytes.fromhex("9091929394959697")
    aad = sequence + b"\x17\xfe\xfd" + struct.pack("!H", len(plaintext))
    ciphertext = AESGCM(key).encrypt(salt + nonce_explicit, plaintext, aad)
    wire = b"\x17\xfe\xfd" + sequence + struct.pack("!H", 8 + len(ciphertext)) + nonce_explicit + ciphertext
    with tempfile.TemporaryDirectory(prefix="salts-dtls-record-") as directory:
        input_file, output_file = Path(directory) / "input.bin", Path(directory) / "output.bin"
        input_file.write_bytes(wire)
        env = dict(os.environ, SALTS_DTLS_RECORD_INPUT=str(input_file), SALTS_DTLS_RECORD_OUTPUT=str(output_file))
        subprocess.run([sys.argv[1]], env=env, check=True, timeout=30)
        record = output_file.read_bytes()
        if record[:3] != b"\x17\xfe\xfd" or record[3:5] != b"\0\1":
            raise AssertionError("invalid DTLS type/version/epoch")
        if record[5:11] != bytes(6) or int.from_bytes(record[11:13], "big") != len(record)-13:
            raise AssertionError("invalid DTLS sequence/record length")
        if record[13:21] != record[3:11]:
            raise AssertionError("sending nonce does not bind epoch/sequence")
        size = len(record)-37
        aad = record[3:11] + record[:3] + struct.pack("!H", size)
        opened = AESGCM(key).decrypt(salt + record[13:21], record[21:], aad)
        if opened != b"native DTLS record":
            raise AssertionError("native record plaintext differs")


if __name__ == "__main__":
    main()
