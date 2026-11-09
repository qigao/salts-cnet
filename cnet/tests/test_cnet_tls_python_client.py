#!/usr/bin/env python3
"""Real Python ssl client to the one production CNet NativeIO TLS server.

Every positive TLS1.2/TLS1.3 case requires complete mutual authentication,
a strict negotiated version, authenticated bidirectional application bytes
and a verified client certificate on the native server. Negative cases must
produce a server-side handshake failure without an authenticated connection.
Test credentials live only inside a private temporary directory.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import hashlib
import socket
import ssl
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import sys
import tempfile
import time


CASES = ("client", "missing", "wrongca", "eku", "expired", "chain", "badsig")
VERSION = {"12": "TLSv1.2", "13": "TLSv1.3"}


def wait_for_native_send(native: subprocess.Popen, port_path: Path) -> None:
    """Wait for the genuine CNet SEND callback before changing TLS phase.

    A received G byte proves wire delivery, not the native SEND event.
    This deterministic boundary separates the negative peer-close test from
    the independently tracked SEND-vs-EOF ownership race.
    """
    marker = Path(str(port_path) + ".sent")
    deadline = time.monotonic() + 4.0
    while not marker.exists():
        if native.poll() is not None:
            raise AssertionError("native CNet exited before SEND acknowledgement")
        if time.monotonic() >= deadline:
            raise AssertionError("native CNet did not publish SEND acknowledgement")
        time.sleep(0.005)


def rejected_close_exchange(
    ctx, raw, proto: str, mode: str, native: subprocess.Popen, port_path: Path
) -> None:
    """Authenticated exchange followed by an invalid TLS shutdown.

    MemoryBIO retains the actual OpenSSL record encryption, so corrupting or
    truncating unwrap's output tests a real encrypted close_notify record.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    peer = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")

    def flush() -> None:
        while outgoing.pending:
            raw.sendall(outgoing.read())

    def receive() -> None:
        wire = raw.recv(16384)
        if not wire:
            raise AssertionError("native closed before authenticated exchange")
        incoming.write(wire)

    while True:
        try:
            peer.do_handshake()
            flush()
            break
        except ssl.SSLWantReadError:
            flush()
            receive()
    if peer.version() != VERSION[proto] or not peer.getpeercert():
        raise AssertionError("negative-close peer must authenticate first")
    if peer.write(b"F") != 1:
        raise AssertionError("missing authenticated request")
    flush()
    while True:
        try:
            if peer.read(1) != b"G":
                raise AssertionError("missing authenticated response")
            break
        except ssl.SSLWantReadError:
            receive()

    if mode not in ("race-eof", "race-eof-pending"):
        wait_for_native_send(native, port_path)

    if mode in ("truncated", "badalert"):
        try:
            peer.unwrap()
        except ssl.SSLWantReadError:
            pass
        alert = bytearray(outgoing.read())
        if len(alert) <= 5:
            raise AssertionError("OpenSSL did not encrypt close_notify")
        if mode == "truncated":
            del alert[-1]
        else:
            alert[-1] ^= 1  # Invalid MAC/AEAD tag, never authenticated consent.
        raw.sendall(alert)
    elif mode == "fatal":
        # Make OpenSSL emit a genuine encrypted fatal bad_record_mac alert
        # under the negotiated client keys; no plaintext alert injection.
        incoming.write(b"\x17\x03\x03\x00\x20" + bytes(32))
        try:
            peer.read(1)
        except ssl.SSLError as exc:
            if isinstance(exc, (ssl.SSLWantReadError, ssl.SSLWantWriteError)):
                raise AssertionError("invalid record did not generate a fatal alert") from exc
        else:
            raise AssertionError("OpenSSL accepted the unauthenticated record")
        if not outgoing.pending:
            raise AssertionError("OpenSSL did not generate encrypted fatal alert")
        flush()
    elif mode not in ("eof", "race-eof", "race-eof-pending"):
        raise AssertionError(f"unknown shutdown failure: {mode}")
    # Preserve the read half so CNet must retire its own NativeIO requests
    # and close within the existing socket deadline. EOF is never success.
    raw.shutdown(socket.SHUT_WR)
    try:
        while raw.recv(16384):
            pass
    except ConnectionResetError:
        pass


def fragmented_tls13_exchange(
    ctx: ssl.SSLContext, raw: socket.socket, *, coalesced: bool = False
) -> None:
    """Actual SSLObject TLS1.3 Finished + first ApplicationData transition.

    Preserve the existing TCP-fragmented case and separately admit their
    complete encrypted records in one socket send. Neither case exposes
    plaintext records or TLS secrets; both use one native production CNet.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    peer = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def flush_ciphertext(*, whole_batch: bool = False) -> None:
        while outgoing.pending:
            wire = outgoing.read()
            if whole_batch:
                # A single real TLS1.3 encrypted Finished+ApplicationData
                # batch, with no Python side timing delay or fake record.
                raw.sendall(wire)
                continue
            offset = 0
            # Preserve the original bounded TCP fragmentation acceptance.
            for n in (1, 2, 7, 31, 127):
                if offset >= len(wire):
                    break
                step = min(n, len(wire) - offset)
                raw.sendall(wire[offset:offset + step])
                offset += step
                time.sleep(0.001)
            if offset < len(wire):
                raw.sendall(wire[offset:])

    def receive_ciphertext(phase: str) -> None:
        wire = raw.recv(16384)
        if not wire:
            raise AssertionError(f"server closed during {phase}")
        incoming.write(wire)

    # Do not permit a second handshake or a version/security fallback.
    while True:
        try:
            peer.do_handshake()
            break
        except ssl.SSLWantWriteError:
            flush_ciphertext()
        except ssl.SSLWantReadError:
            flush_ciphertext()
            receive_ciphertext("TLS1.3 handshake")

    if peer.version() != "TLSv1.3":
        raise AssertionError(f"fragmented peer negotiated {peer.version()!r}")
    if not peer.getpeercert():
        raise AssertionError("Python TLS1.3 peer did not verify server certificate")
    # MemoryBIO must contain the encrypted client Finished from handshake.
    # The application record is then added before EITHER is sent on TCP.
    finished_bytes = outgoing.pending
    if finished_bytes == 0:
        raise AssertionError("TLS1.3 Finished already flushed; coalescing test invalid")
    if peer.write(b"F") != 1 or outgoing.pending <= finished_bytes:
        raise AssertionError("Python SSLObject did not queue app data after Finished")
    flush_ciphertext(whole_batch=coalesced)

    while True:
        try:
            response = peer.read(1)
            if response != b"G":
                raise AssertionError(f"fragmented mTLS response missing: {response!r}")
            return
        except ssl.SSLWantWriteError:
            flush_ciphertext()
        except ssl.SSLWantReadError:
            flush_ciphertext()
            receive_ciphertext("TLS1.3 authenticated response")


def scenario(
    binary: Path, work: Path, crypto, fixtures, proto: str, case: str,
    *, fragmented: bool = False, idle: bool = False,
    orderly_close: bool = False, gated: bool = False,
    coalesced: bool = False, local_close: bool = False,
    send_close: bool = False, rejected_close: str = "",
) -> None:
    if (idle or gated or coalesced or fragmented) and (
        proto != "13" or case != "client" or
        sum((idle, orderly_close, gated, coalesced, fragmented,
             local_close, send_close)) != 1
    ):
        raise AssertionError("special TLS1.3 cases require distinct real client credentials")
    if (orderly_close or local_close or send_close or rejected_close) and (
        case != "client" or
        sum((idle, orderly_close, gated, coalesced, fragmented,
             local_close, send_close, bool(rejected_close))) != 1
    ):
        raise AssertionError("close cases require distinct authenticated credentials")
    expected = (
        rejected_close if rejected_close else
        "sendclose" if send_close else
        "localclose" if local_close else
        "gated" if gated else
        "close" if orderly_close else
        "idle" if idle else
        "accept" if case == "client" else "reject"
    )
    if fragmented and (proto != "13" or case != "client"):
        raise AssertionError("fragmented ciphertext gate is valid TLS1.3 only")
    suffix = (
        f"-{rejected_close}" if rejected_close else
        "-sendclose" if send_close else
        "-localclose" if local_close else
        "-gated" if gated else
        "-close" if orderly_close else
        "-idle" if idle else
        "-coalesced" if coalesced else
        "-fragmented" if fragmented else ""
    )
    port_path = work / f"native-{proto}-{case}{suffix}.port"
    ready_path = Path(str(port_path) + ".ready")
    if port_path.exists():
        raise AssertionError("stale private port marker")
    # Exact-head Python fixture generator and standard-library ssl client.
    # Context creation errors never count as native handshake rejections.
    ctx = crypto.python_tls_context("client", proto, fixtures, case)
    expected_digest = "-"
    if case == "client":
        certificate = x509.load_pem_x509_certificate(fixtures["client"].read_bytes())
        expected_digest = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
    # Certificate rejection can emit more than a Windows pipe buffer.
    # An unread PIPE blocks the native TLS owner before it can send its
    # fatal alert; waiting for the peer first creates a false IOCP hang.
    # Private temporary files collect diagnostics without transport backpressure.
    native_out = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    native_err = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    try:
        native = subprocess.Popen(
            [str(binary), "--python-ssl-client", str(port_path),
             str(fixtures["ca"]), str(fixtures["server"]),
             str(fixtures["server-key"]), proto, expected, expected_digest],
            stdout=native_out, stderr=native_err,
        )
    except BaseException:
        native_out.close()
        native_err.close()
        raise
    failure = None
    phase = "await-native-listen"
    peer_rejected = False
    peer_completed = False
    try:
        deadline = time.monotonic() + 12.0
        while True:
            # fopen creates the marker before fprintf/fclose publishes its
            # contents. Wait for the complete line, within the same deadline.
            port_text = port_path.read_text(encoding="ascii") if port_path.exists() else ""
            if port_text.endswith("\n"):
                break
            if native.poll() is not None:
                raise AssertionError("native CNet server terminated before bind")
            if time.monotonic() >= deadline:
                raise AssertionError("native CNet server did not bind within deadline")
            time.sleep(0.02)
        port = int(port_text.strip())
        if not 0 < port < 65536:
            raise AssertionError("native listener port invalid")
        phase = "tcp-connect"
        with socket.create_connection(("127.0.0.1", port), timeout=8.0) as raw:
            raw.settimeout(9.0)
            try:
                if rejected_close:
                    phase = f"authenticated-rejected-close-{rejected_close}"
                    rejected_close_exchange(
                        ctx, raw, proto, rejected_close, native, port_path
                    )
                    peer_completed = True
                elif fragmented or coalesced:
                    phase = (
                        "tls13-coalesced-finished-plus-application"
                        if coalesced else
                        "tls13-fragmented-finished-plus-application"
                    )
                    fragmented_tls13_exchange(ctx, raw, coalesced=coalesced)
                    # Peer receipt of G can precede the native SEND callback.
                    # Preserve the same completion boundary as ordinary accept
                    # before this successful framing case closes its socket.
                    wait_for_native_send(native, port_path)
                    peer_completed = True
                    phase = "authenticated"
                else:
                    phase = "tls-handshake"
                    with ctx.wrap_socket(raw, server_hostname="localhost") as peer:
                        peer.settimeout(9.0)
                        phase = "negotiated-version"
                        if peer.version() != VERSION[proto]:
                            raise AssertionError("Python negotiated a different TLS version")
                        if idle:
                            # Remain connected and intentionally send zero
                            # application bytes. Native CNet MUST establish
                            # mTLS and then publish its own READ timeout.
                            # Socket closure alone is not sufficient: the
                            # native process verifies status and read stage.
                            phase = "authenticated-idle-read-timeout"
                            response = peer.recv(1)
                            if response:
                                raise AssertionError(
                                    f"idle TLS13 peer received unexpected data: {response!r}"
                                )
                            peer_completed = True
                        else:
                            # Compare the independently negotiated TLS1.3
                            # client Finished against an already-admitted
                            # NativeIO TLS_READ on the real CNet server.
                            # Merely receiving CONNECTED on the client does
                            # not prove the native Owner armed application
                            # receive demand, so wait for its private marker.
                            if gated:
                                phase = "native-receive-admission"
                                ready_deadline = time.monotonic() + 5.0
                                while not ready_path.exists():
                                    if native.poll() is not None:
                                        raise AssertionError(
                                            "native TLS owner exited before receive admission"
                                        )
                                    if time.monotonic() >= ready_deadline:
                                        raise AssertionError(
                                            "native TLS receive admission never published"
                                        )
                                    time.sleep(0.005)
                            phase = "authenticated-request"
                            peer.sendall(b"F")
                            phase = "authenticated-response"
                            response = peer.recv(1)
                            if expected in ("accept", "close", "gated",
                                            "localclose", "sendclose"):
                                if response != b"G":
                                    raise AssertionError(f"valid mTLS app data missing: {response!r}")
                                if orderly_close or local_close or send_close:
                                    if local_close:
                                        # Deterministic admission ordering:
                                        # CNet must accept its own close
                                        # command before the Python peer
                                        # sends reciprocal close_notify.
                                        # Actual NativeIO cancel completion
                                        # remains asynchronous and may
                                        # overlap the peer's TLS shutdown.
                                        phase = "native-local-close-admission"
                                        close_marker = Path(
                                            str(port_path) + ".localclose"
                                        )
                                        close_deadline = time.monotonic() + 4.0
                                        while not close_marker.exists():
                                            if native.poll() is not None:
                                                raise AssertionError(
                                                    "native exited before local close admission"
                                                )
                                            if time.monotonic() >= close_deadline:
                                                raise AssertionError(
                                                    "native TLS close was not admitted"
                                                )
                                            time.sleep(0.005)
                                    # A real TLS1.3 close_notify exchange,
                                    # not EOF or a socket-only shutdown.
                                    phase = "authenticated-close-notify"
                                    peer.unwrap()
                                    phase = "authenticated-close-complete"
                                else:
                                    if expected == "accept":
                                        phase = "native-send-acknowledgement"
                                        wait_for_native_send(native, port_path)
                                    phase = "authenticated"
                                peer_completed = True
                            elif response == b"G":
                                raise AssertionError("invalid mTLS client received authenticated data")
                            else:
                                peer_rejected = True
            except (ssl.SSLError, ConnectionError, EOFError):
                if rejected_close:
                    raise
                if expected in ("accept", "close", "gated", "localclose",
                                "sendclose"):
                    raise
                if idle:
                    # Native's exact READ-stage timeout assertion below is
                    # authoritative; SSL's EOF behavior varies by platform.
                    peer_completed = True
                else:
                    peer_rejected = True
        if expected == "reject" and not peer_rejected:
            raise AssertionError("invalid client was not rejected")
        if (rejected_close or expected in ("accept", "idle", "close", "gated",
                        "localclose", "sendclose")) and not peer_completed:
            raise AssertionError("authenticated peer did not reach required terminal")
    except (socket.timeout, TimeoutError) as exc:
        failure = f"deadline exceeded during {phase}: {type(exc).__name__}"
    except Exception as exc:
        failure = f"{type(exc).__name__} during {phase}: {str(exc)[:300]}"
    finally:
        try:
            native.wait(timeout=12)
        except subprocess.TimeoutExpired:
            native.kill()
            native.wait()
            failure = failure or "native server retained live owner past deadline"
        native_out.seek(0)
        native_err.seek(0)
        out, err = native_out.read(), native_err.read()
        native_out.close()
        native_err.close()
    if failure is not None or native.returncode != 0 or (
        f"PASS production NativeIO CNet server / TLS{proto} / {expected}" not in out
    ):
        diagnostic = "\n".join(
            line for line in err.splitlines()
            if line.startswith(("CNET_", "TLS_EOF_ORDER", "CNet TLS case"))
        )
        raise AssertionError(
            f"TLS{proto} {case} failed at {phase}: {failure or ''} "
            f"native_exit={native.returncode} "
            f"stdout={out[-350:]} stderr={diagnostic[-1200:]} "
            + crypto.safe_native_diagnostic(err.encode("utf-8"))
        )
    print(
        f"PASS independent Python ssl TLS{proto} {case} {expected}"
        + (" Finished+ApplicationData fragmented" if fragmented else
           " Finished+ApplicationData coalesced" if coalesced else "")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture-generator", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or not args.fixture_generator.is_file():
        parser.error("one native CNet executable and exact Python fixture source are required")
    sys.path.insert(0, str(args.fixture_generator.parent))
    import python_mtls

    args.work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cnet-python-peer-", dir=args.work) as temp:
        private = Path(temp)
        private.chmod(0o700)
        fixtures = python_mtls.make_fixtures(private)
        for proto in ("12", "13"):
            for mode in ("race-eof", "race-eof-pending", "eof", "truncated", "badalert", "fatal"):
                scenario(args.binary, private, python_mtls, fixtures, proto,
                         "client", rejected_close=mode)
            for close_mode in ("orderly_close", "local_close", "send_close"):
                scenario(args.binary, private, python_mtls, fixtures, proto,
                         "client", **{close_mode: True})
            if proto == "13":
                # Qualify the retained NativeIO TLS_READ separately before
                # the historically intermittent immediate-send case, and
                # ensure close_notify evidence is not skipped when that case
                # later reveals an unrelated scheduling RED.
                scenario(
                    args.binary, private, python_mtls, fixtures, "13", "client",
                    gated=True,
                )
                # Before the immediate-send case, force the real encrypted
                # ClientFinished+ApplicationData to arrive in a single
                # socket write. Compare its verdict to the separately gated
                # and fragmented modes without adding a new CTest.
                scenario(
                    args.binary, private, python_mtls, fixtures, "13", "client",
                    coalesced=True,
                )
            for case in CASES:
                scenario(args.binary, private, python_mtls, fixtures, proto, case)
        # A single additional real TLS1.3 connection, not a retry/stress
        # loop, fixes wire segmentation deterministically in the same CTest.
        scenario(
            args.binary, private, python_mtls, fixtures, "13", "client",
            fragmented=True,
        )
        # One real idle, mutually authenticated TLS1.3 client. CNet's
        # read_timeout_ms, not Python's socket EOF, must terminate the
        # native owner on its documented post-handshake READ stage.
        scenario(
            args.binary, private, python_mtls, fixtures, "13", "client",
            idle=True,
        )
    print("PASS Python ssl client -> one production CNet REQUIRED-mTLS server on both TLS versions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
