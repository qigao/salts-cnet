#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Original CNet Owner + NativeIO over sole static Crypto REQUIRED-mTLS gate.

No OpenSSL CLI, test C program linked to OpenSSL, fixture copies, provider
fallback, CNet replacement DSO or published production switch. Reuse the
exact-head Crypto Python test fixture generator instead of inventing a
second certificate generation algorithm or keeping test private keys.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--crypto-python-fixtures", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or not args.crypto_python_fixtures.is_file():
        parser.error("exact CNet executable and Crypto fixture source are required")
    sys.path.insert(0, str(args.crypto_python_fixtures.parent))
    import python_mtls  # imported only from explicit, exact-head Crypto source

    args.work.mkdir(parents=True, exist_ok=True)
    cases = ("client", "missing", "wrongca", "eku", "expired", "chain", "badsig")
    with tempfile.TemporaryDirectory(prefix="cnet-mtls-", dir=args.work) as name:
        folder = Path(name)
        folder.chmod(0o700)
        fixtures = python_mtls.make_fixtures(folder)
        for protocol in ("12", "13"):
            for case in cases:
                cert = str(fixtures[case]) if case != "missing" else "-"
                key = str(fixtures[case + "-key"]) if case != "missing" else "-"
                expected = "accept" if case == "client" else "reject"
                command = [
                    str(args.binary), "--mtls", protocol, str(fixtures["ca"]),
                    str(fixtures["server"]), str(fixtures["server-key"]),
                    cert, key, expected,
                ]
                try:
                    done = subprocess.run(
                        command, capture_output=True, text=True, timeout=50,
                        check=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise SystemExit(
                        f"FAIL original NativeIO Owner TLS{protocol} {case}: timeout"
                    ) from exc
                if done.returncode != 0:
                    # Native CNet prints only status/counter metadata on error.
                    # Never expose X.509 fixture bytes or private key material.
                    print(
                        f"FAIL original NativeIO Owner TLS{protocol} {case} "
                        f"exit={done.returncode} "
                        f"stderr={done.stderr[-1500:]}",
                        file=sys.stderr,
                    )
                    return 1
                if "Original CNet Owner + sole static Crypto TLS" not in done.stdout:
                    print(
                        f"FAIL missing actual original Owner evidence TLS{protocol} {case}",
                        file=sys.stderr,
                    )
                    return 1
                print(f"PASS CNet original NativeIO Owner TLS{protocol} {case} {expected}")
    print("PASS original CNet epoll/kqueue/IOCP required mTLS and no-auth-admission")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
