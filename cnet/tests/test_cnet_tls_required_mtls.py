#!/usr/bin/env python3
"""Real public Salts::CNet + NativeIO REQUIRED-mTLS certificate admission.

Exactly one native CNet producer is used. The imported Crypto helper generates
ephemeral X.509 test fixtures; no installed consumer, OpenSSL CLI or alternate
TLS implementation is linked into the native executable.
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
    parser.add_argument("--fixture-generator", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or not args.fixture_generator.is_file():
        parser.error("production CNet executable and local fixture generator are required")

    sys.path.insert(0, str(args.fixture_generator.parent))
    import python_mtls  # solely the exact checked-out Crypto test fixture generator

    args.work.mkdir(parents=True, exist_ok=True)
    cases = ("client", "missing", "wrongca", "eku", "expired", "chain", "badsig")
    with tempfile.TemporaryDirectory(prefix="cnet-public-mtls-", dir=args.work) as temp:
        root = Path(temp)
        root.chmod(0o700)
        fixtures = python_mtls.make_fixtures(root)
        for case in cases:
            cert = str(fixtures[case]) if case != "missing" else "-"
            key = str(fixtures[case + "-key"]) if case != "missing" else "-"
            expected = "accept" if case == "client" else "reject"
            command = [
                str(args.binary), "--required-mtls",
                str(fixtures["ca"]), str(fixtures["server"]),
                str(fixtures["server-key"]), cert, key, expected,
            ]
            try:
                result = subprocess.run(
                    command, check=False, capture_output=True, text=True,
                    timeout=18,
                )
            except subprocess.TimeoutExpired:
                print(f"FAIL public CNet REQUIRED mTLS {case}: timeout",
                      file=sys.stderr)
                return 1
            if result.returncode != 0:
                # C test reports only assertion metadata, never certificate bytes.
                print(
                    f"FAIL public CNet REQUIRED mTLS {case}: "
                    f"exit={result.returncode} stderr={result.stderr[-1200:]}",
                    file=sys.stderr,
                )
                return 1
            print(f"PASS public CNet REQUIRED mTLS {case}: {expected}")
    print("PASS production Salts::CNet epoll REQUIRED client-certificate policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
