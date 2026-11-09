#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Two independently loaded CNet plugins driving REAL simultaneous TLS mTLS.

The same sole physical shared CNet/Crypto Owner serves two native CNet
listeners, clients and verified TLS sessions at once (TLS1.2 and TLS1.3).
Credentials are ephemeral, owned by Crypto's exact pinned Python X.509
fixture generator. No OpenSSL CLI, C test linker dependency, or fallback.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--plugin-a", type=Path, required=True)
    parser.add_argument("--plugin-b", type=Path, required=True)
    parser.add_argument("--crypto-python-fixtures", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    for required in (args.loader, args.plugin_a, args.plugin_b,
                     args.crypto_python_fixtures):
        if not required.is_file():
            parser.error(f"missing exact pinned test artifact: {required}")
    sys.path.insert(0, str(args.crypto_python_fixtures.parent))
    import python_mtls

    args.work.mkdir(parents=True, exist_ok=True)
    cases = ("client", "missing", "wrongca", "eku", "expired", "chain", "badsig")
    with tempfile.TemporaryDirectory(prefix="m6-plugin-mtls-", dir=args.work) as temp:
        folder = Path(temp)
        folder.chmod(0o700)
        fixtures = python_mtls.make_fixtures(folder)
        for case in cases:
            cert = str(fixtures[case]) if case != "missing" else "-"
            key = str(fixtures[case + "-key"]) if case != "missing" else "-"
            outcome = "accept" if case == "client" else "reject"
            command = [
                str(args.loader), "--mtls",
                str(args.plugin_a), str(args.plugin_b),
                str(fixtures["ca"]), str(fixtures["server"]),
                str(fixtures["server-key"]), cert, key, outcome,
            ]
            try:
                done = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=65, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise SystemExit(
                    f"FAIL two-plugin original Owner TLS12/13 case={case}: timeout"
                ) from exc
            if done.returncode != 0 or (
                "M6 original CNet TLS12/TLS13 concurrent mTLS" not in done.stdout
                or "independent plugins PASS" not in done.stdout
            ):
                print(
                    f"FAIL two-plugin NativeIO TLS12/13 mTLS case={case}, "
                    f"exit={done.returncode}, stdout={done.stdout[-750:]}, "
                    f"stderr={done.stderr[-1400:]}",
                    file=sys.stderr,
                )
                return 1
            print(f"PASS one Crypto DSO / two independent CNet plugins / "
                  f"concurrent TLS1.2+1.3 original NativeIO mTLS {case} {outcome}")
    print("PASS M6 two-plugin concurrent original CNet mTLS: "
          "one shared Crypto Provider, no plaintext on rejection, "
          "no active sessions or lease after drain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
