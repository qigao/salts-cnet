"""Independent DNS SAN cases for the static Crypto qualification contract.

The production CNet suite runs the full IP SAN and system-trust scenarios in
external_san_peer.py. This candidate admits only bounded DNS identities.
"""
from external_san_peer import one_session, parse_args, ssl_context


def main():
    args = parse_args()
    context = ssl_context(args.cert, args.key, args.protocol)
    for identity in ("localhost", "wrong.example"):
        if not one_session(context, args.binary, args.protocol, identity):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
