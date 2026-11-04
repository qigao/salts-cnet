#!/usr/bin/env python3
"""Strict byte-identical source provenance for C11 SCTP migration into Core.

Only unchanged original transport/session/test C11 sources are attested.
The removed OpenSSL DTLS adapters and adapted UDP Pion peer are excluded. The obsolete
GmSSL MAC sample, old package and packaging files are deliberately NOT copied
into the native Core SDK. Actual cryptographic algorithm implementations live
only in qigao/crypto.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REF = "qigao/salts@13dbd7266e7aed7277daeb103fb40c4684c3a367"
EXPECTED = {
  "sctp/include/cnet/sctp_session.h": "849966e279cac31fbd78f1c851143d505c2222cd",
  "sctp/include/cnet/sctp_wire.h": "a96278e1552e17b9980c72e34dc02de05afc694f",
  "sctp/src/sctp_assoc_internal.h": "afd056ca5e05db8bc9cbf65610cfa6cf7bb8e675",
  "sctp/src/sctp_assoc.c": "a3bc6e9a2ab7e4b3d48aa78ca5d8f7dd015f257b",
  "sctp/src/sctp_collision_internal.h": "1a83ecced215cc6ce4af2df95d7052a17d103382",
  "sctp/src/sctp_collision.c": "4e1b83be3a39fbe131dba5cc45e5b294a47be8ff",
  "sctp/src/sctp_data_internal.h": "030e95ac053701029d68f6b5e35805058e215ee8",
  "sctp/src/sctp_data.c": "7283b1529cb2e888e2f953f760bf4af1dd441746",
  "sctp/src/sctp_dcep_internal.h": "f54c5fab85e9782e3b3e453375fae0bc7aa6ef94",
  "sctp/src/sctp_dcep.c": "652607d580ef016174635b0528b3afa5a56d8ebf",
  "sctp/src/sctp_init_params_internal.h": "6f9616fa0a7361fc9fe1dc72a9f1c6e9651b9f73",
  "sctp/src/sctp_init_params.c": "0e237d2cc452715c9befe69421ab5c1f17acbd8d",
  "sctp/src/sctp_reliability_internal.h": "5aa78d49e91352c9ef30326cf80e439b07f07ed9",
  "sctp/src/sctp_session_internal.h": "3c6031c8237686e38755c25cb5756cdf7d8d426b",
  "sctp/src/sctp_session.c": "b7c9f306ef15b9b090851b37d1334a1f112dc410",
  "sctp/src/sctp_webrtc_internal.h": "c06e6789392c0f6b0ea192ae36994514a3626fe8",
  "sctp/src/sctp_webrtc.c": "0dd25473259e5b1e5a0567edf481154b1703dcb2",
  "sctp/src/sctp_wire.c": "01fb7d49cd31ffbdb1f2ca315e641e893f5496d4",
  "sctp/tests/assoc_data_test.c": "7c5fcf2900e2aa5e3f55c8d3b7530b3792d3641a",
  "sctp/tests/assoc_test.c": "b281a410baacc11e78e85be66ee7af437a4cf65f",
  "sctp/tests/bundle_test.c": "adc10449ea17dbccd22889e99cb13423d1d84a95",
  "sctp/tests/collision_test.c": "496d2b69a746c16395dda86efce5f660c75a61e5",
  "sctp/tests/congestion_test.c": "54e707a4c88c442806c59fa39146e454ff020367",
  "sctp/tests/data_test.c": "9095669b7bca26b73b1c8c9e9732eafcfb94b86e",
  "sctp/tests/dcep_test.c": "a6a71deb3421a44e6e95d85f72a97678a1b0886d",
  "sctp/tests/fast_recovery_test.c": "33c698c0bbbc3c302091c0a5e8e556224a979dc3",
  "sctp/tests/fragment_test.c": "b3a17a5c81a975171b572d33893e286b3ca45e29",
  "sctp/tests/init_params_test.c": "43ee076d85a288778d3832209cc8c618475e3cfd",
  "sctp/tests/public_api_test.c": "8f63ee561c43bd854e6c30dc6b51d8c289f0ef05",
  "sctp/tests/interleaving_test.c": "c77f3481744f874ebc36211549163f48884c61eb",
  "sctp/tests/owner_thread_test.c": "af32dfdd6b365f21ba31b5547e7f53ccca9fe876",
  "sctp/tests/pr_sctp_test.c": "350dfaf9d797449264acb6dad595232b0a8adb4f",
  "sctp/tests/provider_dso_fixture.c": "f6fa65b2f0745debd84fff628dbfd050ca1320eb",
  "sctp/tests/provider_dso_fixture.h": "1d1349e25e62b0204978fc0c4fcf026f7fdc53f2",
  "sctp/tests/provider_dso_test.c": "9bd859e364b5c0ec717d2def0749b611c0682f6d",
  "sctp/tests/sack_recovery_test.c": "944dbe0bf01dcb79bf23d5c2d2f3c2617e71c279",
  "sctp/tests/session_provider_dso_test.c": "cd88a5e2b488a56b9b2c83ce8bd58f784a82cd12",
  "sctp/tests/session_test.c": "f44927cf5cfb2756a29704f62e977030703eca5d",
  "sctp/tests/wire_test.c": "7a2ebeffc6ff2b258210aa0fca93cb8c6fb2583e",
  "sctp/tests/zero_window_test.c": "bdfcd62f5407d10bfc79d7475c4eced8551d19c4"
}

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def main() -> int:
    failures = []
    for name, want in sorted(EXPECTED.items()):
        source = ROOT / name
        if not source.is_file():
            failures.append(f"missing {name}")
            continue
        # Git checkout on Windows can convert canonical Git LF to CRLF.
        # Normalize only that checkout transformation before SHA verification.
        actual = git_blob(source.read_bytes().replace(b"\r\n", b"\n"))
        if actual != want:
            failures.append(f"source provenance drift: {name}: {actual} != {want}")
    cmake = (ROOT / "sctp/CMakeLists.txt").read_text()
    for forbidden in ("CNetSctpPrototype::", "find_package(GmSSL", "GmSSL::GmSSL", "SaltsCore::"):
        if forbidden in cmake:
            failures.append(f"legacy target or GmSSL provider reference: {forbidden}")
    for name in ("sctp/src/sctp_gmssl_mac.c", "sctp/ci/vcpkg-gmssl/vcpkg.json",
                 "sctp/cmake/CNetSctpPrototypeConfig.cmake.in"):
        if (ROOT / name).exists():
            failures.append(f"old crypto owner or package remains: {name}")
    for failure in failures:
        print("FAIL:", failure)
    print(f"SCTP {len(EXPECTED)} unchanged native source/test blobs from {SOURCE_REF}: "
          + ("FAIL" if failures else "PASS"))
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
