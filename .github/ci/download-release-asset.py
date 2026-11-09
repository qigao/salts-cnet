"""Cache raw SaltsBase release files with the released infrastructure downloader."""
import argparse
import importlib.util
from pathlib import Path
import re


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("url")
parser.add_argument("sha256")
parser.add_argument("size", type=int)
parser.add_argument("destination", type=Path)
args = parser.parse_args()

spec = importlib.util.spec_from_file_location(
    "tool_download", "build/ci-infrastructure/vcpkg-cache/scripts/setup-compiler-toolchain.py")
downloads = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downloads)
if not re.fullmatch(r"[0-9a-f]{64}", args.sha256) or not 0 < args.size <= downloads.MAX_ARCHIVE:
    raise ValueError("Invalid release asset digest or size")

archive = args.destination / args.sha256
if archive.exists():
    if archive.stat().st_size != args.size or downloads.sha256(archive) != args.sha256:
        raise ValueError("Cached release asset size or SHA-256 mismatch")
else:
    downloads.verified_download(args.url, archive, args.sha256, limit=args.size)
    if archive.stat().st_size != args.size:
        raise ValueError("Downloaded release asset size mismatch")
print(f"Prepared release asset {args.sha256}: {args.size} bytes")
