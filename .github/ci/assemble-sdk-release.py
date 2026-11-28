"""Assemble the release from the exact successful native qualification jobs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile

root = Path(__file__).resolve().parents[2]
version = json.loads((root / "vcpkg.json").read_text())["version-semver"]
source = os.environ["GITHUB_SHA"]
base = os.environ["SALTS_BASE_VERSION"]
cache = os.environ["VCPKG_CACHE_VERSION"]
matrix = json.loads((root / ".github/ci/sdk-matrix.json").read_text())["include"]
dist = root / "dist"
dist.mkdir()
sdks = []
for row in matrix:
    if not row["package"]:
        continue
    rid = row["rid"]
    artifact = root / "build/qualified-sdk" / f"salts-cnet-sdk-{rid}-{source}" / "salts-cnet-sdk.tar"
    with tarfile.open(artifact, "r:") as archive:
        member, = (m for m in archive.getmembers() if m.name in ("salts-cnet-sdk-manifest.json", "./salts-cnet-sdk-manifest.json") and m.isfile())
        with archive.extractfile(member) as stream:
            embedded = json.loads(stream.read().decode("utf-8-sig"))
    expected = {
        "schema": 1, "version": version, "source": source, "profile": rid,
        "triplet": row["triplet"], "compiler": row["compiler"], "preset": row["preset"],
        "base_version": base, "cache_version": cache, "native_tests": not row["android_abi"],
    }
    if embedded != expected:
        raise ValueError(f"{rid}: SDK manifest does not match the qualification inputs")
    target = dist / f"salts-cnet-{version}-{rid}.tar"
    shutil.copyfile(artifact, target)
    with target.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    sdks.append({"profile": rid, "file": target.name, "sha256": digest,
                 "sizeBytes": target.stat().st_size, "sdk_manifest": embedded})
manifest = {
    "schema": 1, "repository": os.environ["GITHUB_REPOSITORY"], "version": version,
    "tag": f"v{version}", "commit": source,
    "ci": {"runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"]},
    "base_version": base, "cache_version": cache, "sdks": sdks,
}
(dist / f"salts-cnet-{version}-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
with (dist / "SHA256SUMS").open("w", encoding="utf-8") as output:
    for path in sorted(dist.glob("*")):
        if path.name == "SHA256SUMS":
            continue
        with path.open("rb") as stream:
            print(f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {path.name}", file=output)
print(f"Assembled {len(sdks)} native release profiles for {version} at {source}")
