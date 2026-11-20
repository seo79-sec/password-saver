"""Independently verify a downloaded Windows candidate and its provenance."""

import hashlib
import os
from pathlib import Path
from zipfile import ZipFile


def verify_candidate(directory, name, version, commit, source, expected_zip, expected_exe):
    archive = directory / f"{name}.zip"
    manifest = directory / f"{archive.name}.sha256"
    if sorted(path.name for path in directory.iterdir()) != sorted((archive.name, manifest.name)):
        raise ValueError("Downloaded artifact does not match the exact file allowlist")

    with archive.open("rb") as contents:
        zip_hash = hashlib.file_digest(contents, "sha256").hexdigest()
    if zip_hash != expected_zip:
        raise ValueError("ZIP differs from the file verified on the build runner")
    if manifest.read_bytes() != f"{zip_hash}  {archive.name}\n".encode("ascii"):
        raise ValueError("ZIP checksum manifest does not match the archive")

    exe_name = "PasswordSaver/password-saver.exe"
    readme_name = "PasswordSaver/README.txt"
    checksums_name = "PasswordSaver/SHA256SUMS.txt"
    with ZipFile(archive) as package:
        if sorted(package.namelist()) != sorted((exe_name, readme_name, checksums_name)):
            raise ValueError("ZIP entries do not match the exact file allowlist")
        with package.open(exe_name) as executable:
            header = executable.read(64)
            if len(header) != 64 or header[:2] != b"MZ":
                raise ValueError("Packaged executable has no Windows header")
            executable.seek(int.from_bytes(header[60:64], "little"))
            if executable.read(6) != b"PE\0\0\x64\x86":
                raise ValueError("Packaged executable is not a Windows x64 PE")
            executable.seek(0)
            binary = executable.read()
            exe_hash = hashlib.sha256(binary).hexdigest()
        if exe_hash != expected_exe:
            raise ValueError("EXE differs from the build runner's binary")
        # These known synthetic Go/Playwright markers belong only to tests.
        test_markers = (
            b"legacy-fixture-key",
            b"v2-test-only-master-password",
            b"synthetic-replacement-master-password",
            b"PSRK1-synthetic-key-not-a-real-secret",
            b"Synthetic-master!42",
        )
        if any(marker in binary for marker in test_markers):
            raise ValueError("EXE unexpectedly contains a known synthetic test credential")
        if package.read(checksums_name).splitlines() != [f"{exe_hash}  password-saver.exe".encode("ascii")]:
            raise ValueError("Inner executable checksum does not match the EXE")

        readme = package.read(readme_name).decode("utf-8-sig").splitlines()
        for line in (
            f"PasswordSaver Standard {version} (Windows x64)",
            f"Commit: {commit}",
            f"Source: {source}",
        ):
            if readme.count(line) != 1:
                raise ValueError("Packaged version or source metadata differs from this run")

    return zip_hash, exe_hash


if __name__ == "__main__":
    env = os.environ
    zip_hash, exe_hash = verify_candidate(
        Path(env["ARTIFACT_DIRECTORY"]),
        env["ARTIFACT_NAME"],
        env["PRODUCT_VERSION"],
        env["GITHUB_SHA"],
        env["GITHUB_REF"],
        env["EXPECTED_ZIP_SHA256"],
        env["EXPECTED_EXE_SHA256"],
    )
    details = (
        f"Commit {env['GITHUB_SHA']}. ZIP SHA-256 {zip_hash}. EXE SHA-256 {exe_hash}."
    )
    print(f"::notice title=Verified Windows candidate::{details}")
    with Path(env["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(f"\n### Windows candidate verified after download\n\n{details}\n")
