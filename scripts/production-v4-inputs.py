#!/usr/bin/env python3
"""Download and authenticate the public ProductionV4 miner inputs."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys


BUFFER_BYTES = 8 * 1024 * 1024
EXPECTED_RELEASE = "v0.1.0-devnet.16"
EXPECTED_NETWORK = "CommonFoundry ProductionV4 Testnet-1"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(BUFFER_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def identity_matches(path: Path, size: int, sha256: str) -> bool:
    return path.is_file() and path.stat().st_size == size and sha256_file(path) == sha256


def length_matches(path: Path, size: int) -> bool:
    return path.is_file() and path.stat().st_size == size


def is_reusable_cache(name: str) -> bool:
    return name.endswith(".row-major.codeword")


def safe_relative_path(value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe relative path in manifest: {value}")
    return Path(*relative.parts)


def safe_part_name(value: str) -> str:
    if not value or Path(value).name != value or value in {".", ".."}:
        raise ValueError(f"unsafe part name in manifest: {value}")
    return value


def download(url: str, output: Path) -> None:
    subprocess.run(
        [
            "curl",
            "--location",
            "--fail",
            "--silent",
            "--show-error",
            "--retry",
            "5",
            "--retry-delay",
            "3",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1024",
            "--speed-time",
            "30",
            "--continue-at",
            "-",
            "--output",
            str(output),
            url,
        ],
        check=True,
    )


def prepare_part(part: dict, part_directory: Path, release_bases: tuple[str, ...]) -> Path:
    name = safe_part_name(str(part["name"]))
    part_path = part_directory / name
    size = int(part["bytes"])
    sha256 = str(part["sha256"])
    if identity_matches(part_path, size, sha256):
        return part_path

    temporary = part_path.with_name(f"{part_path.name}.download")
    if temporary.is_file():
        downloaded = temporary.stat().st_size
        if downloaded > size or (downloaded == size and not identity_matches(temporary, size, sha256)):
            temporary.unlink()
    downloaded = temporary.stat().st_size if temporary.is_file() else 0
    print(f"Downloading {name} ({downloaded} of {size} bytes already present)", flush=True)
    errors: list[BaseException] = []
    for release_base in release_bases:
        try:
            download(f"{release_base.rstrip('/')}/{name}", temporary)
            break
        except (OSError, subprocess.CalledProcessError) as error:
            errors.append(error)
    else:
        raise OSError(f"all download sources failed for {name}") from errors[-1]
    if not identity_matches(temporary, size, sha256):
        temporary.unlink(missing_ok=True)
        raise ValueError(f"downloaded part failed authentication: {name}")
    os.replace(temporary, part_path)
    print(f"Authenticated {name}", flush=True)
    return part_path


def prepare_inputs(args: argparse.Namespace) -> set[str]:
    manifest = load_json(args.chunk_manifest)
    if manifest.get("schema_version") != 1 or manifest.get("release") != EXPECTED_RELEASE:
        raise ValueError("unsupported ProductionV4 input chunk manifest")

    destination = args.destination.resolve()
    part_directory = destination / ".parts"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    part_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    part_directory.chmod(0o700)
    release_bases = tuple(
        dict.fromkeys([args.release_base, *args.fallback_release_base])
    )

    authenticated: set[str] = set()
    for entry in manifest.get("files", []):
        if "miner" not in entry.get("roles", []):
            continue
        name = str(entry["name"])
        output = destination / safe_relative_path(str(entry["relative_path"]))
        expected_size = int(entry["bytes"])
        expected_sha256 = str(entry["sha256"])
        reusable_cache = is_reusable_cache(name)
        ready = (
            length_matches(output, expected_size)
            if reusable_cache
            else identity_matches(output, expected_size, expected_sha256)
        )
        if ready:
            if not reusable_cache:
                authenticated.add(name)
            status = "Reusing" if reusable_cache else "Authenticated existing"
            print(f"{status} {name}", flush=True)
            continue

        output.parent.mkdir(parents=True, exist_ok=True)
        parts = list(entry.get("parts", []))
        with ThreadPoolExecutor(max_workers=args.download_concurrency) as executor:
            part_paths = list(
                executor.map(
                    lambda part: prepare_part(part, part_directory, release_bases),
                    parts,
                )
            )

        partial = output.with_name(f"{output.name}.partial")
        partial.unlink(missing_ok=True)
        digest = hashlib.sha256()
        written = 0
        with partial.open("xb") as target:
            for part_path in part_paths:
                with part_path.open("rb") as source:
                    while chunk := source.read(BUFFER_BYTES):
                        target.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        if written != expected_size or digest.hexdigest() != expected_sha256:
            partial.unlink(missing_ok=True)
            raise ValueError(f"assembled file failed authentication: {name}")
        os.replace(partial, output)
        authenticated.add(name)
        for part_path in part_paths:
            part_path.unlink()
        print(f"Prepared {name}", flush=True)

    fixed_target = destination / "fixed" / args.fixed_record.name
    fixed_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.fixed_record, fixed_target)
    return authenticated


def final_input_path(destination: Path, name: str) -> Path:
    if Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"unsafe input name in manifest: {name}")
    if name == "MODEL-V2.bank":
        return destination / name
    return destination / "fixed" / name


def validate_inputs(
    destination: Path,
    manifest_path: Path,
    authenticated: set[str] | None = None,
    prepared: bool = False,
) -> None:
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1 or manifest.get("network") != EXPECTED_NETWORK:
        raise ValueError("unsupported ProductionV4 prover input manifest")
    entries = manifest.get("files", [])
    if not isinstance(entries, list) or len(entries) != 8:
        raise ValueError("ProductionV4 prover input manifest must contain exactly eight files")

    seen: set[str] = set()
    total = 0
    for entry in entries:
        name = str(entry["name"])
        if name in seen:
            raise ValueError(f"ProductionV4 prover input manifest repeats {name}")
        seen.add(name)
        path = final_input_path(destination, name)
        size = int(entry["bytes"])
        sha256 = str(entry["sha256"])
        fixed_record = name == "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
        already_authenticated = (authenticated is not None and name in authenticated) or (
            prepared and not fixed_record
        )
        reusable_cache = is_reusable_cache(name)
        valid = (
            length_matches(path, size)
            if already_authenticated or reusable_cache
            else identity_matches(path, size, sha256)
        )
        if not valid:
            raise ValueError(f"input identity mismatch for {name}: {path}")
        total += size
        status = "Validated reusable cache" if reusable_cache else "Authenticated"
        print(f"{status} {name} ({size} bytes)", flush=True)
    if total != int(manifest.get("total_bytes", -1)):
        raise ValueError(f"input manifest total is invalid: authenticated {total} bytes")
    print(f"Authenticated ProductionV4 input manifest: {total} bytes", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--fixed-record", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--release-base", required=True)
    parser.add_argument("--fallback-release-base", action="append", default=[])
    parser.add_argument("--download-concurrency", type=int, choices=range(1, 17), default=16)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--prepared-inputs", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for path in (args.chunk_manifest, args.input_manifest, args.fixed_record):
        if not path.is_file():
            raise ValueError(f"required package file is missing: {path}")
    if args.prepared_inputs and not args.validate_only:
        raise ValueError("--prepared-inputs requires --validate-only")
    authenticated = None
    if not args.validate_only:
        authenticated = prepare_inputs(args)
    validate_inputs(
        args.destination.resolve(),
        args.input_manifest,
        authenticated,
        prepared=args.prepared_inputs,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
