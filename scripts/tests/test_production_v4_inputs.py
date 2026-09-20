from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "production-v4-inputs.py"
SPEC = importlib.util.spec_from_file_location("production_v4_inputs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class ProductionV4InputTests(unittest.TestCase):
    def test_default_mirror_uses_the_public_binary_repository(self) -> None:
        root = SCRIPT.parents[1]
        expected = "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1"
        for relative in ("windows/PREPARE-V4-INPUTS.ps1", "linux/PREPARE-V4-INPUTS.sh"):
            script = (root / "packaging/production-v4-testnet" / relative).read_text(encoding="utf-8")
            self.assertIn(expected, script)
            self.assertNotIn("github.com/Common-Foundry-1/CommonFoundry/releases/download", script)

    def test_pool_miner_role_requires_only_model_and_fixed_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "chunks.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "release": INPUTS.EXPECTED_RELEASE,
                        "files": [
                            {"name": "MODEL-V2.bank", "roles": ["miner", "pool-miner"]},
                            {
                                "name": "FORGEMATRIX-V4-FIXED-BANK-0.tree",
                                "roles": ["miner"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                INPUTS.required_input_names(manifest, "pool-miner"),
                {"MODEL-V2.bank", INPUTS.FIXED_RECORD_NAME},
            )

    def test_prepare_authenticates_parts_while_assembling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "inputs"
            parts = destination / ".parts"
            parts.mkdir(parents=True)
            fixed_record = root / "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
            fixed_record.write_bytes(b"fixed-record")

            files = []
            input_entries = []
            names = ["MODEL-V2.bank"]
            for bank in range(3):
                names.extend(
                    [
                        f"FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword",
                        f"FORGEMATRIX-V4-FIXED-BANK-{bank}.tree",
                    ]
                )
            for index, name in enumerate(names):
                content = f"left-{index}|right-{index}".encode()
                midpoint = len(content) // 2
                left, right = content[:midpoint], content[midpoint:]
                part_entries = []
                for part_index, value in enumerate((left, right)):
                    part_name = f"part-{index}-{part_index}"
                    (parts / part_name).write_bytes(value)
                    part_entries.append(
                        {"name": part_name, "bytes": len(value), "sha256": sha256(value)}
                    )
                relative = name if name == "MODEL-V2.bank" else f"fixed/{name}"
                identity = {"name": name, "bytes": len(content), "sha256": sha256(content)}
                files.append(
                    {
                        **identity,
                        "relative_path": relative,
                        "roles": ["miner"],
                        "parts": part_entries,
                    }
                )
                input_entries.append(identity)

            input_entries.append(
                {
                    "name": fixed_record.name,
                    "bytes": fixed_record.stat().st_size,
                    "sha256": sha256(fixed_record.read_bytes()),
                }
            )
            chunk_manifest = root / "chunks.json"
            chunk_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "release": INPUTS.EXPECTED_RELEASE,
                        "files": files,
                    }
                ),
                encoding="utf-8",
            )
            input_manifest = root / "inputs.json"
            input_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "network": INPUTS.EXPECTED_NETWORK,
                        "total_bytes": sum(entry["bytes"] for entry in input_entries),
                        "files": input_entries,
                    }
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                chunk_manifest=chunk_manifest,
                input_manifest=input_manifest,
                fixed_record=fixed_record,
                destination=destination,
                release_base="https://invalid.example",
                fallback_release_base=[],
                download_concurrency=16,
                validate_only=False,
            )

            authenticated = INPUTS.prepare_inputs(args)
            INPUTS.validate_inputs(destination, input_manifest, authenticated)
            self.assertEqual(authenticated, set(names))
            for entry in files:
                path = destination / Path(entry["relative_path"])
                index = names.index(entry["name"])
                self.assertEqual(path.read_bytes(), f"left-{index}|right-{index}".encode())

    def test_prepare_part_resumes_from_the_fallback_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            part_directory = Path(temporary)
            value = b"authenticated-part"
            part = {
                "name": "part-01",
                "bytes": len(value),
                "sha256": sha256(value),
            }
            download = part_directory / "part-01.download"
            download.write_bytes(value[:5])
            urls: list[str] = []

            def fake_download(url: str, output: Path) -> None:
                urls.append(url)
                if len(urls) == 1:
                    raise OSError("primary unavailable")
                output.write_bytes(value)

            with mock.patch.object(INPUTS, "download", side_effect=fake_download):
                result = INPUTS.prepare_part(
                    part,
                    part_directory,
                    ("https://primary.example", "https://fallback.example"),
                )

            self.assertEqual(result.read_bytes(), value)
            self.assertEqual(
                urls,
                [
                    "https://primary.example/part-01",
                    "https://fallback.example/part-01",
                ],
            )

    def test_authenticated_fallback_replaces_a_successful_but_corrupt_primary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = b"authenticated-part"
            part = {"name": "part-01", "bytes": len(value), "sha256": sha256(value)}
            urls = []

            def fake_download(url, output):
                urls.append(url)
                self.assertFalse(output.exists())
                output.write_bytes(b"x" * len(value) if len(urls) == 1 else value)

            with mock.patch.object(INPUTS, "download", side_effect=fake_download):
                result = INPUTS.prepare_part(part, root, ("https://primary.example", "https://fallback.example"))
            self.assertEqual(result.read_bytes(), value)
            self.assertEqual(len(urls), 2)
            self.assertIn("fallback.example", urls[-1])

    def test_mirror_retries_once_from_zero_after_a_poisoned_resumed_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = b"authenticated-part"
            part = {"name": "part-01", "bytes": len(value), "sha256": sha256(value)}
            calls = []

            def fake_download(url, output):
                offset = output.stat().st_size if output.exists() else 0
                calls.append((url, offset))
                if "primary.example" in url:
                    output.write_bytes(b"wrong")
                    raise OSError("primary interrupted")
                with output.open("ab") as target:
                    target.write(value[offset:])

            with mock.patch.object(INPUTS, "download", side_effect=fake_download):
                result = INPUTS.prepare_part(part, root, ("https://primary.example", "https://fallback.example"))
            self.assertEqual(result.read_bytes(), value)
            self.assertEqual(calls, [
                ("https://primary.example/part-01", 0),
                ("https://fallback.example/part-01", 5),
                ("https://fallback.example/part-01", 0),
            ])

    def test_invalid_mirrors_are_bounded_and_never_publish_a_part(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = {"name": "part-01", "bytes": 4, "sha256": sha256(b"good")}
            urls = []

            def fake_download(url, output):
                urls.append(url)
                output.write_bytes(b"evil")

            with mock.patch.object(INPUTS, "download", side_effect=fake_download):
                with self.assertRaisesRegex(OSError, "all download sources failed"):
                    INPUTS.prepare_part(part, root, ("https://primary.example", "https://fallback.example"))
            self.assertEqual(len(urls), 2)
            self.assertFalse((root / "part-01").exists())
            self.assertFalse((root / "part-01.download").exists())

    def test_validation_treats_only_row_major_files_as_untrusted_caches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "inputs"
            fixed = destination / "fixed"
            fixed.mkdir(parents=True)
            values = {
                "MODEL-V2.bank": b"model",
                "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json": b"record",
            }
            for bank in range(3):
                values[f"FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword"] = b"cache"
                values[f"FORGEMATRIX-V4-FIXED-BANK-{bank}.tree"] = b"tree"
            entries = []
            for name, value in values.items():
                path = INPUTS.final_input_path(destination, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
                entries.append({"name": name, "bytes": len(value), "sha256": sha256(value)})
            manifest = root / "inputs.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "network": INPUTS.EXPECTED_NETWORK,
                        "total_bytes": sum(entry["bytes"] for entry in entries),
                        "files": entries,
                    }
                ),
                encoding="utf-8",
            )

            (fixed / "FORGEMATRIX-V4-FIXED-BANK-0.row-major.codeword").write_bytes(b"wrong")
            INPUTS.validate_inputs(destination, manifest)
            (fixed / "FORGEMATRIX-V4-FIXED-BANK-0.tree").write_bytes(b"fail")
            with self.assertRaisesRegex(ValueError, "input identity mismatch"):
                INPUTS.validate_inputs(destination, manifest)

            INPUTS.validate_inputs(destination, manifest, prepared=True)
            (fixed / "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json").write_bytes(b"badbad")
            with self.assertRaisesRegex(ValueError, "input identity mismatch"):
                INPUTS.validate_inputs(destination, manifest, prepared=True)


if __name__ == "__main__":
    unittest.main()
