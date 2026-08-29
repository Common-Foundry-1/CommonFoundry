from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from production_v4_wire import FIELD_MODULUS, TRANSPARENT_PROOF_BYTES, write_structural_fixture


SCRIPT = SCRIPTS / "production-v4-verify-qualification.py"
SPEC = importlib.util.spec_from_file_location("production_v4_verify_qualification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)


class ProofMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="cmfd-v4-qualification-")
        self.root = Path(self.directory.name)
        self.source = self.root / "proof.bin"
        write_structural_fixture(self.source)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_every_mutation_changes_the_proof_without_touching_source(self) -> None:
        original = self.source.read_bytes()
        for name, mutation in QUALIFICATION.MUTATIONS.items():
            with self.subTest(name=name):
                destination = self.root / f"{name}.bin"
                QUALIFICATION.mutate_proof(self.source, destination, name)
                self.assertEqual(self.source.read_bytes(), original)
                if mutation[0] == "truncate":
                    self.assertEqual(destination.stat().st_size, TRANSPARENT_PROOF_BYTES - 1)
                elif mutation[0] == "append":
                    self.assertEqual(destination.stat().st_size, TRANSPARENT_PROOF_BYTES + 1)
                else:
                    self.assertEqual(destination.stat().st_size, TRANSPARENT_PROOF_BYTES)
                    changed = destination.read_bytes()
                    differences = [
                        index for index, (left, right) in enumerate(zip(original, changed))
                        if left != right
                    ]
                    self.assertTrue(differences)
                    self.assertLessEqual(len(differences), 4)

    def test_noncanonical_mutation_writes_exact_modulus(self) -> None:
        destination = self.root / "noncanonical.bin"
        QUALIFICATION.mutate_proof(self.source, destination, "noncanonical-field")
        with destination.open("rb") as source:
            source.seek(QUALIFICATION.OUTER_HEADER_BYTES)
            self.assertEqual(struct.unpack("<I", source.read(4))[0], FIELD_MODULUS)

    def test_unknown_mutation_is_rejected(self) -> None:
        with self.assertRaisesRegex(QUALIFICATION.QualificationError, "unknown"):
            QUALIFICATION.mutate_proof(
                self.source, self.root / "unknown.bin", "not-a-mutation"
            )


if __name__ == "__main__":
    unittest.main()
