from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "production-v4-fuzz-report.py"
SPEC = importlib.util.spec_from_file_location("production_v4_fuzz_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def campaign_text(target: str, maximum: int, *, finding: bool = False) -> str:
    suffix = "\nERROR: AddressSanitizer: heap-buffer-overflow" if finding else ""
    return (
        f"     Running `fuzz/target/release/{target} -max_len={maximum} "
        "-timeout=10 -rss_limit_mb=4096 -malloc_limit_mb=1024`\n"
        "INFO: seed corpus: files: 10 min: 1b max: 12025320b total: 12025330b rss: 72Mb\n"
        "#100 DONE cov: 10 ft: 20 corp: 5/100b lim: 100 exec/s: 3 rss: 500Mb\n"
        f"Done 100 runs in 31 second(s){suffix}\n"
    )


class FuzzReportTests(unittest.TestCase):
    def test_complete_campaign_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-fuzz-") as temporary:
            path = Path(temporary) / "proof.log"
            path.write_text(
                campaign_text("production_v4_proof_decode", 13_631_489),
                encoding="utf-8",
            )
            result = REPORT.parse_campaign(path, "production_v4_proof_decode")
            self.assertEqual(result["runs"], 100)
            self.assertEqual(result["peak_rss_mb"], 500)

    def test_sanitizer_finding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-fuzz-") as temporary:
            path = Path(temporary) / "proof.log"
            path.write_text(
                campaign_text(
                    "production_v4_proof_decode", 13_631_489, finding=True
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(REPORT.FuzzReportError, "finding"):
                REPORT.parse_campaign(path, "production_v4_proof_decode")

    def test_missing_full_size_seed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cmfd-v4-fuzz-") as temporary:
            path = Path(temporary) / "proof.log"
            text = campaign_text("production_v4_proof_decode", 13_631_489).replace(
                "max: 12025320b", "max: 16b"
            )
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(REPORT.FuzzReportError, "full-size proof"):
                REPORT.parse_campaign(path, "production_v4_proof_decode")


if __name__ == "__main__":
    unittest.main()
