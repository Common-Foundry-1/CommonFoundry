"""Real curl/PowerShell transport tests against tiny loopback-only mirrors."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest


REPO = Path(__file__).resolve().parents[2]
FIXED = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
PART = "V4-MODEL-V2.bank.part01"


class InputMirrorTests(unittest.TestCase):
    def run_case(self, mode: str, *, native: bool = False, bad_record: bool = False):
        with tempfile.TemporaryDirectory(prefix="cmfd-mirror-test-") as temporary:
            root = Path(temporary)
            value = b"authenticated model bytes\n"
            bad = b"x" * len(value)
            record = b"synthetic fixed record\n"
            sha = lambda data: hashlib.sha256(data).hexdigest()
            part = {"name": PART, "bytes": len(value), "sha256": sha(value)}
            model = {"name": "MODEL-V2.bank", "bytes": len(value), "sha256": sha(value)}
            chunks = root / "V4-INPUT-CHUNKS.json"
            chunks.write_text(json.dumps({
                "schema_version": 1, "release": "v0.1.0-rc.1",
                "files": [{**model, "relative_path": "MODEL-V2.bank", "roles": ["node"], "parts": [part]}],
            }), encoding="utf-8")
            inputs = root / "production-v4-rcnet-1-inputs.json"
            # The real catalog contains eight entries even for a node-only
            # preparation. Miner-only files are not requested in this test.
            entries = [model, {"name": FIXED, "bytes": len(record), "sha256": sha(record)}]
            for bank in range(3):
                for suffix in ("row-major.codeword", "tree"):
                    entries.append({"name": f"FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}",
                                    "bytes": 1, "sha256": sha(b"x")})
            inputs.write_text(json.dumps({
                "schema_version": 1, "network": "CommonFoundry RCNet-1",
                "total_bytes": sum(entry["bytes"] for entry in entries),
                "files": entries,
            }), encoding="utf-8")
            (root / FIXED).write_bytes(b"altered record" if bad_record else record)
            destination = root / "prepared inputs"
            if mode == "resume":
                (destination / ".parts").mkdir(parents=True)
                (destination / ".parts" / (PART + ".download")).write_bytes(b"xx")
            requests = []

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_GET(self):
                    range_header = self.headers.get("Range")
                    requests.append((self.path, range_header))
                    primary = self.path.startswith("/primary/")
                    if primary and mode == "resume":
                        self.send_error(404)
                        return
                    body = bad if mode == "bad" or (primary and mode == "corrupt") else value
                    offset = int(range_header.removeprefix("bytes=").split("-", 1)[0]) if range_header else 0
                    self.send_response(206 if range_header else 200)
                    self.send_header("Content-Length", str(len(body) - offset))
                    if range_header:
                        self.send_header("Content-Range", f"bytes {offset}-{len(body)-1}/{len(body)}")
                    self.end_headers()
                    self.wfile.write(body[offset:])

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            if native:
                script = root / "PREPARE-V4-INPUTS.ps1"
                shutil.copyfile(REPO / "packaging/production-v4-testnet/windows/PREPARE-V4-INPUTS.ps1", script)
                command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
                           "-Role", "Node", "-Destination", str(destination), "-DownloadConcurrency", "1",
                           "-ReleaseBase", base + "/primary", "-FallbackReleaseBase", base + "/fallback"]
            else:
                command = [sys.executable, str(REPO / "scripts/production-v4-inputs.py"),
                           "--chunk-manifest", str(chunks), "--input-manifest", str(inputs),
                           "--fixed-record", str(root / FIXED), "--destination", str(destination),
                           "--role", "node", "--download-concurrency", "1",
                           "--release-base", base + "/primary", "--fallback-release-base", base + "/fallback"]
            environment = os.environ.copy()
            environment["NO_PROXY"] = environment["no_proxy"] = "127.0.0.1,localhost"
            if native:
                # Model a fresh Windows PowerShell process, not a Python child
                # inheriting incompatible PowerShell 7 module locations.
                for key in list(environment):
                    if key.casefold() == "psmodulepath":
                        environment.pop(key)
            try:
                result = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=90)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            if bad_record or mode == "bad":
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((destination / "MODEL-V2.bank").exists())
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((destination / "MODEL-V2.bank").read_bytes(), value)
                self.assertEqual((destination / "fixed" / FIXED).read_bytes(), record)
            if bad_record:
                self.assertIn("Bundled fixed artifact record failed authentication", result.stderr)
                self.assertEqual(requests, [])
            elif mode == "resume":
                self.assertEqual(requests, [("/primary/" + PART, "bytes=2-"),
                                            ("/fallback/" + PART, "bytes=2-"),
                                            ("/fallback/" + PART, None)])
            else:
                self.assertEqual(requests, [("/primary/" + PART, None), ("/fallback/" + PART, None)])
            self.assertFalse((destination / ".parts" / (PART + ".download")).exists())

    def test_python_corrupt_primary_uses_authenticated_mirror(self):
        self.run_case("corrupt")

    def test_python_poisoned_resume_retries_mirror_from_zero(self):
        self.run_case("resume")

    def test_python_all_bad_mirrors_never_publish(self):
        self.run_case("bad")

    @unittest.skipUnless(os.name == "nt", "native Windows PowerShell path")
    def test_windows_corrupt_primary_uses_authenticated_mirror(self):
        self.run_case("corrupt", native=True)

    @unittest.skipUnless(os.name == "nt", "native Windows PowerShell path")
    def test_windows_poisoned_resume_retries_mirror_from_zero(self):
        self.run_case("resume", native=True)

    @unittest.skipUnless(os.name == "nt", "native Windows PowerShell path")
    def test_windows_all_bad_mirrors_never_publish(self):
        self.run_case("bad", native=True)

    @unittest.skipUnless(os.name == "nt", "native Windows PowerShell path")
    def test_windows_bad_fixed_record_fails_before_network_download(self):
        self.run_case("corrupt", native=True, bad_record=True)


if __name__ == "__main__":
    unittest.main()
