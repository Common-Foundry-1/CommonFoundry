from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import exchange_conformance as conformance


class RecordingFixtureRpc(conformance.FixtureRpc):
    endpoint = "http://127.0.0.1:18443/"

    def __init__(self, responses: dict[str, object] | None = None) -> None:
        super().__init__(responses)
        self.calls: list[str] = []

    def call(self, method: str, params: list[object]) -> object:
        self.calls.append(method)
        return super().call(method, params)


class ExchangeConformanceTests(unittest.TestCase):
    def test_error_catalog_uses_unique_composite_routes(self) -> None:
        catalog_path = SCRIPT_DIRECTORY.parent / "exchange-kit" / "errors.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        self.assertEqual(
            catalog["routing_key"], ["error.code", "error.data.code"]
        )
        routes: dict[tuple[int, str], tuple[bool, str, str]] = {}
        for group in catalog["groups"]:
            for data_code in group["data_codes"]:
                route = (group["jsonrpc_code"], data_code)
                self.assertNotIn(route, routes)
                routes[route] = (
                    group["retryable"], group["meaning"], group["action"]
                )

    def test_offline_self_test_passes_and_digest_covers_exact_report(self) -> None:
        evidence = conformance.run_self_test()
        self.assertEqual(evidence["schema"], conformance.EVIDENCE_SCHEMA)
        self.assertEqual(evidence["report"]["result"], "pass")
        self.assertFalse(evidence["report"]["production_ready"])
        self.assertFalse(evidence["report"]["all_required_scenarios_completed"])
        self.assertEqual(
            evidence["report"]["result_scope"], "declared_contract_checks_only"
        )
        self.assertEqual(evidence["report_sha256"], conformance.sha256_hex(
            conformance.canonical_json(evidence["report"])
        ))
        self.assertTrue(all(
            check["status"] == "pass" for check in evidence["report"]["checks"]
        ))

    def test_identity_mismatch_fails_closed(self) -> None:
        responses = conformance.fixture_responses()
        report = conformance.base_report("test")
        report.update(conformance.run_read_conformance(
            conformance.FixtureRpc(responses), "44" * 32, "22" * 32
        ))
        evidence = conformance.complete_report(report)
        self.assertEqual(evidence["report"]["result"], "fail")
        self.assertIn("identity.network_id", evidence["report"]["failed_checks"])

    def test_untrusted_exchange_info_fields_are_not_reflected_into_evidence(self) -> None:
        secret = "password0123456789"
        responses = conformance.fixture_responses()
        responses["getexchangeinfo"]["network_id"] = secret
        responses["getexchangeinfo"]["custody"] = {
            "mode": secret,
            "api_version": secret,
        }
        responses["getblockchaininfo"]["storage_healthy"] = secret
        report = conformance.base_report("test")
        report.update(
            conformance.run_read_conformance(
                conformance.FixtureRpc(responses), "11" * 32, "22" * 32
            )
        )
        evidence = conformance.complete_report(report)
        self.assertNotIn(secret, conformance.canonical_json(evidence).decode("ascii"))

    def test_exchange_info_required_sections_and_custody_fail_closed(self) -> None:
        for missing_field, failed_check in [
            ("service", "contract.exchange_info_root"),
            ("encodings", "contract.encodings"),
            ("deposit_index", "contract.deposit_index"),
        ]:
            with self.subTest(missing_field=missing_field):
                responses = conformance.fixture_responses()
                responses["getexchangeinfo"].pop(missing_field)
                result = conformance.run_read_conformance(
                    conformance.FixtureRpc(responses), "11" * 32, "22" * 32
                )
                evidence = conformance.complete_report(
                    {**conformance.base_report("test"), **result}
                )
                self.assertFalse(result["read_conformance_verified"])
                self.assertEqual(evidence["report"]["result"], "fail")
                self.assertIn(failed_check, evidence["report"]["failed_checks"])

        secret = "garbage-custody-password-0123456789"
        responses = conformance.fixture_responses()
        responses["getexchangeinfo"]["custody"] = {
            "mode": {"untrusted": secret},
            "api_version": [secret],
            "separate_withdrawal_credential": False,
            "external_signer_protocol": secret,
        }
        result = conformance.run_read_conformance(
            conformance.FixtureRpc(responses), "11" * 32, "22" * 32
        )
        evidence = conformance.complete_report(
            {**conformance.base_report("test"), **result}
        )
        self.assertFalse(result["read_conformance_verified"])
        self.assertIn(
            "contract.custody_shape", evidence["report"]["failed_checks"]
        )
        self.assertIn(
            "contract.withdrawal_methods", evidence["report"]["failed_checks"]
        )
        self.assertNotIn(secret, conformance.canonical_json(evidence).decode("ascii"))

    def test_nonstring_deposit_label_fails_as_conformance_error(self) -> None:
        with self.assertRaises(conformance.ConformanceError):
            conformance.validate_visible_label(7)

    def test_wrong_object_shapes_fail_closed_before_privileged_checks(self) -> None:
        responses = conformance.fixture_responses()
        responses["getexchangeinfo"] = []
        responses["getblockchaininfo"] = []
        responses["getdepositevents"] = []
        report = conformance.base_report("test")
        result = conformance.run_read_conformance(
            conformance.FixtureRpc(responses), "11" * 32, "22" * 32
        )
        report.update(result)
        evidence = conformance.complete_report(report)
        self.assertFalse(result["read_conformance_verified"])
        self.assertEqual(evidence["report"]["result"], "fail")
        self.assertEqual(evidence["report"]["identity"], {})
        self.assertIn(
            "contract.exchange_info_shape", evidence["report"]["failed_checks"]
        )
        self.assertIn("chain.status_shape", evidence["report"]["failed_checks"])
        self.assertIn("deposits.page_shape", evidence["report"]["failed_checks"])

    def test_deposit_page_cannot_skip_an_unreturned_cursor(self) -> None:
        responses = conformance.fixture_responses()
        responses["getdepositevents"] = {
            "api_version": conformance.CHAIN_API_VERSION,
            "network_id": "11" * 32,
            "consensus_fingerprint": "22" * 32,
            "indexed_tip": {"height": 1, "hash": "33" * 32},
            "events": [],
            "next_cursor": "1",
            "high_watermark": "1",
            "has_more": False,
        }
        result = conformance.run_read_conformance(
            conformance.FixtureRpc(responses), "11" * 32, "22" * 32
        )
        self.assertFalse(result["read_conformance_verified"])
        self.assertEqual(
            next(
                entry["status"]
                for entry in result["checks"]
                if entry["name"] == "deposits.page_shape"
            ),
            "fail",
        )

        responses["getdepositevents"]["next_cursor"] = "9" * 5000
        with self.assertRaises(conformance.ConformanceError):
            conformance.validate_deposit_page(
                responses["getdepositevents"], "11" * 32, "22" * 32, "0", 1
            )

    def test_endpoint_rejects_dns_remote_and_embedded_credentials(self) -> None:
        invalid = [
            "http://localhost:18443/",
            "http://192.0.2.10:18443/",
            "http://user:password@127.0.0.1:18443/",
            "https://127.0.0.1:18443/",
            "http://127.0.0.1:18443/rpc",
            "http://127.0.0.1:99999/",
            "http://127.0.0.1:abc/",
        ]
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(conformance.ConformanceError):
                    conformance.validate_endpoint(endpoint)
        self.assertEqual(
            conformance.validate_endpoint("http://127.0.0.1:18443/"),
            "http://127.0.0.1:18443/",
        )
        self.assertEqual(
            conformance.validate_endpoint("http://[::1]:18443/"),
            "http://[::1]:18443/",
        )

    def test_rpc_timeout_is_finite_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "auth.txt"
            path.write_bytes(b"exchange:password-0123456789")
            if conformance.os.name != "nt":
                path.chmod(0o600)
            for timeout in (float("nan"), float("inf"), -1.0, 0.0, 61.0):
                with self.subTest(timeout=timeout):
                    with self.assertRaises(conformance.ConformanceError):
                        conformance.RpcClient(
                            "http://127.0.0.1:18443/", path, timeout
                        )

    def test_rpc_redirects_are_never_followed(self) -> None:
        handler = conformance.RejectRedirects()
        request = conformance.urllib.request.Request("http://127.0.0.1:18443/")
        self.assertIsNone(
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://192.0.2.10/",
            )
        )

    def test_authentication_file_and_evidence_are_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.txt"
            secret = b"exchange:password-0123456789"
            path.write_bytes(secret + b"\n")
            if conformance.os.name != "nt":
                path.chmod(0o600)
            self.assertEqual(conformance.load_basic_credential(path), secret)
            client = conformance.RpcClient(
                "http://127.0.0.1:18443/", path.resolve(), 1.0
            )
            proxy_handlers = [
                handler
                for handler in client._opener.handlers
                if isinstance(handler, conformance.urllib.request.ProxyHandler)
            ]
            self.assertEqual(proxy_handlers, [])
            serialized = conformance.canonical_json(conformance.run_self_test())
            self.assertNotIn(secret, serialized)
            path.write_bytes(b"exchange:short")
            with self.assertRaises(conformance.ConformanceError):
                conformance.load_basic_credential(path)

    def test_registration_document_is_canonicalized_without_exposing_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registrations.json"
            path.write_text(json.dumps([
                {"destination_hex": "33" * 32, "label": "account-001"},
                {"label": "account-002", "destination_hex": "44" * 32},
            ]), encoding="utf-8")
            registrations, digest = conformance.load_registration_document(path)
            self.assertEqual(len(registrations), 2)
            self.assertEqual(digest, conformance.sha256_hex(
                conformance.canonical_json(registrations)
            ))

            path.write_text(
                json.dumps(
                    [
                        {"label": "account-001", "destination_hex": "33" * 32},
                        {"label": "account-001", "destination_hex": "44" * 32},
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaises(conformance.ConformanceError):
                conformance.load_registration_document(path)

            path.write_text(
                json.dumps([{"label": "bad label", "destination_hex": "55" * 32}]),
                encoding="utf-8",
            )
            with self.assertRaises(conformance.ConformanceError):
                conformance.load_registration_document(path)

    def test_registration_acknowledgement_must_match_every_input_exactly(self) -> None:
        registrations = [{"label": "account-001", "destination_hex": "33" * 32}]
        client = conformance.FixtureRpc(
            {
                "registerwatchdestinations": {
                    "api_version": conformance.CHAIN_API_VERSION,
                    "registration_count": 1,
                    "registrations": [
                        {
                            "api_version": conformance.CHAIN_API_VERSION,
                            "label": "different-account",
                            "destination_hex": "44" * 32,
                            "registered_at_height": 1,
                            "registered_at_tip": "66" * 32,
                        }
                    ],
                }
            }
        )
        report: dict[str, object] = {"checks": []}
        conformance.add_registration_check(report, client, registrations, "77" * 32)
        self.assertEqual(report["checks"][-1]["status"], "fail")

        extra_fields = conformance.FixtureRpc(
            {
                "registerwatchdestinations": {
                    "api_version": conformance.CHAIN_API_VERSION,
                    "registration_count": 1,
                    "registrations": [
                        {
                            "api_version": conformance.CHAIN_API_VERSION,
                            "label": "account-001",
                            "destination_hex": "33" * 32,
                            "registered_at_height": 1,
                            "registered_at_tip": "66" * 32,
                            "extra": "forbidden",
                        }
                    ],
                }
            }
        )
        report = {"checks": []}
        conformance.add_registration_check(
            report, extra_fields, registrations, "77" * 32
        )
        self.assertEqual(report["checks"][-1]["status"], "fail")

    def test_remote_error_message_is_never_persisted_in_evidence(self) -> None:
        secret = "exchange:password-0123456789"

        class ErrorRpc:
            def call(self, method: str, params: list[object]) -> object:
                del params
                raise conformance.RpcRemoteError(
                    method, -32007, "storage_faulted", f"echo {secret}"
                )

        checks: list[dict[str, str]] = []
        self.assertIsNone(conformance.safe_call(ErrorRpc(), checks, "probe", []))
        self.assertNotIn(secret, conformance.canonical_json(checks).decode("ascii"))
        self.assertNotIn("storage_faulted", checks[0]["detail"])
        self.assertIn("remote text fields redacted", checks[0]["detail"])

    def test_password_shaped_remote_data_code_is_redacted(self) -> None:
        secret = "password0123456789"

        class ErrorRpc:
            def call(self, method: str, params: list[object]) -> object:
                del params
                raise conformance.RpcRemoteError(method, -32007, secret, secret)

        checks: list[dict[str, str]] = []
        self.assertIsNone(conformance.safe_call(ErrorRpc(), checks, "probe", []))
        self.assertNotIn(secret, conformance.canonical_json(checks).decode("ascii"))

    def test_http_error_reason_cannot_echo_authorization_into_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "auth.txt"
            path.write_bytes(b"exchange:password-0123456789")
            if conformance.os.name != "nt":
                path.chmod(0o600)
            client = conformance.RpcClient(
                "http://127.0.0.1:18443/", path, 1.0
            )
            echoed = client._authorization
            error = conformance.urllib.error.HTTPError(
                client.endpoint,
                500,
                f"malicious echo {echoed}",
                {},
                io.BytesIO(b"ignored"),
            )
            with mock.patch.object(client._opener, "open", side_effect=error):
                checks: list[dict[str, str]] = []
                self.assertIsNone(
                    conformance.safe_call(client, checks, "probe", [])
                )
            evidence = conformance.canonical_json(checks).decode("ascii")
            self.assertNotIn(echoed, evidence)
            self.assertIn("HTTP status 500", evidence)

    def test_withdrawal_journal_requires_full_healthy_v05_shape(self) -> None:
        report = conformance.base_report("test")
        conformance.add_withdrawal_observation(
            report,
            conformance.FixtureRpc(
                {"getwithdrawaljournalinfo": {"api_version": conformance.CUSTODY_API_VERSION}}
            ),
        )
        self.assertEqual(report["scenarios"][-1]["status"], "fail")
        self.assertEqual(
            next(
                entry["status"]
                for entry in report["checks"]
                if entry["name"] == "custody.journal_info_shape"
            ),
            "fail",
        )

        inconsistent = conformance.fixture_responses()["getwithdrawaljournalinfo"]
        inconsistent["capacity"]["warning"] = True
        report = conformance.base_report("test")
        conformance.add_withdrawal_observation(
            report, conformance.FixtureRpc({"getwithdrawaljournalinfo": inconsistent})
        )
        self.assertEqual(report["scenarios"][-1]["status"], "fail")

        faulted = conformance.fixture_responses()["getwithdrawaljournalinfo"]
        faulted["faulted"] = True
        report = conformance.base_report("test")
        conformance.add_withdrawal_observation(
            report, conformance.FixtureRpc({"getwithdrawaljournalinfo": faulted})
        )
        self.assertEqual(report["scenarios"][-1]["status"], "fail")
        self.assertEqual(report["observations"]["custody_journal"]["faulted"], True)
        self.assertEqual(
            next(
                entry["status"]
                for entry in report["checks"]
                if entry["name"] == "custody.journal_not_faulted"
            ),
            "fail",
        )

    def test_evidence_output_is_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "evidence.json"
            evidence = conformance.run_self_test()
            conformance.write_create_new(output, evidence)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), evidence)
            with self.assertRaises(conformance.ConformanceError):
                conformance.write_create_new(output, evidence)

    def test_failed_baseline_never_registers_or_loads_withdrawal_credential(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            registrations = root / "registrations.json"
            registrations.write_text(
                json.dumps([{"label": "account-001", "destination_hex": "33" * 32}]),
                encoding="utf-8",
            )
            client = RecordingFixtureRpc()
            args = argparse.Namespace(
                expected_network_id="44" * 32,
                expected_consensus_fingerprint="22" * 32,
                endpoint="http://127.0.0.1:18443/",
                authentication_file=root / "integration.auth",
                withdrawal_authentication_file=root / "withdrawal.auth",
                timeout_seconds=1.0,
                registration_file=registrations,
                allow_registration=True,
            )
            with mock.patch.object(conformance, "RpcClient", return_value=client) as factory:
                evidence = conformance.run_live(args)

            self.assertEqual(evidence["report"]["result"], "fail")
            self.assertNotIn("registerwatchdestinations", client.calls)
            self.assertNotIn("getwithdrawaljournalinfo", client.calls)
            factory.assert_called_once()


if __name__ == "__main__":
    unittest.main()
