#!/usr/bin/env python3
"""Common Foundry exchange RPC conformance and evidence generator.

The default live run is read-only. Batch watch registration requires both an
explicit registration document and --allow-registration. Withdrawal release,
cancellation, signing, and broadcast are intentionally outside this tool's
unattended authority and remain controlled-network rehearsal steps.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


EVIDENCE_SCHEMA = "CMFD_EXCHANGE_CONFORMANCE_V1"
TOOL_VERSION = "1.1.0"
CHAIN_API_VERSION = "chain-preview-v0.4"
CUSTODY_API_VERSION = "chain-preview-v0.5"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
SECP256K1_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
MAX_U64 = (1 << 64) - 1
EXCHANGE_SERVICE = "common-foundry-exchange-rpc"
EXCHANGE_STATUS = "integration_preview"
EXTERNAL_SIGNER_PROTOCOL = "CMFDSIG1-v1-provider-neutral"
AMOUNT_ENCODING = "canonical unsigned decimal atom strings"
DESTINATION_ENCODING = (
    "64 lowercase hexadecimal characters encoding a 32-byte x-only secp256k1 public key"
)
REQUIRED_INTEGRATION_METHODS = {
    "getexchangeinfo",
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblock",
    "getrawtransaction",
    "gettransaction",
    "getaddressbalance",
    "getaddressutxos",
    "getbalance",
    "getrawmempool",
    "sendrawtransaction",
    "registerwatchdestination",
    "registerwatchdestinations",
    "getwatchdestination",
    "getdepositevents",
}
WITHDRAWAL_METHODS_BY_CUSTODY = {
    ("disabled", None): set(),
    ("v0.4-preview", CHAIN_API_VERSION): {
        "preparewithdrawal",
        "releasewithdrawal",
        "getwithdrawal",
        "getwithdrawaljournalinfo",
    },
    ("v0.5-policy-keyring", CUSTODY_API_VERSION): {
        "preparewithdrawal",
        "getwithdrawalsigningpackage",
        "getwithdrawalapprovalpayload",
        "releasewithdrawal",
        "cancelwithdrawal",
        "getwithdrawal",
        "getwithdrawaljournalinfo",
    },
}
EXCHANGE_INFO_FIELDS = {
    "api_version",
    "service",
    "status",
    "production_ready",
    "network_id",
    "consensus_fingerprint",
    "custody",
    "encodings",
    "methods",
    "deposit_index",
}
DEPOSIT_CAPACITY_FIELDS = {
    "watch_destination_count",
    "watch_destination_limit",
    "watch_destination_remaining",
    "active_deposit_count",
    "active_deposit_limit",
    "deposit_event_limit",
    "registration_batch_limit",
    "event_page_limit",
}


class Rpc(Protocol):
    def call(self, method: str, params: list[Any]) -> Any: ...


class ConformanceError(RuntimeError):
    pass


class RpcRemoteError(ConformanceError):
    def __init__(self, method: str, code: Any, data_code: Any, message: Any) -> None:
        del data_code, message
        safe_code = code if type(code) is int and -(1 << 31) <= code < (1 << 31) else None
        super().__init__(
            f"{method} failed with remote JSON-RPC code "
            f"{safe_code if safe_code is not None else 'invalid'}; remote text fields redacted"
        )
        self.method = method
        self.code = safe_code
        self.data_code = None


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_hex32(value: str, label: str) -> str:
    if not HEX32.fullmatch(value):
        raise ConformanceError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def validate_xonly_public_key(value: str, label: str) -> str:
    validate_hex32(value, label)
    x_coordinate = int(value, 16)
    if x_coordinate >= SECP256K1_FIELD:
        raise ConformanceError(f"{label} is not a valid secp256k1 x-only public key")
    curve_value = (pow(x_coordinate, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    y_coordinate = pow(curve_value, (SECP256K1_FIELD + 1) // 4, SECP256K1_FIELD)
    if pow(y_coordinate, 2, SECP256K1_FIELD) != curve_value:
        raise ConformanceError(f"{label} is not a valid secp256k1 x-only public key")
    return value


def validate_visible_label(value: Any) -> str:
    if not isinstance(value, str):
        raise ConformanceError("registration label must be visible ASCII")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ConformanceError("registration label must be visible ASCII") from error
    if not 1 <= len(encoded) <= 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ConformanceError("registration label must contain 1-128 visible ASCII bytes")
    return value


def canonical_u64(value: Any, label: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, str)
        or len(value) > 20
        or not DECIMAL.fullmatch(value)
    ):
        raise ConformanceError(f"{label} is not a canonical unsigned decimal string")
    parsed = int(value)
    if not minimum <= parsed <= MAX_U64:
        raise ConformanceError(f"{label} is outside its unsigned 64-bit range")
    return parsed


def canonical_u64_or_none(value: Any) -> int | None:
    try:
        return canonical_u64(value, "exchange capability counter")
    except ConformanceError:
        return None


def validate_custody_capability(value: Any) -> tuple[str, str | None] | None:
    if not isinstance(value, dict) or set(value) != {
        "mode",
        "api_version",
        "separate_withdrawal_credential",
        "external_signer_protocol",
    }:
        return None
    mode = value["mode"]
    api_version = value["api_version"]
    if not isinstance(mode, str) or (
        api_version is not None and not isinstance(api_version, str)
    ):
        return None
    custody_key = (mode, api_version)
    if custody_key not in WITHDRAWAL_METHODS_BY_CUSTODY:
        return None
    if value["separate_withdrawal_credential"] is not True:
        return None
    if value["external_signer_protocol"] != EXTERNAL_SIGNER_PROTOCOL:
        return None
    return custody_key


def validate_encoding_capability(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {
            "amounts",
            "destination",
            "checksummed_address_available",
        }
        and value["amounts"] == AMOUNT_ENCODING
        and value["destination"] == DESTINATION_ENCODING
        and value["checksummed_address_available"] is False
    )


def validate_method_list(value: Any, expected: set[str]) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(method, str) for method in value)
        and len(value) == len(expected)
        and len(set(value)) == len(value)
        and set(value) == expected
    )


def validate_deposit_index_capability(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "healthy",
        "indexed_tip",
        "high_watermark",
        "capacity",
    }:
        return False
    indexed_tip = value["indexed_tip"]
    if (
        value["healthy"] is not True
        or not isinstance(indexed_tip, dict)
        or set(indexed_tip) != {"height", "hash"}
        or type(indexed_tip["height"]) is not int
        or not 0 <= indexed_tip["height"] <= MAX_U64
        or not isinstance(indexed_tip["hash"], str)
        or not HEX32.fullmatch(indexed_tip["hash"])
    ):
        return False
    capacity = value["capacity"]
    if not isinstance(capacity, dict) or set(capacity) != DEPOSIT_CAPACITY_FIELDS:
        return False
    high_watermark = canonical_u64_or_none(value["high_watermark"])
    watch_count = canonical_u64_or_none(capacity["watch_destination_count"])
    watch_remaining = canonical_u64_or_none(
        capacity["watch_destination_remaining"]
    )
    active_count = canonical_u64_or_none(capacity["active_deposit_count"])
    if high_watermark is None or watch_count is None or watch_remaining is None:
        return False
    if active_count is None:
        return False
    return (
        capacity["watch_destination_limit"] == "100000"
        and capacity["active_deposit_limit"] == "1000000"
        and capacity["deposit_event_limit"] == "1000000"
        and capacity["registration_batch_limit"] == "1000"
        and capacity["event_page_limit"] == "1000"
        and watch_count <= 100000
        and watch_remaining <= 100000
        and watch_count + watch_remaining == 100000
        and active_count <= 1000000
        and high_watermark <= 1000000
    )


def unsigned_json_integer(
    value: Any, label: str, maximum: int = MAX_U64, minimum: int = 0
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ConformanceError(f"{label} is outside its unsigned integer range")
    return value


def validate_deposit_event(event: Any, expected_cursor: int) -> None:
    fields = {
        "cursor",
        "added_cursor",
        "kind",
        "label",
        "destination_hex",
        "txid",
        "vout",
        "value_atoms",
        "spendable_height",
        "coinbase",
        "blockhash",
        "blockheight",
        "blocktime",
    }
    if not isinstance(event, dict) or set(event) != fields:
        raise ConformanceError("deposit event fields do not match the pinned contract")
    cursor = canonical_u64(event["cursor"], "deposit event cursor", 1)
    added_cursor = canonical_u64(
        event["added_cursor"], "deposit event added_cursor", 1
    )
    if cursor != expected_cursor:
        raise ConformanceError("deposit event cursor is not contiguous")
    if event["kind"] == "deposit_added":
        if added_cursor != cursor:
            raise ConformanceError("deposit addition has the wrong added cursor")
    elif event["kind"] == "deposit_removed":
        if added_cursor >= cursor:
            raise ConformanceError("deposit removal does not reference an earlier addition")
    else:
        raise ConformanceError("deposit event kind is unsupported")
    validate_visible_label(event["label"])
    for field in ("destination_hex", "txid", "blockhash"):
        if not isinstance(event[field], str):
            raise ConformanceError(f"deposit event {field} is not a string")
        validate_hex32(event[field], f"deposit event {field}")
    unsigned_json_integer(event["vout"], "deposit event vout", (1 << 32) - 1)
    canonical_u64(event["value_atoms"], "deposit event value_atoms")
    unsigned_json_integer(event["spendable_height"], "deposit spendable height")
    if type(event["coinbase"]) is not bool:
        raise ConformanceError("deposit event coinbase is not a boolean")
    unsigned_json_integer(event["blockheight"], "deposit block height", minimum=1)
    unsigned_json_integer(event["blocktime"], "deposit block time")


def validate_deposit_page(
    page: Any,
    expected_network_id: str,
    expected_consensus_fingerprint: str,
    after_cursor: str,
    limit: int,
) -> None:
    fields = {
        "api_version",
        "network_id",
        "consensus_fingerprint",
        "indexed_tip",
        "events",
        "next_cursor",
        "high_watermark",
        "has_more",
    }
    if not isinstance(page, dict) or set(page) != fields:
        raise ConformanceError("deposit event page fields do not match the pinned contract")
    if (
        page["api_version"] != CHAIN_API_VERSION
        or page["network_id"] != expected_network_id
        or page["consensus_fingerprint"] != expected_consensus_fingerprint
    ):
        raise ConformanceError("deposit event page identity or API version is invalid")
    indexed_tip = page["indexed_tip"]
    if not isinstance(indexed_tip, dict) or set(indexed_tip) != {"height", "hash"}:
        raise ConformanceError("deposit indexed tip fields are invalid")
    unsigned_json_integer(indexed_tip["height"], "deposit indexed tip height")
    if not isinstance(indexed_tip["hash"], str):
        raise ConformanceError("deposit indexed tip hash is not a string")
    validate_hex32(indexed_tip["hash"], "deposit indexed tip hash")
    events = page["events"]
    if not isinstance(events, list) or len(events) > limit:
        raise ConformanceError("deposit event page exceeds its requested limit")
    after = canonical_u64(after_cursor, "deposit after cursor")
    prior = after
    for event in events:
        validate_deposit_event(event, prior + 1)
        prior += 1
    next_cursor = canonical_u64(page["next_cursor"], "deposit next cursor")
    high_watermark = canonical_u64(page["high_watermark"], "deposit high watermark")
    if prior != next_cursor or next_cursor > high_watermark:
        raise ConformanceError("deposit page cursors do not match its exact events")
    if type(page["has_more"]) is not bool or page["has_more"] != (
        next_cursor < high_watermark
    ):
        raise ConformanceError("deposit has_more disagrees with its high watermark")


def validate_anchor(value: Any, label: str) -> dict[str, Any]:
    fields = {"key_id", "journal_instance_id", "generation", "commitment"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConformanceError(f"{label} fields are invalid")
    for field in ("key_id", "journal_instance_id", "commitment"):
        if not isinstance(value[field], str):
            raise ConformanceError(f"{label} {field} is not a string")
        validate_hex32(value[field], f"{label} {field}")
    canonical_u64(value["generation"], f"{label} generation", 1)
    return value


def validate_journal_info(value: Any) -> dict[str, Any]:
    fields = {
        "api_version",
        "anchor",
        "external_anchor",
        "anchor_relationship",
        "policy_id",
        "active_keyring",
        "policy_time_watermark_unix_seconds",
        "policy_release_event_count",
        "capacity",
        "redundancy_degraded",
        "faulted",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ConformanceError("withdrawal journal fields do not match the pinned contract")
    if value["api_version"] != CUSTODY_API_VERSION:
        raise ConformanceError("withdrawal journal API version is invalid")
    anchor = validate_anchor(value["anchor"], "withdrawal journal anchor")
    external = validate_anchor(value["external_anchor"], "external journal anchor")
    relationship = value["anchor_relationship"]
    if relationship not in {"current", "descendant"}:
        raise ConformanceError("withdrawal journal anchor relationship is invalid")
    if (
        anchor["key_id"] != external["key_id"]
        or anchor["journal_instance_id"] != external["journal_instance_id"]
    ):
        raise ConformanceError("withdrawal journal anchors identify different journals")
    anchor_generation = canonical_u64(anchor["generation"], "journal generation", 1)
    external_generation = canonical_u64(
        external["generation"], "external journal generation", 1
    )
    if relationship == "current":
        if anchor != external:
            raise ConformanceError("current journal relationship requires identical anchors")
    elif external_generation >= anchor_generation:
        raise ConformanceError("descendant relationship requires an older external anchor")
    if not isinstance(value["policy_id"], str):
        raise ConformanceError("withdrawal policy id is not a string")
    validate_hex32(value["policy_id"], "withdrawal policy id")
    keyring = value["active_keyring"]
    if not isinstance(keyring, dict) or set(keyring) != {
        "instance_id",
        "generation",
        "commitment",
    }:
        raise ConformanceError("active keyring fields are invalid")
    for field in ("instance_id", "commitment"):
        if not isinstance(keyring[field], str):
            raise ConformanceError(f"active keyring {field} is not a string")
        validate_hex32(keyring[field], f"active keyring {field}")
    canonical_u64(keyring["generation"], "active keyring generation", 1)
    canonical_u64(
        value["policy_time_watermark_unix_seconds"], "policy time watermark"
    )
    canonical_u64(value["policy_release_event_count"], "policy release count")
    capacity = value["capacity"]
    capacity_fields = {
        "live_record_count",
        "live_record_limit",
        "tombstone_count",
        "tombstone_limit",
        "commitment_count",
        "commitment_limit",
        "estimated_full_release_capacity_remaining",
        "warning",
        "warning_threshold_full_releases",
    }
    if not isinstance(capacity, dict) or set(capacity) != capacity_fields:
        raise ConformanceError("withdrawal journal capacity fields are invalid")
    parsed = {
        field: canonical_u64(capacity[field], f"capacity {field}")
        for field in capacity_fields
        if field != "warning"
    }
    if parsed["warning_threshold_full_releases"] != 1024:
        raise ConformanceError("capacity warning threshold is incompatible")
    for count, limit in (
        ("live_record_count", "live_record_limit"),
        ("tombstone_count", "tombstone_limit"),
        ("commitment_count", "commitment_limit"),
    ):
        if parsed[count] > parsed[limit] or parsed[limit] == 0:
            raise ConformanceError("withdrawal journal capacity counters are invalid")
    warning = capacity["warning"]
    if type(warning) is not bool or warning != (
        parsed["estimated_full_release_capacity_remaining"] < 1024
    ):
        raise ConformanceError("withdrawal journal capacity warning is inconsistent")
    if type(value["redundancy_degraded"]) is not bool or type(value["faulted"]) is not bool:
        raise ConformanceError("withdrawal journal health flags are not booleans")
    return {
        "anchor_relationship": relationship,
        "redundancy_degraded": value["redundancy_degraded"],
        "faulted": value["faulted"],
        "capacity_warning": warning,
    }


def validate_endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ConformanceError("endpoint must be an http URL without embedded credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConformanceError("endpoint must be the canonical root URL without query or fragment")
    try:
        port = parsed.port
    except ValueError as error:
        raise ConformanceError("endpoint port is invalid") from error
    if parsed.hostname is None or port is None:
        raise ConformanceError("endpoint must include an explicit loopback IP address and port")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise ConformanceError("endpoint host must be a numeric loopback IP address") from error
    if not address.is_loopback:
        raise ConformanceError("endpoint must use a loopback IP address")
    host = f"[{parsed.hostname}]" if address.version == 6 else parsed.hostname
    return f"http://{host}:{port}/"


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep the scoped Basic credential on the validated loopback endpoint."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def load_basic_credential(path: Path) -> bytes:
    if not path.is_absolute():
        raise ConformanceError("authentication file must be an absolute regular non-symlink file")
    normalized = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConformanceError("authentication file cannot be resolved") from error
    if os.path.normcase(str(normalized)) != os.path.normcase(str(resolved)):
        raise ConformanceError("authentication path must not traverse a symlink or reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(normalized, flags)
    except OSError as error:
        raise ConformanceError("authentication file could not be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ConformanceError("authentication file must be a single-link regular file")
        if os.name != "nt" and (
            metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ConformanceError("authentication file owner or mode is not private")
        with os.fdopen(descriptor, "rb", closefd=False) as credential_file:
            raw = credential_file.read(1025)
    finally:
        os.close(descriptor)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or len(raw) > 1024 or any(byte < 33 or byte > 126 for byte in raw):
        raise ConformanceError("authentication file must contain at most 1024 visible ASCII bytes")
    if raw.count(b":") != 1:
        raise ConformanceError("authentication file must contain exactly username:password")
    username, password = raw.split(b":", 1)
    if not 1 <= len(username) <= 64 or len(password) < 16:
        raise ConformanceError("authentication username or minimum 16-byte password is invalid")
    return raw


class RpcClient:
    def __init__(self, endpoint: str, authentication_file: Path, timeout: float) -> None:
        self.endpoint = validate_endpoint(endpoint)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0.1 <= timeout <= 60.0
        ):
            raise ConformanceError("timeout must be a finite value from 0.1 through 60 seconds")
        credential = load_basic_credential(authentication_file)
        self._authorization = "Basic " + base64.b64encode(credential).decode("ascii")
        self._timeout = timeout
        self._next_id = 1
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), RejectRedirects()
        )

    def call(self, method: str, params: list[Any]) -> Any:
        request_id = f"conformance-{self._next_id}"
        self._next_id += 1
        body = canonical_json(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": self._authorization,
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                payload = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            status = error.code if type(error.code) is int and 100 <= error.code <= 599 else "unknown"
            raise ConformanceError(
                f"{method} transport failed with HTTP status {status}"
            ) from None
        except TimeoutError:
            raise ConformanceError(f"{method} transport timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConformanceError(f"{method} transport failed") from None
        if len(payload) > 4 * 1024 * 1024:
            raise ConformanceError(f"{method} response exceeds the evidence tool limit")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConformanceError(f"{method} returned invalid JSON") from error
        if not isinstance(document, dict) or document.get("jsonrpc") != "2.0":
            raise ConformanceError(f"{method} returned an invalid JSON-RPC envelope")
        if document.get("id") != request_id:
            raise ConformanceError(f"{method} returned a mismatched request id")
        if "error" in document:
            remote = document.get("error")
            if not isinstance(remote, dict):
                raise ConformanceError(f"{method} returned an invalid JSON-RPC error")
            data = remote.get("data") if isinstance(remote.get("data"), dict) else {}
            raise RpcRemoteError(
                method, remote.get("code"), data.get("code"), remote.get("message")
            )
        if "result" not in document:
            raise ConformanceError(f"{method} response omitted result")
        return document["result"]


class FixtureRpc:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or fixture_responses()

    def call(self, method: str, params: list[Any]) -> Any:
        del params
        if method not in self.responses:
            raise ConformanceError(f"fixture has no response for {method}")
        return copy.deepcopy(self.responses[method])


def check(checks: list[dict[str, str]], name: str, condition: bool, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if condition else "fail", "detail": detail})


def safe_call(
    client: Rpc, checks: list[dict[str, str]], method: str, params: list[Any]
) -> Any | None:
    try:
        result = client.call(method, params)
    except ConformanceError as error:
        check(checks, f"rpc.{method}", False, str(error))
        return None
    check(checks, f"rpc.{method}", True, "valid JSON-RPC result received")
    return result


def run_read_conformance(
    client: Rpc,
    expected_network_id: str,
    expected_consensus_fingerprint: str,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    identity: dict[str, Any] = {}
    info = safe_call(client, checks, "getexchangeinfo", [])
    info_is_object = isinstance(info, dict)
    info_has_exact_root = info_is_object and set(info) == EXCHANGE_INFO_FIELDS
    custody = info.get("custody") if info_is_object else None
    custody_key = validate_custody_capability(custody)
    encodings_valid = validate_encoding_capability(
        info.get("encodings") if info_is_object else None
    )
    methods = info.get("methods") if info_is_object else None
    methods_shape_valid = (
        isinstance(methods, dict) and set(methods) == {"integration", "withdrawal"}
    )
    integration_methods_valid = methods_shape_valid and validate_method_list(
        methods["integration"], REQUIRED_INTEGRATION_METHODS
    )
    withdrawal_methods_valid = (
        methods_shape_valid
        and custody_key is not None
        and validate_method_list(
            methods["withdrawal"], WITHDRAWAL_METHODS_BY_CUSTODY[custody_key]
        )
    )
    deposit_index_valid = validate_deposit_index_capability(
        info.get("deposit_index") if info_is_object else None
    )
    check(
        checks,
        "contract.exchange_info_shape",
        info_is_object,
        "exchange capability result is an object",
    )
    check(
        checks,
        "contract.exchange_info_root",
        info_has_exact_root,
        "exchange capability contains exactly the published root fields",
    )
    check(
        checks,
        "contract.chain_api_version",
        info_is_object and info.get("api_version") == CHAIN_API_VERSION,
        "chain API version exactly matches the published contract",
    )
    check(
        checks,
        "contract.exchange_service",
        info_is_object and info.get("service") == EXCHANGE_SERVICE,
        "exchange service identity exactly matches the published contract",
    )
    check(
        checks,
        "status.not_overclaimed",
        info_is_object
        and info.get("production_ready") is False
        and info.get("status") == EXCHANGE_STATUS,
        "server labels the integration as a non-production preview",
    )
    check(
        checks,
        "identity.network_id",
        info_is_object and info.get("network_id") == expected_network_id,
        "network id matches the operator pin",
    )
    check(
        checks,
        "identity.consensus_fingerprint",
        info_is_object
        and info.get("consensus_fingerprint") == expected_consensus_fingerprint,
        "consensus fingerprint matches the operator pin",
    )
    check(
        checks,
        "contract.custody_shape",
        custody_key is not None,
        "custody tuple, credential separation, and signer protocol are exact",
    )
    check(
        checks,
        "contract.encodings",
        encodings_valid,
        "amount, destination, and address availability encodings are exact",
    )
    check(
        checks,
        "contract.methods_shape",
        methods_shape_valid,
        "method inventory contains exactly integration and withdrawal lists",
    )
    check(
        checks,
        "contract.integration_methods",
        integration_methods_valid,
        "integration method inventory exactly matches the published contract",
    )
    check(
        checks,
        "contract.withdrawal_methods",
        withdrawal_methods_valid,
        "withdrawal method inventory exactly matches the custody tuple",
    )
    check(
        checks,
        "contract.deposit_index",
        deposit_index_valid,
        "deposit index health, tip, counters, limits, and capacity are exact",
    )
    if info_is_object:
        network_id = info.get("network_id")
        fingerprint = info.get("consensus_fingerprint")
        custody_mode = custody_key[0] if custody_key is not None else None
        custody_api_version = custody_key[1] if custody_key is not None else None
        identity = {
            "network_id": expected_network_id if network_id == expected_network_id else None,
            "consensus_fingerprint": (
                expected_consensus_fingerprint
                if fingerprint == expected_consensus_fingerprint
                else None
            ),
            "chain_api_version": (
                CHAIN_API_VERSION
                if info.get("api_version") == CHAIN_API_VERSION
                else None
            ),
            "custody_api_version": (
                custody_api_version
                if custody_key is not None
                else None
            ),
            "custody_mode": custody_mode,
        }

    chain = safe_call(client, checks, "getblockchaininfo", [])
    height = safe_call(client, checks, "getblockcount", [])
    tip = safe_call(client, checks, "getbestblockhash", [])
    check(
        checks,
        "chain.status_shape",
        isinstance(chain, dict),
        "chain status result is an object",
    )
    if isinstance(chain, dict):
        check(checks, "chain.identity_consistent", chain.get("network_id") == expected_network_id and chain.get("consensus_fingerprint") == expected_consensus_fingerprint, "chain status matches both operator pins")
        check(checks, "chain.storage_healthy", chain.get("storage_healthy") is True, "authenticated storage reports healthy")
    check(checks, "chain.height_type", type(height) is int and height >= 0, "height is a nonnegative JSON integer")
    check(checks, "chain.tip_shape", isinstance(tip, str) and bool(HEX32.fullmatch(tip)), "tip is a canonical 32-byte hash")
    if type(height) is int and height >= 0 and isinstance(tip, str):
        height_hash = safe_call(client, checks, "getblockhash", [height])
        check(checks, "chain.tip_round_trip", height_hash == tip, "height lookup matches the advertised tip")
        if height > 0:
            block = safe_call(client, checks, "getblock", [tip, 1])
            check(checks, "chain.tip_block", isinstance(block, dict) and block.get("hash") == tip and type(block.get("height")) is int and block.get("height") == height, "tip block identity round-trips")
    mempool = safe_call(client, checks, "getrawmempool", [False])
    check(checks, "mempool.shape", isinstance(mempool, list) and all(isinstance(txid, str) and HEX32.fullmatch(txid) for txid in mempool), "mempool is an array of canonical transaction ids")

    page = safe_call(client, checks, "getdepositevents", ["0", 1])
    page_valid = False
    if page is not None:
        try:
            validate_deposit_page(
                page,
                expected_network_id,
                expected_consensus_fingerprint,
                "0",
                1,
            )
            page_valid = True
        except ConformanceError:
            page_valid = False
    check(
        checks,
        "deposits.page_shape",
        page_valid,
        "deposit event page exactly matches the pinned, contiguous contract",
    )
    if page_valid:
        next_cursor = page.get("next_cursor")
        high_watermark = page.get("high_watermark")
        check(checks, "deposits.identity_consistent", True, "deposit feed matches both operator pins")
        check(checks, "deposits.cursor_shape", True, "deposit cursors are bounded canonical u64 strings")
        check(checks, "deposits.cursor_order", True, "cursor, exact events, high watermark, and has_more agree")
        events = page.get("events")
        check(checks, "deposits.page_bound", True, "server honored the requested page bound")

    return {
        "checks": checks,
        "identity": identity,
        "read_conformance_verified": all(
            entry["status"] == "pass" for entry in checks
        ),
        "observations": {
            "height": height if type(height) is int else None,
            "tip": tip if isinstance(tip, str) and HEX32.fullmatch(tip) else None,
            "storage_healthy": (
                chain.get("storage_healthy")
                if isinstance(chain, dict) and type(chain.get("storage_healthy")) is bool
                else None
            ),
        },
    }


def load_registration_document(path: Path) -> tuple[list[dict[str, str]], str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConformanceError("registration document is unreadable or invalid JSON") from error
    if not isinstance(document, list) or not 1 <= len(document) <= 1000:
        raise ConformanceError("registration document must contain 1 to 1000 entries")
    normalized: list[dict[str, str]] = []
    labels: set[str] = set()
    destinations: set[str] = set()
    for entry in document:
        if not isinstance(entry, dict) or set(entry) != {"label", "destination_hex"}:
            raise ConformanceError("each registration must contain exactly label and destination_hex")
        label = entry["label"]
        destination = entry["destination_hex"]
        if not isinstance(label, str) or not isinstance(destination, str):
            raise ConformanceError("registration label and destination_hex must be strings")
        validate_visible_label(label)
        validate_xonly_public_key(destination, "registration destination_hex")
        if label in labels:
            raise ConformanceError("registration document contains a duplicate label")
        if destination in destinations:
            raise ConformanceError("registration document contains a duplicate destination")
        labels.add(label)
        destinations.add(destination)
        normalized.append({"label": label, "destination_hex": destination})
    return normalized, sha256_hex(canonical_json(normalized))


def add_registration_check(
    report: dict[str, Any], client: Rpc, registrations: list[dict[str, str]], digest: str
) -> None:
    checks = report["checks"]
    result = safe_call(client, checks, "registerwatchdestinations", [registrations])
    returned = result.get("registrations") if isinstance(result, dict) else None
    exact_root = isinstance(result, dict) and set(result) == {
        "api_version",
        "registration_count",
        "registrations",
    }
    exact_registrations = isinstance(returned, list) and len(returned) == len(registrations)
    if exact_registrations:
        for expected, actual in zip(registrations, returned, strict=True):
            exact_registrations = (
                isinstance(actual, dict)
                and set(actual)
                == {
                    "api_version",
                    "label",
                    "destination_hex",
                    "registered_at_height",
                    "registered_at_tip",
                }
                and actual.get("api_version") == CHAIN_API_VERSION
                and actual.get("label") == expected["label"]
                and actual.get("destination_hex") == expected["destination_hex"]
                and type(actual.get("registered_at_height")) is int
                and 0 <= actual["registered_at_height"] <= MAX_U64
                and isinstance(actual.get("registered_at_tip"), str)
                and bool(HEX32.fullmatch(actual["registered_at_tip"]))
            )
            if not exact_registrations:
                break
    check(
        checks,
        "registrations.acknowledged",
        exact_root
        and result.get("api_version") == CHAIN_API_VERSION
        and type(result.get("registration_count")) is int
        and result.get("registration_count") == len(registrations)
        and exact_registrations,
        "the complete explicit registration batch was acknowledged exactly and in order",
    )
    report["registration_input"] = {"count": len(registrations), "sha256": digest}


def add_withdrawal_observation(report: dict[str, Any], client: Rpc | None) -> None:
    checks = report["checks"]
    if client is None:
        report["scenarios"].append({"name": "custody_journal_read", "status": "not_run", "reason": "no withdrawal credential was supplied"})
        return
    result = safe_call(client, checks, "getwithdrawaljournalinfo", [])
    classification: dict[str, Any] | None = None
    if result is not None:
        try:
            classification = validate_journal_info(result)
        except ConformanceError:
            classification = None
    valid = classification is not None
    check(
        checks,
        "custody.journal_info_shape",
        valid,
        "custody journal status exactly matches the v0.5 contract",
    )
    fault_free = valid and classification["faulted"] is False
    current = valid and classification["anchor_relationship"] == "current"
    redundant = valid and classification["redundancy_degraded"] is False
    capacity_clear = valid and classification["capacity_warning"] is False
    check(checks, "custody.journal_not_faulted", fault_free, "custody journal is not faulted")
    check(checks, "custody.external_anchor_current", current, "external anchor exactly matches the current journal")
    check(checks, "custody.redundancy_healthy", redundant, "custody journal redundancy is not degraded")
    check(checks, "custody.capacity_clear", capacity_clear, "custody journal has no capacity warning")
    ready = valid and fault_free and current and redundant and capacity_clear
    report["scenarios"].append(
        {"name": "custody_journal_read", "status": "pass" if ready else "fail"}
    )
    report.setdefault("observations", {})["custody_journal"] = (
        classification
        if valid
        else {
            "anchor_relationship": "invalid",
            "redundancy_degraded": None,
            "faulted": None,
            "capacity_warning": None,
        }
    )


def complete_report(report: dict[str, Any]) -> dict[str, Any]:
    failed = [entry["name"] for entry in report["checks"] if entry["status"] == "fail"]
    report["result"] = "pass" if not failed else "fail"
    report["result_scope"] = "declared_contract_checks_only"
    report["qualification"] = "partial_contract_conformance"
    report["production_ready"] = False
    report["all_required_scenarios_completed"] = all(
        scenario.get("status") == "pass" for scenario in report["scenarios"]
    )
    report["evidence_integrity"] = "sha256_integrity_only_not_authenticated"
    report["failed_checks"] = failed
    digest = sha256_hex(canonical_json(report))
    return {"schema": EVIDENCE_SCHEMA, "report": report, "report_sha256": digest}


def base_report(mode: str) -> dict[str, Any]:
    return {
        "tool": {"name": "exchange_conformance.py", "version": TOOL_VERSION},
        "generated_at_utc": utc_now(),
        "mode": mode,
        "scope": "readiness, read-only chain/deposit checks, and explicitly authorized registration only",
        "checks": [],
        "scenarios": [
            {"name": "deposit_reorg_recovery", "status": "not_run", "reason": "requires a controlled multi-branch network"},
            {"name": "withdrawal_release_cancel_restart", "status": "not_run", "reason": "requires explicit controlled-network funds and approvals"},
            {"name": "physical_power_loss", "status": "not_run", "reason": "requires operator-controlled hardware"},
        ],
    }


def fixture_responses() -> dict[str, Any]:
    network = "11" * 32
    fingerprint = "22" * 32
    tip = "33" * 32
    return {
        "getexchangeinfo": {
            "api_version": CHAIN_API_VERSION,
            "service": EXCHANGE_SERVICE,
            "status": EXCHANGE_STATUS,
            "production_ready": False,
            "network_id": network,
            "consensus_fingerprint": fingerprint,
            "custody": {
                "mode": "v0.5-policy-keyring",
                "api_version": CUSTODY_API_VERSION,
                "separate_withdrawal_credential": True,
                "external_signer_protocol": EXTERNAL_SIGNER_PROTOCOL,
            },
            "encodings": {
                "amounts": AMOUNT_ENCODING,
                "destination": DESTINATION_ENCODING,
                "checksummed_address_available": False,
            },
            "methods": {
                "integration": sorted(REQUIRED_INTEGRATION_METHODS),
                "withdrawal": sorted(
                    WITHDRAWAL_METHODS_BY_CUSTODY[
                        ("v0.5-policy-keyring", CUSTODY_API_VERSION)
                    ]
                ),
            },
            "deposit_index": {
                "healthy": True,
                "indexed_tip": {"height": 1, "hash": tip},
                "high_watermark": "0",
                "capacity": {
                    "watch_destination_count": "0",
                    "watch_destination_limit": "100000",
                    "watch_destination_remaining": "100000",
                    "active_deposit_count": "0",
                    "active_deposit_limit": "1000000",
                    "deposit_event_limit": "1000000",
                    "registration_batch_limit": "1000",
                    "event_page_limit": "1000",
                },
            },
        },
        "getblockchaininfo": {
            "api_version": CHAIN_API_VERSION,
            "network_id": network,
            "consensus_fingerprint": fingerprint,
            "storage_healthy": True,
        },
        "getblockcount": 1,
        "getbestblockhash": tip,
        "getblockhash": tip,
        "getblock": {"hash": tip, "height": 1},
        "getrawmempool": [],
        "getdepositevents": {
            "api_version": CHAIN_API_VERSION,
            "network_id": network,
            "consensus_fingerprint": fingerprint,
            "indexed_tip": {"height": 1, "hash": tip},
            "events": [],
            "next_cursor": "0",
            "high_watermark": "0",
            "has_more": False,
        },
        "getwithdrawaljournalinfo": {
            "api_version": CUSTODY_API_VERSION,
            "anchor": {
                "key_id": "44" * 32,
                "journal_instance_id": "55" * 32,
                "generation": "3",
                "commitment": "66" * 32,
            },
            "external_anchor": {
                "key_id": "44" * 32,
                "journal_instance_id": "55" * 32,
                "generation": "3",
                "commitment": "66" * 32,
            },
            "anchor_relationship": "current",
            "policy_id": "77" * 32,
            "active_keyring": {
                "instance_id": "88" * 32,
                "generation": "1",
                "commitment": "99" * 32,
            },
            "policy_time_watermark_unix_seconds": "1",
            "policy_release_event_count": "0",
            "capacity": {
                "live_record_count": "0",
                "live_record_limit": "1000000",
                "tombstone_count": "0",
                "tombstone_limit": "1000000",
                "commitment_count": "3",
                "commitment_limit": "2000000",
                "estimated_full_release_capacity_remaining": "100000",
                "warning": False,
                "warning_threshold_full_releases": "1024",
            },
            "redundancy_degraded": False,
            "faulted": False,
        },
    }


def write_create_new(path: Path, document: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise ConformanceError("evidence output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(json.dumps(document, indent=2, sort_keys=True).encode("utf-8"))
            output.write(b"\n")
    except FileExistsError as error:
        raise ConformanceError("evidence output already exists") from error


def run_self_test() -> dict[str, Any]:
    report = base_report("offline-self-test")
    report.update(run_read_conformance(FixtureRpc(), "11" * 32, "22" * 32))
    add_withdrawal_observation(report, FixtureRpc())
    return complete_report(report)


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    expected_network = validate_hex32(args.expected_network_id, "expected network id")
    expected_fingerprint = validate_hex32(
        args.expected_consensus_fingerprint, "expected consensus fingerprint"
    )
    client = RpcClient(args.endpoint, args.authentication_file, args.timeout_seconds)
    report = base_report("live")
    report["endpoint"] = client.endpoint
    report.update(run_read_conformance(client, expected_network, expected_fingerprint))
    if report.get("read_conformance_verified") is not True:
        report["scenarios"].extend(
            [
                {
                    "name": "batch_watch_registration",
                    "status": "not_run",
                    "reason": "baseline read-only identity or contract checks failed",
                },
                {
                    "name": "custody_journal_read",
                    "status": "not_run",
                    "reason": "baseline read-only identity or contract checks failed",
                },
            ]
        )
        return complete_report(report)
    if args.registration_file is not None:
        if not args.allow_registration:
            raise ConformanceError("--registration-file requires --allow-registration")
        registrations, digest = load_registration_document(args.registration_file)
        add_registration_check(report, client, registrations, digest)
        report["scenarios"].append({"name": "batch_watch_registration", "status": "pass" if report["checks"][-1]["status"] == "pass" else "fail"})
    else:
        report["scenarios"].append({"name": "batch_watch_registration", "status": "not_run", "reason": "no explicit registration document was supplied"})
    withdrawal_client = (
        RpcClient(args.endpoint, args.withdrawal_authentication_file, args.timeout_seconds)
        if args.withdrawal_authentication_file is not None
        else None
    )
    add_withdrawal_observation(report, withdrawal_client)
    return complete_report(report)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    self_test = commands.add_parser("self-test", help="run deterministic offline contract checks")
    self_test.add_argument("--output", type=Path)
    live = commands.add_parser("live", help="qualify a running loopback exchange RPC")
    live.add_argument("--endpoint", required=True)
    live.add_argument("--authentication-file", required=True, type=Path)
    live.add_argument("--withdrawal-authentication-file", type=Path)
    live.add_argument("--expected-network-id", required=True)
    live.add_argument("--expected-consensus-fingerprint", required=True)
    live.add_argument("--registration-file", type=Path)
    live.add_argument("--allow-registration", action="store_true")
    live.add_argument("--timeout-seconds", type=float, default=10.0)
    live.add_argument("--output", required=True, type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        evidence = run_self_test() if args.command == "self-test" else run_live(args)
        if args.output is not None:
            write_create_new(args.output, evidence)
        else:
            print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0 if evidence["report"]["result"] == "pass" else 2
    except ConformanceError as error:
        print(f"exchange conformance failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
