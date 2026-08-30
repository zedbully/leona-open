#!/usr/bin/env python3
"""Run a fail-closed public-hosted reporting fixture for runtime tests.

The fixture validates the public Android SDK transport contract and returns an
opaque BoxId plus a server-issued canonical identifier.  It intentionally does
not return an allow/deny decision: production policy and business actions stay
on the customer backend.

Only a redacted, hash-only receipt is persisted.  The supplied AppKey, request
identifier, encoded payload, device identifiers, and response identifiers are
never written to the receipt or stdout.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import signal
import sys
import threading
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
PUBLIC_SENSE_PATH = "/v1/sense/public"
HEALTH_PATH = "/healthz"
MAX_BODY_BYTES = 4 * 1024 * 1024
SHA256_HEX = frozenset("0123456789abcdef")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument(
        "--api-key-env",
        default="LEONA_FIXTURE_APP_KEY",
        help="Environment variable containing the ephemeral fixture AppKey",
    )
    parser.add_argument("--receipt", required=True, help="Path for the redacted receipt JSON")
    parser.add_argument("--ready-file", help="Optional file touched after the listener is ready")
    parser.add_argument(
        "--max-requests",
        type=int,
        default=0,
        help="Stop after this many successful reports; 0 keeps serving",
    )
    return parser.parse_args()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    temp.write_bytes(json_bytes(value))
    # Receipts are hash-only, but still describe a concrete test execution.
    # Keep them operator-private even on hosts with a permissive umask.
    os.chmod(temp, 0o600)
    temp.replace(path)


def meaningful_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


class FixtureState:
    def __init__(self, *, api_key: str, receipt_path: Path, max_requests: int) -> None:
        self.api_key = api_key
        self.receipt_path = receipt_path
        self.max_requests = max_requests
        self.success_count = 0
        # Keep the lab fixture's state model aligned with the hosted registry:
        # a lifecycle handle is the preferred alias, while the install hash is
        # retained for old clients that do not send one.
        self.install_ids_by_key: dict[str, str] = {}
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None

    def resolve_install_id(self, *, install_hash: str, lifecycle_hash: str | None) -> str:
        key = f"lifecycle:{lifecycle_hash}" if lifecycle_hash else f"install:{install_hash}"
        with self.lock:
            existing = self.install_ids_by_key.get(key)
            if existing is not None:
                return existing
            issued = "I" + secrets.token_hex(16)
            self.install_ids_by_key[key] = issued
            return issued

    def record_success(self, receipt: dict[str, Any]) -> None:
        with self.lock:
            atomic_write_json(self.receipt_path, receipt)
            self.success_count += 1
            should_stop = self.max_requests > 0 and self.success_count >= self.max_requests
        if should_stop and self.server is not None:
            threading.Thread(target=self.server.shutdown, daemon=True).start()


def validate_public_report(
    *,
    headers: Any,
    raw_body: bytes,
    expected_api_key: str,
    state: FixtureState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    supplied_key = headers.get("X-Leona-App-Key", "")
    if not secrets.compare_digest(supplied_key, expected_api_key):
        raise PermissionError("unauthorized fixture AppKey")

    if headers.get("X-Leona-Reporting-Mode", "") != "public_hosted":
        raise ValueError("reporting mode must be public_hosted")

    try:
        body = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("request body must be valid JSON") from error
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    if body.get("mode") != "public_hosted":
        raise ValueError("body mode must be public_hosted")
    if body.get("payloadEncoding") != "base64":
        raise ValueError("payloadEncoding must be base64")

    request_id = meaningful_string(body.get("requestId"))
    sdk_version = meaningful_string(body.get("sdkVersion"))
    encoded_payload = meaningful_string(body.get("payload"))
    device_context = body.get("deviceContext")
    if request_id is None or sdk_version is None or encoded_payload is None:
        raise ValueError("requestId, sdkVersion, and payload are required")
    if not isinstance(device_context, dict):
        raise ValueError("deviceContext must be an object")
    sdk_int = device_context.get("sdkInt")
    if isinstance(sdk_int, bool) or not isinstance(sdk_int, int) or not (1 <= sdk_int <= 100):
        raise ValueError("deviceContext.sdkInt must be an integer")

    install_hash = meaningful_string(device_context.get("installIdSha256"))
    if install_hash is None or len(install_hash) != 64 or any(char not in SHA256_HEX for char in install_hash):
        raise ValueError("deviceContext.installIdSha256 must be a lowercase SHA-256 digest")
    lifecycle_hash = meaningful_string(device_context.get("installLifecycleSha256"))
    if lifecycle_hash is not None and (
        len(lifecycle_hash) != 64 or any(char not in SHA256_HEX for char in lifecycle_hash)
    ):
        raise ValueError("deviceContext.installLifecycleSha256 must be a lowercase SHA-256 digest")

    try:
        decoded_payload = base64.b64decode(encoded_payload, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("payload must be strict base64") from error
    if not decoded_payload:
        raise ValueError("decoded payload must not be empty")

    evidence_signals = device_context.get("evidenceSignals")
    native_fact_tags = device_context.get("nativeFactTags")
    native_findings = device_context.get("nativeFindingIds")
    if not isinstance(evidence_signals, list):
        raise ValueError("deviceContext.evidenceSignals must be an array")
    if not isinstance(native_fact_tags, list):
        raise ValueError("deviceContext.nativeFactTags must be an array")
    if not isinstance(native_findings, list):
        raise ValueError("deviceContext.nativeFindingIds must be an array")

    canonical_seed = hashlib.sha256(request_id.encode("utf-8") + raw_body).hexdigest()
    response = {
        "boxId": str(uuid.uuid4()),
        "canonicalDeviceId": "L" + canonical_seed,
        "installId": state.resolve_install_id(
            install_hash=install_hash,
            lifecycle_hash=lifecycle_hash,
        ),
    }
    receipt = {
        "schemaVersion": SCHEMA_VERSION,
        "status": "pass",
        "receivedAt": datetime.now(timezone.utc).isoformat(),
        "mode": "public_hosted",
        "apiKeyAccepted": True,
        "sdkVersionHeaderPresent": bool(meaningful_string(headers.get("X-Leona-SDK-Version"))),
        "sdkVersionBodyPresent": True,
        "payloadEncoding": "base64",
        "requestBodySha256": sha256_hex(raw_body),
        "payloadSha256": sha256_hex(decoded_payload),
        "deviceContextSha256": sha256_hex(json_bytes(device_context)),
        "sdkInt": sdk_int,
        "evidenceSignalCount": len(evidence_signals),
        "nativeFactTagCount": len(native_fact_tags),
        "nativeFindingCount": len(native_findings),
        "businessDecisionProduced": False,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
    }
    return response, receipt


def create_handler(state: FixtureState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "LeonaPublicHostedFixture/1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def write_json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
            payload = json_bytes(value)
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            if self.path != HEALTH_PATH:
                self.write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self.write_json(
                HTTPStatus.OK,
                {
                    "status": "ready",
                    "mode": "public_hosted_fixture",
                    "businessDecisionProduced": False,
                },
            )

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            if self.path != PUBLIC_SENSE_PATH:
                self.write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            raw_length = self.headers.get("Content-Length")
            try:
                content_length = int(raw_length or "")
            except ValueError:
                self.write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return
            if content_length <= 0 or content_length > MAX_BODY_BYTES:
                self.write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                response, receipt = validate_public_report(
                    headers=self.headers,
                    raw_body=raw_body,
                    expected_api_key=state.api_key,
                    state=state,
                )
            except PermissionError:
                self.write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            except ValueError:
                self.write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_report"})
                return
            state.record_success(receipt)
            self.write_json(HTTPStatus.OK, response)

    return Handler


def build_server(
    *, host: str, port: int, api_key: str, receipt_path: Path, max_requests: int
) -> tuple[ThreadingHTTPServer, FixtureState]:
    if not api_key:
        raise ValueError("fixture AppKey must not be empty")
    if max_requests < 0:
        raise ValueError("max_requests must be non-negative")
    state = FixtureState(api_key=api_key, receipt_path=receipt_path, max_requests=max_requests)
    server = ThreadingHTTPServer((host, port), create_handler(state))
    state.server = server
    return server, state


def main() -> int:
    args = parse_args()
    api_key = os.environ.get(args.api_key_env, "")
    if not api_key:
        print(f"missing required environment variable: {args.api_key_env}", file=sys.stderr)
        return 2

    server, _state = build_server(
        host=args.host,
        port=args.port,
        api_key=api_key,
        receipt_path=Path(args.receipt),
        max_requests=args.max_requests,
    )

    if args.ready_file:
        ready_file = Path(args.ready_file)
        ready_file.parent.mkdir(parents=True, exist_ok=True)
        ready_file.write_text("ready\n", encoding="utf-8")

    def stop_server(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    server.serve_forever(poll_interval=0.2)
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
