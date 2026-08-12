#!/usr/bin/env python3
"""Fail-closed normalizer for cloudTest sense-result artifacts.

The input may be the receiver's persisted JSON or a bounded logcat/webshell
capture containing exactly one terminal ``sense`` or ``error`` JSON event.
This utility deliberately emits no raw BoxId, error text, or unrecognised
input value, so its stdout/file output is suitable for a public collection
bundle. It validates reporting configuration but does not make a verdict or
business decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


ARTIFACT = "leona-cloudtest-sense-result"
SCHEMA_VERSION = 1
MAX_BYTES = 16 * 1024
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.I)
HINT = re.compile(r"^(?:[ -~]{4}\.\.\.[ -~]{4}|<redacted:[0-9a-f]{8}>)$")
SHORT_SHA256 = re.compile(r"^[0-9a-f]{16}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLASS_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]{0,159}$")
SECRET_LIKE = re.compile(
    r"(?i)(?:\b(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|"
    r"password|secret|private[_-]?key|credential|android[_-]?id|serial|"
    r"fingerprint|device[_-]?id)\b\s*[:=]|(?:ghp_|github_pat_|ct_)[A-Za-z0-9_-]{12,}|"
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----)"
)


class ValidationError(ValueError):
    """An input artifact is not safe or does not match the receiver contract."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Persisted leona-cloudtest-sense-result.json path")
    parser.add_argument("--output", type=Path, help="Write normalized output here instead of stdout")
    parser.add_argument("--format", choices=("json", "line"), default="json", help="json is indented; line is canonical JSONL")
    parser.add_argument("--max-age-seconds", type=int, default=300, help="Maximum artifact mtime age; use -1 to disable")
    parser.add_argument("--now-epoch", type=float, help="UTC epoch used for age validation (test/reproducibility hook)")
    parser.add_argument(
        "--expected-run-id-sha256",
        help="Require the terminal result to match this 16-character run correlation digest",
    )
    return parser.parse_args()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def require_exact_keys(value: dict[str, Any], expected: set[str], shape: str) -> None:
    if set(value) != expected:
        raise ValidationError(f"{shape} has unexpected, missing, or ambiguous fields")


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def require_duration(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 86_400_000:
        raise ValidationError("durationMs must be an integer in the accepted range")
    return value


def validate_public_text(text: str) -> None:
    if SECRET_LIKE.search(text):
        raise ValidationError("artifact contains a secret-like or raw identity value")


def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be a boolean")
    return value


def normalize(payload: Any, expected_run_id_sha256: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("top-level JSON value must be an object")
    if set(payload) == {"event", "payload"}:
        event = require_string(payload["event"], "event")
        event_payload = payload["payload"]
        if event == "sense":
            payload = event_payload
        elif event == "error":
            payload = {"error": event_payload}
        else:
            raise ValidationError("event envelope is not a terminal sense result")
        if not isinstance(payload, dict):
            raise ValidationError("event payload must be an object")

    if "error" in payload:
        require_exact_keys(payload, {"error"}, "error result")
        error = payload["error"]
        if not isinstance(error, dict):
            raise ValidationError("error must be an object")
        legacy_keys = {"class", "message", "durationMs"}
        reporting_keys = {
            "class",
            "messageSha256",
            "durationMs",
            "reportingEndpointConfigured",
            "apiKeyConfigured",
        }
        correlated_keys = reporting_keys | {"runIdSha256"}
        if set(error) not in (legacy_keys, reporting_keys, correlated_keys):
            raise ValidationError("error payload has unexpected, missing, or ambiguous fields")
        error_class = require_string(error["class"], "error.class")
        if not CLASS_NAME.fullmatch(error_class):
            raise ValidationError("error.class has an invalid shape")
        validate_public_text(error_class)
        reporting_endpoint_configured: bool | None = None
        api_key_configured: bool | None = None
        run_id_sha256: str | None = None
        if set(error) == legacy_keys:
            message = error["message"]
            if not isinstance(message, str):
                raise ValidationError("error.message must be a string")
            validate_public_text(message)
        else:
            message_hash = error["messageSha256"]
            if message_hash is not None and (
                not isinstance(message_hash, str) or not SHORT_SHA256.fullmatch(message_hash)
            ):
                raise ValidationError("error.messageSha256 must be null or a 16-character digest")
            reporting_endpoint_configured = require_bool(
                error["reportingEndpointConfigured"],
                "error.reportingEndpointConfigured",
            )
            api_key_configured = require_bool(error["apiKeyConfigured"], "error.apiKeyConfigured")
            if set(error) == correlated_keys:
                run_id_sha256 = require_run_id_sha256(error["runIdSha256"])
        require_expected_run_id(run_id_sha256, expected_run_id_sha256)
        return {
            "artifact": ARTIFACT,
            "apiKeyConfigured": api_key_configured,
            "errorClassSha256": digest(error_class),
            "schemaVersion": SCHEMA_VERSION,
            "status": "error",
            "durationMs": require_duration(error["durationMs"]),
            "reportingEndpointConfigured": reporting_endpoint_configured,
            "runIdSha256": run_id_sha256,
        }

    raw_legacy_keys = {"boxId", "canonicalDeviceIdHint", "canonicalDeviceIdSha256", "durationMs"}
    raw_reporting_keys = raw_legacy_keys | {"reportingEndpointConfigured", "apiKeyConfigured"}
    raw_correlated_keys = raw_reporting_keys | {"runIdSha256"}
    hash_legacy_keys = {"boxIdSha256", "canonicalDeviceIdHint", "canonicalDeviceIdSha256", "durationMs"}
    hash_reporting_keys = hash_legacy_keys | {"reportingEndpointConfigured", "apiKeyConfigured"}
    hash_correlated_keys = hash_reporting_keys | {"runIdSha256"}
    accepted_keys = (
        raw_legacy_keys,
        raw_reporting_keys,
        raw_correlated_keys,
        hash_legacy_keys,
        hash_reporting_keys,
        hash_correlated_keys,
    )
    payload_keys = set(payload)
    if payload_keys not in accepted_keys:
        raise ValidationError("success result has unexpected, missing, or ambiguous fields")
    if "boxId" in payload:
        box_id = require_string(payload["boxId"], "boxId")
        if not (UUID.fullmatch(box_id) or ULID.fullmatch(box_id)):
            raise ValidationError("boxId must be a UUID or ULID")
        box_id_sha256 = digest(box_id)
    else:
        box_id_sha256 = require_string(payload["boxIdSha256"], "boxIdSha256")
        if not SHA256.fullmatch(box_id_sha256):
            raise ValidationError("boxIdSha256 must be a full lowercase SHA-256 digest")
    hint = payload["canonicalDeviceIdHint"]
    canonical_hash = payload["canonicalDeviceIdSha256"]
    if (hint is None) != (canonical_hash is None):
        raise ValidationError("canonical hint and hash must both be present or both be null")
    if hint is not None:
        if not isinstance(hint, str) or not HINT.fullmatch(hint):
            raise ValidationError("canonicalDeviceIdHint must be a recognized redaction hint")
        if not isinstance(canonical_hash, str) or not SHORT_SHA256.fullmatch(canonical_hash):
            raise ValidationError("canonicalDeviceIdSha256 must be a 16-character lowercase hex digest")
        validate_public_text(hint)
    reporting_endpoint_configured: bool | None = None
    api_key_configured: bool | None = None
    run_id_sha256: str | None = None
    if payload_keys in (raw_reporting_keys, raw_correlated_keys, hash_reporting_keys, hash_correlated_keys):
        reporting_endpoint_configured = require_bool(
            payload["reportingEndpointConfigured"],
            "reportingEndpointConfigured",
        )
        api_key_configured = require_bool(payload["apiKeyConfigured"], "apiKeyConfigured")
        if payload_keys in (raw_correlated_keys, hash_correlated_keys):
            run_id_sha256 = require_run_id_sha256(payload["runIdSha256"])
    require_expected_run_id(run_id_sha256, expected_run_id_sha256)
    return {
        "artifact": ARTIFACT,
        "apiKeyConfigured": api_key_configured,
        "boxIdSha256": box_id_sha256,
        "canonicalDeviceIdHint": hint,
        "canonicalDeviceIdSha256": canonical_hash,
        "durationMs": require_duration(payload["durationMs"]),
        "reportingEndpointConfigured": reporting_endpoint_configured,
        "schemaVersion": SCHEMA_VERSION,
        "status": "success",
        "runIdSha256": run_id_sha256,
    }


def require_run_id_sha256(value: Any) -> str:
    if not isinstance(value, str) or not SHORT_SHA256.fullmatch(value):
        raise ValidationError("runIdSha256 must be a 16-character digest")
    return value


def require_expected_run_id(actual: str | None, expected: str | None) -> None:
    if expected is None:
        return
    if not SHORT_SHA256.fullmatch(expected):
        raise ValidationError("expected run correlation digest has an invalid shape")
    if actual != expected:
        raise ValidationError("terminal result does not match the expected run correlation")


def candidate_objects(text: str, expected_run_id_sha256: str | None = None) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for offset, character in enumerate(text):
        if character != "{":
            continue
        try:
            candidate, _ = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            continue
        if not isinstance(candidate, dict):
            continue
        try:
            normalized = normalize(candidate, expected_run_id_sha256)
        except ValidationError:
            continue
        canonical = json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if canonical not in seen:
            seen.add(canonical)
            candidates.append(candidate)
    return candidates


def read_and_validate(
    path: Path,
    max_age_seconds: int,
    now_epoch: float | None,
    expected_run_id_sha256: str | None = None,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValidationError("input must be a regular, non-symlink artifact file")
    if max_age_seconds < -1:
        raise ValidationError("max-age-seconds must be -1 or non-negative")
    if max_age_seconds >= 0:
        age = (time.time() if now_epoch is None else now_epoch) - path.stat().st_mtime
        if age < -5 or age > max_age_seconds:
            raise ValidationError("artifact is stale or has an ambiguous future mtime")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise ValidationError("artifact is empty, oversized, or has an unsupported encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("artifact is not valid UTF-8 text") from exc
    validate_public_text(text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        candidates = candidate_objects(text, expected_run_id_sha256)
        if len(candidates) != 1:
            raise ValidationError("artifact must contain exactly one terminal sense result")
        payload = candidates[0]
    return normalize(payload, expected_run_id_sha256)


def render(result: dict[str, Any], output_format: str) -> str:
    if output_format == "line":
        return json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    return json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def main() -> int:
    args = parse_args()
    try:
        result = read_and_validate(
            args.input,
            args.max_age_seconds,
            args.now_epoch,
            args.expected_run_id_sha256,
        )
        rendered = render(result, args.format)
        if args.output:
            if args.output.resolve() == args.input.resolve():
                raise ValidationError("output must not overwrite input")
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ValidationError) as exc:
        print(f"parse-cloud-test-sense-result: rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
