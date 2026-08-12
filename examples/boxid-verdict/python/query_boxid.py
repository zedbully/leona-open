#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_ENDPOINT = "https://leona.xiyanshan.com/v1/verdict"


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            new_url,
            code,
            "Redirects are forbidden for signed Leona requests",
            headers,
            file_pointer,
        )


def base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def validate_endpoint(endpoint: str, *, allow_loopback_http: bool = False) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.username is not None or parsed.password is not None:
        raise SystemExit("LEONA_ENDPOINT must not contain URL credentials")
    if parsed.query or parsed.fragment:
        raise SystemExit("LEONA_ENDPOINT must not contain query or fragment data")
    if not parsed.hostname or parsed.path != "/v1/verdict":
        raise SystemExit("LEONA_ENDPOINT must be an absolute /v1/verdict URL")
    hostname = parsed.hostname.lower()
    loopback = hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "https":
        return endpoint
    if parsed.scheme == "http" and loopback and allow_loopback_http:
        return endpoint
    raise SystemExit("LEONA_ENDPOINT must use HTTPS (or explicit loopback HTTP for local tests)")


def build_signed_request(secret: str, box_id: str, endpoint: str, timestamp: str, nonce: str) -> dict:
    body = json.dumps({"boxId": box_id}, separators=(",", ":")).encode("utf-8")
    body_sha256 = hashlib.sha256(body).hexdigest()
    signing_text = f"{timestamp}\n{nonce}\n{body_sha256}".encode("utf-8")
    signature = base64url_no_padding(
        hmac.new(secret.encode("utf-8"), signing_text, hashlib.sha256).digest()
    )
    return {
        "endpoint": endpoint,
        "body": body.decode("utf-8"),
        "bodySha256": body_sha256,
        "headers": {
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "X-Leona-Timestamp": timestamp,
            "X-Leona-Nonce": nonce,
            "X-Leona-Signature": signature,
        },
    }


def main() -> int:
    secret = require_env("LEONA_SECRET_KEY")
    box_id = require_env("BOX_ID")
    endpoint = validate_endpoint(
        os.environ.get("LEONA_ENDPOINT", DEFAULT_ENDPOINT),
        allow_loopback_http=os.environ.get("LEONA_ALLOW_LOOPBACK_HTTP") == "1",
    )

    timestamp = os.environ.get("LEONA_TIMESTAMP", str(int(time.time() * 1000)))
    nonce = os.environ.get("LEONA_NONCE", base64url_no_padding(secrets.token_bytes(16)))
    signed = build_signed_request(secret, box_id, endpoint, timestamp, nonce)

    if os.environ.get("LEONA_DRY_RUN") == "1":
        redacted = dict(signed)
        redacted["body"] = "[REDACTED]"
        redacted["headers"] = dict(signed["headers"])
        redacted["headers"]["Authorization"] = "Bearer [REDACTED]"
        redacted["headers"]["X-Leona-Signature"] = "[REDACTED]"
        json.dump(redacted, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    request = urllib.request.Request(
        endpoint,
        data=signed["body"].encode("utf-8"),
        method="POST",
        headers=signed["headers"],
    )

    try:
        opener = urllib.request.build_opener(RejectRedirects())
        with opener.open(request, timeout=15) as response:
            sys.stdout.write(response.read().decode("utf-8"))
            sys.stdout.write("\n")
            return 0
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"Leona query failed: HTTP {exc.code}\n")
        sys.stderr.write(exc.read().decode("utf-8", errors="replace"))
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
