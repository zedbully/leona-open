import unittest
import urllib.error
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import query_boxid


class QueryBoxIdSignatureTest(unittest.TestCase):
    def test_fixed_dry_run_signature(self):
        signed = query_boxid.build_signed_request(
            secret="test_secret_do_not_use",
            box_id="123e4567-e89b-42d3-a456-426614174000",
            endpoint=query_boxid.DEFAULT_ENDPOINT,
            timestamp="1700000000000",
            nonce="nonce_for_dry_run",
        )

        self.assertEqual(signed["body"], '{"boxId":"123e4567-e89b-42d3-a456-426614174000"}')
        self.assertEqual(
            signed["bodySha256"],
            "7ce622a9473ffbe7ed390c57efa3705747981e316ace1fa56000072f20ac7958",
        )
        self.assertEqual(
            signed["headers"]["X-Leona-Signature"],
            "flTDOGc3Xu5CXjzgeMWnyd1GF0O5X6VXtMbhSgsLU7Y",
        )

    def test_endpoint_rejects_non_http_and_credential_urls(self):
        for endpoint in (
            "file:///etc/passwd",
            "ftp://example.invalid/v1/verdict",
            "https://user:password@example.invalid/v1/verdict",
            "https://example.invalid/v1/verdict?secret=value",
            "https://example.invalid/other",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(SystemExit):
                query_boxid.validate_endpoint(endpoint)

    def test_loopback_http_requires_explicit_local_test_opt_in(self):
        endpoint = "http://127.0.0.1:18080/v1/verdict"
        with self.assertRaises(SystemExit):
            query_boxid.validate_endpoint(endpoint)
        self.assertEqual(
            endpoint,
            query_boxid.validate_endpoint(endpoint, allow_loopback_http=True),
        )

    def test_https_endpoint_is_accepted(self):
        self.assertEqual(
            query_boxid.DEFAULT_ENDPOINT,
            query_boxid.validate_endpoint(query_boxid.DEFAULT_ENDPOINT),
        )

    def test_signed_requests_never_follow_redirects(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            query_boxid.RejectRedirects().redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://attacker.invalid/v1/verdict",
            )
        raised.exception.close()

    def test_redacted_dry_run_shape_contains_no_request_material(self):
        signed = query_boxid.build_signed_request(
            secret="test_secret_do_not_use",
            box_id="123e4567-e89b-42d3-a456-426614174000",
            endpoint=query_boxid.DEFAULT_ENDPOINT,
            timestamp="1700000000000",
            nonce="nonce_for_dry_run",
        )
        redacted = dict(signed)
        redacted["body"] = "[REDACTED]"
        redacted["headers"] = dict(signed["headers"])
        redacted["headers"]["Authorization"] = "Bearer [REDACTED]"
        redacted["headers"]["X-Leona-Signature"] = "[REDACTED]"
        output = str(redacted)
        self.assertNotIn("test_secret_do_not_use", output)
        self.assertNotIn("123e4567-e89b-42d3-a456-426614174000", output)
        self.assertNotIn(signed["headers"]["X-Leona-Signature"], output)


if __name__ == "__main__":
    unittest.main()
