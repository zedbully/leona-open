from __future__ import annotations

import base64
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run-public-hosted-reporting-fixture.py"
SPEC = importlib.util.spec_from_file_location("leona_public_hosted_fixture", SCRIPT)
assert SPEC and SPEC.loader
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class PublicHostedReportingFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.receipt = Path(self.temp_dir.name) / "receipt.json"
        self.api_key = "fixture-key-material-must-not-persist"
        self.request_id = "raw-request-id-must-not-persist"
        self.payload = b"raw-native-payload-must-not-persist"
        self.server, _state = FIXTURE.build_server(
            host="127.0.0.1",
            port=0,
            api_key=self.api_key,
            receipt_path=self.receipt,
            max_requests=0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _body(self, *, encoded_payload: str | None = None) -> dict[str, object]:
        return {
            "mode": "public_hosted",
            "requestId": self.request_id,
            "sdkVersion": "0.4.0",
            "payloadEncoding": "base64",
            "payload": encoded_payload or base64.b64encode(self.payload).decode("ascii"),
            "deviceContext": {
                "sdkInt": 23,
                "evidenceSignals": ["environment.emulator.detected"],
                "nativeFactTags": ["native.runtime.available"],
                "nativeFindingIds": [],
                "installIdSha256": "a" * 64,
                "resolvedDeviceIdSha256": "b" * 64,
            },
        }

    def _post(self, body: dict[str, object], *, api_key: str | None = None) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + "/v1/sense/public",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Leona-App-Key": self.api_key if api_key is None else api_key,
                "X-Leona-SDK-Version": "0.4.0",
                "X-Leona-Reporting-Mode": "public_hosted",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_authorized_report_returns_opaque_ids_without_business_decision(self) -> None:
        status, response = self._post(self._body())
        self.assertEqual(200, status)
        self.assertRegex(response["boxId"], r"^[0-9a-f-]{36}$")
        self.assertRegex(response["canonicalDeviceId"], r"^L[0-9a-f]{64}$")
        forbidden = {"decision", "action", "allow", "deny", "riskScore", "riskLevel"}
        self.assertTrue(forbidden.isdisjoint(response))

        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("pass", receipt["status"])
        self.assertEqual(0o600, self.receipt.stat().st_mode & 0o777)
        self.assertEqual(23, receipt["sdkInt"])
        self.assertTrue(receipt["apiKeyAccepted"])
        self.assertFalse(receipt["businessDecisionProduced"])
        self.assertFalse(receipt["secretValuesPrinted"])
        self.assertFalse(receipt["rawIdentifiersPrinted"])
        receipt_text = self.receipt.read_text(encoding="utf-8")
        self.assertNotIn(self.api_key, receipt_text)
        self.assertNotIn(self.request_id, receipt_text)
        self.assertNotIn(self.payload.decode("utf-8"), receipt_text)
        for value in response.values():
            self.assertNotIn(str(value), receipt_text)

    def test_unauthorized_report_is_rejected_without_receipt(self) -> None:
        status, response = self._post(self._body(), api_key="wrong-key")
        self.assertEqual(401, status)
        self.assertEqual({"error": "unauthorized"}, response)
        self.assertFalse(self.receipt.exists())

    def test_malformed_payload_is_rejected_without_receipt(self) -> None:
        status, response = self._post(self._body(encoded_payload="not strict base64%%"))
        self.assertEqual(400, status)
        self.assertEqual({"error": "invalid_report"}, response)
        self.assertFalse(self.receipt.exists())

    def test_health_endpoint_discloses_no_credential(self) -> None:
        with urllib.request.urlopen(self.base_url + "/healthz", timeout=5) as response:
            body = response.read().decode("utf-8")
        self.assertIn('"status": "ready"', body)
        self.assertNotIn(self.api_key, body)
        self.assertIn('"businessDecisionProduced": false', body)


if __name__ == "__main__":
    unittest.main()
