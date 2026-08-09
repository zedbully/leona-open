#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = REPO_DIR / "leona-sdk-android/scripts/verify-v0.4-attestation-real-smoke-preflight.py"
MATERIAL_ENV_KEYS = {
    "LEONA_ATTESTATION_SERVER_ROOT",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "LEONA_ATTESTATION_REAL_PROVIDER_TARGET",
    "LEONA_REQUIRE_REAL_ATTESTATION_PROVIDER",
    "LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP",
    "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
    "LEONA_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
    "LEONA_PLAY_INTEGRITY_PACKAGE_NAME",
    "LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS",
    "LEONA_PLAY_INTEGRITY_DEVICE_TOKEN_ARTIFACT",
    "LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS",
    "LEONA_OEM_ATTESTATION_PRIVATE_VERIFIER_READY",
    "LEONA_OEM_ATTESTATION_PROVIDER_NAMESPACE",
    "LEONA_OEM_ATTESTATION_BRIDGE_READY",
}


class AttestationRealSmokePreflightTest(unittest.TestCase):
    def run_preflight(
        self,
        output_dir: Path,
        *,
        target: str = "both",
        require_real_provider: bool = False,
        extra_env: dict[str, str] | None = None,
        include_private_server: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        env = os.environ.copy()
        for key in MATERIAL_ENV_KEYS:
            env.pop(key, None)
        if include_private_server:
            private_server_root = output_dir.parent / "private-server-fixture"
            self.write_private_server_fixture(private_server_root)
            env["LEONA_ATTESTATION_SERVER_ROOT"] = str(private_server_root)
        else:
            env["LEONA_ATTESTATION_SERVER_ROOT"] = str(output_dir.parent / "absent-private-server")
        env.update(extra_env or {})
        command = [
            sys.executable,
            str(SCRIPT),
            "--output-dir",
            str(output_dir),
            "--target",
            target,
        ]
        if require_real_provider:
            command.append("--require-real-provider")
        result = subprocess.run(
            command,
            cwd=REPO_DIR,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        report = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
        return result, report

    @staticmethod
    def write_private_server_fixture(root: Path) -> None:
        files = {
            "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java":
                "PrivateOemAttestationVerifier OEM_ATTESTATION_VERIFIER_MISSING\n",
            "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/PlayIntegrityAttestationVerifiers.java":
                "PrivatePlayIntegrityAttestationVerifier PLAY_INTEGRITY_VERIFIER_MISSING\n",
            "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivatePlayIntegrityAttestationVerifier.java":
                "LEONA_PLAY_INTEGRITY_PACKAGE_NAME LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS PLAY_INTEGRITY_CHALLENGE_MISMATCH\n",
            "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/GooglePlayIntegrityTokenDecoder.java":
                "https://www.googleapis.com/auth/playintegrity https://playintegrity.googleapis.com decodeIntegrityToken\n",
            "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/SessionService.java":
                "leona.handshake.attestation.enforce:false\n",
            "deploy/prod-homeleona/.env.example": (
                "LEONA_HANDSHAKE_ATTESTATION_ENFORCE=false\n"
                "LEONA_HANDSHAKE_ATTESTATION_TRUST_JWS_PAYLOAD_CLAIMS=false\n"
                "LEONA_PLAY_INTEGRITY_PACKAGE_NAME=\n"
                "LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS=\n"
                "LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=\n"
            ),
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_default_both_lane_reports_exact_fail_closed_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result, report = self.run_preflight(Path(temp_dir) / "report")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("local-pass-with-external-blockers", report["status"])
        self.assertEqual(14, report["localCheckCount"])
        self.assertEqual(14, report["localPassCount"])
        self.assertEqual(0, report["localFailureCount"])
        self.assertEqual(10, report["externalBlockerCount"])
        self.assertEqual(
            {"play_integrity": 6, "oem": 4, "other": 0},
            report["externalBlockerCountsByProvider"],
        )
        self.assertEqual([], report["missingExpectedExternalBlockers"])
        self.assertEqual([], report["unexpectedExternalBlockers"])
        self.assertFalse(report["realProviderContacted"])
        self.assertEqual("pass", report["providerReplayStatus"])
        self.assertTrue(report["privateServerContractAvailable"])

    def test_public_checkout_without_private_server_reports_contract_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result, report = self.run_preflight(
                Path(temp_dir) / "report",
                include_private_server=False,
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("local-pass-with-external-blockers", report["status"])
        self.assertEqual(8, report["localCheckCount"])
        self.assertEqual(8, report["localPassCount"])
        self.assertEqual(12, report["externalBlockerCount"])
        self.assertIn("play_integrity_server_verifier_contract", report["externalBlockerCodes"])
        self.assertIn("oem_server_verifier_contract", report["externalBlockerCodes"])
        self.assertFalse(report["privateServerContractAvailable"])

    def test_play_lane_becomes_ready_only_with_private_material_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            adc = root / "adc.json"
            adc.write_text(json.dumps({"type": "external_account"}), encoding="utf-8")
            adc.chmod(0o600)
            token_material = "private-real-device-token-placeholder"
            token = root / "integrity-token.private"
            token.write_text(token_material, encoding="utf-8")
            token.chmod(0o600)
            output = root / "report"
            result, report = self.run_preflight(
                output,
                target="play_integrity",
                extra_env={
                    "LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP": "true",
                    "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER": "123456789012",
                    "LEONA_PLAY_INTEGRITY_PACKAGE_NAME": "io.leonasec.sample",
                    "LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS": "ab" * 32,
                    "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
                    "LEONA_PLAY_INTEGRITY_DEVICE_TOKEN_ARTIFACT": str(token),
                },
            )
            rendered = (output / "summary.json").read_text(encoding="utf-8") + (output / "summary.md").read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ready-for-real-smoke", report["status"])
        self.assertEqual(0, report["externalBlockerCount"])
        self.assertEqual([], report["externalBlockerCodes"])
        self.assertFalse(report["realProviderContacted"])
        self.assertNotIn(token_material, rendered)
        self.assertNotIn(str(adc), rendered)
        self.assertNotIn(str(token), rendered)
        self.assertNotIn("123456789012", rendered)
        self.assertNotIn("io.leonasec.sample", rendered)

    def test_world_readable_private_files_remain_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            adc = root / "adc.json"
            adc.write_text(json.dumps({"type": "service_account"}), encoding="utf-8")
            adc.chmod(0o644)
            token = root / "integrity-token.private"
            token.write_text("world-readable-device-token-placeholder", encoding="utf-8")
            token.chmod(0o644)
            result, report = self.run_preflight(
                root / "report",
                target="play_integrity",
                extra_env={
                    "LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP": "true",
                    "LEONA_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER": "123456789012",
                    "LEONA_PLAY_INTEGRITY_PACKAGE_NAME": "io.leonasec.sample",
                    "LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS": "ab" * 32,
                    "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
                    "LEONA_PLAY_INTEGRITY_DEVICE_TOKEN_ARTIFACT": str(token),
                },
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("local-pass-with-external-blockers", report["status"])
        self.assertEqual(
            {
                "play_integrity_application_default_credentials",
                "play_integrity_device_token_artifact",
            },
            set(report["externalBlockerCodes"]),
        )

    def test_require_real_provider_fails_without_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result, report = self.run_preflight(
                Path(temp_dir) / "report",
                target="play_integrity",
                require_real_provider=True,
            )

        self.assertEqual(1, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertEqual(6, report["externalBlockerCount"])
        self.assertFalse(report["realProviderContacted"])


if __name__ == "__main__":
    unittest.main()
