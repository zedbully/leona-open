#!/usr/bin/env python3
"""Artifact and behavior contract for the frozen Android protobuf lane."""
import hashlib
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTO = ROOT / "sdk/src/main/proto/leona/evidence/v1/ingest.proto"
DESCRIPTOR = ROOT / "sdk/src/main/resources/leona/evidence/v1/ingest.pb"
GOLDEN = ROOT / "sdk/src/test/resources/leona/evidence/v1/valid-ingest.bin"
CODEC = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/proto/LeonaEvidenceProtobufCodec.kt"
CHANNEL = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/SecureChannel.kt"
LEONA = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/Leona.kt"
DOC = ROOT / "docs/v1-android-protobuf.md"
MANIFEST = ROOT / "sdk/src/main/proto/leona/evidence/v1/codegen-manifest.json"
SBOM = ROOT / "sdk/src/main/proto/leona/evidence/v1/sbom.json"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AndroidProtobufContractTest(unittest.TestCase):
    def test_frozen_artifacts_and_generated_bindings(self):
        self.assertEqual(sha256(PROTO), "e93b2c21f55db26f0179be7d18e35ea2a5005786f8e43e3a6027ddf59b9268a3")
        self.assertEqual(sha256(DESCRIPTOR), "1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703")
        self.assertEqual(sha256(GOLDEN), "b372aee07b4372234bcdfa102bbbd05e1f7e68d1d15b6a2f9164bde4af89d1da")
        generated = list((ROOT / "sdk/src/main/java/io/leonasec/proto/v1").glob("*.java"))
        self.assertEqual(len(generated), 12)
        self.assertTrue(all("Protobuf Java Version: 4.29.4" in p.read_text() for p in generated))

    def test_codegen_manifest_is_reproducible(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(manifest["source"]["sha256"], sha256(PROTO))
        self.assertEqual(manifest["descriptor"]["sha256"], sha256(DESCRIPTOR))
        self.assertEqual(manifest["golden"]["sha256"], sha256(GOLDEN))
        self.assertEqual(manifest["protoc"], "libprotoc 29.4")
        generated = sorted((ROOT / "sdk/src/main/java/io/leonasec/proto/v1").glob("*.java"))
        h = hashlib.sha256()
        for path in generated:
            h.update(path.relative_to(ROOT).as_posix().encode())
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
        self.assertEqual(manifest["generated_sources"]["sha256_path_and_bytes"], h.hexdigest())
        sbom = json.loads(SBOM.read_text())
        component = sbom["components"][0]
        self.assertEqual(component["purl"], "pkg:maven/com.google.protobuf/protobuf-javalite@4.29.4")
        self.assertEqual(component["hashes"][0]["content"], "622f9ddfd99e8391efb5b2be5cb149dacaba1104905635eecf6ceac8e43e122e")

    def test_schema_numbers_reserved_and_closed_oneof(self):
        source = PROTO.read_text()
        for field in ("protocol_major = 1", "tenant_id = 2", "evidence_batch = 12", "enum_value = 10"):
            self.assertIn(field, source)
        self.assertIn("reserved 13 to 15", source)
        self.assertIn("oneof value", source)
        self.assertNotRegex(source, r"\b(Any|Struct)\b|map\s*<")

    def test_codec_has_bounds_descriptor_and_no_downgrade(self):
        source = CODEC.read_text()
        for marker in ("DEFAULT_APP_CAP_BYTES = 128 * 1024", "MAX_ENTRIES", "WireValidator", "LEONA_SCHEMA_DIGEST", "ExternalBlocked", "private constructor"):
            self.assertIn(marker, source)
        self.assertIn("digest.contentEquals(LEONA_SCHEMA_DIGEST)", source)
        self.assertIn("MALFORMED_WIRE", source)
        self.assertIn("INVALID_ONEOF", source)
        self.assertNotRegex(source, r"(?i)json|plaintext|fallback")

    def test_typed_handoff_encodes_carrier_before_existing_upload(self):
        source = CHANNEL.read_text()
        self.assertIn("uploadProtectedLogicalPayload", source)
        self.assertIn("PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE", source)
        self.assertIn("LeonaProtectedPayloadCarrierV1", source)
        encode_at = source.index("protectedPayloadEncoder(handoff)")
        upload_match = re.search(r"return\s+uploadInternal\(\s*carrier\s*,\s*deviceContext\s*,\s*includeDeviceContextHeaders\s*=\s*false\s*\)", source)
        self.assertIsNotNone(upload_match)
        upload_at = upload_match.start()
        self.assertLess(encode_at, upload_at)
        self.assertNotIn("typed protobuf descriptor carrier is not admitted", source)
        # Existing transport remains Leo media type only; no new clear custom headers.
        self.assertNotRegex(source, r"setHeader\(\s*\"X-(?:Leona|Leo)-")

    def test_public_sense_never_uploads_raw_native_body(self):
        source = LEONA.read_text()
        start = source.index("suspend fun sense()")
        end = source.index("Shared production/test seam", start)
        sense = source[start:end]
        self.assertIn("NativeBridge.collect()", sense)
        self.assertIn("runTypedSense", sense)
        self.assertIn("uploadProtectedLogicalPayload", sense)
        self.assertNotRegex(sense, r"\.upload\(\s*payload\s*=\s*payload")

    def test_dependency_pin_and_consumer_rule(self):
        gradle = (ROOT / "sdk/build.gradle.kts").read_text()
        versions = (ROOT / "gradle/libs.versions.toml").read_text()
        rules = (ROOT / "sdk/consumer-rules.pro").read_text()
        self.assertIn("libs.protobuf.javalite", gradle)
        self.assertIn('protobuf = "4.29.4"', versions)
        self.assertIn("io.leonasec.proto.v1", rules)

    def test_docs_keep_runtime_and_admission_separate(self):
        source = DOC.read_text()
        self.assertIn("128 KiB", source)
        self.assertIn("NOT_RUN/BLOCKED", source)
        self.assertIn("typed error before HTTP", source)
        self.assertNotIn("8 MiB", source)
        self.assertNotRegex(source, r"clear HTTP headers.*X-Leona")


if __name__ == "__main__":
    unittest.main()
