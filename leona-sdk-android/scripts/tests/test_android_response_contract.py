#!/usr/bin/env python3
"""Contract custody and fail-closed checks for the response-only LPRESP01 lane."""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTO = ROOT / "sdk/src/main/proto/leona/evidence/response/v1/response.proto"
DESCRIPTOR = ROOT / "sdk/src/main/resources/leona/evidence/response/v1/response.pb"
PAYLOAD = ROOT / "sdk/src/test/resources/leona/evidence/response/v1/valid-response.bin"
CARRIER = ROOT / "sdk/src/test/resources/leona/evidence/response/v1/valid-response-carrier.bin"
ENVELOPE = ROOT / "sdk/src/test/resources/leona/evidence/response/v1/valid-response-envelope.bin"
MANIFEST = ROOT / "sdk/src/main/proto/leona/evidence/response/v1/codegen-manifest.json"
CARRIER_KT = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/proto/LeonaProtectedResponseCarrierV1.kt"
CODEC_KT = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/proto/LeonaEvidenceResponseProtobufCodec.kt"
CHANNEL_KT = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/SecureChannel.kt"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AndroidResponseContractTest(unittest.TestCase):
    def test_authoritative_response_files_are_byte_identical(self):
        self.assertEqual(sha(PROTO), "90b2f2753c3cdf9e86d3690ec5e37c3de15873267bcb0b1b26f5a4091918619c")
        self.assertEqual(sha(DESCRIPTOR), "01ca791bcbd4e7727da47e8d0351538c32e4f40394927676372a4d8d23ca6e73")
        self.assertEqual(sha(PAYLOAD), "38c53d6f2635ba836853d45f5fc20f27ed9eae7fe047e63c398ca933a6bbc8a1")
        self.assertEqual(sha(CARRIER), "34a10a47d1334621089bc9614f892703bf63b4ca178e74c611fe7e49b7dc43ac")
        self.assertEqual(sha(ENVELOPE), "a585599e283207be3cee6e16c03add73de64dbad7413773ab0b81b33d04d0ac5")

    def test_response_schema_is_closed_and_reserved(self):
        source = PROTO.read_text()
        for marker in (
            "package leona.evidence.response.v1",
            "protocol_major = 1", "request_id = 2", "request_carrier_sha256 = 3",
            "response_id = 4", "box_id = 5", "server_install_id = 6",
            "canonical_device_id = 7", "issued_at_epoch_ms = 8",
            "box_expires_at_epoch_ms = 9", "collection_status = 10",
            "reserved 11 to 31", "COLLECTION_STATUS_ACCEPTED = 1",
        ):
            self.assertIn(marker, source)
        declarations = "\n".join(line.split("//", 1)[0] for line in source.splitlines())
        self.assertNotRegex(declarations, r"\b(risk|decision|score|policy|Any|Struct)\b|map\s*<")

    def test_response_manifest_matches_files(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(manifest["source"]["sha256"], sha(PROTO))
        self.assertEqual(manifest["descriptor"]["sha256"], sha(DESCRIPTOR))
        self.assertEqual(manifest["golden"]["sha256"], sha(PAYLOAD))
        self.assertEqual(manifest["protoc"], "libprotoc 31.1")

    def test_response_carrier_and_codec_keep_response_only_bounds(self):
        carrier = CARRIER_KT.read_text()
        codec = CODEC_KT.read_text()
        self.assertIn('"LPRESP01"', carrier)
        self.assertIn("MAX_PAYLOAD_BYTES = 65_536", carrier)
        self.assertIn("MAX_CARRIER_BYTES = 65_709", carrier)
        self.assertIn("DESCRIPTOR_SHA256_HEX = \"01ca791bcbd4e7727da47e8d0351538c32e4f40394927676372a4d8d23ca6e73\"", codec)
        for marker in ("UNKNOWN_FIELD", "DUPLICATE_FIELD", "NON_MINIMAL_VARINT", "UNKNOWN_ENUM", "INVALID_UTF8"):
            self.assertIn(marker, codec)

    def test_typed_channel_parses_strict_response_before_legacy_json(self):
        source = CHANNEL_KT.read_text()
        start = source.index("if (typedResponse != null)")
        end = source.index("val body = response.body.toString", start)
        typed = source[start:end]
        self.assertIn("LeonaProtectedResponseCarrierV1.decode", typed)
        self.assertIn("LeonaEvidenceResponseProtobufCodec.decode", typed)
        self.assertNotIn("JSONObject", typed)
        self.assertIn("decision = \"evidence_collected\"", typed)
        self.assertIn("action = \"business_defined\"", typed)


if __name__ == "__main__":
    unittest.main()
