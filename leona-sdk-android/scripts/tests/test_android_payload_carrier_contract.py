#!/usr/bin/env python3
"""Pure contract corpus for the frozen LPCARR01 request carrier."""
import hashlib
import pathlib
import struct
import unittest
import json
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
CARRIER = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/proto/LeonaProtectedPayloadCarrierV1.kt"
GOLDEN = ROOT / "sdk/src/test/resources/leona/evidence/v1/valid-carrier.bin"
DOC = ROOT / "docs/v1-android-protected-carrier.md"
VECTORS = ROOT / "sdk/src/test/resources/leona/evidence/v1/tamper-vectors.json"
HTTP_CLIENT = ROOT / "sdk/src/main/kotlin/io/leonasec/leona/internal/LeonaCryptoHttpClient.kt"
EXPECTED_DIGEST = bytes.fromhex("1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703")
CODEC = b"LEONA_PROTOBUF"
SCHEMA = b"leona.evidence.v1"
MESSAGE = b"leona.evidence.v1.EvidenceIngestRequest"


def parse_carrier(raw: bytes, validate_proto: bool = True):
    if len(raw) > 131226:
        return "OVERSIZE"
    if len(raw) < 12:
        return "TRUNCATED"
    if raw[:8] != b"LPCARR01":
        return "BAD_MAGIC"
    if raw[8] != 1:
        return "UNSUPPORTED_VERSION"
    if raw[9] != 5:
        return "FIELD_COUNT_MISMATCH"
    if struct.unpack(">H", raw[10:12])[0] != 0:
        return "NONZERO_RESERVED"
    offset, previous, values = 12, 0, {}
    for _ in range(5):
        if len(raw) - offset < 8:
            return "TRUNCATED"
        tag, flags = raw[offset], raw[offset + 1]
        reserved = struct.unpack(">H", raw[offset + 2:offset + 4])[0]
        length = struct.unpack(">I", raw[offset + 4:offset + 8])[0]
        if tag not in range(1, 6):
            return "UNKNOWN_TAG"
        if tag == previous:
            return "DUPLICATE_TAG"
        if tag < previous:
            return "OUT_OF_ORDER_TAG"
        if flags:
            return "NONZERO_FLAGS"
        if reserved:
            return "NONZERO_RESERVED"
        end = offset + 8 + length
        if end < offset or end > len(raw):
            return "TRUNCATED"
        values[tag] = raw[offset + 8:end]
        previous, offset = tag, end
    if offset != len(raw):
        return "TRAILING_BYTES"
    if any(tag not in values for tag in range(1, 6)):
        return "FIELD_COUNT_MISMATCH"
    try:
        for tag in (1, 2, 3):
            values[tag].decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "INVALID_UTF8"
    if values[1] != CODEC or values[2] != SCHEMA or values[3] != MESSAGE or values[4] != EXPECTED_DIGEST:
        return "DESCRIPTOR_MISMATCH"
    if not values[5]:
        return "EMPTY_PAYLOAD"
    if len(values[5]) > 131072:
        return "OVERSIZE"
    # Carrier-layer vectors may intentionally use non-Protobuf bytes at max.
    if validate_proto and values[5] != GOLDEN.read_bytes()[154:]:
        return "PROTOBUF_REJECTED"
    return "PASS"


def tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag, 0)) + b"\0\0" + struct.pack(">I", len(value)) + value


def build(payload: bytes = None) -> bytes:
    if payload is None:
        payload = GOLDEN.read_bytes()[154:]
    return b"LPCARR01" + bytes((1, 5)) + b"\0\0" + b"".join(
        [tlv(1, CODEC), tlv(2, SCHEMA), tlv(3, MESSAGE), tlv(4, EXPECTED_DIGEST), tlv(5, payload)]
    )


class AndroidPayloadCarrierContractTest(unittest.TestCase):
    def test_frozen_golden_shape_and_digest(self):
        golden = GOLDEN.read_bytes()
        self.assertEqual(len(golden), 339)
        self.assertEqual(hashlib.sha256(golden).hexdigest(), "c568be45ad673497265fb4634eaa9767ed76383cb67c52a4e8aef64aaead4bd3")
        self.assertEqual(parse_carrier(golden), "PASS")
        self.assertEqual(hashlib.sha256(VECTORS.read_bytes()).hexdigest(), "e6c0afc9236bacc8d959f039b8a53ac616c85cf95c519a492544d650aee17e81")

    def test_all_23_frozen_vectors(self):
        golden = GOLDEN.read_bytes()
        cases = []
        cases.append(("valid", "PASS", golden))
        def mutate(name, expected, fn):
            value = bytearray(golden); fn(value); cases.append((name, expected, bytes(value)))
        mutate("bad-magic", "BAD_MAGIC", lambda x: x.__setitem__(0, 0))
        mutate("bad-version", "UNSUPPORTED_VERSION", lambda x: x.__setitem__(8, 2))
        mutate("bad-count", "FIELD_COUNT_MISMATCH", lambda x: x.__setitem__(9, 4))
        mutate("header-reserved", "NONZERO_RESERVED", lambda x: x.__setitem__(10, 1))
        mutate("unknown-tag", "UNKNOWN_TAG", lambda x: x.__setitem__(59, 6))
        mutate("duplicate-tag", "DUPLICATE_TAG", lambda x: x.__setitem__(34, 1))
        mutate("out-of-order", "OUT_OF_ORDER_TAG", lambda x: x.__setitem__(59, 1))
        mutate("tlv-flags", "NONZERO_FLAGS", lambda x: x.__setitem__(13, 1))
        mutate("tlv-reserved", "NONZERO_RESERVED", lambda x: x.__setitem__(14, 1))
        mutate("codec-mismatch", "DESCRIPTOR_MISMATCH", lambda x: x.__setitem__(20, ord("X")))
        mutate("schema-mismatch", "DESCRIPTOR_MISMATCH", lambda x: x.__setitem__(42, ord("X")))
        mutate("message-mismatch", "DESCRIPTOR_MISMATCH", lambda x: x.__setitem__(67, ord("X")))
        mutate("digest-mismatch", "DESCRIPTOR_MISMATCH", lambda x: x.__setitem__(114, 0))
        mutate("invalid-utf8", "INVALID_UTF8", lambda x: x.__setitem__(20, 0x80))
        empty = bytearray(golden[:154]); empty[150:154] = b"\0\0\0\0"; cases.append(("empty-payload", "EMPTY_PAYLOAD", bytes(empty)))
        cases.append(("max-payload", "PASS", build(b"\0" * 131072)))
        cases.append(("max-plus-one", "OVERSIZE", build(b"\0" * 131073)))
        cases.append(("truncated-header", "TRUNCATED", golden[:11]))
        mutate("truncated-value", "TRUNCATED", lambda x: x.__setitem__(16, 0x7f))
        cases.append(("trailing-byte", "TRAILING_BYTES", golden + b"\0"))
        malformed = bytearray(golden); malformed[154] = 0; cases.append(("malformed-protobuf", "PROTOBUF_REJECTED", bytes(malformed)))
        cases.append(("provider-tamper", "EXTERNAL_BLOCKED", None))
        frozen = json.loads(VECTORS.read_text())
        self.assertEqual([v["id"] for v in frozen["vectors"]], [name for name, _, _ in cases])
        self.assertEqual(len(cases), 23)
        for name, expected, value in cases:
            if name == "provider-tamper":
                self.assertEqual(expected, "EXTERNAL_BLOCKED")
                continue
            actual = parse_carrier(value, validate_proto=name != "max-payload")
            self.assertEqual(expected, actual, name)

    def test_source_and_docs_preserve_boundaries(self):
        source, doc = CARRIER.read_text(), DOC.read_text()
        for marker in ("LPCARR01", "MAX_PAYLOAD_BYTES = 131_072", "MAX_CARRIER_BYTES = 131_226", "decodeRequest", "checkedAdd"):
            self.assertIn(marker, source)
        self.assertIn("request-only", doc)
        self.assertIn("EXTERNAL_BLOCKED", doc)
        self.assertIn("User-Agent", doc)
        self.assertIn("Accept-Encoding", doc)
        self.assertIn("CookieJar", doc)
        self.assertIn("synthetic test seam", doc)
        self.assertIn("externally reachable", doc)
        self.assertNotRegex(doc, r"(?i)JSON/plaintext/custom-crypto fallback")
        self.assertNotRegex(source, r"(?i)clear\s+HTTP|X-Leona-|X-Leo-")

    def test_outer_http_headers_are_not_expanded(self):
        client = HTTP_CLIENT.read_text()
        doc = DOC.read_text()
        explicit = re.findall(r'\.header\(\s*"([^"]+)"', client)
        self.assertEqual(set(explicit), {"Content-Type", "Accept"})
        self.assertIn(".cookieJar(CookieJar.NO_COOKIES)", client)
        self.assertIn(".addNetworkInterceptor(StrictOuterResponseInterceptor())", client)
        for marker in (
            "Content-Encoding",
            "Set-Cookie",
            "duplicate content-length",
            "content-length does not match body bytes",
            "readBoundedBody",
        ):
            self.assertIn(marker, client)
        self.assertIn("User-Agent", doc)
        self.assertIn("Accept-Encoding", doc)
        self.assertIn("Cookie", doc)


if __name__ == "__main__":
    unittest.main()
