from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-v0.4-domestic-private-distribution.py"
GROUP = "io.leonasec"
ARTIFACT = "leona-sdk-android"
VERSION = "0.4.0"
COORDINATE = f"{GROUP}:{ARTIFACT}:{VERSION}"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DomesticPrivateDistributionVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("gpg") is None:
            raise unittest.SkipTest("gpg is required")
        # Keep the GnuPG socket path short on macOS; the default per-user temp
        # root can exceed the Unix-domain socket length limit.
        cls.key_root = Path(tempfile.mkdtemp(prefix="leona-dist-test-key-", dir="/tmp"))
        cls.gpg_home = cls.key_root / "gnupg"
        cls.gpg_home.mkdir(mode=0o700)
        spec = cls.key_root / "key-spec"
        spec.write_text(
            """Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: Leona Distribution Test
Name-Email: test@invalid.local
Expire-Date: 1d
%no-protection
%commit
"""
        )
        os.chmod(spec, 0o600)
        subprocess.run(
            ["gpg", "--batch", "--homedir", str(cls.gpg_home), "--generate-key", str(spec)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        listing = subprocess.check_output(
            ["gpg", "--batch", "--homedir", str(cls.gpg_home), "--with-colons", "--list-secret-keys"],
            text=True,
        )
        cls.fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        )
        cls.public_key = cls.key_root / "public-key.asc"
        cls.public_key.write_bytes(
            subprocess.check_output(
                ["gpg", "--batch", "--homedir", str(cls.gpg_home), "--armor", "--export", cls.fingerprint]
            )
        )
        cls.private_key = cls.key_root / "private-key.asc"
        cls.private_key.write_bytes(
            subprocess.check_output(
                [
                    "gpg",
                    "--batch",
                    "--homedir",
                    str(cls.gpg_home),
                    "--armor",
                    "--export-secret-keys",
                    cls.fingerprint,
                ]
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.key_root)

    def create_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        repository = root / "repository"
        coordinate_dir = repository.joinpath(*GROUP.split("."), ARTIFACT, VERSION)
        coordinate_dir.mkdir(parents=True)
        base = f"{ARTIFACT}-{VERSION}"

        classes_buffer = io.BytesIO()
        with zipfile.ZipFile(classes_buffer, "w") as classes:
            classes.writestr("io/leonasec/leona/Leona.class", b"test-class")
            # The public evidence-provider abstraction is allowed; only the
            # Google Play SDK runtime package is forbidden from the bundle.
            classes.writestr(
                "io/leonasec/leona/attestation/PlayIntegrityAttestationProvider.class",
                b"test-interface",
            )
        with zipfile.ZipFile(coordinate_dir / f"{base}.aar", "w") as aar:
            aar.writestr("classes.jar", classes_buffer.getvalue())
            aar.writestr("R.txt", "")
        for classifier in ("sources", "javadoc"):
            with zipfile.ZipFile(coordinate_dir / f"{base}-{classifier}.jar", "w") as jar:
                jar.writestr("README.txt", classifier)

        pom = coordinate_dir / f"{base}.pom"
        pom.write_text(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>{GROUP}</groupId>
  <artifactId>{ARTIFACT}</artifactId>
  <version>{VERSION}</version>
  <packaging>aar</packaging>
  <dependencies>
    <dependency><groupId>androidx.core</groupId><artifactId>core-ktx</artifactId><version>1.13.1</version></dependency>
    <dependency><groupId>org.jetbrains.kotlinx</groupId><artifactId>kotlinx-coroutines-android</artifactId><version>1.8.1</version></dependency>
    <dependency><groupId>com.squareup.okhttp3</groupId><artifactId>okhttp</artifactId><version>4.12.0</version></dependency>
  </dependencies>
</project>
"""
        )
        aar_path = coordinate_dir / f"{base}.aar"
        sources_path = coordinate_dir / f"{base}-sources.jar"
        javadoc_path = coordinate_dir / f"{base}-javadoc.jar"
        module = coordinate_dir / f"{base}.module"
        module.write_text(
            json.dumps(
                {
                    "formatVersion": "1.1",
                    "component": {
                        "group": GROUP,
                        "module": ARTIFACT,
                        "version": VERSION,
                        "attributes": {"org.gradle.status": "release"},
                    },
                    "variants": [
                        {
                            "name": "runtime",
                            "dependencies": [
                                {"group": "androidx.core", "module": "core-ktx", "version": {"requires": "1.13.1"}},
                                {"group": "org.jetbrains.kotlinx", "module": "kotlinx-coroutines-android", "version": {"requires": "1.8.1"}},
                                {"group": "com.squareup.okhttp3", "module": "okhttp", "version": {"requires": "4.12.0"}},
                            ],
                            "files": [self.module_file(aar_path)],
                        },
                        {"name": "sources", "files": [self.module_file(sources_path)]},
                        {"name": "javadoc", "files": [self.module_file(javadoc_path)]},
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

        for artifact_path in sorted(
            p for p in coordinate_dir.iterdir() if p.suffix in {".aar", ".pom", ".module", ".jar"}
        ):
            self.sign_and_checksum(artifact_path)

        consumer = root / "consumer-summary.json"
        consumer.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "coordinate": COORDINATE,
                    "repositoryArtifactAarSha256": digest(aar_path),
                    "resolvedArtifactExtension": "aar",
                    "requiredTransitives": ["core-ktx", "kotlinx-coroutines-android", "okhttp"],
                    "noGoogleRuntimeDependency": True,
                    "sdkDecisionRole": "collect-and-report-evidence",
                    "businessDecisionOwner": "customer-backend",
                    "commercialAdmissionClaimed": False,
                    "secretValuesPrinted": False,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        return repository, coordinate_dir, consumer

    @staticmethod
    def module_file(path: Path) -> dict[str, object]:
        return {"name": path.name, "url": path.name, "size": path.stat().st_size, "sha256": digest(path)}

    def sign_and_checksum(self, path: Path) -> None:
        signature = path.with_name(path.name + ".asc")
        if signature.exists():
            signature.unlink()
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(self.gpg_home),
                "--local-user",
                self.fingerprint,
                "--armor",
                "--detach-sign",
                "--output",
                str(signature),
                str(path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        path.with_name(path.name + ".sha256").write_text(f"{digest(path)}  {path.name}\n")

    def run_verifier(
        self,
        repository: Path,
        consumer: Path,
        output: Path,
        public_key: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--repository-dir",
                str(repository),
                "--public-key",
                str(public_key or self.public_key),
                "--consumer-summary",
                str(consumer),
                "--output-dir",
                str(output),
                *(extra_args or []),
            ],
            capture_output=True,
            text=True,
        )

    def test_valid_signed_bundle_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, _, consumer = self.create_fixture(root)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("pass", report["status"])
        self.assertEqual(5, report["artifactCount"])
        self.assertTrue(report["signaturesVerified"])
        self.assertTrue(report["checksumsVerified"])
        self.assertTrue(report["consumerVerified"])
        self.assertTrue(report["noGoogleRuntimeDependency"])
        self.assertFalse(report["commercialAdmissionClaimed"])

    def test_tampered_aar_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            with (coordinate_dir / f"{ARTIFACT}-{VERSION}.aar").open("ab") as handle:
                handle.write(b"tamper")
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertTrue(any("checksum" in failure or "signature" in failure for failure in report["failures"]))

    def test_private_key_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, _, consumer = self.create_fixture(root)
            result = self.run_verifier(repository, consumer, root / "output", self.private_key)
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("private key material" in failure for failure in report["failures"]))

    def test_play_integrity_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            pom = coordinate_dir / f"{ARTIFACT}-{VERSION}.pom"
            text = pom.read_text().replace(
                "</dependencies>",
                "<dependency><groupId>com.google.android.play</groupId><artifactId>integrity</artifactId><version>1.6.0</version></dependency></dependencies>",
            )
            pom.write_text(text)
            self.sign_and_checksum(pom)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("Google runtime dependency" in failure for failure in report["failures"]))

    def test_non_play_google_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            pom = coordinate_dir / f"{ARTIFACT}-{VERSION}.pom"
            text = pom.read_text().replace(
                "</dependencies>",
                "<dependency><groupId>com.google.firebase</groupId>"
                "<artifactId>firebase-common</artifactId><version>21.0.0</version>"
                "</dependency></dependencies>",
            )
            pom.write_text(text)
            self.sign_and_checksum(pom)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("Google runtime dependency" in failure for failure in report["failures"]))

    def test_pom_external_entity_is_rejected_without_reading_local_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            local_secret = root / "must-not-be-read"
            local_secret.write_text("leona-xxe-sentinel")
            pom = coordinate_dir / f"{ARTIFACT}-{VERSION}.pom"
            pom.write_text(
                f'''<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY xxe SYSTEM "{local_secret.as_uri()}">]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>{GROUP}</groupId><artifactId>{ARTIFACT}</artifactId>
  <version>{VERSION}</version><packaging>aar</packaging>
  <dependencies><dependency><groupId>&xxe;</groupId>
  <artifactId>core</artifactId></dependency></dependencies>
</project>
'''
            )
            self.sign_and_checksum(pom)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertTrue(any("POM parse failed" in failure for failure in report["failures"]))
        self.assertNotIn("leona-xxe-sentinel", json.dumps(report))

    def test_utf16_pom_cannot_bypass_declaration_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            pom = coordinate_dir / f"{ARTIFACT}-{VERSION}.pom"
            pom.write_bytes(
                f'''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///never-read">]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>{GROUP}</groupId><artifactId>{ARTIFACT}</artifactId>
  <version>{VERSION}</version><packaging>aar</packaging>
</project>
'''.encode("utf-16")
            )
            self.sign_and_checksum(pom)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertTrue(any("POM parse failed" in failure for failure in report["failures"]))

    def test_play_integrity_gradle_module_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            module = coordinate_dir / f"{ARTIFACT}-{VERSION}.module"
            payload = json.loads(module.read_text())
            payload["variants"][0]["dependencies"].append(
                {
                    "group": "com.google.android.play",
                    "module": "integrity",
                    "version": {"requires": "1.6.0"},
                }
            )
            module.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            self.sign_and_checksum(module)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(
            any("Gradle module contains Google runtime dependency" in failure for failure in report["failures"])
        )

    def test_coordinate_traversal_segment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, _, consumer = self.create_fixture(root)
            result = self.run_verifier(
                repository,
                consumer,
                root / "output",
                extra_args=["--artifact-id", ".."],
            )
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("artifact-id shape invalid" in failure for failure in report["failures"]))

    def test_ambiguous_extra_coordinate_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            (coordinate_dir / "unexpected.bin").write_bytes(b"ambiguous")
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("exact artifact/signature/checksum set" in failure for failure in report["failures"]))

    def test_symlinked_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            sources = coordinate_dir / f"{ARTIFACT}-{VERSION}-sources.jar"
            target = root / "external-sources.jar"
            sources.replace(target)
            os.symlink(target, sources)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("symlink" in failure for failure in report["failures"]))

    def test_embedded_google_play_runtime_class_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            aar_path = coordinate_dir / f"{ARTIFACT}-{VERSION}.aar"
            with zipfile.ZipFile(aar_path) as aar:
                classes_data = aar.read("classes.jar")
                other_entries = {
                    name: aar.read(name) for name in aar.namelist() if name != "classes.jar"
                }
            classes_buffer = io.BytesIO()
            with zipfile.ZipFile(classes_buffer, "w") as classes:
                with zipfile.ZipFile(io.BytesIO(classes_data)) as old_classes:
                    for name in old_classes.namelist():
                        classes.writestr(name, old_classes.read(name))
                classes.writestr(
                    "com/google/android/play/integrity/StandardIntegrityManager.class",
                    b"forbidden-runtime",
                )
            rebuilt_aar = aar_path.with_suffix(".aar.rebuilt")
            with zipfile.ZipFile(rebuilt_aar, "w") as aar:
                aar.writestr("classes.jar", classes_buffer.getvalue())
                for name, payload in other_entries.items():
                    aar.writestr(name, payload)
            rebuilt_aar.replace(aar_path)
            self.sign_and_checksum(aar_path)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("Google runtime package" in failure for failure in report["failures"]))

    def test_embedded_non_play_google_runtime_class_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository, coordinate_dir, consumer = self.create_fixture(root)
            aar_path = coordinate_dir / f"{ARTIFACT}-{VERSION}.aar"
            with zipfile.ZipFile(aar_path) as aar:
                classes_data = aar.read("classes.jar")
                other_entries = {
                    name: aar.read(name) for name in aar.namelist() if name != "classes.jar"
                }
            classes_buffer = io.BytesIO()
            with zipfile.ZipFile(classes_buffer, "w") as classes:
                with zipfile.ZipFile(io.BytesIO(classes_data)) as old_classes:
                    for name in old_classes.namelist():
                        classes.writestr(name, old_classes.read(name))
                classes.writestr("com/google/firebase/FirebaseApp.class", b"forbidden-runtime")
            rebuilt_aar = aar_path.with_suffix(".aar.rebuilt")
            with zipfile.ZipFile(rebuilt_aar, "w") as aar:
                aar.writestr("classes.jar", classes_buffer.getvalue())
                for name, payload in other_entries.items():
                    aar.writestr(name, payload)
            rebuilt_aar.replace(aar_path)
            self.sign_and_checksum(aar_path)
            result = self.run_verifier(repository, consumer, root / "output")
            report = json.loads((root / "output/summary.json").read_text())
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(any("Google runtime package" in failure for failure in report["failures"]))


if __name__ == "__main__":
    unittest.main()
