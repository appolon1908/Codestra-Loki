from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReadinessTests(unittest.TestCase):
    def test_validator(self) -> None:
        subprocess.run(["python3", "scripts/validate_repository_readiness.py"], cwd=ROOT, check=True)

    def test_bundle_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar.gz"
            second = Path(directory) / "second.tar.gz"
            for output in (first, second):
                subprocess.run(["python3", "scripts/build_config_bundle.py", "--output", str(output)], cwd=ROOT, check=True)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            manifest = json.loads((ROOT / "codestra/release/config-bundle.manifest.json").read_text())
            with tarfile.open(first) as archive:
                self.assertEqual(set(archive.getnames()), set(manifest["files"]) | {"codestra/release/config-bundle.manifest.json"})

    def test_secret_file_boundary(self) -> None:
        compose = (ROOT / "codestra/deploy/compose.candidate.yaml").read_text()
        config = (ROOT / "codestra/config/loki.yaml").read_text()
        self.assertIn("AWS_SHARED_CREDENTIALS_FILE: /run/secrets/loki_s3_credentials", compose)
        self.assertNotIn("LOKI_S3_SECRET_ACCESS_KEY", compose + config)
        self.assertNotIn("access_key_id:", config)

    def test_sensitive_value_gate_scans_signed_yaml(self) -> None:
        path = ROOT / "scripts/validate_codestra_sensitive_values.py"
        spec = importlib.util.spec_from_file_location("loki_sensitive_values", path)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            codestra = Path(directory) / "codestra"
            codestra.mkdir()
            (codestra / "loki.yaml").write_text(
                "storage_config:\n  object_store:\n    access_key_secret: committed-value\n"
            )
            module.ROOT = Path(directory)
            module.CODESTRA = codestra
            with self.assertRaises(SystemExit) as error:
                module.main()
            self.assertIn("codestra/loki.yaml", str(error.exception))

    def test_corporate_gate_installs_pinned_yaml_parser(self) -> None:
        workflow = (ROOT / ".github/workflows/validate-codestra-enterprise-profile.yml").read_text()
        self.assertIn("pip install --disable-pip-version-check --no-cache-dir -r requirements-validation.txt", workflow)

    def test_release_identity_uses_service_contract_names(self) -> None:
        compose = (ROOT / "codestra/deploy/compose.candidate.yaml").read_text()
        contract = json.loads((ROOT / "codestra/api/service-contract.v1.json").read_text())
        release = contract["release"]
        self.assertIn(release["sourceRevisionEnvironment"] + ":", compose)
        self.assertIn(release["imageDigestEnvironment"] + ":", compose)
        self.assertNotIn("CODESTRA_SOURCE_SHA:", compose)
        self.assertNotIn("CODESTRA_IMAGE_DIGEST:", compose)


if __name__ == "__main__":
    unittest.main()
