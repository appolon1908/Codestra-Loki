"""Loki platform contract: private tenant-authenticated storage of sanitised logs, OpenBao-referenced credentials."""
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("loki_platform", ROOT / "scripts" / "validate_codestra_loki_platform.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class LokiPlatformTests(unittest.TestCase):
    def test_validator_passes_offline(self) -> None:
        result = subprocess.run([sys.executable, "scripts/validate_codestra_loki_platform.py"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LOKI_PUBLIC_LISTENER=NONE", result.stdout)

    def test_every_forbidden_class_names_an_upstream_enforcer(self) -> None:
        contract = json.loads((ROOT / "codestra/redaction-contract.v1.json").read_text(encoding="utf-8"))
        classes = {item["class"]: item["enforcedBy"] for item in contract["forbiddenContentClasses"]}
        self.assertEqual(set(classes), MODULE.REQUIRED_CLASSES)
        for enforcers in classes.values():
            self.assertTrue(any("Codestra-Alloy" in e for e in enforcers))
            self.assertTrue(any("Codestra-Telemetry" in e for e in enforcers))

    def test_correlation_and_trace_ids_are_metadata_never_labels(self) -> None:
        contract = json.loads((ROOT / "codestra/redaction-contract.v1.json").read_text(encoding="utf-8"))
        policy = contract["labelPolicy"]
        for name in ("correlation_id", "trace_id", "span_id"):
            self.assertIn(name, policy["structuredMetadataAllowed"])
            self.assertIn(name, policy["neverIndexedLabels"])
            self.assertNotIn(name, policy["indexedLabelsAllowed"])

    def test_public_port_is_rejected(self) -> None:
        compose = (ROOT / "codestra/deploy/compose.candidate.yaml").read_text(encoding="utf-8")
        poisoned = compose + "\n    ports:\n      - \"3100:3100\"\n"
        original = Path.read_text

        def fake(self, *args, **kwargs):
            if self.name == "compose.candidate.yaml":
                return poisoned
            return original(self, *args, **kwargs)

        with patch.object(Path, "read_text", fake):
            with self.assertRaises(SystemExit):
                MODULE.validate_no_public_listener()

    def test_value_bearing_reference_is_rejected(self) -> None:
        document = json.loads((ROOT / "codestra/secret-references.v1.json").read_text(encoding="utf-8"))
        poisoned = copy.deepcopy(document)
        poisoned["references"][0]["value"] = "AKIA" + "A" * 16
        with self.assertRaises(SystemExit):
            MODULE.reject_secret_material(poisoned, "root")

    def test_rules_pin_matches_committed_rules(self) -> None:
        pinned = (ROOT / "codestra/rules/platform/openbao-audit-rules.sha256").read_text(encoding="utf-8").split()[0]
        self.assertEqual(MODULE.lf_sha256(ROOT / "codestra/rules/platform/openbao-audit-rules.yml"), pinned)


if __name__ == "__main__":
    unittest.main()
