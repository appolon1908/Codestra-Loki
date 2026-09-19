"""Middleware V3 log labels stay closed and low-cardinality; identifiers stay structured metadata."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_middleware_v3_log_labels", ROOT / "scripts" / "validate_middleware_v3_log_labels.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class LogLabelContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(VALIDATOR.CONTRACT.read_text(encoding="utf-8"))
        cls.redaction = json.loads(VALIDATOR.REDACTION.read_text(encoding="utf-8"))
        cls.loki = VALIDATOR.load_yaml(VALIDATOR.LOKI)

    def reject(self, contract: dict) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate_contract(contract, self.redaction, self.loki)

    def test_source_passes(self) -> None:
        VALIDATOR.validate_contract(self.contract, self.redaction, self.loki)
        self.assertGreater(VALIDATOR.validate_rules(self.contract), 0)

    def test_pins(self) -> None:
        self.assertEqual(self.contract["middleware"]["prep_base_sha"], "22d023a9c65b0789a0f7ee6c28548753521a9eff")
        self.assertEqual(self.contract["middleware"]["v3_final_sha"], "PENDING")

    def test_identifiers_are_never_labels(self) -> None:
        never = set(self.contract["label_policy"]["never_indexed_labels"])
        for label in ("tenant_id", "customer_id", "command_id", "operation_id", "correlation_id", "email", "phone", "trace_id"):
            self.assertIn(label, never)
        allowed = set(self.contract["label_policy"]["indexed_labels_allowed"])
        self.assertFalse(allowed & never)
        structured = set(self.contract["label_policy"]["structured_metadata_allowed"])
        self.assertTrue({"correlation_id", "operation_id", "trace_id", "span_id", "deployment_sha"} <= structured)
        self.assertFalse(structured & allowed)

    def test_bounds_match_loki_yaml(self) -> None:
        limits = self.loki["limits_config"]
        self.assertTrue(limits["allow_structured_metadata"])
        self.assertEqual(self.contract["bounds_from_loki_yaml"]["max_label_names_per_series"], limits["max_label_names_per_series"])
        self.assertLessEqual(limits["max_label_names_per_series"], 20)

    def test_drift_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["label_policy"]["indexed_labels_allowed"].append("operation_id")
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["label_policy"]["never_indexed_labels"].remove("command_id")
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["activation_enabled"] = True
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["bounds_from_loki_yaml"]["max_label_names_per_series"] = 99
        self.reject(mutated)

    def test_rules_never_aggregate_by_identifiers(self) -> None:
        import tempfile

        original = VALIDATOR.RULES
        try:
            with tempfile.TemporaryDirectory() as folder:
                VALIDATOR.RULES = Path(folder)
                good = 'groups:\n  - name: g\n    rules:\n      - alert: A\n        expr: sum by (service, environment) (count_over_time({service="middleware"} | json | operation_id != "" [5m])) > 0\n'
                (Path(folder) / "good.yml").write_text(good, encoding="utf-8")
                self.assertEqual(VALIDATOR.validate_rules(self.contract), 1)
                for bad in (
                    'groups:\n  - name: g\n    rules:\n      - alert: B\n        expr: sum by (operation_id) (count_over_time({service="middleware"}[5m])) > 0\n',
                    'groups:\n  - name: g\n    rules:\n      - alert: C\n        expr: sum(count_over_time({service="middleware", customer_id="42"}[5m])) > 0\n',
                    'groups:\n  - name: g\n    rules:\n      - alert: D\n        expr: sum(count_over_time({service="middleware"}[5m])) > 0\n        labels:\n          email: ops@example.com\n',
                ):
                    (Path(folder) / "good.yml").write_text(bad, encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        VALIDATOR.validate_rules(self.contract)
        finally:
            VALIDATOR.RULES = original


if __name__ == "__main__":
    unittest.main()
