#!/usr/bin/env python3
"""Fail-closed validation of the Middleware V3 log-label contract.

``codestra/contracts/middleware-v3-log-labels.v1.json`` fixes the closed label set
Loki indexes for Middleware V3 logs and the identifiers that must stay structured
fields or structured metadata. This validator proves the contract is dark and
pinned, that it mirrors ``codestra/redaction-contract.v1.json`` and the bounds in
``codestra/config/loki.yaml`` (structured metadata enabled, label limits), that no
never-indexed identifier is also allowed, and that every LogQL rule under
``codestra/rules`` aggregates only by allowed labels. PyYAML is the only dependency.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
CONTRACT = CODESTRA / "contracts" / "middleware-v3-log-labels.v1.json"
REDACTION = CODESTRA / "redaction-contract.v1.json"
LOKI = CODESTRA / "config" / "loki.yaml"
RULES = CODESTRA / "rules"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
BY_CLAUSE = re.compile(r"\bby\s*\(([^)]*)\)")
STREAM_SELECTOR = re.compile(r"\{([^}]*)\}")
MISSION_NEVER_LABELS = {"tenant_id", "customer_id", "command_id", "operation_id", "correlation_id", "email", "phone"}
V3_STRUCTURED = {"correlation_id", "operation_id", "trace_id", "span_id", "deployment_sha"}


def fail(message: str) -> None:
    print(f"MIDDLEWARE_V3_LOG_LABELS_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: Path) -> Any:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def validate_contract(contract: dict[str, Any], redaction: dict[str, Any], loki: dict[str, Any]) -> None:
    if contract.get("contract_id") != "middleware-v3-log-labels" or contract.get("status") != "PREPARED_DISABLED":
        fail("contract identity or status drift")
    if contract.get("activation_enabled") is not False:
        fail("activation_enabled must be false")
    middleware = contract.get("middleware", {})
    if not SHA40.fullmatch(str(middleware.get("prep_base_sha", ""))):
        fail("middleware.prep_base_sha must be a 40-hex commit")
    if middleware.get("v3_final_sha") != "PENDING" and not SHA40.fullmatch(str(middleware.get("v3_final_sha"))):
        fail("middleware.v3_final_sha must be PENDING or a 40-hex commit")

    policy = contract.get("label_policy", {})
    reviewed = redaction.get("labelPolicy", {})
    allowed = set(policy.get("indexed_labels_allowed", []))
    never = set(policy.get("never_indexed_labels", []))
    structured = set(policy.get("structured_metadata_allowed", []))
    if allowed != set(reviewed.get("indexedLabelsAllowed", [])):
        fail("indexed_labels_allowed drifted from codestra/redaction-contract.v1.json")
    if never != set(reviewed.get("neverIndexedLabels", [])):
        fail("never_indexed_labels drifted from codestra/redaction-contract.v1.json")
    if structured != set(reviewed.get("structuredMetadataAllowed", [])):
        fail("structured_metadata_allowed drifted from codestra/redaction-contract.v1.json")
    if allowed & never:
        fail(f"labels both allowed and never indexed: {sorted(allowed & never)}")
    if not MISSION_NEVER_LABELS <= never:
        fail(f"never_indexed_labels must include {sorted(MISSION_NEVER_LABELS - never)}")
    if not V3_STRUCTURED <= structured:
        fail(f"structured_metadata_allowed must include {sorted(V3_STRUCTURED - structured)}")
    if structured & allowed:
        fail("structured metadata names can never be indexed labels")
    if not {"service_id", "environment", "deployment_sha", "correlation_id", "operation_id", "trace_id"} <= set(policy.get("structured_fields_kept_in_line", [])):
        fail("the six required common fields must be kept as structured fields")

    limits = loki.get("limits_config", {})
    bounds = contract.get("bounds_from_loki_yaml", {})
    if limits.get("allow_structured_metadata") is not True or bounds.get("allow_structured_metadata") is not True:
        fail("structured metadata must be enabled in loki.yaml and declared in the contract")
    for key, source in (("max_label_names_per_series", "max_label_names_per_series"), ("max_label_name_length", "max_label_name_length"), ("max_label_value_length", "max_label_value_length")):
        if bounds.get(key) != limits.get(source) or bounds.get(key) != reviewed.get({"max_label_names_per_series": "maxLabelNamesPerSeries", "max_label_name_length": "maxLabelNameLength", "max_label_value_length": "maxLabelValueLength"}[key]):
            fail(f"{key} differs between contract, redaction contract and loki.yaml")
    if limits.get("max_label_names_per_series", 0) > 20:
        fail("label names per series must stay bounded (<= 20)")
    if str(bounds.get("max_line_size")) != str(limits.get("max_line_size")):
        fail("max_line_size differs from loki.yaml")
    if limits.get("reject_old_samples") is not True:
        fail("loki.yaml must reject old samples")

    ruler = contract.get("ruler_policy", {})
    if not MISSION_NEVER_LABELS <= set(ruler.get("never_aggregate_by", [])):
        fail("ruler policy must forbid aggregation by every never-indexed identifier")
    if contract.get("redaction_reference", {}).get("loki_has_no_content_filter") is not True:
        fail("the contract must record that Loki has no content filter of its own")


def validate_rules(contract: dict[str, Any]) -> int:
    allowed = set(contract["ruler_policy"]["aggregation_labels_allowed"])
    never = set(contract["label_policy"]["never_indexed_labels"])
    count = 0
    for path in sorted(RULES.rglob("*.yml")):
        doc = load_yaml(path)
        for group in (doc or {}).get("groups", []):
            for rule in group.get("rules", []):
                expr = str(rule.get("expr", ""))
                count += 1
                for clause in BY_CLAUSE.findall(expr):
                    labels = {item.strip() for item in clause.split(",") if item.strip()}
                    if labels - allowed:
                        fail(f"{path.name}: rule aggregates by disallowed labels {sorted(labels - allowed)}")
                for selector in STREAM_SELECTOR.findall(expr):
                    for item in selector.split(","):
                        key = item.split("=")[0].strip().rstrip("!~")
                        if key in never:
                            fail(f"{path.name}: rule selects on never-indexed label {key}")
                labels = rule.get("labels", {})
                if set(labels) & never:
                    fail(f"{path.name}: rule emits a never-indexed label")
    return count


def main() -> None:
    contract = load_json(CONTRACT)
    redaction = load_json(REDACTION)
    loki = load_yaml(LOKI)
    validate_contract(contract, redaction, loki)
    rules = validate_rules(contract)
    print(
        "MIDDLEWARE_V3_LOG_LABELS=PASS "
        f"prep_base={contract['middleware']['prep_base_sha'][:12]} v3_final={contract['middleware']['v3_final_sha']} "
        f"labels={len(contract['label_policy']['indexed_labels_allowed'])} rules_checked={rules}"
    )


if __name__ == "__main__":
    main()
