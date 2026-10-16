#!/usr/bin/env python3
"""Fail-closed validation of Loki's place in the monitoring platform.

Loki stores sanitised operational logs on private listeners for business-domain
tenants. This validator proves, from source only, that the server keeps tenant
authentication and bounded labels, that no host port is published, that the
redaction contract names an upstream enforcer for every forbidden content
class, that the OpenBao audit ruler rules are the pinned copy of the OpenBao
authority, and that every object-storage credential is an OpenBao secret
reference rather than a value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
CONFIG = CODESTRA / "config" / "loki.yaml"
RUNTIME_CONFIG = CODESTRA / "config" / "runtime-config.yaml"
COMPOSE = CODESTRA / "deploy" / "compose.candidate.yaml"
ENV_EXAMPLE = CODESTRA / "deploy" / "runtime.env.example"
REDACTION = CODESTRA / "redaction-contract.v1.json"
RULES = CODESTRA / "rules" / "platform" / "openbao-audit-rules.yml"
RULES_PIN = CODESTRA / "rules" / "platform" / "openbao-audit-rules.sha256"
SECRET_REFERENCES = CODESTRA / "secret-references.v1.json"
SECRET_SCHEMA = CODESTRA / "contracts" / "secret-reference.v1.schema.json"
SECRET_SCHEMA_PIN = CODESTRA / "contracts" / "secret-reference.v1.schema.sha256"

REQUIRED_CLASSES = {
    "bearer_tokens", "openbao_tokens", "oauth_client_secrets", "passwords", "authorization_headers",
    "webhook_signatures", "private_keys", "database_credentials", "smtp_credentials", "jwt_shaped_values",
}
BUSINESS_TENANTS = {
    "platform", "codestra", "moneybee", "beyvra", "breero", "larim-a", "transportation", "booked4seasons",
    "social", "klyrow", "telnexa", "kyqra", "restaurant", "provisioning",
}
FORBIDDEN_REFERENCE_KEYS = {
    "value", "password", "token", "private_key", "client_secret", "secret",
    "secret_value", "unseal_key", "recovery_key", "root_token",
}
SECRET_ENV = re.compile(r"(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|ACCESS_KEY)\s*=\s*\S")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def validate_server() -> dict[str, Any]:
    config = load_yaml(CONFIG)
    if config.get("auth_enabled") is not True:
        fail("Loki must keep tenant authentication enabled")
    limits = config.get("limits_config", {})
    if limits.get("allow_structured_metadata") is not True:
        fail("structured metadata must stay enabled for bounded correlation/trace drilldown")
    if not (0 < int(limits.get("max_label_names_per_series", 0)) <= 20):
        fail("max_label_names_per_series must be bounded (<= 20)")
    if int(limits.get("max_label_name_length", 0)) > 128 or int(limits.get("max_label_value_length", 0)) > 2048:
        fail("label name/value length limits drifted above the reviewed bounds")
    if limits.get("reject_old_samples") is not True or not limits.get("retention_period"):
        fail("Loki must reject stale samples and enforce retention")
    if config.get("ruler", {}).get("enable_api") is not False:
        fail("the ruler API must stay disabled; rules are shipped from reviewed source")
    if config.get("analytics", {}).get("reporting_enabled") is not False:
        fail("usage reporting must stay disabled")
    text = CONFIG.read_text(encoding="utf-8")
    if SECRET_ENV.search(text):
        fail("loki.yaml carries an inline credential")
    return limits


def validate_no_public_listener() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*ports\s*:", compose):
        fail("Loki compose must not publish a host port; only the private observability network reaches 3100/9095")
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    if SECRET_ENV.search(env):
        fail("runtime.env.example carries an inline credential")


def validate_tenants() -> None:
    overrides = load_yaml(RUNTIME_CONFIG).get("overrides", {})
    unknown = set(overrides) - BUSINESS_TENANTS
    if unknown:
        fail(f"tenant overrides must be business domains, never customers: {sorted(unknown)}")


def validate_redaction_contract(limits: dict[str, Any]) -> None:
    contract = load_json(REDACTION)
    classes = {item.get("class") for item in contract.get("forbiddenContentClasses", [])}
    if classes != REQUIRED_CLASSES:
        fail(f"redaction contract classes drifted: {sorted(classes ^ REQUIRED_CLASSES)}")
    for item in contract["forbiddenContentClasses"]:
        if not item.get("enforcedBy") or not all("Codestra-" in e for e in item["enforcedBy"]):
            fail(f"redaction class {item.get('class')} names no reviewed upstream enforcer")
    policy = contract.get("labelPolicy", {})
    if policy.get("maxLabelNamesPerSeries") != limits.get("max_label_names_per_series"):
        fail("redaction contract label bound differs from loki.yaml")
    if policy.get("maxLabelNameLength") != limits.get("max_label_name_length") or policy.get("maxLabelValueLength") != limits.get("max_label_value_length"):
        fail("redaction contract label length bounds differ from loki.yaml")
    if set(policy.get("indexedLabelsAllowed", [])) & set(policy.get("neverIndexedLabels", [])):
        fail("a label cannot be both allowed and never indexed")
    for forbidden in ("correlation_id", "trace_id", "user_id", "email"):
        if forbidden not in policy.get("neverIndexedLabels", []):
            fail(f"{forbidden} must be listed as never indexed")
    if contract.get("tenancy", {}).get("callerSuppliedTenantHeaderTrusted") is not False:
        fail("caller-supplied tenant headers must never be trusted")
    if contract.get("openbaoAudit", {}).get("hmacPreserved") is not True or contract.get("openbaoAudit", {}).get("publicEndpointDelivery") is not False:
        fail("OpenBao audit contract drifted")
    if contract.get("runtimeApplyAuthorized") is not False:
        fail("redaction contract must not authorize runtime apply")


def validate_rules(openbao_repo: Path | None) -> str:
    document = load_yaml(RULES)
    names = {rule.get("alert") for group in document.get("groups", []) for rule in group.get("rules", [])}
    for required in ("OpenBaoAuditStreamSilent", "OpenBaoRootTokenUsage", "OpenBaoPermissionDenialSurge", "OpenBaoPolicyModified"):
        if required not in names:
            fail(f"OpenBao audit rules missing {required}")
    for group in document.get("groups", []):
        for rule in group.get("rules", []):
            if 'service="openbao"' not in str(rule.get("expr")):
                fail(f"rule {rule.get('alert')} must select the OpenBao audit stream")
            if any(token in str(rule.get("expr")).lower() for token in ("secret_value", "unseal_key", "root_token=")):
                fail(f"rule {rule.get('alert')} must not reference secret values")
    pin_line = RULES_PIN.read_text(encoding="utf-8").strip()
    pinned = pin_line.split()[0]
    if lf_sha256(RULES) != pinned:
        fail("OpenBao audit rules differ from their pinned digest")
    if openbao_repo is not None:
        source = openbao_repo / "monitoring" / "alerts" / "openbao-audit-loki-rules.yml"
        if not source.is_file():
            fail("OpenBao checkout has no audit ruler rules")
        if lf_sha256(source) != pinned:
            fail("OpenBao audit rules differ from the OpenBao authority")
        return "PASS"
    return "SKIPPED_NO_OPENBAO_CHECKOUT"


def reject_secret_material(value: Any, trail: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_REFERENCE_KEYS or str(key).lower().endswith(("_password", "_token", "_secret")):
                fail(f"secret reference carries a value-bearing key at {trail}.{key}")
            reject_secret_material(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_material(item, f"{trail}[{index}]")
    elif isinstance(value, str) and (value.startswith("hvs.") or "PRIVATE KEY" in value or re.fullmatch(r"AKIA[0-9A-Z]{16}", value)):
        fail(f"secret-shaped value at {trail}")


def validate_secret_references() -> None:
    schema = load_json(SECRET_SCHEMA)
    pin = SECRET_SCHEMA_PIN.read_text(encoding="utf-8").strip()
    if hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() != pin:
        fail("vendored secret-reference schema does not match its pin")
    document = load_json(SECRET_REFERENCES)
    if document.get("secretValuesIncluded") is not False or document.get("schemaSha256") != pin:
        fail("secret references must declare no values and bind the pinned schema")
    if document.get("authority", {}).get("workloadIdentity") != "loki-runtime":
        fail("Loki reads OpenBao only as the loki-runtime identity")
    reject_secret_material(document, "secret-references")
    environments: set[str] = set()
    for index, reference in enumerate(document.get("references", [])):
        trail = f"references[{index}]"
        for required in schema["required"]:
            if required not in reference:
                fail(f"{trail} missing {required}")
        env = reference["environment"]
        ref = reference["secret_ref"]
        if reference["provider"] != "openbao" or reference["workload_identity"] != "loki-runtime":
            fail(f"{trail} must be an openbao reference readable by loki-runtime")
        if ref != f"codestra/{env}/observability/loki/object-storage":
            fail(f"{trail} must reference the reviewed loki object-storage path for {env}")
        if reference.get("reference_uri") != "openbao://" + ref:
            fail(f"{trail} reference_uri must equal openbao:// + secret_ref")
        if reference["secret_class"] != "object_storage_credentials":
            fail(f"{trail} must be object_storage_credentials")
        environments.add(env)
    if environments != {"staging", "production"}:
        fail("secret references must cover exactly staging and production")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openbao-repo")
    parser.add_argument("--require-cross-check", action="store_true")
    args = parser.parse_args()
    repo = Path(args.openbao_repo or os.environ.get("OPENBAO_REPO", "")) if (args.openbao_repo or os.environ.get("OPENBAO_REPO")) else None
    if repo is None and args.require_cross_check:
        fail("OpenBao checkout is required for the rules cross-check")
    limits = validate_server()
    validate_no_public_listener()
    validate_tenants()
    validate_redaction_contract(limits)
    cross = validate_rules(repo)
    validate_secret_references()
    print("Codestra Loki platform validation PASS")
    print(f"LOKI_OPENBAO_AUDIT_RULES_CROSS_CHECK={cross}")
    print("LOKI_PUBLIC_LISTENER=NONE")
    print("LOKI_SECRET_VALUES_IN_SOURCE=NONE")


if __name__ == "__main__":
    main()
