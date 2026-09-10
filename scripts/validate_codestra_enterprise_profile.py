#!/usr/bin/env python3
"""Fail-closed validation for the Codestra Loki overlay."""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = ROOT / "codestra/enterprise-profile.v1.json"
LOKI_CONFIG = ROOT / "codestra/config/loki.yaml"
RUNTIME_CONFIG = ROOT / "codestra/config/runtime-config.yaml"
COMPOSE = ROOT / "codestra/deploy/compose.candidate.yaml"
OPERATING_MODEL = ROOT / "codestra/docs/OPERATING-MODEL.md"

BUSINESSES = {
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
}
TENANTS = BUSINESSES | {"platform"}
REQUIRED_LABELS = {
    "environment",
    "service",
    "application",
    "server",
    "region",
    "deployment",
    "codestra_business",
}
FORBIDDEN_LABELS = {
    "tenant_id",
    "customer_id",
    "user_id",
    "request_id",
    "correlation_id",
    "trace_id",
    "email",
    "phone",
    "message_id",
    "order_id",
    "raw_url",
    "query_string",
    "container_id",
    "pod_uid",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_file(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_fragments(text: str, fragments: Iterable[str], source: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            fail(f"{source} must contain: {fragment}")


def reject_fragments(text: str, fragments: Iterable[str], source: str) -> None:
    lowered = text.lower()
    for fragment in fragments:
        if fragment.lower() in lowered:
            fail(f"{source} contains forbidden content: {fragment}")


profile_text = require_file(PROFILE)
loki_text = require_file(LOKI_CONFIG)
runtime_text = require_file(RUNTIME_CONFIG)
compose_text = require_file(COMPOSE)
require_file(OPERATING_MODEL)

data = json.loads(profile_text)
repo = os.environ.get("GITHUB_REPOSITORY", "appolon1908-hue/Codestra-Loki")

if repo != "appolon1908-hue/Codestra-Loki":
    fail(f"validator is bound to Codestra-Loki, received {repo}")
if data.get("schemaVersion") != "1.1":
    fail("schemaVersion must be 1.1")
if data.get("canonicalHostname") != "loki.codestra.media":
    fail("canonical hostname must be loki.codestra.media")
if data.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
    fail("status must remain CONFIG_PREPARED_NOT_DEPLOYED")
if data.get("exposure") != "internal_private":
    fail("Loki native service exposure must remain internal_private")

businesses = data.get("businessScope", [])
if set(businesses) != BUSINESSES:
    fail("businessScope must exactly match the approved Codestra portfolio")
if len(businesses) != len(set(businesses)):
    fail("businessScope contains duplicate IDs")
if set(data.get("requiredLabels", [])) != REQUIRED_LABELS:
    fail("requiredLabels must exactly match the canonical low-cardinality set")
if set(data.get("requiredLabels", [])) & FORBIDDEN_LABELS:
    fail("forbidden high-cardinality fields may not be required labels")

for feature in (
    "structuredJson",
    "traceCorrelation",
    "businessTenantIsolation",
    "retentionTiers",
    "volumeGuardrails",
    "s3BackedTsdb",
    "walRecovery",
    "privateHaTopology",
    "runtimeOverrides",
    "selfMonitoring",
):
    if data.get("features", {}).get(feature) is not True:
        fail(f"required corporate feature is disabled: {feature}")

if data.get("tenancy", {}).get("customerIdentifiersAsTenantIds") is not False:
    fail("customer identifiers may not be Loki tenant IDs")
if data.get("tenancy", {}).get("callerSuppliedTenantHeaderTrusted") is not False:
    fail("caller-supplied tenant headers may not be trusted")
if data.get("topology", {}).get("instances") != 3:
    fail("corporate topology must define three Loki instances")
if data.get("topology", {}).get("replicationFactor") != 3:
    fail("corporate topology must use replication factor three")

require_fragments(
    loki_text,
    (
        "auth_enabled: true",
        "target: all",
        "replication_factor: 3",
        "store: tsdb",
        "object_store: s3",
        "schema: v13",
        "runtime-config.yaml",
        "retention_enabled: true",
        "delete_request_store: s3",
        "reporting_enabled: false",
        "enabled: true",
        "native_aws_auth_enabled: true",
        "LOKI_ALERTMANAGER_URL",
        "ruler_storage:",
        "backend: s3",
    ),
    "codestra/config/loki.yaml",
)
reject_fragments(
    loki_text,
    ("access_key_id: loki", "secret_access_key: supersecret", "auth_enabled: false"),
    "codestra/config/loki.yaml",
)
ruler_lines = loki_text.splitlines()
try:
    ruler_index = next(index for index, line in enumerate(ruler_lines) if line.strip() == "ruler:" and not line.startswith((" ", "\t")))
except StopIteration:
    fail("codestra/config/loki.yaml must define the ruler")
body_lines: list[str] = []
for line in ruler_lines[ruler_index + 1 :]:
    if line and not line.startswith((" ", "\t")):
        break
    body_lines.append(line)
if any(re.fullmatch(r"  storage:\s*", line) for line in body_lines):
    fail("ruler storage must use top-level ruler_storage with Thanos object storage")

runtime_tenants = set(re.findall(r"^  ([a-z0-9-]+):\s*$", runtime_text, flags=re.MULTILINE))
if runtime_tenants != TENANTS:
    missing = sorted(TENANTS - runtime_tenants)
    extra = sorted(runtime_tenants - TENANTS)
    fail(f"runtime tenant catalogue mismatch; missing={missing}, extra={extra}")
for forbidden in ("customer", "account", "email", "phone", "user_id", "tenant_id"):
    if re.search(rf"^  .*{re.escape(forbidden)}.*:\s*$", runtime_text, flags=re.MULTILINE | re.IGNORECASE):
        fail(f"runtime config contains a customer-level tenant key: {forbidden}")

require_fragments(
    compose_text,
    (
        "docker.io/grafana/loki@sha256:847c287ada0e12603910589f42038c5cdaaad04e248bd1dc6c6e0920a235f427",
        "AWS_SHARED_CREDENTIALS_FILE: /run/secrets/loki_s3_credentials",
        "LOKI_S3_CREDENTIALS_FILE:?mount an OpenBao-rendered AWS shared-credentials file",
        "read_only: true",
        "no-new-privileges:true",
        "cap_drop:",
        "- ALL",
        "loki-1:",
        "loki-2:",
        "loki-3:",
        "COMPACTOR_MODE: main",
        "codestra-observability",
        'test: ["CMD", "/usr/bin/loki", "-health"]',
    ),
    "codestra/deploy/compose.candidate.yaml",
)
if re.search(r"^\s*ports:\s*$", compose_text, flags=re.MULTILINE):
    fail("compose candidate may not publish native Loki host ports")
if re.search(r"image:\s*[^\n]*:latest(?:\s|$)", compose_text, flags=re.IGNORECASE):
    fail("compose candidate may not use a latest image tag")

# Fail on committed private keys, common cloud access-key formats, or populated secret assignments.
all_overlay_text = "\n".join(
    path.read_text(encoding="utf-8", errors="replace")
    for path in (ROOT / "codestra").rglob("*")
    if path.is_file()
)
reject_fragments(
    all_overlay_text,
    ("-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "AKIA"),
    "codestra overlay",
)
for forbidden_assignment in ("LOKI_S3_ACCESS_KEY_ID=", "LOKI_S3_SECRET_ACCESS_KEY="):
    if forbidden_assignment in all_overlay_text:
        fail(f"inline object-store credential assignment is forbidden: {forbidden_assignment}")

print("Codestra Loki corporate configuration validation PASS")
