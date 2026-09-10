#!/usr/bin/env python3
"""Reject committed credential values in Codestra Loki JSON and YAML files."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"

SENSITIVE_KEY_TOKENS = {
    "password",
    "passwd",
    "authorization",
    "authorizationheader",
    "authorizationheaders",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "apikey",
    "clientsecret",
    "secretaccesskey",
    "accesskeysecret",
    "accesstoken",
    "refreshtoken",
    "sessiontoken",
    "privatekey",
    "roottoken",
    "databaseurl",
    "dsn",
    "brokersigningsecret",
    "brokersigningkey",
    "exchangeapikey",
    "exchangesecret",
}

PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"INJECT_FROM_(?:OPENBAO|SECRET_FILE|DEPLOYMENT)|"
    r"REDACTED|\[REDACTED\]|"
    r"\$\{[A-Z0-9_]+(?::\?[^}]*)?\}"
    r")$"
)


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def is_sensitive_key(key: str) -> bool:
    normalized = normalize_key(key)
    return any(token in normalized for token in SENSITIVE_KEY_TOKENS)


def is_safe_reference(key: str, value: str) -> bool:
    stripped = value.strip()
    normalized = normalize_key(key)
    if not stripped:
        return True
    if PLACEHOLDER_RE.fullmatch(stripped):
        return True
    if normalized.endswith("file") and stripped.startswith("/run/secrets/"):
        return True
    return False


def find_violations(value: Any, path: str = "") -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            if is_sensitive_key(str(key)) and isinstance(child, str):
                if not is_safe_reference(str(key), child):
                    violations.append(child_path)
            violations.extend(find_violations(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            violations.extend(find_violations(child, f"{path}[{index}]"))
    return violations


def load_document(path: pathlib.Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            return json.loads(text)
        return yaml.safe_load(text)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SystemExit(f"invalid control document {path}: {exc}")


def prove_detector() -> None:
    unsafe_samples = (
        {"authorization_headers": "Bearer committed-token"},
        {"session_token": "committed-session"},
        {"broker_signing_secret": "committed-signing-material"},
        {"api_key": "committed-api-key"},
        {"clientSecret": "committed-client-secret"},
        {"secret_access_key": "committed-secret-access-key"},
        {"awsSecretAccessKey": "committed-aws-secret-access-key"},
        {"private_key": "committed-private-key"},
        {"root-token": "committed-root-token"},
        {"access_key_secret": "committed-object-store-secret"},
    )
    for sample in unsafe_samples:
        if not find_violations(sample):
            raise SystemExit(f"sensitive-value detector failed negative test: {sample}")

    safe_samples = (
        {"clientSecretFile": "/run/secrets/loki_client_secret"},
        {"secretAccessKeyFile": "/run/secrets/loki_s3_secret_access_key"},
        {"api_key": "INJECT_FROM_OPENBAO"},
        {"session_token": "${LOKI_SESSION_TOKEN:?injected at runtime}"},
        {"captureAuthorizationHeaders": False},
        {"password": "${PASSWORD:?injected at runtime}"},
    )
    unsafe_placeholder_samples = (
        {"password": "${PASSWORD:-committed-secret}"},
        {"clientSecret": "${CLIENT_SECRET:committed-secret}"},
    )
    for sample in unsafe_placeholder_samples:
        if not find_violations(sample):
            raise SystemExit(f"sensitive-value detector accepted populated default: {sample}")

    for sample in safe_samples:
        if find_violations(sample):
            raise SystemExit(f"sensitive-value detector rejected safe control data: {sample}")


def main() -> None:
    prove_detector()
    governed_files = sorted(
        path
        for path in CODESTRA.rglob("*")
        if path.is_file() and path.suffix in {".json", ".yaml", ".yml"}
    )
    if not governed_files:
        raise SystemExit("no Codestra JSON or YAML control files found")
    violations: list[str] = []
    for path in governed_files:
        for field in find_violations(load_document(path)):
            violations.append(f"{path.relative_to(ROOT)}:{field}")
    if violations:
        raise SystemExit(
            "committed credential-like values found in Codestra control files: "
            + ", ".join(violations)
        )
    print("Codestra Loki sensitive-value validation PASS")


if __name__ == "__main__":
    main()
