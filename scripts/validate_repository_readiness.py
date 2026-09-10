#!/usr/bin/env python3
"""Validate repository-only Loki release readiness."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from config_bundle_contract import verify_bundle_files

ROOT = Path(__file__).resolve().parents[1]
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
AUTHORITY = (
    "appolon1908-hue/Codestra-Telemetry/.github/workflows/"
    "reusable-release-config-bundle.yml@777292781faeca9348d0e2ecdce6ac3f50c91d93"
)
REQUIRED = (
    "README.md", "REPOSITORY_PROFILE.md", "SECURITY.md", ".github/CODEOWNERS",
    "docs/BACKUP_RESTORE_ROLLBACK.md", "docs/UPGRADE.md", ".gitleaks.toml",
    "codestra/release/runtime-image.lock.json", "codestra/release/config-bundle.manifest.json",
    "scripts/build_config_bundle.py", ".github/workflows/release-config-bundle.yml",
    "requirements-validation.txt",
)


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load(relative: str) -> dict:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{relative} must contain an object")
    return value


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing readiness files: {missing}")
    if any(path.is_file() for path in (ROOT / "codestra/runtime-v1").glob("**/*")):
        fail("ambiguous legacy runtime-v1 authority remains")
    lock = load("codestra/release/runtime-image.lock.json")
    if lock.get("artifactModel") != "verified-upstream-image-plus-signed-config":
        fail("Loki must use release Model B")
    if not IMAGE.fullmatch(str(lock.get("image", ""))):
        fail("runtime image is mutable")
    if not GIT_SHA.fullmatch(str(lock.get("upstreamTagCommit", ""))):
        fail("upstream tag commit is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock.get("linuxAmd64Manifest", ""))):
        fail("linux/amd64 manifest is invalid")
    if lock.get("productionActivation") is not False:
        fail("source may not activate production")
    if lock.get("upstreamSignature") != {"available": False, "verification": "NO_SIGSTORE_SIGNATURE_PUBLISHED"}:
        fail("upstream signature disposition is inaccurate")
    manifest = load("codestra/release/config-bundle.manifest.json")
    if manifest.get("component") != "loki" or manifest.get("repository") != "appolon1908-hue/Codestra-Loki":
        fail("configuration manifest identity mismatch")
    if manifest.get("productionActivation") is not False:
        fail("configuration bundle may not activate production")
    verify_bundle_files(ROOT, manifest.get("files"))
    compose_text = (ROOT / "codestra/deploy/compose.candidate.yaml").read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    services = compose.get("services", {})
    if set(services) != {"loki-1", "loki-2", "loki-3"}:
        fail("canonical three-instance topology mismatch")
    for name, service in services.items():
        if service.get("image") != lock["image"] or service.get("ports"):
            fail(f"unsafe or mutable runtime identity: {name}")
        if service.get("privileged") is True or service.get("network_mode") == "host" or service.get("pid") == "host":
            fail(f"unsafe container boundary: {name}")
        if service.get("secrets") != ["loki_s3_credentials"]:
            fail(f"credential file mount missing: {name}")
        environment = service.get("environment", {})
        if environment.get("AWS_SHARED_CREDENTIALS_FILE") != "/run/secrets/loki_s3_credentials":
            fail(f"AWS credential-file identity mismatch: {name}")
        if environment.get("CODESTRA_LOKI_IMAGE_DIGEST") != lock["image"].rsplit("@", 1)[1]:
            fail(f"runtime image read-back identity mismatch: {name}")
        source_revision = str(environment.get("CODESTRA_LOKI_SOURCE_REVISION", ""))
        if "CODESTRA_LOKI_SOURCE_REVISION" not in source_revision:
            fail(f"runtime source read-back identity mismatch: {name}")
    if re.search(r"LOKI_S3_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)", compose_text):
        fail("inline object-store credential environment is forbidden")
    config = (ROOT / "codestra/config/loki.yaml").read_text(encoding="utf-8")
    if config.count("native_aws_auth_enabled: true") != 2:
        fail("both S3 clients must use the mounted AWS credential chain")
    if (
        "access_key_id:" in config
        or "secret_access_key:" in config
        or "access_key_secret:" in config
        or "insecure: true" in config
    ):
        fail("unsafe object-store credential or TLS configuration")
    release = yaml.safe_load((ROOT / ".github/workflows/release-config-bundle.yml").read_text())
    job = release.get("jobs", {}).get("release", {})
    if job.get("uses") != AUTHORITY or job.get("with", {}).get("component_id") != "loki":
        fail("release caller authority mismatch")
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        for reference in re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text):
            if not reference.startswith("./") and not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference):
                fail(f"mutable action: {workflow.name}: {reference}")
        if re.search(r"git push\s+origin\s+HEAD:(?:main|development|test|staging|production)", text):
            fail(f"direct protected-branch push: {workflow.name}")
    print("LOKI_REPOSITORY_READINESS_SOURCE=PASS")
    print("ARTIFACT_MODEL=SIGNED_CONFIGURATION_BUNDLE")
    print("PRODUCTION_ACTIVATION=NO")


if __name__ == "__main__":
    main()
