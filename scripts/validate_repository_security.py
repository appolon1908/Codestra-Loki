#!/usr/bin/env python3
"""Validate Codestra Loki protected source authority."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SECRET_SCANNER_PATH = ROOT / "scripts/reject_repository_secrets.sh"
EXPECTED_GITMODULES = """[submodule \"upstream/operator/website/themes/doks\"]
\tpath = upstream/operator/website/themes/doks
\turl = https://github.com/h-enk/doks.git
"""


def validate_upstream(source: dict, lock: dict) -> None:
    expected = {
        "component": "loki",
        "codestra_repository": "appolon1908-hue/Codestra-Loki",
        "upstream_repository": "grafana/loki",
        "upstream_clone_url": "https://github.com/grafana/loki.git",
        "import_path": "upstream",
        "deployment_enabled": False,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    ref = source.get("upstream_ref")
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    for key in ("upstream_clone_url", "import_path", "deployment_enabled"):
        if lock.get(key) != expected[key]:
            raise ValueError(f"upstream_lock_drift:{key}")
    if lock.get("upstream_ref") != ref or lock.get("upstream_commit") != ref:
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    forbidden = (
        r"git\s+push\s+origin\s+(?:HEAD:)?(?:main|staging|production)(?:\s|$)",
        r"git\s+push\s+--force",
    )
    if any(re.search(pattern, source) for pattern in forbidden):
        raise ValueError("protected_branch_sync_forbidden")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'SYNC_BRANCH="sync/loki-upstream-${UPSTREAM_SHA}"',
        'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
        "EXPECTED_UPSTREAM_TREE=\"$(git -C .codestra-upstream-src rev-parse 'HEAD^{tree}')\"",
        "EXPECTED_LOCK_BLOB=\"$(git hash-object CODESTRA_UPSTREAM_LOCK.json)\"",
        'REMOTE_UPSTREAM_TREE="$(git rev-parse "${REMOTE_SHA}:upstream")"',
        'REMOTE_LOCK_BLOB="$(git rev-parse "${REMOTE_SHA}:CODESTRA_UPSTREAM_LOCK.json")"',
        '[[ "$REMOTE_UPSTREAM_TREE" == "$EXPECTED_UPSTREAM_TREE" ]]',
        '[[ "$REMOTE_LOCK_BLOB" == "$EXPECTED_LOCK_BLOB" ]]',
        "git diff --name-only \"$REMOTE_PARENT\" \"$REMOTE_SHA\" -- . ':(exclude)upstream'",
        '[[ "${REMOTE_CONTROL_CHANGES[0]}" == CODESTRA_UPSTREAM_LOCK.json ]]',
        "gh pr list",
        "Multiple open synchronization pull requests found.",
        "gh pr create",
        "--base main",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "'synchronized_at': os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")
    if source.index('if [[ -n "$REMOTE_SHA" ]]') > source.index('git commit -m'):
        raise ValueError("existing_sync_branch_must_be_reused_before_commit")
    if source.index("EXPECTED_UPSTREAM_TREE=") > source.index(
        "rm -rf .codestra-upstream-src/.git"
    ):
        raise ValueError("upstream_tree_must_be_captured_before_metadata_removal")


def validate_workflow(source: str) -> None:
    required = (
        "pull_request:",
        "workflow_dispatch:",
        "validate-source:",
        "name: validate-source",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "persist-credentials: false",
        "fetch-depth: 0",
        "Bind vendored Git tree to exact official commit",
        "git rev-parse 'HEAD:upstream'",
        '[[ "$vendored_tree" == "$official_tree" ]]',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", source):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_secret_scanner(source: str) -> None:
    if '-path "$search_root/tests"' in source or "--exclude-dir=tests" in source:
        raise ValueError("repository_tests_must_be_secret_scanned")
    required = (
        'find "$search_root"',
        '-path "$search_root/.git"',
        '-path "$search_root/upstream"',
        "-type f -o -type l",
        '[[ -L "$path" ]]',
        "grep -aEiq",
        "find_status=$?",
        "secret_scan_status=$?",
        'exit "$secret_scan_status"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scan_boundary_missing:{token}")
    if re.search(r"!\s+grep\s+-R", source):
        raise ValueError("secret_scan_errors_must_fail_closed")
    if re.search(r"grep\s+-[^\n]*I", source):
        raise ValueError("binary_secret_scan_must_not_be_skipped")


def validate_gitmodules(source: str) -> None:
    if source != EXPECTED_GITMODULES:
        raise ValueError("root_gitmodule_mapping_drift")


def validate_repository() -> None:
    paths = {
        "source": ROOT / "CODESTRA_UPSTREAM.json",
        "lock": ROOT / "CODESTRA_UPSTREAM_LOCK.json",
        "sync": ROOT / ".github/workflows/upstream-source-sync.yml",
        "validate": ROOT / ".github/workflows/validate.yml",
        "gitmodules": ROOT / ".gitmodules",
        "secret_scanner": SECRET_SCANNER_PATH,
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    source = json.loads(paths["source"].read_text())
    lock = json.loads(paths["lock"].read_text())
    sync_source = paths["sync"].read_text()
    validate_source = paths["validate"].read_text()
    validate_upstream(source, lock)
    validate_sync(sync_source, yaml.safe_load(sync_source))
    yaml.safe_load(validate_source)
    validate_workflow(validate_source)
    validate_secret_scanner(paths["secret_scanner"].read_text())
    validate_gitmodules(paths["gitmodules"].read_text())
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"LOKI_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("LOKI_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
