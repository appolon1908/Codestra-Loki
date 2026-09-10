#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_security", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_sync_uses_reviewed_retry_safe_pull_request(self) -> None:
        VALIDATOR.validate_sync(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)
        for token in (
            '[[ "$REMOTE_UPSTREAM_TREE" == "$EXPECTED_UPSTREAM_TREE" ]]',
            '[[ "$REMOTE_LOCK_BLOB" == "$EXPECTED_LOCK_BLOB" ]]',
            '[[ "${REMOTE_CONTROL_CHANGES[0]}" == CODESTRA_UPSTREAM_LOCK.json ]]',
            "if (( ${#OPEN_PRS[@]} > 1 )); then",
            'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        ):
            self.assertIn(token, self.sync_source)

    def test_existing_sync_branch_is_reused_before_creating_a_commit(self) -> None:
        remote_branch = self.sync_source.index('if [[ -n "$REMOTE_SHA" ]]')
        local_commit = self.sync_source.index('git commit -m')
        self.assertLess(remote_branch, local_commit)
        self.assertIn(
            "git diff --name-only \"$REMOTE_PARENT\" \"$REMOTE_SHA\" -- . ':(exclude)upstream'",
            self.sync_source,
        )
        self.assertIn('exit 0\n          fi', self.sync_source)

    def test_upstream_tree_is_captured_before_temporary_git_metadata_is_removed(self) -> None:
        capture = self.sync_source.index(
            "EXPECTED_UPSTREAM_TREE=\"$(git -C .codestra-upstream-src rev-parse 'HEAD^{tree}')\""
        )
        removal = self.sync_source.index("rm -rf .codestra-upstream-src/.git")
        remote_comparison = self.sync_source.index(
            '[[ "$REMOTE_UPSTREAM_TREE" == "$EXPECTED_UPSTREAM_TREE" ]]'
        )
        self.assertLess(capture, removal)
        self.assertLess(removal, remote_comparison)

    def test_bot_created_pr_dispatches_exact_branch_validation(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )

    def test_vendored_tree_is_bound_to_fresh_official_commit(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn('fetch --depth 1 --no-tags origin "$upstream_ref"', source)
        self.assertIn("rev-parse 'HEAD^{tree}'", source)
        self.assertIn("git rev-parse 'HEAD:upstream'", source)
        self.assertIn('[[ "$vendored_tree" == "$official_tree" ]]', source)

    def test_actions_are_pinned_and_validation_is_unconditional(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        VALIDATOR.validate_workflow(source)
        unsafe = source.replace("pull_request:\n", "pull_request:\n    paths:\n      - scripts/**\n")
        with self.assertRaisesRegex(ValueError, "pull_request_validation_must_be_unconditional"):
            VALIDATOR.validate_workflow(unsafe)

    def test_root_gitmodule_maps_only_the_exact_upstream_gitlink(self) -> None:
        source = (ROOT / ".gitmodules").read_text()
        VALIDATOR.validate_gitmodules(source)
        with self.assertRaisesRegex(ValueError, "root_gitmodule_mapping_drift"):
            VALIDATOR.validate_gitmodules(source.replace("h-enk/doks.git", "example/drift.git"))

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )

    def test_secret_scan_errors_fail_even_when_a_secret_also_matches(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        VALIDATOR.validate_secret_scanner(scanner.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.symlink(root / "missing", root / "dangling")
            (root / "credential.txt").write_text(
                "Author"
                + "ization: "
                + "Bearer "
                + "abc/def+ghijklmnopqrstuvwxyz==\n"
            )
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertGreater(result.returncode, 1)
            self.assertIn("symbolic link", result.stderr)

    def test_repository_tests_and_common_access_tokens_are_secret_scanned(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        source = scanner.read_text()
        self.assertNotIn('-path "$search_root/tests"', source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "tests/provider/credential.txt"
            fixture.parent.mkdir(parents=True)
            credentials = (
                "gh" + "p_" + ("A" * 24),
                "github" + "_pat_" + ("B" * 24),
                "AK" + "IA" + ("C" * 16),
                "AS" + "IA" + ("E" * 16),
                "gl" + "pat-" + ("D" * 24),
                "-----BEGIN PRIVATE" + " KEY-----\nfixture",
                "-----BEGIN ENCRYPTED PRIVATE" + " KEY-----\nfixture",
                "-----BEGIN PGP PRIVATE" + " KEY BLOCK-----\nfixture",
            )
            for credential in credentials:
                fixture.write_text(credential + "\n")
                result = subprocess.run(
                    [scanner, root], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1, credential[:8])


if __name__ == "__main__":
    unittest.main(verbosity=2)
