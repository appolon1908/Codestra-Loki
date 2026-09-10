from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "loki_bundle_contract", ROOT / "scripts/config_bundle_contract.py"
)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class BundleIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.files = {}
        for relative in contract.CANONICAL_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative)
            self.files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_exact_canonical_files_are_accepted(self) -> None:
        paths = contract.verify_bundle_files(self.root, self.files)
        self.assertEqual({str(p.relative_to(self.root)) for p in paths}, contract.CANONICAL_FILES)

    def test_same_count_substitution_is_rejected_even_with_valid_checksum(self) -> None:
        self.files.pop("codestra/config/loki.yaml")
        replacement = self.root / "codestra/config/unrelated.yaml"
        replacement.write_text("unrelated")
        self.files["codestra/config/unrelated.yaml"] = hashlib.sha256(replacement.read_bytes()).hexdigest()
        with self.assertRaisesRegex(SystemExit, "exact canonical file set"):
            contract.verify_bundle_files(self.root, self.files)

    def test_missing_and_extra_members_are_rejected(self) -> None:
        for extra in (False, True):
            files = dict(self.files)
            if extra:
                files["README.md"] = "0" * 64
            else:
                files.pop("codestra/config/loki.yaml")
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(SystemExit, "exact canonical file set"):
                    contract.verify_bundle_files(self.root, files)

    def test_changed_content_is_rejected(self) -> None:
        (self.root / "codestra/config/loki.yaml").write_text("changed")
        with self.assertRaisesRegex(SystemExit, "checksum mismatch"):
            contract.verify_bundle_files(self.root, self.files)

    def test_symlinked_file_and_parent_are_rejected(self) -> None:
        original = self.root / "codestra/config/loki.yaml"
        target = self.root / "saved.yaml"
        original.rename(target)
        original.symlink_to(target)
        with self.assertRaisesRegex(SystemExit, "symbolic configuration"):
            contract.verify_bundle_files(self.root, self.files)
        original.unlink()
        target.rename(original)
        directory = self.root / "codestra/config"
        moved = self.root / "saved-config"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "symbolic configuration"):
            contract.verify_bundle_files(self.root, self.files)


if __name__ == "__main__":
    unittest.main()
