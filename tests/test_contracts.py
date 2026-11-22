from __future__ import annotations

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_contracts  # noqa: E402
from validate_contracts import validate_repository  # noqa: E402


class ContractTests(unittest.TestCase):
    def test_repository_contracts(self) -> None:
        self.assertEqual(validate_repository(), [])

    def test_every_vector_corpus_is_validated(self) -> None:
        self.assertIn("tests/release-3.4.json", validate_contracts.vector_corpora())
        self.assertNotIn("tests/canonicalization.json", validate_contracts.vector_corpora())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "release-9.9.json").write_text(json.dumps({"positive": [], "negative": []}))
            (root / "tests" / "canonicalization.json").write_text(json.dumps({"vectors": []}))
            with mock.patch.object(validate_contracts, "ROOT", root):
                self.assertEqual(validate_contracts.vector_corpora(), ["tests/release-9.9.json"])

    def test_install_lines_name_the_release_version(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        stale = (ROOT / "README.md").read_text(encoding="utf-8").replace(f"agent-approval-gate@v{version}", "agent-approval-gate@v0.0.1")
        real_read_text = Path.read_text

        def read_text(path: Path, *args, **kwargs) -> str:
            return stale if path == ROOT / "README.md" else real_read_text(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", read_text):
            failures = validate_repository()
        self.assertIn(f"README.md: uses agent-approval-gate@v0.0.1, not v{version}", failures)

    def test_schema_version_const_follows_the_release_version(self) -> None:
        schemas, registry = validate_contracts.schema_catalog()
        stale = deepcopy(schemas)
        stale["schemas/common.schema.json"]["$defs"]["schema_version"]["const"] = "0.0.0"
        with mock.patch.object(validate_contracts, "schema_catalog", return_value=(stale, registry)):
            failures = validate_repository()
        self.assertIn("schemas/common.schema.json: schema_version const '0.0.0' is not VERSION "
                      + (ROOT / "VERSION").read_text(encoding="utf-8").strip(), failures)


if __name__ == "__main__":
    unittest.main()
