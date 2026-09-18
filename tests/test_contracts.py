from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_contracts import validate_repository  # noqa: E402


class ContractTests(unittest.TestCase):
    def test_repository_contracts(self) -> None:
        self.assertEqual(validate_repository(), [])


if __name__ == "__main__":
    unittest.main()
