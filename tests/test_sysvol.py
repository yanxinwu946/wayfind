"""SYSVOL cpassword walk must be gone from shipped ldap checker."""

import unittest
from pathlib import Path

import wayfind


class SysvolWalkTests(unittest.TestCase):
    def _ldap_src(self) -> str:
        return (Path(wayfind.__file__).parent / "checks" / "ldap.py").read_text(encoding="utf-8")

    def test_no_one_level_policies_walk(self):
        src = self._ldap_src()
        self.assertNotIn("listPath('SYSVOL'", src)
        self.assertNotIn('listPath("SYSVOL"', src)
        self.assertNotIn("policies_path", src)
        self.assertNotIn("_check_sysvol_passwords", src)

    def test_check_ldap_does_not_call_sysvol_walk(self):
        src = self._ldap_src()
        start = src.find("def check_ldap")
        self.assertGreater(start, 0)
        block = src[start:start + 600]
        self.assertNotIn("_check_sysvol_passwords", block)
        self.assertIn("_check_ldap_signing", block)


if __name__ == "__main__":
    unittest.main()
