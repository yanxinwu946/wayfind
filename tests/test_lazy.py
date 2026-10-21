"""SecurityChecker constructs checkers on first use."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from wayfind.checks import SecurityChecker
from wayfind.checks.domain import DomainChecker
from wayfind.checks.password import PasswordChecker
from wayfind.checks.timeroast import TimeroastChecker


def _checker(tmp: Path) -> SecurityChecker:
    ldap = MagicMock()
    ldap.config.server = "10.0.0.10"
    ldap.config.domain = "corp.local"
    ldap.config.base_dn = "DC=corp,DC=local"
    session = MagicMock()
    session.target.domain = "corp.local"
    session.target.username = "j.analyst"
    session.target.password = "Password1!"
    session.target.hashes = None
    scope = MagicMock()
    return SecurityChecker(
        ldap, {"data": tmp}, target_scope=scope, session=session,
    )


class LazyCheckerTests(unittest.TestCase):
    def test_init_builds_nothing(self):
        with TemporaryDirectory() as d:
            sc = _checker(Path(d))
            self.assertEqual(sc._instances, {})

    def test_run_check_builds_only_that_checker(self):
        with TemporaryDirectory() as d:
            sc = _checker(Path(d))
            with patch.object(TimeroastChecker, "check_timeroast"):
                sc.run_check("timeroast")
            self.assertEqual(set(sc._instances), {"timeroast_checker"})
            self.assertIsInstance(sc._instances["timeroast_checker"], TimeroastChecker)
            self.assertNotIn("ntlm_checker", sc._instances)
            self.assertNotIn("bloodhound_checker", sc._instances)

    def test_shared_checker_reused(self):
        with TemporaryDirectory() as d:
            sc = _checker(Path(d))
            with patch.object(PasswordChecker, "check_password_policy"), \
                 patch.object(PasswordChecker, "check_kerberos_policy"):
                sc.run_check("password-policy")
                first = sc._instances["password_checker"]
                self.assertEqual(first.CHECK, "password-policy")
                sc.run_check("kerberos-policy")
                self.assertIs(sc._instances["password_checker"], first)
                self.assertEqual(first.CHECK, "kerberos-policy")
            self.assertEqual(set(sc._instances), {"password_checker"})

    def test_attr_access_lazy(self):
        with TemporaryDirectory() as d:
            sc = _checker(Path(d))
            self.assertEqual(sc._instances, {})
            checker = sc.domain_checker
            self.assertIsInstance(checker, DomainChecker)
            self.assertIs(sc.domain_checker, checker)
            self.assertEqual(set(sc._instances), {"domain_checker"})


if __name__ == "__main__":
    unittest.main()
