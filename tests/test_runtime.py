"""Session runtime: nxc argv, emit helper, kerberos LDAP bind."""

import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from wayfind.checks.emit import note
from wayfind.core.session import Session
from wayfind.core.target import Target
from wayfind.utils.bins import nxc_cmd_from_target
from wayfind.utils.ldap import LDAPConfig, LDAPConnection


def _target(**kw):
    base = dict(domain="corp.local", dc_ip="10.0.0.10", username="j.analyst", password="Password1!")
    base.update(kw)
    return Target(**base)


class NxcCmdTests(unittest.TestCase):
    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_dns_and_password(self, _bin):
        cmd = nxc_cmd_from_target(_target(dns="10.0.0.10"), "smb")
        self.assertIn("--dns-server", cmd)
        self.assertEqual(cmd[cmd.index("--dns-server") + 1], "10.0.0.10")
        self.assertIn("-p", cmd)
        self.assertIn("-d", cmd)

    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_kerberos_kdc(self, _bin):
        cmd = nxc_cmd_from_target(
            _target(kerberos=True, dc_host="DC.corp.local", password=None), "ldap"
        )
        self.assertIn("-k", cmd)
        self.assertIn("--kdcHost", cmd)
        self.assertEqual(cmd[cmd.index("--kdcHost") + 1], "DC.corp.local")

    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_hash_not_password(self, _bin):
        cmd = nxc_cmd_from_target(_target(password=None, hashes="aad3b435b51404eeaad3b435b51404ee:31d6"), "smb")
        self.assertIn("-H", cmd)
        self.assertNotIn("-p", cmd)

    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_auth_false_null_session(self, _bin):
        cmd = nxc_cmd_from_target(
            _target(), "smb", extra=["-u", "", "-p", ""], auth=False, host="hosts.txt"
        )
        self.assertEqual(cmd[2], "hosts.txt")
        self.assertNotIn("-k", cmd)
        self.assertEqual(cmd[-4:], ["-u", "", "-p", ""])
        self.assertIn("--dns-server", cmd)


class NoteEmitTests(unittest.TestCase):
    def test_note_emits_when_session(self):
        t = _target()
        session = Session(t, {"data": Path("/tmp"), "root": Path("/tmp")})
        checker = MagicMock()
        checker.session = session
        checker.CHECK = "laps"
        checker.logger = MagicMock()
        note(checker, "The current user could read LAPS passwords", severity="high")
        ids = [f.id for f in session.findings._items]
        self.assertTrue(any(i.startswith("laps.") for i in ids))
        self.assertTrue(any("LAPS" in f.title for f in session.findings._items))

    def test_note_without_session_logs(self):
        checker = MagicMock()
        checker.session = None
        checker.CHECK = "laps"
        note(checker, "hello")
        checker.logger.finding.assert_called_once_with("hello")


class LdapKerberosTests(unittest.TestCase):
    @patch("wayfind.utils.ldap.Connection")
    @patch("wayfind.utils.ldap.Server")
    def test_kerberos_sasl(self, _server, conn_cls):
        from ldap3 import SASL
        cfg = LDAPConfig(
            server="10.0.0.10", domain="corp.local", username="j.analyst",
            password="", use_kerberos=True,
        )
        LDAPConnection(cfg).connect()
        kwargs = conn_cls.call_args.kwargs
        self.assertEqual(kwargs.get("authentication"), SASL)

    @patch("wayfind.utils.ldap.Connection")
    @patch("wayfind.utils.ldap.Server")
    def test_ntlm_still_default(self, _server, conn_cls):
        from ldap3 import NTLM
        cfg = LDAPConfig(
            server="10.0.0.10", domain="corp.local", username="j.analyst",
            password="Password1!",
        )
        LDAPConnection(cfg).connect()
        kwargs = conn_cls.call_args.kwargs
        self.assertEqual(kwargs.get("authentication"), NTLM)


if __name__ == "__main__":
    unittest.main()

class TargetAuthTests(unittest.TestCase):
    def test_hash_bind_secret_lm_nt(self):
        t = _target(password=None, hashes="31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertTrue(t.ldap_bind_secret.endswith(":31d6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertTrue(t.ldap_bind_secret.startswith("aad3b435b51404eeaad3b435b51404ee:"))
        self.assertIsNone(t.ldap_config().pfx)

    def test_pfx_on_ldap_config(self):
        t = _target(pfx="/tmp/user.pfx", password=None)
        self.assertEqual(t.ldap_config().pfx, "/tmp/user.pfx")

    def test_adauthmanager_removed(self):
        import wayfind.core.auth as auth
        self.assertFalse(hasattr(auth, "ADAuthManager"))
        self.assertTrue(hasattr(auth, "Credentials"))

    def test_old_nxc_cmd_removed(self):
        import wayfind.utils.bins as bins
        self.assertFalse(hasattr(bins, "nxc_cmd"))
        self.assertTrue(hasattr(bins, "nxc_cmd_from_target"))


class NxcPfxTests(unittest.TestCase):
    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_pfx_cert_not_password(self, _bin):
        cmd = nxc_cmd_from_target(_target(pfx="/tmp/user.pfx", password=None), "ldap")
        self.assertIn("--pfx-cert", cmd)
        self.assertEqual(cmd[cmd.index("--pfx-cert") + 1], "/tmp/user.pfx")
        self.assertNotIn("-p", cmd)
        self.assertNotIn("-H", cmd)

    @patch("wayfind.utils.bins.nxc_bin", return_value="nxc")
    def test_ccache_use_kcache(self, _bin):
        cmd = nxc_cmd_from_target(
            _target(kerberos=True, ccache="/tmp/user.ccache", password=None, dc_host="DC.corp.local"),
            "ldap",
        )
        self.assertIn("-k", cmd)
        self.assertIn("--use-kcache", cmd)
        self.assertIn("--kdcHost", cmd)


class LdapPfxTests(unittest.TestCase):
    @patch("wayfind.utils.ldap.LDAPConnection._tls_from_pfx")
    @patch("wayfind.utils.ldap.Connection")
    @patch("wayfind.utils.ldap.Server")
    def test_pfx_sasl_external(self, _server, conn_cls, tls_fn):
        from ldap3 import SASL, EXTERNAL
        tls_fn.return_value = MagicMock()
        cfg = LDAPConfig(
            server="10.0.0.10", domain="corp.local", username="j.analyst",
            password="", pfx="/tmp/user.pfx",
        )
        LDAPConnection(cfg).connect()
        kwargs = conn_cls.call_args.kwargs
        self.assertEqual(kwargs.get("authentication"), SASL)
        self.assertEqual(kwargs.get("sasl_mechanism"), EXTERNAL)
        tls_fn.assert_called_once()

