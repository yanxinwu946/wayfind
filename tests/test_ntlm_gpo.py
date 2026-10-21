"""NTLM GPO parse: one pass, Registry.pol wins over GptTmpl.inf."""

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from wayfind.checks.ntlm import GpoSettings, apply_gpttmpl, apply_pol


def _dword(value: int) -> bytes:
    return struct.pack("<I", value)


class ApplyPolTests(unittest.TestCase):
    def test_pol_fills_lm_llmnr_restrict(self):
        rec = GpoSettings(guid="{AAA}", name="Test")
        entries = [
            (r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 4, 4, _dword(2)),
            (r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 4, 4, _dword(0)),
            (r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictNTLMInDomain", 4, 4, _dword(4)),
        ]
        with patch("wayfind.checks.ntlm.parse_pol_file", return_value=entries):
            apply_pol(rec, b"preg")
        self.assertEqual(rec.lm_level, 2)
        self.assertEqual(rec.enable_multicast, 0)
        self.assertEqual(rec.restrict_ntlm_domain, 4)
        self.assertTrue(rec.restricted)

    def test_pol_does_not_overwrite(self):
        rec = GpoSettings(guid="{AAA}", name="Test", lm_level=5)
        entries = [
            (r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 4, 4, _dword(1)),
        ]
        with patch("wayfind.checks.ntlm.parse_pol_file", return_value=entries):
            apply_pol(rec, b"preg")
        self.assertEqual(rec.lm_level, 5)


class ApplyGpttmplTests(unittest.TestCase):
    def test_inf_fills_missing_lm(self):
        rec = GpoSettings(guid="{AAA}", name="Test")
        parsed = {
            "Registry Values": {
                r"machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel": "4,3",
            }
        }
        with patch("wayfind.checks.ntlm.parse_gpttmpl_inf", return_value=parsed):
            apply_gpttmpl(rec, b"inf")
        self.assertEqual(rec.lm_level, 3)

    def test_pol_wins_over_inf(self):
        rec = GpoSettings(guid="{AAA}", name="Test", lm_level=2)
        parsed = {
            "Registry Values": {
                r"machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel": "4,5",
                r"machine\system\currentcontrolset\control\lsa\msv1_0\restrictsendingntlmtraffic": "4,2",
            }
        }
        with patch("wayfind.checks.ntlm.parse_gpttmpl_inf", return_value=parsed):
            apply_gpttmpl(rec, b"inf")
        self.assertEqual(rec.lm_level, 2)
        self.assertEqual(rec.restrict_sending, 2)
        self.assertTrue(rec.restricted)


def _ntlm_checker(tmp: Path):
    from wayfind.checks.ntlm import NTLMChecker

    findings = tmp / "findings"
    checks = tmp / "checks"
    findings.mkdir()
    checks.mkdir()
    ldap = MagicMock()
    ldap.config.base_dn = "DC=corp,DC=local"
    ldap.config.server = "10.0.0.10"
    ldap.config.domain = "corp.local"
    ldap.query.return_value = [
        {"dNSHostName": "dc.corp.local", "name": "DC", "operatingSystem": "Windows Server 2022"}
    ]
    ldap.get_config_dn.return_value = "CN=Configuration,DC=corp,DC=local"
    return NTLMChecker(
        ldap, {"findings": findings, "checks": checks},
        server="10.0.0.10", username="j", password="p", domain="corp.local",
    )


class LoadOnceTests(unittest.TestCase):
    def test_check_ntlm_lists_policies_once(self):
        with TemporaryDirectory() as d:
            checker = _ntlm_checker(Path(d))
            policy = MagicMock()
            policy.get_longname.return_value = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

            with patch.object(checker, "_get_linked_gpo_guids", return_value=set()), \
                 patch.object(checker, "_get_gpo_display_name", return_value="Default Domain Policy"), \
                 patch.object(checker, "_read_sysvol", return_value=None), \
                 patch("wayfind.checks.ntlm.select_reachable_dc", return_value="dc.corp.local"), \
                 patch("impacket.smbconnection.SMBConnection") as smb_cls:
                conn = smb_cls.return_value
                conn.listPath.return_value = [policy]
                checker.check_ntlm()
                self.assertEqual(conn.listPath.call_count, 1)
                conn.login.assert_called_once()
                conn.logoff.assert_called_once()

    def test_unlinked_guid_skipped_still_one_listing(self):
        with TemporaryDirectory() as d:
            checker = _ntlm_checker(Path(d))
            linked = MagicMock()
            linked.get_longname.return_value = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
            orphan = MagicMock()
            orphan.get_longname.return_value = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"

            with patch.object(
                     checker, "_get_linked_gpo_guids",
                     return_value={"{31B2F340-016D-11D2-945F-00C04FB984F9}"},
                 ), \
                 patch.object(checker, "_get_gpo_display_name", return_value="Default Domain Policy"), \
                 patch.object(checker, "_read_sysvol", return_value=None) as read_sysvol, \
                 patch("wayfind.checks.ntlm.select_reachable_dc", return_value="dc.corp.local"), \
                 patch("impacket.smbconnection.SMBConnection") as smb_cls:
                conn = smb_cls.return_value
                conn.listPath.return_value = [linked, orphan]
                checker.check_ntlm()
                self.assertEqual(conn.listPath.call_count, 1)
                read_paths = [call.args[1] for call in read_sysvol.call_args_list]
                self.assertTrue(any("{31B2F340-016D-11D2-945F-00C04FB984F9}" in p for p in read_paths))
                self.assertFalse(any("AAAAAAAA-AAAA" in p for p in read_paths))


if __name__ == "__main__":
    unittest.main()
