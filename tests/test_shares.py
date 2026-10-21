"""Authenticated nxc --shares table parser."""

import unittest

from wayfind.utils.nxc_parse import parse_nxc_shares
from wayfind.core.profiles import category_of, checks_for_profile


SAMPLE = """
SMB  192.168.3.131  445  DC  [*] Windows Server 2025
SMB  192.168.3.131  445  DC  [+] maze.sec\\svc_backup:Backup!2026
SMB  192.168.3.131  445  DC  Share           Permissions     Remark
SMB  192.168.3.131  445  DC  -----           -----------     ------
SMB  192.168.3.131  445  DC  ADMIN$          READ            Remote Admin
SMB  192.168.3.131  445  DC  C$              READ,WRITE      Default share
SMB  192.168.3.131  445  DC  IPC$            READ            IPC
SMB  192.168.3.131  445  DC  NETLOGON        READ            Logon server share
SMB  192.168.3.131  445  DC  Public          READ
SMB  192.168.3.131  445  DC  SQLBackup
SMB  192.168.3.131  445  DC  SYSVOL          READ            Logon server share
"""


class ShareParseTests(unittest.TestCase):
    def test_parse_admin_and_public(self):
        rows = parse_nxc_shares(SAMPLE)
        by_name = {r["name"]: r["perms"] for r in rows}
        self.assertEqual(by_name["ADMIN$"], "READ")
        self.assertEqual(by_name["C$"], "READ,WRITE")
        self.assertEqual(by_name["Public"], "READ")
        self.assertEqual(by_name["SQLBackup"], "")
        self.assertNotIn("Share", by_name)

    def test_shares_in_audit(self):
        self.assertEqual(category_of("shares"), "directory")
        self.assertIn("shares", checks_for_profile("audit"))
        self.assertNotIn("shares", checks_for_profile("recon"))


if __name__ == "__main__":
    unittest.main()
