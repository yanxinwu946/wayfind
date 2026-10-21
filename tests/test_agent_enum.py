"""Agent-enum contract: tickets gate, owned hops, pfx/socks, prior findings."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wayfind.core.hops import compose_hops
from wayfind.core.loot import LootStore
from wayfind.core.profiles import included_in, want_kerberos_tickets, checks_for_profile
from wayfind.core.session import Session
from wayfind.core.target import Target
from wayfind.output.findings import FindingStore
from wayfind.utils.bins import apply_socks_env


class TicketGateTests(unittest.TestCase):
    def test_audit_lists_roasting_without_tickets(self):
        self.assertTrue(included_in("audit", "roasting"))
        self.assertIn("roasting", checks_for_profile("audit"))
        self.assertFalse(want_kerberos_tickets("audit"))
        self.assertTrue(want_kerberos_tickets("offensive"))
        self.assertFalse(included_in("audit", "dc-vulns"))


class OwnedHopTests(unittest.TestCase):
    def test_gpp_plus_addmember(self):
        facts = [
            {
                "id": "gpp.cpassword",
                "asset": "j.analyst",
                "evidence": "Groups.xml",
            },
            {
                "id": "acl.AddMember",
                "asset": "T1-HELP@CORP.LOCAL",
                "evidence": "J.ANALYST@CORP.LOCAL -AddMember-> T1-HELP@CORP.LOCAL",
                "extra": {
                    "right": "AddMember",
                    "src": "J.ANALYST@CORP.LOCAL",
                    "dst": "T1-HELP@CORP.LOCAL",
                },
            },
        ]
        hops = compose_hops(facts)
        self.assertTrue(hops)
        ids = {h["id"] for h in hops}
        self.assertIn("hop.owned-acl", ids)
        blob = " ".join(h["evidence"] for h in hops).lower()
        self.assertIn("addmember", blob)
        self.assertIn("t1-help", blob)

    def test_loot_owned_matches_upn(self):
        facts = [
            {
                "id": "acl.GenericAll",
                "asset": "DOMAIN ADMINS@CORP.LOCAL",
                "evidence": "J.ANALYST@CORP.LOCAL -GenericAll-> DOMAIN ADMINS@CORP.LOCAL",
                "extra": {"right": "GenericAll", "src": "J.ANALYST@CORP.LOCAL", "dst": "DOMAIN ADMINS@CORP.LOCAL"},
            }
        ]
        hops = compose_hops(facts, owned=["j.analyst"])
        self.assertTrue(any(h["id"] == "hop.owned-acl" for h in hops))


class CertipyPfxTests(unittest.TestCase):
    def test_pfx_forwarded_not_password(self):
        t = Target(
            domain="corp.local",
            dc_ip="10.0.0.10",
            username="j.analyst",
            password="Password1!",
            pfx="/tmp/user.pfx",
            socks="127.0.0.1:1080",
            use_ldaps=True,
        )
        session = Session(t, {"data": Path("/tmp"), "root": Path("/tmp")})
        with patch("wayfind.core.session.certipy_bin", return_value="/usr/local/bin/certipy"):
            cmd = session.certipy_cmd(["find", "-vulnerable", "-json"])
        self.assertIn("-pfx", cmd)
        self.assertIn("/tmp/user.pfx", cmd)
        self.assertIn("-socks", cmd)
        self.assertNotIn("-p", cmd)


class SocksEnvTests(unittest.TestCase):
    def test_all_proxy(self):
        import os
        os.environ.pop("ALL_PROXY", None)
        apply_socks_env("127.0.0.1:9050")
        self.assertEqual(os.environ.get("ALL_PROXY"), "socks5://127.0.0.1:9050")
        os.environ.pop("ALL_PROXY", None)
        os.environ.pop("all_proxy", None)
        os.environ.pop("SOCKS_PROXY", None)


class SeedFindingsTests(unittest.TestCase):
    def test_seed_from_loot_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "findings.json").write_text(json.dumps({
                "findings": [{
                    "id": "gpp.cpassword",
                    "severity": "high",
                    "title": "GPP cpassword for j.analyst",
                    "asset": "j.analyst",
                    "evidence": "Groups.xml",
                    "replay": "nxc -M gpp_password",
                    "backend": "nxc",
                    "check": "gpp",
                    "opsec": "hit DC",
                }]
            }) + "\n", encoding="utf-8")
            loot = root / "loot.json"
            LootStore().write_json(loot)
            t = Target(domain="corp.local", dc_ip="10.0.0.10", username="j.analyst")
            session = Session(t, {"data": root, "root": root})
            n = session.seed_prior_findings(loot)
            self.assertEqual(n, 1)
            ids = [f["id"] for f in session.findings.as_list()]
            self.assertIn("gpp.cpassword", ids)


if __name__ == "__main__":
    unittest.main()
