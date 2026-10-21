"""Cypher strings, BH graph parse, hop composer — shipped functions."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from wayfind.core.cypher import ACL_RIGHTS, CYPHER_QUERIES, cypher_for_right
from wayfind.core.graph import parse_bloodhound_zip, shortest_acl_paths
from wayfind.core.hops import compose_hops
from wayfind.core.loot import LootStore
from wayfind.utils.nxc_parse import parse_ldap_security


class CypherTests(unittest.TestCase):
    def test_enum_rights_include_core_and_dcsync(self):
        rights = set(ACL_RIGHTS)
        for name in ("AddMember", "ForceChangePassword", "WriteSPN", "AddKeyCredentialLink",
                     "ReadGMSAPassword", "GenericAll", "WriteDacl", "GetChanges", "GetChangesAll"):
            self.assertIn(name, rights)
        for right in ACL_RIGHTS:
            query = cypher_for_right(right)
            self.assertIn(right, query)
            self.assertIn("shortestPath", query)
            self.assertIn(right, CYPHER_QUERIES[right])


class GraphTests(unittest.TestCase):
    def test_parse_zip_addmember_path(self):
        users = {
            "data": [
                {
                    "ObjectIdentifier": "S-1-5-21-1-1001",
                    "Properties": {"name": "J.ANALYST@CORP.LOCAL", "samaccountname": "j.analyst"},
                    "Aces": [],
                }
            ]
        }
        groups = {
            "data": [
                {
                    "ObjectIdentifier": "S-1-5-21-1-1100",
                    "Properties": {"name": "T1-HELP@CORP.LOCAL", "samaccountname": "T1-Help"},
                    "Aces": [
                        {
                            "PrincipalSID": "S-1-5-21-1-1001",
                            "RightName": "AddMember",
                            "PrincipalType": "User",
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            zpath = Path(tmp) / "bh.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("users.json", json.dumps(users))
                zf.writestr("groups.json", json.dumps(groups))
            edges = parse_bloodhound_zip(zpath)
            self.assertTrue(any(e[1] == "AddMember" for e in edges))
            paths = shortest_acl_paths(edges, ["j.analyst", "J.ANALYST@CORP.LOCAL"])
            self.assertTrue(paths)
            evidence = " ".join(p["evidence"] for p in paths)
            self.assertIn("AddMember", evidence)
            self.assertIn("T1-HELP", evidence.upper())


class HopTests(unittest.TestCase):
    def test_gmsa_plus_resettable_reader(self):
        facts = [
            {
                "id": "gmsa.readers",
                "asset": "gmsa-lattice$",
                "evidence": "PrincipalsAllowedToReadPassword=t.keene",
            },
            {
                "id": "acl.ForceChangePassword",
                "asset": "t.keene",
                "evidence": "J.ANALYST -ForceChangePassword-> T.KEENE",
                "extra": {"right": "ForceChangePassword", "dst": "t.keene"},
            },
        ]
        hops = compose_hops(facts)
        self.assertTrue(hops)
        self.assertIn("gmsa-lattice$", hops[0]["title"])
        self.assertIn("t.keene", hops[0]["evidence"])
        self.assertIn("ForceChangePassword", hops[0]["evidence"])


class LootTests(unittest.TestCase):
    def test_store_roundtrip(self):
        store = LootStore()
        store.add(username="j.analyst", password="Password1!", source="gpp.cpassword")
        ident = store.get("j.analyst")
        self.assertIsNotNone(ident)
        self.assertEqual(ident.password, "Password1!")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loot.json"
            store.write_json(path)
            loaded = LootStore.load(path)
            self.assertEqual(loaded.get("j.analyst").password, "Password1!")


class NxcParseTests(unittest.TestCase):
    def test_enforced_not_true_banner(self):
        sample = (
            "LDAP  10.0.0.10  389  DC  [*] Windows Server 2025 "
            "(signing:Enforced) (channel binding:Always)"
        )
        parsed = parse_ldap_security(sample)
        self.assertEqual(parsed["signing"], "Enforced")
        self.assertEqual(parsed["channel_binding"], "Always")
        self.assertNotEqual(parsed["signing"], "True")

    def test_field_without_parens(self):
        parsed = parse_ldap_security("signing:None channel binding:Never")
        self.assertEqual(parsed["signing"], "None")
        self.assertEqual(parsed["channel_binding"], "Never")


if __name__ == "__main__":
    unittest.main()
