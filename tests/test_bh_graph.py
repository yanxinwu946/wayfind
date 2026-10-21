"""BloodHound zip parse follows Viewer relations: Members, SID lookup, no dump-all."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from wayfind.core.graph import (
    is_default_ace_source,
    parse_bloodhound_zip,
    should_emit_owned_path,
    shortest_acl_paths,
)


def _zip(users, groups) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    path = Path(tmp.name)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("users.json", json.dumps({"meta": {"type": "users"}, "data": users}))
        zf.writestr("groups.json", json.dumps({"meta": {"type": "groups"}, "data": groups}))
    return path


class ViewerParseTests(unittest.TestCase):
    def test_memberof_from_sam_alias(self):
        users = [{
            "ObjectIdentifier": "S-1-5-21-1-1108",
            "Properties": {"name": "SVC_BACKUP@MAZE.SEC", "samaccountname": "svc_backup"},
            "Aces": [],
        }]
        groups = [{
            "ObjectIdentifier": "S-1-5-21-1-551",
            "Properties": {"name": "BACKUP OPERATORS@MAZE.SEC", "samaccountname": "Backup Operators"},
            "Members": [{"ObjectIdentifier": "S-1-5-21-1-1108", "ObjectType": "User"}],
            "Aces": [{
                "PrincipalSID": "S-1-5-21-1-512",
                "RightName": "GenericAll",
                "PrincipalType": "Group",
            }],
        }]
        path = _zip(users, groups)
        try:
            edges = parse_bloodhound_zip(path)
            self.assertTrue(any(e[1] == "MemberOf" for e in edges))
            paths = shortest_acl_paths(edges, ["svc_backup"])
            self.assertTrue(paths)
            evidence = " ".join(p["evidence"] for p in paths)
            self.assertIn("MemberOf", evidence)
            self.assertIn("BACKUP OPERATORS", evidence.upper())
            owned = [p for p in paths if should_emit_owned_path(p)]
            self.assertTrue(owned)
            self.assertTrue(all(p["right"] == "MemberOf" for p in owned))
        finally:
            path.unlink()

    def test_nested_group_then_genericwrite(self):
        users = [{
            "ObjectIdentifier": "S-1-5-21-1-1001",
            "Properties": {"name": "A.CHEN@MAZE.SEC", "samaccountname": "a.chen"},
            "Aces": [],
        }, {
            "ObjectIdentifier": "S-1-5-21-1-1104",
            "Properties": {"name": "SVC_SQL@MAZE.SEC", "samaccountname": "svc_sql"},
            "Aces": [{
                "PrincipalSID": "S-1-5-21-1-1200",
                "RightName": "GenericWrite",
                "PrincipalType": "Group",
            }],
        }]
        groups = [{
            "ObjectIdentifier": "S-1-5-21-1-1200",
            "Properties": {"name": "HELPDESKTEAM@MAZE.SEC", "samaccountname": "HelpdeskTeam"},
            "Members": [{"ObjectIdentifier": "S-1-5-21-1-1001", "ObjectType": "User"}],
            "Aces": [],
        }]
        path = _zip(users, groups)
        try:
            edges = parse_bloodhound_zip(path)
            paths = shortest_acl_paths(edges, ["a.chen"])
            rights = {p["right"] for p in paths}
            self.assertIn("MemberOf", rights)
            self.assertIn("GenericWrite", rights)
            gw = [p for p in paths if p["right"] == "GenericWrite"]
            self.assertTrue(any("SVC_SQL" in p["dst"].upper() for p in gw))
        finally:
            path.unlink()

    def test_default_ace_source_filtered(self):
        self.assertTrue(is_default_ace_source("DOMAIN ADMINS@MAZE.SEC"))
        self.assertTrue(is_default_ace_source("Administrators"))
        self.assertFalse(is_default_ace_source("SVC_PORTAL@MAZE.SEC"))
        self.assertFalse(is_default_ace_source("HELPDESKTEAM@MAZE.SEC"))

    def test_domain_users_memberof_not_emitted(self):
        item = {
            "src": "SVC_BACKUP@MAZE.SEC",
            "dst": "DOMAIN USERS@MAZE.SEC",
            "right": "MemberOf",
        }
        self.assertFalse(should_emit_owned_path(item))
        item["dst"] = "BACKUP OPERATORS@MAZE.SEC"
        self.assertTrue(should_emit_owned_path(item))


if __name__ == "__main__":
    unittest.main()
