"""0.1.6 findings API: stable ids, extra, severity, replay, hop dedup, run meta."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wayfind.checks.emit import note, sams
from wayfind.core.hops import compose_hops
from wayfind.core.session import Session
from wayfind.core.target import Target
from wayfind.output.findings import SCHEMA, FindingStore


def _target(**kw):
    base = dict(domain="maze.sec", dc_ip="192.168.3.129", username="n.elias", password="x")
    base.update(kw)
    return Target(**base)


def _session(tmp: Path, **kw) -> Session:
    root = tmp
    paths = {
        "root": root,
        "findings": root / "findings",
        "data": root / "data",
        "checks": root / "checks",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return Session(_target(**kw), paths)


class StableIdTests(unittest.TestCase):
    def test_note_keeps_explicit_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp))
            checker = MagicMock()
            checker.session = session
            checker.CHECK = "password-policy"
            checker.logger = MagicMock()
            note(
                checker,
                "Password length requirement is 7 characters",
                id="password-policy.min-length",
                min_length=7,
            )
            row = session.findings.as_list()[0]
            self.assertEqual(row["id"], "password-policy.min-length")
            self.assertEqual(row["extra"]["min_length"], 7)

    def test_sams_and_count(self):
        names = sams([{"sAMAccountName": "a"}, {"sAMAccountName": "b"}])
        self.assertEqual(names, ["a", "b"])
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp))
            checker = MagicMock()
            checker.session = session
            checker.CHECK = "user-attrs"
            checker.logger = MagicMock()
            note(checker, "2 users have DONT_EXPIRE_PASSWORD flag",
                 id="user-attrs.dont-expire", names=names)
            extra = session.findings.as_list()[0]["extra"]
            self.assertEqual(extra["names"], ["a", "b"])
            self.assertEqual(extra["count"], 2)


class ReplayTests(unittest.TestCase):
    def test_collect_replay_has_no_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp), dc_host="dc.maze.sec", use_ldaps=True)
            replay = session.collect_replay("dc.maze.sec")
            self.assertIn("bloodhound-python", replay)
            self.assertIn("-u", replay)
            self.assertIn("n.elias", replay)
            self.assertIn("-d", replay)
            self.assertIn("maze.sec", replay)
            self.assertIn("--zip", replay)
            self.assertIn("-dc", replay)
            self.assertIn("dc.maze.sec", replay)
            parts = replay.split()
            self.assertNotIn("-p", parts)
            self.assertNotIn("--hashes", parts)
            self.assertIn("--use-ldaps", parts)

    def test_certipy_replay_has_no_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp), dc_host="dc.maze.sec", use_ldaps=True)
            replay = session.certipy_replay(["find", "-json"])
            self.assertIn("certipy find -json", replay)
            self.assertIn("n.elias@maze.sec", replay)
            parts = replay.split()
            self.assertNotIn("-p", parts)
            self.assertIn("-ldap-scheme", parts)
            self.assertIn("ldaps", parts)


class HopDedupTests(unittest.TestCase):
    def test_owned_acl_replaces_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp))
            session.emit(
                id="acl.AddMember", severity="medium", title="owned",
                asset="T1-CALLDESK@MAZE.SEC", check="bloodhound",
                src="N.ELIAS@MAZE.SEC", right="AddMember", dst="T1-CALLDESK@MAZE.SEC",
            )
            session.emit(
                id="acl.AddMember", severity="medium", title="inventory",
                asset="FABRIC-READERS@MAZE.SEC", check="bloodhound",
                src="Q.MORA@MAZE.SEC", right="AddMember", dst="FABRIC-READERS@MAZE.SEC",
            )
            session.write_findings()
            rows = session.findings.as_list()
            ids = [r["id"] for r in rows]
            self.assertIn("hop.owned-acl", ids)
            owned_acl = [r for r in rows if r["id"] == "acl.AddMember"]
            self.assertEqual(len(owned_acl), 1)
            self.assertEqual(owned_acl[0]["extra"]["src"], "Q.MORA@MAZE.SEC")
            hop = next(r for r in rows if r["id"] == "hop.owned-acl")
            self.assertEqual(hop["severity"], "high")
            self.assertEqual(hop["extra"]["right"], "AddMember")

    def test_owned_group_from_memberof(self):
        facts = [{
            "id": "acl.MemberOf",
            "asset": "BACKUP OPERATORS@MAZE.SEC",
            "extra": {
                "right": "MemberOf",
                "src": "SVC_BACKUP@MAZE.SEC",
                "dst": "BACKUP OPERATORS@MAZE.SEC",
            },
        }]
        hops = compose_hops(facts, owned=["svc_backup"])
        self.assertEqual(hops[0]["id"], "hop.owned-group")
        self.assertTrue(hops[0]["privileged"])
        self.assertEqual(hops[0]["right"], "MemberOf")

    def test_gmsa_readers_from_extra_names(self):
        facts = [
            {
                "id": "gmsa.readers",
                "asset": "gmsa-lattice$",
                "extra": {"readers": ["t.keene"], "names": ["t.keene"], "count": 1},
            },
            {
                "id": "acl.ForceChangePassword",
                "asset": "t.keene",
                "extra": {"right": "ForceChangePassword", "dst": "t.keene"},
            },
        ]
        hops = compose_hops(facts)
        self.assertTrue(hops)
        self.assertEqual(hops[0]["id"], "hop.compose")


class RunMetaTests(unittest.TestCase):
    def test_findings_json_embeds_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _session(Path(tmp), dc_host="dc.maze.sec", use_ldaps=True, dns="192.168.3.129")
            session.mark_check("bloodhound")
            session.mark_check("password-policy")
            session.emit(
                id="password-policy.min-length", severity="medium",
                title="Password length requirement is 7 characters",
                check="password-policy", min_length=7,
            )
            session.write_findings()
            payload = json.loads((Path(tmp) / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], SCHEMA)
            self.assertEqual(payload["version"], "0.1.6")
            run = payload["run"]
            self.assertEqual(run["identity"], "n.elias")
            self.assertEqual(run["domain"], "maze.sec")
            self.assertEqual(run["dc"], "192.168.3.129")
            self.assertEqual(run["dc_host"], "dc.maze.sec")
            self.assertTrue(run["ldaps"])
            self.assertEqual(run["dns"], "192.168.3.129")
            self.assertEqual(run["checks"], ["bloodhound", "password-policy"])
            self.assertEqual(run["findings"], 1)
            sidecar = json.loads((Path(tmp) / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(sidecar["identity"], "n.elias")
            self.assertEqual(sidecar["checks"], ["bloodhound", "password-policy"])


if __name__ == "__main__":
    unittest.main()
