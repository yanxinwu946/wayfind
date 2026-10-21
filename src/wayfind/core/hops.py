"""Compose related findings into hop findings (no LDAP)."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


PRIVILEGED_GROUPS = {
    "administrators",
    "account operators",
    "backup operators",
    "print operators",
    "server operators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "dns admins",
    "group policy creator owners",
    "krbtgt",
    "enterprise key admins",
    "key admins",
    "cryptographic operators",
    "replicator",
    "domain controllers",
    "enterprise domain controllers",
    "read-only domain controllers",
    "adminsdholder",
}


def principal_sam(name: str) -> str:
    n = (name or "").strip()
    if "\\" in n:
        n = n.rsplit("\\", 1)[-1]
    if "/" in n:
        n = n.rsplit("/", 1)[-1]
    if "@" in n:
        n = n.split("@", 1)[0]
    return n.lower()


_sam = principal_sam


def is_privileged_group(name: str) -> bool:
    sam = principal_sam(name).replace("_", " ").replace("-", " ")
    return sam in PRIVILEGED_GROUPS


def _readers_from_gmsa(fact: Mapping[str, Any]) -> List[str]:
    evidence = str(fact.get("evidence") or "")
    extra = fact.get("extra") or {}
    raw = extra.get("readers") or extra.get("names") or extra.get("PrincipalsAllowedToReadPassword") or ""
    if "PrincipalsAllowedToReadPassword=" in evidence and not raw:
        raw = evidence.split("PrincipalsAllowedToReadPassword=", 1)[1]
    if isinstance(raw, (list, tuple)):
        return [str(n) for n in raw if n]
    names = re.split(r"[,;]\s*", str(raw).strip())
    return [n for n in names if n]


def _acl_principal(fact: Mapping[str, Any], key: str = "dst") -> str:
    extra = fact.get("extra") or {}
    if extra.get(key):
        return str(extra[key])
    if key == "dst":
        return str(fact.get("asset") or "")
    return ""


def _acl_right(fact: Mapping[str, Any]) -> str:
    extra = fact.get("extra") or {}
    evidence = str(fact.get("evidence") or "")
    if extra.get("right"):
        return str(extra["right"])
    fid = str(fact.get("id") or "")
    if fid.startswith("acl."):
        return fid.split(".", 1)[1]
    for right in (
        "AddMember",
        "ForceChangePassword",
        "WriteSPN",
        "AddKeyCredentialLink",
        "ReadGMSAPassword",
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights",
        "GetChanges",
        "GetChangesAll",
        "DCSync",
        "AddSelf",
        "Owns",
        "ReadLAPSPassword",
        "MemberOf",
    ):
        if right in evidence or right in fid:
            return right
    return ""


def _acl_src(fact: Mapping[str, Any]) -> str:
    extra = fact.get("extra") or {}
    if extra.get("src"):
        return str(extra["src"])
    evidence = str(fact.get("evidence") or "")
    if " -" in evidence and "-> " in evidence:
        return evidence.split(" -", 1)[0].strip()
    return ""


def compose_hops(
    facts: Iterable[Mapping[str, Any]],
    owned: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Turn related facts into hop findings for an agent planner."""
    items = list(facts)
    gmsa_facts = [f for f in items if str(f.get("id") or "") == "gmsa.readers"]
    gpp_facts = [f for f in items if str(f.get("id") or "") == "gpp.cpassword"]
    acl_facts = [
        f for f in items
        if str(f.get("id") or "").startswith("acl.") or _acl_right(f)
    ]
    hops: List[Dict[str, Any]] = []
    seen = set()

    owned_sams = {principal_sam(x) for x in (owned or []) if x}
    for gpp in gpp_facts:
        owned_sams.add(principal_sam(str(gpp.get("asset") or "")))

    for gmsa in gmsa_facts:
        gmsa_name = str(gmsa.get("asset") or "")
        for reader in _readers_from_gmsa(gmsa):
            for acl in acl_facts:
                right = _acl_right(acl)
                dst = _acl_principal(acl)
                if not right or principal_sam(dst) != principal_sam(reader):
                    continue
                key = ("gmsa", gmsa_name.lower(), principal_sam(reader), right)
                if key in seen:
                    continue
                seen.add(key)
                hops.append({
                    "id": "hop.compose",
                    "severity": "high",
                    "title": f"{gmsa_name} via {reader} ({right})",
                    "asset": gmsa_name,
                    "evidence": (
                        f"gMSA {gmsa_name} readable by {reader}; "
                        f"{right} on {reader}"
                    ),
                    "replay": str(acl.get("replay") or gmsa.get("replay") or ""),
                    "backend": "compose",
                    "check": "bloodhound",
                    "opsec": "read-only LDAP",
                    "reader": reader,
                    "right": right,
                    "src": reader,
                    "dst": gmsa_name,
                })

    for acl in acl_facts:
        right = _acl_right(acl)
        src = _acl_src(acl)
        dst = _acl_principal(acl)
        if not right or not src or principal_sam(src) not in owned_sams:
            continue
        replay = str(acl.get("replay") or "")
        if right == "MemberOf":
            key = ("owned-group", principal_sam(src), principal_sam(dst))
            if key in seen:
                continue
            seen.add(key)
            hops.append({
                "id": "hop.owned-group",
                "severity": "high",
                "title": f"owned {principal_sam(src)} member of {dst}",
                "asset": dst,
                "evidence": f"looted/current {principal_sam(src)} is MemberOf {dst}",
                "replay": replay,
                "backend": "compose",
                "check": "bloodhound",
                "opsec": "read-only LDAP",
                "src": src,
                "right": right,
                "dst": dst,
                "privileged": is_privileged_group(dst),
            })
            continue
        key = ("owned", principal_sam(src), right, principal_sam(dst))
        if key in seen:
            continue
        seen.add(key)
        hops.append({
            "id": "hop.owned-acl",
            "severity": "high",
            "title": f"owned {principal_sam(src)} {right} {dst}",
            "asset": dst,
            "evidence": f"looted/current {principal_sam(src)} has {right} on {dst}",
            "replay": replay,
            "backend": "compose",
            "check": "bloodhound",
            "opsec": "read-only LDAP",
            "src": src,
            "right": right,
            "dst": dst,
        })
    return hops
