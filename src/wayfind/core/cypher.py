"""Fixed BloodHound Cypher for ACL rights we emit as enum facts."""

from __future__ import annotations

from typing import Dict, Tuple

# Inventory edges for an agent. Not an exploit list.
ACL_RIGHTS: Tuple[str, ...] = (
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
)


def cypher_for_right(right: str) -> str:
    if right not in ACL_RIGHTS:
        raise ValueError(f"unsupported ACL right: {right}")
    return (
        f"MATCH p=shortestPath((n)-[:{right}*1..]->(m)) "
        f"RETURN n.name AS src, m.name AS dst, length(p) AS hops, type(relationships(p)[0]) AS right"
    )


def cypher_owned_paths(owned_name: str) -> str:
    rights = "|".join(ACL_RIGHTS)
    return (
        f"MATCH p=shortestPath((n {{name: '{owned_name}'}})-[:{rights}*1..6]->(m)) "
        f"RETURN n.name AS src, m.name AS dst, [r IN relationships(p) | type(r)] AS rights, length(p) AS hops"
    )


CYPHER_QUERIES: Dict[str, str] = {right: cypher_for_right(right) for right in ACL_RIGHTS}
CYPHER_QUERIES["owned-paths"] = cypher_owned_paths("{owned}")
