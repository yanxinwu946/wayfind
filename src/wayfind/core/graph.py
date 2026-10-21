"""Parse BloodHound JSON/zip into graph edges.

Relation extraction follows Bloodhound_Viewer:
content-typed collections, SID lookup, Members/memberOf, PrimaryGroupSID,
Aces, sessions, and delegation. Pathfinding is local BFS, not Cypher.
"""

from __future__ import annotations

import json
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .cypher import ACL_RIGHTS

Edge = Tuple[str, str, str]  # src, right, dst

TRAVERSE_RIGHTS: Set[str] = set(ACL_RIGHTS) | {
    "MemberOf",
    "AllowedToDelegate",
    "AllowedToAct",
}

# Built-in principals whose outbound ACEs are default domain noise.
_DEFAULT_ACE_SOURCES = {
    "ADMINISTRATORS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "ENTERPRISE DOMAIN CONTROLLERS",
    "DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
    "ENTERPRISE KEY ADMINS",
    "KEY ADMINS",
    "ACCOUNT OPERATORS",
    "PRINT OPERATORS",
    "SERVER OPERATORS",
    "RAS AND IAS SERVERS",
    "CLONEABLE DOMAIN CONTROLLERS",
    "GROUP POLICY CREATOR OWNERS",
    "CRYPTOGRAPHIC OPERATORS",
}

_PRIVILEGED_GROUPS = {
    "ADMINISTRATORS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMS",
    "SCHEMA ADMINS",
    "BACKUP OPERATORS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "DNSADMINS",
    "GROUP POLICY CREATOR OWNERS",
    "HYPER-V ADMINISTRATORS",
    "REMOTE DESKTOP USERS",
    "REMOTE MANAGEMENT USERS",
    "REPLICATOR",
    "DISTRIBUTED COM USERS",
}

_COLLECTION_KEYS = {
    "user": "users",
    "users": "users",
    "group": "groups",
    "groups": "groups",
    "computer": "computers",
    "computers": "computers",
    "domain": "domains",
    "domains": "domains",
    "gpo": "gpos",
    "gpos": "gpos",
    "ou": "ous",
    "ous": "ous",
    "container": "containers",
    "containers": "containers",
}


def _norm(name: str) -> str:
    return (name or "").strip().upper()


def _sam_key(name: str) -> str:
    n = _norm(name)
    if "\\" in n:
        n = n.rsplit("\\", 1)[-1]
    if "/" in n:
        n = n.rsplit("/", 1)[-1]
    if "@" in n:
        n = n.split("@", 1)[0]
    return n


def _aliases(name: str) -> List[str]:
    n = _norm(name)
    if not n:
        return []
    out = [n]
    sam = _sam_key(n)
    if sam and sam not in out:
        out.append(sam)
    return out


def is_default_ace_source(name: str) -> bool:
    return _sam_key(name) in _DEFAULT_ACE_SOURCES


def is_privileged_group(name: str) -> bool:
    return _sam_key(name) in _PRIVILEGED_GROUPS


def should_emit_owned_path(item: dict) -> bool:
    right = item.get("right") or ""
    if right in ACL_RIGHTS or right in ("AllowedToDelegate", "AllowedToAct"):
        return True
    if right == "MemberOf":
        return is_privileged_group(str(item.get("dst") or ""))
    return False


def _object_name(entry: dict) -> str:
    props = entry.get("Properties") or {}
    return (
        props.get("name")
        or props.get("samaccountname")
        or entry.get("Name")
        or entry.get("ObjectIdentifier")
        or ""
    )


def _object_entries(payload) -> List[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return [item for item in payload["data"] if isinstance(item, dict)]
    return []


def _meta_type(payload) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    raw = (meta or {}).get("type") or payload.get("type") or ""
    return _COLLECTION_KEYS.get(str(raw).strip().lower())


def _detect_collection_key(entries: Sequence[dict]) -> Optional[str]:
    scores = {
        "users": 0,
        "groups": 0,
        "computers": 0,
        "domains": 0,
        "gpos": 0,
        "ous": 0,
        "containers": 0,
    }
    for item in list(entries)[:25]:
        props = item.get("Properties") if isinstance(item.get("Properties"), dict) else {}
        if any(k in item for k in ("Trusts", "Links", "ChildObjects", "GPOChanges")) or any(
            k in props for k in ("domainsid", "functionallevel", "machineaccountquota", "minpwdlength")
        ):
            scores["domains"] += 4
        if isinstance(item.get("Members"), list) or "groupscope" in props:
            scores["groups"] += 4
        if any(
            k in item
            for k in (
                "Sessions",
                "PrivilegedSessions",
                "RegistrySessions",
                "NtlmSessions",
                "LocalAdmins",
                "RemoteDesktopUsers",
                "DcomUsers",
                "PSRemoteUsers",
            )
        ) or any(k in props for k in ("operatingsystem", "haslaps", "isdc", "isreadonlydc", "trustedtoauth")):
            scores["computers"] += 4
        if "SPNTargets" in item or any(
            k in props
            for k in (
                "displayname",
                "email",
                "title",
                "hasspn",
                "dontreqpreauth",
                "smartcardrequired",
                "passwordexpired",
                "pwdneverexpires",
                "sensitive",
            )
        ):
            scores["users"] += 4
        if "gpcpath" in props:
            scores["gpos"] += 4
        if "blocksinheritance" in props:
            scores["ous"] += 4
        sam = str(props.get("samaccountname") or "")
        if sam.endswith("$"):
            scores["computers"] += 2
        elif sam:
            scores["users"] += 1
            scores["groups"] += 1
        if "PrimaryGroupSID" in item:
            if sam.endswith("$") or "operatingsystem" in props:
                scores["computers"] += 2
            else:
                scores["users"] += 2
    ranked = sorted(((k, v) for k, v in scores.items() if v > 0), key=lambda kv: kv[1], reverse=True)
    if not ranked:
        return None
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return None
    return ranked[0][0]


def load_bloodhound_collection(payload) -> Tuple[Optional[str], List[dict]]:
    entries = _object_entries(payload)
    return _meta_type(payload) or _detect_collection_key(entries), entries


def _relation_id(item) -> str:
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return ""
    return str(
        item.get("ObjectIdentifier")
        or item.get("PrincipalSID")
        or item.get("UserSID")
        or item.get("ComputerSID")
        or item.get("GUID")
        or ""
    )


def _relation_list(container) -> List:
    if container is None:
        return []
    if isinstance(container, list):
        return container
    if isinstance(container, dict):
        results = container.get("Results")
        if isinstance(results, list):
            return results
    return []


def _index_sids(entries: Iterable[dict]) -> Dict[str, str]:
    names: Dict[str, str] = {}
    for entry in entries:
        oid = str(entry.get("ObjectIdentifier") or "")
        name = _object_name(entry)
        if oid and name:
            names[oid] = name
        props = entry.get("Properties") if isinstance(entry.get("Properties"), dict) else {}
        for extra in (props.get("objectsid"), props.get("domainsid")):
            if extra and name:
                names[str(extra)] = name
    return names


def _resolve(sid_or_name: str, sid_names: Dict[str, str]) -> str:
    if not sid_or_name:
        return ""
    return sid_names.get(sid_or_name) or sid_or_name


def _add_edge(edges: List[Edge], src: str, right: str, dst: str) -> None:
    if src and right and dst:
        edges.append((src, right, dst))


def extract_edges(entries: Sequence[dict], sid_names: Optional[Dict[str, str]] = None) -> List[Edge]:
    sid_names = sid_names if sid_names is not None else _index_sids(entries)
    edges: List[Edge] = []
    for entry in entries:
        dst = _object_name(entry)
        oid = str(entry.get("ObjectIdentifier") or "")
        if oid and dst:
            sid_names[oid] = dst

        for ace in entry.get("Aces") or []:
            if not isinstance(ace, dict):
                continue
            right = ace.get("RightName") or ace.get("Right") or ""
            if right not in ACL_RIGHTS:
                continue
            src = _resolve(_relation_id(ace), sid_names)
            _add_edge(edges, src, right, dst)

        for member in entry.get("Members") or []:
            member_id = _relation_id(member)
            src = _resolve(member_id, sid_names)
            _add_edge(edges, src, "MemberOf", dst)

        primary = str(entry.get("PrimaryGroupSID") or "")
        if primary:
            _add_edge(edges, dst, "MemberOf", _resolve(primary, sid_names))

        for field, right in (
            ("AllowedToDelegate", "AllowedToDelegate"),
            ("AllowedToAct", "AllowedToAct"),
        ):
            for target in _relation_list(entry.get(field)):
                target_id = _relation_id(target)
                target_name = _resolve(target_id, sid_names)
                if not target_name and isinstance(target, dict):
                    target_name = str(target.get("Name") or target.get("ComputerName") or "")
                _add_edge(edges, dst, right, target_name)

        for field, label in (
            ("Sessions", "HasSession"),
            ("PrivilegedSessions", "HasSession"),
            ("RegistrySessions", "HasSession"),
            ("NtlmSessions", "HasSession"),
        ):
            for result in _relation_list(entry.get(field)):
                if not isinstance(result, dict):
                    continue
                user = _resolve(str(result.get("UserSID") or ""), sid_names)
                computer = _resolve(str(result.get("ComputerSID") or oid), sid_names) or dst
                _add_edge(edges, computer, label, user)
                _add_edge(edges, user, label, computer)
    return edges


def parse_bloodhound_json(payload: dict, sid_names: Optional[Dict[str, str]] = None) -> List[Edge]:
    _key, entries = load_bloodhound_collection(payload)
    return extract_edges(entries, sid_names)


def _load_payloads(path: Path) -> List[Tuple[str, object]]:
    path = Path(path)
    files: List[Tuple[str, object]] = []
    if path.is_dir():
        for json_path in sorted(path.glob("*.json")):
            files.append((json_path.name, json.loads(json_path.read_text(encoding="utf-8-sig"))))
        return files
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if name.endswith("/") or not name.lower().endswith(".json"):
                continue
            with zf.open(name) as handle:
                text = handle.read().decode("utf-8-sig")
            files.append((name, json.loads(text)))
    return files


def parse_bloodhound_zip(path: Path) -> List[Edge]:
    files = _load_payloads(path)
    all_entries: List[dict] = []
    for _, payload in files:
        _key, entries = load_bloodhound_collection(payload)
        all_entries.extend(entries)
    sid_names = _index_sids(all_entries)
    return extract_edges(all_entries, sid_names)


def shortest_acl_paths(
    edges: Sequence[Edge],
    sources: Iterable[str],
    max_hops: int = 6,
) -> List[dict]:
    graph: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    display = {}
    for src, right, dst in edges:
        if right not in TRAVERSE_RIGHTS:
            continue
        src_n = _norm(src)
        dst_n = _norm(dst)
        display[src_n] = src
        display[dst_n] = dst
        for alias in _aliases(src):
            graph[alias].append((right, dst_n))
            display[alias] = src

    starts = []
    seen_starts = set()
    for raw in sources:
        for alias in _aliases(raw):
            if alias and alias not in seen_starts:
                seen_starts.add(alias)
                starts.append(alias)

    findings: List[dict] = []
    seen_paths = set()
    for start in starts:
        queue = deque([(start, [])])
        visited = {start}
        while queue:
            node, path = queue.popleft()
            if len(path) >= max_hops:
                continue
            for right, nxt in graph.get(node, []):
                step = (display.get(node, node), right, display.get(nxt, nxt))
                new_path = path + [step]
                key = tuple((a, r, b) for a, r, b in new_path)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                findings.append({
                    "src": new_path[0][0],
                    "dst": step[2],
                    "right": right,
                    "hops": len(new_path),
                    "path": new_path,
                    "evidence": " -> ".join(
                        f"{a} -{r}-> {b}" for a, r, b in new_path
                    ),
                })
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, new_path))
    return findings
