"""Parse known nxc fields. Do not key off colour banners."""

from __future__ import annotations

import re
from typing import Dict, Optional

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SIGNING_RE = re.compile(r"signing\s*:\s*([A-Za-z0-9_]+)", re.I)
BINDING_RE = re.compile(r"channel binding\s*:\s*([A-Za-z0-9_]+)", re.I)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def parse_ldap_security(output: str) -> Dict[str, Optional[str]]:
    """Extract LDAP signing and channel binding from nxc ldap output.

    Matches `signing:Enforced` / `channel binding:Always` as fields.
    Does not require the historical `(signing:True)` banner form.
    """
    clean = strip_ansi(output)
    signing = None
    binding = None
    m = SIGNING_RE.search(clean)
    if m:
        signing = m.group(1)
    m = BINDING_RE.search(clean)
    if m:
        binding = m.group(1)
    return {"signing": signing, "channel_binding": binding}

SHARE_ROW_RE = re.compile(
    r"\b445\s+\S+\s+(\S+)(?:\s+(READ(?:,WRITE)?|WRITE))?(?:\s+(.*))?$"
)
ADMIN_SHARES = {"ADMIN$", "C$", "D$", "ADMIN", "C"}
DEFAULT_SHARES = {"IPC$", "NETLOGON", "SYSVOL"}


def parse_nxc_shares(output: str):
    """Parse nxc smb --shares table into {name, perms, remark}."""
    rows = []
    in_table = False
    for raw in (output or "").splitlines():
        line = strip_ansi(raw).strip()
        if "Share" in line and "Permissions" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if "-----" in line or "-----------" in line:
            continue
        m = SHARE_ROW_RE.search(line)
        if not m:
            continue
        name = m.group(1)
        if name in {"Share", "-----"}:
            continue
        perms = (m.group(2) or "").upper()
        remark = (m.group(3) or "").strip()
        rows.append({"name": name, "perms": perms, "remark": remark})
    return rows
