"""Run profiles and check categories.

Profiles = how far to go (opsec).
Categories = what to enumerate.

  anonymous  no domain creds (timeroast / SMB null-guest / LDAP anonymous)
  directory  authenticated LDAP / SYSVOL / ADCS / BloodHound
  host       spray hosts
  probe      Zerologon / NoPac
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

DEFAULT_PROFILE = "audit"

OPSEC_LDAP = "read-only LDAP"
OPSEC_TICKETS = "request tickets"
OPSEC_HIT_DC = "hit DC"

CATEGORIES: Dict[str, Tuple[str, ...]] = {
    "anonymous": (
        "timeroast",
        "smb",
        "ldap-anonymous-bind",
    ),
    "directory": (
        "bloodhound",
        "functional-level",
        "password-policy",
        "kerberos-policy",
        "fgpp",
        "laps",
        "descriptions",
        "roasting",
        "delegation",
        "user-attrs",
        "privileged-groups",
        "outdated",
        "adidns",
        "exchange",
        "adcs",
        "trusts",
        "azure",
        "sccm",
        "ldap",
        "gpp",
        "shares",
        "gmsa",
        "shadow",
        "dmsa",
        "ntlm",
        "wsus",
    ),
    "host": (
        "cve",
        "network",
        "access",
        "sql",
        "domain-admin-sessions",
    ),
    "probe": (
        "dc-vulns",
    ),
}

CATEGORY_HELP: Dict[str, str] = {
    "anonymous": "no domain creds: timeroast / SMB null-guest / LDAP anonymous",
    "directory": "authenticated LDAP, SYSVOL, ADCS, BloodHound",
    "host": "spray hosts: access / SQL / CVE / DA sessions",
    "probe": "Zerologon / NoPac",
}

# Fine-grained aliases still callable via --check; covered by outdated in directory.
CHECK_CATEGORY: Dict[str, str] = {}
for _cat, _names in CATEGORIES.items():
    for _name in _names:
        CHECK_CATEGORY[_name] = _cat
CHECK_CATEGORY["privileged-accounts"] = "directory"
CHECK_CATEGORY["legacy"] = "directory"

PROFILE_ALIASES = {
    "anonymous": "recon",
}

PROFILE_CATEGORIES: Dict[str, Tuple[str, ...]] = {
    "recon": ("anonymous",),
    "audit": ("directory",),
    "offensive": ("anonymous", "directory", "host", "probe"),
}

RECON_CHECKS: Tuple[str, ...] = CATEGORIES["anonymous"]
AUDIT_CHECKS: Tuple[str, ...] = CATEGORIES["directory"]
OFFENSIVE_EXTRA: Tuple[str, ...] = CATEGORIES["host"] + CATEGORIES["probe"]
OFFENSIVE_ONLY: Tuple[str, ...] = CATEGORIES["probe"]

CHECK_OPSEC: Dict[str, str] = {
    "timeroast": OPSEC_HIT_DC,
    "smb": OPSEC_HIT_DC,
    "ldap-anonymous-bind": OPSEC_LDAP,
    "gpp": OPSEC_HIT_DC,
    "shares": OPSEC_HIT_DC,
    "dc-vulns": OPSEC_HIT_DC,
    "cve": OPSEC_HIT_DC,
    "network": OPSEC_HIT_DC,
    "access": OPSEC_HIT_DC,
    "sql": OPSEC_HIT_DC,
    "domain-admin-sessions": OPSEC_HIT_DC,
    "ntlm": OPSEC_HIT_DC,
    "wsus": OPSEC_HIT_DC,
    "roasting": OPSEC_LDAP,
}


def normalize_profile(name: str | None) -> str:
    value = (name or DEFAULT_PROFILE).strip().lower()
    value = PROFILE_ALIASES.get(value, value)
    if value not in PROFILE_CATEGORIES:
        raise ValueError(f"unknown profile: {name}")
    return value


def want_kerberos_tickets(profile: str | None) -> bool:
    """TGS/AS-REP hash request is offensive-only. Audit lists SPNs."""
    return normalize_profile(profile) == "offensive"


def checks_for_category(name: str) -> Tuple[str, ...]:
    key = (name or "").strip().lower()
    if key not in CATEGORIES:
        raise ValueError(f"unknown category: {name}")
    return CATEGORIES[key]


def checks_for_profile(name: str | None) -> Tuple[str, ...]:
    profile = normalize_profile(name)
    seen: List[str] = []
    for cat in PROFILE_CATEGORIES[profile]:
        for item in CATEGORIES[cat]:
            if item not in seen:
                seen.append(item)
    return tuple(seen)


def category_of(check: str) -> str | None:
    return CHECK_CATEGORY.get(check)


def expand_selector(name: str, known_checks: Iterable[str] | None = None) -> Tuple[str, ...]:
    """Expand --check value: category, profile alias, comma list, or one check."""
    raw = (name or "").strip().lower()
    if not raw:
        raise ValueError("empty check")
    if "," in raw:
        out: List[str] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            for item in expand_selector(part, known_checks=known_checks):
                if item not in out:
                    out.append(item)
        return tuple(out)
    if raw in CATEGORIES:
        return CATEGORIES[raw]
    if raw in PROFILE_ALIASES or raw in PROFILE_CATEGORIES:
        return checks_for_profile(raw)
    known = set(known_checks) if known_checks is not None else None
    if known is not None and raw not in known:
        raise ValueError(f"unknown check: {name}")
    return (raw,)


def included_in(profile: str | None, check: str) -> bool:
    """Whether a named check belongs to a profile.

    roasting inventory is in audit; ticket request is gated separately.
    """
    return check in checks_for_profile(profile)


def profiles_for_check(check: str) -> List[str]:
    tags = []
    for name in ("recon", "audit", "offensive"):
        if included_in(name, check):
            tags.append(name)
    return tags


def opsec_for(check: str, default: str = OPSEC_LDAP) -> str:
    return CHECK_OPSEC.get(check, default)


def format_profile_help(available: Iterable[Tuple[str, str]] | None = None) -> str:
    desc = dict(available) if available else {}
    lines = [
        f"Default profile: {DEFAULT_PROFILE}",
        "",
        "Profiles (how far):",
        "  recon, anonymous   anonymous enum, no domain creds",
        "  audit              directory enum (default, read-only). Lists SPNs; no TGS",
        "  offensive          anonymous + directory + host + probe; TGS; Zerologon/NoPac",
        "",
        "Categories (what). Also valid as --check:",
    ]
    listed = set()
    for cat, names in CATEGORIES.items():
        lines.append(f"  {cat}")
        lines.append(f"    {CATEGORY_HELP[cat]}")
        for name in names:
            listed.add(name)
            extra = desc.get(name, "")
            if extra:
                lines.append(f"    {name:22} {extra}")
            else:
                lines.append(f"    {name}")
    leftovers = []
    for name, extra in desc.items():
        if name not in listed:
            leftovers.append((name, extra))
    if leftovers:
        lines.append("")
        lines.append("Fine-grained (inside directory; --check still works):")
        for name, extra in leftovers:
            lines.append(f"    {name:22} {extra}")
    return "\n".join(lines)
