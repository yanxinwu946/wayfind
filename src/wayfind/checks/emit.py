"""Push a human finding into findings.json when a Session is attached."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Mapping


def sams(rows: Iterable[Any], *keys: str) -> List[str]:
    names: List[str] = []
    fields = keys or ("sAMAccountName",)
    for row in rows:
        if isinstance(row, str):
            if row:
                names.append(row)
            continue
        if not isinstance(row, Mapping):
            continue
        for key in fields:
            value = row.get(key)
            if value:
                names.append(str(value))
                break
    return names


def note(checker, title: str, **kwargs):
    session = getattr(checker, "session", None)
    check = kwargs.pop("check", None) or getattr(checker, "CHECK", None) or "check"
    if session is None:
        checker.logger.finding(title)
        return None
    fid = kwargs.pop("id", None)
    if not fid:
        slug = re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")[:48]
        fid = f"{check}.{slug}" if slug else f"{check}.hit"
        logger = getattr(checker, "logger", None)
        if logger is not None:
            logger.debug(f"[!] note() missing id, slugged {fid}")
    names = kwargs.get("names")
    if names is not None and kwargs.get("count") is None:
        try:
            kwargs["count"] = len(names)
        except TypeError:
            pass
    kwargs.setdefault("severity", "medium")
    kwargs.setdefault("evidence", title)
    kwargs.setdefault("backend", "ldap")
    return session.emit(id=fid, title=title, check=check, **kwargs)
