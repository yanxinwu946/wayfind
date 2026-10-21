"""Structured findings. JSON is the state; txt files are a rendering."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SCHEMA = "wayfind.findings/v1"


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    asset: str = ""
    evidence: str = ""
    replay: str = ""
    backend: str = ""
    check: str = ""
    opsec: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if not data.get("extra"):
            data.pop("extra", None)
        return data


class FindingStore:
    def __init__(self):
        self._items: List[Finding] = []

    def add(self, finding: Finding) -> Finding:
        self._items.append(finding)
        return finding

    def emit(
        self,
        id: str,
        severity: str,
        title: str,
        asset: str = "",
        evidence: str = "",
        replay: str = "",
        backend: str = "",
        check: str = "",
        opsec: str = "",
        **extra: Any,
    ) -> Finding:
        if extra.get("opsec") and not opsec:
            opsec = extra.pop("opsec")
        elif "opsec" in extra:
            extra.pop("opsec")
        return self.add(
            Finding(
                id=id,
                severity=severity,
                title=title,
                asset=asset,
                evidence=evidence,
                replay=replay,
                backend=backend,
                check=check,
                opsec=opsec,
                extra=extra or {},
            )
        )

    def __len__(self) -> int:
        return len(self._items)

    def seed_from_json(self, path: Path) -> int:
        """Load prior findings without logging (agent fact carry-forward)."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rows = data.get("findings") or []
        n = 0
        for row in rows:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            extra = dict(row.get("extra") or {})
            self.add(
                Finding(
                    id=str(row.get("id") or ""),
                    severity=str(row.get("severity") or "info"),
                    title=str(row.get("title") or row.get("id") or ""),
                    asset=str(row.get("asset") or ""),
                    evidence=str(row.get("evidence") or ""),
                    replay=str(row.get("replay") or ""),
                    backend=str(row.get("backend") or ""),
                    check=str(row.get("check") or ""),
                    opsec=str(row.get("opsec") or ""),
                    extra=extra,
                )
            )
            n += 1
        return n

    def drop_acl_keys(self, keys: Iterable[Tuple[str, str, str]]) -> int:
        """Drop inventory acl.* rows that match owned hop (src, right, dst) keys."""
        from ..core.hops import principal_sam

        drop: Set[Tuple[str, str, str]] = set(keys)
        kept: List[Finding] = []
        n = 0
        for item in self._items:
            extra = item.extra or {}
            key = (
                principal_sam(str(extra.get("src") or "")),
                str(extra.get("right") or ""),
                principal_sam(str(extra.get("dst") or "")),
            )
            if item.id.startswith("acl.") and key in drop:
                n += 1
                continue
            kept.append(item)
        self._items = kept
        return n

    def as_list(self) -> List[Dict[str, Any]]:
        return [item.to_dict() for item in self._items]

    def write_json(
        self,
        path: Path,
        *,
        version: str = "",
        run: Optional[Dict[str, Any]] = None,
    ) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "schema": SCHEMA,
            "version": version,
            "findings": self.as_list(),
        }
        if run:
            payload["run"] = run
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    def write_txt(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines: List[str] = []
        for item in self._items:
            lines.append(f"[{item.severity}] {item.id}  {item.title}")
            if item.asset:
                lines.append(f"  asset:    {item.asset}")
            if item.evidence:
                lines.append(f"  evidence: {item.evidence}")
            if item.replay:
                lines.append(f"  replay:   {item.replay}")
            if item.backend:
                lines.append(f"  backend:  {item.backend}")
            if item.opsec:
                lines.append(f"  opsec:    {item.opsec}")
            lines.append("")
        path.write_text("\n".join(lines).rstrip() + ("\n" if lines else ""), encoding="utf-8")
        return path
