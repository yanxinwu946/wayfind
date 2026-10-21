"""Recovered identities. Later checks can bind as a stored account."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class LootedIdentity:
    username: str
    password: Optional[str] = None
    hashes: Optional[str] = None
    source: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def has_secret(self) -> bool:
        return bool(self.password or self.hashes)


class LootStore:
    def __init__(self) -> None:
        self._items: Dict[str, LootedIdentity] = {}

    def add(
        self,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        source: str = "",
        **extra: Any,
    ) -> LootedIdentity:
        key = username.lower()
        ident = LootedIdentity(
            username=username,
            password=password,
            hashes=hashes,
            source=source,
            extra=extra or {},
        )
        self._items[key] = ident
        return ident

    def get(self, username: str) -> Optional[LootedIdentity]:
        return self._items.get(username.lower())

    def __len__(self) -> int:
        return len(self._items)

    def usernames(self) -> List[str]:
        return [item.username for item in self._items.values() if item.username]

    def as_list(self) -> List[Dict[str, Any]]:
        return [asdict(item) for item in self._items.values()]

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"identities": self.as_list()}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "LootStore":
        store = cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for row in data.get("identities") or data.get("loot") or []:
            store.add(
                username=row.get("username") or "",
                password=row.get("password"),
                hashes=row.get("hashes"),
                source=row.get("source") or "",
                **(row.get("extra") or {}),
            )
        return store
