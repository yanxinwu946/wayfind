"""IP exclusion parsing and matching."""

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple, Union


@dataclass(frozen=True)
class IPExclusions:
    """CIDR-aware IP exclusion list."""
    networks: Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], ...]

    @classmethod
    def from_values(
        cls,
        values: Optional[Iterable[str]] = None,
        option_name: str = "--exclude-ip",
    ) -> "IPExclusions":
        networks = []
        for item, source in cls._expand_values(values):
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError as e:
                location = f" in {source}" if source else ""
                raise ValueError(f"Invalid {option_name} value '{item}'{location}: {e}") from e
        return cls(tuple(networks))

    @classmethod
    def _expand_values(cls, values: Optional[Iterable[str]]) -> Iterable[Tuple[str, Optional[str]]]:
        for value in values or []:
            for item in cls._split_items(value):
                path = Path(item).expanduser()
                if path.is_file():
                    yield from cls._read_items_from_file(path)
                else:
                    yield item, None

    @staticmethod
    def _split_items(value: str) -> Iterable[str]:
        for part in value.split(','):
            item = part.strip()
            if item:
                yield item

    @classmethod
    def _read_items_from_file(cls, path: Path) -> Iterable[Tuple[str, Optional[str]]]:
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except OSError as e:
            raise ValueError(f"Could not read IP list file '{path}': {e}") from e

        for line_number, line in enumerate(lines, 1):
            line = line.split('#', 1)[0]
            for item in cls._split_items(line):
                yield item, f"{path}:{line_number}"

    def __bool__(self) -> bool:
        return bool(self.networks)

    def contains_ip(self, ip: str) -> bool:
        if not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in network for network in self.networks)

    def summary(self) -> str:
        return ', '.join(str(network) for network in self.networks)
