"""Target filtering and target-file helpers."""

import ipaddress
import os
import socket
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Union

from .ip_exclusions import IPExclusions

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(frozen=True)
class FilteredTargets:
    """Targets after applying the audit target scope."""
    targets: List[str]
    excluded_count: int = 0


class TargetScope:
    """Audit target policy for include/exclude IP ranges except domain controllers."""

    def __init__(
        self,
        exclusions: Optional[IPExclusions] = None,
        allowed_ips: Optional[Iterable[IPAddress]] = None,
        inclusions: Optional[IPExclusions] = None,
    ):
        self.exclusions = exclusions or IPExclusions.from_values()
        self.inclusions = inclusions or IPExclusions.from_values()
        self.allowed_ips = frozenset(allowed_ips or [])

    def __bool__(self) -> bool:
        return bool(self.exclusions) or bool(self.inclusions)

    @classmethod
    def from_ldap(
        cls,
        ldap_conn,
        exclusions: Optional[IPExclusions] = None,
        logger=None,
        domain_controllers=None,
        extra_targets: Optional[Iterable[str]] = None,
        inclusions: Optional[IPExclusions] = None,
    ) -> "TargetScope":
        scope = cls(exclusions, inclusions=inclusions)
        if not scope:
            return scope

        targets = list(extra_targets or [])
        dcs = domain_controllers
        if dcs is None:
            try:
                dcs = ldap_conn.query(
                    search_base=ldap_conn.config.base_dn,
                    search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                    attributes=['dNSHostName', 'name']
                )
            except Exception as e:
                if logger:
                    logger.warning(f"[!] Could not resolve all DC exclusions safely: {e}")
                dcs = []

        for dc in dcs or []:
            hostname = dc.get('dNSHostName') or dc.get('name')
            if hostname:
                targets.append(hostname)

        updated = scope.with_allowed_targets(targets)
        newly_allowed = sorted(
            str(ip) for ip in updated.allowed_ips - scope.allowed_ips
            if scope.filter_reason(str(ip))
        )
        if newly_allowed and logger:
            logger.info("[*] Keeping Domain Controller IP(s) in scope despite "
                        f"{scope.filter_label()}: "
                        + ', '.join(newly_allowed))
        return updated

    def with_allowed_targets(self, targets: Iterable[str]) -> "TargetScope":
        allowed_ips = set(self.allowed_ips)
        for target in targets:
            ip = self.resolve_target(target)
            if ip:
                allowed_ips.add(ip)
        return TargetScope(self.exclusions, allowed_ips, self.inclusions)

    def resolve_target(self, target: str) -> Optional[IPAddress]:
        if not target:
            return None
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass
        try:
            return ipaddress.ip_address(socket.gethostbyname(target))
        except Exception:
            return None

    def filter_reason(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "--include-ip" if self.inclusions else None
        if addr in self.allowed_ips:
            return None
        if self.inclusions and not self.inclusions.contains_ip(ip):
            return "--include-ip"
        if self.exclusions.contains_ip(ip):
            return "--exclude-ip"
        return None

    def excludes_ip(self, ip: str) -> bool:
        return self.filter_reason(ip) is not None

    def filter_ips(self, ips: Iterable[str]) -> FilteredTargets:
        targets = list(ips)
        filtered = [ip for ip in targets if not self.excludes_ip(ip)]
        return FilteredTargets(filtered, len(targets) - len(filtered))

    def filter_targets(self, targets: Iterable[str], logger=None, label: str = "target") -> FilteredTargets:
        kept = []
        excluded_count = 0
        for target in targets:
            resolved = self.resolve_target(target)
            if not resolved and self.inclusions:
                excluded_count += 1
                if logger:
                    logger.log_verbose(
                        f"[*] Excluding {label} {target} because it cannot be matched by --include-ip"
                    )
                continue
            reason = self.filter_reason(str(resolved)) if resolved else None
            if reason:
                excluded_count += 1
                if logger:
                    logger.log_verbose(f"[*] Excluding {label} {target} ({resolved}) by {reason}")
                continue
            kept.append(target)
        return FilteredTargets(kept, excluded_count)

    def has_non_dc_target_limits(self) -> bool:
        if self.inclusions:
            return True
        for network in self.exclusions.networks:
            if network.num_addresses == 1 and network.network_address in self.allowed_ips:
                continue
            return True
        return False

    def summary(self) -> str:
        return self.exclusions.summary()

    def filter_label(self) -> str:
        if self.inclusions and self.exclusions:
            return "--include-ip/--exclude-ip"
        if self.inclusions:
            return "--include-ip"
        return "--exclude-ip"


class TargetFiles:
    """Read, filter, and materialize target files for external tools."""

    def __init__(self, data_path: Path, target_scope: Optional[TargetScope] = None, logger=None):
        self.data_path = data_path
        self.target_scope = target_scope or TargetScope()
        self.logger = logger

    def read(self, filename: Union[str, Path], label: str = "target", log: bool = True) -> FilteredTargets:
        hosts_file = self._path(filename)
        if not hosts_file.exists():
            return FilteredTargets([])
        with open(hosts_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        result = self.filter_ips(hosts, label, log)
        return result

    def read_discovered(self, filename: Union[str, Path], label: str = "target") -> FilteredTargets:
        """Read hosts discovered by the network scan and explain an empty result."""
        result = self.read(filename, label)
        if result.targets:
            return result

        if self.logger:
            hosts_file = self._path(filename)
            if hosts_file.exists() and result.excluded_count:
                self.logger.info(
                    f"[*] No {label} hosts remain after applying {self.target_scope.filter_label()}"
                )
            elif (self.data_path / 'scandata_hostalive.txt').exists():
                self.logger.success(f"[+] No {label} hosts discovered by the network scan")
            else:
                self.logger.warning(
                    f"[!] No {label} host data found - run '--check network' first "
                    "(same output dir/day) or a full scan to populate hosts"
                )

        return result

    def has_targets(self, filename: Union[str, Path]) -> bool:
        return bool(self.read(filename, log=False).targets)

    def count(self, filename: Union[str, Path]) -> int:
        return len(self.read(filename, log=False).targets)

    def filter_ips(self, ips: Iterable[str], label: str = "target", log: bool = True) -> FilteredTargets:
        result = self.target_scope.filter_ips(ips)
        if log:
            self._log_excluded(result.excluded_count, label)
        return result

    @contextmanager
    def approved_file(self, filename: Union[str, Path], label: str = "target"):
        hosts_file = self._path(filename)
        result = self.read(hosts_file, label)
        if not result.targets:
            yield None
            return
        if result.excluded_count == 0:
            yield hosts_file
            return
        with self.temporary_targets(result.targets) as temp_file:
            yield temp_file

    @contextmanager
    def temporary_targets(self, targets: Iterable[str]):
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for target in targets:
                    f.write(f"{target}\n")
                temp_file = Path(f.name)
            yield temp_file
        finally:
            if temp_file:
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass

    def _path(self, filename: Union[str, Path]) -> Path:
        path = Path(filename)
        if path.is_absolute():
            return path
        return self.data_path / path

    def _log_excluded(self, excluded_count: int, label: str):
        if excluded_count and self.logger:
            self.logger.info(
                f"[*] Excluded {excluded_count} {label} host(s) by "
                f"{self.target_scope.filter_label()}"
            )
