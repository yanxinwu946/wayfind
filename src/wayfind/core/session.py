"""Audit session: one Target, loot, findings, command builders."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .loot import LootStore, LootedIdentity
from .hops import compose_hops, principal_sam
from .profiles import DEFAULT_PROFILE, opsec_for
from .target import Target
from .. import __version__
from ..output.findings import Finding, FindingStore
from ..utils.bins import apply_socks_env, certipy_bin, nxc_cmd_from_target
from ..utils.clock import kerberos_should_skip, ntp_offset_seconds
from ..utils.logger import get_logger
from ..utils.output import write_lines


class Session:
    def __init__(
        self,
        target: Target,
        output_paths: Dict[str, Path],
        loot: Optional[LootStore] = None,
        profile: str = DEFAULT_PROFILE,
    ):
        self.target = target
        self.output_paths = output_paths
        self.findings = FindingStore()
        self.loot = loot or LootStore()
        self.profile = profile or DEFAULT_PROFILE
        self.ldap = None
        self.logger = get_logger()
        self.clock_offset = None
        self.kerberos_blocked = False
        self.kerberos_block_reason = ""
        self.checks_run: List[str] = []
        if target.ccache:
            os.environ["KRB5CCNAME"] = target.ccache
        apply_socks_env(target.socks)

    def attach_ldap(self, ldap_conn) -> None:
        self.ldap = ldap_conn

    def seed_prior_findings(self, loot_path: Optional[Path]) -> int:
        """Carry facts from a previous run next to loot.json."""
        if not loot_path:
            return 0
        path = Path(loot_path)
        candidates = [path.parent / "findings.json", path.with_name("findings.json")]
        for cand in candidates:
            if cand.is_file():
                n = self.findings.seed_from_json(cand)
                if n:
                    self.logger.info(f"[*] Seeded {n} prior finding(s) from {cand}")
                return n
        return 0

    def probe_clock(self) -> Optional[float]:
        self.clock_offset = ntp_offset_seconds(self.target.dc_ip)
        skip, msg = kerberos_should_skip(self.clock_offset, self.target.dc_ip)
        self.kerberos_blocked = skip
        self.kerberos_block_reason = msg
        if skip:
            self.logger.warning(f"[!] {msg}")
            self.emit(
                id="clock.skew",
                severity="medium",
                title=msg.split(".")[0] if msg else "Clock skew vs DC",
                asset=self.target.dc_ip,
                evidence=msg,
                replay=f"ntpdate {self.target.dc_ip}",
                backend="ntp",
                check="clock",
                opsec="request tickets",
            )
        elif self.clock_offset is not None:
            self.logger.success(f"[+] Clock skew vs DC NTP is {self.clock_offset:.1f}s")
        return self.clock_offset

    def allow_kerberos(self) -> bool:
        if not self.kerberos_blocked:
            skip, msg = kerberos_should_skip(self.clock_offset, self.target.dc_ip)
            self.kerberos_blocked = skip
            self.kerberos_block_reason = msg
        if self.kerberos_blocked:
            self.logger.warning(f"[!] {self.kerberos_block_reason}")
            return False
        return True

    def emit(self, **kwargs) -> Finding:
        check = kwargs.get("check") or ""
        if not kwargs.get("opsec"):
            kwargs["opsec"] = opsec_for(check)
        finding = self.findings.emit(**kwargs)
        self.logger.finding(finding.title)
        if finding.replay:
            self.logger.info(f"    replay: {finding.replay}")
        if finding.opsec:
            self.logger.info(f"    opsec:  {finding.opsec}")
        return finding

    def add_loot(self, username: str, password: Optional[str] = None,
                 hashes: Optional[str] = None, source: str = "", **extra) -> LootedIdentity:
        ident = self.loot.add(username=username, password=password, hashes=hashes, source=source, **extra)
        self.logger.info(f"[+] Looted identity {username} ({source or 'session'})")
        return ident

    def nxc_cmd(
        self,
        protocol: str,
        extra: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        auth: bool = True,
    ) -> List[str]:
        return nxc_cmd_from_target(self.target, protocol, extra=extra, host=host, auth=auth)

    def nxc_replay(
        self,
        protocol: str,
        extra: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        auth: bool = True,
    ) -> str:
        return shlex.join(self.nxc_cmd(protocol, extra=extra, host=host, auth=auth))

    def archive_nxc(self, name: str, output: str) -> Path:
        path = self.output_paths["data"] / name
        write_lines((output or "").splitlines(), path)
        return path

    def run_nxc(
        self,
        protocol: str,
        extra: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        archive: Optional[str] = None,
        timeout: int = 180,
        auth: bool = True,
        cwd: Optional[str] = None,
    ) -> Tuple[str, subprocess.CompletedProcess]:
        cmd = self.nxc_cmd(protocol, extra=extra, host=host, auth=auth)
        self.logger.debug(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, cwd=cwd,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if archive:
            self.archive_nxc(archive, output)
        return output, result

    def certipy_cmd(self, extra: Optional[Sequence[str]] = None) -> List[str]:
        binary = certipy_bin()
        if not binary:
            raise FileNotFoundError("certipy/certipy-ad not in PATH")
        t = self.target
        cmd = [binary]
        if extra:
            cmd.extend(list(extra))
        cmd.extend(["-u", f"{t.username}@{t.domain}" if t.domain else t.username])
        cmd.extend(["-dc-ip", t.dc_ip])
        if t.dc_host:
            cmd.extend(["-target", t.dc_host])
        if t.socks:
            cmd.extend(["-socks", t.socks])
        if t.kerberos:
            cmd.append("-k")
        if t.pfx:
            cmd.extend(["-pfx", t.pfx])
        elif t.hashes:
            cmd.extend(["-hashes", t.hashes])
        elif t.password is not None:
            cmd.extend(["-p", t.password])
        scheme = "ldaps" if t.use_ldaps else "ldap"
        cmd.extend(["-ldap-scheme", scheme])
        if t.dns_server:
            cmd.extend(["-ns", t.dns_server])
        return cmd

    def mark_check(self, name: str) -> None:
        if name and name not in self.checks_run:
            self.checks_run.append(name)

    def collect_replay(self, dc_host: str) -> str:
        t = self.target
        parts = [
            "bloodhound-python",
            "-u", t.username,
            "-d", t.domain,
            "--zip",
            "-c", "DCOnly",
            "-dc", dc_host or t.dc_host or t.dc_ip,
            "-ns", t.dns_server,
            "--dns-tcp",
        ]
        if t.use_ldaps:
            parts.append("--use-ldaps")
        if not t.kerberos:
            parts.extend(["--auth-method", "ntlm"])
        return shlex.join(parts)

    def certipy_replay(self, extra: Optional[Sequence[str]] = None) -> str:
        t = self.target
        parts = ["certipy"]
        if extra:
            parts.extend(list(extra))
        user = f"{t.username}@{t.domain}" if t.domain else t.username
        parts.extend(["-u", user, "-dc-ip", t.dc_ip])
        if t.dc_host:
            parts.extend(["-target", t.dc_host])
        parts.extend(["-ldap-scheme", "ldaps" if t.use_ldaps else "ldap"])
        if t.dns_server:
            parts.extend(["-ns", t.dns_server])
        if t.kerberos:
            parts.append("-k")
        return shlex.join(parts)

    def run_meta(self) -> dict:
        t = self.target
        return {
            "schema": "wayfind.findings/v1",
            "version": __version__,
            "profile": self.profile,
            "identity": t.username,
            "domain": t.domain,
            "dc": t.dc_ip,
            "dc_host": t.dc_host or "",
            "ldaps": bool(t.use_ldaps),
            "dns": t.dns_server,
            "kerberos": bool(t.kerberos),
            "checks": list(self.checks_run),
            "clock_offset": self.clock_offset,
            "kerberos_blocked": self.kerberos_blocked,
            "kerberos_block_reason": self.kerberos_block_reason,
            "findings": len(self.findings),
            "loot": len(self.loot),
        }

    def write_findings(self) -> None:
        owned = []
        if self.target.username:
            owned.append(self.target.username)
        owned.extend(self.loot.usernames())
        hops = compose_hops(self.findings.as_list(), owned=owned)
        drop_keys = {
            (
                principal_sam(str(h.get("src") or "")),
                str(h.get("right") or ""),
                principal_sam(str(h.get("dst") or "")),
            )
            for h in hops
            if h.get("id") in ("hop.owned-acl", "hop.owned-group")
        }
        if drop_keys:
            self.findings.drop_acl_keys(drop_keys)
        for hop in hops:
            self.findings.emit(**hop)
            self.logger.finding(hop["title"])
        root = self.output_paths["root"]
        run = self.run_meta()
        json_path = self.findings.write_json(root / "findings.json", version=__version__, run=run)
        txt_path = self.findings.write_txt(root / "findings" / "findings.txt")
        loot_path = self.loot.write_json(root / "loot.json")
        run_path = root / "run.json"
        run_path.write_text(
            json.dumps(run, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        count = len(self.findings)
        self.logger.info(f"[+] {count} finding(s) -> {json_path}")
        if count:
            self.logger.info(f"[+] Replay list -> {txt_path}")
        if len(self.loot):
            self.logger.info(f"[+] Loot -> {loot_path}")
