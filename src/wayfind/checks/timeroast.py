"""Timeroast via NetExec. Unauthenticated NTP hashes, hashcat mode 31300."""

import re
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.netexec import report_netexec_failure
from ..core.session import Session

HASH_RE = re.compile(r"(\d+):(\$sntp-ms\$\S+)")


class TimeroastChecker:
    """Wrap nxc smb -M timeroast."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, session: Optional[Session] = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.domain = domain or ldap_conn.config.domain
        self.username = username or ""
        self.password = password or ""
        self.hashes = hashes
        self.server = ldap_conn.config.server

    def check_timeroast(self):
        self.logger.info("---Checking Timeroast (nxc -M timeroast)---")
        try:
            output, result = self.session.run_nxc(
                "smb", extra=["-M", "timeroast"], timeout=180,
                archive="nxc_timeroast.txt",
            )
            report_netexec_failure(self.logger, "nxc timeroast", result)
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return
        except subprocess.TimeoutExpired:
            self.logger.error("[-] nxc timeroast timed out")
            return
        except Exception as e:
            self.logger.error(f"[-] nxc timeroast: {e}")
            return

        write_lines(output.splitlines(), self.output_paths["data"] / "nxc_timeroast.txt")
        hashes = self._parse(output)
        replay = self.session.nxc_replay("smb", extra=["-M", "timeroast"])
        if hashes:
            lines = [f"{rid}:{h}" for rid, h in hashes]
            write_lines(lines, self.output_paths["findings"] / "timeroast_hashes.txt")
            self.session.emit(
                id="timeroast.hashes",
                severity="medium",
                title=f"{len(hashes)} Timeroast hashes (hashcat 31300)",
                asset=self.server,
                evidence=f"{len(hashes)} $sntp-ms hashes",
                replay=replay,
                backend="nxc",
                check="timeroast",
                count=len(hashes),
            )
            self.logger.info("[*] Server 2025 often returns RID only; map RID to name separately")
        else:
            self.logger.success("[+] No Timeroast hashes returned")

    def _parse(self, output: str) -> List[tuple]:
        found = []
        for raw in output.splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            m = HASH_RE.search(line)
            if m:
                found.append((m.group(1), m.group(2)))
        return found
