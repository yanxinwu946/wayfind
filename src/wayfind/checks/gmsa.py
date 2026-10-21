"""gMSA password readability via NetExec --gmsa."""

import re
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.netexec import report_netexec_failure
from ..core.session import Session

ACCOUNT_RE = re.compile(
    r"Account:\s*(\S+)\s+NTLM:\s*(\S+(?:\s+\S+)*)\s+PrincipalsAllowedToReadPassword:\s*(.*)\s*$",
    re.I,
)


class GMSAChecker:
    """Wrap nxc ldap --gmsa."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, session: Optional[Session] = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.server = ldap_conn.config.server

    def check_gmsa(self):
        self.logger.info("---Checking gMSA passwords (nxc ldap --gmsa)---")
        try:
            output, result = self.session.run_nxc(
                "ldap", extra=["--gmsa"], timeout=120, archive="nxc_gmsa.txt"
            )
            report_netexec_failure(self.logger, "nxc --gmsa", result)
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return
        except subprocess.TimeoutExpired:
            self.logger.error("[-] nxc --gmsa timed out")
            return
        except Exception as e:
            self.logger.error(f"[-] nxc --gmsa: {e}")
            return

        write_lines(output.splitlines(), self.output_paths["data"] / "nxc_gmsa.txt")
        accounts = self._parse(output)
        if not accounts:
            self.logger.info("[*] No gMSA accounts reported")
            return

        replay = self.session.nxc_replay("ldap", extra=["--gmsa"])
        readable = []
        denied = []
        for acc in accounts:
            ntlm = acc["ntlm"]
            readers = [n for n in re.split(r"[,;]\s*", acc["readers"] or "") if n]
            line = f"{acc['account']} ntlm={ntlm} readers={acc['readers']}"
            if "no read" in ntlm.lower() or ntlm.startswith("<"):
                denied.append(line)
                self.logger.info(
                    f"[*] {acc['account']}: current user cannot read password "
                    f"(allowed: {acc['readers']})"
                )
                self.session.emit(
                    id="gmsa.readers",
                    severity="info",
                    title=f"gMSA {acc['account']} readable by {acc['readers']}",
                    asset=acc["account"],
                    evidence=f"PrincipalsAllowedToReadPassword={acc['readers']}",
                    replay=replay,
                    backend="nxc",
                    check="gmsa",
                    readers=readers,
                    names=readers,
                    count=len(readers),
                )
            else:
                readable.append(line)
                self.session.emit(
                    id="gmsa.readable",
                    severity="high",
                    title=f"gMSA {acc['account']} password readable",
                    asset=acc["account"],
                    evidence=ntlm,
                    replay=replay,
                    backend="nxc",
                    check="gmsa",
                    readers=readers,
                    names=readers,
                    count=len(readers),
                )

        if readable:
            write_lines(readable, self.output_paths["findings"] / "gmsa_readable.txt")
        if denied:
            write_lines(denied, self.output_paths["checks"] / "gmsa_no_read.txt")

    def _parse(self, output: str) -> List[Dict[str, str]]:
        found = []
        for raw in output.splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            m = ACCOUNT_RE.search(line)
            if m:
                found.append({
                    "account": m.group(1),
                    "ntlm": m.group(2).strip(),
                    "readers": m.group(3).strip(),
                })
        return found
