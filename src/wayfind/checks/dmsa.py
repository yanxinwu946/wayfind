"""dMSA / BadSuccessor via NetExec badsuccessor module."""

import re
import subprocess
from typing import Dict, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.netexec import report_netexec_failure
from ..core.session import Session


class DMSAChecker:
    """Wrap nxc ldap -M badsuccessor."""

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

    def check_dmsa(self):
        self.logger.info("---Checking dMSA / BadSuccessor (nxc -M badsuccessor)---")
        try:
            output, result = self.session.run_nxc(
                "ldap", extra=["-M", "badsuccessor"], timeout=120,
                archive="nxc_badsuccessor.txt",
            )
            report_netexec_failure(self.logger, "nxc badsuccessor", result)
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return
        except subprocess.TimeoutExpired:
            self.logger.error("[-] nxc badsuccessor timed out")
            return
        except Exception as e:
            self.logger.error(f"[-] nxc badsuccessor: {e}")
            return

        write_lines(output.splitlines(), self.output_paths["data"] / "nxc_badsuccessor.txt")
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
        replay = self.session.nxc_replay("ldap", extra=["-M", "badsuccessor"])
        if re.search(r"vulnerable|CreateChild|GenericAll|GenericWrite", clean, re.I) and \
                not re.search(r"No account found", clean):
            write_lines(clean.splitlines(), self.output_paths["findings"] / "badsuccessor.txt")
            self.session.emit(
                id="dmsa.badsuccessor",
                severity="high",
                title="BadSuccessor / dMSA privilege reported",
                asset=self.server,
                evidence="nxc -M badsuccessor",
                replay=replay,
                backend="nxc",
                check="dmsa",
            )
        else:
            self.logger.info("[*] nxc badsuccessor did not report an exploitable principal")
