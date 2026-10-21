"""GPP cpassword via NetExec gpp_password. Do not reimplement SYSVOL walk."""

import re
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.netexec import report_netexec_failure
from ..core.session import Session


def _strip_utf16_le(value: str) -> str:
    if "\x00" in value:
        try:
            return value.encode("latin-1").decode("utf-16-le").rstrip("\x00")
        except Exception:
            return value.replace("\x00", "")
    return value


class GPPChecker:
    """Wrap nxc smb -M gpp_password / gpp_autologin."""

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

    def check_gpp(self):
        self.logger.info("---Checking GPP passwords (nxc gpp_password)---")
        output = self._run_module("gpp_password")
        creds = self._parse_gpp_password(output)
        replay = self.session.nxc_replay("smb", extra=["-M", "gpp_password"])
        if creds:
            lines = []
            for row in creds:
                user = row.get("userName", "?")
                passwd = row.get("Password", "?")
                path = row.get("file", "")
                lines.append(f"{user} : {passwd} : {path}")
                self.session.emit(
                    id="gpp.cpassword",
                    severity="high",
                    title=f"GPP cpassword for {user}",
                    asset=user,
                    evidence=path,
                    replay=replay,
                    backend="nxc",
                    check="gpp",
                    password=passwd,
                    names=[user],
                    count=1,
                )
                self.session.add_loot(
                    username=user,
                    password=passwd,
                    source="gpp.cpassword",
                    file=path,
                )
            write_lines(lines, self.output_paths["findings"] / "gpp_passwords.txt")
        else:
            self.logger.success("[+] No GPP cpassword found via nxc gpp_password")

        auto = self._run_module("gpp_autologin")
        if auto and re.search(r"\[\+\].*password", auto, re.I):
            self.logger.warning("[!] gpp_autologin returned credentials")
            write_lines(auto.splitlines(), self.output_paths["checks"] / "gpp_autologin.txt")
            self.session.emit(
                id="gpp.autologin",
                severity="high",
                title="GPP autologin credentials found",
                replay=self.session.nxc_replay("smb", extra=["-M", "gpp_autologin"]),
                backend="nxc",
                check="gpp",
            )
        write_lines((output or "").splitlines(), self.output_paths["data"] / "nxc_gpp_password.txt")

    def _run_module(self, module: str) -> str:
        try:
            output, result = self.session.run_nxc(
                "smb", extra=["-M", module], timeout=180
            )
            report_netexec_failure(self.logger, f"nxc {module}", result)
            return output
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return ""
        except subprocess.TimeoutExpired:
            self.logger.error(f"[-] nxc {module} timed out")
            return ""
        except Exception as e:
            self.logger.error(f"[-] nxc {module}: {e}")
            return ""

    def _parse_gpp_password(self, output: str) -> List[Dict[str, str]]:
        creds = []
        current = {}
        for raw in (output or "").splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            found = re.search(r"Found credentials in\s+(\S+)", line)
            if found:
                if current.get("Password") or current.get("userName"):
                    creds.append(current)
                current = {"file": found.group(1)}
                continue
            m = re.search(r"\b(Password|userName|fullName|description|action)\s*:\s*(.*)\s*$", line)
            if m and current is not None:
                key, val = m.group(1), _strip_utf16_le(m.group(2).strip())
                current[key] = val
        if current.get("Password") or current.get("userName"):
            creds.append(current)
        return creds
