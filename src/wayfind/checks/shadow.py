"""Shadow Credentials: enumerate msDS-KeyCredentialLink via LDAP."""

from typing import Dict, Optional
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..core.session import Session


class ShadowChecker:
    """List objects that already have a KeyCredentialLink blob."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 session: Optional[Session] = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.base_dn = ldap_conn.config.base_dn

    def check_shadow(self):
        self.logger.info("---Checking shadow credentials (msDS-KeyCredentialLink)---")
        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter="(msDS-KeyCredentialLink=*)",
                attributes=["sAMAccountName", "distinguishedName", "msDS-KeyCredentialLink"],
            )
        except Exception as e:
            self.logger.error(f"[-] Shadow credential query failed: {e}")
            return

        if not results:
            self.logger.success("[+] No msDS-KeyCredentialLink values found")
            return

        lines = []
        t = self.session.target
        replay = (
            f"certipy shadow list -u {t.username}@{t.domain} "
            f"-dc-ip {t.dc_ip} -ldap-scheme {'ldaps' if t.use_ldaps else 'ldap'}"
        )
        for entry in results:
            sam = entry.get("sAMAccountName") or entry.get("distinguishedName") or "?"
            blob = entry.get("msDS-KeyCredentialLink")
            count = len(blob) if isinstance(blob, list) else 1
            lines.append(f"{sam} key_credential_count={count}")
            self.session.emit(
                id="shadow.keycredentiallink",
                severity="medium",
                title=f"{sam} has {count} KeyCredentialLink value(s)",
                asset=str(sam),
                evidence=f"msDS-KeyCredentialLink count={count}",
                replay=replay,
                backend="ldap",
                check="shadow",
            )

        write_lines(lines, self.output_paths["checks"] / "shadow_credentials.txt")
