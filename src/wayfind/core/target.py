"""First-class Target: identity, DC, DNS, SOCKS, and LDAP transport."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .auth import Credentials
from ..utils.ldap import LDAPConfig


@dataclass
class Target:
    """Connection parameters shared by LDAP, nxc, and certipy."""

    domain: str
    dc_ip: str
    username: str = ""
    password: Optional[str] = None
    hashes: Optional[str] = None
    aes: Optional[str] = None
    kerberos: bool = False
    ccache: Optional[str] = None
    pfx: Optional[str] = None
    dns: Optional[str] = None
    dc_host: Optional[str] = None
    socks: Optional[str] = None
    use_ldaps: bool = False
    timeout: int = 10

    @property
    def dns_server(self) -> str:
        return self.dns or self.dc_ip

    @property
    def use_kerberos(self) -> bool:
        return self.kerberos

    def has_secret(self) -> bool:
        return bool(self.password or self.hashes or self.kerberos or self.ccache or self.pfx)

    def split_hashes(self) -> Tuple[Optional[str], Optional[str]]:
        if not self.hashes:
            return None, None
        if ":" in self.hashes:
            lm, nt = self.hashes.split(":", 1)
            return lm or None, nt or None
        return None, self.hashes

    @property
    def ldap_bind_secret(self) -> str:
        """Secret ldap3 NTLM bind expects (password or LM:NT hash)."""
        lm, nt = self.split_hashes()
        if nt:
            return f"{lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}"
        return self.password or ""

    @property
    def domain_username(self) -> str:
        return f"{self.domain.upper()}\\{self.username}"

    def credentials(self) -> Credentials:
        lm, nt = self.split_hashes()
        return Credentials(
            domain=self.domain,
            username=self.username,
            password=self.password or "",
            lm_hash=lm,
            nt_hash=nt,
            use_kerberos=self.kerberos,
            use_ldaps=self.use_ldaps,
        )

    def ldap_config(self) -> LDAPConfig:
        return LDAPConfig(
            server=self.dc_ip,
            domain=self.domain,
            username=self.username,
            password=self.ldap_bind_secret,
            use_ldaps=self.use_ldaps,
            use_kerberos=self.kerberos,
            hashes=self.hashes,
            pfx=self.pfx,
        )
