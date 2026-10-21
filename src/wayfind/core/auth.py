"""Credential container used by Target."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Credentials:
    domain: str
    username: str
    password: str
    lm_hash: Optional[str] = None
    nt_hash: Optional[str] = None
    use_kerberos: bool = False
    use_ldaps: bool = False

    @property
    def domain_username(self) -> str:
        return self.domain.upper() + chr(92) + self.username

    @property
    def user_principal_name(self) -> str:
        return f"{self.username}@{self.domain.lower()}"

    def has_ntlm_hash(self) -> bool:
        return self.nt_hash is not None
