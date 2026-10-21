"""LDAP connection and query utilities."""

from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

# Workaround for MD4 being disabled in OpenSSL 3.0+
# NTLM authentication requires MD4, so we patch hashlib to use pycryptodome
import hashlib
try:
    hashlib.new('md4')
except ValueError:
    # MD4 not available, patch it with pycryptodome
    import functools
    from Cryptodome.Hash import MD4 as _MD4
    
    _orig_hashlib_new = hashlib.new
    
    @functools.wraps(_orig_hashlib_new)
    def _patched_hashlib_new(name, *args, **kwargs):
        if name.lower() == 'md4':
            return _MD4.new(*args, **kwargs)
        return _orig_hashlib_new(name, *args, **kwargs)
    
    hashlib.new = _patched_hashlib_new

from ldap3 import Server, Connection, NTLM, SASL, KERBEROS, EXTERNAL, Tls, SUBTREE, ALL_ATTRIBUTES, ENCRYPT, TLS_CHANNEL_BINDING
from ldap3.core.exceptions import (
    LDAPBindError, LDAPSocketOpenError, LDAPException, LDAPCommunicationError
)

from ..utils.logger import get_logger
from ..core.exceptions import ConnectionError, EnumerationError


def ntlm_session_options(use_ldaps: bool) -> Dict[str, str]:
    """Extra Connection kwargs so NTLM binds satisfy hardened DCs.

    Plain LDAP gets NTLM sealing (implies signing) for "Require signing" DCs;
    LDAPS gets channel binding instead, since TLS already protects the session.
    """
    if use_ldaps:
        return {"channel_binding": TLS_CHANNEL_BINDING}
    return {"session_security": ENCRYPT}


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""
    server: str
    domain: str
    username: str
    password: str
    use_ldaps: bool = False
    use_kerberos: bool = False
    hashes: str = None
    pfx: Optional[str] = None

    @property
    def domain_username(self) -> str:
        """Return DOMAIN\\username format."""
        return f"{self.domain.upper()}\\{self.username}"
    
    @property
    def base_dn(self) -> str:
        """Generate base DN from domain."""
        return ','.join([f"DC={part}" for part in self.domain.lower().split('.')])


class LDAPConnection:
    """Manages LDAP connections and queries."""
    PAGE_SIZE = 1000
    
    def __init__(self, config: LDAPConfig):
        self.config = config
        self.connection: Optional[Connection] = None
        self.logger = get_logger()
        self._pfx_tmp = None
    
    def _tls_from_pfx(self):
        import os
        import ssl
        import tempfile
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, pkcs12

        data = Path(self.config.pfx).read_bytes()
        key, cert, _chain = pkcs12.load_key_and_certificates(data, b"")
        if key is None or cert is None:
            raise ConnectionError("PFX is missing a private key or certificate")
        fd_k, key_path = tempfile.mkstemp(suffix=".key")
        fd_c, cert_path = tempfile.mkstemp(suffix=".pem")
        os.close(fd_k)
        os.close(fd_c)
        Path(key_path).write_bytes(
            key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        )
        Path(cert_path).write_bytes(cert.public_bytes(Encoding.PEM))
        self._pfx_tmp = (key_path, cert_path)
        return Tls(local_private_key=key_path, local_certificate=cert_path, validate=ssl.CERT_NONE)

    def _cleanup_pfx(self):
        import os
        if not self._pfx_tmp:
            return
        for path in self._pfx_tmp:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._pfx_tmp = None

    def connect(self) -> bool:
        """Establish LDAP connection."""
        try:
            use_ssl = self.config.use_ldaps or bool(self.config.pfx)
            port = 636 if use_ssl else 389
            tls = self._tls_from_pfx() if self.config.pfx else None
            server = Server(
                self.config.server,
                port=port,
                use_ssl=use_ssl,
                tls=tls,
                get_info='ALL'
            )

            if self.config.pfx:
                self.connection = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=EXTERNAL,
                    auto_bind=True,
                    raise_exceptions=True,
                )
            elif self.config.use_kerberos:
                self.connection = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True,
                    raise_exceptions=True,
                )
            elif not self.config.username:
                self.connection = Connection(
                    server, auto_bind=True, raise_exceptions=True
                )
            else:
                self.connection = Connection(
                    server,
                    user=self.config.domain_username,
                    password=self.config.password,
                    authentication=NTLM,
                    auto_bind=True,
                    raise_exceptions=True,
                    **ntlm_session_options(use_ssl)
                )

            self.logger.log_verbose(f"Connected to LDAP server {self.config.server}")
            return True

        except (LDAPBindError, LDAPSocketOpenError) as e:
            self._cleanup_pfx()
            self.logger.error(f"LDAP connection failed: {e}")
            raise ConnectionError(f"Failed to connect to LDAP: {e}")
        except Exception as e:
            self._cleanup_pfx()
            self.logger.error(f"LDAP error: {e}")
            raise ConnectionError(f"LDAP error: {e}")
    
    def disconnect(self):
        """Close LDAP connection."""
        if self.connection:
            try:
                self.connection.unbind()
                self.logger.log_verbose("LDAP connection closed")
            except Exception:
                pass
        self._cleanup_pfx()
    
    def _search_with_retry(self, **search_kwargs):
        """Run an LDAP search, reconnecting once if the connection was dropped.

        During a long audit the single LDAP connection can sit idle while
        external tools run (BloodHound, port scans, netexec) and the DC closes
        it server-side. The next write then fails with a broken-pipe/communication
        error. We transparently rebind once and retry so late-running checks
        don't spuriously report no results.
        """
        try:
            self.connection.search(**search_kwargs)
        except LDAPCommunicationError as e:
            self.logger.log_verbose(f"LDAP connection lost ({e}); reconnecting and retrying")
            self.connect()
            self.connection.search(**search_kwargs)

    def _paged_search_with_retry(self, **search_kwargs):
        """Run a paged LDAP search, reconnecting once if needed."""
        try:
            return self.connection.extend.standard.paged_search(**search_kwargs)
        except LDAPCommunicationError as e:
            self.logger.log_verbose(f"LDAP connection lost ({e}); reconnecting and retrying")
            self.connect()
            return self.connection.extend.standard.paged_search(**search_kwargs)

    def query(self, search_base: str, search_filter: str, attributes: List[str] = None) -> List[Dict]:
        """
        Execute LDAP query.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve (default: ALL)
            
        Returns:
            List of dictionaries with entry data
        """
        if not self.connection:
            raise ConnectionError("LDAP not connected")
        
        try:
            attrs = attributes if attributes else ALL_ATTRIBUTES

            response = self._paged_search_with_retry(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=self.PAGE_SIZE,
                generator=False
            )
            
            results = []
            for entry in response:
                if entry.get('type') != 'searchResEntry':
                    continue

                entry_data = {}
                for attr, value in entry.get('attributes', {}).items():
                    if isinstance(value, list) and len(value) == 1:
                        value = value[0]
                    entry_data[attr] = value
                results.append(entry_data)
            
            return results
            
        except LDAPException as e:
            self.logger.error(f"LDAP query failed: {e}")
            raise EnumerationError(f"Query failed: {e}")
    
    def get_config_dn(self) -> str:
        """Get the Configuration naming context from RootDSE."""
        if not self.connection:
            raise ConnectionError("LDAP not connected")
        
        try:
            # Query RootDSE - attributes are returned in allOperationalAttributes
            self._search_with_retry(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope=0,  # BASE scope for RootDSE
                attributes=['*', '+']  # All user + operational attributes
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                # RootDSE attributes are stored in entry entry_attributes
                for attr in entry.entry_attributes:
                    if attr.lower() == 'configurationnamingcontext':
                        value = entry[attr].value
                        if isinstance(value, list):
                            return value[0]
                        return value
            
            raise EnumerationError("Could not retrieve Configuration naming context")
            
        except LDAPException as e:
            self.logger.error(f"Failed to get Configuration DN: {e}")
            raise EnumerationError(f"Failed to get Configuration DN: {e}")
    
    def get_domain_sid(self) -> str:
        """Get the domain SID."""
        results = self.query(
            search_base=self.config.base_dn,
            search_filter='(objectClass=domain)',
            attributes=['objectSid']
        )
        
        if not results:
            raise EnumerationError("Could not retrieve domain SID")
        
        sid_bytes = results[0].get('objectSid')
        if isinstance(sid_bytes, list):
            sid_bytes = sid_bytes[0]
        
        return self._convert_sid(sid_bytes)
    
    @staticmethod
    def _convert_sid(sid_bytes) -> str:
        """Convert binary SID to string format."""
        if isinstance(sid_bytes, str):
            return sid_bytes
        
        # Parse binary SID
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], 'big')
        
        sid_str = f"S-{revision}-{identifier_authority}"
        
        offset = 8
        for i in range(sub_authority_count):
            sub_authority = int.from_bytes(sid_bytes[offset:offset+4], 'little')
            sid_str += f"-{sub_authority}"
            offset += 4
        
        return sid_str
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.disconnect()
