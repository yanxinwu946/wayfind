"""WSUS security checks - detect HTTP WSUS which is vulnerable to MITM attacks."""

import io
import re
from typing import Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_file, write_lines
from ..utils.registry_pol import parse_pol_file


class WSUSChecker:
    """Check WSUS configuration for HTTP usage which enables MITM attacks."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain
    
    def check_wsus(self):
        """Check WSUS configuration for HTTP usage (vulnerable to MITM)."""
        self.logger.info("---Checking WSUS configuration for HTTP usage---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] WSUS check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection, SessionError
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            conn = SMBConnection(self.server, self.server)
            conn.login(self.username, self.password, self.domain)
            
            wsus_policies = self._extract_wsus_policies(conn)
            
            conn.logoff()
            
            if not wsus_policies:
                self.logger.success("[+] No WSUS policies found in SYSVOL")
                return
            
            # Categorize policies by scheme
            http_policies = [p for p in wsus_policies if p['scheme'] == 'http']
            https_policies = [p for p in wsus_policies if p['scheme'] == 'https']
            
            # Report findings
            if http_policies:
                note(self, f"{len(http_policies)} WSUS policies use HTTP (vulnerable to MITM)", id="wsus.http", names=[p.get('gpo_name') for p in http_policies], severity="high")
                findings = []
                for policy in http_policies:
                    findings.append(
                        f"GPO: {policy['gpo_name']}\n"
                        f"  URL: {policy['scheme']}://{policy['host']}:{policy['port']}\n"
                        f"  VULNERABLE: WSUS over HTTP allows MITM attacks (see WSUSpect/wsuks)"
                    )
                write_lines(findings, self.output_paths['findings'] / 'wsus_http_vulnerable.txt')
            
            if https_policies:
                self.logger.success(f"[+] {len(https_policies)} WSUS policies use HTTPS (not vulnerable)")
                data = []
                for policy in https_policies:
                    data.append(f"GPO: {policy['gpo_name']} - {policy['scheme']}://{policy['host']}:{policy['port']}")
                write_lines(data, self.output_paths['data'] / 'wsus_https_policies.txt')
            
            if not http_policies and not https_policies:
                self.logger.success("[+] No WSUS policies with WUServer configured")
            elif not http_policies:
                self.logger.success("[+] All WSUS policies use HTTPS")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking WSUS configuration: {e}")
    
    def _extract_wsus_policies(self, conn) -> List[Dict]:
        """Extract WSUS server configuration from all GPO Registry.pol files."""
        from impacket.smbconnection import SessionError
        
        wsus_policies = []
        
        try:
            # List all policies in SYSVOL
            policies = conn.listPath("SYSVOL", f"{self.domain}/Policies/*")
        except Exception as e:
            self.logger.error(f"[-] Could not list SYSVOL policies: {e}")
            return wsus_policies
        
        for policy in policies:
            policy_name = policy.get_longname()
            
            # Skip . and ..
            if policy_name in ['.', '..']:
                continue
            
            share_path = f"{self.domain}/Policies/{policy_name}/Machine/Registry.pol"
            
            try:
                content_buffer = io.BytesIO()
                conn.getFile("SYSVOL", share_path, content_buffer.write)
                content = content_buffer.getvalue()
                
                if content:
                    wsus_info = self._parse_wsus_from_pol(content, policy_name)
                    if wsus_info:
                        wsus_policies.append(wsus_info)
                        
            except SessionError:
                # Registry.pol doesn't exist for this GPO, skip silently
                pass
            except Exception as e:
                self.logger.debug(f"Could not read Registry.pol for {policy_name}: {e}")
        
        return wsus_policies
    
    def _parse_wsus_from_pol(self, content: bytes, gpo_name: str) -> Optional[Dict]:
        """Parse Registry.pol content and extract WSUS server configuration.
        
        Looks for:
        - Key: Software\\Policies\\Microsoft\\Windows\\WindowsUpdate
        - Value: WUServer
        - Data: URL like http://wsus.domain.com:8530 or https://wsus.domain.com:8531
        """
        entries = parse_pol_file(content)
        
        for key, value_name, reg_type, size, data in entries:
            if (key == "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate" and 
                value_name == "WUServer"):
                
                # Data should be a URL string (REG_SZ, type 1)
                if reg_type == 1:  # REG_SZ
                    try:
                        url = data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                        
                        # Parse URL: http(s)://host:port
                        match = re.search(r'^(https?)://([^:/]+):?(\d+)?', url)
                        if match:
                            scheme = match.group(1).lower()
                            host = match.group(2)
                            port = int(match.group(3)) if match.group(3) else (443 if scheme == 'https' else 8530)
                            
                            return {
                                'gpo_name': gpo_name,
                                'scheme': scheme,
                                'host': host,
                                'port': port,
                                'url': url
                            }
                    except Exception:
                        pass
        
        return None
