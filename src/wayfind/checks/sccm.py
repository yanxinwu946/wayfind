"""SCCM (System Center Configuration Manager) detection check.

Checks for SCCM by looking for the System Management container in LDAP.
"""

from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines


class SCCMChecker:
    """Check for SCCM presence in Active Directory."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_sccm(self):
        """Check if SCCM System Management container exists."""
        self.logger.info("---Checking for SCCM---")
        
        # The SCCM System Management container path
        sccm_container = f"CN=System Management,CN=System,{self.base_dn}"
        
        self.logger.info(f"[*] Looking for SCCM container: {sccm_container}")
        
        try:
            # Query for the System Management container
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(distinguishedName={sccm_container})',
                attributes=['distinguishedName', 'objectClass', 'whenCreated', 'nTSecurityDescriptor']
            )
            
            if results:
                self.logger.warning(f"[!] SCCM System Management container found")
                
                # Collect info (not a finding - SCCM itself is not a vulnerability)
                info_lines = [
                    "SCCM System Management container detected",
                    f"Container: {sccm_container}",
                    "",
                    "Details:"
                ]
                
                for result in results:
                    for key, value in result.items():
                        info_lines.append(f"  {key}: {value}")
                
                info_lines.append("")
                info_lines.append("Note: SCCM presence is informational only.")
                info_lines.append("Review SCCM permissions for potential attack paths.")
                
                # Write to data (not findings since it's not a vulnerability)
                write_lines(info_lines,
                           self.output_paths['data'] / 'sccm_container.txt')
                
                return True
            else:
                self.logger.success("[+] SCCM System Management container not found")
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Error checking for SCCM: {e}")
            return False
