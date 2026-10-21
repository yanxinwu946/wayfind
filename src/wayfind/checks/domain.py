"""Domain-level security checks."""

from typing import Dict
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_file
from ..config import DOMAIN_FUNCTIONAL_LEVELS


class DomainChecker:
    """Checks related to domain configuration and functional level."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_functional_level(self):
        """Check if domain functional level is Windows Server 2025."""
        self.logger.info("---Checking domain functional level---")
        
        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['msDS-Behavior-Version', 'name', 'dc']
            )
            
            if not results:
                self.logger.error("[-] Could not retrieve domain information")
                return
            
            domain_data = results[0]
            level = domain_data.get('msDS-Behavior-Version', 0)
            if isinstance(level, list):
                level = level[0] if level else 0
            level = int(level) if level else 0
            
            level_name = DOMAIN_FUNCTIONAL_LEVELS.get(level, f"Unknown ({level})")
            filepath_findings = self.output_paths['findings'] / 'domainfunctionallevel.txt'
            filepath_checks = self.output_paths['checks'] / 'domainfunctionallevel.txt'
            
            output_lines = [
                f"Domain: {domain_data.get('name', 'unknown')}",
                f"Functional Level: {level_name}",
                f"Level Number: {level}",
                f"Distinguished Name: {domain_data.get('dn', 'unknown')}",
                "",
                "Raw Data:",
                f"  msDS-Behavior-Version: {domain_data.get('msDS-Behavior-Version', 'N/A')}",
            ]
            
            # Level 0-6: Obsolete (Server 2012 R2 and older, all end-of-support) - finding
            # Level 7+:  Current (Server 2016/2019/2022/2025) - secure
            if level <= 6:
                note(self, f"The domain functional level is {level_name}", id="domain.functional-level", level=level_name)
                write_file('\n'.join(output_lines), filepath_findings, self.logger)
            else:
                self.logger.success(f"[+] The domain functional level is {level_name}")
                write_file('\n'.join(output_lines), filepath_checks, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking domain functional level: {e}")
