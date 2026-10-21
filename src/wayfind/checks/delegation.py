"""Delegation security checks."""

from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines


class DelegationChecker:
    """Checks for constrained, unconstrained, and resource-based constrained delegation."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_delegation(self):
        """Run all delegation-related checks."""
        self._check_constrained_delegation_users()
        self._check_unconstrained_delegation_users()
        self._check_constrained_delegation_computers()
        self._check_unconstrained_delegation_computers()
        self._check_resource_based_delegation()
    
    def _check_constrained_delegation_users(self):
        """Check for users with constrained delegation (msDS-AllowedToDelegateTo)."""
        self.logger.info("---Checking constrained delegation users---")
        
        try:
            # Note: objectClass=user also matches computers, so we exclude objectClass=computer
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(!(objectClass=computer))(msDS-AllowedToDelegateTo=*))',
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
            )
            
            filepath = self.output_paths['findings'] / 'users_constrained_delegation.txt'
            
            if users:
                count = len(users)
                note(self, f"{count} users have constrained delegation enabled", id="delegation.users-constrained", names=sams(users))
                write_csv(users, filepath)
            else:
                self.logger.success("[+] No users with constrained delegation")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking constrained delegation users: {e}")
    
    def _check_unconstrained_delegation_users(self):
        """Check for users with unconstrained delegation (TRUSTED_FOR_DELEGATION)."""
        self.logger.info("---Checking unconstrained delegation users---")
        
        try:
            # TRUSTED_FOR_DELEGATION = 0x1000000 = 524288
            # Note: objectClass=user also matches computers, so we exclude objectClass=computer
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_unconstrained_delegation.txt'
            
            if users:
                count = len(users)
                note(self, f"{count} users have unconstrained delegation enabled", id="delegation.users-unconstrained", names=sams(users), severity="high")
                write_csv(users, filepath)
            else:
                self.logger.success("[+] No users with unconstrained delegation")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking unconstrained delegation users: {e}")
    
    def _check_constrained_delegation_computers(self):
        """Check for computers with constrained delegation."""
        self.logger.info("---Checking constrained delegation computers---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))',
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
            )
            
            filepath = self.output_paths['findings'] / 'computers_constrained_delegation.txt'
            
            if computers:
                count = len(computers)
                note(self, f"{count} computers have constrained delegation enabled", id="delegation.computers-constrained", names=sams(computers, "sAMAccountName", "dNSHostName"))
                write_csv(computers, filepath)
            else:
                self.logger.success("[+] No computers with constrained delegation")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking constrained delegation computers: {e}")
    
    def _check_unconstrained_delegation_computers(self):
        """Check for computers with unconstrained delegation (excluding DCs)."""
        self.logger.info("---Checking unconstrained delegation computers---")
        
        try:
            # TRUSTED_FOR_DELEGATION = 0x1000000 = 524288, exclude SERVER_TRUST_ACCOUNT (DCs)
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'computers_unconstrained_delegation.txt'
            
            if computers:
                count = len(computers)
                note(self, f"{count} non-DC computers have unconstrained delegation enabled", id="delegation.computers-unconstrained", names=sams(computers, "sAMAccountName", "dNSHostName"), severity="high")
                write_csv(computers, filepath)
            else:
                self.logger.success("[+] No non-DC computers with unconstrained delegation")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking unconstrained delegation computers: {e}")
    
    def _check_resource_based_delegation(self):
        """Check for resource-based constrained delegation (RBCD)."""
        self.logger.info("---Checking resource-based constrained delegation---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))',
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            
            filepath = self.output_paths['findings'] / 'computers_resource_based_constrained_delegation.txt'
            
            if computers:
                count = len(computers)
                note(self, f"{count} computers have RBCD configured - review for legitimacy and abuse paths", id="delegation.computers-rbcd", names=sams(computers, "sAMAccountName", "dNSHostName"))
                names = [c.get('sAMAccountName', '') for c in computers if c.get('sAMAccountName')]
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No computers with RBCD")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking RBCD: {e}")
