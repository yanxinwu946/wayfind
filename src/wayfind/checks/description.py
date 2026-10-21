"""Description field security checks."""

from typing import Dict, List
from pathlib import Path
import re

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines


class DescriptionChecker:
    """Checks for sensitive information in description fields."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        
        # Password-related keywords to search for
        self.pass_keywords = ['pw', 'pass', 'ww', 'wachtwoord', 'pwd', 'password', 'key', 'secret']
    
    def check_descriptions(self):
        """Check all description fields for sensitive information."""
        self._check_user_descriptions()
        self._check_group_descriptions()
        self._check_computer_descriptions()
    
    def _check_user_descriptions(self):
        """Check user descriptions for passwords."""
        self.logger.info("---Checking description field for passwords---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(description=*))',
                attributes=['sAMAccountName', 'description']
            )
            
            filepath = self.output_paths['checks'] / 'description_users.txt'
            
            if users:
                count = len(users)
                self.logger.info(f"[*] {count} users have descriptions (saved for manual review)")
                write_csv(users, filepath)
                
                # Check for password-related keywords - this is the actual finding
                suspicious = []
                for user in users:
                    username = user.get('sAMAccountName', '').lower()
                    # Skip krbtgt account
                    if username == 'krbtgt':
                        continue
                    desc = user.get('description', '').lower()
                    if any(kw in desc for kw in self.pass_keywords):
                        suspicious.append(user)
                
                if suspicious:
                    self.logger.warning(f"[!] {len(suspicious)} users have password-related keywords in description!")
                    suspicious_file = self.output_paths['checks'] / 'description_users_passstrings.txt'
                    write_csv(suspicious, suspicious_file)
                else:
                    self.logger.success("[+] No password-related keywords in user descriptions")
            else:
                self.logger.info("[*] No users with descriptions found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking user descriptions: {e}")
    
    def _check_group_descriptions(self):
        """Check group descriptions for interesting information."""
        self.logger.info("---Checking groups description field---")
        
        try:
            groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=group)(description=*))',
                attributes=['sAMAccountName', 'description']
            )
            
            filepath = self.output_paths['checks'] / 'description_groups.txt'
            
            if groups:
                count = len(groups)
                self.logger.info(f"[*] {count} groups have descriptions (saved for manual review)")
                write_csv(groups, filepath)
                
                # Check for password-related keywords
                # Exclude well-known default groups whose descriptions naturally
                # contain password-related words
                default_groups = {
                    'allowed rodc password replication group',
                    'denied rodc password replication group',
                    'key admins',
                    'enterprise key admins',
                }
                suspicious = []
                for group in groups:
                    name = group.get('sAMAccountName', '').lower()
                    if name in default_groups:
                        continue
                    desc = group.get('description', '').lower()
                    if any(kw in desc for kw in self.pass_keywords):
                        suspicious.append(group)
                
                if suspicious:
                    self.logger.warning(f"[!] {len(suspicious)} groups have password-related keywords in description!")
                    suspicious_file = self.output_paths['checks'] / 'description_groups_passstrings.txt'
                    write_csv(suspicious, suspicious_file)
                else:
                    self.logger.success("[+] No password-related keywords in group descriptions")
            else:
                self.logger.info("[*] No groups with descriptions found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking group descriptions: {e}")
    
    def _check_computer_descriptions(self):
        """Check computer descriptions for interesting information."""
        self.logger.info("---Checking computer description field---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(description=*))',
                attributes=['sAMAccountName', 'description']
            )
            
            filepath = self.output_paths['checks'] / 'description_computers.txt'
            
            if computers:
                count = len(computers)
                self.logger.info(f"[*] {count} computers have descriptions (saved for manual review)")
                write_csv(computers, filepath)
                
                # Check for password-related keywords
                suspicious = []
                for computer in computers:
                    desc = computer.get('description', '').lower()
                    if any(kw in desc for kw in self.pass_keywords):
                        suspicious.append(computer)
                
                if suspicious:
                    note(self, f"{len(suspicious)} computers have password-related keywords in description!", id="description.computer-password-keywords", names=sams(suspicious, "sAMAccountName", "dNSHostName"))
                    suspicious_file = self.output_paths['findings'] / 'description_computers_passstrings.txt'
                    write_csv(suspicious, suspicious_file)
                else:
                    self.logger.success("[+] No password-related keywords in computer descriptions")
            else:
                self.logger.info("[*] No computers with descriptions found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking computer descriptions: {e}")
