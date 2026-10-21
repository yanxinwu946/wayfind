"""User attribute security checks."""

from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines


class UserAttrsChecker:
    """Checks for user attributes that decrease account security."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_user_attributes(self):
        """Run all user attribute-related checks."""
        self._check_passwd_not_reqd()
        self._check_dont_expire_password()
        self._check_reversible_encryption()
        self._check_des_encryption()
        self._check_user_password()
    
    def _check_passwd_not_reqd(self):
        """Check for users with PASSWD_NOTREQD attribute."""
        self.logger.info("---Checking PASSWD_NOTREQD users---")
        
        try:
            # PASSWD_NOTREQD = 0x20 = 32
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_passwdnotreqd.txt'
            
            if users:
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"{len(names)} users have PASSWD_NOTREQD (password not required)",
                     id="user-attrs.passwd-notreqd", names=names)
                write_lines(names, filepath)
                self.logger.info("[+] These users may have empty passwords - consider testing")
            else:
                self.logger.success("[+] No users with PASSWD_NOTREQD")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking PASSWD_NOTREQD: {e}")
    
    def _check_dont_expire_password(self):
        """Check for users with DONT_EXPIRE_PASSWORD attribute."""
        self.logger.info("---Checking DONT_EXPIRE_PASSWORD users---")
        
        try:
            # DONT_EXPIRE_PASSWORD = 0x10000 = 65536
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_dontexpirepassword.txt'
            
            if users:
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"{len(names)} users have DONT_EXPIRE_PASSWORD flag",
                     id="user-attrs.dont-expire", names=names)
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with DONT_EXPIRE_PASSWORD flag")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking DONT_EXPIRE_PASSWORD: {e}")
    
    def _check_reversible_encryption(self):
        """Check for users with reversible encryption enabled."""
        self.logger.info("---Checking reversible encryption users---")
        
        try:
            # ENCRYPTED_TEXT_PWD_ALLOWED = 0x80 = 128
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_reversibleencryption.txt'
            
            if users:
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"{len(names)} users have reversible encryption (CRITICAL!)",
                     id="user-attrs.reversible-encryption", names=names, severity="high")
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with reversible encryption")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking reversible encryption: {e}")
    
    def _check_des_encryption(self):
        """Check for users with DES encryption only."""
        self.logger.info("---Checking DES encryption users---")
        
        try:
            # USE_DES_KEY_ONLY = 0x200000 = 2097152
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_desencryption.txt'
            
            if users:
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"{len(names)} users have DES-only encryption (WEAK!)",
                     id="user-attrs.des-only", names=names)
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with DES-only encryption")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking DES encryption: {e}")
    
    def _check_user_password(self):
        """Check for users with userPassword attribute exposed in LDAP.
        
        The userPassword attribute may contain cleartext or hashed passwords
        stored in LDAP. This is a security risk if accessible by authenticated users.
        """
        self.logger.info("---Checking userPassword attribute---")
        
        try:
            # Search for users with userPassword attribute present
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userPassword=*))',
                attributes=['sAMAccountName', 'userPassword']
            )
            
            filepath = self.output_paths['findings'] / 'users_userpassword.txt'
            
            if users:
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"{len(names)} users have userPassword attribute exposed!",
                     id="user-attrs.userpassword", names=names, severity="high")
                
                results = []
                for user in users:
                    username = user.get('sAMAccountName', 'UNKNOWN')
                    password_attr = user.get('userPassword', '')
                    
                    # Handle bytes or string values
                    if isinstance(password_attr, bytes):
                        try:
                            password_attr = password_attr.decode('utf-8')
                        except UnicodeDecodeError:
                            password_attr = password_attr.hex()
                    elif isinstance(password_attr, list):
                        password_attr = str(password_attr[0]) if password_attr else ''
                    
                    note(self, f"  User: {username} - userPassword: {password_attr}", id="user-attrs.userpassword-value", asset=username, password_attr=str(password_attr))
                    results.append(f"{username}:{password_attr}")
                
                write_lines(results, filepath)
                self.logger.info(f"[+] Results saved to {filepath}")
            else:
                self.logger.success("[+] No users with userPassword attribute exposed")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking userPassword: {e}")
