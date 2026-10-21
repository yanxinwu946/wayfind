"""Exchange Server security checks."""

from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime, timedelta

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines


class ExchangeChecker:
    """Checks for Exchange Server configuration and permissions."""
    
    # Exchange specific group names
    EXCHANGE_GROUPS = [
        "Exchange Trusted Subsystem",
        "Exchange Windows Permissions", 
        "Organization Management"
    ]
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_exchange(self):
        """Run all Exchange security checks."""
        self._check_exchange_groups()
    
    def _check_exchange_groups(self):
        """Check for Exchange groups and enumerate memberships."""
        self.logger.info("---Checking if Exchange is used within the domain---")
        
        try:
            # Check for default Exchange groups
            exchange_groups = []
            for group_name in self.EXCHANGE_GROUPS:
                groups = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter=f'(&(objectClass=group)(cn={group_name}))',
                    attributes=['cn', 'distinguishedName', 'member']
                )
                if groups:
                    exchange_groups.extend(groups)
            
            if not exchange_groups:
                self.logger.success("[+] No default Exchange groups discovered")
                return
            
            self.logger.info("[+] Default Exchange groups exist")
            write_csv(exchange_groups, self.output_paths['data'] / 'Exchange_groups.txt')
            
            # Check for Exchange servers via Exchange Trusted Subsystem members
            self._check_exchange_servers()
            
            # Check Exchange Windows Permissions membership
            self._check_exchange_permissions_group()
            
            # Check Organization Management membership  
            self._check_organization_management()
            
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange groups: {e}")
    
    def _check_exchange_servers(self):
        """Check for Exchange servers in Exchange Trusted Subsystem group."""
        self.logger.info("---Checking for Exchange servers---")
        
        try:
            # Check for computer objects in Exchange Trusted Subsystem
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(memberOf=CN=Exchange Trusted Subsystem,*))',
                attributes=['sAMAccountName', 'distinguishedName', 'lastLogonTimestamp']
            )
            
            exchange_servers = []
            
            # Get computers from memberOf
            for comp in computers:
                exchange_servers.append(comp)
            
            # Also check for Exchange servers by name patterns
            exchange_name_patterns = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(|(name=*EXCH*)(name=*MAIL*)(name=*EXCHANGE*)))',
                attributes=['sAMAccountName', 'distinguishedName', 'lastLogonTimestamp']
            )
            
            for comp in exchange_name_patterns:
                # Avoid duplicates
                if not any(c.get('sAMAccountName') == comp.get('sAMAccountName') for c in exchange_servers):
                    exchange_servers.append(comp)
            
            if exchange_servers:
                self.logger.info(f"[*] Discovered {len(exchange_servers)} potential Exchange servers")
                write_csv(exchange_servers, self.output_paths['data'] / 'Exchange_servers.txt')
                
                # Check for recent logons (within last 31 days)
                cutoff = (datetime.now() - timedelta(days=31)).timestamp()
                recent_logons = []
                
                for server in exchange_servers:
                    last_logon = server.get('lastLogonTimestamp')
                    if last_logon:
                        try:
                            # Convert LDAP timestamp to unix timestamp
                            if isinstance(last_logon, str):
                                last_logon = int(last_logon)
                            # LDAP timestamp is 100-nanosecond intervals since 1601
                            ldap_epoch = 11644473600  # Seconds between 1601 and 1970
                            unix_time = (last_logon / 10000000) - ldap_epoch
                            
                            if unix_time > cutoff:
                                recent_logons.append(server)
                        except Exception:
                            continue
                
                if recent_logons:
                    self.logger.info(f"[*] There has been a logon on {len(recent_logons)} Exchange server(s) in the last 30 days")
                    self.logger.info("[*] Manually check for access/open mailboxes with OWA or Mailsniper")
                else:
                    self.logger.info("[*] No logon within the last 31 days, might be old servers")
            else:
                self.logger.success("[+] Exchange Trusted Subsystem has no computer memberships")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange servers: {e}")
    
    def _check_exchange_permissions_group(self):
        """Check Exchange Windows Permissions group membership.
        
        This group typically has WriteDACL on the domain root, meaning any
        member can grant themselves DCSync rights and compromise the entire
        domain (PrivExchange / CVE-2019-1040 attack path).
        """
        self.logger.info("---Checking for Exchange Windows Permissions membership---")
        
        try:
            # Get members of Exchange Windows Permissions
            members = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(memberOf=CN=Exchange Windows Permissions,*))',
                attributes=['sAMAccountName', 'distinguishedName', 'memberOf']
            )
            
            if members:
                note(self, 
                    f"{len(members)} user(s) in Exchange Windows Permissions - this group typically has WriteDACL on the domain root (PrivExchange escalation path)",
                    id="exchange.windows-permissions", names=sams(members), severity="high",
                )
                write_csv(
                    members, 
                    self.output_paths['data'] / 'Exchange_memberships_ExchangeWindowsPermissions.txt'
                )
            else:
                self.logger.success("[+] There are no users in Exchange Windows Permissions")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange Windows Permissions: {e}")
    
    def _check_organization_management(self):
        """Check Organization Management group membership.
        
        Organization Management has full control over the Exchange organization
        and can manage Exchange Windows Permissions membership, providing an
        indirect path to domain compromise via WriteDACL escalation.
        """
        self.logger.info("---Checking for Organization Management membership---")
        
        try:
            # Get members of Organization Management
            members = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(memberOf=CN=Organization Management,*))',
                attributes=['sAMAccountName', 'distinguishedName', 'memberOf']
            )
            
            if members:
                note(self, 
                    f"{len(members)} user(s) in Organization Management - can manage Exchange group memberships and escalate to domain admin",
                    id="exchange.organization-management", names=sams(members), severity="high",
                )
                write_csv(
                    members,
                    self.output_paths['data'] / 'Exchange_memberships_OrganizationManagement.txt'
                )
            else:
                self.logger.success("[+] There are no users in Organization Management")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Organization Management: {e}")
