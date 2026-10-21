"""Privileged groups membership checks."""

from typing import Dict, List, Optional
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines


class PrivilegedGroupsChecker:
    """Checks for members of high privileged groups that shouldn't have non-admin members."""
    
    # Well-known SIDs for builtin groups
    ACCOUNT_OPERATORS_SID = "S-1-5-32-548"
    BACKUP_OPERATORS_SID = "S-1-5-32-551"
    PRINT_OPERATORS_SID = "S-1-5-32-550"
    REMOTE_MANAGEMENT_USERS_SID = "S-1-5-32-580"
    HYPER_V_ADMINS_SID = "S-1-5-32-578"
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self._domain_sid = None
        self._domain_admins_dn = None
        self._enterprise_admins_dn = None
    
    def _get_domain_sid(self) -> Optional[str]:
        """Get the domain SID."""
        if self._domain_sid:
            return self._domain_sid
        
        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['objectSid']
            )
            if results:
                sid = results[0].get('objectSid', '')
                if isinstance(sid, list):
                    sid = sid[0] if sid else ''
                self._domain_sid = str(sid)
                return self._domain_sid
        except Exception as e:
            self.logger.error(f"[-] Error getting domain SID: {e}")
        return None
    
    def _get_privileged_group_dns(self):
        """Get distinguished names of Domain Admins and Enterprise Admins."""
        domain_sid = self._get_domain_sid()
        if not domain_sid:
            return
        
        try:
            # Domain Admins: domain SID + -512
            da_sid = f"{domain_sid}-512"
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(objectSid={da_sid})',
                attributes=['distinguishedName']
            )
            if results:
                self._domain_admins_dn = results[0].get('distinguishedName', '')
            
            # Enterprise Admins: domain SID + -519
            ea_sid = f"{domain_sid}-519"
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(objectSid={ea_sid})',
                attributes=['distinguishedName']
            )
            if results:
                self._enterprise_admins_dn = results[0].get('distinguishedName', '')
        except Exception as e:
            self.logger.error(f"[-] Error getting privileged group DNs: {e}")
    
    def _get_group_members_by_sid(self, sid: str) -> List[Dict]:
        """Get members of a group by its SID, excluding Domain/Enterprise Admins."""
        try:
            # First get the group DN by SID
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(objectSid={sid})',
                attributes=['distinguishedName', 'sAMAccountName']
            )
            
            if not results:
                return []
            
            group_dn = results[0].get('distinguishedName', '')
            if not group_dn:
                return []
            
            return self._get_group_members(group_dn)
        except Exception as e:
            self.logger.error(f"[-] Error getting group members by SID {sid}: {e}")
            return []
    
    def _get_group_members_by_name(self, name: str) -> List[Dict]:
        """Get members of a group by its name, excluding Domain/Enterprise Admins."""
        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(&(objectClass=group)(sAMAccountName={name}))',
                attributes=['distinguishedName', 'sAMAccountName']
            )
            
            if not results:
                return []
            
            group_dn = results[0].get('distinguishedName', '')
            if not group_dn:
                return []
            
            return self._get_group_members(group_dn)
        except Exception as e:
            self.logger.error(f"[-] Error getting group members by name {name}: {e}")
            return []
    
    def _get_group_members(self, group_dn: str) -> List[Dict]:
        """Get user members of a group, excluding Domain/Enterprise Admins."""
        members = []
        
        try:
            # Query for users who are members of the group (recursive via LDAP_MATCHING_RULE_IN_CHAIN)
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(&(objectClass=user)(!(objectClass=computer))(memberOf:1.2.840.113556.1.4.1941:={group_dn}))',
                attributes=['sAMAccountName', 'memberOf', 'distinguishedName']
            )
            
            if not results:
                return []
            
            # Filter out users who are members of Domain Admins or Enterprise Admins
            for user in results:
                member_of = user.get('memberOf', [])
                if isinstance(member_of, str):
                    member_of = [member_of]
                
                is_privileged_admin = False
                for group in member_of:
                    if self._domain_admins_dn and self._domain_admins_dn in group:
                        is_privileged_admin = True
                        break
                    if self._enterprise_admins_dn and self._enterprise_admins_dn in group:
                        is_privileged_admin = True
                        break
                
                if not is_privileged_admin:
                    members.append(user)
            
            return members
        except Exception as e:
            self.logger.error(f"[-] Error getting group members for {group_dn}: {e}")
            return []
    
    def check_privileged_groups(self):
        """Run all privileged group membership checks."""
        self.logger.info("---Checking if there are members in high privileged groups---")
        
        # Initialize privileged group DNs for filtering
        self._get_privileged_group_dns()
        
        # Check each privileged group
        self._check_account_operators()
        self._check_backup_operators()
        self._check_print_operators()
        self._check_dns_admins()
        self._check_schema_admins()
    
    def _check_account_operators(self):
        """Check for non-admin members in Account Operators group."""
        members = self._get_group_members_by_sid(self.ACCOUNT_OPERATORS_SID)
        filepath = self.output_paths['checks'] / 'users_highprivilegegroups_AccountOperators.txt'
        
        if members:
            count = len(members)
            note(self, f"{count} users in the Account Operators group that aren't Domain- or Enterprise Administrators", id="privileged-groups.account-operators", names=sams(members))
            names = [m.get('sAMAccountName', '') for m in members if m.get('sAMAccountName')]
            write_lines(names, filepath)
        else:
            self.logger.success("[+] There are no users in the Account Operators group")
    
    def _check_backup_operators(self):
        """Check for non-admin members in Backup Operators group."""
        members = self._get_group_members_by_sid(self.BACKUP_OPERATORS_SID)
        filepath = self.output_paths['checks'] / 'users_highprivilegegroups_BackupOperators.txt'
        
        if members:
            count = len(members)
            note(self, f"{count} users in the Backup Operators group that aren't Domain- or Enterprise Administrators", id="privileged-groups.backup-operators", names=sams(members))
            names = [m.get('sAMAccountName', '') for m in members if m.get('sAMAccountName')]
            write_lines(names, filepath)
        else:
            self.logger.success("[+] There are no users in the Backup Operators group")
    
    def _check_print_operators(self):
        """Check for non-admin members in Print Operators group."""
        members = self._get_group_members_by_sid(self.PRINT_OPERATORS_SID)
        filepath = self.output_paths['checks'] / 'users_highprivilegegroups_PrintOperators.txt'
        
        if members:
            count = len(members)
            note(self, f"{count} users in the Print Operators group that aren't Domain- or Enterprise Administrators", id="privileged-groups.print-operators", names=sams(members))
            names = [m.get('sAMAccountName', '') for m in members if m.get('sAMAccountName')]
            write_lines(names, filepath)
        else:
            self.logger.success("[+] There are no users in the Print Operators group")
    
    def _check_dns_admins(self):
        """Check for non-admin members in DNS Admins group."""
        # DNS Admins doesn't have a well-known SID, search by name
        members = self._get_group_members_by_name("DnsAdmins")
        filepath = self.output_paths['checks'] / 'users_highprivilegegroups_DNSAdmins.txt'
        
        if members:
            count = len(members)
            note(self, f"{count} users in the DNS Admins group that aren't Domain- or Enterprise Administrators", id="privileged-groups.dns-admins", names=sams(members))
            names = [m.get('sAMAccountName', '') for m in members if m.get('sAMAccountName')]
            write_lines(names, filepath)
        else:
            self.logger.success("[+] There are no users in the DNS Admins group")
    
    def _check_schema_admins(self):
        """Check for non-admin members in Schema Admins group."""
        domain_sid = self._get_domain_sid()
        if not domain_sid:
            self.logger.error("[-] Could not get domain SID for Schema Admins check")
            return
        
        # Schema Admins: domain SID + -518
        schema_admins_sid = f"{domain_sid}-518"
        members = self._get_group_members_by_sid(schema_admins_sid)
        filepath = self.output_paths['checks'] / 'users_highprivilegegroups_SchemaAdmins.txt'
        
        if members:
            count = len(members)
            note(self, f"{count} users in the Schema Admins group that aren't Domain- or Enterprise Administrators", id="privileged-groups.schema-admins", names=sams(members))
            names = [m.get('sAMAccountName', '') for m in members if m.get('sAMAccountName')]
            write_lines(names, filepath)
        else:
            self.logger.success("[+] There are no users in the Schema Admins group")
