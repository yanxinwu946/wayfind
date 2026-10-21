"""Active Directory enumeration module."""

import csv
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass

from .utils.logger import get_logger
from .utils.ldap import LDAPConnection, LDAPConfig
from .utils.output import write_csv, write_lines
from .core.exceptions import EnumerationError


@dataclass
class DomainData:
    """Container for domain enumeration results."""
    users: List[Dict]
    groups: List[Dict]
    computers: List[Dict]
    gpos: List[Dict]
    ous: List[Dict]
    domain_controllers: List[Dict]
    domain_sid: str


class ADEnumerator:
    """Handles Active Directory enumeration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def enumerate_all(self) -> DomainData:
        """Run all enumeration tasks."""
        # Get domain SID first (needed for privileged group enumeration)
        self.logger.log_verbose("Gathering domain SID")
        domain_sid = self.get_domain_sid()
        
        # Enumerate all objects
        users = self.enumerate_users()
        groups = self.enumerate_groups()
        computers = self.enumerate_computers()
        gpos = self.enumerate_gpos()
        ous = self.enumerate_ous()
        dcs = self.enumerate_domain_controllers()
        
        return DomainData(
            users=users,
            groups=groups,
            computers=computers,
            gpos=gpos,
            ous=ous,
            domain_controllers=dcs,
            domain_sid=domain_sid
        )
    
    def get_domain_sid(self) -> str:
        """Get the domain SID."""
        return self.ldap.get_domain_sid()
    
    def enumerate_users(self) -> List[Dict]:
        """Enumerate all users."""
        self.logger.log_verbose("Gathering data of all Users")
        
        attributes = [
            'sAMAccountName', 'description', 'mail', 'servicePrincipalName',
            'msDS-AllowedToDelegateTo', 'userAccountControl', 'lastLogon',
            'pwdLastSet', 'memberOf', 'adminCount'
        ]
        
        users = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(&(objectClass=user)(objectCategory=person))',
            attributes=attributes
        )
        
        # Save to CSV
        if users:
            csv_path = self.output_paths['data'] / 'data_users.csv'
            write_csv(users, csv_path)
        
        return users
    
    def enumerate_groups(self) -> List[Dict]:
        """Enumerate all groups."""
        self.logger.log_verbose("Gathering data of all Groups")
        
        attributes = ['sAMAccountName', 'description', 'groupType', 'member', 'adminCount']
        
        groups = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=group)',
            attributes=attributes
        )
        
        if groups:
            csv_path = self.output_paths['data'] / 'data_groups.csv'
            write_csv(groups, csv_path)
        
        return groups
    
    def enumerate_computers(self) -> List[Dict]:
        """Enumerate all computers."""
        self.logger.log_verbose("Gathering data of all Computerobjects")
        
        attributes = ['dNSHostName', 'sAMAccountName', 'operatingSystem', 
                     'operatingSystemVersion', 'lastLogon', 'userAccountControl']
        
        computers = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=computer)',
            attributes=attributes
        )
        
        if computers:
            csv_path = self.output_paths['data'] / 'data_computers.csv'
            write_csv(computers, csv_path)
        
        return computers
    
    def enumerate_gpos(self) -> List[Dict]:
        """Enumerate all GPOs."""
        self.logger.log_verbose("Gathering data of all GPOs")
        
        attributes = ['displayName', 'gPCFileSysPath', 'versionNumber']
        
        gpos = self.ldap.query(
            search_base=f"CN=Policies,CN=System,{self.base_dn}",
            search_filter='(objectClass=groupPolicyContainer)',
            attributes=attributes
        )
        
        if gpos:
            csv_path = self.output_paths['data'] / 'data_gpo.csv'
            write_csv(gpos, csv_path)
        
        return gpos
    
    def enumerate_ous(self) -> List[Dict]:
        """Enumerate all OUs."""
        self.logger.log_verbose("Gathering data of all OUs")
        
        attributes = ['name', 'description']
        
        ous = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=organizationalUnit)',
            attributes=attributes
        )
        
        if ous:
            csv_path = self.output_paths['data'] / 'data_ou.csv'
            write_csv(ous, csv_path)
        
        return ous
    
    def enumerate_domain_controllers(self) -> List[Dict]:
        """Enumerate domain controllers."""
        self.logger.log_verbose("Gathering data of all domain controllers")
        
        attributes = ['dNSHostName', 'sAMAccountName', 'operatingSystem']
        
        dcs = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=attributes
        )
        
        if dcs:
            csv_path = self.output_paths['data'] / 'data_domaincontrollers.csv'
            write_csv(dcs, csv_path)
        
        return dcs
    

    def enumerate_privileged_group_members(self, domain_sid: str) -> dict:
        """Enumerate members of Domain Admins and Enterprise Admins groups.
        
        Returns:
            Dict mapping group name to member count
        """
        self.logger.log_verbose("Enumerating Domain Admins and Enterprise Admins members")
        member_counts = {}
        
        # Well-known RIDs for privileged groups
        privileged_groups = {
            'Domain Admins': f"{domain_sid}-512",
            'Enterprise Admins': f"{domain_sid}-519"
        }
        
        for group_name, group_sid in privileged_groups.items():
            try:
                # Get the group with its member attribute
                group_result = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter=f'(objectSid={group_sid})',
                    attributes=['distinguishedName', 'sAMAccountName', 'member']
                )
                
                if not group_result:
                    self.logger.warning(f"[!] Could not find {group_name} group")
                    continue
                
                # Get direct members from the member attribute
                member_dns = group_result[0].get('member', [])
                if isinstance(member_dns, str):
                    member_dns = [member_dns]
                
                # Resolve each member DN to get sAMAccountName
                usernames = []
                for member_dn in member_dns:
                    if not member_dn:
                        continue
                    try:
                        self.logger.log_verbose(f"Resolving member: {member_dn}")
                        member = self.ldap.query(
                            search_base=member_dn,
                            search_filter='(objectClass=*)',
                            attributes=['sAMAccountName', 'objectClass']
                        )
                        if member and member[0].get('sAMAccountName'):
                            self.logger.log_verbose(f"  Resolved to: {member[0]['sAMAccountName']} (type: {member[0].get('objectClass')})")
                            usernames.append(member[0]['sAMAccountName'])
                        else:
                            self.logger.log_verbose(f"  No sAMAccountName found, using CN fallback")
                            # If we can't resolve, extract CN from DN
                            if member_dn.startswith('CN='):
                                cn = member_dn.split(',')[0][3:]
                                usernames.append(cn)
                    except Exception as e:
                        self.logger.log_verbose(f"  Error resolving member: {e}")
                        # If we can't resolve, extract CN from DN
                        if member_dn.startswith('CN='):
                            cn = member_dn.split(',')[0][3:]
                            usernames.append(cn)
                
                # Save to text file in data folder
                safe_name = group_name.replace(' ', '').lower()
                filepath = self.output_paths['data'] / f'list_{safe_name}.txt'
                
                if usernames:
                    write_lines(usernames, filepath)
                else:
                    # Write empty file if no members found
                    write_lines([], filepath)
                member_counts[group_name] = len(usernames)
                    
            except Exception as e:
                self.logger.error(f"[-] Error enumerating {group_name}: {e}")
                member_counts[group_name] = 0
        
        return member_counts
