"""Phase 6 security checks - Outdated computers, inactive objects, privileged objects, domain join, Pre-Windows 2000."""

import re
from typing import Dict, List
from pathlib import Path
from datetime import date, datetime, timedelta

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..config import (
    EOL_OS_PATTERNS,
    WIN10_EOS_VERSIONS,
    WIN10_LONG_TERM_SUPPORT,
    WIN10_VERSION_NAMES,
    WIN11_EOS_VERSIONS,
    WIN11_VERSION_NAMES,
)
from ..utils.output import write_csv, write_lines


class OutdatedChecker:
    """Checks for outdated operating systems and inactive objects."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def run_all_checks(self):
        """Run all Phase 6 checks."""
        self._check_outdated_computers()
        self._check_inactive_objects()
        self._check_privileged_objects()
        self._check_privileged_old_passwords()
        self._check_krbtgt_password()
        self._check_domain_join()
        self._check_prewindows2000_group()
        self._check_anonymous_logon_groups()
        self._check_prewindows2000_computers()

    def check_privileged_accounts(self):
        """Privileged account hardening: Protected Users / delegation flags,
        privileged password age, and KRBTGT password age."""
        self._check_privileged_objects()
        self._check_privileged_old_passwords()
        self._check_krbtgt_password()

    def check_legacy(self):
        """Legacy access & misconfiguration: Pre-Windows 2000 group/computers,
        anonymous logon group membership, and who can join machines to the domain."""
        self._check_prewindows2000_group()
        self._check_prewindows2000_computers()
        self._check_anonymous_logon_groups()
        self._check_domain_join()

    @staticmethod
    def _extract_os_build(version: str) -> str:
        """Extract Windows build from AD formats like '10.0 (19045)' or '10.0.19045'."""
        if not version:
            return ''

        parenthesized = re.search(r'\((\d{5})\)', version)
        if parenthesized:
            return parenthesized.group(1)

        parts = version.split('.')
        if len(parts) > 2 and parts[2].isdigit():
            return parts[2]

        standalone = re.search(r'\b(\d{5})\b', version)
        return standalone.group(1) if standalone else ''

    @staticmethod
    def _has_supported_win10_long_term_lifecycle(os: str, build: str) -> bool:
        os_lower = os.lower()
        for release in WIN10_LONG_TERM_SUPPORT:
            if release['build'] != build:
                continue
            if not any(marker.lower() in os_lower for marker in release['markers']):
                continue
            return date.today() <= date.fromisoformat(release['end_date'])
        return False

    def _check_outdated_computers(self):
        """Check for EOL operating systems in AD."""
        self.logger.info("---Checking for EOL operating systems---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName', 'operatingSystem', 'operatingSystemVersion', 'lastLogon']
            )
            
            if not computers:
                self.logger.info("[*] No computers found")
                return
            
            # Check EOL OS
            eol_computers = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                if any(pattern in os for pattern in EOL_OS_PATTERNS):
                    eol_computers.append(comp)
            
            if eol_computers:
                note(self, f"{len(eol_computers)} computers with EOL operating systems", id="outdated.eol-os", names=sams(eol_computers, "dNSHostName", "sAMAccountName"))
                write_csv(eol_computers, self.output_paths['findings'] / 'computers_OS_EOL.txt')
            else:
                self.logger.success("[+] No EOL operating systems found")
            
            # Check Windows 10 End of Service
            win10_eos = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                version = comp.get('operatingSystemVersion') or ''
                if 'Windows 10' in os:
                    build = self._extract_os_build(version)
                    if build in WIN10_EOS_VERSIONS and not self._has_supported_win10_long_term_lifecycle(os, build):
                        readable = WIN10_VERSION_NAMES.get(build, build)
                        comp['operatingSystemVersion'] = version.replace(build, readable)
                        win10_eos.append(comp)
            
            if win10_eos:
                note(self, f"{len(win10_eos)} Windows 10 computers with End of Service versions", id="outdated.win10-eos", names=sams(win10_eos, "dNSHostName", "sAMAccountName"))
                write_csv(win10_eos, self.output_paths['findings'] / 'computers_W10_EOS.txt')
            else:
                self.logger.success("[+] No Windows 10 End of Service versions found")
            
            # Check Windows 11 End of Service
            win11_eos = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                version = comp.get('operatingSystemVersion') or ''
                if 'Windows 11' in os:
                    build = self._extract_os_build(version)
                    if build in WIN11_EOS_VERSIONS:
                        readable = WIN11_VERSION_NAMES.get(build, build)
                        comp['operatingSystemVersion'] = version.replace(build, readable)
                        win11_eos.append(comp)
            
            if win11_eos:
                note(self, f"{len(win11_eos)} Windows 11 computers with End of Service versions", id="outdated.win11-eos", names=sams(win11_eos, "dNSHostName", "sAMAccountName"))
                write_csv(win11_eos, self.output_paths['findings'] / 'computers_W11_EOS.txt')
            else:
                self.logger.success("[+] No Windows 11 End of Service versions found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking outdated computers: {e}")
    
    def _check_inactive_objects(self):
        """Check for inactive computers and users (365+ days)."""
        self.logger.info("---Checking for inactive objects---")
        
        try:
            # LDAP expects generalized time format without timezone for comparisons
            cutoff_date = (datetime.now() - timedelta(days=365))
            # Convert to filetime or use a simpler approach - query all and filter in Python
            
            # Inactive computers (no logon AND pwdlastset > 365 days)
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName', 'pwdLastSet', 'lastLogon']
            )
            
            # Filter in Python
            inactive_computers = []
            for comp in computers:
                last_logon = comp.get('lastLogon')
                pwd_last_set = comp.get('pwdLastSet')
                # Check if either is old enough
                if self._is_inactive(last_logon, pwd_last_set, 365):
                    inactive_computers.append(comp)
            
            if inactive_computers:
                note(self, f"{len(inactive_computers)} computers inactive > 365 days", id="outdated.computers-inactive", names=sams(inactive_computers, "dNSHostName", "sAMAccountName"))
                write_csv(inactive_computers, self.output_paths['findings'] / 'computers_inactive.txt')
            else:
                self.logger.success("[+] No inactive computers found")
            
            # Inactive users (no logon AND pwdlastset > 365 days, not disabled)
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'pwdLastSet', 'lastLogon']
            )
            
            # Filter in Python
            inactive_users = []
            for user in users:
                last_logon = user.get('lastLogon')
                pwd_last_set = user.get('pwdLastSet')
                if self._is_inactive(last_logon, pwd_last_set, 365):
                    inactive_users.append(user)
            
            if inactive_users:
                note(self, f"{len(inactive_users)} users inactive > 365 days", id="outdated.users-inactive", names=sams(inactive_users))
                write_csv(inactive_users, self.output_paths['findings'] / 'users_inactive.txt')
            else:
                self.logger.success("[+] No inactive users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking inactive objects: {e}")
    
    def _check_privileged_objects(self):
        """Check privileged users for security settings."""
        self.logger.info("---Checking privileged objects security---")
        
        try:
            # Get users with adminCount=1
            privileged = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(adminCount=1))',
                attributes=['sAMAccountName', 'memberOf', 'userAccountControl', 'pwdLastSet']
            )
            
            if not privileged:
                self.logger.info("[*] No privileged users found")
                return
            
            # Check if privileged users are in Protected Users group
            not_protected = []
            for user in privileged:
                member_of = user.get('memberOf') or []
                if isinstance(member_of, str):
                    member_of = [member_of]
                if not any('CN=Protected Users' in g for g in member_of):
                    not_protected.append(user)
            
            if not_protected:
                note(self, f"{len(not_protected)} privileged users NOT in Protected Users group", id="outdated.privileged-not-protected-users", names=sams(not_protected))
                names = [u.get('sAMAccountName', '') for u in not_protected if u.get('sAMAccountName')]
                write_lines(names, self.output_paths['findings'] / 'administrators_notin_protectedusersgroup.txt')
            else:
                self.logger.success("[+] All privileged users are in Protected Users group")
            
            # Check NOT_DELEGATED flag (0x100000 = 1048576)
            not_delegated = []
            for user in privileged:
                uac = user.get('userAccountControl', 0)
                if isinstance(uac, str):
                    uac = int(uac)
                if not (uac & 1048576):
                    not_delegated.append(user)
            
            if not_delegated:
                note(self, f"{len(not_delegated)} privileged users without NOT_DELEGATED flag", id="outdated.privileged-not-delegated", names=sams(not_delegated))
                names = [u.get('sAMAccountName', '') for u in not_delegated if u.get('sAMAccountName')]
                write_lines(names, self.output_paths['findings'] / 'administrators_delegation_flag.txt')
            else:
                self.logger.success("[+] All privileged users have NOT_DELEGATED flag")
            
            # Check computers in high privileged groups
            high_priv_groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=group)(adminCount=1)(!(cn=Cert Publishers)))',
                attributes=['distinguishedName', 'cn']
            )
            
            if high_priv_groups is not None and len(high_priv_groups) > 0:
                # Get DNs of high privileged groups
                high_priv_dns = [g['distinguishedName'] for g in high_priv_groups if g.get('distinguishedName')]
                
                # Query computers and check memberOf
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(objectClass=computer)',
                    attributes=['sAMAccountName', 'memberOf']
                )
                
                computers_in_groups = []
                for comp in (all_computers or []):
                    member_of = comp.get('memberOf') or []
                    if isinstance(member_of, str):
                        member_of = [member_of]
                    if any(g in high_priv_dns for g in member_of):
                        computers_in_groups.append(comp)
                
                if computers_in_groups:
                    note(self, f"{len(computers_in_groups)} computers in high privileged groups", id="outdated.computers-in-privileged-groups", names=sams(computers_in_groups, "dNSHostName", "sAMAccountName"))
                    write_csv(computers_in_groups, self.output_paths['findings'] / 'computers_part_of_highprivilegedgroups.txt')
                else:
                    self.logger.success("[+] No computers in high privileged groups")
            
        except Exception as e:
            self.logger.error(f"[-] Error checking privileged objects: {e}")
    
    def _check_privileged_old_passwords(self):
        """Check if privileged users have passwords older than 180 days."""
        self.logger.info("---Checking if privileged users have password older than 180 days---")
        
        try:
            privileged = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'pwdLastSet']
            )
            
            if not privileged:
                self.logger.info("[*] No privileged users found")
                return
            
            old_password_priv = []
            for user in privileged:
                pwd_last_set = user.get('pwdLastSet')
                if pwd_last_set and pwd_last_set != '0':
                    if self._is_pwd_old(pwd_last_set, 180):
                        old_password_priv.append(user)
            
            if old_password_priv:
                note(self, f"{len(old_password_priv)} privileged users with password older than 180 days", id="outdated.privileged-old-password", names=sams(old_password_priv))
                # Include pwdLastSet in output
                lines = []
                for u in old_password_priv:
                    name = u.get('sAMAccountName', 'unknown')
                    pwd = u.get('pwdLastSet')
                    if isinstance(pwd, datetime):
                        pwd_str = pwd.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        pwd_str = str(pwd) if pwd else 'unknown'
                    lines.append(f"{name} - pwdLastSet: {pwd_str}")
                write_lines(lines, self.output_paths['findings'] / 'oldpassword_privilegedusers.txt')
            else:
                self.logger.success("[+] No privileged users with password older than 180 days")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking privileged user passwords: {e}")
    
    def _check_krbtgt_password(self):
        """Check if KRBTGT account has password older than 180 days."""
        self.logger.info("---Checking if KRBTGT has password older than 180 days---")
        
        try:
            krbtgt = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=krbtgt)',
                attributes=['sAMAccountName', 'pwdLastSet']
            )
            
            if krbtgt:
                krbtgt_pwd = krbtgt[0].get('pwdLastSet')
                if krbtgt_pwd and krbtgt_pwd != '0':
                    if self._is_pwd_old(krbtgt_pwd, 180):
                        note(self, "KRBTGT account has password older than 180 days", id="outdated.krbtgt-old-password", asset="krbtgt")
                        # Format the pwdLastSet date for output (remove microseconds and timezone)
                        if isinstance(krbtgt_pwd, datetime):
                            pwd_str = krbtgt_pwd.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            pwd_str = str(krbtgt_pwd)
                        write_lines([f"pwdLastSet: {pwd_str}"], self.output_paths['findings'] / 'oldpassword_krbtgt.txt')
                    else:
                        self.logger.success("[+] KRBTGT password is not older than 180 days")
                else:
                    self.logger.info("[*] KRBTGT pwdLastSet not available")
            else:
                self.logger.info("[*] KRBTGT account not found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking KRBTGT password: {e}")
    
    def _check_domain_join(self):
        """Check who can join computers to domain."""
        self.logger.info("---Checking domain join permissions---")
        
        try:
            # Get domain policy - check ms-DS-MachineAccountQuota
            domain = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=domain)',
                attributes=['ms-DS-MachineAccountQuota']
            )
            
            if domain:
                quota = domain[0].get('ms-DS-MachineAccountQuota', '10')  # Default is 10
                if quota is None or quota == '':
                    quota = 10
                else:
                    quota = int(quota) if str(quota).isdigit() else 10
                
                if quota == 0:
                    self.logger.success("[+] Users cannot join computers to domain (quota = 0)")
                elif quota >= 1:
                    note(self, f"Authenticated users can join {quota} computers to domain", id="outdated.machine-quota", quota=quota)
                    write_lines([f"MachineAccountQuota: {quota}"], self.output_paths['findings'] / 'authenticated_users_can_join_domain.txt')
                else:
                    self.logger.info(f"[*] MachineAccountQuota: {quota}")
            
        except Exception as e:
            self.logger.error(f"[-] Error checking domain join permissions: {e}")
    
    def _check_prewindows2000_group(self):
        """Check Pre-Windows 2000 Compatible Access group."""
        self.logger.info("---Checking Pre-Windows 2000 Compatible Access---")
        
        try:
            # Find the group
            groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(cn=Pre-Windows 2000 Compatible Access)',
                attributes=['distinguishedName', 'member']
            )
            
            if not groups:
                self.logger.info("[*] Pre-Windows 2000 Compatible Access group not found")
                return
            
            group = groups[0]
            members = group.get('member', [])
            if isinstance(members, str):
                members = [members]
            
            write_csv([{'member': m} for m in members], self.output_paths['data'] / 'Pre-Windows_2000_Compatible_Access_Members.txt')
            
            # Check for Authenticated Users (S-1-5-11)
            authenticated_users = [m for m in members if 'S-1-5-11' in m or 'Authenticated Users' in m]
            
            if authenticated_users:
                note(self, "Authenticated Users is member of Pre-Windows 2000 Compatible Access", id="outdated.pre-win2000")
                write_csv([{'member': m} for m in authenticated_users], self.output_paths['findings'] / 'Pre-Windows_2000_Compatible_Access_Authenticated_users.txt')
            else:
                self.logger.success("[+] Authenticated Users NOT in Pre-Windows 2000 Compatible Access")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Pre-Windows 2000 group: {e}")
    
    def _check_anonymous_logon_groups(self):
        """Check if ANONYMOUS LOGON (S-1-5-7) is a member of any group."""
        self.logger.info("---Checking ANONYMOUS LOGON group memberships---")
        
        try:
            groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=group)',
                attributes=['cn', 'distinguishedName', 'member']
            )
            
            if not groups:
                self.logger.info("[*] No groups found")
                return
            
            findings = []
            
            for group in groups:
                members = group.get('member') or []
                if isinstance(members, str):
                    members = [members]
                
                for member in members:
                    if 'S-1-5-7' in member or 'ANONYMOUS LOGON' in member.upper():
                        group_name = group.get('cn', group.get('distinguishedName', 'unknown'))
                        note(self, f"ANONYMOUS LOGON is member of '{group_name}'", id="outdated.anonymous-logon-member", asset=str(group_name))
                        findings.append(f"{group_name}: ANONYMOUS LOGON (S-1-5-7)")
                        break
            
            if findings:
                write_lines(findings, self.output_paths['findings'] / 'anonymous_logon_group_membership.txt')
            else:
                self.logger.success("[+] ANONYMOUS LOGON is not a member of any group")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ANONYMOUS LOGON group membership: {e}")
    
    def _check_prewindows2000_computers(self):
        """Generate lists for Pre-Windows 2000 computer password spraying."""
        self.logger.info("---Checking Pre-Windows 2000 computers---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName']
            )
            
            if not computers:
                self.logger.info("[*] No computers found")
                return
            
            # Extract computer names (remove $)
            names = [c.get('sAMAccountName', '').rstrip('$') for c in computers if c.get('sAMAccountName')]
            write_lines(names, self.output_paths['checks'] / 'list_computers.txt')
            
            # Generate potential passwords (first 14 chars, lowercase)
            passwords = []
            for name in names:
                name_lower = name.lower()
                if len(name_lower) > 14:
                    passwords.append(name_lower[:14])
                else:
                    passwords.append(name_lower)
            
            write_lines(passwords, self.output_paths['checks'] / 'list_computers_Pre-Windows2000Computers_pass.txt')
            
            self.logger.info(f"[*] Generated {len(passwords)} potential passwords for Pre-Windows 2000 computer spraying")
            self.logger.info("[*] Check for STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT error")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Pre-Windows 2000 computers: {e}")
    
    def _is_inactive(self, last_logon, pwd_last_set, days=365):
        """Check if an account is inactive based on lastLogon and pwdLastSet.
        
        LDAP timestamps are in 100-nanosecond intervals since Jan 1, 1601.
        ldap3 may return datetime objects directly (timezone-aware UTC).
        A value of '0' or missing means never set/logged on.
        """
        try:
            import re
            from datetime import datetime, timezone
            
            # Use timezone-aware datetime for comparison
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            
            # ldap3 returns datetime objects for these attributes (timezone-aware)
            if isinstance(last_logon, datetime):
                if last_logon.tzinfo is None:
                    last_logon = last_logon.replace(tzinfo=timezone.utc)
                last_logon_dt = last_logon
            else:
                # Convert to int if string
                if last_logon and isinstance(last_logon, str):
                    last_logon = re.sub(r'[^0-9]', '', last_logon)[:18]
                    last_logon = int(last_logon) if last_logon else 0
                # Convert LDAP timestamp to datetime
                if last_logon and last_logon != 0:
                    ldap_epoch = datetime(1601, 1, 1)
                    last_logon_dt = ldap_epoch + timedelta(seconds=last_logon / 10000000)
                else:
                    last_logon_dt = None
            
            if isinstance(pwd_last_set, datetime):
                if pwd_last_set.tzinfo is None:
                    pwd_last_set = pwd_last_set.replace(tzinfo=timezone.utc)
                pwd_last_set_dt = pwd_last_set
            else:
                if pwd_last_set and isinstance(pwd_last_set, str):
                    pwd_last_set = re.sub(r'[^0-9]', '', pwd_last_set)[:18]
                    pwd_last_set = int(pwd_last_set) if pwd_last_set else 0
                if pwd_last_set and pwd_last_set != 0:
                    ldap_epoch = datetime(1601, 1, 1)
                    pwd_last_set_dt = ldap_epoch + timedelta(seconds=pwd_last_set / 10000000)
                else:
                    pwd_last_set_dt = None
            
            # If both are None, can't determine
            if not last_logon_dt and not pwd_last_set_dt:
                return False
            
            # Check if both are older than cutoff
            if last_logon_dt and pwd_last_set_dt:
                return last_logon_dt < cutoff and pwd_last_set_dt < cutoff
            elif last_logon_dt:
                return last_logon_dt < cutoff
            elif pwd_last_set_dt:
                return pwd_last_set_dt < cutoff
            
            return False
        except Exception:
            return False
    
    def _is_pwd_old(self, pwd_last_set, days=180):
        """Check if a password is older than specified days.
        
        LDAP timestamps are in 100-nanosecond intervals since Jan 1, 1601.
        ldap3 may return datetime objects directly (timezone-aware UTC).
        """
        try:
            import re
            from datetime import datetime, timezone
            
            # Use timezone-aware datetime for comparison (ldap3 returns UTC)
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            
            # ldap3 returns datetime objects for pwdLastSet (timezone-aware)
            if isinstance(pwd_last_set, datetime):
                # Make sure both are comparable
                if pwd_last_set.tzinfo is None:
                    pwd_last_set = pwd_last_set.replace(tzinfo=timezone.utc)
                return pwd_last_set < cutoff
            
            # Convert to int if string
            if pwd_last_set and isinstance(pwd_last_set, str):
                pwd_last_set = re.sub(r'[^0-9]', '', pwd_last_set)[:18]
                pwd_last_set = int(pwd_last_set) if pwd_last_set else 0
            
            if not pwd_last_set or pwd_last_set == 0:
                return False
            
            # LDAP epoch is 1601-01-01, convert to datetime
            ldap_epoch = datetime(1601, 1, 1)
            
            # Convert LDAP timestamp (100-nanosecond intervals) to datetime
            seconds = pwd_last_set / 10000000
            pwd_last_set_dt = ldap_epoch + timedelta(seconds=seconds)
            
            return pwd_last_set_dt < cutoff
        except Exception:
            return False
