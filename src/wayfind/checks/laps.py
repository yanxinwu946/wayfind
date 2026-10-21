"""LAPS security checks."""

import io
import struct
from typing import Dict, List, Tuple, Optional
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_file, write_lines, write_csv
from ..utils.registry_pol import parse_pol_file


class LAPSChecker:
    """Checks related to LAPS deployment and configuration."""
    
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
    
    def check_laps(self):
        """Check LAPS deployment and configuration."""
        self.logger.info("---Checking if LAPS is deployed---")
        
        try:
            gpos = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter='(displayName=*LAPS*)',
                attributes=['displayName', 'gPCFileSysPath']
            )
            
            gpo_file = self.output_paths['data'] / 'laps_gpo.txt'
            
            if gpos:
                count = len(gpos)
                self.logger.success(f"[+] There are {count} GPOs with LAPS in their name")
                write_csv(gpos, gpo_file)
                
                for gpo in gpos:
                    gpo_dn = gpo.get('dn', '')
                    if 'CN={' in gpo_dn:
                        guid = gpo_dn.split('CN={')[1].split('}')[0]
                        
                        linked_ous = self.ldap.query(
                            search_base=self.base_dn,
                            search_filter=f'(gPLink=*{guid}*)',
                            attributes=['name', 'distinguishedName']
                        )
                        
                        if linked_ous:
                            self.logger.success(f"[+] GPO {gpo.get('displayName')} is linked to {len(linked_ous)} OU(s)")
                            ou_file = self.output_paths['checks'] / 'laps_gpo_ou.txt'
                            ou_data = [f"{gpo.get('displayName')}:"]
                            for ou in linked_ous:
                                ou_data.append(f"  - {ou.get('name', 'unknown')}: {ou.get('distinguishedName', '')}")
                            write_lines(ou_data, ou_file)
                        else:
                            note(self, f"GPO {gpo.get('displayName')} isn't linked to any OU", id="laps.gpo-unlinked", asset=str(gpo.get("displayName") or ""))
                
                self._check_laps_policy(gpos)
            else:
                note(self, "There is no GPO with LAPS in their name", id="laps.no-gpo")
            
            laps_file = self.output_paths['data'] / 'laps_computers_enabled.txt'
            
            # Check if LAPS schema is installed by probing for the attribute
            # in the schema partition, avoiding a noisy LDAP error on the main query
            laps_types = self._check_laps_schema()
            
            if not laps_types['legacy'] and not laps_types['windows']:
                note(self, "LAPS schema not installed (neither legacy nor Windows LAPS attributes found)", id="laps.schema-missing")
                findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                write_file("LAPS SCHEMA NOT INSTALLED", findings_file, self.logger)
            else:
                # Build attribute list based on which LAPS schema is installed
                # Only request attributes that exist to avoid LDAP errors
                attrs = ['sAMAccountName', 'distinguishedName',
                         'lastLogon', 'whenChanged', 'operatingSystem']
                
                if laps_types['legacy']:
                    attrs.extend(['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'])
                if laps_types['windows']:
                    attrs.extend(['msLAPS-PasswordExpirationTime'])
                
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(&(objectClass=computer)(operatingSystem=*Windows*))',
                    attributes=attrs
                )
                
                # Detect LAPS deployment via expiration time attributes (readable by any user)
                laps_computers = [
                    c for c in all_computers
                    if c.get('ms-Mcs-AdmPwdExpirationTime') or c.get('msLAPS-PasswordExpirationTime')
                ]
                no_laps = [
                    c for c in all_computers
                    if not c.get('ms-Mcs-AdmPwdExpirationTime') and not c.get('msLAPS-PasswordExpirationTime')
                ]
                
                if laps_computers:
                    count = len(laps_computers)
                    self.logger.success(f"[+] There are {count} systems where LAPS is enabled")
                    write_lines([c.get('sAMAccountName', '') for c in laps_computers if c.get('sAMAccountName')], laps_file)
                    
                    # Check if the current user can read LAPS passwords (DA/delegated only)
                    self.logger.info("---Checking if current user has permissions to read LAPS passwords---")
                    readable_passwords = [c for c in laps_computers if c.get('ms-Mcs-AdmPwd')]
                    if readable_passwords:
                        note(self, "The current user could read LAPS passwords", id="laps.readable", severity="high")
                        pwd_file = self.output_paths['findings'] / 'laps_passwords_readable.txt'
                        pwd_data = [f"{c.get('sAMAccountName', 'unknown')}: {c.get('ms-Mcs-AdmPwd', '')}" for c in readable_passwords]
                        write_lines(pwd_data, pwd_file)
                    else:
                        self.logger.success("[+] The current user couldn't read any LAPS passwords")
                    
                    self.logger.info("---Checking for computers without LAPS---")
                    if no_laps:
                        no_laps_file = self.output_paths['findings'] / 'laps_computers_disabled.txt'
                        note(self, f"There are {len(no_laps)} Windows systems where LAPS isn't enabled", id="laps.not-enabled", names=sams(no_laps, "dNSHostName", "sAMAccountName"))
                        write_lines([c.get('sAMAccountName', '') for c in no_laps if c.get('sAMAccountName')], no_laps_file)
                    else:
                        self.logger.success("[+] All Windows systems have LAPS enabled")
                else:
                    note(self, "There are no systems where LAPS is enabled", id="laps.none-enabled")
                    findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                    write_file("LAPS NOT ENABLED ON ANY COMPUTER", findings_file, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking LAPS: {e}")
    
    def _check_laps_policy(self, gpos: List[Dict]):
        """Check LAPS policy settings from GPO Registry.pol files."""
        self.logger.info("---Checking the LAPS policy for each GPO---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] LAPS policy check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            conn = SMBConnection(self.server, self.server)
            conn.login(self.username, self.password, self.domain)
            
            for gpo in gpos:
                gpo_name = gpo.get('displayName', 'Unknown')
                gpc_path = gpo.get('gPCFileSysPath', '')
                
                if not gpc_path:
                    self.logger.warning(f"[!] No gPCFileSysPath for GPO {gpo_name}")
                    continue
                
                # gPCFileSysPath format: \\domain.com\SysVol\domain.com\Policies\{GUID}
                # We need: domain.com/Policies/{GUID}/Machine/Registry.pol
                normalized = gpc_path.replace('\\', '/')
                # Remove leading slashes
                while normalized.startswith('/'):
                    normalized = normalized[1:]
                # Split: domain.com/SysVol/domain.com/Policies/{GUID}
                parts = normalized.split('/')
                # Find 'SysVol' or 'SYSVOL' index and take everything after it
                sysvol_idx = -1
                for i, part in enumerate(parts):
                    if part.lower() == 'sysvol':
                        sysvol_idx = i
                        break
                
                if sysvol_idx == -1 or sysvol_idx + 1 >= len(parts):
                    self.logger.warning(f"[!] Could not parse gPCFileSysPath for {gpo_name}: {gpc_path}")
                    continue
                
                # Join parts after SYSVOL: domain.com/Policies/{GUID}
                share_path = '/'.join(parts[sysvol_idx + 1:]) + '/Machine/Registry.pol'
                
                try:
                    content_buffer = io.BytesIO()
                    conn.getFile('SYSVOL', share_path, content_buffer.write)
                    content = content_buffer.getvalue()
                    
                    if content:
                        self._analyze_laps_policy(gpo_name, content)
                except Exception as e:
                    self.logger.warning(f"[!] Could not read Registry.pol for {gpo_name}: {e}")
            
            conn.logoff()
            
        except Exception as e:
            self.logger.error(f"[-] Error connecting to SYSVOL: {e}")

    def _analyze_laps_policy(self, gpo_name: str, content: bytes):
        """Analyze LAPS policy settings from parsed Registry.pol content."""
        entries = parse_pol_file(content)
        
        if not entries:
            self.logger.warning(f"[!] Could not parse Registry.pol for {gpo_name}")
            return
        
        laps_settings = {}
        for key, value_name, reg_type, data_size, data in entries:
            if 'LAPS' in key or 'AdmPwd' in key:
                if reg_type == 4:  # REG_DWORD
                    laps_settings[value_name] = struct.unpack('<I', data)[0] if data_size >= 4 else 0
                elif reg_type == 1:  # REG_SZ
                    laps_settings[value_name] = data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                else:
                    laps_settings[value_name] = data
        
        if not laps_settings:
            self.logger.info(f"[*] No LAPS-specific settings found in {gpo_name}")
            return
        
        self.logger.info(f"[+] Found LAPS policy settings for {gpo_name}")
        
        policy_lines = [f"LAPS Policy: {gpo_name}", ""]
        findings = []
        
        admin_account = laps_settings.get('AdminAccountName')
        if admin_account is None or admin_account == '':
            self.logger.warning("[!] The LAPS local admin user is the default administrator account")
            findings.append("AdminAccountName: Using default administrator account")
            policy_lines.append("AdminAccountName: <default administrator>")
        else:
            self.logger.success(f"[+] The LAPS local admin user is not the default: {admin_account}")
            policy_lines.append(f"AdminAccountName: {admin_account}")
        
        pwd_complexity = laps_settings.get('PasswordComplexity')
        if pwd_complexity is not None:
            policy_lines.append(f"PasswordComplexity: {pwd_complexity}")
            if pwd_complexity == 4:
                self.logger.success("[+] The password complexity is 4")
            else:
                note(self, f"The password complexity is {pwd_complexity} (should be 4)", id="laps.complexity", value=pwd_complexity)
                findings.append(f"PasswordComplexity: {pwd_complexity} (recommended: 4)")
        
        pwd_length = laps_settings.get('PasswordLength')
        if pwd_length is not None:
            policy_lines.append(f"PasswordLength: {pwd_length}")
            if pwd_length == 14:
                self.logger.warning("[!] The password length is the default 14")
                findings.append("PasswordLength: 14 (default, consider increasing)")
            elif pwd_length < 14:
                note(self, f"The password length is {pwd_length} (less than 14)", id="laps.length", value=pwd_length)
                findings.append(f"PasswordLength: {pwd_length} (should be at least 14)")
            else:
                self.logger.success(f"[+] The password length is {pwd_length} (longer than default)")
        
        pwd_age = laps_settings.get('PasswordAgeDays')
        if pwd_age is not None:
            policy_lines.append(f"PasswordAgeDays: {pwd_age}")
            if pwd_age == 30:
                self.logger.warning("[!] The password age days is the default 30")
            elif pwd_age < 30:
                self.logger.success(f"[+] The password age days is {pwd_age} (less than 30)")
            else:
                note(self, f"The password age days is {pwd_age} (more than 30)", id="laps.age-days", value=pwd_age)
                findings.append(f"PasswordAgeDays: {pwd_age} (should be 30 or less)")
        
        pwd_expiration = laps_settings.get('PwdExpirationProtectionEnabled')
        if pwd_expiration is not None:
            policy_lines.append(f"PwdExpirationProtectionEnabled: {pwd_expiration}")
            if pwd_expiration == 1:
                self.logger.success("[+] PwdExpirationProtectionEnabled is enabled")
            else:
                note(self, "PwdExpirationProtectionEnabled is disabled or not configured", id="laps.expiration-protection-disabled")
                findings.append("PwdExpirationProtectionEnabled: Disabled (should be enabled)")
        else:
            note(self, "PwdExpirationProtectionEnabled is not configured (defaults to disabled)", id="laps.expiration-protection-unconfigured")
            findings.append("PwdExpirationProtectionEnabled: Not configured (defaults to disabled)")
        
        admpwd_enabled = laps_settings.get('AdmPwdEnabled')
        if admpwd_enabled is not None:
            policy_lines.append(f"AdmPwdEnabled: {admpwd_enabled}")
            if admpwd_enabled == 1:
                self.logger.success("[+] The LAPS policy is enabled")
            else:
                note(self, "The LAPS policy is disabled", id="laps.policy-disabled")
                findings.append("AdmPwdEnabled: Disabled (LAPS policy not active)")
        
        policy_lines.append("")
        if findings:
            policy_lines.append("Findings:")
            policy_lines.extend([f"  - {f}" for f in findings])
        else:
            policy_lines.append("Findings: None - LAPS policy is secure")
        
        policy_lines.append("")
        policy_lines.append("All Settings:")
        for key, value in laps_settings.items():
            policy_lines.append(f"  {key}: {value}")
        
        # Only report as a finding if the policy is actually weak
        if findings:
            filepath = self.output_paths['findings'] / 'laps_policy.txt'
        else:
            filepath = self.output_paths['checks'] / 'laps_policy.txt'
        write_file('\n'.join(policy_lines), filepath, self.logger)
    
    def _check_laps_schema(self) -> dict:
        """Check which LAPS schema extensions are installed.
        
        Probes the AD schema for ms-Mcs-AdmPwd (legacy LAPS) and
        msLAPS-Password (Windows LAPS) attribute definitions.
        
        Returns:
            Dict with 'legacy' and 'windows' booleans.
        """
        result = {'legacy': False, 'windows': False}
        try:
            config_dn = f"CN=Schema,CN=Configuration,{self.base_dn}"
            try:
                config_dn = f"CN=Schema,{self.ldap.get_config_dn()}"
            except Exception:
                pass
            
            results = self.ldap.query(
                search_base=config_dn,
                search_filter='(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))',
                attributes=['lDAPDisplayName']
            )
            for r in results:
                attr_name = r.get('lDAPDisplayName', '')
                if attr_name == 'ms-Mcs-AdmPwd':
                    result['legacy'] = True
                elif attr_name == 'msLAPS-Password':
                    result['windows'] = True
        except Exception:
            pass
        return result
