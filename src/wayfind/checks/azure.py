"""Azure AD Connect checks."""

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path

from ldap3.utils.conv import escape_filter_chars

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_file, write_lines


_CONNECT_SERVER_PATTERNS = [
    r"\brunning\s+on\s+computer\s+([A-Za-z0-9][A-Za-z0-9._-]*)",
    r"\bserver\s*:\s*([A-Za-z0-9][A-Za-z0-9._-]*)",
]
_CONNECT_SERVER_TRAILING_PUNCTUATION = ".,;:)]}"
TRUSTED_FOR_DELEGATION = 0x80000
TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
KERBEROS_ENCTYPE_RC4 = 0x4
KERBEROS_ENCTYPE_AES128 = 0x8
KERBEROS_ENCTYPE_AES256 = 0x10
KERBEROS_ENCTYPE_AES = KERBEROS_ENCTYPE_AES128 | KERBEROS_ENCTYPE_AES256


def _extract_connect_server_reference(description: str) -> Optional[str]:
    if not isinstance(description, str) or not description:
        return None

    for pattern in _CONNECT_SERVER_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(_CONNECT_SERVER_TRAILING_PUNCTUATION)

    return None


def _format_connect_server_references(references: List[Dict[str, str]]) -> str:
    sections = []
    for ref in references:
        sections.append(
            "\n".join([
                f"Microsoft Entra Connect Server Reference: {ref['server']}",
                f"AD DS Connector Account: {ref['account']}",
                f"Description: {ref['description']}",
                "",
                "Evidence scope:",
                (
                    "The LDAP account description references this server as the computer "
                    "associated with the Connect installation. This does not confirm that "
                    "the ADSync service is currently installed, running, or synchronizing "
                    "successfully."
                ),
            ])
        )

    return "\n\n".join(sections) + "\n"


def _coerce_int(value) -> Optional[int]:
    if isinstance(value, int):
        return value

    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None

    return None


def _as_list(value) -> List:
    if value in (None, '', []):
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ldap_or_filter(attribute: str, values: List) -> str:
    terms = [f"({attribute}={escape_filter_chars(str(value))})" for value in values]
    if len(terms) == 1:
        return terms[0]
    return f"(|{''.join(terms)})"


def _coerce_ad_datetime(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value

    value = _coerce_int(value)
    if value and value > 0:
        windows_epoch_diff = 116444736000000000
        unix_timestamp = (value - windows_epoch_diff) / 10000000
        return datetime.fromtimestamp(unix_timestamp, timezone.utc)

    return None


class AzureChecker:
    """Checks for Azure AD Connect configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn

    def run_all_checks(self):
        """Run all Azure/Entra-related checks."""
        self.check_azure_ad_connect()
        self.check_azure_ad_connect_server()
        self.check_azureadssoacc_security()
    
    def check_azure_ad_connect(self):
        """Check for Azure AD Connect installation and configuration."""
        self.logger.info("---Checking for Microsoft Entra Connect (Azure AD Connect)---")
        
        findings = []
        
        # Check for Azure AD Connect service accounts
        azure_accounts = self._check_azure_accounts()
        if azure_accounts:
            findings.extend(azure_accounts)
        
        # Check for MSOL accounts
        msol_accounts = self._check_msol_accounts()
        if msol_accounts:
            findings.extend(msol_accounts)
        
        # Check for AADConnect group membership
        sync_groups = self._check_sync_groups()
        if sync_groups:
            findings.extend(sync_groups)
        
        if findings:
            self.logger.info("[*] Microsoft Entra Connect indicators found - review configuration, patch level, and connector-account privileges")
            write_csv(findings, self.output_paths['checks'] / 'azure_ad_connect.txt')
        else:
            self.logger.success("[+] No Microsoft Entra Connect indicators detected by these LDAP checks")
    
    def _check_azure_accounts(self) -> List[Dict]:
        """Check for Azure AD Connect related service accounts."""
        accounts = []
        seen_accounts = set()
        
        try:
            # Search for accounts with Azure-related SPNs or names
            azure_patterns = [
                '(servicePrincipalName=*Azure*)',
                '(servicePrincipalName=*AADConnect*)',
                '(sAMAccountName=*azure*)',
                '(sAMAccountName=*AADConnect*)',
                '(sAMAccountName=*sync_*)',
                '(displayName=*Azure AD Connect*)'
            ]
            
            for pattern in azure_patterns:
                try:
                    results = self.ldap.query(
                        search_base=self.base_dn,
                        search_filter=f'(&(objectClass=user){pattern})',
                        attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf', 'description']
                    )
                    
                    for result in results:
                        username = result.get('sAMAccountName', '')
                        account_key = username.lower()
                        if account_key in seen_accounts:
                            continue

                        seen_accounts.add(account_key)
                        accounts.append({
                            'type': 'Azure-related Account',
                            'username': username,
                            'spn': result.get('servicePrincipalName', ''),
                            'description': result.get('description', '')
                        })
                        self.logger.warning(f"[!] Found Azure-related account: {username}")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking Azure accounts: {e}")
        
        return accounts
    
    def _check_msol_accounts(self) -> List[Dict]:
        """Check for MSOL (Microsoft Online) service accounts."""
        accounts = []
        
        try:
            # MSOL accounts are created by Azure AD Connect
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=MSOL_*)',
                attributes=['sAMAccountName', 'displayName', 'description', 'memberOf']
            )
            
            for result in results:
                username = result.get('sAMAccountName', '')
                accounts.append({
                    'type': 'MSOL Account',
                    'username': username,
                    'display_name': result.get('displayName', ''),
                    'description': result.get('description', '')
                })
                self.logger.warning(f"[!] Found MSOL account: {username}")
                self.logger.warning("[!] MSOL/AD DS Connector accounts may have DCSync-equivalent replication rights depending on enabled sync features - high-value target; verify ACLs")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking MSOL accounts: {e}")
        
        return accounts
    
    def _check_sync_groups(self) -> List[Dict]:
        """Check for Azure AD Connect synchronization groups."""
        groups = []
        
        sync_groups = [
            "ADSyncAdmins",
            "ADSyncOperators", 
            "ADSyncBrowse",
            "ADSyncPasswordSet",
            "Azure AD Connect Admins"
        ]
        
        try:
            for group_name in sync_groups:
                try:
                    results = self.ldap.query(
                        search_base=self.base_dn,
                        search_filter=f'(&(objectClass=group)(cn={group_name}))',
                        attributes=['cn', 'member', 'description']
                    )
                    
                    for result in results:
                        group_cn = result.get('cn', '')
                        members = result.get('member', [])
                        member_count = len(members) if isinstance(members, list) else 1 if members else 0
                        
                        groups.append({
                            'type': 'Azure Sync Group',
                            'group_name': group_cn,
                            'member_count': member_count,
                            'description': result.get('description', '')
                        })
                        self.logger.warning(f"[!] Found Azure AD Connect group: {group_cn} ({member_count} members)")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking sync groups: {e}")
        
        return groups
    
    def check_azure_ad_connect_server(self):
        """Check MSOL account descriptions for Microsoft Entra Connect server references."""
        self.logger.info("---Checking for Microsoft Entra Connect server reference---")
        
        try:
            # The MSOL account name format is usually MSOL_<installation_id>.
            # Custom installations may use an administrator-created connector account.
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=MSOL_*)',
                attributes=['sAMAccountName', 'description']
            )

            if not results:
                self.logger.info("[*] No MSOL-prefixed AD DS Connector accounts found")
                self.logger.info("[*] Custom Microsoft Entra Connect installations may use a connector account without an MSOL_ prefix")
                return

            references = []
            seen_servers = set()
            for result in results:
                description = result.get('description', '')
                server_name = _extract_connect_server_reference(description)
                if not server_name:
                    continue

                server_key = server_name.lower()
                if server_key in seen_servers:
                    continue

                seen_servers.add(server_key)
                references.append({
                    'server': server_name,
                    'account': result.get('sAMAccountName', '') or 'Unknown',
                    'description': description,
                })
                self.logger.info(f"[*] Microsoft Entra Connect server reference found: {server_name}")

            if references:
                write_file(
                    _format_connect_server_references(references),
                    self.output_paths['checks'] / 'azure_ad_connect_server.txt',
                    self.logger
                )
            else:
                self.logger.info("[*] No Microsoft Entra Connect server reference could be extracted from MSOL account descriptions")
                self.logger.info("[*] Custom Microsoft Entra Connect installations may use a connector account without an MSOL_ prefix")
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking Microsoft Entra Connect server reference: {e}")
    
    def check_azureadssoacc_security(self):
        """Check AZUREADSSOACC computer account security.
        
        Per Microsoft recommendations:
        - Kerberos delegation must be disabled on the account
        - No other account should have delegation permissions to AZUREADSSOACC
        - Kerberos decryption key should be renewed at least every 30 days
        
        Reference: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works
        """
        self.logger.info("---Checking AZUREADSSOACC security---")
        
        try:
            # Search for AZUREADSSOACC computer account
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(sAMAccountName=AZUREADSSOACC$))',
                attributes=[
                    'sAMAccountName', 'servicePrincipalName', 'userAccountControl', 'pwdLastSet',
                    'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'msDS-SupportedEncryptionTypes'
                ]
            )
            
            if not results:
                self.logger.info("[*] AZUREADSSOACC computer account not found (Seamless SSO not configured)")
                return
            
            account = results[0]
            findings = []
            account_name = account.get('sAMAccountName', 'AZUREADSSOACC$')
            
            self.logger.warning(f"[!] Found {account_name} - checking security configuration")

            self._check_azureadssoacc_uac_delegation(account, findings)
            self._check_azureadssoacc_constrained_delegation(account, findings)
            self._check_azureadssoacc_rbcd(account, findings)
            self._check_azureadssoacc_key_age(account, findings)
            self._check_azureadssoacc_encryption(account, findings)
            self._check_delegation_to_azureadssoacc(account, findings)
            
            # Write findings
            if findings:
                write_lines(
                    ["AZUREADSSOACC Security Issues", "=" * 40, ""] + findings + 
                    ["", "Reference: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works"],
                    self.output_paths['findings'] / 'azureadssoacc_security.txt'
                )
            else:
                self.logger.success("[+] No AZUREADSSOACC issues found in checked settings")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking AZUREADSSOACC security: {e}")

    def _check_azureadssoacc_uac_delegation(self, account: Dict, findings: List[str]):
        """Check delegation-related userAccountControl flags on AZUREADSSOACC."""
        uac = _coerce_int(account.get('userAccountControl')) or 0

        if uac & TRUSTED_FOR_DELEGATION:
            note(self, f"AZUREADSSOACC has unconstrained Kerberos delegation ENABLED (vulnerable!)", id="azure.unconstrained-delegation", asset="AZUREADSSOACC", severity="high")
            findings.append("CRITICAL: Unconstrained Kerberos delegation is ENABLED on AZUREADSSOACC - should be disabled")
        else:
            self.logger.success("[+] AZUREADSSOACC is not trusted for unconstrained Kerberos delegation")

        if uac & TRUSTED_TO_AUTH_FOR_DELEGATION:
            note(self, "AZUREADSSOACC is trusted to authenticate for delegation", id="azure.trusted-to-auth", asset="AZUREADSSOACC", severity="high")
            findings.append("CRITICAL: TRUSTED_TO_AUTH_FOR_DELEGATION is set on AZUREADSSOACC - delegation should be disabled")
        else:
            self.logger.success("[+] AZUREADSSOACC is not trusted to authenticate for delegation")

    def _check_azureadssoacc_constrained_delegation(self, account: Dict, findings: List[str]):
        """Check constrained delegation targets configured on AZUREADSSOACC itself."""
        allowed_to_delegate = _as_list(account.get('msDS-AllowedToDelegateTo'))
        if allowed_to_delegate:
            note(self, "AZUREADSSOACC has constrained delegation configured", id="azure.constrained-delegation", asset="AZUREADSSOACC")
            for target in allowed_to_delegate:
                findings.append(f"CRITICAL: Constrained delegation to: {target}")
        else:
            self.logger.success("[+] AZUREADSSOACC has no constrained delegation targets")

    def _check_azureadssoacc_rbcd(self, account: Dict, findings: List[str]):
        """Check resource-based constrained delegation on AZUREADSSOACC."""
        rbcd = account.get('msDS-AllowedToActOnBehalfOfOtherIdentity')
        if rbcd:
            note(self, "AZUREADSSOACC has RBCD configured - other accounts can delegate to it!", id="azure.rbcd", asset="AZUREADSSOACC", severity="high")
            findings.append("CRITICAL: RBCD is configured - other accounts have delegation permissions to AZUREADSSOACC")
        else:
            self.logger.success("[+] No RBCD configured on AZUREADSSOACC")

    def _check_azureadssoacc_key_age(self, account: Dict, findings: List[str]):
        """Check AZUREADSSOACC Kerberos decryption key age."""
        pwd_last_set = account.get('pwdLastSet')
        pwd_date = _coerce_ad_datetime(pwd_last_set)
        if pwd_date:
            now = datetime.now(pwd_date.tzinfo) if pwd_date.tzinfo else datetime.now()
            age_days = (now - pwd_date).days

            if age_days > 30:
                note(self, f"AZUREADSSOACC Kerberos key is {age_days} days old (should be renewed every 30 days)", id="azure.key-age", asset="AZUREADSSOACC", days=age_days)
                findings.append(f"WARNING: Kerberos decryption key is {age_days} days old - Microsoft recommends renewal every 30 days")
                findings.append(f"Last password change: {pwd_date.strftime('%Y-%m-%d')}")
            else:
                self.logger.success(f"[+] AZUREADSSOACC Kerberos key is {age_days} days old (within 30-day window)")
        elif pwd_last_set in (0, "0"):
            self.logger.warning("[!] AZUREADSSOACC password never set")
            findings.append("WARNING: Password appears to never have been set")
        else:
            self.logger.warning("[!] AZUREADSSOACC pwdLastSet not available or could not be parsed - Kerberos key age not checked")
            findings.append("WARNING: Kerberos key age could not be checked because pwdLastSet was not available or parseable")

    def _check_azureadssoacc_encryption(self, account: Dict, findings: List[str]):
        """Check AZUREADSSOACC Kerberos encryption types."""
        encryption_types = _coerce_int(account.get('msDS-SupportedEncryptionTypes'))
        if encryption_types is None:
            self.logger.warning("[!] AZUREADSSOACC msDS-SupportedEncryptionTypes not available - Kerberos encryption type not checked")
            return

        if encryption_types == 0:
            self.logger.warning("[!] AZUREADSSOACC Kerberos encryption type is not explicitly configured - verify AES is used")
            findings.append("WARNING: Kerberos encryption type is not explicitly configured; verify AZUREADSSOACC uses AES instead of RC4")
        elif encryption_types & KERBEROS_ENCTYPE_AES:
            if encryption_types & KERBEROS_ENCTYPE_RC4:
                self.logger.warning("[!] AZUREADSSOACC supports AES but RC4 is still allowed - consider AES-only")
                findings.append("WARNING: AZUREADSSOACC supports AES but RC4 is still allowed; Microsoft recommends AES-based encryption instead of RC4")
            else:
                self.logger.success("[+] AZUREADSSOACC uses AES Kerberos encryption types")
        else:
            note(self, "AZUREADSSOACC does not advertise AES Kerberos encryption types", id="azure.no-aes", asset="AZUREADSSOACC")
            findings.append("WARNING: AZUREADSSOACC does not advertise AES Kerberos encryption types; Microsoft recommends AES-based encryption instead of RC4")
    
    def _check_delegation_to_azureadssoacc(self, account: Dict, findings: List[str]):
        """Check if any accounts have constrained delegation to AZUREADSSOACC SPNs."""
        try:
            account_name = account.get('sAMAccountName', 'AZUREADSSOACC$')
            spns = _as_list(account.get('servicePrincipalName'))
            if not spns:
                self.logger.warning("[!] AZUREADSSOACC servicePrincipalName not available - delegation-to-account check is incomplete")
                findings.append("WARNING: Delegation to AZUREADSSOACC could not be checked because servicePrincipalName was not available")
                return

            spn_filter = _ldap_or_filter('msDS-AllowedToDelegateTo', spns)
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=spn_filter,
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass']
            )

            spn_lookup = {str(spn).lower() for spn in spns}
            delegated_accounts = []
            for result in results:
                delegate_name = result.get('sAMAccountName', 'Unknown')
                if delegate_name.lower() == account_name.lower():
                    continue

                delegated_spns = [
                    spn for spn in _as_list(result.get('msDS-AllowedToDelegateTo'))
                    if str(spn).lower() in spn_lookup
                ]
                if delegated_spns:
                    delegated_accounts.append((delegate_name, delegated_spns))

            if delegated_accounts:
                note(self, f"{len(delegated_accounts)} accounts have constrained delegation to AZUREADSSOACC SPNs", id="azure.constrained-to-ssoacc", names=[n for n, _ in delegated_accounts])
                for delegate_name, delegated_spns in delegated_accounts:
                    spn_text = ', '.join(str(spn) for spn in delegated_spns)
                    findings.append(f"CRITICAL: {delegate_name} has constrained delegation to AZUREADSSOACC SPN(s): {spn_text}")
            else:
                self.logger.success("[+] No accounts have constrained delegation to AZUREADSSOACC SPNs")
                
        except Exception as e:
            self.logger.debug(f"Error checking delegation to AZUREADSSOACC: {e}")
