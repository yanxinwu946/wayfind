"""Security checks module for wayfind."""

from typing import Dict
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.targets import TargetFiles, TargetScope


# Available checks registry - maps check name to (description, checker_attr, method_name)
# Ordered by execution sequence in run_all_checks()
AVAILABLE_CHECKS = {
    'bloodhound': ('BloodHound data collection', 'bloodhound_checker', 'check_bloodhound'),
    'functional-level': ('Domain functional level check', 'domain_checker', 'check_functional_level'),
    'password-policy': ('Password policy checks', 'password_checker', 'check_password_policy'),
    'kerberos-policy': ('Kerberos policy checks', 'password_checker', 'check_kerberos_policy'),
    'fgpp': ('Fine-grained password policy', 'password_checker', 'check_fine_grained_password_policy'),
    'laps': ('LAPS configuration check', 'laps_checker', 'check_laps'),
    'descriptions': ('User/computer descriptions', 'description_checker', 'check_descriptions'),
    'roasting': ('Kerberoast/AS-REP roast', 'roasting_checker', 'check_roasting'),
    'delegation': ('Delegation configuration', 'delegation_checker', 'check_delegation'),
    'user-attrs': ('User attributes check', 'user_attrs_checker', 'check_user_attributes'),
    'privileged-groups': ('Privileged groups membership', 'privileged_groups_checker', 'check_privileged_groups'),
    'outdated': ('EOL OS, inactive/legacy objects, privileged accounts, KRBTGT', 'outdated_checker', 'run_all_checks'),
    'privileged-accounts': ('Privileged account hardening (Protected Users, delegation, KRBTGT/priv password age)', 'outdated_checker', 'check_privileged_accounts'),
    'legacy': ('Legacy access (Pre-Win2000 group/computers, anonymous logon, domain join)', 'outdated_checker', 'check_legacy'),
    'adidns': ('AD-integrated DNS', 'adidns_checker', 'check_adidns'),
    'exchange': ('Exchange configuration', 'exchange_checker', 'check_exchange'),
    'adcs': ('AD Certificate Services', 'adcs_checker', 'check_adcs'),
    'trusts': ('Domain trusts', 'trust_checker', 'check_trusts'),
    'azure': ('Azure/Entra Connect and AZUREADSSOACC', 'azure_checker', 'run_all_checks'),
    'sccm': ('SCCM/MECM configuration', 'sccm_checker', 'check_sccm'),
    'ldap': ('LDAP security settings', 'ldap_checker', 'check_ldap'),
    'ldap-anonymous-bind': ('LDAP anonymous (unauthenticated) bind check', 'ldap_checker', '_check_ldap_anonymous_bind'),
    'network': ('Network enumeration', 'network_checker', 'check_network'),
    'cve': ('CVE / NTLM reflection + WebClient (netexec enum_cve)', 'network_checker', 'check_webclient_cve'),
    'smb': ('SMB security checks', 'smb_checker', 'check_smb_access'),
    'domain-admin-sessions': ('Domain admin sessions on non-DCs', 'smb_checker', 'check_domain_admin_sessions'),
    'access': ('Access checks (SMB/RDP/WINRM/MSSQL)', 'access_checker', 'check_access'),
    'sql': ('SQL Server enumeration', 'sql_checker', 'check_sql'),
    'wsus': ('WSUS HTTP configuration (MITM vulnerability)', 'wsus_checker', 'check_wsus'),
    'dc-vulns': ('DC vulnerabilities (Zerologon, NoPac)', 'dc_vulns_checker', 'check_dc_vulnerabilities'),
    'ntlm': ('NTLM security (NTLMv1 support, NTLM restrictions)', 'ntlm_checker', 'check_ntlm'),
    'gpp': ('GPP cpassword via nxc gpp_password', 'gpp_checker', 'check_gpp'),
    'shares': ('Authenticated SMB share access', 'smb_checker', 'check_dc_shares'),
    'timeroast': ('Timeroast hashes via nxc -M timeroast', 'timeroast_checker', 'check_timeroast'),
    'gmsa': ('gMSA passwords via nxc ldap --gmsa', 'gmsa_checker', 'check_gmsa'),
    'shadow': ('Shadow credentials msDS-KeyCredentialLink', 'shadow_checker', 'check_shadow'),
    'dmsa': ('dMSA / BadSuccessor via nxc -M badsuccessor', 'dmsa_checker', 'check_dmsa'),
}


class SecurityChecker:
    """Main security checker that aggregates all check categories."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, bloodhound_options: str = "all",
                 skip_bloodhound: bool = False, skip_roasting: bool = False,
                 target_scope: TargetScope = None, session=None):
        self.session = session
        if session is not None:
            domain = domain or session.target.domain
            username = username or session.target.username
            password = password if password is not None else session.target.password
            hashes = hashes or session.target.hashes
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.bloodhound_options = bloodhound_options
        self.skip_bloodhound = skip_bloodhound
        self.skip_roasting = skip_roasting
        self.target_scope = target_scope or TargetScope.from_ldap(
            ldap_conn,
            None,
            self.logger,
            extra_targets=[ldap_conn.config.server],
        )
        self.target_files = TargetFiles(output_paths['data'], self.target_scope, self.logger)
        self._instances: Dict[str, object] = {}

    def __getattr__(self, name: str):
        if name.endswith("_checker"):
            return self._checker(name)
        raise AttributeError(f"{type(self).__name__!r} has no attribute {name!r}")

    def _checker(self, attr: str):
        checker = self._instances.get(attr)
        if checker is None:
            checker = self._build(attr)
            checker.session = self.session
            self._instances[attr] = checker
        return checker

    def _build(self, attr: str):
        ldap, paths, session = self.ldap, self.output_paths, self.session
        server = ldap.config.server
        cred = dict(domain=self.domain, username=self.username,
                    password=self.password, hashes=self.hashes)
        auth = dict(server=server, domain=self.domain,
                    username=self.username, password=self.password)

        if attr == "domain_checker":
            from .domain import DomainChecker
            return DomainChecker(ldap, paths)
        if attr == "password_checker":
            from .password import PasswordChecker
            return PasswordChecker(ldap, paths, **auth)
        if attr == "laps_checker":
            from .laps import LAPSChecker
            return LAPSChecker(ldap, paths, **auth)
        if attr == "description_checker":
            from .description import DescriptionChecker
            return DescriptionChecker(ldap, paths)
        if attr == "roasting_checker":
            from .roasting import RoastingChecker
            return RoastingChecker(ldap, paths, session=session, **cred)
        if attr == "delegation_checker":
            from .delegation import DelegationChecker
            return DelegationChecker(ldap, paths)
        if attr == "user_attrs_checker":
            from .user_attrs import UserAttrsChecker
            return UserAttrsChecker(ldap, paths)
        if attr == "outdated_checker":
            from .outdated import OutdatedChecker
            return OutdatedChecker(ldap, paths)
        if attr == "adidns_checker":
            from .adidns import ADIDNSChecker
            return ADIDNSChecker(ldap, paths, domain=self.domain)
        if attr == "exchange_checker":
            from .exchange import ExchangeChecker
            return ExchangeChecker(ldap, paths)
        if attr == "adcs_checker":
            from .adcs import ADCSChecker
            return ADCSChecker(ldap, paths, server=server, session=session, **cred)
        if attr == "network_checker":
            from .network import NetworkChecker
            return NetworkChecker(
                ldap, paths, server=server, target_scope=self.target_scope,
                target_files=self.target_files, **cred,
            )
        if attr == "ldap_checker":
            from .ldap import LDAPChecker
            return LDAPChecker(ldap, paths, session=session, **auth)
        if attr == "trust_checker":
            from .trusts import TrustChecker
            return TrustChecker(ldap, paths)
        if attr == "azure_checker":
            from .azure import AzureChecker
            return AzureChecker(ldap, paths)
        if attr == "sccm_checker":
            from .sccm import SCCMChecker
            return SCCMChecker(ldap, paths)
        if attr == "bloodhound_checker":
            from .bloodhound import BloodHoundChecker
            return BloodHoundChecker(ldap, paths, session=session, **cred)
        if attr == "sql_checker":
            from .sql import SQLChecker
            return SQLChecker(
                ldap, paths, username=self.username, password=self.password,
                hashes=self.hashes, target_scope=self.target_scope,
                target_files=self.target_files,
            )
        if attr == "privileged_groups_checker":
            from .privileged_groups import PrivilegedGroupsChecker
            return PrivilegedGroupsChecker(ldap, paths)
        if attr == "smb_checker":
            from .smb import SMBChecker
            return SMBChecker(
                ldap, paths, target_files=self.target_files, **cred,
            )
        if attr == "access_checker":
            from .access import AccessChecker
            return AccessChecker(
                ldap, paths, target_files=self.target_files, **cred,
            )
        if attr == "wsus_checker":
            from .wsus import WSUSChecker
            return WSUSChecker(ldap, paths, **auth)
        if attr == "dc_vulns_checker":
            from .dc_vulns import DCVulnsChecker
            return DCVulnsChecker(ldap, paths, **cred)
        if attr == "ntlm_checker":
            from .ntlm import NTLMChecker
            return NTLMChecker(ldap, paths, **auth)
        if attr == "gpp_checker":
            from .gpp import GPPChecker
            return GPPChecker(ldap, paths, session=session, **cred)
        if attr == "timeroast_checker":
            from .timeroast import TimeroastChecker
            return TimeroastChecker(ldap, paths, session=session, **cred)
        if attr == "gmsa_checker":
            from .gmsa import GMSAChecker
            return GMSAChecker(ldap, paths, session=session, **cred)
        if attr == "shadow_checker":
            from .shadow import ShadowChecker
            return ShadowChecker(ldap, paths, session=session)
        if attr == "dmsa_checker":
            from .dmsa import DMSAChecker
            return DMSAChecker(ldap, paths, session=session, **cred)
        raise KeyError(attr)

    def run_all_checks(self, profile: str = "audit"):
        """Run checks belonging to the selected profile (default audit)."""
        from ..core.profiles import checks_for_profile, DEFAULT_PROFILE
        profile = profile or DEFAULT_PROFILE
        self.logger.info(f"[*] Running profile: {profile}")
        names = list(checks_for_profile(profile))
        if self.skip_bloodhound:
            names = [n for n in names if n != "bloodhound"]
        if self.skip_roasting:
            names = [n for n in names if n != "roasting"]
        for name in names:
            if name == "bloodhound":
                self._warn_if_bloodhound_cannot_enforce_exclusions()
            self.run_check(name, bloodhound_options=self.bloodhound_options)
        return

    def run_check(self, check_name: str, **kwargs) -> bool:
        """Run a specific check by name.

        Returns True if check was found and executed, False otherwise.
        """
        if check_name not in AVAILABLE_CHECKS:
            self.logger.error(f"[-] Unknown check: {check_name}")
            return False

        description, checker_attr, method_name = AVAILABLE_CHECKS[check_name]
        checker = self._checker(checker_attr)
        checker.CHECK = check_name

        method = getattr(checker, method_name, None)
        if not method:
            self.logger.error(f"[-] Method not found: {method_name}")
            return False

        self.logger.info(f"Running check: {check_name} - {description}")

        if check_name == 'bloodhound':
            self._warn_if_bloodhound_cannot_enforce_exclusions()
            method(kwargs.get('bloodhound_options', 'all'))
        else:
            method()
        if self.session is not None:
            self.session.mark_check(check_name)
        return True

    @staticmethod
    def list_checks() -> Dict[str, str]:
        """Return dict of available check names and descriptions."""
        return {name: info[0] for name, info in AVAILABLE_CHECKS.items()}

    def _warn_if_bloodhound_cannot_enforce_exclusions(self):
        if self.target_scope.has_non_dc_target_limits():
            self.logger.warning(
                "[!] --include-ip/--exclude-ip is not enforced for BloodHound because netexec "
                "does not expose a BloodHound target exclusion flag"
            )


__all__ = ['SecurityChecker']
