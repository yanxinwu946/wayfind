"""SQL Server enumeration and checks using netexec."""

import subprocess
from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.netexec import report_netexec_failure
from ..utils.targets import TargetFiles, TargetScope
from ..utils.output import write_lines


class SQLChecker:
    """SQL Server enumeration via netexec."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 username: str = None, password: str = None, hashes: str = None,
                 target_scope: TargetScope = None,
                 target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_scope = target_scope or TargetScope()
        self.target_files = target_files or TargetFiles(output_paths['data'], self.target_scope, self.logger)
    
    def check_sql(self):
        """Run all SQL checks."""
        self.logger.info("---Checking SQL enumeration---")
        
        # Find computers with MSSQL SPN
        mssql_hosts = self._get_mssql_hosts()
        if not mssql_hosts:
            self.logger.info("[*] No MSSQL servers found via SPN")
            return
        
        self.logger.info(f"[*] Found {len(mssql_hosts)} MSSQL servers")
        self.logger.debug(f"[*] MSSQL hosts: {mssql_hosts}")
        
        # Check each MSSQL host
        linked_servers = []
        impersonate_privs = []
        encryption_disabled = []
        
        # Collect all outputs for saving
        all_outputs = []
        
        for host in mssql_hosts:
            # Check linked servers - show output and parse
            links_output = self._run_netexec_module(host, 'enum_links')
            if links_output:
                self.logger.debug(links_output)  # Raw netexec output (debug only)
                all_outputs.append(f"=== {host} - enum_links ===")
                all_outputs.append(links_output)
                all_outputs.append("")
                links = self._parse_links_output(links_output)
                if links:
                    linked_servers.append({'host': host, 'links': links})
                # Check for encryption disabled
                if 'EncryptionReq:False' in links_output:
                    encryption_disabled.append(host)
            
            # Check impersonation - show output and parse
            imp_output = self._run_netexec_module(host, 'enum_impersonate')
            if imp_output:
                self.logger.debug(imp_output)  # Raw netexec output (debug only)
                all_outputs.append(f"=== {host} - enum_impersonate ===")
                all_outputs.append(imp_output)
                all_outputs.append("")
                users = self._parse_impersonate_output(imp_output)
                if users:
                    impersonate_privs.append({'host': host, 'users': users})
                # Check for encryption disabled (if not already found)
                if 'EncryptionReq:False' in imp_output and host not in encryption_disabled:
                    encryption_disabled.append(host)
        
        # Save results
        if linked_servers:
            note(self, f"Found linked servers on {len(linked_servers)} MSSQL hosts", id="sql.linked-servers", names=[i.get('host') for i in linked_servers if i.get('host')])
            lines = []
            for item in linked_servers:
                lines.append(f"Host: {item['host']}")
                for link in item['links']:
                    lines.append(f"  - {link}")
                lines.append("")
            write_lines(lines, self.output_paths['findings'] / 'mssql_linked_servers.txt')
        
        if impersonate_privs:
            note(self, f"Found impersonation privileges on {len(impersonate_privs)} MSSQL hosts", id="sql.impersonation", names=[i.get('host') for i in impersonate_privs if i.get('host')])
            lines = []
            for item in impersonate_privs:
                lines.append(f"Host: {item['host']}")
                for user in item['users']:
                    lines.append(f"  - {user}")
                lines.append("")
            write_lines(lines, self.output_paths['findings'] / 'mssql_impersonate_privs.txt')
        
        if encryption_disabled:
            self.logger.info("---Checking for MSSQL without encryption---")
            note(self, f"Found {len(encryption_disabled)} MSSQL hosts with encryption disabled", id="sql.encryption-disabled", names=encryption_disabled)
            write_lines(encryption_disabled, self.output_paths['findings'] / 'mssql_encryption_disabled.txt')
        
        # Save all netexec outputs
        if all_outputs:
            write_lines(all_outputs, self.output_paths['data'] / 'mssql_servers.txt')
    
    def _get_mssql_hosts(self) -> List[str]:
        """Find MSSQL servers via SPN enumeration and network scan results."""
        hosts = []
        spn_hosts = []
        
        # First, check network scan results for MSSQL hosts (port 1433)
        try:
            filtered_hosts = self.target_files.read('scandata_hostalive_mssql.txt', "MSSQL").targets
            for ip in filtered_hosts:
                if ip not in hosts:
                    hosts.append(ip)
            if hosts:
                self.logger.info(f"[*] Found {len(hosts)} MSSQL hosts from network scan")
        except Exception as e:
            self.logger.debug(f"Failed to read network scan MSSQL results: {e}")
        
        # Also search for MSSQL SPNs in LDAP
        try:
            query = """(&(objectCategory=computer)(servicePrincipalName=MSSQL*))"""
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=query,
                attributes=['dNSHostName', 'servicePrincipalName']
            )
            
            hostnames = [entry.get('dNSHostName', '') for entry in results if entry.get('dNSHostName')]
            filtered_spns = self.target_scope.filter_targets(
                hostnames, logger=self.logger, label="MSSQL SPN host"
            ).targets
            for hostname in filtered_spns:
                if hostname and hostname not in hosts:
                    hosts.append(hostname)
                    spn_hosts.append(hostname)
            
            if spn_hosts:
                self.logger.info(f"[*] Found {len(spn_hosts)} additional MSSQL hosts from SPNs")
        except Exception as e:
            self.logger.debug(f"Failed to enumerate MSSQL SPNs: {e}")
        
        return hosts
    
    def _run_netexec_module(self, host: str, module: str) -> str:
        """Run a netexec module against a host."""
        extra = ['-M', module]
        try:
            output, result = self.session.run_nxc(
                'mssql', extra=extra, host=host, timeout=30
            )
            report_netexec_failure(self.logger, f"netexec MSSQL {module} module for {host}", result)
            return output
        except subprocess.TimeoutExpired:
            self.logger.error(f"[-] netexec MSSQL {module} module timed out for {host}")
            return ""
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
            return ""
        except Exception as e:
            self.logger.error(f"[-] Error running netexec MSSQL {module} module for {host}: {e}")
            return ""
    
    def _parse_links_output(self, output: str) -> List[str]:
        """Parse enum_links output for linked servers."""
        links = []
        if "Linked servers found:" in output:
            in_links = False
            for line in output.split('\n'):
                if "Linked servers found:" in line:
                    in_links = True
                    continue
                if in_links and line.strip().startswith('-'):
                    link = line.strip()[1:].strip()
                    if link:
                        links.append(link)
                elif in_links and not line.strip().startswith('-'):
                    break
        return links
    
    def _parse_impersonate_output(self, output: str) -> List[str]:
        """Parse enum_impersonate output for users with impersonation rights."""
        users = []
        if "Users with impersonation rights:" in output:
            in_users = False
            for line in output.split('\n'):
                if "Users with impersonation rights:" in line:
                    in_users = True
                    continue
                if in_users and line.strip().startswith('-'):
                    user = line.strip()[1:].strip()
                    if user:
                        users.append(user)
                elif in_users and not line.strip().startswith('-'):
                    break
        return users
