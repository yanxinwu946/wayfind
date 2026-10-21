"""LDAP and SYSVOL security checks.

Uses netexec to check LDAP signing and channel binding.
"""

import subprocess
import re
from typing import Dict, List
from pathlib import Path

import ldap3

from impacket.dcerpc.v5 import transport, rprn

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.nxc_parse import parse_ldap_security
from ..config import NETLOGON_PASSWORD_KEYWORDS


class LDAPChecker:
    """LDAP signing, channel binding, and SYSVOL checks."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None, session=None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain
    
    def check_ldap(self):
        """LDAP signing/CB, NETLOGON, spooler. Anonymous bind is --check anonymous."""
        self._check_ldap_signing()
        self._check_netlogon_passwords()
        self._check_printspooler_dc()
    
    def _check_ldap_anonymous_bind(self):
        """Check whether each DC allows anonymous (unauthenticated) LDAP binds."""
        self.logger.info("---Checking LDAP anonymous bind---")

        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
        except Exception as e:
            self.logger.error(f"[-] Failed to query domain controllers: {e}")
            dcs = []

        if not dcs:
            dcs = [{'dNSHostName': self.server, 'name': 'DC'}]

        vulnerable_dcs = []

        for dc in dcs:
            hostname = dc.get('dNSHostName', '')
            name = dc.get('name', '')

            if not hostname:
                continue

            self.logger.info(f"[*] Testing anonymous LDAP bind on {name} ({hostname})")

            try:
                server = ldap3.Server(hostname, port=389, get_info=ldap3.NONE)
                conn = ldap3.Connection(
                    server,
                    authentication=ldap3.ANONYMOUS,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=10
                )
                bound = conn.bind()

                if bound:
                    # Windows AD always accepts an anonymous bind, so we must
                    # verify whether the server actually allows querying
                    # domain data.  rootDSE is always accessible anonymously
                    # (RFC 4512), so we skip it and test real domain queries.
                    anonymous_access = False

                    # Try to read an actual domain object
                    try:
                        conn.search(
                            search_base=self.base_dn,
                            search_filter='(objectClass=domain)',
                            search_scope=ldap3.BASE,
                            attributes=['distinguishedName']
                        )
                        # ldap3 does not raise on operationsError, so check
                        # the result code explicitly (0 = success)
                        if conn.result.get('result') == 0 and conn.entries:
                            anonymous_access = True
                    except Exception:
                        pass

                    # Fallback: try enumerating users (single result)
                    if not anonymous_access:
                        try:
                            conn.search(
                                search_base=self.base_dn,
                                search_filter='(objectClass=user)',
                                search_scope=ldap3.SUBTREE,
                                attributes=['sAMAccountName'],
                                size_limit=1
                            )
                            if conn.result.get('result') == 0 and conn.entries:
                                anonymous_access = True
                        except Exception:
                            pass

                    if anonymous_access:
                        note(self, f"Anonymous LDAP bind allowed on {name} ({hostname})", id="ldap.anonymous-bind", severity="high", asset=name, check="ldap-anonymous-bind")
                        vulnerable_dcs.append(f"{name} ({hostname}): anonymous LDAP bind allowed")
                    else:
                        self.logger.success(f"[+] Anonymous LDAP bind denied on {name}")

                else:
                    self.logger.success(f"[+] Anonymous LDAP bind denied on {name}")

                conn.unbind()

            except Exception as e:
                self.logger.debug(f"Anonymous bind check failed for {hostname}: {e}")
                self.logger.warning(f"[!] Could not test anonymous bind on {name}: {e}")

        if vulnerable_dcs:
            write_lines(vulnerable_dcs,
                        self.output_paths['findings'] / 'ldap_anonymous_bind.txt')

    def _check_ldap_signing(self):
        """Check LDAP signing and LDAPS channel binding using netexec."""
        self.logger.info("---Checking LDAP signing and LDAPS channel binding---")
        
        # Get all domain controllers
        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
        except Exception as e:
            self.logger.error(f"[-] Failed to query domain controllers: {e}")
            dcs = []
        
        if not dcs:
            self.logger.warning("[!] No domain controllers found, trying configured server")
            dcs = [{'dNSHostName': self.server, 'name': 'DC'}]
        
        all_results = []
        vulnerable_dcs = []
        
        for dc in dcs:
            hostname = dc.get('dNSHostName', '')
            name = dc.get('name', '')
            
            if not hostname:
                continue
            
            self.logger.info(f"[*] Checking DC: {name} ({hostname})")
            
            try:
                output, result = self.session.run_nxc(
                    'ldap', host=hostname, timeout=60, archive=f'nxc_ldap_{name}.txt'
                )
                self.logger.debug(f"netexec ldap stdout:\n{result.stdout}")
                self.logger.debug(f"netexec ldap stderr:\n{result.stderr}")
                parsed = parse_ldap_security(output)
                signing = parsed.get('signing')
                binding = parsed.get('channel_binding')
                
                results = [f"Domain Controller: {name} ({hostname})"]
                
                # Check LDAP signing
                if signing:
                    if signing.lower() in ('true', 'enforced', 'required', 'yes'):
                        self.logger.success(f"[+] {name}: LDAP signing IS enforced ({signing})")
                        results.append(f"LDAP signing: ENFORCED ({signing})")
                    else:
                        results.append(f"LDAP signing: NOT ENFORCED ({signing})")
                        vulnerable_dcs.append(f"{name}: LDAP signing not enforced ({signing})")
                        self.session.emit(
                                id="ldap.signing",
                                severity="high",
                                title=f"{name}: LDAP signing not enforced ({signing})",
                                asset=name,
                                evidence=f"signing={signing}",
                                replay=self.session.nxc_replay('ldap', host=hostname),
                                backend="nxc",
                                check="ldap",
                            )
                else:
                    self.logger.warning(f"[!] {name}: Could not determine LDAP signing")
                    results.append("LDAP signing: UNKNOWN")
                
                # Check LDAPS channel binding
                if binding:
                    if binding.lower() in ('required', 'always', 'enforced'):
                        self.logger.success(f"[+] {name}: LDAPS channel binding REQUIRED ({binding})")
                        results.append(f"LDAPS channel binding: REQUIRED ({binding})")
                    elif binding.lower() == 'never':
                        results.append("LDAPS channel binding: NEVER (vulnerable to relay)")
                        vulnerable_dcs.append(f"{name}: LDAPS channel binding set to Never")
                        self.session.emit(
                                id="ldap.channel-binding",
                                severity="high",
                                title=f"{name}: LDAPS channel binding NEVER",
                                asset=name,
                                evidence=f"channel binding={binding}",
                                replay=self.session.nxc_replay('ldap', host=hostname),
                                backend="nxc",
                                check="ldap",
                            )
                    elif binding.lower() in ('supported', 'when_supported', 'when supported'):
                        self.logger.warning(f"[!] {name}: LDAPS channel binding WHEN SUPPORTED")
                        results.append("LDAPS channel binding: WHEN SUPPORTED")
                    else:
                        self.logger.info(f"[*] {name}: LDAPS channel binding: {binding}")
                        results.append(f"LDAPS channel binding: {binding}")
                else:
                    self.logger.warning(f"[!] {name}: Could not determine LDAPS channel binding")
                    results.append("LDAPS channel binding: UNKNOWN")
                
                all_results.extend(results)
                all_results.append("")
                
                # Also save raw output
                all_results.append("Raw netexec output:")
                all_results.extend(output.strip().split('\n'))
                all_results.append("")
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"[-] Timeout checking {hostname}")
            except FileNotFoundError:
                self.logger.error("[-] netexec not found")
                break
            except Exception as e:
                self.logger.error(f"Error checking {name}: {e}")
        
        # Write results
        if all_results:
            write_lines(all_results, self.output_paths['data'] / 'ldap_checks.txt')
        
        # Write findings if vulnerable
        if vulnerable_dcs:
            write_lines(vulnerable_dcs, self.output_paths['findings'] / 'ldap_vulnerabilities.txt')
    
    def _check_netlogon_passwords(self):
        """Check for passwords in NETLOGON share using impacket."""
        self.logger.info("---Checking NETLOGON for passwords---")
        self.logger.info("[*] This might take a while")
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available")
            return
        
        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not dcs:
                self.logger.info("[*] No domain controllers found")
                return
            
            findings = []
            
            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')
                
                if not hostname:
                    continue
                
                self.logger.info(f"[*] Checking NETLOGON of {name}")
                
                try:
                    conn = SMBConnection(hostname, hostname)
                    conn.login(self.username, self.password, self.domain)
                    
                    # Connect to NETLOGON share
                    conn.connectTree('NETLOGON')
                    
                    # List files recursively and check content
                    found_password = False
                    
                    def scan_share_path(conn, share, path=""):
                        nonlocal found_password
                        try:
                            files = conn.listPath(share, path + "/*" if path else "*")
                            
                            for file in files:
                                fname = file.get_longname()
                                if fname in ['.', '..']:
                                    continue
                                    
                                full_path = f"{path}/{fname}" if path else fname
                                
                                if file.is_directory():
                                    scan_share_path(conn, share, full_path)
                                else:
                                    # Check filename for any keyword
                                    fname_lower = fname.lower()
                                    for keyword in NETLOGON_PASSWORD_KEYWORDS:
                                        if keyword in fname_lower:
                                            found_password = True
                                            findings.append(f"{name}: Suspicious filename '{full_path}' (matched '{keyword}')")
                                            break
                                    
                                    # Try to read text files
                                    if fname.endswith(('.bat', '.cmd', '.ps1', '.vbs', '.txt')):
                                        try:
                                            tid = conn.connectTree(share)
                                            fid = conn.openFile(tid, full_path)
                                            content = conn.readFile(tid, fid)
                                            conn.closeFile(tid, fid)
                                            
                                            if content:
                                                content_lower = content.lower()
                                                for keyword in NETLOGON_PASSWORD_KEYWORDS:
                                                    if keyword.encode() in content_lower:
                                                        found_password = True
                                                        findings.append(f"{name}: Found '{keyword}' in {full_path}")
                                                        break
                                                
                                        except Exception as e:
                                            self.logger.debug(f"Error reading {full_path}: {e}")
                        except Exception as e:
                            self.logger.debug(f"Error listing {path}: {e}")
                    
                    scan_share_path(conn, 'NETLOGON')
                    conn.logoff()
                    
                    if found_password:
                        self.logger.warning(f"[!] Possible passwords found in NETLOGON of {name}")
                    else:
                        self.logger.success(f"[+] No obvious passwords in NETLOGON of {name}")
                        
                except Exception as e:
                    self.logger.error(f"[-] Error accessing NETLOGON on {hostname}: {e}")
            
            if findings:
                write_lines(findings,
                           self.output_paths['checks'] / 'netlogon_passwords.txt')
                self.logger.warning("[!] Please manually check NETLOGON for passwords")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking NETLOGON: {e}")
    
    def _check_printspooler_dc(self):
        """Check if PrintSpooler service is running on DCs using impacket RPC."""
        self.logger.info("---Checking PrintSpooler service on DCs---")
        
        try:
            # Get domain controllers
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not dcs:
                self.logger.info("[*] No domain controllers found")
                return
            
            spooler_enabled = []
            
            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')
                
                if not hostname:
                    continue
                
                try:
                    # Check for MS-RPRN (Print Spooler) using impacket
                    if self._check_spooler_rpc(hostname):
                        note(self, f"PrintSpooler enabled on {name}", id="ldap.spooler", severity="medium", asset=name, check="ldap")
                        spooler_enabled.append(f"{name} ({hostname})")
                    else:
                        self.logger.success(f"[+] PrintSpooler disabled on {name}")
                        
                except Exception as e:
                    self.logger.debug(f"Error checking {hostname}: {e}")
            
            if spooler_enabled:
                write_lines(spooler_enabled,
                           self.output_paths['findings'] / 'printspooler_domaincontrollers.txt')
                                           
        except Exception as e:
            self.logger.error(f"[-] Error checking PrintSpooler: {e}")
    
    def _check_spooler_rpc(self, target: str) -> bool:
        """Check if Print Spooler RPC interface is available on target."""
        try:
            # MS-RPRN UUID (Print System Remote Protocol)
            MSRPRN_UUID = ('12345678-1234-abcd-ef00-0123456789ab', '1.0')
            
            # Try to bind to the MS-RPRN interface
            string_binding = f'ncacn_np:{target}[\\pipe\\spoolss]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            
            # Set credentials if available
            if self.username and self.password:
                rpc_transport.set_credentials(self.username, self.password, self.domain, '', '')
            
            rpc_transport.set_connect_timeout(10)
            
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            
            # If we get here, spooler is running
            dce.disconnect()
            return True
            
        except Exception as e:
            self.logger.debug(f"Spooler check failed for {target}: {e}")
            return False
