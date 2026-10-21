"""Domain Controller vulnerability checks - Zerologon and NoPac."""

import subprocess
import tempfile
import re
import os
from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.netexec import report_netexec_failure
from ..utils.output import write_lines


class DCVulnsChecker:
    """Check Domain Controllers for critical vulnerabilities."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
    
    def check_dc_vulnerabilities(self):
        """Check all DCs for Zerologon and NoPac vulnerabilities."""
        self.logger.info("---Checking DCs for critical vulnerabilities (Zerologon, NoPac)---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] DC vulnerability checks require credentials")
            return
        
        # Get list of Domain Controllers
        dc_ips = self._get_dc_ips()
        
        if not dc_ips:
            self.logger.info("[*] No Domain Controller IPs found")
            return
        
        self.logger.info(f"[*] Checking {len(dc_ips)} Domain Controllers for vulnerabilities")
        self.logger.info("[*] This can take some time; the check times out after 10 minutes")
        
        # Run netexec with both modules in single command
        self._run_vulnerability_check(dc_ips)
    
    def _get_dc_ips(self) -> List[str]:
        """Get IP addresses of Domain Controllers."""
        try:
            # Query for domain controllers
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not results:
                return []
            
            # Resolve DC hostnames to IPs
            dc_ips = []
            for dc in results:
                hostname = dc.get('dNSHostName', '')
                if hostname:
                    ip = self._resolve_hostname(hostname)
                    if ip:
                        dc_ips.append(ip)
            
            return dc_ips
            
        except Exception as e:
            self.logger.error(f"[-] Error getting DC list: {e}")
            return []
    
    def _resolve_hostname(self, hostname: str) -> str:
        """Resolve hostname to IP address."""
        import socket
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            self.logger.debug(f"Could not resolve {hostname}")
            return None
    
    def _run_vulnerability_check(self, dc_ips: List[str]):
        """Run netexec with zerologon and nopac modules."""
        hosts_file = None
        try:
            # Create temp file with DC IPs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for ip in dc_ips:
                    f.write(f"{ip}\n")
                hosts_file = f.name
            
            # Build netexec command with both modules
            extra = ['-M', 'nopac', '-M', 'zerologon']
            output, result = self.session.run_nxc(
                'smb', extra=extra, host=hosts_file, timeout=600
            )
            
            # Debug: raw netexec output
            self.logger.debug(f"netexec dc_vulns stdout:\n{result.stdout}")
            self.logger.debug(f"netexec dc_vulns stderr:\n{result.stderr}")
            
            # Save raw output
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_dc_vulns.txt')

            if report_netexec_failure(self.logger, "netexec zerologon/nopac modules", result):
                self.logger.warning("[!] Skipping DC vulnerability parsing because the NetExec module command failed")
                return
            
            # Parse results
            self._parse_vulnerability_output(output)
            
        except subprocess.TimeoutExpired:
            self.logger.error("[-] DC vulnerability check timed out after 10 minutes")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found")
        except Exception as e:
            self.logger.error(f"[-] Error running DC vulnerability check: {e}")
        finally:
            if hosts_file and os.path.exists(hosts_file):
                os.unlink(hosts_file)
    
    def _parse_vulnerability_output(self, output: str):
        """Parse netexec output for vulnerabilities and errors."""
        zerologon_vulnerable = []
        nopac_vulnerable = []
        errors = []
        
        # Check the FULL output for known error patterns first.
        # Rich/netexec may split error details across multiple lines,
        # so per-line matching misses multi-line tracebacks.
        if 'KRB_AP_ERR_SKEW' in output or 'Clock skew' in output:
            errors.append("Kerberos clock skew (time synchronization issue)")
        if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' in output:
            errors.append("Kerberos error: client principal unknown")
        if 'KDC_ERR_PREAUTH_FAILED' in output:
            errors.append("Kerberos error: pre-authentication failed")
        
        # Parse individual lines for vulnerability results
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Skip error/traceback lines
            if 'ERROR' in line or 'Traceback' in line:
                continue
            
            # Extract IP from line
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if not ip_match:
                continue
            
            ip = ip_match.group()
            
            # Check for VULNERABLE in the line
            if 'VULNERABLE' not in line:
                continue
            
            # Determine which module reported the vulnerability
            if line.startswith('ZEROLOGON') or 'ZEROLOGON' in line.split()[0]:
                if ip not in zerologon_vulnerable:
                    zerologon_vulnerable.append(ip)
            elif line.startswith('NOPAC') or 'NOPAC' in line.split()[0]:
                if ip not in nopac_vulnerable:
                    nopac_vulnerable.append(ip)
        
        # Report errors if any occurred
        has_errors = False
        if errors:
            errors = list(set(errors))  # Remove duplicates
            has_errors = True
            self.logger.warning("[!] DC vulnerability check encountered errors (results incomplete):")
            for error in errors:
                self.logger.warning(f"    - {error}")
        
        # Only report results if no errors occurred
        if has_errors:
            self.logger.warning("[!] DC vulnerability checks could not complete due to errors")
            return
        
        # Report Zerologon findings
        if zerologon_vulnerable:
            note(self, f"{len(zerologon_vulnerable)} DC(s) vulnerable to Zerologon (CVE-2020-1472)", id="dc-vulns.zerologon", names=zerologon_vulnerable, severity="high")
            findings = [
                "Zerologon Vulnerable Domain Controllers",
                "=" * 40,
                "",
                "CVE-2020-1472 - Critical vulnerability allowing domain takeover",
                "Reference: https://github.com/dirkjanm/CVE-2020-1472",
                "",
                "Vulnerable DCs:"
            ]
            findings.extend([f"  - {ip}" for ip in zerologon_vulnerable])
            write_lines(findings, self.output_paths['findings'] / 'dc_zerologon_vulnerable.txt')
        else:
            self.logger.success("[+] No DCs vulnerable to Zerologon")
        
        # Report NoPac findings
        if nopac_vulnerable:
            note(self, f"{len(nopac_vulnerable)} DC(s) vulnerable to NoPac (CVE-2021-42278/CVE-2021-42287)", id="dc-vulns.nopac", names=nopac_vulnerable, severity="high")
            findings = [
                "NoPac Vulnerable Domain Controllers",
                "=" * 40,
                "",
                "CVE-2021-42278/CVE-2021-42287 - Privilege escalation to Domain Admin",
                "Reference: https://github.com/Ridter/noPac",
                "",
                "Vulnerable DCs:"
            ]
            findings.extend([f"  - {ip}" for ip in nopac_vulnerable])
            write_lines(findings, self.output_paths['findings'] / 'dc_nopac_vulnerable.txt')
        else:
            self.logger.success("[+] No DCs vulnerable to NoPac")
