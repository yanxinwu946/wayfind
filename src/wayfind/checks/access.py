"""Access checks using netexec for SMB, RDP, WINRM, and MSSQL."""

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.targets import TargetFiles, TargetScope
from ..utils.output import write_lines


class AccessChecker:
    """Check for local admin/access on various protocols using netexec."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_files = target_files or TargetFiles(output_paths['data'], TargetScope(), self.logger)
        self.pwn3d_label = self._get_pwn3d_label()
    
    def _get_pwn3d_label(self) -> str:
        """Read pwn3d_label from ~/.nxc/nxc.conf, default to 'Pwn3d!'."""
        default_label = "Pwn3d!"
        config_path = Path.home() / ".nxc" / "nxc.conf"
        
        if not config_path.exists():
            self.logger.debug(f"nxc config not found at {config_path}, using default pwn3d_label: {default_label}")
            return default_label
        
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('pwn3d_label'):
                        # Parse: pwn3d_label = Pwn3d!
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            label = parts[1].strip()
                            self.logger.debug(f"Found pwn3d_label in config: {label}")
                            return label
        except Exception as e:
            self.logger.debug(f"Error reading nxc config: {e}")
        
        self.logger.debug(f"pwn3d_label not found in config, using default: {default_label}")
        return default_label
    
    def check_access(self):
        """Run all access checks."""
        self.logger.debug(f"[*] Using pwn3d_label: {self.pwn3d_label}")
        
        self._check_smb_access()
        self._check_winrm_access()
        self._check_rdp_access()
        self._check_mssql_access()
    
    def _get_hosts_file(self, filename: str, label: str) -> Optional[Path]:
        """Get the path to a hosts file if it exists."""
        hosts_file = self.output_paths['data'] / filename
        if self.target_files.read_discovered(hosts_file, label).targets:
            return hosts_file
        return None
    
    def _read_filtered_hosts(self, hosts_file: Path) -> Tuple[List[str], int]:
        result = self.target_files.read(hosts_file)
        return result.targets, result.excluded_count

    def _run_netexec(self, protocol: str, hosts_file: Path, timeout: int = 300) -> str:
        """Run netexec and return output."""
        with self.target_files.approved_file(hosts_file, protocol.upper()) as target_file:
            if not target_file:
                return ""

            try:
                output, result = self.session.run_nxc(
                    protocol, host=str(target_file), timeout=timeout
                )
            
                # Strip ANSI color codes
                output = re.sub(r'\x1b\[[0-9;]*m', '', output)
            
                return output
            except subprocess.TimeoutExpired:
                self.logger.error(f"[-] netexec {protocol} timed out")
                return ""
            except FileNotFoundError:
                self.logger.error("[-] netexec not found on system")
                return ""
            except Exception as e:
                self.logger.error(f"[-] Error running netexec {protocol}: {e}")
                return ""
    
    def _parse_pwn3d_output(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec output for lines containing pwn3d_label.
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        
        for line in output.split('\n'):
            if self.pwn3d_label in line:
                # Extract IP and hostname from line
                # Example: RDP  10.6.10.11  3389  WINTERFELL  [+] ... (Pwn3d!)
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                # Try to extract hostname - typically after port number
                # Format: PROTOCOL  IP  PORT  HOSTNAME  [status]
                parts = line.split()
                hostname = ""
                
                if ip_match:
                    ip = ip_match.group(1)
                    # Find hostname - it's typically the 4th field
                    # Look for uppercase word after port that doesn't start with [
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            # Next part is port, part after that should be hostname
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    results.append((ip, hostname))
        
        return results
    
    def _parse_mssql_success(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec MSSQL output for [+] success lines.
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        
        for line in output.split('\n'):
            # For MSSQL, [+] indicates successful access (no pwn3d required)
            if '[+]' in line:
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    hostname = ""
                    
                    # Extract hostname
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    # Avoid duplicates
                    if (ip, hostname) not in results:
                        results.append((ip, hostname))
        
        return results
    
    def _format_results(self, results: List[Tuple[str, str]]) -> List[str]:
        """Format results as 'IP - Computername' lines."""
        lines = []
        seen = set()
        
        for ip, hostname in results:
            key = (ip, hostname)
            if key not in seen:
                seen.add(key)
                if hostname:
                    lines.append(f"{ip} - {hostname}")
                else:
                    lines.append(ip)
        
        return sorted(lines)
    
    def _count_hosts_in_file(self, hosts_file: Path) -> int:
        """Count number of non-empty lines in hosts file."""
        try:
            return self.target_files.count(hosts_file)
        except Exception:
            return 0
    
    def _check_smb_access(self):
        """Check for local admin access over SMB."""
        self.logger.info("---Checking for local admin access over SMB---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_smb.txt', 'SMB')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec SMB against {host_count} host(s)")
        
        output = self._run_netexec('smb', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec SMB output:\n{output}")
        
        results = self._parse_pwn3d_output(output)
        
        if results:
            formatted = self._format_results(results)
            note(self, f"There are {len(formatted)} systems where the current user has local admin over SMB", id="access.local-admin-smb", names=formatted, severity="high")
            write_lines(formatted, self.output_paths['findings'] / 'access_localadmin_smb.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has local admin over SMB")
    
    def _check_winrm_access(self):
        """Check for access over WINRM."""
        self.logger.info("---Checking for access over WINRM---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_winrm.txt', 'WinRM')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec WINRM against {host_count} host(s)")
        
        output = self._run_netexec('winrm', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec WINRM output:\n{output}")
        
        results = self._parse_pwn3d_output(output)
        
        if results:
            formatted = self._format_results(results)
            note(self, f"There are {len(formatted)} systems where the current user has access over WINRM", id="access.winrm", names=formatted, severity="high")
            write_lines(formatted, self.output_paths['findings'] / 'access_winrm.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has access over WINRM")
    
    def _check_rdp_access(self):
        """Check for local admin access over RDP."""
        self.logger.info("---Checking for local admin access over RDP---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_rdp.txt', 'RDP')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec RDP against {host_count} host(s)")
        
        output = self._run_netexec('rdp', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec RDP output:\n{output}")
        
        # Check for local admin access
        results = self._parse_pwn3d_output(output)
        
        if results:
            formatted = self._format_results(results)
            note(self, f"There are {len(formatted)} systems where the current user has local admin over RDP", id="access.local-admin-rdp", names=formatted, severity="high")
            write_lines(formatted, self.output_paths['findings'] / 'access_localadmin_rdp.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has local admin over RDP")
        
        # Check for NLA disabled
        self.logger.info("---Checking for RDP NLA configuration---")
        nla_disabled = self._parse_nla_disabled(output)
        
        if nla_disabled:
            formatted = self._format_results(nla_disabled)
            note(self, f"There are {len(formatted)} systems with RDP NLA disabled", id="access.rdp-nla-disabled", names=formatted)
            write_lines(formatted, self.output_paths['findings'] / 'rdp_nla_disabled.txt')
        else:
            self.logger.success("[+] All RDP systems have NLA enabled")
    
    def _parse_nla_disabled(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec RDP output for hosts with NLA disabled (nla:False).
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        
        for line in output.split('\n'):
            # Look for nla:False in the output
            # Format: RDP  IP  PORT  HOSTNAME  [*] ... (nla:False)
            if 'nla:False' in line or 'nla:false' in line.lower():
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    hostname = ""
                    
                    # Extract hostname
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    # Avoid duplicates
                    if (ip, hostname) not in results:
                        results.append((ip, hostname))
        
        return results

    def _check_mssql_access(self):
        """Check for access over MSSQL and sysadmin privileges."""
        self.logger.info("---Checking for access over MSSQL---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_mssql.txt', 'MSSQL')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec MSSQL against {host_count} host(s)")
        
        output = self._run_netexec('mssql', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec MSSQL output:\n{output}")
        
        # For MSSQL, [+] means access (no pwn3d required)
        access_results = self._parse_mssql_success(output)
        
        if access_results:
            formatted = self._format_results(access_results)
            note(self, f"There are {len(formatted)} systems where the current user has access over MSSQL", id="access.mssql", names=formatted)
            write_lines(formatted, self.output_paths['findings'] / 'access_mssql.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has access over MSSQL")
        
        # Check for sysadmin (pwn3d_label means sysadmin on MSSQL)
        self.logger.info("---Checking for sysadmin access over MSSQL---")
        sysadmin_results = self._parse_pwn3d_output(output)
        
        if sysadmin_results:
            formatted = self._format_results(sysadmin_results)
            note(self, f"There are {len(formatted)} systems where the current user is sysadmin on MSSQL", id="access.mssql-sysadmin", names=formatted, severity="high")
            write_lines(formatted, self.output_paths['findings'] / 'access_mssql_sysadmin.txt')
        else:
            self.logger.success("[+] There are no systems where the current user is sysadmin on MSSQL")
