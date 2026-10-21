"""Network enumeration and SMB checks."""

import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass
import ipaddress

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.netexec import report_netexec_failure
from ..utils.targets import TargetFiles, TargetScope
from ..utils.output import write_lines


@dataclass
class HostInfo:
    """Host information container."""
    hostname: str
    ip: Optional[str] = None
    open_ports: List[int] = None
    smb_signing: Optional[bool] = None
    smbv1: Optional[bool] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []


class NetworkChecker:
    """Network enumeration and SMB checks."""
    
    # Common Windows ports to scan
    DEFAULT_PORTS = [80, 443, 139, 445, 1433, 3389, 5985, 5986]
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], 
                 server: str = None, domain: str = None, username: str = None,
                 password: str = None, hashes: str = None,
                 target_scope: TargetScope = None,
                 target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.dns_server = server or ldap_conn.config.server
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_scope = target_scope or TargetScope()
        self.target_files = target_files or TargetFiles(output_paths['data'], self.target_scope, self.logger)
        self.hosts: List[HostInfo] = []
    
    def check_network(self):
        """Run all network checks."""
        self._resolve_host_ips()
        self._scan_ports()
        self._check_smb()
        self._check_webclient()
    
    def _resolve_host_ips(self):
        """Resolve IP addresses for all domain computers via DNS."""
        self.logger.info("---Resolving IP addresses for domain computers---")
        
        try:
            # Get all computers with DNS hostnames
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(dNSHostName=*))',
                attributes=['dNSHostName', 'sAMAccountName']
            )
            
            if not computers:
                self.logger.info("[*] No computers with DNS hostnames found")
                return
            
            # Resolve IPs for each host
            host_ip_map = []
            ips = []
            excluded_count = 0
            
            for comp in computers:
                hostname = comp.get('dNSHostName', '')
                if not hostname:
                    continue
                
                ip = self._dns_resolve(hostname)
                if ip:
                    filter_reason = self.target_scope.filter_reason(ip)
                    if filter_reason:
                        excluded_count += 1
                        self.logger.log_verbose(
                            f"[*] Excluding {hostname} ({ip}) from network scan by {filter_reason}"
                        )
                        continue
                    host_ip_map.append(f"{hostname}: {ip}")
                    ips.append(ip)
                    self.hosts.append(HostInfo(hostname=hostname, ip=ip))
                else:
                    self.hosts.append(HostInfo(hostname=hostname))
            
            # Write hostname:ip mappings
            if host_ip_map:
                write_lines(sorted(host_ip_map), 
                          self.output_paths['data'] / 'computers_name_ip.txt')
            
            # Write IPs
            if ips:
                write_lines(sorted(set(ips)), 
                          self.output_paths['data'] / 'computers_ips.txt')
            
            # Calculate /24 ranges
            self._calculate_ip_ranges(ips)
            
            self.logger.info(f"[*] Resolved IPs for {len(ips)} hosts")
            if excluded_count:
                self.logger.info(
                    f"[*] Excluded {excluded_count} host(s) by {self.target_scope.filter_label()}"
                )
            
        except Exception as e:
            self.logger.error(f"[-] Error resolving host IPs: {e}")
    
    def _dns_resolve(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP using DNS."""
        try:
            # Use socket for DNS resolution
            # Use the domain controller as DNS server if possible
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if addr_info:
                return addr_info[0][4][0]
        except Exception:
            pass
        return None
    
    def _calculate_ip_ranges(self, ips: List[str]):
        """Calculate /24 ranges from IP addresses."""
        self.logger.info("---Calculating /24 ranges from IPs---")
        
        try:
            ranges = set()
            
            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    # Get /24 network
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    ranges.add(str(network))
                except Exception:
                    continue
            
            if ranges:
                write_lines(sorted(ranges), 
                          self.output_paths['data'] / 'computers_ipranges.txt')
                self.logger.info(f"[*] Found {len(ranges)} unique /24 ranges")
            
        except Exception as e:
            self.logger.error(f"[-] Error calculating IP ranges: {e}")
    
    def _scan_ports(self):
        """Scan common ports on discovered hosts using nmap or threaded Python fallback."""
        self.logger.info("---Scanning common Windows ports---")
        
        if not self.hosts:
            self.logger.info("[*] No hosts to scan")
            return
        
        # Filter hosts with IPs
        hosts_with_ips = [h for h in self.hosts if h.ip and not self.target_scope.excludes_ip(h.ip)]
        
        if not hosts_with_ips:
            self.logger.info("[*] No hosts with resolved IPs to scan")
            return
        
        # Try nmap first, fall back to threaded Python scanner
        if shutil.which('nmap'):
            self.logger.info("[*] Using nmap for port scanning")
            self._scan_with_nmap(hosts_with_ips)
        else:
            self.logger.info("[*] nmap not found, using threaded Python scanner")
            self._scan_threaded(hosts_with_ips)
    
    def _scan_with_nmap(self, hosts: List[HostInfo]):
        """Use nmap for fast port scanning."""
        try:
            import re
            
            # Build port list
            ports_str = ','.join(map(str, self.DEFAULT_PORTS))
            
            # Run nmap with connect scan (-sT) - SYN scan requires root
            self.logger.info(f"[*] Running nmap against {len(hosts)} host(s)")
            
            with self.target_files.temporary_targets([host.ip for host in hosts]) as hosts_file:
                result = subprocess.run(
                    ['nmap', '-Pn', '-n', '-sT', '-p', ports_str,
                     '-iL', str(hosts_file), '-oG', '-'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=300
                )
            
            # Check for errors
            if result.returncode != 0:
                self.logger.error(f"[-] nmap failed: {result.stderr}")
                # Fall back to threaded scanner
                self.logger.info("[*] Falling back to threaded Python scanner")
                self._scan_threaded(hosts)
                return
            
            # Log raw output for debugging (first few lines)
            if result.stdout:
                lines = [l for l in result.stdout.split('\n') if l.strip()]
                self.logger.log_verbose(f"[*] nmap output ({len(lines)} lines)")
                # Log first few host lines for debugging
                for line in lines[:10]:
                    if 'Host:' in line:
                        self.logger.log_verbose(f"    {line[:100]}")
            
            # Parse nmap output
            hosts_alive = []
            smb_hosts = []
            winrm_hosts = []
            rdp_hosts = []
            mssql_hosts = []
            http_hosts = []
            https_hosts = []
            hosts_found = 0
            
            for line in result.stdout.split('\n'):
                if 'Host:' in line and 'Ports:' in line:
                    hosts_found += 1
                    self.logger.log_verbose(f"[*] Parsing: {line[:80]}")
                    # Parse: Host: 10.0.0.1 ()  Ports: 445/open/tcp//microsoft-ds///
                    ip_match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)
                    
                    # Find host object
                    host = next((h for h in hosts if h.ip == ip), None)
                    if not host:
                        self.logger.log_verbose(f"[!] Host {ip} not found in host list")
                        continue
                    
                    # Parse open ports
                    ports_match = re.search(r'Ports:\s+(.+)$', line)
                    if ports_match:
                        ports_str = ports_match.group(1)
                        open_ports = []
                        for port_info in ports_str.split(','):
                            if '/open/' in port_info:
                                port_num = int(port_info.split('/')[0].strip())
                                open_ports.append(port_num)
                        
                        host.open_ports = open_ports
                        
                        if open_ports:
                            hosts_alive.append(host)
                            if 445 in open_ports:
                                smb_hosts.append(ip)
                            if 5985 in open_ports or 5986 in open_ports:
                                winrm_hosts.append(ip)
                            if 3389 in open_ports:
                                rdp_hosts.append(ip)
                            if 1433 in open_ports:
                                mssql_hosts.append(ip)
                            if 80 in open_ports:
                                http_hosts.append(ip)
                            if 443 in open_ports:
                                https_hosts.append(ip)
            
            self.logger.info(f"[*] nmap found {hosts_found} host(s) with port data")
            
            # Log what we found for debugging
            for host in hosts_alive:
                self.logger.log_verbose(f"[*] {host.ip}: {sorted(host.open_ports)}")
            
            # Write results
            self._write_scan_results(hosts_alive, smb_hosts, winrm_hosts, rdp_hosts, mssql_hosts, http_hosts, https_hosts)
            
        except subprocess.TimeoutExpired:
            self.logger.error("[-] nmap timed out after 5 minutes")
            self.logger.info("[*] Falling back to threaded Python scanner")
            self._scan_threaded(hosts)
        except FileNotFoundError:
            self.logger.error("[-] nmap not found")
            self.logger.info("[*] Falling back to threaded Python scanner")
            self._scan_threaded(hosts)
        except Exception as e:
            self.logger.error(f"[-] Error running nmap: {e}")
            self.logger.info("[*] Falling back to threaded Python scanner")
            self._scan_threaded(hosts)
    
    def _scan_threaded(self, hosts: List[HostInfo]):
        """Use threaded Python scanner as fallback."""
        self.logger.info(f"[*] Scanning {len(hosts)} hosts with {len(self.DEFAULT_PORTS)} ports each")
        
        hosts_alive = []
        smb_hosts = []
        winrm_hosts = []
        rdp_hosts = []
        mssql_hosts = []
        http_hosts = []
        https_hosts = []
        
        # Use ThreadPoolExecutor for parallel scanning
        max_workers = min(50, len(hosts) * len(self.DEFAULT_PORTS))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {}
            for host in hosts:
                for port in self.DEFAULT_PORTS:
                    future = executor.submit(self._check_port, host.ip, port, 1)
                    future_to_port[future] = (host, port)
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                host, port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open and port not in host.open_ports:
                        host.open_ports.append(port)
                except Exception:
                    pass
        
        # Process results
        for host in hosts:
            if host.open_ports:
                hosts_alive.append(host)
                if 445 in host.open_ports:
                    smb_hosts.append(host.ip)
                if 5985 in host.open_ports or 5986 in host.open_ports:
                    winrm_hosts.append(host.ip)
                if 3389 in host.open_ports:
                    rdp_hosts.append(host.ip)
                if 1433 in host.open_ports:
                    mssql_hosts.append(host.ip)
                if 80 in host.open_ports:
                    http_hosts.append(host.ip)
                if 443 in host.open_ports:
                    https_hosts.append(host.ip)
        
        # Write results
        self._write_scan_results(hosts_alive, smb_hosts, winrm_hosts, rdp_hosts, mssql_hosts, http_hosts, https_hosts)
    
    def _check_port(self, ip: str, port: int, timeout: float) -> bool:
        """Check if a single port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _write_scan_results(self, hosts_alive, smb_hosts, winrm_hosts, rdp_hosts, mssql_hosts, http_hosts, https_hosts):
        """Write scan results to files."""
        if hosts_alive:
            host_port_lines = [f"{h.hostname} ({h.ip}): {', '.join(map(str, sorted(h.open_ports)))}" 
                             for h in hosts_alive]
            write_lines(host_port_lines, 
                       self.output_paths['data'] / 'scandata_hostalive.txt')
            self.logger.info(f"[*] {len(hosts_alive)} computers with open ports")
        
        if smb_hosts:
            write_lines(sorted(set(smb_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_smb.txt')
            self.logger.info(f"[*] {len(set(smb_hosts))} hosts with SMB (port 445)")
        
        if winrm_hosts:
            write_lines(sorted(set(winrm_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_winrm.txt')
            self.logger.info(f"[*] {len(set(winrm_hosts))} hosts with WinRM (port 5985/5986)")
        
        if rdp_hosts:
            write_lines(sorted(set(rdp_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_rdp.txt')
            self.logger.info(f"[*] {len(set(rdp_hosts))} hosts with RDP (port 3389)")
        
        if mssql_hosts:
            write_lines(sorted(set(mssql_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_mssql.txt')
            self.logger.info(f"[*] {len(set(mssql_hosts))} hosts with MSSQL (port 1433)")
        
        if http_hosts:
            write_lines(sorted(set(http_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_http.txt')
            self.logger.info(f"[*] {len(set(http_hosts))} hosts with HTTP (port 80)")
        
        if https_hosts:
            write_lines(sorted(set(https_hosts)), 
                       self.output_paths['data'] / 'scandata_hostalive_https.txt')
            self.logger.info(f"[*] {len(set(https_hosts))} hosts with HTTPS (port 443)")
    
    def _check_smb(self):
        """Check SMB signing and SMBv1 on discovered hosts using impacket."""
        self.logger.info("---Checking SMB signing and SMBv1---")
        
        # Get SMB hosts from scanned hosts
        smb_hosts = [h for h in self.hosts if 445 in h.open_ports]
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check")
            return
        
        self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts")
        
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.smb import SMB_DIALECT
            
            smbv1_hosts = []
            no_signing_hosts = []
            
            for host in smb_hosts:
                smb = None
                try:
                    # Create SMB connection (anonymous/null session)
                    smb = SMBConnection(host.ip, host.ip, timeout=3)
                    
                    # Check if SMBv1 is supported by trying to connect with SMBv1 dialect
                    try:
                        # Try SMBv1 connection
                        smb.negotiateSession(preferredDialect=SMB_DIALECT)
                        smbv1_hosts.append(host.ip)
                        is_smbv1 = True
                    except Exception:
                        # SMBv1 not supported, use SMB2/3
                        is_smbv1 = False
                    
                    # Check signing requirement
                    # For SMBv1: use isSigningRequired()
                    # For SMBv3: check _SMBConnection._Connection["RequireSigning"]
                    try:
                        if is_smbv1:
                            signing_required = smb.isSigningRequired()
                        else:
                            # For SMB2/3, check the connection settings
                            signing_required = smb._SMBConnection._Connection.get("RequireSigning", False)
                        
                        if not signing_required:
                            no_signing_hosts.append(host.ip)
                            
                    except Exception as e:
                        self.logger.log_verbose(f"[!] Could not check signing for {host.ip}: {e}")
                    
                    if smb:
                        smb.close()
                        
                except Exception as e:
                    self.logger.log_verbose(f"[!] SMB connection failed for {host.ip}: {e}")
                    continue
                finally:
                    if smb:
                        try:
                            smb.close()
                        except Exception:
                            pass
            
            # Write findings
            if smbv1_hosts:
                note(self, f"{len(smbv1_hosts)} computers have SMBv1 enabled", id="network.smbv1", names=smbv1_hosts)
                write_lines(smbv1_hosts, 
                           self.output_paths['findings'] / 'computers_smbv1.txt')
            else:
                self.logger.success("[+] No computers have SMBv1 enabled")
            
            if no_signing_hosts:
                note(self, f"{len(no_signing_hosts)} computers don't require SMB signing", id="network.no-signing", names=no_signing_hosts)
                write_lines(no_signing_hosts, 
                           self.output_paths['findings'] / 'computers_nosigning.txt')
            else:
                self.logger.success("[+] All computers require SMB signing")
                
        except ImportError:
            self.logger.error("[-] Impacket not available for SMB checks")
            self.logger.info("[*] Install impacket: pip install impacket")
    
    def check_webclient_cve(self):
        """Run the WebClient + enum_cve (CVE / NTLM reflection) check standalone.

        Loads SMB hosts from the network scan output so this can run as an
        individual --check without re-scanning. Requires a prior network scan
        (same output dir/day) to have populated scandata_hostalive_smb.txt.
        """
        smb_file = self.output_paths['data'] / 'scandata_hostalive_smb.txt'
        smb_ips = self.target_files.read_discovered(smb_file, "SMB").targets

        if not smb_ips:
            self.logger.info("---Checking for WebClient service---")
            return

        # Populate self.hosts so _check_webclient can filter on port 445
        self.hosts = [HostInfo(hostname=ip, ip=ip, open_ports=[445]) for ip in smb_ips]
        self._check_webclient()

    def _check_webclient(self):
        """Check for WebClient service and NTLM reflection on SMB hosts using netexec."""
        # Get SMB hosts
        smb_hosts = [h for h in self.hosts if 445 in h.open_ports]
        
        if not smb_hosts:
            self.logger.info("---Checking for WebClient service---")
            self.logger.info("[*] No SMB hosts to check for WebClient")
            self.logger.info("---Checking for NTLM reflection---")
            self.logger.info("[*] No SMB hosts to check for NTLM reflection")
            return
        
        try:
            with self.target_files.temporary_targets([h.ip for h in smb_hosts if h.ip]) as hosts_file:
                # Run netexec with both webdav and enum_cve modules (single command)
                # netexec smb <hosts_file> -u user -p pass -d domain -M webdav -M enum_cve
                # (enum_cve replaces the old ntlm_reflection module and reports several CVEs)
                extra = ['-M', 'webdav', '-M', 'enum_cve']
                try:
                    output, result = self.session.run_nxc(
                        'smb', extra=extra, host=str(hosts_file), timeout=900
                    )
                except subprocess.TimeoutExpired:
                    self.logger.error("[-] netexec timed out after 5 minutes")
                    return
                except FileNotFoundError:
                    self.logger.error("[-] netexec not found on system")
                    return
                
                # Debug: raw netexec output
                self.logger.debug(f"netexec webdav/enum_cve stdout:\n{result.stdout}")
                self.logger.debug(f"netexec webdav/enum_cve stderr:\n{result.stderr}")
                
                output = (result.stdout or '') + (result.stderr or '')
                
                # Write all netexec output (raw dump of both modules)
                write_lines(output.split('\n'),
                          self.output_paths['data'] / 'netexec_smb_modules.txt')

                if report_netexec_failure(self.logger, "netexec webdav/enum_cve modules", result):
                    self.logger.warning("[!] Skipping WebClient/CVE parsing because the NetExec module command failed")
                    return
                
                # --- WebClient service check ---
                self.logger.info("---Checking for WebClient service---")
                
                webclient_hosts = []
                for line in output.split('\n'):
                    if 'WebClient Service enabled on' in line:
                        import re
                        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                        if ip_match:
                            webclient_hosts.append(ip_match.group())
                
                webclient_hosts = sorted(set(webclient_hosts))
                
                if webclient_hosts:
                    note(self, f"{len(webclient_hosts)} systems have WebClient service running", id="network.webclient", names=webclient_hosts)
                    write_lines(webclient_hosts, 
                               self.output_paths['findings'] / 'computers_webdav.txt')
                else:
                    self.logger.success("[+] No systems have WebClient service running")
                
                # --- CVE enumeration (netexec enum_cve module, formerly ntlm_reflection) ---
                # enum_cve can report any number of CVEs per host, and the set grows
                # over time, so collect them generically rather than matching known IDs.
                self.logger.info("---Checking hosts for known CVEs---")

                import re
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                cve_id_pattern = r'CVE-\d{4}-\d+'

                cve_lines = []              # full ENUM_CVE result lines (host + CVE + description)
                ntlm_reflection_hosts = []  # hosts vulnerable to NTLM reflection (CVE-2025-33073)
                for line in output.split('\n'):
                    if not line.lstrip().startswith('ENUM_CVE') or 'CVE-' not in line:
                        continue
                    cve_lines.append(line.strip())
                    # NTLM reflection (CVE-2025-33073) is also reported separately below
                    if 'CVE-2025-33073' in line:
                        ip_match = re.search(ip_pattern, line)
                        if ip_match:
                            ntlm_reflection_hosts.append(ip_match.group())

                cve_lines = sorted(set(cve_lines))

                if cve_lines:
                    unique_cves = sorted(set(
                        m.group() for line in cve_lines
                        if (m := re.search(cve_id_pattern, line))
                    ))
                    note(self, f"{len(cve_lines)} CVE finding(s) across hosts ({', '.join(unique_cves)})", id="network.cve", names=unique_cves, count=len(cve_lines))
                    for cve_line in cve_lines:
                        self.logger.warning(f"[!] {cve_line}")
                    write_lines(cve_lines,
                               self.output_paths['findings'] / 'computers_cve.txt')
                else:
                    self.logger.success("[+] No known CVEs detected by enum_cve")

                # --- NTLM reflection (kept as its own finding + file) ---
                self.logger.info("---Checking for NTLM reflection---")
                ntlm_reflection_hosts = sorted(set(ntlm_reflection_hosts))
                if ntlm_reflection_hosts:
                    note(self, f"{len(ntlm_reflection_hosts)} systems vulnerable to NTLM reflection (CVE-2025-33073)", id="network.ntlm-reflection", names=ntlm_reflection_hosts, severity="high")
                    write_lines(ntlm_reflection_hosts,
                               self.output_paths['findings'] / 'computers_ntlm_reflection.txt')
                else:
                    self.logger.success("[+] No systems vulnerable to NTLM reflection")
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking WebClient/NTLM reflection: {e}")
