"""SMB access checks - null authentication, guest access, and domain admin sessions."""

import subprocess
import tempfile
import os
import re
import csv
from typing import Dict, List, Set
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.targets import TargetFiles, TargetScope
from ..utils.output import write_lines
from ..utils.nxc_parse import parse_nxc_shares, ADMIN_SHARES, DEFAULT_SHARES


class SMBChecker:
    """Check SMB hosts for null authentication, guest access, and domain admin sessions."""
    
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
    
    def check_smb_access(self, smb_hosts: List[str] = None):
        """Run SMB access checks on discovered hosts.
        
        Args:
            smb_hosts: List of IP addresses with SMB (port 445) open.
                      If None, reads from scandata_hostalive_smb.txt
        """
        # Load SMB hosts from file if not provided
        if smb_hosts is None:
            smb_hosts = self._load_smb_hosts()
        else:
            smb_hosts = self._filter_hosts(smb_hosts)
        
        if not smb_hosts:
            return
        
        self._check_null_session(smb_hosts)
        self._check_guest_access(smb_hosts)
    
    def _load_smb_hosts(self) -> List[str]:
        """Load SMB hosts from scan data file."""
        return self.target_files.read_discovered('scandata_hostalive_smb.txt', "SMB").targets

    def _filter_hosts(self, hosts: List[str]) -> List[str]:
        return self.target_files.filter_ips(hosts, "SMB").targets
    
    def _check_null_session(self, smb_hosts: List[str]):
        """Check for null/anonymous session access on SMB hosts using netexec."""
        self.logger.info("---Checking for SMB null session access---")
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check")
            return
        
        try:
            with self.target_files.temporary_targets(smb_hosts) as hosts_file:
                self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for null session")
            
                # Run netexec with null credentials (empty username and password)
                # netexec smb <targets> -u '' -p ''
                extra = ['-u', '', '-p', '']
                output, result = self.session.run_nxc(
                    'smb', extra=extra, host=str(hosts_file), timeout=900, auth=False
                )
            
            self.logger.debug(f"netexec null session stdout:\n{result.stdout}")
            self.logger.debug(f"netexec null session stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_null_session.txt')
            
            # Parse for successful null sessions
            # Look for lines with [+] indicating success or "STATUS_ACCESS_DENIED" for failures
            null_session_hosts = []
            
            for line in output.split('\n'):
                # netexec shows [+] for success, [-] for failure
                # Success pattern: SMB  10.0.0.1  445  HOSTNAME  [+] \: 
                if '[+]' in line and 'SMB' in line:
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        null_session_hosts.append(ip_match.group())
            
            null_session_hosts = sorted(set(null_session_hosts))
            
            if null_session_hosts:
                note(self, f"{len(null_session_hosts)} hosts allow SMB null session", id="smb.null-session", names=null_session_hosts)
                write_lines(null_session_hosts,
                           self.output_paths['findings'] / 'smb_null_session.txt')
            else:
                self.logger.success("[+] No hosts allow SMB null session")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec null session check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking null session: {e}")
    
    def _check_guest_access(self, smb_hosts: List[str]):
        """Check for guest account access on SMB hosts using netexec."""
        self.logger.info("---Checking for SMB guest access---")
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check")
            return
        
        try:
            with self.target_files.temporary_targets(smb_hosts) as hosts_file:
                self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for guest access")
            
                # Run netexec with guest credentials
                # netexec smb <targets> -u 'guest' -p ''
                extra = ['-u', 'guest', '-p', '']
                output, result = self.session.run_nxc(
                    'smb', extra=extra, host=str(hosts_file), timeout=900, auth=False
                )
            
            self.logger.debug(f"netexec guest access stdout:\n{result.stdout}")
            self.logger.debug(f"netexec guest access stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_guest_access.txt')
            
            # Parse for successful guest access
            guest_access_hosts = []
            
            for line in output.split('\n'):
                # Look for [+] indicating successful authentication
                # Also check for "(Guest)" which netexec shows when guest session is established
                if '[+]' in line and 'SMB' in line:
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        guest_access_hosts.append(ip_match.group())
            
            guest_access_hosts = sorted(set(guest_access_hosts))
            
            if guest_access_hosts:
                note(self, f"{len(guest_access_hosts)} hosts allow SMB guest access", id="smb.guest", names=guest_access_hosts)
                write_lines(guest_access_hosts,
                           self.output_paths['findings'] / 'smb_guest_access.txt')
            else:
                self.logger.success("[+] No hosts allow SMB guest access")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec guest access check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking guest access: {e}")
    
    def _load_domain_admins(self) -> List[str]:
        """Load domain admins from data file."""
        admins_file = self.output_paths['data'] / 'list_domainadmins.txt'
        if admins_file.exists():
            with open(admins_file, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        return []
    
    def _load_domain_controllers(self) -> Set[str]:
        """Load domain controller hostnames from data file."""
        dc_file = self.output_paths['data'] / 'data_domaincontrollers.csv'
        dc_hostnames = set()
        
        if dc_file.exists():
            with open(dc_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'sAMAccountName' in row and row['sAMAccountName']:
                        # Remove trailing $ from computer account name
                        hostname = row['sAMAccountName'].rstrip('$').upper()
                        dc_hostnames.add(hostname)
                    if 'dNSHostName' in row and row['dNSHostName']:
                        # Also add the DNS hostname (without domain suffix)
                        dns_name = row['dNSHostName'].split('.')[0].upper()
                        dc_hostnames.add(dns_name)
        
        return dc_hostnames
    
    def check_domain_admin_sessions(self, smb_hosts: List[str] = None):
        """Check for domain admin sessions on non-domain controller systems.
        
        This is a security finding because domain admin credentials should only
        be used on domain controllers to prevent credential theft.
        
        Args:
            smb_hosts: List of IP addresses with SMB (port 445) open.
                      If None, reads from scandata_hostalive_smb.txt
        """
        self.logger.info("---Checking for domain admin sessions on non-DCs---")
        
        # Verify we have credentials
        if not self.username:
            self.logger.info("[*] No credentials available, skipping domain admin sessions check")
            return
        
        # Load SMB hosts from file if not provided
        if smb_hosts is None:
            smb_hosts = self._load_smb_hosts()
        else:
            smb_hosts = self._filter_hosts(smb_hosts)
        
        if not smb_hosts:
            return
        
        # Load domain admins
        domain_admins = self._load_domain_admins()
        if not domain_admins:
            self.logger.info("[*] No domain admins list found, skipping session check")
            return
        
        # Load domain controllers to exclude from findings
        dc_hostnames = self._load_domain_controllers()
        self.logger.debug(f"[*] Loaded {len(dc_hostnames)} domain controller hostnames")
        
        admins_file = None
        
        try:
            # Create temp file with domain admin usernames
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for admin in domain_admins:
                    f.write(f"{admin}\n")
                admins_file = f.name
            
            self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for domain admin sessions")
            with self.target_files.temporary_targets(smb_hosts) as hosts_file:
                # Build command: netexec smb <hosts> -u <user> -p <pass> --reg-sessions <admins>
                extra = ['--reg-sessions', admins_file]
                output, result = self.session.run_nxc(
                    'smb', extra=extra, host=str(hosts_file), timeout=900
                )
            
            # Strip ANSI color codes
            output = re.sub(r'\x1b\[[0-9;]*m', '', output)
            
            # Debug: raw netexec output
            self.logger.debug(f"netexec reg-sessions stdout:\n{result.stdout}")
            self.logger.debug(f"netexec reg-sessions stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_reg_sessions.txt')
            
            # Parse output for domain admin sessions on non-DCs
            # Output format: SMB  IP  445  HOSTNAME  username  SID
            # Lines with SID (S-1-5-21) indicate a session was found
            findings = []
            seen = set()
            
            for line in output.split('\n'):
                # Look for lines containing SID pattern (indicates session data)
                if 'S-1-5-21' not in line:
                    continue
                
                # Skip header lines
                if 'USERNAME' in line or '========' in line:
                    continue
                
                # Parse the line to extract hostname, IP, and username
                # Format: SMB  10.2.10.13  445  SCCM-SQL  ludus\domainadmin  S-1-5-21-...
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                # Find IP (second field), hostname (after port 445), and username (before SID)
                ip = None
                hostname = None
                username = None
                
                for i, part in enumerate(parts):
                    if part == 'SMB' and i + 1 < len(parts):
                        # IP is the field after "SMB"
                        ip = parts[i + 1]
                    if part == '445' and i + 1 < len(parts):
                        hostname = parts[i + 1]
                    if 'S-1-5-21' in part and i > 0:
                        username = parts[i - 1]
                        break
                
                if not hostname or not username or not ip:
                    continue
                
                # Normalize hostname for comparison
                hostname_upper = hostname.upper()
                
                # Skip if this is a domain controller
                if hostname_upper in dc_hostnames:
                    self.logger.debug(f"[*] Skipping DC: {hostname}")
                    continue
                
                # Extract just the username (remove domain prefix if present)
                if '\\' in username:
                    username = username.split('\\')[1]
                
                # Check if this user is in domain admins list
                if username.lower() not in domain_admins:
                    continue
                
                # Create finding entry: "username - hostname (ip)"
                finding_key = f"{username.lower()} {hostname_upper}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append(f"{username} - {hostname} ({ip})")
            
            # Sort findings by hostname (second field)
            findings = sorted(findings, key=lambda x: x.split()[1] if len(x.split()) > 1 else x)
            
            if findings:
                note(self, f"{len(findings)} domain admin sessions on non-DCs", id="smb.da-sessions", names=findings, severity="high")
                write_lines(findings,
                           self.output_paths['findings'] / 'domainadmin_sessions_nondcs.txt')
            else:
                self.logger.success("[+] No domain admin sessions on non-DCs")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec reg-sessions check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking domain admin sessions: {e}")
        finally:
            # Clean up temp files
            for f in [admins_file]:
                if f:
                    try:
                        os.unlink(f)
                    except Exception:
                        pass
    def check_dc_shares(self):
        """Authenticated nxc smb --shares against the DC."""
        self.logger.info("---Checking authenticated SMB share access---")
        if not self.username:
            self.logger.info("[*] No credentials, skipping share check")
            return
        try:
            output, result = self.session.run_nxc(
                "smb", extra=["--shares"], timeout=180, archive="nxc_shares.txt",
            )
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return
        except subprocess.TimeoutExpired:
            self.logger.error("[-] nxc --shares timed out")
            return
        except Exception as e:
            self.logger.error(f"[-] nxc --shares: {e}")
            return
        rows = parse_nxc_shares(output)
        write_lines(
            [f"{r['name']}	{r['perms']}	{r['remark']}" for r in rows],
            self.output_paths["data"] / "nxc_shares.txt",
        )
        if not rows:
            self.logger.info("[*] No share table parsed from nxc --shares")
            return
        replay = self.session.nxc_replay("smb", extra=["--shares"])
        hits = []
        for row in rows:
            name = row["name"]
            perms = row["perms"]
            if not perms:
                continue
            upper = name.upper()
            if upper in DEFAULT_SHARES and "WRITE" not in perms:
                continue
            severity = "high" if upper in ADMIN_SHARES else "medium"
            title = f"SMB share {name} {perms}"
            self.session.emit(
                id="shares.access",
                severity=severity,
                title=title,
                asset=name,
                evidence=f"{name} {perms} {row.get('remark') or ''}".strip(),
                replay=replay,
                backend="nxc",
                check="shares",
                perms=perms,
            )
            hits.append(f"{name} {perms}")
        if hits:
            write_lines(hits, self.output_paths["findings"] / "smb_share_access.txt")
        else:
            self.logger.success("[+] No extra authenticated share access beyond defaults")
