"""Active Directory Certificate Services (ADCS) security checks."""

import json
import subprocess
import tempfile
import os
import shutil
from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines
from ..utils.bins import certipy_bin
from .emit import note


class ADCSChecker:
    """Checks for Active Directory Certificate Services configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, domain: str = None, username: str = None,
                 password: str = None, hashes: str = None, session=None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.session = session
    
    def check_adcs(self):
        """Run all ADCS security checks."""
        self._check_cert_publishers()
        self._check_certipy_vulnerabilities()
    
    def _check_cert_publishers(self):
        """Check for ADCS by searching for PKI Enrollment Services."""
        self.logger.info("---Checking if Active Directory Certificate Services is used within the domain---")
        
        try:
            # Get Configuration naming context (pKIEnrollmentService is stored there)
            config_dn = self.ldap.get_config_dn()
            
            enrollment_services = self.ldap.query(
                search_base=config_dn,
                search_filter='(objectClass=pKIEnrollmentService)',
                attributes=['cn', 'dNSHostName', 'cACertificateDN']
            )
            
            if not enrollment_services:
                self.logger.success("[+] ADCS not found (no PKI Enrollment Services)")
                return
            
            results = []
            for service in enrollment_services:
                # Get PKI Enrollment Server (dNSHostName)
                dns_hostname = service.get('dNSHostName', '')
                if dns_hostname:
                    self.logger.warning(f"[!] Found PKI Enrollment Server: {dns_hostname}")
                
                # Get CA Common Name
                ca_cn = service.get('cn', '')
                if ca_cn:
                    self.logger.warning(f"[!] Found CN: {ca_cn}")
                
                results.append({
                    'type': 'PKI Enrollment Service',
                    'cn': ca_cn,
                    'dns_hostname': dns_hostname
                })
            
            if results:
                self.logger.warning(f"[!] ADCS installed with {len(results)} PKI Enrollment Service(s)")
                write_csv(results, self.output_paths['checks'] / 'ADCS.txt')
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ADCS: {e}")
    
    def _check_certipy_vulnerabilities(self):
        """Run certipy find to detect vulnerable certificate templates."""
        self.logger.info("---Checking for vulnerable certificate templates with certipy---")
        
        # Check if certipy is available
        certipy = certipy_bin()
        if not certipy:
            self.logger.warning("[!] certipy/certipy-ad not found. Install with: pipx install certipy-ad")
            return
        
        if not self.server or not self.username:
            self.logger.warning("[!] Missing credentials for certipy check")
            return
        
        try:
            cmd = self.session.certipy_cmd(['find', '-json'])
            
            self.logger.log_verbose(f"[D] Running: certipy find -dc-ip {self.server} -u {self.username}@{self.domain} -json")
            
            # Run certipy in a temp directory to capture output file
            with tempfile.TemporaryDirectory() as tmpdir:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    cwd=tmpdir,
                    timeout=300
                )
                
                # Log raw output in verbose mode
                if result.stdout:
                    self.logger.log_verbose(f"[D] certipy stdout:\n{result.stdout}")
                if result.stderr:
                    self.logger.log_verbose(f"[D] certipy stderr:\n{result.stderr}")
                
                # Find the JSON output file
                json_files = [f for f in os.listdir(tmpdir) if f.endswith('_Certipy.json')]
                
                if not json_files:
                    self.logger.warning("[!] No certipy JSON output found")
                    return
                
                json_path = os.path.join(tmpdir, json_files[0])
                
                with open(json_path, 'r') as f:
                    certipy_data = json.load(f)
                
                # Copy JSON to output directory
                output_json = self.output_paths['checks'] / 'ADCS_certipy.json'
                with open(output_json, 'w') as f:
                    json.dump(certipy_data, f, indent=2)
                self.logger.log_verbose(f"[+] Saved certipy output to {output_json}")
                
                # Parse vulnerabilities from Certificate Templates
                self._parse_certipy_vulnerabilities(certipy_data)
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] certipy command timed out")
        except Exception as e:
            self.logger.error(f"[-] Error running certipy: {e}")
    
    def _parse_certipy_vulnerabilities(self, data: dict):
        """Parse certipy JSON output for vulnerabilities."""
        vulnerable_templates = []
        replay = ""
        if self.session is not None:
            replay = self.session.certipy_replay(["find", "-json"])
        
        # Check Certificate Authorities for vulnerabilities (like ESC8)
        cas = data.get('Certificate Authorities', {})
        if isinstance(cas, dict):
            for idx, ca in cas.items():
                if not isinstance(ca, dict):
                    continue
                ca_name = ca.get('CA Name', 'Unknown CA')
                ca_vulns = ca.get('[!] Vulnerabilities', {})
                if ca_vulns and isinstance(ca_vulns, dict):
                    for vuln_type, description in ca_vulns.items():
                        self.logger.warning(f"[!] CA {ca_name}: {vuln_type} - {description}")
                        note(
                            self,
                            f"CA {ca_name}: {vuln_type}",
                            severity="high",
                            evidence=str(description),
                            id=f"adcs.{str(vuln_type).lower()}",
                            asset=ca_name,
                            backend="certipy",
                            replay=replay,
                            ca=ca_name,
                            vuln=str(vuln_type),
                        )
                        vulnerable_templates.append({
                            'template_name': f"CA: {ca_name}",
                            'vulnerabilities': [vuln_type],
                            'details': {vuln_type: description},
                            'remarks': {},
                            'enrollable_by': [],
                            'acl_principals': []
                        })
        
        # Check Certificate Templates
        templates = data.get('Certificate Templates', {})

        if isinstance(templates, dict) and templates:
            names = []
            for _idx, template in templates.items():
                if isinstance(template, dict):
                    names.append(template.get('Template Name') or template.get('Display Name') or str(_idx))
            if names:
                self.logger.info(f"[*] certipy enumerated {len(names)} certificate template(s)")
                write_lines(names, self.output_paths['checks'] / 'ADCS_templates.txt')

        # Handle case where templates is a string error message instead of dict
        if not templates or not isinstance(templates, dict):
            if isinstance(templates, str):
                self.logger.warning(f"[!] certipy: {templates}")
        else:
            for idx, template in templates.items():
                # Handle case where template might be a string instead of dict
                if not isinstance(template, dict):
                    continue
                    
                template_name = template.get('Template Name', 'Unknown')
                vulnerabilities = template.get('[!] Vulnerabilities', {})
                remarks = template.get('[*] Remarks', {})
                enrollable = template.get('[+] User Enrollable Principals', [])
                acl_principals = template.get('[+] User ACL Principals', [])
                
                # Handle case where vulnerabilities might be a string or None
                if not vulnerabilities or not isinstance(vulnerabilities, dict):
                    continue
                
                vuln_entry = {
                    'template_name': template_name,
                    'vulnerabilities': list(vulnerabilities.keys()),
                    'details': vulnerabilities,
                    'remarks': remarks if isinstance(remarks, dict) else {},
                    'enrollable_by': enrollable if isinstance(enrollable, list) else [],
                    'acl_principals': acl_principals if isinstance(acl_principals, list) else []
                }
                vulnerable_templates.append(vuln_entry)
                
                # Log each vulnerability
                for vuln_type, description in vulnerabilities.items():
                    self.logger.warning(f"[!] {template_name}: {vuln_type} - {description}")
                    note(
                        self,
                        f"{template_name}: {vuln_type}",
                        severity="high",
                        evidence=str(description),
                        id=f"adcs.{str(vuln_type).lower()}",
                        asset=template_name,
                        backend="certipy",
                        replay=replay,
                        template=template_name,
                        vuln=str(vuln_type),
                        names=enrollable if isinstance(enrollable, list) else [],
                        enrollable=enrollable if isinstance(enrollable, list) else [],
                    )
                    if isinstance(remarks, dict) and vuln_type in remarks:
                        self.logger.info(f"    [*] Note: {remarks[vuln_type]}")
                    if enrollable and isinstance(enrollable, list):
                        self.logger.info(f"    [*] Enrollable by: {', '.join(enrollable)}")
        
        if vulnerable_templates:
            self.logger.warning(f"[!] Found {len(vulnerable_templates)} vulnerable certificate template(s)")
            # Write summary to file
            vuln_summary = self.output_paths['checks'] / 'ADCS_vulnerabilities.txt'
            with open(vuln_summary, 'w') as f:
                for entry in vulnerable_templates:
                    f.write(f"Template: {entry['template_name']}\n")
                    f.write(f"Vulnerabilities: {', '.join(entry['vulnerabilities'])}\n")
                    for vuln, desc in entry['details'].items():
                        f.write(f"  - {vuln}: {desc}\n")
                    if entry['enrollable_by']:
                        f.write(f"Enrollable by: {', '.join(entry['enrollable_by'])}\n")
                    f.write("\n")
            self.logger.info(f"[+] Saved vulnerability summary to {vuln_summary}")
        else:
            self.logger.success("[+] No vulnerable certificate templates found")
