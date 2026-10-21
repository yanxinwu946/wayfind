"""Domain trust enumeration and checks."""

import struct
from typing import Dict, List, Union
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_file


def convert_sid_to_string(sid_bytes: Union[bytes, str]) -> str:
    """Convert binary SID bytes to readable string format (S-1-5-21-...)."""
    if isinstance(sid_bytes, str):
        return sid_bytes
    
    if not sid_bytes or len(sid_bytes) < 8:
        return str(sid_bytes)
    
    try:
        # SID structure:
        # Byte 0: Revision (1 byte)
        # Byte 1: Sub-authority count (1 byte)
        # Bytes 2-7: Authority (6 bytes, big-endian)
        # Then 4 bytes per sub-authority (little-endian)
        
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        
        # Authority is 6 bytes, big-endian
        authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
        
        # Build SID string
        sid_str = f"S-{revision}-{authority}"
        
        # Add sub-authorities (4 bytes each, little-endian)
        offset = 8
        for _ in range(sub_auth_count):
            if offset + 4 <= len(sid_bytes):
                sub_auth = int.from_bytes(sid_bytes[offset:offset+4], byteorder='little')
                sid_str += f"-{sub_auth}"
                offset += 4
            else:
                break
        
        return sid_str
    except Exception:
        return str(sid_bytes)


TRUST_DIRECTIONS = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound", 
    3: "Bidirectional"
}

TRUST_TYPES = {
    1: "Downlevel (Windows NT domain)",
    2: "Uplevel (Active Directory domain)",
    3: "MIT (non-Windows Kerberos realm)",
    4: "DCE (DCE realm - historical)"
}

TRUST_ATTRIBUTES = {
    0x00000001: "Non-transitive",
    0x00000002: "Uplevel only (Windows 2000+)",
    0x00000004: "Quarantined (SID filtering enabled)",
    0x00000008: "Forest transitive",
    0x00000010: "Cross-organization",
    0x00000020: "Within-forest (same forest)",
    0x00000040: "Treat as external",
    0x00000080: "Uses RC4 encryption",
    0x00000100: "Uses AES encryption",
    0x00000200: "Cross-organization no TGT delegation",
    0x00000400: "PIM trust",
    0x00000800: "Cross-organization enable TGT delegation"
}


class TrustChecker:
    """Checks for domain trust relationships."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_trusts(self):
        """Enumerate domain trusts."""
        self.logger.info("---Checking for domain trusts---")
        
        try:
            # Search for trustedDomain objects in System container
            system_dn = f"CN=System,{self.base_dn}"
            trusts = self.ldap.query(
                search_base=system_dn,
                search_filter='(objectClass=trustedDomain)',
                attributes=['cn', 'trustDirection', 'trustType', 'trustAttributes', 
                          'securityIdentifier', 'flatName']
            )
            
            if not trusts:
                self.logger.success("[+] No domain trusts found")
                return
            
            results = []
            for trust in trusts:
                trust_info = self._parse_trust(trust)
                results.append(trust_info)
                self._log_trust(trust_info)
            
            # Save results
            write_csv(results, self.output_paths['data'] / 'domain_trusts.txt')
            
            # Check for interesting trust configurations
            self._check_trust_security(results)
            
        except Exception as e:
            self.logger.error(f"[-] Error enumerating trusts: {e}")
    
    def _parse_trust(self, trust: Dict) -> Dict:
        """Parse trust object into readable format."""
        direction_val = trust.get('trustDirection', 0)
        type_val = trust.get('trustType', 0)
        attrs_val = trust.get('trustAttributes', 0)
        
        # Handle list values
        if isinstance(direction_val, list):
            direction_val = direction_val[0] if direction_val else 0
        if isinstance(type_val, list):
            type_val = type_val[0] if type_val else 0
        if isinstance(attrs_val, list):
            attrs_val = attrs_val[0] if attrs_val else 0
        
        direction_val = int(direction_val) if direction_val else 0
        type_val = int(type_val) if type_val else 0
        attrs_val = int(attrs_val) if attrs_val else 0
        
        # Parse attributes
        attr_flags = []
        for flag_val, flag_name in TRUST_ATTRIBUTES.items():
            if attrs_val & flag_val:
                attr_flags.append(flag_name)
        
        sid = trust.get('securityIdentifier', '')
        if isinstance(sid, list):
            sid = sid[0] if sid else ''
        
        # Convert binary SID to readable string
        sid_str = convert_sid_to_string(sid) if sid else 'N/A'
        
        return {
            'domain': trust.get('cn', ''),
            'flat_name': trust.get('flatName', ''),
            'direction': TRUST_DIRECTIONS.get(direction_val, f"Unknown ({direction_val})"),
            'direction_raw': direction_val,
            'type': TRUST_TYPES.get(type_val, f"Unknown ({type_val})"),
            'type_raw': type_val,
            'attributes': ', '.join(attr_flags) if attr_flags else 'None',
            'attributes_raw': attrs_val,
            'sid': sid_str
        }
    
    def _log_trust(self, trust_info: Dict):
        """Log trust information."""
        self.logger.warning(f"[!] Found trust: {trust_info['domain']}")
        self.logger.info(f"    Direction: {trust_info['direction']}")
        self.logger.info(f"    Type: {trust_info['type']}")
        if trust_info['attributes'] != 'None':
            self.logger.info(f"    Attributes: {trust_info['attributes']}")
        if trust_info['sid'] != 'N/A':
            self.logger.info(f"    SID: {trust_info['sid']}")
    
    def _check_trust_security(self, trusts: List[Dict]):
        """Check for trust security issues."""
        findings = []
        
        for trust in trusts:
            issues = []
            
            # Check for inbound trusts (potential attack path)
            # Within-forest trusts (e.g. parent-child) are bidirectional by design
            # and are not a finding - only flag external/cross-forest inbound trusts
            attrs_raw = trust.get('attributes_raw', 0)
            is_within_forest = bool(attrs_raw & 0x00000020)
            if trust['direction_raw'] in [1, 3] and not is_within_forest:  # Inbound or Bidirectional
                issues.append(f"Inbound trust - potential attack path from {trust['domain']}")
            
            # Check for SID filtering (quarantined)
            if not (attrs_raw & 0x00000004):  # Not quarantined
                if trust['direction_raw'] in [1, 3]:  # Inbound trusts
                    if is_within_forest:
                        # Within-forest trusts have SID filtering disabled by design
                        # (Microsoft enforces this) - not a finding
                        pass
                    else:
                        issues.append("SID filtering NOT enabled - vulnerable to SID history injection")
            
            # Check for external trusts without quarantine
            if attrs_raw & 0x00000040:  # Treat as external
                if not (attrs_raw & 0x00000004):
                    issues.append("External trust without SID filtering")
            
            # Check for cross-forest trusts
            if attrs_raw & 0x00000008:  # Forest transitive
                issues.append("Forest trust - check for inter-forest SID filtering")
            
            if issues:
                findings.append({
                    'domain': trust['domain'],
                    'issues': '; '.join(issues)
                })
                for issue in issues:
                    note(self, f"{trust['domain']}: {issue}", id="trusts.issue", asset=str(trust.get('domain') or ''), issue=issue)
        
        if findings:
            write_csv(findings, self.output_paths['findings'] / 'trust_vulnerabilities.txt')
