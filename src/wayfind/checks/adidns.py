"""ADIDNS security checks."""

import ldap3
from typing import Dict, List
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.security_descriptor import parse_security_descriptor
from ..tools.powermad import ADIDNSEnumerator


class ADIDNSChecker:
    """Checks for ADIDNS permissions and configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        
        # Get server from LDAP connection
        self.server = ldap_conn.config.server
    
    def check_adidns(self):
        """Run all ADIDNS security checks."""
        self._check_adidns_permissions()
        self._check_adidns_wildcard()
    
    def _check_adidns_permissions(self):
        """Check ADIDNS permissions - specifically if Authenticated Users can add records."""
        self.logger.info("---Checking ADIDNS permissions---")
        
        try:
            # Try different partitions to find the DNS zone
            partitions = ["DomainDNSZones", "ForestDNSZones", "System"]
            zone_found = False
            
            for partition in partitions:
                try:
                    # Build the search base for this partition
                    if partition == "System":
                        search_base = f"CN={partition}"
                    else:
                        search_base = f"DC={partition}"
                    
                    for dc in self.domain.split('.'):
                        search_base += f",DC={dc}"
                    
                    # Search for the zone with security descriptor
                    self.ldap.connection.search(
                        search_base=search_base,
                        search_filter=f'(&(objectClass=dnsZone)(name={self.domain}))',
                        attributes=['distinguishedName', 'nTSecurityDescriptor'],
                        search_scope=ldap3.SUBTREE,
                        controls=[('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]  # Request DACL
                    )
                    
                    if self.ldap.connection.entries:
                        entry = self.ldap.connection.entries[0]
                        zone_dn = str(entry.entry_dn)
                        zone_found = True
                        
                        # Get security descriptor raw bytes
                        sd_raw = entry['nTSecurityDescriptor'].raw_values[0] if entry['nTSecurityDescriptor'].raw_values else None
                        
                        if sd_raw:
                            # Parse the security descriptor
                            sd = parse_security_descriptor(sd_raw)
                            
                            if sd:
                                # Check if Authenticated Users (S-1-5-11) has CreateChild permission
                                auth_users_sid = "S-1-5-11"
                                
                                if sd.can_create_child(auth_users_sid):
                                    note(self, "Authenticated Users (S-1-5-11) can add DNS records (CreateChild permission)", id="adidns.create-child")
                                    write_lines(
                                        [f"Zone: {self.domain}",
                                         f"Partition: {partition}",
                                         f"DN: {zone_dn}",
                                         "Authenticated Users (S-1-5-11) has CreateChild permission"],
                                        self.output_paths['findings'] / 'ADIDNS_authenticated_users.txt'
                                    )
                                else:
                                    self.logger.success("[+] Authenticated Users (S-1-5-11) cannot add DNS records (no CreateChild permission)")
                            else:
                                self.logger.info("[*] Could not parse security descriptor")
                        else:
                            self.logger.info("[*] Could not read security descriptor - insufficient permissions")
                        
                        break  # Found the zone
                        
                except Exception as e:
                    continue
            
            if not zone_found:
                self.logger.info("[*] No ADIDNS zone found (may not exist or insufficient permissions)")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ADIDNS permissions: {e}")
    
    def _check_adidns_wildcard(self):
        """Check for ADIDNS wildcard record."""
        self.logger.info("---Checking ADIDNS wildcard record---")
        
        try:
            enumerator = ADIDNSEnumerator(self.ldap, self.domain, self.server)
            
            # Try different partitions for wildcard
            partitions = ["DomainDNSZones", "ForestDNSZones", "System"]
            wildcard_exists = False
            
            for partition in partitions:
                try:
                    if enumerator.check_wildcard_record(self.domain, partition):
                        wildcard_exists = True
                        break
                except Exception:
                    continue
            
            if wildcard_exists:
                self.logger.success("[+] Wildcard record in ADIDNS exists")
            else:
                note(self, "No wildcard record in ADIDNS", id="adidns.no-wildcard")
                write_lines(
                    ["No wildcard DNS record found - ADIDNS poisoning may be possible"],
                    self.output_paths['findings'] / 'ADIDNS_wildcard_record.txt'
                )
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ADIDNS wildcard: {e}")
