"""ADIDNS enumeration functions based on Powermad.

Implements ADIDNS enumeration and permission checking based on Powermad.ps1
by Kevin Robertson (@kevin_robertson).

Reference: https://github.com/Kevin-Robertson/Powermad
"""

import ldap3
from typing import List, Dict, Optional
from pathlib import Path


class ADIDNSEnumerator:
    """ADIDNS enumeration and permission checking."""
    
    def __init__(self, ldap_conn, domain: str, server: str):
        self.ldap = ldap_conn
        self.domain = domain
        self.server = server
        self.domain_parts = domain.split('.')
    
    def _build_dn(self, zone: str, partition: str = "DomainDNSZones", node: Optional[str] = None) -> str:
        """Build distinguished name for ADIDNS zone/node."""
        # Build the base path for the partition
        if partition == "System":
            base = f"CN={partition}"
        else:
            base = f"DC={partition}"
        
        # Add domain components to base
        for dc in self.domain_parts:
            base += f",DC={dc}"
        
        # Build the DNS path
        if node:
            dns_path = f"DC={node},DC={zone},CN=MicrosoftDNS,{base}"
        else:
            dns_path = f"DC={zone},CN=MicrosoftDNS,{base}"
        
        return dns_path
    

    def get_node_attribute(self, node: str, attribute: str = 'dnsRecord', 
                          zone: Optional[str] = None, partition: str = "DomainDNSZones") -> Optional[bytes]:
        """Get a specific attribute from an ADIDNS node.
        
        Args:
            node: Node name (e.g., '*' for wildcard)
            attribute: Attribute to retrieve (default: dnsRecord)
            zone: DNS zone (defaults to domain)
            partition: AD partition (DomainDNSZones, ForestDNSZones, System)
            
        Returns:
            Raw attribute value or None if not found
        """
        if not zone:
            zone = self.domain
        
        dn = self._build_dn(zone, partition, node)
        
        try:
            self.ldap.connection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                attributes=[attribute],
                search_scope=ldap3.BASE
            )
            
            if not self.ldap.connection.entries:
                return None
            
            entry = self.ldap.connection.entries[0]
            return entry[attribute].value if hasattr(entry, attribute) else None
            
        except Exception:
            return None
    

    def check_wildcard_record(self, zone: Optional[str] = None, 
                              partition: str = "DomainDNSZones") -> bool:
        """Check if wildcard record exists in ADIDNS zone.
        
        Returns:
            True if wildcard record exists, False otherwise
        """
        result = self.get_node_attribute('*', 'dnsRecord', zone, partition)
        return result is not None
    
