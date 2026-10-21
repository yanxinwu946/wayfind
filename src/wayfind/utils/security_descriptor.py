"""Security Descriptor parsing utilities.

Parses Windows security descriptor binary format to extract ACEs and check permissions.
"""

import struct
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import IntFlag


class AceType(IntFlag):
    """ACE type constants."""
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06



class AccessMask(IntFlag):
    """Active Directory access rights."""
    CREATE_CHILD = 0x00000001
    DELETE_CHILD = 0x00000002
    LIST_CHILDREN = 0x00000004
    SELF_WRITE = 0x00000008
    READ_PROPERTY = 0x00000010
    WRITE_PROPERTY = 0x00000020
    DELETE_TREE = 0x00000040
    LIST_OBJECT = 0x00000080
    CONTROL_ACCESS = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


@dataclass
class ACE:
    """Access Control Entry."""
    ace_type: int
    ace_flags: int
    access_mask: int
    sid: bytes
    sid_string: str
    
    def has_right(self, right: int) -> bool:
        """Check if this ACE grants a specific right."""
        # GENERIC_ALL implies all rights
        if self.access_mask & AccessMask.GENERIC_ALL:
            return True
        return bool(self.access_mask & right)
    
    def is_allowed(self) -> bool:
        """Check if this is an allow ACE."""
        return self.ace_type == AceType.ACCESS_ALLOWED_ACE_TYPE or \
               self.ace_type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
    
    def is_denied(self) -> bool:
        """Check if this is a deny ACE."""
        return self.ace_type == AceType.ACCESS_DENIED_ACE_TYPE or \
               self.ace_type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE


@dataclass
class SecurityDescriptor:
    """Parsed security descriptor."""
    revision: int
    control: int
    owner_sid: str
    group_sid: str
    aces: List[ACE]

    def can_create_child(self, sid: str) -> bool:
        """Check if a SID has CreateChild permission."""
        # Check for explicit deny first
        for ace in self.aces:
            if ace.sid_string == sid and ace.is_denied():
                if ace.has_right(AccessMask.CREATE_CHILD) or ace.has_right(AccessMask.GENERIC_ALL):
                    return False
        
        # Check for allow
        for ace in self.aces:
            if ace.sid_string == sid and ace.is_allowed():
                if ace.has_right(AccessMask.CREATE_CHILD) or ace.has_right(AccessMask.GENERIC_ALL):
                    return True
        
        return False


def sid_to_string(sid_bytes: bytes) -> str:
    """Convert binary SID to string representation (e.g., S-1-5-11)."""
    if len(sid_bytes) < 8:
        return ""
    
    # Parse revision
    revision = sid_bytes[0]
    
    # Parse authority (6 bytes, big endian)
    authority = int.from_bytes(sid_bytes[2:8], 'big')
    
    # Parse sub-authorities
    sub_authority_count = sid_bytes[1]
    sub_authorities = []
    
    offset = 8
    for _ in range(sub_authority_count):
        if offset + 4 > len(sid_bytes):
            break
        sub_auth = int.from_bytes(sid_bytes[offset:offset+4], 'little')
        sub_authorities.append(sub_auth)
        offset += 4
    
    # Build SID string
    sid_str = f"S-{revision}-{authority}"
    for sub_auth in sub_authorities:
        sid_str += f"-{sub_auth}"
    
    return sid_str


def parse_security_descriptor(data: bytes) -> Optional[SecurityDescriptor]:
    """Parse a security descriptor binary blob.
    
    Args:
        data: Raw security descriptor bytes
        
    Returns:
        Parsed SecurityDescriptor or None if invalid
    """
    if len(data) < 20:
        return None
    
    try:
        # SECURITY_DESCRIPTOR structure
        # Offset 0: Revision (1 byte)
        # Offset 1: Sbz1 (1 byte, padding)
        # Offset 2: Control (2 bytes)
        revision = data[0]
        control = int.from_bytes(data[2:4], 'little')
        
        # Offsets to owner SID, group SID, DACL
        owner_offset = int.from_bytes(data[4:8], 'little')
        group_offset = int.from_bytes(data[8:12], 'little')
        sacl_offset = int.from_bytes(data[12:16], 'little')
        dacl_offset = int.from_bytes(data[16:20], 'little')
        
        # Extract owner SID
        owner_sid = ""
        if owner_offset > 0 and owner_offset < len(data):
            owner_sid = sid_to_string(data[owner_offset:])
        
        # Extract group SID
        group_sid = ""
        if group_offset > 0 and group_offset < len(data):
            group_sid = sid_to_string(data[group_offset:])
        
        # Parse DACL (Discretionary Access Control List)
        aces = []
        if dacl_offset > 0 and dacl_offset < len(data):
            aces = parse_acl(data[dacl_offset:])
        
        return SecurityDescriptor(
            revision=revision,
            control=control,
            owner_sid=owner_sid,
            group_sid=group_sid,
            aces=aces
        )
        
    except Exception:
        return None


def parse_acl(data: bytes) -> List[ACE]:
    """Parse an Access Control List (ACL) structure.
    
    Args:
        data: Raw ACL bytes
        
    Returns:
        List of parsed ACEs
    """
    if len(data) < 8:
        return []
    
    try:
        # ACL structure:
        # Offset 0: AclRevision (1 byte)
        # Offset 1: Sbz1 (1 byte)
        # Offset 2: AclSize (2 bytes)
        # Offset 4: AceCount (2 bytes)
        # Offset 6: Sbz2 (2 bytes)
        
        ace_count = int.from_bytes(data[4:6], 'little')
        acl_size = int.from_bytes(data[2:4], 'little')
        
        aces = []
        offset = 8  # Start after ACL header
        
        for _ in range(ace_count):
            if offset + 4 > len(data):
                break
            
            # ACE structure:
            # Offset 0: AceType (1 byte)
            # Offset 1: AceFlags (1 byte)
            # Offset 2: AceSize (2 bytes)
            
            ace_type = data[offset]
            ace_flags = data[offset + 1]
            ace_size = int.from_bytes(data[offset+2:offset+4], 'little')
            
            if offset + ace_size > len(data):
                break
            
            ace_data = data[offset:offset + ace_size]
            
            # Parse ACE header (4 bytes) + Access Mask (4 bytes) + SID
            access_mask = int.from_bytes(ace_data[4:8], 'little')
            
            # SID starts at offset 8
            sid_data = ace_data[8:]
            sid_str = sid_to_string(sid_data)
            
            aces.append(ACE(
                ace_type=ace_type,
                ace_flags=ace_flags,
                access_mask=access_mask,
                sid=sid_data,
                sid_string=sid_str
            ))
            
            offset += ace_size
        
        return aces
        
    except Exception:
        return []


# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-5-11": "Authenticated Users",
    "S-1-5-7": "Anonymous",
    "S-1-1-0": "Everyone",
    "S-1-5-18": "System",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicator",
}
