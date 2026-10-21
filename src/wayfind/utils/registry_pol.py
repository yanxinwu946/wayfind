"""Registry.pol file parsing utilities."""

import struct
from typing import List, Tuple


def parse_pol_file(content: bytes) -> List[Tuple[str, str, int, int, bytes]]:
    """
    Parse a Windows Group Policy Registry.pol file.
    
    Registry.pol format (all strings UTF-16LE):
    - Header: 4 bytes signature (PReg) + 4 bytes version
    - Entries: [key;value;type;size;data]
    
    Args:
        content: Raw bytes of the Registry.pol file
        
    Returns:
        List of tuples: (key, value_name, type, size, data)
        - key: Registry key path (e.g., "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate")
        - value_name: Value name within the key (e.g., "WUServer")
        - type: Registry value type (1=REG_SZ, 4=REG_DWORD, etc.)
        - size: Size of the data in bytes
        - data: Raw bytes of the value data
    """
    entries = []
    
    if len(content) < 8:
        return entries
    
    signature = content[:4]
    if signature != b'PReg':
        return entries
    
    # UTF-16LE markers
    OPEN_BRACKET = b'[\x00'
    CLOSE_BRACKET = b']\x00'
    SEMICOLON = b';\x00'
    NULL_TERM = b'\x00\x00'
    
    offset = 8
    while offset < len(content) - 2:
        # Find opening bracket
        if content[offset:offset+2] != OPEN_BRACKET:
            offset += 1
            continue
        
        offset += 2  # Skip [
        
        try:
            # Find key (null-terminated UTF-16LE string)
            key_end = content.find(NULL_TERM, offset)
            if key_end == -1:
                break
            # Ensure we're on an even boundary for UTF-16
            if (key_end - offset) % 2 == 1:
                key_end += 1
            key = content[offset:key_end].decode('utf-16-le', errors='ignore')
            offset = key_end + 2  # Skip null terminator
            
            # Skip semicolon
            if content[offset:offset+2] != SEMICOLON:
                continue
            offset += 2
            
            # Find value name
            value_end = content.find(NULL_TERM, offset)
            if value_end == -1:
                break
            if (value_end - offset) % 2 == 1:
                value_end += 1
            value_name = content[offset:value_end].decode('utf-16-le', errors='ignore')
            offset = value_end + 2
            
            # Skip semicolon
            if content[offset:offset+2] != SEMICOLON:
                continue
            offset += 2
            
            # Read type (4 bytes little-endian DWORD)
            if offset + 4 > len(content):
                break
            reg_type = struct.unpack('<I', content[offset:offset+4])[0]
            offset += 4
            
            # Skip semicolon
            if content[offset:offset+2] != SEMICOLON:
                continue
            offset += 2
            
            # Read size (4 bytes little-endian DWORD)
            if offset + 4 > len(content):
                break
            data_size = struct.unpack('<I', content[offset:offset+4])[0]
            offset += 4
            
            # Skip semicolon
            if content[offset:offset+2] != SEMICOLON:
                continue
            offset += 2
            
            # Read data
            if offset + data_size > len(content):
                break
            data = content[offset:offset+data_size]
            offset += data_size
            
            # Skip closing bracket
            if content[offset:offset+2] == CLOSE_BRACKET:
                offset += 2
            
            entries.append((key, value_name, reg_type, data_size, data))
            
        except Exception:
            offset += 1
            continue
    
    return entries
