"""Domain controller reachability and selection helpers."""

import socket
from typing import Dict, List, Optional


def check_dc_reachable(dc_ip: str, ports: list = [389, 636, 445, 88]) -> bool:
    """Check if the domain controller is reachable on any of the given TCP ports."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((dc_ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


def select_reachable_dc(dcs: List[Dict], fallback: Optional[str] = None,
                        port: int = 445, logger=None) -> Optional[str]:
    """Return the dNSHostName of the first DC reachable on the given TCP port.

    Probes each DC's ``dNSHostName`` and returns the first one that accepts a
    connection on ``port`` (445/SMB by default). This avoids a single dead DC
    at the top of the LDAP result set killing checks that other healthy DCs
    could answer.

    If no DC exposes a ``dNSHostName``, ``fallback`` is returned. If none of
    the DCs are reachable, the first DC's hostname is returned so the caller
    still surfaces a meaningful connection error.
    """
    hostnames = [dc.get('dNSHostName') for dc in dcs if dc.get('dNSHostName')]
    if not hostnames:
        return fallback

    for host in hostnames:
        if check_dc_reachable(host, ports=[port]):
            if logger and host != hostnames[0]:
                logger.info(f"[*] Using reachable DC {host} (port {port})")
            return host
        if logger:
            logger.warning(f"[!] DC {host} not reachable on port {port}, trying next")

    if logger:
        logger.warning(f"[!] No domain controller reachable on port {port}, using {hostnames[0]}")
    return hostnames[0]
