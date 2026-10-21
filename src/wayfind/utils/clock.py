"""Clock-skew check against the DC NTP service. Kerberos fails beyond ~5 minutes."""

from __future__ import annotations

import socket
import struct
import time
from typing import Optional, Tuple


NTP_UNIX_DELTA = 2208988800
SKEW_WARN_SECONDS = 300


def ntp_offset_seconds(dc_ip: str, timeout: float = 3.0) -> Optional[float]:
    """Return local_time - dc_time in seconds, or None on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        packet = b"\x1b" + 47 * b"\x00"
        sock.sendto(packet, (dc_ip, 123))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) < 48:
            return None
        transmit = struct.unpack("!12I", data[:48])[10]
        dc_unix = transmit - NTP_UNIX_DELTA
        return time.time() - dc_unix
    except OSError:
        return None


def kerberos_should_skip(offset_seconds: Optional[float], dc_ip: str) -> Tuple[bool, str]:
    """Return (skip, message). >5 minute skew skips TGS/PKINIT/Kerberos."""
    if offset_seconds is None:
        return False, ""
    if abs(offset_seconds) > SKEW_WARN_SECONDS:
        minutes = abs(offset_seconds) / 60.0
        msg = (
            f"Clock skew vs DC is {minutes:.1f} min; skip Kerberos/TGS/PKINIT. "
            f"Align with: ntpdate {dc_ip}"
        )
        return True, msg
    return False, ""


def warn_clock_skew(logger, dc_ip: str) -> Optional[float]:
    offset = ntp_offset_seconds(dc_ip)
    skip, msg = kerberos_should_skip(offset, dc_ip)
    if offset is None:
        logger.log_verbose(f"NTP not reachable on {dc_ip}:123, skip clock check")
        return None
    if skip:
        logger.warning(f"[!] {msg}")
    else:
        logger.success(f"[+] Clock skew vs DC NTP is {offset:.1f}s")
    return offset
