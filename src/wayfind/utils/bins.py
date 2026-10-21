"""Resolve wrapper binaries. Prefer Kali names, then upstream names."""

from functools import lru_cache
import shutil
from typing import Optional, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.target import Target


@lru_cache(maxsize=1)
def nxc_bin() -> str:
    for name in ("nxc", "netexec"):
        path = shutil.which(name)
        if path:
            return path
    raise FileNotFoundError("nxc/netexec not found in PATH")


@lru_cache(maxsize=1)
def certipy_bin() -> Optional[str]:
    for name in ("certipy", "certipy-ad"):
        path = shutil.which(name)
        if path:
            return path
    return None


@lru_cache(maxsize=1)
def bloodhound_python_bin() -> Optional[str]:
    for name in ("bloodhound-python", "bloodhound.py"):
        path = shutil.which(name)
        if path:
            return path
    return None


@lru_cache(maxsize=1)
def bhcli_bin() -> Optional[str]:
    return shutil.which("bhcli")


def apply_socks_env(socks: Optional[str]) -> None:
    """nxc has no --socks; export ALL_PROXY so agent-supplied SOCKS reaches libs."""
    import os
    if not socks:
        return
    proxy = socks if "://" in socks else f"socks5://{socks}"
    os.environ.setdefault("ALL_PROXY", proxy)
    os.environ.setdefault("all_proxy", proxy)
    os.environ.setdefault("SOCKS_PROXY", proxy)


def nxc_cmd_from_target(
    target: "Target",
    protocol: str,
    extra: Optional[Sequence[str]] = None,
    host: Optional[str] = None,
    auth: bool = True,
):
    """Build an nxc command from Target. DNS is a flag, never a system change."""
    cmd = [nxc_bin(), protocol, str(host or target.dc_ip)]
    if target.domain:
        cmd.extend(["-d", target.domain])
    if auth:
        if target.username:
            cmd.extend(["-u", target.username])
        if target.pfx:
            cmd.extend(["--pfx-cert", target.pfx])
        elif target.kerberos:
            cmd.append("-k")
            if target.ccache:
                cmd.append("--use-kcache")
            if target.dc_host:
                cmd.extend(["--kdcHost", target.dc_host])
        elif target.hashes:
            cmd.extend(["-H", target.hashes])
        elif target.password is not None:
            cmd.extend(["-p", target.password])
    cmd.extend(["--dns-server", target.dns_server])
    if extra:
        cmd.extend(list(extra))
    return cmd
