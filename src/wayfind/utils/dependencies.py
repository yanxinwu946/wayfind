"""External tool availability (nxc / certipy). DNS is --dns-server, never a system change."""

import json
import subprocess
import re
import shlex
import shutil
from pathlib import Path
from typing import Optional, List

from .logger import get_logger

def check_certipy_available() -> bool:
    """
    Check if certipy is available on the system.
    
    Returns:
        True if certipy is available, False otherwise
    """
    logger = get_logger()
    
    # Check for 'certipy' command
    from .bins import certipy_bin
    path = certipy_bin()
    if path:
        logger.log_verbose(f"[+] certipy is available: {path}")
        return True

    logger.warning("[!] certipy/certipy-ad is not installed or not in PATH")
    logger.info("[*] Install with: pipx install certipy-ad")
    return False


def check_netexec_available() -> bool:
    """
    Check if netexec (nxc) is available on the system.
    
    Returns:
        True if netexec is available, False otherwise
    """
    logger = get_logger()
    
    # Check for 'nxc' command (netexec binary name)
    if shutil.which('nxc') or shutil.which('netexec'):
        logger.log_verbose("[+] netexec is available")
        return True
    
    logger.error("[-] netexec (nxc) is not installed or not in PATH")
    logger.info("[*] Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
    return False


def check_netexec_modules_available(protocol: str, modules: List[str], required: bool = False) -> bool:
    """
    Check whether installed NetExec exposes required modules for a protocol.

    Args:
        protocol: NetExec protocol, e.g. smb or mssql.
        modules: Module names required by wayfind checks.
        required: If True, log missing modules as errors.

    Returns:
        True if all requested modules are present or module listing cannot be
        verified, False when required modules are missing.
    """
    logger = get_logger()
    netexec_cmd = shutil.which('netexec') or shutil.which('nxc')

    if not netexec_cmd:
        return check_netexec_available()

    try:
        result = subprocess.run(
            [netexec_cmd, protocol, '-L'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"[!] Could not verify NetExec {protocol} modules: {e}")
        return True

    if result.returncode != 0:
        logger.warning(f"[!] Could not list NetExec {protocol} modules")
        logger.debug(f"netexec {protocol} -L stdout:\n{result.stdout}")
        logger.debug(f"netexec {protocol} -L stderr:\n{result.stderr}")
        return True

    available = set()
    for line in (result.stdout or '').splitlines():
        match = re.match(r'^\[\*\]\s+(\S+)', line.strip())
        if match:
            available.add(match.group(1))

    missing = [module for module in modules if module not in available]
    if not missing:
        logger.log_verbose(f"[+] NetExec {protocol} modules available: {', '.join(modules)}")
        return True

    level = logger.error if required else logger.warning
    level(f"[!] Missing NetExec {protocol} module(s): {', '.join(missing)}")
    logger.info(f"[*] NetExec version: {_get_netexec_version(netexec_cmd)}")
    if protocol == 'smb' and 'enum_cve' in missing:
        logger.info("[*] enum_cve is currently only available in NetExec main after commit ac735513 (2026-03-12)")
    logger.info("[*] Install or upgrade NetExec from the upstream main branch to enable these checks")
    return False


def _get_netexec_version(netexec_cmd: str) -> str:
    try:
        result = subprocess.run(
            [netexec_cmd, '--version'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"

    version = (result.stdout or result.stderr or '').strip()
    return version or "unknown"


def check_netexec_bloodhound_ce_available(required: bool = False) -> bool:
    """
    Check whether NetExec's Python environment has BloodHound CE support.

    Args:
        required: If True, log a hard error message. If False, warn and allow
            callers to skip only BloodHound collection.

    Returns:
        True if BloodHound CE support appears healthy or cannot be verified,
        False when a broken package state is detected.
    """
    logger = get_logger()
    netexec_cmd = shutil.which('netexec') or shutil.which('nxc')

    if not netexec_cmd:
        return check_netexec_available()

    python_path = _python_from_console_script(netexec_cmd)
    if not python_path:
        logger.warning(f"[!] Could not verify BloodHound CE support for {netexec_cmd}")
        logger.info("[*] NetExec executable is not a standard Python console script")
        return True

    packages = _query_python_packages(python_path, ['bloodhound-ce', 'bloodhound'])
    if packages is None:
        logger.warning(f"[!] Could not inspect NetExec Python environment: {python_path}")
        return True

    ce_version = packages.get('bloodhound-ce')
    legacy_version = packages.get('bloodhound')

    if ce_version and not legacy_version:
        logger.log_verbose(f"[+] bloodhound-ce {ce_version} is available for NetExec")
        return True

    level = logger.error if required else logger.warning
    level("[!] NetExec BloodHound CE package check failed")
    logger.info(f"[*] NetExec executable: {netexec_cmd}")
    logger.info(f"[*] NetExec Python: {python_path}")

    if not ce_version:
        level("[-] bloodhound-ce is not installed in NetExec's Python environment")
    if legacy_version:
        level(f"[-] legacy bloodhound package is installed ({legacy_version})")

    if _looks_like_pipx_netexec(netexec_cmd, python_path):
        logger.info("[*] Fix with:")
        logger.info("    pipx runpip netexec uninstall -y bloodhound")
        logger.info("    pipx inject netexec bloodhound-ce --force")
    else:
        logger.info("[*] This NetExec install is not managed by pipx.")
        logger.info(
            "[*] Remove the legacy bloodhound package and install bloodhound-ce "
            "in the Python environment shown above."
        )

    return False


def _python_from_console_script(executable: str) -> Optional[str]:
    """Return the Python interpreter from a console-script shebang."""
    try:
        with open(executable, 'rb') as f:
            first_line = f.readline(256).decode('utf-8', errors='replace').strip()
    except OSError:
        return None

    if not first_line.startswith('#!'):
        return None

    try:
        parts = shlex.split(first_line[2:])
    except ValueError:
        return None

    if not parts:
        return None

    command = Path(parts[0]).name
    if command == 'env' and len(parts) > 1:
        candidate = parts[1]
        if 'python' in Path(candidate).name:
            return shutil.which(candidate)
        return None

    if 'python' in command:
        return parts[0]

    return None


def _query_python_packages(python_path: str, package_names: List[str]) -> Optional[dict]:
    """Query package versions from a specific Python interpreter."""
    package_names_literal = repr(package_names)
    script = f"""
import json
from importlib.metadata import PackageNotFoundError, version

packages = {{}}
for name in {package_names_literal}:
    try:
        packages[name] = version(name)
    except PackageNotFoundError:
        packages[name] = None
print(json.dumps(packages))
"""

    try:
        result = subprocess.run(
            [python_path, '-c', script],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _looks_like_pipx_netexec(executable: str, python_path: str) -> bool:
    combined = f"{executable} {python_path}"
    return 'pipx' in combined and 'venvs/netexec' in combined
