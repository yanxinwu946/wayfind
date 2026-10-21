"""Core configuration and constants for wayfind."""

from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

# Domain functional levels mapping
# Note: Windows Server 2019 and 2022 use the same functional level as 2016 (level 7)
# See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels
DOMAIN_FUNCTIONAL_LEVELS = {
    0: "Windows 2000 native",
    1: "Windows 2003 interim",
    2: "Windows 2003",
    3: "Windows 2008",
    4: "Windows 2008 R2",
    5: "Windows 2012",
    6: "Windows 2012 R2",
    7: "Windows 2016",
    10: "Windows 2025"
}

# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-32-578": "Hyper-V Administrators",
}

# Relative identifiers for domain-specific groups
DOMAIN_RIDS = {
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

LDAP_PORT = 389
LDAPS_PORT = 636
SMB_PORT = 445

DEFAULT_OUTPUT_DIRS = {
    "findings": "findings",
    "checks": "checks",
    "data": "data"
}

ADMIN_THRESHOLD_PERCENTAGE = 5.0

# EOL Operating System patterns and versions
EOL_OS_PATTERNS = [
    'Windows 7',
    'Windows 8',
    'Windows Server 2008',
    'Windows Server 2003',
    'Windows Server 2012',
    'Windows Server 2016',
    'XP'
]

# Windows 10 End of Service versions (build numbers)
WIN10_EOS_VERSIONS = [
    '10240', '10586', '14393', '15063', '16299', '17134', '17763',
    '18362', '18363', '19041', '19042', '19043', '19044', '19045'
]
WIN10_VERSION_NAMES = {
    '10240': '1507',
    '10586': '1511',
    '14393': '1607',
    '15063': '1703',
    '16299': '1709',
    '17134': '1803',
    '17763': '1809',
    '18362': '1903',
    '18363': '1909',
    '19041': '2004',
    '19042': '20H2',
    '19043': '21H1',
    '19044': '21H2',
    '19045': '22H2'
}

WIN10_LONG_TERM_SUPPORT = [
    {
        'build': '19044',
        'markers': ['IoT Enterprise LTSC'],
        'end_date': '2032-01-13',
    },
    {
        'build': '19044',
        'markers': ['LTSC'],
        'end_date': '2027-01-12',
    },
    {
        'build': '17763',
        'markers': ['LTSC'],
        'end_date': '2029-01-09',
    },
    {
        'build': '14393',
        'markers': ['LTSB'],
        'end_date': '2026-10-13',
    },
]

# Windows 11 End of Service versions (build numbers)
WIN11_EOS_VERSIONS = ['22000', '22621', '22631']

WIN11_VERSION_NAMES = {
    '22000': '21H2',
    '22621': '22H2',
    '22631': '23H2',
    '26100': '24H2',
    '26200': '25H2',
    '28000': '26H1'
}

# SYSVOL password search keywords (checked in XML files under Policies)
SYSVOL_PASSWORD_KEYWORDS = [
    'password',
    'pwd',
    'pass',
    'secret',
    'credential',
    'token',
    'auth',
    'wachtwoord',
    'ww',
    'authentication'
]

# NETLOGON password search keywords (checked in all files)
NETLOGON_PASSWORD_KEYWORDS = [
    'pass',
    'password',
    'pwd',
    'secret',
    'credential',
    'token',
    'auth',
    'wachtwoord',
    'ww',
    'authentication'
]
