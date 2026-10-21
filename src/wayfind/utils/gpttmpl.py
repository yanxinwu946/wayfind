"""GptTmpl.inf parser utility.

GptTmpl.inf is a UTF-16LE INI file used by the Security Configuration Engine
in Group Policy. It stores settings for password policy, Kerberos policy,
audit policy, security options (registry values), and more.
"""

import configparser
from typing import Dict


def parse_gpttmpl_inf(content: bytes) -> Dict[str, Dict[str, str]]:
    r"""Parse a GptTmpl.inf file and return a dict of section -> key -> value.

    GptTmpl.inf is typically UTF-16LE encoded with a BOM. This function
    handles common encodings and returns a nested dict keyed by INI section.

    Security Options are stored under [Registry Values] as:
      MACHINE\path\to\key\ValueName=Type,Data
    where Type 4 = REG_DWORD.

    Args:
        content: Raw bytes of the GptTmpl.inf file.

    Returns:
        Dict mapping section names to dicts of key-value pairs.
        Returns empty dict on parse failure.
    """
    result = {}

    try:
        # Decode content (usually UTF-16 LE with BOM)
        try:
            text = content.decode('utf-16-le')
        except UnicodeDecodeError:
            try:
                text = content.decode('utf-16')
            except UnicodeDecodeError:
                text = content.decode('utf-8', errors='ignore')

        # Remove BOM if present
        if text.startswith('\ufeff'):
            text = text[1:]

        # Parse as INI file
        config = configparser.ConfigParser()
        config.read_string(text)

        for section in config.sections():
            result[section] = dict(config.items(section))

    except Exception:
        pass

    return result
