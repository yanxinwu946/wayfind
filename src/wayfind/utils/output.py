"""Output directory management utilities."""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .logger import get_logger

_LAST_LOGON_FIELDS = {'lastLogon', 'lastLogonTimestamp'}
_NO_LOGON_RECORDED = 'No last logon'


def create_output_directory(
    domain: str,
    base_path: Optional[Path] = None
) -> Dict[str, Path]:
    """
    Create output directory structure matching PowerShell script format.
    
    Args:
        domain: The domain name (e.g., 'contoso.com')
        base_path: Optional base path, defaults to current directory
        
    Returns:
        Dictionary with paths to created directories
    """
    logger = get_logger()
    
    date_str = datetime.now().strftime('%Y-%m-%d')
    domain_clean = domain.replace('.', '_')
    
    if base_path:
        output_dir = base_path / f"{domain_clean}-{date_str}"
    else:
        output_dir = Path.cwd() / f"{domain_clean}-{date_str}"
    
    # Create subdirectories
    findings_path = output_dir / "findings"
    data_path = output_dir / "data"
    checks_path = output_dir / "checks"
    
    paths = {
        "root": output_dir,
        "findings": findings_path,
        "data": data_path,
        "checks": checks_path
    }
    
    # Create directories
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
        logger.log_verbose(f"Created directory {path}")
    
    logger.info(f"[+] Output will be written in {output_dir}")
    
    return paths


def write_file(content: str, filepath: Path, logger=None) -> bool:
    """
    Write content to file with logging.
    
    Args:
        content: Content to write
        filepath: Target file path
        logger: Optional logger instance
        
    Returns:
        True if successful, False otherwise
    """
    if logger is None:
        logger = get_logger()
    
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.write(f"Writing to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to write {filepath}: {e}")
        return False


def _format_csv_value(header: str, value):
    if header in _LAST_LOGON_FIELDS and value == []:
        return _NO_LOGON_RECORDED
    return value


def write_csv(data: list, filepath: Path, headers: Optional[list] = None) -> bool:
    """
    Write data to CSV file.
    
    Args:
        data: List of dictionaries or lists
        filepath: Target file path
        headers: Optional column headers
        
    Returns:
        True if successful, False otherwise
    """
    import csv
    
    logger = get_logger()
    
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if data and isinstance(data[0], dict):
                if headers is None:
                    # Use the union of keys across all rows (preserving first-seen
                    # order) so heterogeneous dicts don't trip DictWriter.
                    headers = list(data[0].keys())
                    for row in data[1:]:
                        for key in row.keys():
                            if key not in headers:
                                headers.append(key)
                rows = [
                    {header: _format_csv_value(header, row.get(header)) for header in headers}
                    for row in data
                ]
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
            else:
                writer = csv.writer(f)
                if headers:
                    writer.writerow(headers)
                writer.writerows(data)
        
        logger.write(f"Writing to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to write CSV {filepath}: {e}")
        return False


def write_lines(lines: list, filepath: Path) -> bool:
    """
    Write list of lines to text file.
    
    Args:
        lines: List of strings to write
        filepath: Target file path
        
    Returns:
        True if successful, False otherwise
    """
    logger = get_logger()
    
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(str(line) for line in lines))
        logger.write(f"Writing to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to write {filepath}: {e}")
        return False
