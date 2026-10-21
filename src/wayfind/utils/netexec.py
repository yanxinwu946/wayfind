"""Helpers for running and reporting NetExec checks."""

from subprocess import CompletedProcess


def report_netexec_failure(logger, label: str, result: CompletedProcess) -> bool:
    """Log a concise non-verbose error when a NetExec command fails."""
    if result.returncode == 0:
        return False

    summary = _extract_error_summary((result.stderr or '') + '\n' + (result.stdout or ''))
    if summary:
        logger.error(f"[-] NetExec error: {summary}")
    else:
        logger.error(f"[-] {label} failed with code {result.returncode}")
        logger.warning("[!] Run with --verbose to see raw NetExec output")

    return True


def _extract_error_summary(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]

    for line in lines:
        if 'netexec: error:' in line:
            return _trim_choices(line.split('netexec: error:', 1)[1].strip())

    for line in lines:
        lower = line.lower()
        if 'invalid choice:' in lower or 'error:' in lower:
            return _trim_choices(line)

    for line in lines:
        if line.startswith('[-]'):
            return line

    return ''


def _trim_choices(line: str) -> str:
    return line.split(' (choose from ', 1)[0]
