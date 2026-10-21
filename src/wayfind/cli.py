"""Wayfind Tool - Main entry point."""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from typer.core import TyperGroup

from . import __version__
from .config import DOMAIN_FUNCTIONAL_LEVELS
from .core.exceptions import WayfindError
from .core.loot import LootStore
from .core.profiles import DEFAULT_PROFILE, expand_selector, format_profile_help, normalize_profile
from .core.session import Session
from .core.target import Target
from .utils.logger import get_logger, set_verbose
from .utils.output import create_output_directory, write_lines
from .utils.ldap import LDAPConnection
from .utils.ip_exclusions import IPExclusions
from .utils.targets import TargetScope
from .utils.dependencies import (
    check_netexec_available,
    check_netexec_bloodhound_ce_available,
    check_netexec_modules_available,
    check_certipy_available,
)
from .utils.clock import warn_clock_skew
from .enumeration import ADEnumerator
from .checks import SecurityChecker


class WayfindGroup(TyperGroup):
    def collect_usage_pieces(self, ctx: typer.Context) -> list[str]:
        return [self.options_metavar] if self.options_metavar else []


app = typer.Typer(
    name="wayfind",
    help="Active Directory domain scan",
    add_completion=False,
    pretty_exceptions_enable=False,
    cls=WayfindGroup,
    context_settings={"help_option_names": []},
)


def _opt(*decls: str, help: str, panel: str, hidden: bool = False, **kwargs):
    return typer.Option(*decls, help=help, rich_help_panel=panel, hidden=hidden, **kwargs)


def _emit_help(ctx: typer.Context, full: bool = False) -> None:
    revealed = []
    if full:
        for param in ctx.command.params:
            if getattr(param, "hidden", False):
                param.hidden = False
                revealed.append(param)
    try:
        text = ctx.get_help()
        if text:
            typer.echo(text, color=ctx.color)
    finally:
        for param in revealed:
            param.hidden = True


def _help_callback(ctx: typer.Context, param: typer.CallbackParam, value: int):
    if ctx.resilient_parsing or not value:
        return
    _emit_help(ctx, full=value >= 2)
    raise typer.Exit()


NETEXEC_MODULE_REQUIREMENTS = {
    'cve': {'smb': ['webdav', 'enum_cve']},
    'network': {'smb': ['webdav', 'enum_cve']},
    'dc-vulns': {'smb': ['nopac', 'zerologon']},
    'sql': {'mssql': ['enum_links', 'enum_impersonate']},
}


def _version_callback(value: bool):
    if value:
        print(f"wayfind {__version__}")
        raise typer.Exit(0)


def _check_netexec_module_requirements(check_names: List[str], required: bool = False) -> bool:
    requirements = {}
    for check_name in check_names:
        for protocol, modules in NETEXEC_MODULE_REQUIREMENTS.get(check_name, {}).items():
            requirements.setdefault(protocol, set()).update(modules)

    ok = True
    for protocol, modules in requirements.items():
        if not check_netexec_modules_available(protocol, sorted(modules), required=required):
            ok = False
    return ok


def _apply_loot(as_identity: Optional[str], loot_path: Optional[Path],
                username: Optional[str], password: Optional[str], hashes: Optional[str]):
    logger = get_logger()
    store = None
    if loot_path:
        store = LootStore.load(loot_path)
    if as_identity:
        if store is None:
            logger.error("[-] --as requires --loot pointing at loot.json")
            raise typer.Exit(1)
        ident = store.get(as_identity)
        if ident is None:
            logger.error(f"[-] identity {as_identity} not in loot")
            raise typer.Exit(1)
        username = ident.username
        if ident.password:
            password = ident.password
        if ident.hashes:
            hashes = ident.hashes
        logger.info(f"[*] Using looted identity {username} from {loot_path}")
    return store, username, password, hashes


def _build_target(
    domain: str,
    server: str,
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    dns: Optional[str],
    aes: Optional[str],
    ccache: Optional[str],
    pfx: Optional[str],
    use_ldaps: bool,
    dc_host: Optional[str] = None,
    socks: Optional[str] = None,
    profile: str = DEFAULT_PROFILE,
    allow_empty_secret: bool = False,
) -> Target:
    logger = get_logger()
    if not domain:
        logger.error("[-] Missing required option: --domain / -d")
        raise typer.Exit(1)
    if not server:
        logger.error("[-] Missing required option: --dc-ip / -dc")
        raise typer.Exit(1)
    if not username and profile != "recon":
        logger.error("[-] Missing required option: --username / -u")
        raise typer.Exit(1)
    if not allow_empty_secret and not password and not hashes and not kerberos and not ccache and not pfx:
        if profile != "recon":
            logger.error("[-] Need -p, -H, -k/--ccache, --pfx, or --as with --loot")
            raise typer.Exit(1)
    if ccache:
        os.environ["KRB5CCNAME"] = ccache
    return Target(
        domain=domain,
        dc_ip=server,
        username=username or "",
        password=password,
        hashes=hashes,
        aes=aes,
        kerberos=kerberos or bool(ccache),
        ccache=ccache,
        pfx=pfx,
        dns=dns,
        dc_host=dc_host,
        socks=socks,
        use_ldaps=use_ldaps,
    )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    domain: Annotated[Optional[str], _opt("--domain", "-d", help="Domain", panel="Target")] = None,
    server: Annotated[Optional[str], _opt("--dc-ip", "-dc", "--server", help="Domain controller IP", panel="Target")] = None,
    dc_host: Annotated[Optional[str], _opt("--dc-host", help="DC hostname", panel="Target")] = None,
    use_ldaps: Annotated[bool, _opt("--ldaps", help="Use LDAPS", panel="Target")] = False,
    dns: Annotated[Optional[str], _opt("--dns", help="DNS for tools (default: DC IP)", panel="Target")] = None,
    username: Annotated[Optional[str], _opt("--username", "-u", help="Username", panel="Auth")] = None,
    password: Annotated[Optional[str], _opt("--password", "-p", help="Password", panel="Auth")] = None,
    hashes: Annotated[Optional[str], _opt("--hashes", "-H", help="NTLM hash (NT or LM:NT)", panel="Auth")] = None,
    kerberos: Annotated[bool, _opt("--kerberos", "-k", help="Kerberos", panel="Auth")] = False,
    profile: Annotated[str, _opt("--profile", help="recon | audit | offensive", panel="Scan")] = DEFAULT_PROFILE,
    check: Annotated[Optional[str], _opt("--check", "-c", help="Check or category", panel="Scan")] = None,
    skip_bloodhound: Annotated[bool, _opt("--skip-bloodhound", help="Skip BloodHound", panel="Scan")] = False,
    list_checks: Annotated[bool, _opt("--list", "-L", help="List checks and profiles", panel="Scan")] = False,
    output: Annotated[Optional[Path], _opt("--output", "-o", help="Output directory", panel="Output")] = None,
    verbose: Annotated[bool, _opt("--verbose", "-v", help="Verbose", panel="Output")] = False,
    socks: Annotated[Optional[str], _opt("--socks", help="SOCKS proxy host:port", panel="Advanced", hidden=True)] = None,
    aes: Annotated[Optional[str], _opt("--aes", help="Kerberos AES key", panel="Advanced", hidden=True)] = None,
    ccache: Annotated[Optional[str], _opt("--ccache", help="Kerberos ccache (KRB5CCNAME)", panel="Advanced", hidden=True)] = None,
    pfx: Annotated[Optional[str], _opt("--pfx", help="PFX certificate", panel="Advanced", hidden=True)] = None,
    as_identity: Annotated[Optional[str], _opt("--as", help="Looted identity (needs --loot)", panel="Advanced", hidden=True)] = None,
    loot: Annotated[Optional[Path], _opt("--loot", help="loot.json from a previous run", panel="Advanced", hidden=True)] = None,
    bloodhound_options: Annotated[str, _opt("--bloodhound-options", help="BloodHound collection: all, default, sessions, acl, computer", panel="Advanced", hidden=True)] = "all",
    skip_roasting: Annotated[bool, _opt("--skip-roasting", help="Skip Kerberoast / AS-REP roast", panel="Advanced", hidden=True)] = False,
    include_ip: Annotated[Optional[List[str]], _opt("--include-ip", help="Limit host scan to IP/CIDR or file", panel="Advanced", hidden=True)] = None,
    exclude_ip: Annotated[Optional[List[str]], _opt("--exclude-ip", help="Exclude IP/CIDR or file from host scan", panel="Advanced", hidden=True)] = None,
    version: Annotated[Optional[bool], _opt("--version", help="Show version", panel="Output", callback=_version_callback, is_eager=True)] = None,
    _help: Annotated[int, _opt("--help", "-h", help="Show help; -hh for advanced options", panel="Output", count=True, is_eager=True, callback=_help_callback, metavar="", show_default=False)] = 0,
):
    """Active Directory domain scan."""
    set_verbose(verbose)
    logger = get_logger(verbose)

    if list_checks:
        print(format_profile_help(SecurityChecker.list_checks().items()))
        raise typer.Exit(0)

    if not domain and not server and not username and not check:
        _emit_help(ctx)
        raise typer.Exit(0)

    try:
        profile_name = normalize_profile(profile)
    except ValueError as e:
        logger.error(f"[-] {e}")
        raise typer.Exit(1)

    loot_store, username, password, hashes = _apply_loot(
        as_identity, loot, username, password, hashes
    )

    target = _build_target(
        domain=domain, server=server, username=username, password=password,
        hashes=hashes, kerberos=kerberos, dns=dns, aes=aes, ccache=ccache,
        pfx=pfx, use_ldaps=use_ldaps, dc_host=dc_host, socks=socks,
        profile=profile_name, allow_empty_secret=bool(as_identity),
    )

    kwargs = dict(
        target=target, output=output, verbose=verbose,
        use_ldaps=use_ldaps, bloodhound_options=bloodhound_options,
        include_ip=include_ip, exclude_ip=exclude_ip,
        loot_store=loot_store, profile=profile_name, loot_path=loot,
    )
    if check:
        try:
            check_names = list(expand_selector(check, known_checks=SecurityChecker.list_checks()))
        except ValueError as e:
            logger.error(f"[-] {e}")
            logger.info("Use -L to list categories and checks")
            raise typer.Exit(1)
        _run_check(check_names=check_names, **kwargs)
    else:
        _run_audit(
            skip_bloodhound=skip_bloodhound, skip_roasting=skip_roasting, **kwargs
        )


def _new_session(target: Target, paths, loot_store=None, profile: str = DEFAULT_PROFILE, loot_path=None) -> Session:
    session = Session(target, paths, loot=loot_store, profile=profile)
    session.seed_prior_findings(loot_path)
    session.probe_clock()
    return session


def _run_check(
    check_names: list, target: Target,
    output: Optional[Path] = None, verbose: bool = False,
    use_ldaps: bool = False, bloodhound_options: str = "all",
    include_ip: Optional[List[str]] = None,
    exclude_ip: Optional[List[str]] = None,
    loot_store=None, profile: str = DEFAULT_PROFILE, loot_path=None,
):
    """Run one check or an expanded category (anonymous / directory / host / probe)."""
    logger = get_logger(verbose)
    ip_inclusions = _parse_ip_inclusions(include_ip, logger)
    ip_exclusions = _parse_ip_exclusions(exclude_ip, logger)

    available = SecurityChecker.list_checks()
    for check_name in check_names:
        if check_name not in available:
            logger.error(f"[-] Unknown check: {check_name}")
            logger.info("Use -L to list categories and checks")
            raise typer.Exit(1)

    if "bloodhound" in check_names:
        if not check_netexec_available():
            logger.warning("[!] nxc missing; BloodHound will try bloodhound-python")

    if not _check_netexec_module_requirements(check_names, required=True):
        raise typer.Exit(1)

    shown = ",".join(check_names)
    logger.info(f"[*] Tool DNS: {target.dns_server} (system resolver unchanged)")
    logger.info(f"[*] Profile: {profile} (check {shown})")
    if target.dc_host:
        logger.info(f"[*] dc-ip={target.dc_ip} dc-host={target.dc_host}")
    if target.socks:
        logger.info(f"[*] SOCKS: {target.socks}")
    paths = create_output_directory(target.domain, output)
    session = _new_session(target, paths, loot_store, profile=profile, loot_path=loot_path)

    try:
        with LDAPConnection(target.ldap_config()) as ldap_conn:
            session.attach_ldap(ldap_conn)
            target_scope = TargetScope.from_ldap(
                ldap_conn, ip_exclusions, logger, extra_targets=[target.dc_ip],
                inclusions=ip_inclusions
            )
            checker = SecurityChecker(
                ldap_conn, paths,
                domain=target.domain,
                username=target.username,
                password=target.password,
                hashes=target.hashes,
                bloodhound_options=bloodhound_options,
                target_scope=target_scope,
                session=session,
            )
            for check_name in check_names:
                checker.run_check(check_name, bloodhound_options=bloodhound_options)
    except Exception as e:
        logger.error(f"Check failed: {e}")
        session.write_findings()
        raise typer.Exit(1)

    session.write_findings()
    logger.success(f"\n[+] Check {shown} completed")


def _run_audit(
    target: Target,
    output: Optional[Path] = None, verbose: bool = False,
    skip_bloodhound: bool = False, bloodhound_options: str = "all",
    skip_roasting: bool = False, use_ldaps: bool = False,
    include_ip: Optional[List[str]] = None,
    exclude_ip: Optional[List[str]] = None,
    loot_store=None, profile: str = DEFAULT_PROFILE, loot_path=None,
):
    """Internal function to run the audit."""
    set_verbose(verbose)
    logger = get_logger(verbose)

    ip_inclusions = _parse_ip_inclusions(include_ip, logger)
    ip_exclusions = _parse_ip_exclusions(exclude_ip, logger)

    start_time = datetime.now()
    logger.success(f"[+] Domain audit started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"[*] Tool DNS: {target.dns_server} (system resolver unchanged)")
    logger.info(f"[*] Profile: {profile}")
    if target.dc_host:
        logger.info(f"[*] dc-ip={target.dc_ip} dc-host={target.dc_host}")
    if target.socks:
        logger.info(f"[*] SOCKS: {target.socks}")

    if not check_netexec_available():
        raise typer.Exit(1)

    _check_netexec_module_requirements(list(NETEXEC_MODULE_REQUIREMENTS))

    if not skip_bloodhound and not check_netexec_bloodhound_ce_available():
        logger.warning("[!] nxc bloodhound-ce missing; will try bloodhound-python")

    if not check_certipy_available():
        logger.warning("[!] Continuing without certipy; ADCS template checks will be skipped")

    paths = create_output_directory(target.domain, output)
    session = _new_session(target, paths, loot_store, profile=profile, loot_path=loot_path)
    print_explanation(paths["root"])

    try:
        if profile == "recon":
            with LDAPConnection(target.ldap_config()) as ldap_conn:
                session.attach_ldap(ldap_conn)
                target_scope = TargetScope.from_ldap(
                    ldap_conn, ip_exclusions, logger, extra_targets=[target.dc_ip],
                    inclusions=ip_inclusions
                )
                checker = SecurityChecker(
                    ldap_conn, paths,
                    domain=target.domain,
                    username=target.username,
                    password=target.password,
                    hashes=target.hashes,
                    bloodhound_options=bloodhound_options,
                    skip_bloodhound=True,
                    skip_roasting=True,
                    target_scope=target_scope,
                    session=session,
                )
                checker.run_all_checks(profile=profile)
        else:
            with LDAPConnection(target.ldap_config()) as ldap_conn:
                session.attach_ldap(ldap_conn)
                enumerator = ADEnumerator(ldap_conn, paths)
                domain_data = enumerator.enumerate_all()
                target_scope = TargetScope.from_ldap(
                    ldap_conn, ip_exclusions, logger, domain_data.domain_controllers,
                    extra_targets=[target.dc_ip],
                    inclusions=ip_inclusions
                )
                _print_domain_summary(domain_data, paths, target.domain, enumerator)
                checker = SecurityChecker(
                    ldap_conn, paths,
                    domain=target.domain,
                    username=target.username,
                    password=target.password,
                    hashes=target.hashes,
                    bloodhound_options=bloodhound_options,
                    skip_bloodhound=skip_bloodhound,
                    skip_roasting=skip_roasting,
                    target_scope=target_scope,
                    session=session,
                )
                checker.run_all_checks(profile=profile)
    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        session.write_findings()
        raise typer.Exit(1)

    session.write_findings()
    end_time = datetime.now()
    logger.success(f"\n\n[+] Domain audit completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")


def _parse_ip_exclusions(exclude_ip, logger) -> IPExclusions:
    try:
        ip_exclusions = IPExclusions.from_values(exclude_ip)
    except ValueError as e:
        logger.error(f"[-] {e}")
        raise typer.Exit(1)

    if not ip_exclusions:
        return ip_exclusions

    logger.info(f"[*] Excluding non-DC IP targets: {ip_exclusions.summary()}")
    return ip_exclusions


def _parse_ip_inclusions(include_ip, logger) -> IPExclusions:
    try:
        ip_inclusions = IPExclusions.from_values(include_ip, option_name="--include-ip")
    except ValueError as e:
        logger.error(f"[-] {e}")
        raise typer.Exit(1)

    if not ip_inclusions:
        return ip_inclusions

    logger.info(f"[*] Limiting non-DC IP targets to: {ip_inclusions.summary()}")
    return ip_inclusions


def print_explanation(output_dir: Path):
    """Print explanation of output structure."""
    logger = get_logger()

    logger.section("DATA EXPLAINED")
    logger.info(f"All data is written to {output_dir}")
    logger.info("findings.json is the structured finding list (id/severity/replay/opsec)")
    logger.info("loot.json stores recovered identities for --as")
    logger.info("files in \\findings\\ are findings that should be reported")
    logger.info("files in \\checks\\ needs to be checked")
    logger.info("files in \\data\\ is raw data")
    logger.info("")

    logger.section("COLORS EXPLAINED")
    logger.info("White is informational text")
    logger.success("Green means check has passed")
    logger.warning("Yellow means manually check the data")
    logger.error("Red means finding")
    logger.info("")


def _print_domain_summary(domain_data, paths, domain, enumerator):
    """Print summary of domain enumeration."""
    logger = get_logger()

    member_counts = enumerator.enumerate_privileged_group_members(domain_data.domain_sid)
    da_count = member_counts.get('Domain Admins', 0)
    ea_count = member_counts.get('Enterprise Admins', 0)

    if domain_data.users:
        users = [u.get('sAMAccountName', '') for u in domain_data.users if u.get('sAMAccountName')]
        write_lines(sorted(users), paths['data'] / 'list_users.txt')
        enabled_users = [
            u.get('sAMAccountName', '') for u in domain_data.users
            if u.get('sAMAccountName') and not ((u.get('userAccountControl') or 0) & 2)
        ]
        write_lines(sorted(enabled_users), paths['data'] / 'list_users_enabled.txt')

    if domain_data.computers:
        computers = [c.get('dNSHostName', '') for c in domain_data.computers if c.get('dNSHostName')]
        write_lines(sorted(computers), paths['data'] / 'list_computers.txt')

    if domain_data.groups:
        groups = [g.get('sAMAccountName', '') for g in domain_data.groups if g.get('sAMAccountName')]
        write_lines(sorted(groups), paths['data'] / 'list_groups.txt')

    logger.section("DOMAIN INFORMATION")
    logger.info(f"Domain SID: {domain_data.domain_sid}")
    logger.info(f"In the domain {domain} there are:")
    logger.info(f"- {len(domain_data.users)} users")
    logger.info(f"- {len(domain_data.groups)} groups")
    logger.info(f"- {len(domain_data.computers)} computers")
    logger.info(f"- {len(domain_data.ous)} OUs")
    logger.info(f"- {len(domain_data.gpos)} GPOs")
    logger.info(f"- {len(domain_data.domain_controllers)} Domain Controllers")
    logger.info(f"- {da_count} Domain Admins")
    logger.info(f"- {ea_count} Enterprise Admins")
    logger.info("")


if __name__ == "__main__":
    app()
