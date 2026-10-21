"""BloodHound collection + ACL path findings from zip/JSON."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

from ..core.cypher import ACL_RIGHTS, CYPHER_QUERIES
from ..core.graph import (
    is_default_ace_source,
    parse_bloodhound_zip,
    should_emit_owned_path,
    shortest_acl_paths,
)
from ..core.session import Session
from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection
from ..utils.output import write_lines
from ..utils.bins import nxc_bin, bloodhound_python_bin, bhcli_bin
from ..utils.dependencies import check_netexec_bloodhound_ce_available


class BloodHoundChecker:
    """BloodHound data collection wrapper."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, session: Optional[Session] = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes

    def check_bloodhound(self, collection_method: str = "all", zip_output: bool = True):
        self.logger.info("---Checking BloodHound data collection---")
        dc_ip = self.session.target.dc_ip
        dc_host = self._dc_hostname(dc_ip, self.session.target.dc_host or dc_ip)
        bh_output = self.output_paths["data"] / "bloodhound"
        bh_output.mkdir(parents=True, exist_ok=True)
        write_lines(
            [f"{right}: {CYPHER_QUERIES[right]}" for right in ACL_RIGHTS],
            bh_output / "cypher.txt",
        )

        zip_path = None
        error_lines = []
        nxc_ok = False
        if check_netexec_bloodhound_ce_available():
            nxc_ok = self._run_nxc(dc_ip, collection_method, bh_output)
        else:
            self.logger.info("[*] nxc BloodHound-CE unavailable, using bloodhound-python")
        if nxc_ok:
            zip_path = self._find_zip(bh_output)
        else:
            if check_netexec_bloodhound_ce_available():
                self.logger.warning("[!] nxc BloodHound failed or unavailable, trying bloodhound-python")
            ok, err = self._run_bloodhound_python(dc_host, dc_ip, bh_output)
            if not ok:
                error_lines.append(err or "bloodhound-python failed")
                write_lines(error_lines, bh_output / "collector-error.txt")
                self.session.emit(
                    id="bloodhound.collector-error",
                    severity="info",
                    title="BloodHound collector failed",
                    evidence=err or "collector failed",
                    backend="bloodhound-python",
                    check="bloodhound",
                )
                return False
            zip_path = self._find_zip(bh_output)

        if zip_path:
            self._emit_acl_paths(zip_path, dc_host)
        return True


    def _dc_hostname(self, dc_ip: str, dc_host: str) -> str:
        host = (dc_host or "").strip()
        if host and any(c.isalpha() for c in host):
            return host
        try:
            rows = self.ldap.query(
                search_base=self.ldap.config.base_dn,
                search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                attributes=["dNSHostName", "name"],
            ) or []
            for row in rows:
                dns = row.get("dNSHostName") or ""
                if dns:
                    return dns
                name = row.get("name") or ""
                if name and self.domain and "." not in name:
                    return f"{name}.{self.domain}"
                if name:
                    return name
        except Exception:
            pass
        if self.domain:
            return f"dc.{self.domain}"
        return dc_ip

    def _find_zip(self, bh_output: Path) -> Optional[Path]:
        zips = list(bh_output.glob("*bloodhound*.zip")) + list(bh_output.glob("*.zip"))
        return zips[0] if zips else None

    def _emit_acl_paths(self, zip_path: Path, dc_host: str = "") -> None:
        try:
            edges = parse_bloodhound_zip(zip_path)
        except Exception as e:
            self.logger.error(f"[-] Failed to parse BloodHound zip: {e}")
            return
        sources = []
        if self.username:
            sources.append(self.username)
            if self.domain:
                sources.append(f"{self.username}@{self.domain}")
                sources.append(f"{self.username.upper()}@{self.domain.upper()}")
        for ident in self.session.loot.as_list():
            u = ident.get("username") or ""
            if u:
                sources.append(u)
                if self.domain:
                    sources.append(f"{u}@{self.domain}")
        paths = shortest_acl_paths(edges, sources)
        replay = self.session.collect_replay(dc_host)
        count = 0
        seen = set()

        def emit_edge(src, right, dst, evidence):
            nonlocal count
            key = (src.upper(), right, dst.upper())
            if key in seen:
                return
            seen.add(key)
            count += 1
            self.session.emit(
                id=f"acl.{right}",
                severity="medium",
                title=f"{src} {right} {dst}",
                asset=str(dst),
                evidence=evidence,
                replay=replay,
                backend="bloodhound",
                check="bloodhound",
                right=right,
                src=src,
                dst=dst,
            )

        for item in paths:
            if not should_emit_owned_path(item):
                continue
            emit_edge(item["src"], item["right"], item["dst"], item["evidence"])

        for src, right, dst in edges:
            if right not in ACL_RIGHTS:
                continue
            if is_default_ace_source(src):
                continue
            emit_edge(src, right, dst, f"{src} -{right}-> {dst}")

        if count:
            self.logger.info(f"[+] {count} ACL path finding(s) from {zip_path}")
        else:
            self.logger.info(f"[*] No ACL path from current identity in {zip_path}")

        bhcli = bhcli_bin()
        if bhcli:
            self.logger.info(f"[*] bhcli present ({bhcli}); Cypher saved to cypher.txt")

    def _run_nxc(self, dc: str, collection_method: str, bh_output: Path) -> bool:
        try:
            nxc_bin()
        except FileNotFoundError:
            self.logger.error("[-] nxc/netexec not found")
            return False

        extra = ["--bloodhound", "-c", collection_method]
        self.logger.info(f"[*] Running nxc BloodHound collection: {collection_method}")
        try:
            output, result = self.session.run_nxc(
                "ldap", extra=extra, host=dc, timeout=900,
                cwd=str(bh_output), archive="bloodhound/nxc_raw.txt",
            )
        except subprocess.TimeoutExpired:
            self.logger.warning("[!] nxc BloodHound timed out")
            return False
        except Exception as e:
            self.logger.error(f"[-] nxc BloodHound: {e}")
            return False

        write_lines(["nxc BloodHound output", "=" * 40, "", output],
                    bh_output / "bloodhound_nxc.txt")
        if result.returncode != 0:
            self.logger.error(f"[-] nxc BloodHound exited {result.returncode}")
            self.logger.debug(output)
            return False
        nxc_unusable = (
            "Configuration Issue" in output
            or ("bloodhound-ce" in output.lower() and "fix this" in output.lower())
        )
        if nxc_unusable:
            self.logger.warning("[!] nxc BloodHound-CE not usable; falling back")
            return False
        if "_bloodhound.zip" not in output and "Compressing output into" not in output:
            self.logger.warning("[!] nxc BloodHound produced no zip; falling back")
            return False

        self.logger.success("[+] nxc BloodHound collection completed")
        zip_source = None
        for line in output.splitlines():
            if "Compressing output into" in line:
                zip_source = line.split("Compressing output into")[-1].strip()
                break
            if "_bloodhound.zip" in line:
                for part in line.split():
                    if "_bloodhound.zip" in part:
                        zip_source = part
        if zip_source and Path(zip_source).exists():
            dest = bh_output / "bloodhound.zip"
            shutil.copy2(zip_source, dest)
            self.logger.info(f"[*] BloodHound ZIP saved to: {dest}")
        return True

    def _bloodhound_python_prefix(self) -> Optional[list]:
        dist = Path("/usr/lib/python3/dist-packages")
        if (dist / "bloodhound").is_dir() and getattr(sys, "executable", None):
            code = (
                "import sys; sys.path.append(%r); "
                "from bloodhound import main; "
                "sys.argv[0] = 'bloodhound-python'; main()" % str(dist)
            )
            return [sys.executable, "-c", code]
        binary = bloodhound_python_bin()
        return [binary] if binary else None

    def _run_bloodhound_python(self, dc_host: str, dc_ip: str, bh_output: Path):
        prefix = self._bloodhound_python_prefix()
        if not prefix:
            msg = "bloodhound-python not in PATH"
            self.logger.warning(f"[!] {msg}")
            return False, msg
        if not self.username:
            msg = "bloodhound-python needs a username"
            self.logger.error(f"[-] {msg}")
            return False, msg

        dns = self.session.target.dns_server
        base = prefix + [
            "-u", self.username,
            "-d", self.domain,
            "-dc", dc_host,
            "-ns", dns,
            "--dns-tcp",
            "--zip",
            "-c", "DCOnly",
            "-op", "wayfind",
        ]
        if self.hashes and not self.password:
            base.extend(["--hashes", self.hashes])
        else:
            base.extend(["-p", self.password])
        if not self.session.target.kerberos:
            base.extend(["--auth-method", "ntlm"])

        use_ldaps = self.session.target.use_ldaps
        variants = []
        if use_ldaps:
            variants.append(("ldaps+cb", ["--use-ldaps", "--ldap-channel-binding"]))
            variants.append(("ldaps", ["--use-ldaps"]))
            variants.append(("ldap", []))
        else:
            variants.append(("ldap", []))
            variants.append(("ldaps+cb", ["--use-ldaps", "--ldap-channel-binding"]))
            variants.append(("ldaps", ["--use-ldaps"]))

        if self.session.target.socks:
            self.logger.info(
                f"[*] SOCKS {self.session.target.socks} "
                "(bloodhound-python has no --socks; wrap externally)"
            )

        self.logger.info("[*] Running bloodhound-python DCOnly")
        self.logger.info(f"[*] dc-host={dc_host} dc-ip={dc_ip} ns={dns}")
        last_output = ""
        for label, extra in variants:
            cmd = base + extra
            self.logger.info(f"[*] bloodhound-python variant {label}")
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=900, cwd=str(bh_output),
                )
            except subprocess.TimeoutExpired:
                msg = "bloodhound-python timed out"
                self.logger.warning(f"[!] {msg}")
                return False, msg
            except Exception as e:
                msg = f"bloodhound-python: {e}"
                self.logger.error(f"[-] {msg}")
                return False, msg

            output = (result.stdout or "") + (result.stderr or "")
            last_output = output
            write_lines(
                [f"bloodhound-python output ({label})", "=" * 40, "", output],
                bh_output / f"bloodhound_python_{label}.txt",
            )
            zips = list(bh_output.glob("*bloodhound*.zip")) + list(bh_output.glob("*.zip"))
            if result.returncode == 0:
                write_lines(
                    ["bloodhound-python output", "=" * 40, "", output],
                    bh_output / "bloodhound_python.txt",
                )
                if zips:
                    self.logger.success(f"[+] bloodhound-python zip ({label}): {zips[0]}")
                else:
                    self.logger.success(f"[+] bloodhound-python finished ({label})")
                return True, output
            self.logger.warning(
                f"[!] bloodhound-python {label} exited {result.returncode}; trying next variant"
            )
            self.logger.debug(output)

        msg = "bloodhound-python exited nonzero on all variants" + chr(10) + last_output
        self.logger.error("[-] bloodhound-python failed all variants")
        write_lines(
            ["bloodhound-python output", "=" * 40, "", last_output],
            bh_output / "bloodhound_python.txt",
        )
        return False, msg
