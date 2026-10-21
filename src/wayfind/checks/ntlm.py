"""NTLM security checks - NTLMv1 support and NTLM restriction policies."""

import io
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from ..utils.logger import get_logger
from .emit import note
from ..utils.ldap import LDAPConnection
from ..utils.output import write_file
from ..utils.registry_pol import parse_pol_file
from ..utils.gpttmpl import parse_gpttmpl_inf
from ..utils.dc import select_reachable_dc


LM_COMPATIBILITY_LEVELS = {
    0: "Send LM & NTLM responses",
    1: "Send LM & NTLM - use NTLMv2 session security if negotiated",
    2: "Send NTLM response only",
    3: "Send NTLMv2 response only",
    4: "Send NTLMv2 response only, refuse LM",
    5: "Send NTLMv2 response only, refuse LM & NTLM",
}

GPTMPL_NTLM_KEYS = {
    r"machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel": "lm_level",
    r"machine\system\currentcontrolset\services\netlogon\parameters\restrictntlmindomain": "restrict_ntlm_domain",
    r"machine\system\currentcontrolset\control\lsa\msv1_0\restrictsendingntlmtraffic": "restrict_sending",
    r"machine\system\currentcontrolset\control\lsa\msv1_0\restrictreceivingntlmtraffic": "restrict_receiving",
    r"machine\system\currentcontrolset\control\lsa\msv1_0\auditreceivingntlmtraffic": "audit_ntlm_domain",
    r"machine\system\currentcontrolset\services\netlogon\parameters\auditntlmauthenticationindomain": "audit_ntlm_domain",
}

GPTMPL_INF = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
REGISTRY_POL = "Machine/Registry.pol"


@dataclass
class GpoSettings:
    guid: str
    name: str
    lm_level: Optional[int] = None
    restrict_ntlm_domain: Optional[int] = None
    restrict_sending: Optional[int] = None
    restrict_receiving: Optional[int] = None
    audit_ntlm_domain: Optional[int] = None
    enable_multicast: Optional[int] = None

    @property
    def restricted(self) -> bool:
        if self.restrict_ntlm_domain is not None and self.restrict_ntlm_domain > 0:
            return True
        if self.restrict_sending is not None and self.restrict_sending >= 2:
            return True
        if self.restrict_receiving is not None and self.restrict_receiving >= 1:
            return True
        return False

    def has_restriction_fields(self) -> bool:
        return any(
            v is not None
            for v in (
                self.restrict_ntlm_domain,
                self.restrict_sending,
                self.restrict_receiving,
                self.audit_ntlm_domain,
            )
        )


class NTLMChecker:
    """Check NTLM security settings including NTLMv1 support and NTLM restrictions."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain

    def check_ntlm(self):
        """Run all NTLM-related security checks against one SYSVOL pass."""
        if not self.username or not self.password:
            self.logger.warning("[!] NTLM checks require SMB credentials")
            return
        try:
            gpos, dcs = self._load_gpo_settings()
        except Exception as e:
            self.logger.error(f"[-] Error reading SYSVOL GPOs: {e}")
            return
        self._check_ntlmv1_support(gpos, dcs)
        self._check_ntlm_restrictions(gpos)
        self._check_llmnr(gpos)

    def _load_gpo_settings(self) -> Tuple[List[GpoSettings], List[Dict]]:
        """One SMB login, one Policies listing, Registry.pol + GptTmpl.inf per linked GPO."""
        from impacket.smbconnection import SMBConnection

        dcs = self.ldap.query(
            search_base=self.base_dn,
            search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            attributes=["dNSHostName", "name", "operatingSystem"],
        ) or []
        dc_hostname = select_reachable_dc(dcs, fallback=self.server, logger=self.logger) if dcs else self.server

        conn = SMBConnection(dc_hostname, dc_hostname)
        conn.login(self.username, self.password, self.domain)
        try:
            linked = self._get_linked_gpo_guids()
            try:
                policies = conn.listPath("SYSVOL", f"{self.domain}/Policies")
            except Exception as e:
                self.logger.debug(f"Could not list GPO policies: {e}")
                return [], dcs

            by_guid: Dict[str, GpoSettings] = {}
            for policy in policies:
                guid = policy.get_longname()
                if guid in (".", ".."):
                    continue
                if linked and guid.upper() not in linked:
                    continue
                rec = GpoSettings(
                    guid=guid,
                    name=self._get_gpo_display_name(guid) or guid,
                )
                base = f"{self.domain}/Policies/{guid}"
                pol = self._read_sysvol(conn, f"{base}/{REGISTRY_POL}")
                if pol:
                    apply_pol(rec, pol)
                inf = self._read_sysvol(conn, f"{base}/{GPTMPL_INF}")
                if inf:
                    apply_gpttmpl(rec, inf)
                by_guid[guid.upper()] = rec
            return list(by_guid.values()), dcs
        finally:
            try:
                conn.logoff()
            except Exception:
                pass

    def _read_sysvol(self, conn, share_path: str) -> Optional[bytes]:
        from impacket.smbconnection import SessionError
        try:
            buf = io.BytesIO()
            conn.getFile("SYSVOL", share_path, buf.write)
            data = buf.getvalue()
            return data or None
        except SessionError:
            return None
        except Exception as e:
            self.logger.debug(f"Could not read {share_path}: {e}")
            return None

    def _check_ntlmv1_support(self, gpos: List[GpoSettings], dcs: List[Dict]):
        self.logger.info("---Checking for NTLMv1 support on Domain Controllers---")
        if not dcs:
            self.logger.warning("[!] No domain controllers found")
            return

        default_vulnerable = self._check_dc_os_defaults(dcs)
        ntlmv1_findings = []
        gpo_settings = []
        for rec in gpos:
            if rec.lm_level is None:
                continue
            level_desc = LM_COMPATIBILITY_LEVELS.get(rec.lm_level, f"Unknown ({rec.lm_level})")
            gpo_settings.append({
                "gpo_name": rec.name,
                "gpo_guid": rec.guid,
                "lm_level": rec.lm_level,
                "description": level_desc,
            })
            if rec.lm_level <= 2:
                ntlmv1_findings.append(
                    f"{rec.name}: LmCompatibilityLevel={rec.lm_level} ({level_desc})"
                )

        if ntlmv1_findings:
            note(self, f"NTLMv1 supported in {len(ntlmv1_findings)} GPO(s) - vulnerable to downgrade/relay attacks", id="ntlm.v1-gpo", count=len(ntlmv1_findings), severity="high")
            output_lines = [
                "NTLMv1 Support Detected",
                "=" * 50,
                "",
                "RISK: NTLMv1 is vulnerable to:",
                "  - Downgrade attacks (forcing NTLMv1 instead of NTLMv2)",
                "  - Relay attacks with easier hash cracking",
                "  - Rainbow table attacks on captured hashes",
                "",
                "RECOMMENDATION: Set LmCompatibilityLevel to 3 or higher",
                "  3 = Send NTLMv2 response only",
                "  4 = Send NTLMv2 response only, refuse LM",
                "  5 = Send NTLMv2 response only, refuse LM & NTLM (most secure)",
                "",
                "Affected GPOs:",
            ]
            output_lines.extend([f"  - {f}" for f in ntlmv1_findings])
            write_file("\n".join(output_lines),
                       self.output_paths["findings"] / "ntlmv1_supported.txt",
                       self.logger)
        elif gpo_settings:
            self.logger.success("[+] NTLMv1 is disabled (LmCompatibilityLevel >= 3)")
            output_lines = ["LmCompatibilityLevel Settings (Secure)", ""]
            for setting in gpo_settings:
                output_lines.append(
                    f"{setting['gpo_name']}: Level {setting['lm_level']} - {setting['description']}"
                )
            write_file("\n".join(output_lines),
                       self.output_paths["checks"] / "ntlmv1_settings.txt",
                       self.logger)
        elif default_vulnerable:
            self.logger.warning(
                "[!] No LmCompatibilityLevel GPO found - DCs on legacy OS may use vulnerable defaults unless set via local GPO/registry/MDM (verify on host)"
            )
            output_lines = [
                "NTLMv1 Support (OS Default)",
                "=" * 50,
                "",
                "No LmCompatibilityLevel GPO setting found.",
                "",
                "RISK: Domain Controllers are running legacy operating systems with vulnerable defaults:",
            ]
            for dc_name, os_name, default_level in default_vulnerable:
                output_lines.append(f"  - {dc_name}: {os_name} (default level {default_level})")
            output_lines.extend([
                "",
                "These OS defaults allow NTLMv1:",
                "  - Server 2000/XP: Level 1 (NTLMv1)",
                "  - Server 2003: Level 2 (NTLMv1 with v2 session security)",
                "",
                "RECOMMENDATION: Set LmCompatibilityLevel to 3+ via GPO",
                "Verify by running Responder and coerce the DC to check actual behavior",
            ])
            write_file("\n".join(output_lines),
                       self.output_paths["findings"] / "ntlmv1_supported.txt",
                       self.logger)
        else:
            self.logger.warning("[!] No LmCompatibilityLevel GPO found - OS defaults apply")
            dc_os_list = []
            for dc in dcs:
                dc_name = dc.get("name", dc.get("dNSHostName", "Unknown"))
                os_name = dc.get("operatingSystem", "Unknown")
                dc_os_list.append(f"  - {dc_name}: {os_name}")
            self.logger.info("[*] All DCs have secure OS defaults (level 3 - NTLMv2 only)")
            output_lines = [
                "No LmCompatibilityLevel GPO setting found.",
                "",
                "Domain Controllers (all have secure defaults):",
            ]
            output_lines.extend(dc_os_list)
            output_lines.extend([
                "",
                "OS defaults:",
                "  - Server 2008 and newer: Level 3 (NTLMv2 only) - Secure",
                "  - Server 2003: Level 2 (NTLMv1 with v2 session) - Vulnerable",
                "  - Server 2000/XP: Level 1 (NTLMv1) - Vulnerable",
                "",
                "Verify by running Responder and coerce the DC to check if LmCompatibilityLevel",
                "is set at the local registry level only instead of GPO",
            ])
            write_file("\n".join(output_lines),
                       self.output_paths["checks"] / "ntlmv1_settings.txt",
                       self.logger)

    def _check_ntlm_restrictions(self, gpos: List[GpoSettings]):
        self.logger.info("---Checking NTLM restriction policies---")
        ntlm_restrictions = []
        for rec in gpos:
            if not rec.has_restriction_fields():
                continue
            ntlm_restrictions.append({
                "gpo_name": rec.name,
                "gpo_guid": rec.guid,
                "restrict_ntlm_domain": rec.restrict_ntlm_domain,
                "restrict_sending": rec.restrict_sending,
                "restrict_receiving": rec.restrict_receiving,
                "audit_ntlm_domain": rec.audit_ntlm_domain,
                "restricted": rec.restricted,
            })

        has_restrictions = any(r.get("restricted") for r in ntlm_restrictions)
        if has_restrictions:
            self.logger.success("[+] NTLM restrictions are configured")
            output_lines = ["NTLM Restriction Policies", "=" * 50, ""]
            for r in ntlm_restrictions:
                output_lines.append(f"GPO: {r['gpo_name']}")
                if r.get("restrict_ntlm_domain") is not None:
                    val = r["restrict_ntlm_domain"]
                    output_lines.append(
                        f"  RestrictNTLMInDomain (DC): {val} - {self._get_restrict_ntlm_domain_desc(val)}"
                    )
                if r.get("restrict_sending") is not None:
                    val = r["restrict_sending"]
                    output_lines.append(
                        f"  RestrictSendingNTLMTraffic (Clients): {val} - {self._get_restrict_sending_desc(val)}"
                    )
                if r.get("restrict_receiving") is not None:
                    val = r["restrict_receiving"]
                    output_lines.append(
                        f"  RestrictReceivingNTLMTraffic (Servers): {val} - {self._get_restrict_receiving_desc(val)}"
                    )
                if r.get("audit_ntlm_domain") is not None:
                    output_lines.append(f"  AuditNTLMInDomain: {r['audit_ntlm_domain']}")
                output_lines.append("")
            write_file("\n".join(output_lines),
                       self.output_paths["checks"] / "ntlm_restrictions.txt",
                       self.logger)
        else:
            if ntlm_restrictions:
                self.logger.info("[*] NTLM audit settings found but no restrictions enforced")
            self.logger.warning(
                "[!] No domain GPO restricts NTLM - may be unrestricted unless set via local GPO/registry/MDM (verify on host)"
            )
            output_lines = [
                "NTLM Not Restricted",
                "=" * 50,
                "",
                "No NTLM restriction policies were found in GPOs.",
                "",
                "RISK: NTLM authentication is enabled domain-wide, which allows:",
                "  - NTLM relay attacks",
                "  - Pass-the-hash attacks",
                "  - Credential capture and offline cracking",
                "",
                "RECOMMENDATION: Consider implementing NTLM restrictions:",
                "  1. Enable NTLM auditing first to identify dependencies",
                "  2. Add exceptions for required services",
                "  3. Gradually restrict NTLM traffic",
                "",
                "Relevant GPO settings:",
                "  - Network security: Restrict NTLM: NTLM authentication in this domain",
                "  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers",
                "  - Network security: Restrict NTLM: Audit NTLM authentication in this domain",
            ]
            write_file("\n".join(output_lines),
                       self.output_paths["findings"] / "ntlm_not_restricted.txt",
                       self.logger)

    def _check_llmnr(self, gpos: List[GpoSettings]):
        self.logger.info("---Checking LLMNR configuration---")
        llmnr_gpos = []
        llmnr_disabled = False
        for rec in gpos:
            if rec.enable_multicast is None:
                continue
            llmnr_gpos.append((rec.name, rec.enable_multicast))
            if rec.enable_multicast == 0:
                llmnr_disabled = True

        if llmnr_disabled:
            self.logger.success("[+] LLMNR is disabled via GPO")
            output_lines = ["LLMNR Configuration", "=" * 50, ""]
            for gpo_name, enabled in llmnr_gpos:
                status = "Disabled" if enabled == 0 else "Enabled"
                output_lines.append(f"{gpo_name}: EnableMulticast = {enabled} ({status})")
            write_file("\n".join(output_lines),
                       self.output_paths["checks"] / "llmnr_disabled.txt",
                       self.logger)
        else:
            self.logger.warning(
                "[!] No domain GPO disables LLMNR - vulnerable to Responder unless disabled via local GPO/registry/MDM (verify on host)"
            )
            output_lines = [
                "LLMNR Not Disabled",
                "=" * 50,
                "",
                "No GPO found disabling LLMNR (Link-Local Multicast Name Resolution).",
                "",
                "RISK: LLMNR is commonly exploited for:",
                "  - Credential capture using Responder",
                "  - NTLM relay attacks",
                "  - Man-in-the-middle attacks on name resolution",
                "",
                "GPO to disable LLMNR:",
                "  Computer Configuration > Administrative Templates > Network > DNS Client",
                "  > Turn off multicast name resolution = Enabled",
                "",
                "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                "  EnableMulticast = 0",
            ]
            write_file("\n".join(output_lines),
                       self.output_paths["findings"] / "llmnr_enabled.txt",
                       self.logger)

    def _get_gpo_display_name(self, gpo_guid: str) -> Optional[str]:
        try:
            results = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter=f"(cn={gpo_guid})",
                attributes=["displayName"],
            )
            if results:
                return results[0].get("displayName")
        except Exception:
            pass
        return None

    def _get_linked_gpo_guids(self) -> set:
        import re

        linked_guids = set()
        gp_link_pattern = re.compile(
            r"\[LDAP://[Cc][Nn]=(\{[0-9A-Fa-f\-]+\}),[Cc][Nn]=Policies.*?;(\d+)\]",
            re.IGNORECASE,
        )

        def extract_linked_guids(results):
            for obj in results:
                gp_link = obj.get("gPLink", "")
                if not gp_link:
                    continue
                for match in gp_link_pattern.finditer(gp_link):
                    guid = match.group(1).upper()
                    options = int(match.group(2))
                    if options in (0, 2):
                        linked_guids.add(guid)

        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter="(|(objectClass=domain)(objectClass=organizationalUnit))",
                attributes=["gPLink", "distinguishedName"],
            )
            if results:
                extract_linked_guids(results)
        except Exception as e:
            self.logger.debug(f"Could not query domain/OU gPLink attributes: {e}")

        try:
            try:
                config_dn = self.ldap.get_config_dn()
            except Exception:
                config_dn = f"CN=Configuration,{self.base_dn}"
            results = self.ldap.query(
                search_base=f"CN=Sites,{config_dn}",
                search_filter="(objectClass=site)",
                attributes=["gPLink", "distinguishedName"],
            )
            if results:
                extract_linked_guids(results)
        except Exception as e:
            self.logger.debug(f"Could not query site gPLink attributes: {e}")

        return linked_guids

    def _get_restrict_ntlm_domain_desc(self, value: int) -> str:
        descriptions = {
            0: "Disabled (allow all)",
            1: "Deny domain accounts to domain servers",
            2: "Deny domain accounts",
            3: "Deny domain servers",
            4: "Deny all",
        }
        return descriptions.get(value, f"Unknown ({value})")

    def _get_restrict_sending_desc(self, value: int) -> str:
        descriptions = {
            0: "Allow all",
            1: "Audit all (no blocking)",
            2: "Deny all",
        }
        return descriptions.get(value, f"Unknown ({value})")

    def _get_restrict_receiving_desc(self, value: int) -> str:
        descriptions = {
            0: "Allow all",
            1: "Deny domain accounts",
            2: "Deny all",
        }
        return descriptions.get(value, f"Unknown ({value})")

    def _check_dc_os_defaults(self, dcs: List[Dict]) -> Optional[List[tuple]]:
        vulnerable_dcs = []
        for dc in dcs:
            dc_name = dc.get("name", dc.get("dNSHostName", "Unknown"))
            os_name = dc.get("operatingSystem", "Unknown")
            default_level = None
            if os_name and os_name != "Unknown":
                os_lower = os_name.lower()
                if any(x in os_lower for x in ["2000", "windows xp"]):
                    default_level = 1
                elif "2003" in os_lower:
                    default_level = 2
            if default_level is not None and default_level <= 2:
                vulnerable_dcs.append((dc_name, os_name, default_level))
        return vulnerable_dcs or None


def apply_pol(rec: GpoSettings, content: bytes) -> None:
    """Fill GpoSettings from Registry.pol. Existing fields win."""
    for key, value_name, reg_type, _size, data in parse_pol_file(content):
        if reg_type != 4 or len(data) < 4:
            continue
        val = struct.unpack("<I", data[:4])[0]
        vl = value_name.lower()
        if "dnsclient" in key.lower() and vl == "enablemulticast":
            if rec.enable_multicast is None:
                rec.enable_multicast = val
            continue
        if vl == "lmcompatibilitylevel" and "control\\lsa" in key.lower():
            if rec.lm_level is None:
                rec.lm_level = val
            continue
        if "msv1_0" not in key.lower() and "lsa" not in key.lower() and "netlogon" not in key.lower():
            continue
        if vl == "restrictntlmindomain" and rec.restrict_ntlm_domain is None:
            rec.restrict_ntlm_domain = val
        elif vl == "auditntlmindomain" and rec.audit_ntlm_domain is None:
            rec.audit_ntlm_domain = val
        elif vl == "restrictsendingntlmtraffic" and rec.restrict_sending is None:
            rec.restrict_sending = val
        elif vl == "restrictreceivingntlmtraffic" and rec.restrict_receiving is None:
            rec.restrict_receiving = val


def apply_gpttmpl(rec: GpoSettings, content: bytes) -> None:
    """Fill GpoSettings from GptTmpl.inf. Existing fields (from Registry.pol) win."""
    parsed = parse_gpttmpl_inf(content)
    registry_values = parsed.get("Registry Values", {})
    for reg_key, reg_value in registry_values.items():
        field_name = GPTMPL_NTLM_KEYS.get(reg_key)
        if field_name is None:
            continue
        if getattr(rec, field_name) is not None:
            continue
        try:
            parts = reg_value.split(",")
            if len(parts) >= 2 and parts[0].strip() == "4":
                setattr(rec, field_name, int(parts[1].strip()))
        except (ValueError, IndexError):
            continue
