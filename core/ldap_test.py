import socket
import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Tuple
from .models import ScanConfig, Severity, RawLDAPFinding, LDAPServerType
from .utils import bind_msg, verbose, apex_domain, domain_to_dc, info

class LDAPPacketBuilder:
    @staticmethod
    def _ber_len(length: int) -> bytes:
        if length < 0x80: return bytes([length])
        elif length < 0x100: return bytes([0x81, length])
        elif length < 0x10000: return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError(f"Length too large: {length}")

    @staticmethod
    def _tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag]) + LDAPPacketBuilder._ber_len(len(value)) + value

    @staticmethod
    def _integer(value: int) -> bytes:
        if value == 0: return LDAPPacketBuilder._tlv(0x02, b'\x00')
        encoded = []
        v = value
        while v: encoded.insert(0, v & 0xFF); v >>= 8
        if encoded[0] & 0x80: encoded.insert(0, 0x00)
        return LDAPPacketBuilder._tlv(0x02, bytes(encoded))

    @staticmethod
    def _octet_string(value: str) -> bytes:
        return LDAPPacketBuilder._tlv(0x04, value.encode("utf-8", errors="replace"))

    @classmethod
    def anonymous_bind(cls, msg_id: int = 1) -> bytes:
        version = cls._integer(3); bind_dn = cls._octet_string(""); simple = cls._tlv(0x80, b"")
        return cls._tlv(0x30, cls._integer(msg_id) + cls._tlv(0x60, version + bind_dn + simple))

    @classmethod
    def simple_bind(cls, bind_dn: str, password: str, msg_id: int = 1) -> bytes:
        version = cls._integer(3); dn_enc = cls._octet_string(bind_dn); pw_bytes = password.encode("utf-8", errors="replace")
        return cls._tlv(0x30, cls._integer(msg_id) + cls._tlv(0x60, version + dn_enc + cls._tlv(0x80, pw_bytes)))

    @classmethod
    def rootdse_search(cls, msg_id: int = 2) -> bytes:
        base_dn = cls._octet_string(""); scope = cls._integer(0); deref = cls._integer(0)
        size_limit = cls._integer(10); time_limit = cls._integer(5); types_only = cls._tlv(0x01, b'\x00'); filt = cls._tlv(0x87, b"objectClass")
        attrs_to_req = ["supportedLDAPVersion", "vendorName", "vendorVersion", "namingContexts", "defaultNamingContext", "dnsHostName", "forestFunctionality", "domainFunctionality", "supportedSASLMechanisms", "subschemaSubentry", "supportedControl"]
        attr_list = b"".join(cls._octet_string(a) for a in attrs_to_req)
        return cls._tlv(0x30, cls._integer(msg_id) + cls._tlv(0x63, base_dn + scope + deref + size_limit + time_limit + types_only + filt + cls._tlv(0x30, attr_list)))

    @classmethod
    def schema_search(cls, subschema_dn: str, msg_id: int = 3) -> bytes:
        base_dn = cls._octet_string(subschema_dn); scope = cls._integer(0); deref = cls._integer(0)
        size_limit = cls._integer(1); time_limit = cls._integer(10); types_only = cls._tlv(0x01, b'\x00'); filt = cls._tlv(0x87, b"objectClass")
        attr_list = cls._octet_string("attributeTypes") + cls._octet_string("objectClasses")
        return cls._tlv(0x30, cls._integer(msg_id) + cls._tlv(0x63, base_dn + scope + deref + size_limit + time_limit + types_only + filt + cls._tlv(0x30, attr_list)))

class LDAPResponseParser:
    @staticmethod
    def parse_bind_response(data: bytes) -> Dict[str, Any]:
        result = {"result_code": -1, "matched_dn": "", "diagnostic_message": "", "success": False, "raw_hex": data[:32].hex() if data else ""}
        try:
            if not data or len(data) < 7: return result
            if data[0] != 0x30: return result
            offset = 2 if data[1] < 0x80 else (2 + (data[1] & 0x7F))
            if data[offset] != 0x02: return result
            offset += 2 + data[offset+1]
            if data[offset] != 0x61: return result
            len_byte = data[offset+1]
            offset += 2 if len_byte < 0x80 else (2 + (len_byte & 0x7F))
            if data[offset] != 0x02: return result
            rc_len = data[offset+1]; offset += 2
            rc = 0
            for b in data[offset:offset+rc_len]: rc = (rc << 8) | b
            result["result_code"] = rc; result["success"] = (rc == 0); offset += rc_len
            if offset < len(data) and data[offset] == 0x04:
                dn_len = data[offset+1]; offset += 2
                result["matched_dn"] = data[offset:offset+dn_len].decode("utf-8", errors="replace"); offset += dn_len
            if offset < len(data) and data[offset] == 0x04:
                msg_len = data[offset+1]; offset += 2
                result["diagnostic_message"] = data[offset:offset+msg_len].decode("utf-8", errors="replace")
        except Exception as exc: result["parse_error"] = str(exc)
        return result

    @staticmethod
    def parse_rootdse_response(data: bytes) -> Dict[str, List[str]]:
        attrs: Dict[str, List[str]] = {}
        try:
            pos = 0
            while pos < len(data) - 4:
                if data[pos] == 0x04:
                    slen = data[pos+1]
                    if slen < 0x80 and pos + 2 + slen < len(data):
                        val = data[pos+2:pos+2+slen].decode("utf-8", errors="replace")
                        if "=" not in val and len(val) > 2:
                            last_attr = list(attrs.keys())[-1] if attrs else None
                            if last_attr: attrs[last_attr].append(val)
                        pos += 2 + slen; continue
                pos += 1
        except Exception: pass
        return attrs

class LDAPDirectTester:
    LDAP_PORTS = [389, 636, 3268, 3269]
    LDAPS_PORTS = {636, 3269}
    _CRED_PAIRS = [
        ("admin/admin", ["cn=admin,{dc}", "Administrator", "admin@{domain}"], "admin"),
        ("admin/password", ["cn=admin,{dc}", "Administrator", "admin@{domain}"], "password"),
        ("admin/empty", ["cn=admin,{dc}", "Administrator", "admin@{domain}"], ""),
        ("ldap/ldap", ["cn=ldap,{dc}", "ldap@{domain}"], "ldap"),
        ("manager/manager", ["cn=manager,{dc}", "manager@{domain}"], "manager"),
    ]

    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg; self._timeout = min(cfg.timeout, 5)
        self._apex = apex_domain(cfg.target); self._dc = domain_to_dc(self._apex)

    def _connect(self, host: str, port: int, use_tls: bool = False) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self._timeout); s.connect((host, port))
            if use_tls and port in self.LDAPS_PORTS:
                import ssl; ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            return s
        except Exception: return None

    def _send_recv(self, sock: socket.socket, data: bytes, max_recv: int = 4096) -> bytes:
        try: sock.sendall(data); return sock.recv(max_recv)
        except Exception: return b""

    def probe_port(self, host: str, port: int) -> Dict[str, Any]:
        use_tls = port in self.LDAPS_PORTS
        sock = self._connect(host, port, use_tls)
        if sock is None: return {"port": port, "open": False, "is_ldap": False, "tls": use_tls}
        response = self._send_recv(sock, LDAPPacketBuilder.anonymous_bind(1))
        sock.close()
        is_ldap = len(response) >= 7 and response[0] == 0x30
        return {"port": port, "open": True, "is_ldap": is_ldap, "tls": use_tls, "banner_hex": response[:16].hex() if response else ""}

    def test_anonymous_bind(self, host: str, port: int) -> Optional[RawLDAPFinding]:
        sock = self._connect(host, port, port in self.LDAPS_PORTS)
        if sock is None: return None
        response = self._send_recv(sock, LDAPPacketBuilder.anonymous_bind(1))
        sock.close(); parsed = LDAPResponseParser.parse_bind_response(response)
        bind_msg(f"  Anonymous bind {host}:{port} → rc={parsed['result_code']} success={parsed['success']}")
        if parsed["success"] or parsed["result_code"] == 0:
            return RawLDAPFinding(host=host, port=port, finding_type="ANONYMOUS_BIND_ALLOWED", severity=Severity.CRITICAL, evidence=f"LDAP anonymous bind succeeded on {host}:{port}.", server_type="generic")
        return None

    def fetch_rootdse(self, host: str, port: int) -> Dict[str, Any]:
        sock = self._connect(host, port, port in self.LDAPS_PORTS)
        if sock is None: return {}
        self._send_recv(sock, LDAPPacketBuilder.anonymous_bind(1))
        search_resp = self._send_recv(sock, LDAPPacketBuilder.rootdse_search(2), max_recv=8192)
        sock.close(); attrs = LDAPResponseParser.parse_rootdse_response(search_resp)
        raw_str = search_resp.decode("utf-8", errors="replace"); server_type = self._detect_server_type_from_rootdse(raw_str)
        bind_msg(f"  RootDSE {host}:{port} → server={server_type} attrs={list(attrs.keys())[:5]}")
        return {"server_type": server_type, "attributes": attrs, "raw_response": raw_str[:500]}

    @staticmethod
    def _detect_server_type_from_rootdse(raw: str) -> str:
        if re.search(r"Active Directory|Microsoft|MSFT|forestFunctionality|domainFunctionality|sAMAccountName|DSID", raw, re.I): return LDAPServerType.AD.value
        if re.search(r"OpenLDAP|slapd|inetOrgPerson|posixAccount", raw, re.I): return LDAPServerType.OPENLDAP.value
        if re.search(r"389 Directory|Red Hat Directory|Fedora Directory|nsslapd", raw, re.I): return LDAPServerType.DS389.value
        if re.search(r"eDirectory|Novell|NDS", raw, re.I): return LDAPServerType.NOVELL.value
        return LDAPServerType.GENERIC.value

    def test_weak_credentials(self, host: str, port: int, server_type: str) -> Optional[RawLDAPFinding]:
        for desc, dn_templates, password in self._CRED_PAIRS:
            for dn_template in dn_templates:
                rendered = dn_template.format(domain=self._apex, dc=self._dc)
                for bind_dn in [rendered, rendered.replace(f",{self._dc}", f"@{self._apex}")]:
                    sock = self._connect(host, port, port in self.LDAPS_PORTS)
                    if sock is None: continue
                    response = self._send_recv(sock, LDAPPacketBuilder.simple_bind(bind_dn, password, 1))
                    sock.close(); parsed = LDAPResponseParser.parse_bind_response(response)
                    bind_msg(f"  Cred test {host}:{port} dn={bind_dn[:40]!r} pw={password!r} → rc={parsed['result_code']}")
                    if parsed["success"]:
                        return RawLDAPFinding(host=host, port=port, finding_type="WEAK_CREDENTIALS", severity=Severity.CRITICAL, evidence=f"LDAP bind succeeded with common credentials. Bind DN: {bind_dn!r}, Password: {password!r}.", bind_dn=bind_dn, bind_pw=password, server_type=server_type)
        return None

    def run(self) -> Tuple[List[RawLDAPFinding], Dict[str, Any]]:
        host = urlparse(self._cfg.target).hostname or self._cfg.target
        findings: List[RawLDAPFinding] = []; intel = {"open_ports": [], "server_type": LDAPServerType.GENERIC.value, "rootdse_data": {}, "anonymous_bind_allowed": False}
        open_ports = []
        for port in self.LDAP_PORTS:
            res = self.probe_port(host, port)
            if res["is_ldap"]: open_ports.append(res); intel["open_ports"].append(port); bind_msg(f"  LDAP port confirmed: {host}:{port}")
        if not open_ports: return findings, intel
        primary_port = open_ports[0]["port"]
        rootdse = self.fetch_rootdse(host, primary_port); intel["server_type"] = rootdse.get("server_type", LDAPServerType.GENERIC.value); intel["rootdse_data"] = rootdse
        if rootdse.get("attributes") or rootdse.get("raw_response"):
            findings.append(RawLDAPFinding(host=host, port=primary_port, finding_type="ROOTDSE_EXPOSED", severity=Severity.MEDIUM, evidence=f"LDAP RootDSE exposed. Server type: {intel['server_type']}", server_type=intel["server_type"], rootdse_data=rootdse.get("attributes", {})))
        anon = self.test_anonymous_bind(host, primary_port)
        if anon: findings.append(anon); intel["anonymous_bind_allowed"] = True
        cred = self.test_weak_credentials(host, primary_port, intel["server_type"])
        if cred: findings.append(cred)
        return findings, intel
