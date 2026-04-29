import re
import socket
import json
from typing import List, Set, Dict, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin, urlunparse
import requests
try: from bs4 import BeautifulSoup; _BS4_OK = True
except ImportError: _BS4_OK = False
from .models import Endpoint, AuthState, ScanConfig, Payload, PayloadTier, Baseline
from .client import HTTPClient
from .patterns import STATIC_EXT_RE, AUTH_EP_RE, LDAP_ERRORS_RE, JS_FETCH_RE, JS_API_PATH_RE
from .utils import info, warn, verbose, build_safe_data, vprint, build_injection_data
from .detection import DetectionPipeline
from .budget import AdaptiveBudgetManager

class TargetLivenessChecker:
    def __init__(self, cfg: ScanConfig): self._cfg = cfg
    def check(self) -> Dict[str, Any]:
        res = {"live": False, "dns_ok": False, "resolved_ip": "", "open_ports": [], "http_ok": False}
        p = urlparse(self._cfg.target); host = p.hostname or self._cfg.target
        try: res["resolved_ip"] = socket.gethostbyname(host); res["dns_ok"] = True
        except: return res
        try:
            r = requests.head(self._cfg.target, timeout=4, verify=self._cfg.verify_ssl)
            res["http_ok"] = r.status_code < 500; res["live"] = res["http_ok"]
        except: pass
        return res

class Crawler:
    def __init__(self, client: HTTPClient, cfg: ScanConfig): self._client = client; self._cfg = cfg; self._seen = set(); self._page_html_cache = {}
    def crawl(self, target: str) -> List[Endpoint]:
        info(f"  Crawling {target}..."); pages = []; eps = []; q = [target]; self._seen.add(target)
        while q and len(pages) < self._cfg.depth * 20:
            url = q.pop(0); resp = self._client.get(url, phase="discovery")
            if not resp: continue
            pages.append(url); html = resp.text or ""; self._page_html_cache[url] = html[:8000]
            # Form extraction
            if _BS4_OK:
                soup = BeautifulSoup(html, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", ""); method = form.get("method", "GET").upper(); params = [i.get("name") for i in form.find_all(["input", "select", "textarea"]) if i.get("name")]
                    if params: eps.append(Endpoint(url=urljoin(url, action), method=method, params=params, source="form", auth_state=AuthState.UNAUTH))
            # Link extraction
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                n = urljoin(url, m.group(1)); p = urlparse(n)
                if p.netloc == urlparse(target).netloc and n not in self._seen and not STATIC_EXT_RE.search(p.path): self._seen.add(n); q.append(n)
        return eps

class DirectorySchemaProbe:
    _PROBE_ATTRS_GENERIC = ["uid", "cn", "sAMAccountName", "mail", "userPassword", "userPrincipalName", "memberOf", "objectClass"]
    _PROBE_OBJECT_CLASSES = ["person", "user", "inetOrgPerson", "posixAccount", "group"]
    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline, budget: AdaptiveBudgetManager, cfg: ScanConfig):
        self._client = client; self._pipeline = pipeline; self._budget = budget; self._cfg = cfg
    def discover(self, ep: Endpoint, param: str, baseline: Baseline, stype: str = "generic") -> Dict[str, Any]:
        res = {"attributes": [], "object_classes": [], "naming_attr": "uid", "payloads": []}
        for a in self._PROBE_ATTRS_GENERIC:
            if not self._budget.acquire_verification(): break
            if self._bool_probe(ep, param, f"*({a}=*)", baseline): res["attributes"].append(a); verbose(f"    [Schema] attr [{a}] present")
        for oc in self._PROBE_OBJECT_CLASSES:
            if not self._budget.acquire_verification(): break
            if self._bool_probe(ep, param, f"*(objectClass={oc})", baseline): res["object_classes"].append(oc); verbose(f"    [Schema] objectClass [{oc}] present")
        return res
    def _bool_probe(self, ep: Endpoint, param: str, filt: str, bl: Baseline) -> bool:
        pl = Payload(raw=filt, desc="schema-probe", technique="bool_enum", tier=PayloadTier.TIER2_BOOLEAN)
        resp = self._client.send_endpoint(ep, build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix), phase="verification")
        return self._pipeline.run(resp, bl, pl).fired if resp else False
