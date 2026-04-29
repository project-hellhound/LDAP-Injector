import json
import random
import uuid
import re
import statistics
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, quote, urlencode
from typing import List, Dict, Optional, Tuple, Any, Set
from .models import Endpoint, Severity, ResponseClass, _TECHNIQUE_TO_FAMILY, _CVSS_VECTORS
from .patterns import LDAP_ERRORS_RE, AUTH_SUCCESS_HIGH_RE, AUTH_SUCCESS_LOW_RE, AUTH_FAIL_RE, AUTH_FAIL_HTML_RE

def now_iso() -> str: return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def finding_id() -> str: return f"DNW-{uuid.uuid4().hex[:8].upper()}"

def build_curl_poc(ep: Endpoint, param: str, payload: str, cookies: Optional[Dict[str, str]] = None, extra_headers: Optional[Dict[str, str]] = None) -> str:
    safe_pl = quote(payload, safe=""); cookie_str = f" -b '{'; '.join(f'{k}={v}' for k, v in cookies.items())}'" if cookies else ""
    header_str = " -H 'Content-Type: application/json'" if ep.use_json else " -H 'Content-Type: application/x-www-form-urlencoded'"
    if extra_headers:
        for k, v in extra_headers.items(): header_str += f" -H '{k}: {v}'"
    if ep.method.upper() == "POST":
        body = json.dumps({param: payload}) if ep.use_json else f"{param}={safe_pl}"
        return f"curl -sk -X POST '{ep.url}'{cookie_str}{header_str} -d '{body}'"
    return f"curl -sk '{ep.url}?{param}={safe_pl}'{cookie_str}"

def build_raw_request(ep: Endpoint, param: str, payload: str) -> str:
    parsed = urlparse(ep.url); host = parsed.netloc; path = parsed.path or "/"
    if ep.method.upper() == "POST":
        data = {p: (payload if p == param else "8472") for p in ep.params}; body = urlencode(data)
        return f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    return f"GET {path}?{urlencode({param: payload})} HTTP/1.1\r\nHost: {host}\r\n\r\n"

def severity_from_score(score: float, has_auth_bypass: bool = False, has_error: bool = False) -> Tuple[Severity, str]:
    if has_auth_bypass: return Severity.CRITICAL, "Authentication bypass confirmed"
    if has_error and score >= 3.5: return Severity.HIGH, "LDAP error disclosure"
    if score >= 5.0: return Severity.CRITICAL, "Critical signal score"
    if score >= 3.5: return Severity.HIGH, "High signal score"
    if score >= 2.0: return Severity.MEDIUM, "Moderate signal"
    return Severity.LOW, "Low signal"

def assign_cvss(technique: str, has_auth_bypass: bool = False, requires_auth: bool = False) -> Tuple[str, float]:
    fam = _TECHNIQUE_TO_FAMILY.get(technique, "generic"); vec, score = _CVSS_VECTORS.get(fam, ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3))
    if has_auth_bypass: vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"; score = 9.1
    if requires_auth: vec = vec.replace("/PR:N/", "/PR:L/"); score = max(0, score - 0.5)
    return vec, round(score, 1)

def get_remediation(framework: str) -> str:
    rems = {"generic": "1. Parameterize LDAP queries.\n2. Escape metacharacters.\n3. Validate input."}
    return rems.get(framework.lower(), rems["generic"])

def safe_val(param: str, suffix: str = "8472") -> str:
    if "mail" in param.lower(): return f"test{suffix}@example.com"
    if "user" in param.lower(): return f"user{suffix}"
    return f"val{suffix}"

def build_safe_data(params: List[str], randomize: bool = True) -> Dict[str, str]:
    sfx = str(random.randint(1000, 9999)) if randomize else "8472"; return {p: safe_val(p, sfx) for p in params}

def build_injection_data(ep: Endpoint, param: str, payload: str, suffix: str = "") -> Dict[str, str]:
    return {p: (payload + suffix if p == param else safe_val(p)) for p in ep.params}

def vprint(msg: str): print(msg)
def info(msg: str): print(f"[*] {msg}")
def warn(msg: str): print(f"[!] {msg}")
def ok(msg: str): print(f"[+] {msg}")
def success(msg: str): print(f"[+] {msg}")
def finding(msg: str): print(f"[+] {msg}")
def detect_msg(msg: str): print(f"[*] {msg}")

def binomial_cdf(k: int, n: int, p: float = 0.5) -> float:
    from math import comb
    cdf = 0.0
    for i in range(k + 1): cdf += comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
    return cdf

def is_statistically_significant(hits: int, trials: int, alpha: float = 0.05, p_null: float = 0.5) -> bool:
    return (1.0 - binomial_cdf(hits - 1, trials, p_null)) < alpha
def err(msg: str): print(f"[-] {msg}")
def verbose(msg: str): pass

def domain_to_dc(domain: str) -> str: return ",".join(f"dc={part}" for part in domain.split(".") if part)
def sim_delta(a: str, b: str) -> float:
    if not a or not b: return 1.0
    return 1.0 - (len(set(a.split()) & set(b.split())) / max(len(set(a.split()) | set(b.split())), 1))

def classify_response_body(body: str, status: int, cookies: Set[str], has_prior_baseline: bool = False, baseline: Any = None) -> str:
    if status in (301, 302, 303, 307, 308): return ResponseClass.REDIRECT.value
    if status in (500, 502, 503) or LDAP_ERRORS_RE.search(body): return ResponseClass.ERROR.value
    is_success = bool(AUTH_SUCCESS_HIGH_RE.search(body) or AUTH_SUCCESS_LOW_RE.search(body))
    if is_success:
        if has_prior_baseline and baseline:
            if not bool(AUTH_SUCCESS_HIGH_RE.search(baseline.body) or AUTH_SUCCESS_LOW_RE.search(baseline.body)): return ResponseClass.AUTH_SUCCESS.value
        else: return ResponseClass.AUTH_SUCCESS.value
    if has_prior_baseline and baseline:
        if baseline.has_form and status == 200 and not re.search(r"<form[\s>]", body, re.I) and not (AUTH_FAIL_RE.search(body) or AUTH_FAIL_HTML_RE.search(body)): return ResponseClass.AUTH_SUCCESS.value
        if any(re.search(r"session|auth|token|jwt|sid|access", c, re.I) for c in (cookies - baseline.cookies)): return ResponseClass.AUTH_SUCCESS.value
    if AUTH_FAIL_RE.search(body) or AUTH_FAIL_HTML_RE.search(body) or status in (401, 403): return ResponseClass.AUTH_FAIL.value
    return ResponseClass.STATIC.value

def classify_response(resp: Any, baseline: Any) -> str:
    return classify_response_body(resp.text or "", resp.status_code, {c.name for c in resp.cookies}, True, baseline)

class AdaptiveRateController:
    def __init__(self, rps: float): self._delay = 1.0/rps if rps > 0 else 0; self._last = 0
    def wait(self):
        elapsed = time.time() - self._last
        if elapsed < self._delay: time.sleep(self._delay - elapsed)
        self._last = time.time()
    def throttle(self): self._delay *= 1.5
    def recover(self): self._delay = max(0.01, self._delay * 0.9)

class CSRFTokenManager:
    def __init__(self): self._tokens = {}
    def update_from_html(self, html: str):
        for m in re.finditer(r'name=["\'](?:csrf|token|nonce)["\'][^>]*value=["\']([^"\']+)["\']', html, re.I): self._tokens["csrf"] = m.group(1)
    def get_tokens(self) -> Dict[str, str]: return self._tokens

class C:
    BCYAN = "\033[96m"; BRED = "\033[91m"; BGREEN = "\033[92m"; BYELLOW = "\033[93m"; BWHITE = "\033[97m"; DIM = "\033[2m"; BOLD = "\033[1m"; RESET = "\033[0m"

def color(text: str, *codes: str) -> str: return "".join(codes) + str(text) + C.RESET
def tprint(msg: str): print(msg)
def section(title: str): print(f"\n{C.BOLD}{C.BCYAN}--- {title} ---{C.RESET}")
def phase_header(num: int, title: str): print(f"\n{C.BOLD}{C.BYELLOW}Phase {num}: {title}{C.RESET}")
def label(k: str, v: str): print(f"  {C.BCYAN}{k}:{C.RESET} {v}")
def budget_msg(msg: str): print(f"{C.DIM}[Budget] {msg}{C.RESET}")
def print_finding_card(f: Any, idx: int = 0):
    p = f"[{idx}] " if idx else ""
    print(f"\n{C.BRED}{C.BOLD}{p}CONFIRMED VULNERABILITY: LDAP Injection{C.RESET}")
    label("Endpoint", f.endpoint_url); label("Parameter", f.parameter_name); label("Payload", f.payload_raw); label("Severity", f.severity)

BANNER = "DNwatch v1.0"
