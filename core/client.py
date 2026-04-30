import requests
import random
import threading
import time
import re
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from .models import ScanConfig, AuthState, Endpoint
from .utils import (
    AdaptiveRateController, CSRFTokenManager, warn, info, err, success, 
    verbose, tprint, C, color, label, build_safe_data, build_injection_data
)
from .patterns import WAF_SIGS, AUTH_EP_RE, AUTH_FAIL_RE, LDAP_METACHAR_SET, _USER_AGENTS, _ACCEPT_LANGS
from .budget import AdaptiveBudgetManager

class AccountLockoutGuard:
    def __init__(self, max_attempts: int = 5):
        self.max_attempts = max_attempts
        self._failures = defaultdict(int)
        self._lock = threading.Lock()

    def should_skip(self, url: str) -> bool:
        if not AUTH_EP_RE.search(url): return False
        with self._lock: return self._failures[url] >= self.max_attempts

    def mark_failure(self, url: str):
        if not AUTH_EP_RE.search(url): return
        with self._lock:
            self._failures[url] += 1
            if self._failures[url] == self.max_attempts:
                warn(f"Account lockout safety triggered for {url}. Skipping further auth probes.")

class InjectionSafetyGuard:
    DANGER_KEYWORDS = ["delete", "drop", "modify", "remove", "trunc"]
    @classmethod
    def is_safe(cls, url: str, payload: str) -> bool:
        url_lower = url.lower()
        if "password" in url_lower and "change" in url_lower: return False
        pay_lower = payload.lower()
        for k in cls.DANGER_KEYWORDS:
            if f"({k}" in pay_lower: return False
        return True

class HTTPClient:
    def __init__(self, cfg: ScanConfig, budget: AdaptiveBudgetManager):
        self._cfg = cfg; self._budget = budget
        self._gap = 1.0 / max(cfg.rps, 0.1); self._proxies = ({"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else {})
        self._tlock = threading.Lock(); self._last = defaultdict(float)
        self.rate_controller = AdaptiveRateController(cfg.rps); self.csrf_manager = CSRFTokenManager(); self.lockout_guard = AccountLockoutGuard()
        self._per_host_limiters = defaultdict(lambda: threading.Semaphore(2)); self._host_limiter_lock = threading.Lock()
        self._waf_name = "Generic"; self._waf_detected = False; self._waf_delay = 0.0; self._waf_count = 0; self._framework = "Generic"; self._survived_chars = set(LDAP_METACHAR_SET)
        pool_size = min(cfg.threads, 4); self._unauth_pool = [self._build_session() for _ in range(pool_size)]; self._auth_pool = []; self._pool_idx = 0; self._pool_lock = threading.Lock()
        for s in self._unauth_pool:
            for n, v in cfg.cookies.items(): s.cookies.set(n, v)
            for n, v in cfg.extra_headers.items(): s.headers[n] = v
        self._req_count = 0; self._req_lock = threading.Lock()

    def _build_session(self) -> requests.Session:
        s = requests.Session(); retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry); s.mount("http://", adapter); s.mount("https://", adapter)
        s.headers.update({"User-Agent": random.choice(_USER_AGENTS), "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9", "Accept-Language": random.choice(_ACCEPT_LANGS), "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"})
        if self._proxies: s.proxies.update(self._proxies)
        s.verify = self._cfg.verify_ssl; return s

    def authenticate(self) -> bool:
        if not self._cfg.auth_url or not self._cfg.auth_data: return False
        info(f"  Authenticating: {self._cfg.auth_url}")
        try:
            auth_session = self._build_session()
            for n, v in self._cfg.cookies.items(): auth_session.cookies.set(n, v)
            resp = auth_session.post(self._cfg.auth_url, data=self._cfg.auth_data, timeout=self._cfg.timeout, verify=self._cfg.verify_ssl, allow_redirects=True)
            cookies_found = {c.name: c.value for r in (getattr(resp, "history", []) + [resp]) for c in r.cookies}
            token = None
            try: j = resp.json(); token = j.get("token") or j.get("access_token") or j.get("jwt")
            except Exception: pass
            if not cookies_found and not token: return False
            self._auth_pool = []
            for _ in range(min(self._cfg.threads, 4)):
                s = self._build_session()
                for n, v in self._cfg.cookies.items(): s.cookies.set(n, v)
                for n, v in cookies_found.items(): s.cookies.set(n, v)
                if token: s.headers["Authorization"] = f"Bearer {token}"
                self._auth_pool.append(s)
            success(f"  Authenticated: {len(cookies_found)} cookie(s) {'+ JWT' if token else ''}")
            return True
        except Exception as exc: err(f"  Authentication error: {exc}"); return False

    @property
    def auth_available(self) -> bool: return len(self._auth_pool) > 0

    def _get_session(self, auth_state: AuthState) -> requests.Session:
        with self._pool_lock:
            pool = self._auth_pool if auth_state == AuthState.AUTH and self._auth_pool else self._unauth_pool
            s = pool[self._pool_idx % len(pool)]; self._pool_idx += 1; return s

    def _get_host_limiter(self, url: str) -> threading.Semaphore:
        try: netloc = urlparse(url).netloc.lower()
        except Exception: netloc = "__default__"
        with self._host_limiter_lock: return self._per_host_limiters[netloc]

    def _send(self, method: str, url: str, auth_state: AuthState = AuthState.UNAUTH, phase: str = "injection", follow_redirects: bool = True, _retry_count: int = 0, **kwargs) -> Optional[requests.Response]:
        if self.lockout_guard.should_skip(url): return None
        self.rate_controller.wait(); host_limiter = self._get_host_limiter(url); host_limiter.acquire()
        try:
            if "data" in kwargs and isinstance(kwargs["data"], dict):
                tokens = self.csrf_manager.get_tokens()
                for k, v in tokens.items():
                    if k not in kwargs["data"]: kwargs["data"][k] = v
            try:
                s = self._get_session(auth_state)
                resp = s.request(method, url, timeout=self._cfg.timeout, proxies=self._proxies, verify=self._cfg.verify_ssl, allow_redirects=follow_redirects, **kwargs)
                if resp.status_code == 429:
                    self.rate_controller.throttle()
                    if _retry_count < 3: return self._send(method, url, auth_state, phase, follow_redirects, _retry_count=_retry_count + 1, **kwargs)
                    return resp
                self.rate_controller.recover(); self.csrf_manager.update_from_html(resp.text); self._handle_waf_response(resp.status_code, resp.text[:1000])
                if resp.status_code in (401, 403) or AUTH_FAIL_RE.search(resp.text): self.lockout_guard.mark_failure(url)
                return resp
            except requests.exceptions.RequestException: return None
        finally: host_limiter.release()

    def _handle_waf_response(self, status: int, body: str = "") -> None:
        if status in (403, 406, 429):
            with self._tlock:
                self._waf_delay = min(getattr(self, "_waf_delay", 0) + 0.4, 3.0)
                self._waf_count = getattr(self, "_waf_count", 0) + 1
                self._waf_detected = True
            if not self._waf_name:
                for name, pat in WAF_SIGS:
                    if pat.search(body): self._waf_name = name; break
        else:
            with self._tlock: self._waf_count = max(0, self._waf_count - 1)

    def _inc(self) -> None:
        with self._req_lock: self._req_count += 1

    def get(self, url: str, params: Optional[Dict] = None, auth_state: AuthState = AuthState.UNAUTH, phase: str = "discovery") -> Optional[requests.Response]:
        if not self._budget.acquire_for_phase(phase): return None
        self._inc(); return self._send("GET", url, auth_state=auth_state, phase=phase, params=params or {})

    def post(self, url: str, data: Optional[Dict] = None, json_body: Optional[Dict] = None, auth_state: AuthState = AuthState.UNAUTH, phase: str = "injection", follow_redirects: bool = True) -> Optional[requests.Response]:
        if not self._budget.acquire_for_phase(phase): return None
        self._inc(); kwargs = {"data": data} if data else {"json": json_body}
        return self._send("POST", url, auth_state=auth_state, phase=phase, follow_redirects=follow_redirects, **kwargs)

    def request(self, method: str, url: str, data: Optional[Dict] = None, json_body: Optional[Dict] = None, auth_state: AuthState = AuthState.UNAUTH, phase: str = "injection") -> Optional[requests.Response]:
        return self._send(method, url, auth_state=auth_state, phase=phase, data=data, json=json_body)

    def send_endpoint(self, ep: Endpoint, data: Dict[str, str], phase: str = "injection") -> Optional[requests.Response]:
        if not InjectionSafetyGuard.is_safe(ep.url, str(data)): return None
        if ep.use_json: return self.post(ep.url, json_body=data, auth_state=ep.auth_state, phase=phase)
        return self.request(ep.method, ep.url, data=data, auth_state=ep.auth_state, phase=phase)

    def send_header(self, ep: Endpoint, header_name: str, payload: str, phase: str = "injection") -> Optional[requests.Response]:
        if not InjectionSafetyGuard.is_safe(ep.url, payload): return None
        data = build_safe_data(ep.params, randomize=False); session = self._get_session(ep.auth_state); old_val = session.headers.get(header_name)
        session.headers[header_name] = payload
        try: resp = self._send(ep.method, ep.url, auth_state=ep.auth_state, phase=phase, data=data)
        finally:
            if old_val is None: session.headers.pop(header_name, None)
            else: session.headers[header_name] = old_val
        return resp

    @property
    def total_requests(self) -> int: return self._req_count
    @property
    def waf_detected(self) -> bool: return self._waf_detected
    @property
    def waf_name(self) -> Optional[str]: return self._waf_name
