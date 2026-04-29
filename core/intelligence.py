import threading
import time
import re
import random
import statistics
import socket
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any, Tuple
from urllib.parse import urlparse
from enum import Enum
from collections import defaultdict
import requests
from .models import Endpoint, Payload, PayloadTier, ScanConfig, AuthState, HandoffFinding, _TECHNIQUE_TO_FAMILY
from .detection import DetectionResult
from .client import HTTPClient
from .utils import now_iso, info, warn, vprint, safe_val, sim_delta

class ControlPlaneMemory:
    def __init__(self):
        self._lock = threading.Lock(); self._payload_outcomes = defaultdict(lambda: [0, 0, 0]); self._encoding_scores = defaultdict(int); self._endpoint_states = defaultdict(dict); self._param_signals = defaultdict(set); self.framework = "generic"; self.waf_name = None; self.stack_hints = {}; self._csrf_map = {}; self._auth_tokens = {}; self.total_rate_limits = 0; self.consecutive_blocks = 0; self.adaptive_delay = 0.0; self._stored_markers = []
    def record_payload(self, raw: str, success: bool, waf_blocked: bool = False):
        with self._lock:
            o = self._payload_outcomes[raw[:60]]
            if success: o[0] += 1
            elif waf_blocked: o[2] += 1
            else: o[1] += 1
    def top_encodings(self, n: int = 3) -> List[str]:
        with self._lock: return [k for k, _ in sorted(self._encoding_scores.items(), key=lambda x: x[1], reverse=True)[:n]]
    def record_encoding(self, name: str, success: bool):
        with self._lock: self._encoding_scores[name] += (2 if success else -1)
    def record_rate_limit(self, url: str) -> float:
        with self._lock: self._endpoint_states[url]["rate_limited"] = True; self.total_rate_limits += 1; self.consecutive_blocks += 1; self.adaptive_delay = min(0.5 * (2 ** min(self.consecutive_blocks, 5)), 15.0); return self.adaptive_delay
    def record_success(self, url: str):
        with self._lock: self.consecutive_blocks = max(0, self.consecutive_blocks - 1); self.adaptive_delay = max(0.0, self.adaptive_delay * 0.8)
    def update_csrf(self, url: str, token: str):
        with self._lock: self._csrf_map[url] = token
    def record_param_signal(self, url: str, param: str):
        with self._lock: self._param_signals[url].add(param)
    def get_signaling_params(self, url: str) -> Set[str]:
        with self._lock: return set(self._param_signals.get(url, set()))

class ControlPlaneIntelligence:
    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg = cfg; self._client = client; self.memory = ControlPlaneMemory(); self._lock = threading.Lock()
    def on_waf_detected(self, waf_name: str, survived: Set[str]):
        self.memory.waf_name = waf_name; info(f"[CP] WAF '{waf_name}' detected — adapting strategy"); (self.memory.record_encoding("char_encode", True) if len(survived) < 4 else None)
    def on_rate_limit(self, url: str):
        delay = self.memory.record_rate_limit(url); warn(f"[CP] Rate limit on {url} — backing off {delay:.1f}s"); time.sleep(delay)
    def inter_request_delay(self) -> float:
        base = 1.0 / max(self._cfg.rps, 0.1); extra = self.memory.adaptive_delay; return base + extra + random.uniform(0.0, base * 0.3)

class WebSocketProbe:
    _WS_URL_RE = re.compile(r"""(?:new\s+WebSocket|io\.connect|socket\.connect|SockJS)\s*\(\s*[`'"](wss?://[^`'"]+)[`'"]""", re.I)
    _WS_PATH_RE = re.compile(r"""[`'"](\/(?:ws|socket\.io|sockjs|websocket|realtime|live)[^`'"?#\s]{0,100})[`'"]""", re.I)
    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg = cfg; self._client = client; self._target = cfg.target.rstrip("/")
    def probe(self, pages_html: List[str], js_urls: List[str]) -> List[Endpoint]:
        eps = []; seen = set()
        for html in pages_html:
            for m in self._WS_URL_RE.finditer(html): (eps.append(self._make_ws_ep(m.group(1))) if m.group(1) not in seen else None); seen.add(m.group(1))
        if eps: info(f"  [WS] Discovered {len(eps)} WebSocket endpoint(s)")
        return eps
    def _make_ws_ep(self, url: str) -> Endpoint: return Endpoint(url=url, method="WS", params=["message","data","query","filter"], source="websocket", auth_state=AuthState.UNAUTH, ldap_prob=25)

class RecursiveParameterDiscovery:
    def __init__(self, cfg: ScanConfig, client: HTTPClient): self._cfg = cfg; self._client = client
    def discover_specs(self, pages: List[str], client: HTTPClient) -> Tuple[List[str], List[str]]:
        oa = []; gql = []; target = self._cfg.target.rstrip("/")
        for p in ["/openapi.json", "/swagger.json", "/api-docs"]:
            try:
                r = client.get(target+p, phase="discovery")
                (oa.append(target+p) if r and r.status_code == 200 and "openapi" in r.text.lower() else None)
            except: pass
        return oa, gql

class BehavioralRiskAnalyzer:
    @dataclass
    class BehavioralRiskScore:
        param: str; function_class: str; timing_delta: float; size_delta: float; content_shift: float; signal_count: int; risk_level: str; evidence: List[str] = field(default_factory=list)
    def __init__(self, cfg: ScanConfig, client: HTTPClient, memory: ControlPlaneMemory): self._cfg = cfg; self._client = client; self._memory = memory
    def analyze_endpoint(self, ep: Endpoint) -> Dict[str, BehavioralRiskScore]:
        res = {}; bl_body = ""; bl_time = 0.05
        try:
            bl_resp = self._client.send_endpoint(ep, {p: safe_val(p) for p in ep.params}, phase="tier0")
            if bl_resp: bl_body = bl_resp.text or ""; bl_time = bl_resp.elapsed.total_seconds()
        except: pass
        for p in ep.params[:8]: score = self._probe_param(ep, p, bl_body, bl_time); res[p] = score; (self._memory.record_param_signal(ep.url, p) if score.risk_level == "HIGH" else None)
        return res
    def _probe_param(self, ep: Endpoint, param: str, bl_body: str, bl_time: float) -> BehavioralRiskScore:
        sigs = 0; ev = []; bl_len = len(bl_body)
        # Simplified probe for brevity
        return self.BehavioralRiskScore(param=param, function_class="generic", timing_delta=0, size_delta=0, content_shift=0, signal_count=0, risk_level="LOW")

class AdaptiveBaselineCircuitBreaker:
    class State(Enum): CLOSED = "CLOSED"; OPEN = "OPEN"; HALF_OPEN = "HALF_OPEN"
    @dataclass
    class EPState: failures: int = 0; state: str = "CLOSED"; last_fail_ts: float = 0.0
    def __init__(self, memory: ControlPlaneMemory): self._memory = memory; self._states = {}; self._lock = threading.Lock()
    def is_open(self, url: str) -> bool:
        with self._lock:
            st = self._states.get(url, self.EPState())
            if st.state == self.State.OPEN.value:
                if time.time() - st.last_fail_ts >= 8.0: st.state = self.State.HALF_OPEN.value; return False
                return True
            return False

class ConfidenceScorer:
    @staticmethod
    def score(det: DetectionResult, grade: str, oob: bool, replay: bool, sig_count: int) -> int:
        b = {"CONFIRMED": 60, "PROBABLE": 40, "CANDIDATE": 20}.get(grade, 0)
        b += min(sig_count * 5, 20)
        if oob: b += 15
        if replay: b += 5
        return min(int(b + det.score*2), 100)

class ImpactMapper:
    @classmethod
    def map_technique(cls, tech: str, sev: str, ext: Dict = None) -> Dict:
        fam = _TECHNIQUE_TO_FAMILY.get(tech, "generic"); return {"scenario": f"LDAP {fam} injection", "impact_type": fam, "severity": sev}

class CrossEndpointCorrelator:
    def __init__(self): self._findings = []; self._ep_by_param = defaultdict(list); self._lock = threading.Lock()
    def register(self, f: HandoffFinding):
        with self._lock: self._findings.append(f); self._ep_by_param[f.parameter_name].append(f.endpoint_url)
    def correlate(self) -> List[Dict]:
        res = []
        with self._lock:
            for p, urls in self._ep_by_param.items():
                if len(urls) >= 2: res.append({"type": "multi_endpoint_param", "param": p, "endpoints": list(dict.fromkeys(urls)), "description": f"Param '{p}' injectable across {len(urls)} endpoints", "severity": "HIGH"})
        return res
