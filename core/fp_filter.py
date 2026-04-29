import threading
import re
from collections import defaultdict
from typing import List, Tuple, Dict, Any
from .models import Endpoint, Baseline, Payload
from .detection import DetectionPipeline, DetectionResult
from .client import HTTPClient
from .utils import build_safe_data, build_injection_data, sim_delta, warn, verbose
from .patterns import LDAP_ERRORS_RE

class FalsePositiveFilter:
    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline, cfg: Any):
        self._client = client; self._pipeline = pipeline; self._cfg = cfg; self._ep_fp_counts = defaultdict(int); self._lock = threading.Lock()
    def _layer1_benign_control(self, ep: Endpoint, param: str, payload: Payload, baseline: Baseline) -> Tuple[bool, str]:
        data = build_injection_data(ep, param, baseline.replay_params.get(param, ""), self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if not resp: return True, "L1: no response"
        res = self._pipeline.run(resp, baseline, payload)
        return (not res.fired, "L1: control clean" if not res.fired else "L1: benign triggers")
    def _layer2_cross_param(self, ep: Endpoint, param: str, payload: Payload, baseline: Baseline) -> Tuple[bool, str]:
        other = [p for p in ep.params if p != param][:3]
        if len(other) < 2: return True, "L2: low params"
        hits = 0
        for op in other:
            resp = self._client.send_endpoint(ep, build_injection_data(ep, op, payload.raw, self._cfg.deterministic_suffix), phase="verification")
            if resp and self._pipeline.run(resp, baseline, payload).fired: hits += 1
        return (hits < 2, f"L2: {hits}/{len(other)} cross hits")
    def _layer3_structural_uniqueness(self, inj_body: str, baseline: Baseline, control_body: str) -> Tuple[bool, str]:
        diff_bl = sim_delta(baseline.body, inj_body); diff_ctl = sim_delta(control_body, inj_body) if control_body else 1.0
        if LDAP_ERRORS_RE.search(inj_body) and not (LDAP_ERRORS_RE.search(control_body) if control_body else False) and not LDAP_ERRORS_RE.search(baseline.body):
            return True, f"L3(A): error in injection only (Δbl={diff_bl:.1%})"
        if diff_bl >= baseline.diff_threshold and diff_ctl >= (baseline.diff_threshold * 0.5):
            return True, f"L3(B): structural unique Δbl={diff_bl:.1%} Δctl={diff_ctl:.1%}"
        return False, f"L3: not unique Δbl={diff_bl:.1%}"
    def _layer4_replay_stability(self, hits: int) -> Tuple[bool, str]:
        return (hits >= 2, f"L4: replay stable {hits}/3")
    def _layer5_score_gate(self, result: DetectionResult) -> Tuple[bool, str]:
        det_names = [s.detector for s in result.signals]; has_strong = bool({"ClassTransition", "LDAPError", "Behavioral", "OOBCallback"} & set(det_names))
        min_sc = 4.5 if not has_strong else 0.0
        return (result.score >= min_sc, f"L5: score {result.score:.1f} OK")
    def _layer6_session_consistency(self, ep: Endpoint, baseline: Baseline) -> Tuple[bool, str]:
        resp = self._client.send_endpoint(ep, build_safe_data(ep.params, randomize=False), phase="verification")
        if not resp: return True, "L6: no response"
        delta = sim_delta(baseline.body, resp.text or "")
        return (delta <= max(baseline.diff_threshold * 1.5, 0.1), f"L6: consistent (Δ={delta:.1%})" if delta <= max(baseline.diff_threshold * 1.5, 0.1) else "L6: drift detected")
    def validate(self, ep: Endpoint, param: str, payload: Payload, baseline: Baseline, result: DetectionResult, inj_body: str, replay_hits: int, control_body: str = "", ldap_ports_open: bool = False) -> Tuple[bool, bool, List[str]]:
        reasons = []; ep_key = ep.key
        with self._lock: (reasons.append(f"UNRELIABLE: {self._ep_fp_counts[ep_key]} FPs") if self._ep_fp_counts[ep_key] >= 3 else None)
        l1_ok, l1_r = self._layer1_benign_control(ep, param, payload, baseline); reasons.append(l1_r)
        if not l1_ok: self._record_fp(ep_key); return False, False, reasons
        l2_ok, l2_r = self._layer2_cross_param(ep, param, payload, baseline); reasons.append(l2_r); (self._record_fp(ep_key) if not l2_ok else None)
        if not l2_ok: return False, False, reasons
        l3_ok, l3_r = self._layer3_structural_uniqueness(inj_body, baseline, control_body); reasons.append(l3_r); (self._record_fp(ep_key) if not l3_ok else None)
        if not l3_ok: return False, False, reasons
        l4_ok, l4_r = self._layer4_replay_stability(replay_hits); reasons.append(l4_r); (self._record_fp(ep_key) if not l4_ok else None)
        if not l4_ok: return False, False, reasons
        l5_ok, l5_r = self._layer5_score_gate(result); reasons.append(l5_r); (self._record_fp(ep_key) if not l5_ok else None)
        if not l5_ok: return False, False, reasons
        l6_ok, l6_r = self._layer6_session_consistency(ep, baseline); reasons.append(l6_r)
        return True, not l6_ok, reasons
    def _record_fp(self, key: str):
        with self._lock: self._ep_fp_counts[key] += 1; (warn(f"  EP {key} flagged unreliable") if self._ep_fp_counts[key] == 3 else None)
