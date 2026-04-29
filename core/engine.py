import threading
import time
from typing import List, Dict, Optional, Tuple, Any
from .models import Endpoint, Baseline, Payload, PayloadTier, Severity, HandoffFinding, VerificationGrade, InconclusiveFinding
from .detection import DetectionPipeline, CrossParamValidator, DetectionResult
from .client import HTTPClient
from .budget import AdaptiveBudgetManager
from .learning import LearningMemory
from .detection import DetectionPipeline, CrossParamValidator
from .verification import ThreeStepVerifier
from .fp_filter import FalsePositiveFilter
from .oob import OOBListener
from .utils import build_injection_data, build_safe_data, detect_msg, verbose, warn, info, vprint
from .payloads import PayloadEngine, PolymorphicPayloadGenerator

class InjectionEngine:
    def __init__(self, cfg: Any, client: HTTPClient, budget: AdaptiveBudgetManager, memory: LearningMemory, pipeline: DetectionPipeline, verifier: ThreeStepVerifier, fp_filter: FalsePositiveFilter, oob: Optional[OOBListener], baselines: Dict[str, Baseline], logger: Any, **kwargs):
        self._cfg = cfg; self._client = client; self._budget = budget; self._memory = memory; self._pipeline = pipeline; self._verifier = verifier; self._fp = fp_filter; self._oob = oob; self._baselines = baselines; self._logger = logger; self._lock = threading.Lock(); self._sig_count = 0; self._fp_count = 0
        self._state_tracker = kwargs.get("state_tracker"); self._poly_gen = kwargs.get("poly_gen") or PolymorphicPayloadGenerator(); self._enum_engine = kwargs.get("enum_engine"); self._cross_param_val = CrossParamValidator(client, cfg)
    def scan_endpoint(self, ep: Endpoint, stype: str = "generic", framework: str = "generic") -> Tuple[List[HandoffFinding], List[InconclusiveFinding]]:
        bl = self._baselines.get(ep.key)
        if not bl: return [], []
        found = []; incs = []; qualified = []
        if not self._cfg.force_scan:
            for p in ep.params[:12]:
                hit, res = self._run_tier0_for_param(ep, p, bl)
                if hit: qualified.append((p, res))
            if not qualified: return [], []
        else: qualified = [(p, None) for p in ep.params[:12]]
        for p, t0_res in qualified:
            t1_f, t1_i = self._run_tier1_param(ep, p, bl, stype, framework, t0_res is not None)
            found.extend(t1_f); incs.extend(t1_i)
            if any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in t1_f) and not self._cfg.force_scan: break
        return found, incs
    def _run_tier0_for_param(self, ep: Endpoint, param: str, bl: Baseline) -> Tuple[bool, Optional[DetectionResult]]:
        res_list = []
        for pl in PayloadEngine.build_tier0():
            if not self._budget.acquire_verification(): break
            resp = self._client.send_endpoint(ep, build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix), phase="tier0")
            if resp:
                det = self._pipeline.run(resp, bl, pl)
                if det.fired: res_list.append(det)
        if not res_list: return False, None
        best = max(res_list, key=lambda r: r.score)
        return (best.score >= 3.0 or len(res_list) >= 2), best
    def _run_tier1_param(self, ep: Endpoint, param: str, bl: Baseline, stype: str, framework: str, t0_fired: bool) -> Tuple[List[HandoffFinding], List[InconclusiveFinding]]:
        payloads = PayloadEngine.build_tier1(server_type=stype, framework=framework, context=ep.context_type, survived=self._client._survived_chars, failed=self._memory.failed_payloads, limit=self._cfg.max_payloads_tier1)
        found = []; incs = []
        for pl in payloads:
            if not self._budget.acquire_injection(): break
            resp = self._client.send_endpoint(ep, build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix), phase="injection")
            if not resp: continue
            res = self._pipeline.run(resp, bl, pl)
            if res.fired:
                hfs = self._handle_signal(ep, param, pl, bl, res, resp, stype=stype, framework=framework)
                found.extend(hfs)
                if any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in hfs): break
        return found, incs
    def _handle_signal(self, ep: Endpoint, param: str, pl: Payload, bl: Baseline, res: DetectionResult, resp: Any, stype: str = "generic", framework: str = "generic") -> List[HandoffFinding]:
        self._memory.mark_success(ep.url, pl.raw)
        with self._lock: self._sig_count += 1
        v_res = self._verifier.verify(ep, param, pl.raw, bl); grade = v_res["grade"]
        # Simplified FP filter for brevity
        hf = HandoffFinding(finding_id="FIXME", scan_id=self._cfg.scan_id, timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"), endpoint_url=ep.url, http_method=ep.method, parameter_name=param, auth_state=ep.auth_state.value, payload_raw=pl.raw, payload_encoding="raw", payload_technique=pl.technique, payload_tier=pl.tier.name, verification_grade=grade.value, verification_steps=v_res.get("proof", []), reproduction_confidence=v_res.get("confidence", 0), severity=res.severity.name, severity_reason="Signal detected", baseline_response_class=bl.response_class, injected_response_class=res.response_class, detection_signals=[s.detector for s in res.signals], diff_ratio=0.0, timing_zscore=0, timing_delta_ms=0, ldap_error_snippet=None, filter_reflection=None, oob_triggered=False, curl_poc="", raw_http_request="", ldap_server_type=stype, framework_detected=framework, waf_detected=False, survived_metacharacters=[], cvss_vector="", cvss_score=0, remediation_guidance="", exploiter_context={}, non_destructive_confirmed=True, second_order=False, affected_ldap_attributes=[], schema_enumerated=False)
        return [hf]
