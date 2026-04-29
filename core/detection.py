import re
import requests
import json
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
from .models import DetectionSignal, Severity, ResponseClass, Baseline, ScanConfig, Payload
from .utils import classify_response, sim_delta, severity_from_score
from .patterns import LDAP_ERRORS_RE, LDAP_ERRORS_LOW_RE, AUTH_SUCCESS_HIGH_RE, AUTH_SUCCESS_LOW_RE, AUTH_FAIL_RE, AUTH_FAIL_HTML_RE, PROTECTED_PATH_RE, LDAP_FILTER_REFLECT_RE, LDAP_METACHAR_SET

@dataclass
class DetectionResult:
    fired: bool
    score: float
    signals: List[DetectionSignal]
    severity: Severity
    evidence: str
    has_auth_bypass: bool = False
    has_error: bool = False
    response_class: str = ResponseClass.STATIC.value

class DetectionPipeline:
    def __init__(self, cfg: ScanConfig): self._cfg = cfg
    def _d1_class_transition(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        bl_class = baseline.response_class; resp_class = classify_response(resp, baseline)
        if bl_class == resp_class or bl_class == ResponseClass.AUTH_SUCCESS.value: return None
        trans = {(ResponseClass.AUTH_FAIL.value, ResponseClass.AUTH_SUCCESS.value): (5.5, True), (ResponseClass.AUTH_FAIL.value, ResponseClass.REDIRECT.value): (5.0, True), (ResponseClass.STATIC.value, ResponseClass.AUTH_SUCCESS.value): (4.5, True), (ResponseClass.STATIC.value, ResponseClass.REDIRECT.value): (3.5, False), (ResponseClass.ERROR.value, ResponseClass.AUTH_SUCCESS.value): (3.5, True), (ResponseClass.AUTH_FAIL.value, ResponseClass.ERROR.value): (3.0, False), (ResponseClass.STATIC.value, ResponseClass.ERROR.value): (2.5, False)}
        score, bypass = trans.get((bl_class, resp_class), (1.0, False))
        return DetectionSignal("ClassTransition", score, f"Response class: {bl_class} → {resp_class}", f"Baseline: {bl_class}, Post: {resp_class}")
    def _d2_ldap_error(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        combined = (resp.text or "")
        if "application/json" in resp.headers.get("Content-Type", ""):
            try: combined += " " + json.dumps(resp.json())
            except Exception: pass
        if LDAP_ERRORS_RE.search(baseline.body) or LDAP_ERRORS_LOW_RE.search(baseline.body): return None
        m_high = LDAP_ERRORS_RE.search(combined)
        if m_high: return DetectionSignal("LDAPError", 3.5, f"LDAP error (HIGH): {combined[max(0, m_high.start()-5):m_high.end()+80].strip()[:100]!r}")
        m_low = LDAP_ERRORS_LOW_RE.search(combined)
        if m_low: return DetectionSignal("LDAPErrorLow", 1.5, f"LDAP error (LOW): {combined[max(0, m_low.start()-5):m_low.end()+80].strip()[:100]!r}")
        return None
    def _d3_behavioral(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        combined = (resp.text or ""); indicators = []; sc_high = 0.0; sc_low = 0.0
        if AUTH_SUCCESS_HIGH_RE.search(combined) and not AUTH_SUCCESS_HIGH_RE.search(baseline.body): sc_high += 2.5; indicators.append("Auth-success (high) appeared")
        if AUTH_SUCCESS_LOW_RE.search(combined) and not AUTH_SUCCESS_LOW_RE.search(baseline.body): sc_low += 1.0; indicators.append("Auth-success (low) candidate")
        if (AUTH_FAIL_RE.search(baseline.body) or AUTH_FAIL_HTML_RE.search(baseline.body)) and not (AUTH_FAIL_RE.search(combined) or AUTH_FAIL_HTML_RE.search(combined)): sc_high += 2.0; indicators.append("Auth failure disappeared")
        if baseline.has_form and 'action=' in baseline.body.lower() and not re.search(r"<form[\s>]", combined, re.I): sc_high += 1.5; indicators.append("Login form absent")
        new_ck = {c.name for c in resp.cookies if re.search(r"session|auth|token|jwt|sid|access", c.name, re.I)} - baseline.cookies
        if new_ck: sc_high += 2.0; indicators.append(f"New auth cookies: {sorted(new_ck)}")
        if resp.status_code == 200 and baseline.status in (400, 401, 403): sc_high += 2.5; indicators.append(f"Status escalation {baseline.status}→200")
        if resp.status_code in (301, 302, 303) and PROTECTED_PATH_RE.search(resp.headers.get("Location","")): sc_high += 2.5; indicators.append(f"Redirect to protected: {resp.headers.get('Location')}")
        total = sc_high + (sc_low * 0.5 if sc_high >= 4.0 else 0)
        total *= self._cfg.behavioral_sensitivity
        return DetectionSignal("Behavioral", total, " | ".join(indicators), (resp.text or "")[:200].replace("\n"," ")) if total > 0 else None
    def _d4_structural(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        if baseline.highly_dynamic: return None
        diff = sim_delta(baseline.body, resp.text or "")
        if diff < baseline.diff_threshold: return None
        if baseline.len_variance > 0 and diff < ((baseline.len_variance**0.5)/max(baseline.body_len,1))*2.5: return None
        return DetectionSignal("StructuralDiff", min(diff*5.0, 2.5), f"Structure changed: Δ={diff:.1%}")
    def _d5_boolean(self, true_body: str, false_body: str, baseline: Baseline) -> Optional[DetectionSignal]:
        if baseline.highly_dynamic or not true_body or not false_body: return None
        tf_delta = sim_delta(true_body, false_body); fbl_delta = sim_delta(false_body, baseline.body)
        if tf_delta >= baseline.bool_threshold and fbl_delta < baseline.diff_threshold: return DetectionSignal("BooleanDifferential", 2.5, f"Boolean TRUE/FALSE Δtf={tf_delta:.1%}")
        return None
    def _d6_filter_reflect(self, resp: requests.Response) -> Optional[DetectionSignal]:
        m = LDAP_FILTER_REFLECT_RE.search(resp.text or "")
        return DetectionSignal("FilterReflection", 1.5, f"Filter reflected: {(resp.text or '')[max(0, m.start()-5):m.end()+80]!r}") if m else None
    def _d7_timing(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        z_min = self._cfg.calibrated_z_min or self._cfg.timing_z_min; t = resp.elapsed.total_seconds()
        if not baseline.is_timing_anomaly(t, z_min): return None
        return DetectionSignal("TimingOracle", 1.5, f"Timing anomaly: {t*1000:.0f}ms (z={baseline.z_score(t):.1f}σ)")
    def _d8_oob(self, oob_triggered: bool) -> Optional[DetectionSignal]:
        return DetectionSignal("OOBCallback", 4.0, "OOB callback confirmed") if oob_triggered else None
    def _d9_header_anomaly(self, resp: requests.Response, baseline: Baseline) -> Optional[DetectionSignal]:
        hdr_re = re.compile(r"X-LDAP-DN|X-Auth-User|X-Remote-User|X-Username|ldap|directory|dn=|cn=|dc=|objectclass", re.I)
        for n, v in resp.headers.items():
            if (hdr_re.search(n) or hdr_re.search(v)) and baseline.headers.get(n) != v: return DetectionSignal("HeaderAnomaly", 2.0, f"LDAP header appeared/changed: {n}", f"{n}: {v[:100]}")
        return None
    def _aggregate(self, signals: List[DetectionSignal], resp: requests.Response, baseline: Baseline) -> DetectionResult:
        if not signals: return DetectionResult(False, 0.0, [], Severity.LOW, "")
        total = min(sum(s.score for s in signals), 10.0); det_names = [s.detector for s in signals]
        if len(signals) == 1:
            sole = signals[0].detector
            if sole not in ("ClassTransition", "OOBCallback", "HeaderAnomaly") and not (sole == "Behavioral" and total >= 4.0) and not (sole == "LDAPError" and total >= 3.5): return DetectionResult(False, total, signals, Severity.LOW, f"{sole} alone - insufficient")
        if len(signals) >= 2 and total < 2.0: return DetectionResult(False, total, signals, Severity.LOW, "Multi-signal but score too low")
        has_bypass = "ClassTransition" in det_names or ("Behavioral" in det_names and any("bypass" in s.indicator.lower() or "success" in s.indicator.lower() for s in signals))
        sev, reason = severity_from_score(total, has_bypass, "LDAPError" in det_names)
        return DetectionResult(True, total, signals, sev, "; ".join(s.indicator for s in signals[:3]), has_bypass, "LDAPError" in det_names, classify_response(resp, baseline))
    def run(self, resp: requests.Response, baseline: Baseline, payload: Payload, true_body: Optional[str] = None, false_body: Optional[str] = None, oob_triggered: bool = False) -> DetectionResult:
        signals = []; d1 = self._d1_class_transition(resp, baseline)
        if d1: signals.append(d1); return self._aggregate(signals, resp, baseline)
        for d in [self._d2_ldap_error(resp, baseline), self._d3_behavioral(resp, baseline), self._d4_structural(resp, baseline)]: (signals.append(d) if d else None)
        if true_body and false_body: (signals.append(self._d5_boolean(true_body, false_body, baseline)) if self._d5_boolean(true_body, false_body, baseline) else None)
        for d in [self._d6_filter_reflect(resp), self._d9_header_anomaly(resp, baseline), self._d8_oob(oob_triggered)]: (signals.append(d) if d else None)
        if sum(s.score for s in signals) < 2.0: (signals.append(self._d7_timing(resp, baseline)) if self._d7_timing(resp, baseline) else None)
        return self._aggregate(signals, resp, baseline)

class CrossParamValidator:
    def __init__(self, client: Any, cfg: Any): self._client = client; self._cfg = cfg
    def validate(self, ep: Endpoint, trigger_param: str, trigger_payload: str, baseline: Any, pipeline: DetectionPipeline, budget: Any) -> Dict[str, Any]:
        res = {"cross_param_confirmed": False, "sibling_anomalies": [], "confidence_boost": 0}
        siblings = [p for p in ep.params if p != trigger_param][:4]
        if not siblings: return res
        anomalies = 0
        for sib in siblings:
            if not budget.acquire_injection(): break
            data = {p: (trigger_payload if p == trigger_param else safe_val(sib) if p == sib else baseline.replay_params.get(p, safe_val(p))) for p in ep.params}
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp:
                det = pipeline.run(resp, baseline, Payload(raw=trigger_payload, desc="cross-param", technique="cross_param", tier=PayloadTier.TIER1_CORE))
                if det.fired: anomalies += 1; res["sibling_anomalies"].append({"sibling": sib, "score": det.score})
        if anomalies >= 2: res["cross_param_confirmed"] = True; res["confidence_boost"] = 20
        elif anomalies == 1: res["confidence_boost"] = 10
        return res
