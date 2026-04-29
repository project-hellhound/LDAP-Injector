import time
import re
import statistics
import threading
import uuid
from typing import List, Tuple, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
try: from bs4 import BeautifulSoup; _BS4_OK = True
except ImportError: _BS4_OK = False
from .models import Endpoint, Baseline, VolatilityClass, ScanConfig
from .client import HTTPClient
from .utils import (
    build_safe_data, safe_val, warn, verbose, info, ok, 
    _body_hash, _norm_body_hash, classify_baseline_response
)
from .patterns import AUTH_SUCCESS_HIGH_RE, AUTH_FAIL_RE

class VolatilityClassifier:
    @staticmethod
    def classify(len_samples: List[int]) -> VolatilityClass:
        if len(len_samples) < 2: return VolatilityClass.STATIC
        s = sorted(len_samples); q1, q3 = s[len(s)//4], s[3*len(s)//4]; iqr = q3 - q1
        clean = [x for x in s if (q1 - 1.5*iqr) <= x <= (q3 + 1.5*iqr)] or s
        mean = sum(clean) / len(clean)
        if mean < 1: return VolatilityClass.STATIC
        std = statistics.stdev(clean) if len(clean) > 1 else 0; cv = std / max(mean, 1)
        if cv < 0.05: return VolatilityClass.STATIC
        if cv < 0.25: return VolatilityClass.UNSTABLE
        return VolatilityClass.HIGHLY_DYNAMIC
    @staticmethod
    def calibrate_thresholds(vol: VolatilityClass) -> Tuple[float, float]:
        if vol == VolatilityClass.STATIC: return 0.08, 0.10
        if vol == VolatilityClass.UNSTABLE: return 0.12, 0.18
        return 0.30, 0.38

class BaselineCollector:
    _SAMPLES_INITIAL = 4
    _RATELIMIT_RE = re.compile(r"rate\s*limit|too\s*many\s*requests|slow\s*down|throttl", re.I)
    def __init__(self, client: HTTPClient, cfg: ScanConfig):
        self._client = client; self._cfg = cfg
    def _collect_batch(self, ep: Endpoint, n: int) -> Tuple[List[float], List[int], List[Any]]:
        timings = []; lengths = []; resps = []
        for _ in range(n):
            data = build_safe_data(ep.params, randomize=True); start = time.monotonic()
            resp = self._client.send_endpoint(ep, data, phase="discovery")
            if resp is not None:
                if resp.status_code == 429 or self._RATELIMIT_RE.search(resp.text or ""):
                    warn(f"  Rate limit detected during baseline for {ep.url}"); time.sleep(2.0); continue
                timings.append(time.monotonic() - start); lengths.append(len(resp.text or "")); resps.append(resp)
            time.sleep(0.08)
        return timings, lengths, resps
    def collect(self, ep: Endpoint) -> Optional[Baseline]:
        timings, lengths, resps = self._collect_batch(ep, self._SAMPLES_INITIAL)
        if not resps: return None
        vol = VolatilityClassifier.classify(lengths)
        if vol == VolatilityClass.UNSTABLE: t2, l2, r2 = self._collect_batch(ep, 4); timings += t2; lengths += l2; resps += r2
        elif vol == VolatilityClass.HIGHLY_DYNAMIC: t3, l3, r3 = self._collect_batch(ep, 10); timings += t3; lengths += l3; resps += r3
        if not resps: return None
        median_len = sorted(lengths)[len(lengths) // 2]; last = min(resps, key=lambda r: abs(len(r.text or "") - median_len))
        diff_thr, bool_thr = VolatilityClassifier.calibrate_thresholds(vol); body = last.text or ""; replay = build_safe_data(ep.params, randomize=False); defaults = {}
        if _BS4_OK:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for inp in soup.find_all(["input", "select"]):
                    if inp.get("name") in ep.params: defaults[inp.get("name")] = inp.get("value", "") or ""
            except Exception: pass
        for p in ep.params: (defaults.setdefault(p, replay.get(p, "")))
        if not ep.default_params: ep.default_params = defaults
        bl = Baseline(status=last.status_code, body=body, body_len=len(body), body_hash=_body_hash(body), norm_body_hash=_norm_body_hash(body), has_form=bool(re.search(r"<form[\s>]", body, re.I)), final_url=last.url, cookies={c.name for c in last.cookies}, response_class=classify_baseline_response(last), volatility=vol, samples=timings, len_samples=lengths, len_variance=statistics.variance(lengths) if len(lengths) >= 2 else 0.0, unstable=(vol != VolatilityClass.STATIC), highly_dynamic=(vol == VolatilityClass.HIGHLY_DYNAMIC), replay_params=replay, diff_threshold=diff_thr, bool_threshold=bool_thr, headers=dict(last.headers))
        if AUTH_SUCCESS_HIGH_RE.search(body) and not AUTH_FAIL_RE.search(body) and ep.is_auth_ep:
            for _ in range(3):
                alt_data = {p: safe_val(p, uuid.uuid4().hex[:8]) for p in ep.params}; alt_resp = self._client.send_endpoint(ep, alt_data, phase="discovery")
                if alt_resp and not AUTH_SUCCESS_HIGH_RE.search(alt_resp.text or ""):
                    bl.body = alt_resp.text or ""; bl.body_len = len(bl.body); bl.body_hash = _body_hash(bl.body); bl.norm_body_hash = _norm_body_hash(bl.body); bl.response_class = classify_baseline_response(alt_resp); bl.replay_params = alt_data; ok(f"  Baseline re-sampled clean"); break
        verbose(f"  Baseline: {ep.url} [{ep.auth_state.value}] vol={vol.value} len={bl.body_len}"); return bl
    def collect_parallel(self, eps: List[Endpoint], max_workers: int = 4) -> Dict[str, Baseline]:
        results = {}; lock = threading.Lock()
        def _job(ep: Endpoint):
            bl = self.collect(ep)
            if bl:
                with lock: results[ep.key] = bl
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for fut in as_completed([pool.submit(_job, ep) for ep in eps]):
                try: fut.result()
                except Exception as exc: verbose(f"  Baseline error: {exc}")
        info(f"  Baselines collected: {len(results)}/{len(eps)}"); return results
