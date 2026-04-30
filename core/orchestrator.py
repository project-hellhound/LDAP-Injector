import threading
import time
import os
import sys
import json
from datetime import datetime, timezone
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any

from .models import ScanConfig, ScanHandoff, Endpoint, AuthState, Baseline, ResponseClass, VerificationGrade, VolatilityClass
from .client import HTTPClient
from .budget import AdaptiveBudgetManager
from .learning import LearningMemory
from .discovery import Crawler, TargetLivenessChecker, DirectorySchemaProbe
from .detection import DetectionPipeline
from .verification import ThreeStepVerifier
from .fp_filter import FalsePositiveFilter
from .oob import OOBListener
from .extraction import BlindAttributeExtractor
from .state import ExploitStateTracker
from .payloads import PolymorphicPayloadGenerator, ChainedPayloadMutator, TargetAwarePayloadAdaptor
from .intelligence import ControlPlaneIntelligence, WebSocketProbe, RecursiveParameterDiscovery, BehavioralRiskAnalyzer, AdaptiveBaselineCircuitBreaker, ImpactMapper
from .logging import ScanSessionLogger
from .reporting import HandoffSerializer, HTMLReportGenerator, FindingDeduplicator
from .engine import InjectionEngine
from .utils import info, warn, success, verbose, vprint, section, phase_header, color, C, print_finding_card, safe_val, now_iso, classify_response

class ScanOrchestrator:
    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg; self._start = datetime.now(timezone.utc); self._handoff = ScanHandoff(scan_id=cfg.scan_id, target=cfg.target, timestamp_start=now_iso())
        self._budget = AdaptiveBudgetManager(cfg); self._client = HTTPClient(cfg, self._budget); self._memory = LearningMemory(); self._cp = ControlPlaneIntelligence(cfg, self._client); self._logger = ScanSessionLogger(cfg); self._serializer = HandoffSerializer(cfg)
        self._pipeline = DetectionPipeline(cfg)
        self._verifier = ThreeStepVerifier(self._client, self._pipeline, self._budget)
        self._fp = FalsePositiveFilter(self._client, self._pipeline, cfg)
        self._oob = OOBListener(self._cfg.collab, self._cfg.scan_id, self._cfg.oob_port) if self._cfg.collab else None

    def run(self) -> str:
        phase_header(1, "Pre-flight & Discovery")
        live = TargetLivenessChecker(self._cfg).check()
        if not live["live"]: warn(f"Target might be down (DNS: {live['dns_ok']}, HTTP: {live['http_ok']})"); (sys.exit(1) if not self._cfg.force_scan else None)
        
        if self._cfg.auth_url:
            self._client.authenticate()

        crawler = Crawler(self._client, self._cfg); eps = crawler.crawl(self._cfg.target)
        if not eps: warn("No injectable endpoints discovered."); return self._finalize([])
        info(f"  Discovered {len(eps)} potential endpoint(s).")

        baselines = {}; phase_header(2, "Baselines")
        for ep in eps:
            bl = self._collect_baseline(ep)
            if bl: baselines[ep.key] = bl

        phase_header(3, "Injection & Detection")
        engine = InjectionEngine(self._cfg, self._client, self._budget, self._memory, self._pipeline, self._verifier, self._fp, self._oob, baselines, self._logger)
        
        all_findings = []
        with ThreadPoolExecutor(max_workers=self._cfg.threads) as executor:
            future_to_ep = {executor.submit(engine.scan_endpoint, ep): ep for ep in eps}
            for future in as_completed(future_to_ep):
                found, incs = future.result()
                all_findings.extend(found)
                for f in found:
                    if not self._cfg.quiet: print_finding_card(f)

        deduped = FindingDeduplicator.dedup(all_findings)
        return self._finalize(deduped)

    def _collect_baseline(self, ep: Endpoint) -> Optional[Baseline]:
        verbose(f"  Baselining {ep.url}...")
        resp = self._client.send_endpoint(ep, {p: safe_val(p) for p in ep.params}, phase="discovery")
        if not resp: return None
        
        bl = Baseline(
            status=resp.status_code,
            body=resp.text or "",
            body_len=len(resp.text or ""),
            body_hash=hashlib.md5((resp.text or "").encode()).hexdigest() if resp.text else "",
            norm_body_hash="",
            has_form="<form" in (resp.text or "").lower(),
            final_url=resp.url,
            cookies={c.name for c in resp.cookies},
            response_class=classify_response(resp, None),
            replay_params={p: safe_val(p) for p in ep.params},
            headers=dict(resp.headers)
        )
        bl.set_volatility_thresholds()
        return bl

    def _finalize(self, findings: List[Any]) -> str:
        self._handoff.confirmed_findings = [asdict(f) for f in findings]
        self._handoff.endpoints_discovered = len(self._handoff.confirmed_findings) # Simplified
        return self._serializer.emit(self._handoff, self._start)

import hashlib
