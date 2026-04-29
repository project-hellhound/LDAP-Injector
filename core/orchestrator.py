import threading
import time
import os
import sys
import json
from datetime import datetime, timezone
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any

from .models import ScanConfig, ScanHandoff, Endpoint, AuthState, Baseline, ResponseClass, VerificationGrade
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
from .utils import info, warn, success, verbose, vprint, section, phase_header, color, C, print_finding_card, safe_val, now_iso

class ScanOrchestrator:
    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg; self._start = datetime.now(timezone.utc); self._handoff = ScanHandoff(scan_id=cfg.scan_id, target=cfg.target, timestamp_start=now_iso())
        self._budget = AdaptiveBudgetManager(cfg); self._client = HTTPClient(cfg, self._budget); self._memory = LearningMemory(); self._cp = ControlPlaneIntelligence(cfg, self._client); self._logger = ScanSessionLogger(cfg); self._serializer = HandoffSerializer(cfg)
    def run(self) -> str:
        phase_header(1, "Pre-flight & Discovery")
        live = TargetLivenessChecker(self._cfg).check()
        if not live["live"]: warn(f"Target might be down (DNS: {live['dns_ok']}, HTTP: {live['http_ok']})"); (sys.exit(1) if not self._cfg.force_scan else None)
        crawler = Crawler(self._client, self._cfg); eps = crawler.crawl(self._cfg.target)
        # Simplified discovery for brevity
        baselines = {}; phase_header(2, "Baselines")
        # Logic to collect baselines...
        phase_header(3, "Injection & Detection")
        # Logic to run injection...
        return self._finalize([])
    def _finalize(self, findings: List[Any]) -> str:
        # Categorize and emit...
        return self._serializer.emit(self._handoff, self._start)
