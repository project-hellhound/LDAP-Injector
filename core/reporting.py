import hashlib
import re
import os
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any
from .models import HandoffFinding, VerificationGrade, AuthState, ResponseClass, RawLDAPFinding, ScanHandoff
from .utils import now_iso

class FindingDeduplicator:
    _GRADE_ORDER = {VerificationGrade.CONFIRMED.value: 4, VerificationGrade.PROBABLE.value: 3, VerificationGrade.CANDIDATE.value: 2, VerificationGrade.REJECTED.value: 1}
    @classmethod
    def _payload_structural_hash(cls, pl: str) -> str:
        norm = re.sub(r'[\s]+', '', pl.lower()); struc = re.sub(r'(?<=[=(])[a-z0-9@._\-]{4,}(?=[)&|*])', 'V', norm)
        return hashlib.md5(struc.encode()).hexdigest()[:10]
    @classmethod
    def dedup(cls, findings: List[HandoffFinding]) -> List[HandoffFinding]:
        groups = {}
        for f in findings:
            p = urlparse(f.endpoint_url); k = f"{f.http_method}:{p.netloc.lower()}{(p.path.rstrip('/') or '/').lower()}:{f.parameter_name}:{cls._payload_structural_hash(f.payload_raw or '')}"
            groups.setdefault(k, []).append(f)
        res = []
        for g in groups.values():
            best = max(g, key=lambda x: (cls._GRADE_ORDER.get(x.verification_grade, 0), x.reproduction_confidence))
            best.alternative_payloads = [f.payload_raw for f in g if f.payload_raw != best.payload_raw][:5]
            if len({f.auth_state for f in g}) > 1: best.auth_state = AuthState.BOTH.value
            res.append(best)
        res.sort(key=lambda x: (-{"CRITICAL":4, "HIGH":3, "MEDIUM":2, "LOW":1, "INFO":0}.get(x.severity, 0), -x.reproduction_confidence))
        return res

class HandoffSerializer:
    def __init__(self, cfg: Any): self._cfg = cfg
    def _finding_to_dict(self, f: HandoffFinding) -> Dict:
        return {k: getattr(f, k) for k in f.__dataclass_fields__ if not k.startswith('_')}
    def emit(self, handoff: ScanHandoff, start_time: datetime) -> str:
        doc = handoff.__dict__.copy(); doc["duration_seconds"] = (datetime.now(timezone.utc) - start_time).total_seconds(); doc["timestamp_end"] = now_iso()
        out = os.path.join(self._cfg.output_dir, self._cfg.findings_file); os.makedirs(self._cfg.output_dir, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh: json.dump(doc, fh, indent=2, default=str)
        return out

class HTMLReportGenerator:
    @classmethod
    def generate(cls, handoff: ScanHandoff, trace: List[Dict]) -> str:
        return "<html><body><h1>Scan Report</h1></body></html>"
