import json
import threading
import uuid
import os
from typing import Dict, List, Optional, Any
from .utils import now_iso
from .models import HandoffFinding

class ScanSessionLogger:
    def __init__(self, cfg: Any):
        self._path = os.path.join(cfg.output_dir, cfg.audit_file); os.makedirs(cfg.output_dir, exist_ok=True); self._lock = threading.Lock(); self._seq = 0; self._current = threading.local()
    def _write(self, event: str, data: Dict, rid: str = None):
        rid = rid or getattr(self._current, 'id', 'default')
        entry = {"ts": now_iso(), "seq": self._seq, "event": event, "request_id": rid, **data}
        try:
            with self._lock: self._seq += 1; (open(self._path, "a", encoding="utf-8").write(json.dumps(entry, default=str) + "\n"))
        except: pass
    def set_request_id(self, rid: str): self._current.id = rid
    def gen_request_id(self) -> str: rid = f"inj-{uuid.uuid4().hex[:12]}"; self.set_request_id(rid); return rid
    def log_phase(self, phase: str, details: Dict = None, rid: str = None): self._write("PHASE_START", {"phase": phase, **(details or {})}, rid=rid)
    def log_signal(self, ep_key: str, param: str, payload: str, detectors: List[str], score: float, rid: str = None): self._write("SIGNAL", {"ep_key": ep_key, "param": param, "payload": payload[:80], "detectors": detectors, "score": round(score, 3)}, rid=rid)
    def log_finding(self, f: HandoffFinding, rid: str = None): self._write("FINDING", {"finding_id": f.finding_id, "url": f.endpoint_url, "param": f.parameter_name, "severity": f.severity, "grade": f.verification_grade}, rid=rid)
    def log_error(self, area: str, msg: str, rid: str = None): self._write("ERROR", {"area": area, "message": msg}, rid=rid)
