import threading
from typing import Set, Dict, List
from collections import defaultdict

class LearningMemory:
    def __init__(self):
        self._lock = threading.Lock()
        self._success_payloads: Set[str] = set()
        self._failed_payloads: Set[str] = set()
        self._waf_blocked: Set[str] = set()
        self._ep_success: Dict[str, int] = defaultdict(int)

    def mark_success(self, url: str, payload: str):
        with self._lock: self._success_payloads.add(payload); self._ep_success[url] += 1

    def mark_failure(self, url: str, payload: str, waf: bool = False):
        with self._lock: (self._waf_blocked.add(payload) if waf else self._failed_payloads.add(payload))

    @property
    def failed_payloads(self) -> Set[str]: return set(self._failed_payloads)
