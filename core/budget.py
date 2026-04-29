import threading
from typing import Dict, List, Optional
from collections import defaultdict
from .models import ScanConfig, BudgetMode
from .utils import budget_msg

class AdaptiveBudgetManager:
    POOL_TIER0        = "tier0_qualify"
    POOL_DISCOVERY    = "discovery"
    POOL_INJECTION    = "injection"
    POOL_VERIFICATION = "verification"
    POOL_EMERGENCY    = "emergency"

    _RATIOS: Dict[str, List[float]] = {
        BudgetMode.MINIMAL.value:    [0.18, 0.15, 0.45, 0.17, 0.05],
        BudgetMode.STANDARD.value:   [0.18, 0.12, 0.40, 0.25, 0.05],
        BudgetMode.HIGH_VALUE.value: [0.16, 0.10, 0.38, 0.30, 0.06],
    }

    _BASE_TOTALS: Dict[str, int] = {
        BudgetMode.MINIMAL.value:    300,
        BudgetMode.STANDARD.value:   800,
        BudgetMode.HIGH_VALUE.value: 1500,
    }

    _EP_FLOOR = 15

    def __init__(self, cfg: ScanConfig):
        self._cfg       = cfg
        self._lock      = threading.Lock()
        self._mode      = BudgetMode.STANDARD
        self._total     = cfg.request_budget
        self._pools:    Dict[str, int] = {}
        self._used:     Dict[str, int] = {}
        self._donated:  Dict[str, int] = defaultdict(int)
        self._ep_floors_reserved = 0
        self._signal_active      = False
        self._initialized        = False
        self._pre_init_burned    = 0

    def select_mode(self, endpoint_count: int, ldap_signals_found: bool, ldap_ports_open: bool, waf_detected: bool) -> BudgetMode:
        is_high_value = (ldap_signals_found or ldap_ports_open or waf_detected or endpoint_count >= 20)
        is_minimal = (endpoint_count < 8 and not ldap_signals_found and not ldap_ports_open and not waf_detected)
        if is_high_value: self._mode = BudgetMode.HIGH_VALUE
        elif is_minimal: self._mode = BudgetMode.MINIMAL
        else: self._mode = BudgetMode.STANDARD
        budget_msg(f"Budget mode: {self._mode.value} (endpoints={endpoint_count} ldap_signals={ldap_signals_found} ports_open={ldap_ports_open} waf={waf_detected})")
        return self._mode

    def initialize(self, qualified_endpoint_count: int, mode: Optional[BudgetMode] = None) -> None:
        if mode: self._mode = mode
        mode_key = self._mode.value
        base_total = self._BASE_TOTALS[mode_key]
        if self._mode == BudgetMode.HIGH_VALUE:
            dynamic_total = max(base_total, qualified_endpoint_count * 35)
            self._total = min(dynamic_total, self._cfg.request_budget) if self._cfg.request_budget != 800 else dynamic_total
        else:
            self._total = min(base_total, self._cfg.request_budget)
        with self._lock:
            self._total = max(1, self._total - self._pre_init_burned)
        floors_needed = qualified_endpoint_count * self._EP_FLOOR
        ratios = self._RATIOS[mode_key]
        pool_names = [self.POOL_TIER0, self.POOL_DISCOVERY, self.POOL_INJECTION, self.POOL_VERIFICATION, self.POOL_EMERGENCY]
        with self._lock:
            for name, ratio in zip(pool_names, ratios):
                self._pools[name] = max(1, int(self._total * ratio))
                self._used[name]  = 0
            inj_pool = self._pools[self.POOL_INJECTION]
            if floors_needed > inj_pool:
                max_eps = inj_pool // self._EP_FLOOR
                self._ep_floors_reserved = max_eps * self._EP_FLOOR
                budget_msg(f"Budget floor trimming: can guarantee floor for {max_eps}/{qualified_endpoint_count} endpoints")
            else:
                self._ep_floors_reserved = floors_needed
            self._initialized = True
        budget_msg(f"Budget initialized: total={self._total} mode={mode_key} pools={self.status()}")

    def _acquire(self, pool: str, count: int = 1) -> bool:
        with self._lock:
            if not self._initialized:
                pre_used = sum(self._used.values())
                if pre_used + count <= self._cfg.request_budget:
                    self._used[pool] = self._used.get(pool, 0) + count
                    self._pre_init_burned += count
                    return True
                return False
            if self._used[pool] + count <= self._pools[pool]:
                self._used[pool] += count
                return True
            return False

    def acquire_tier0(self)        -> bool: return self._acquire(self.POOL_TIER0)
    def acquire_discovery(self)    -> bool: return self._acquire(self.POOL_DISCOVERY)
    def acquire_injection(self)    -> bool: return self._acquire(self.POOL_INJECTION)
    def acquire_verification(self) -> bool: return self._acquire(self.POOL_VERIFICATION)
    def acquire_emergency(self)    -> bool:
        if not self._signal_active: return False
        return self._acquire(self.POOL_EMERGENCY)

    def signal_active(self, active: bool) -> None:
        with self._lock: self._signal_active = active

    def acquire_for_phase(self, phase: str) -> bool:
        dispatch = {"tier0": self.acquire_tier0, "discovery": self.acquire_discovery, "injection": self.acquire_injection, "verification": self.acquire_verification, "emergency": self.acquire_emergency}
        return dispatch.get(phase, self.acquire_injection)()

    def donate_unused(self, from_pool: str) -> int:
        if not self._initialized: return 0
        with self._lock:
            unused = self._pools.get(from_pool, 0) - self._used.get(from_pool, 0)
            if unused > 0 and from_pool != self.POOL_INJECTION:
                self._pools[self.POOL_INJECTION] += unused
                self._pools[from_pool] = self._used.get(from_pool, 0)
                self._donated[from_pool] += unused
                budget_msg(f"Donated {unused} from {from_pool} → injection pool")
                return unused
        return 0

    def donate_all_unused_to_injection(self) -> int:
        return sum(self.donate_unused(p) for p in [self.POOL_TIER0, self.POOL_DISCOVERY, self.POOL_EMERGENCY])

    def _remaining(self, pool: str) -> int:
        return self._pools.get(pool, 0) - self._used.get(pool, 0)

    def remaining(self, pool: str) -> int:
        with self._lock: return self._remaining(pool)

    def total_used(self) -> int:
        with self._lock: return sum(self._used.values())

    def total_remaining(self) -> int:
        with self._lock: return sum(self._remaining(p) for p in self._pools)

    def status(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            return {p: {"total": self._pools[p], "used": self._used[p], "remaining": self._remaining(p)} for p in self._pools}

    def log_status(self) -> str:
        s = self.status()
        return f"Budget[{' | '.join([f'{p[:3]}:{v['used']}/{v['total']}' for p, v in s.items()])}]"

    @property
    def mode(self) -> BudgetMode: return self._mode
    @property
    def total(self) -> int: return self._total
