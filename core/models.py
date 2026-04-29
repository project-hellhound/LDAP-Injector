from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid
import statistics
import re
import requests

# ═══════════════════════════════════════════════════════════════════════════════
# §5  ENUMERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    CRITICAL = 4
    HIGH     = 3
    MEDIUM   = 2
    LOW      = 1
    INFO     = 0

class VerificationGrade(Enum):
    CONFIRMED = "CONFIRMED"   # All 3 verification steps passed
    PROBABLE  = "PROBABLE"    # Steps 1+3 passed, step 2 inconclusive
    CANDIDATE = "CANDIDATE"   # Step 1 passed, replay inconsistent
    REJECTED  = "REJECTED"    # FP filtered or step 1 failed

class ResponseClass(Enum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAIL    = "AUTH_FAIL"
    ERROR        = "ERROR"
    REDIRECT     = "REDIRECT"
    STATIC       = "STATIC"

class VolatilityClass(Enum):
    STATIC         = "STATIC"          # CV < 0.05  — stable pages
    UNSTABLE       = "UNSTABLE"        # CV 0.05–0.25 — some dynamic content
    HIGHLY_DYNAMIC = "HIGHLY_DYNAMIC"  # CV > 0.25  — heavy dynamic content

class AuthState(Enum):
    UNAUTH = "unauth"
    AUTH   = "auth"
    BOTH   = "both"

class LDAPServerType(Enum):
    AD       = "ad"
    OPENLDAP = "openldap"
    DS389    = "389ds"
    NOVELL   = "novell"
    ORACLE   = "oracle"
    GENERIC  = "generic"

class BudgetMode(Enum):
    MINIMAL    = "A"  # < 8 endpoints, no LDAP signals — 300 requests
    STANDARD   = "B"  # Default — 800 requests
    HIGH_VALUE = "C"  # LDAP signals found or LDAP ports open — 1500 requests

class PayloadTier(Enum):
    TIER0_PROBE    = 0   # 3 payloads — always runs, free budget
    TIER1_CORE     = 1   # 8 payloads — runs when Tier 0 signals
    TIER2_BOOLEAN  = 2   # 6 payloads — blind oracle confirmation
    TIER3_WAF      = 3   # Dynamic — generated from successful T1 payload
    TIER4_OOB      = 4   # 3 payloads — only when collab host configured
    TIER5_MUTATION = 5   # Obfuscated/mutated bypass payloads
    TIER6_SECOND_ORDER = 6 # Probes reflected after initial injection

# ═══════════════════════════════════════════════════════════════════════════════
# §6  CORE DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    target:              str
    scan_id:             str            = field(default_factory=lambda: uuid.uuid4().hex[:12])
    deterministic_suffix: str           = field(default_factory=lambda: uuid.uuid4().hex[:8])
    auth_url:            Optional[str]  = None
    auth_data:           Dict[str, str] = field(default_factory=dict)
    cookies:             Dict[str, str] = field(default_factory=dict)
    extra_headers:       Dict[str, str] = field(default_factory=dict)
    proxy:               Optional[str]  = None
    verify_ssl:          bool           = False
    timeout:             int            = 12
    rps:                 float          = 4.0
    threads:             int            = 4
    depth:               int            = 4
    crawl_page_limit:    int            = 200
    request_budget:      int            = 800
    budget_mode:         Optional[str]  = None
    min_ldap_prob:       int            = 10
    entropy_min:         float          = 0.05
    timing_z_min:        float          = 2.5
    max_payloads_tier1:  int            = 8
    second_order_delay:  float          = 1.0
    server_type:         str            = "auto"
    calibrated_z_min:    Optional[float]= None
    extract:             bool           = False
    extract_limit:       int            = 32
    replay_count:        int            = 5
    no_extract:          bool           = False
    collab:              Optional[str]  = None
    oob_port:            int            = 53
    force_scan:          bool           = False
    safe_mode:           bool           = False
    js_crawl:            bool           = True
    apispec_harvest:     bool           = True
    sitemap_harvest:     bool           = True
    headless:            bool           = False
    cred_file:           Optional[str]  = None
    output_dir:          str            = "."
    findings_file:       str            = "ldapi_findings_{scan_id}.json"
    audit_file:          str            = "ldapi_audit.ndjson"
    checkpoint_file:     str            = "checkpoint.json"
    verbose:             bool           = False
    quiet:               bool           = False
    min_confidence:      int            = 0
    resume:              bool           = False
    endpoints_file:      Optional[str]  = None
    behavioral_sensitivity: float       = 1.0
    timing_extract:         bool        = False
    timing_sleep_ms:        int         = 2000
    timing_samples:         int         = 5
    stateful_mode:          bool        = False
    state_delay:            float       = 2.0
    polymorphic_waf:        bool        = True
    poly_depth:             int         = 3
    context_aware:          bool        = True
    schema_probe_enabled:   bool        = True
    schema_discovery:       bool        = True
    enumerate_schema:       bool        = False
    enum_max_users:         int         = 50
    enum_attrs:             List[str]   = field(default_factory=list)

@dataclass
class Endpoint:
    url:             str
    method:          str
    params:          List[str]
    source:          str
    auth_state:      AuthState              = AuthState.UNAUTH
    is_auth_ep:      bool                   = False
    ldap_prob:       int                    = 0
    priority:        float                  = 0.0
    use_json:        bool                   = False
    csrf_data:       Dict[str, str]         = field(default_factory=dict)
    default_params:  Dict[str, str]         = field(default_factory=dict)
    context_type:    str                    = "generic"
    framework:       Optional[str]          = None
    discovered_via:  str                    = ""
    array_params:    List[str]              = field(default_factory=list)

    @property
    def key(self) -> str:
        from urllib.parse import urlparse
        p = urlparse(self.url)
        state = self.auth_state.value
        return (f"{self.method.upper()}:"
                f"{p.netloc.lower()}"
                f"{(p.path.rstrip('/') or '/').lower()}"
                f":{state}")

@dataclass
class ScanHandoff:
    schema_version:   str   = "3.0"
    tool:             str   = "LDAPi Detection Agent"
    scan_id:          str   = ""
    target:           str   = ""
    timestamp_start:  str   = ""
    timestamp_end:    str   = ""
    duration_seconds: float = 0.0

    # Scan context (from Phase 0)
    ldap_server_type:        str          = "generic"
    framework_detected:      str          = "generic"
    waf_detected:            bool         = False
    waf_name:                str          = ""
    survived_metacharacters: List[str]    = field(default_factory=list)
    raw_ldap_ports_open:     List[int]    = field(default_factory=list)
    auth_tested:             bool         = False
    budget_mode:             str          = "B"

    # Findings by grade
    confirmed_findings:  List[Dict]  = field(default_factory=list)
    probable_findings:   List[Dict]  = field(default_factory=list)
    candidate_findings:  List[Dict]  = field(default_factory=list)
    inconclusive_ldap_findings: List[Dict] = field(default_factory=list)
    raw_ldap_findings:   List[Dict]  = field(default_factory=list)

    # Statistics
    total_requests:          int  = 0
    endpoints_discovered:    int  = 0
    endpoints_scanned:       int  = 0
    unauth_endpoints_tested: int  = 0
    auth_endpoints_tested:   int  = 0
    payloads_sent:           int  = 0
    signals_fired:           int  = 0
    fp_filtered:             int  = 0
    total_cvss_score:        float = 0.0

    # V11 — WAF Indeterminate State
    waf_confidence:              str          = "indeterminate"

    # V11 — Liveness pre-flight
    target_live:                 bool         = True
    target_dns_resolved:         bool         = False
    target_ports_open:           List[int]    = field(default_factory=list)

    # V11 — Execution trace
    execution_trace:             List[Dict]   = field(default_factory=list)

    # V8 — Extended handoff fields
    cross_endpoint_correlations: List[Dict] = field(default_factory=list)
    behavioral_risk_summary:     Dict[str, Any] = field(default_factory=dict)
    control_plane_summary:       Dict[str, Any] = field(default_factory=dict)
    openapi_specs_found:         List[str]      = field(default_factory=list)
    graphql_endpoints_found:     List[str]      = field(default_factory=list)
    websocket_endpoints_found:   List[str]      = field(default_factory=list)
    adaptive_delay_applied:      float          = 0.0
    mutation_chains_effective:   List[str]      = field(default_factory=list)

@dataclass
class Baseline:
    status:            int
    body:              str
    body_len:          int
    body_hash:         str
    norm_body_hash:    str
    has_form:          bool
    final_url:         str
    cookies:           Set[str]
    response_class:    str
    volatility:        VolatilityClass = VolatilityClass.STATIC
    samples:           List[float]     = field(default_factory=list)
    len_samples:       List[int]       = field(default_factory=list)
    len_variance:      float           = 0.0
    unstable:          bool            = False
    highly_dynamic:    bool            = False
    replay_params:     Dict[str, str]  = field(default_factory=dict)
    diff_threshold:    float           = 0.05
    bool_threshold:    float           = 0.08
    headers:           Dict[str, str]  = field(default_factory=dict)

    def set_volatility_thresholds(self) -> None:
        if self.volatility == VolatilityClass.STATIC:
            self.diff_threshold = 0.03
            self.bool_threshold = 0.05
        elif self.volatility == VolatilityClass.UNSTABLE:
            self.diff_threshold = 0.08
            self.bool_threshold = 0.12
        else:
            self.diff_threshold = 0.15
            self.bool_threshold = 0.20

    @property
    def median_time(self) -> float:
        s = self._iqr_samples()
        return statistics.median(s) if s else 0.5

    @property
    def stddev(self) -> float:
        s = self._iqr_samples()
        if len(s) < 2:
            return max(self.median_time * 0.3, 0.3)
        if self.unstable:
            med = statistics.median(s)
            mad = statistics.median([abs(x - med) for x in s])
            return max(1.4826 * mad, 0.05)
        return statistics.stdev(s)

    def _iqr_samples(self) -> List[float]:
        s = sorted(self.samples)
        if len(s) < 4:
            return s
        q1, q3 = s[len(s) // 4], s[3 * len(s) // 4]
        iqr = q3 - q1
        return [x for x in s
                if (q1 - 1.5 * iqr) <= x <= (q3 + 1.5 * iqr)] or s

    def z_score(self, t: float) -> float:
        return (t - self.median_time) / max(self.stddev, 0.05)

    def is_timing_anomaly(self, t: float, z_min: Optional[float] = None) -> bool:
        threshold = z_min or 3.0
        if self.unstable:
            threshold *= 1.5
        absolute_min = 0.4
        return (self.z_score(t) >= threshold and (t - self.median_time) >= absolute_min)

@dataclass
class Payload:
    raw:              str
    desc:             str
    technique:        str
    tier:             PayloadTier
    priority:         int  = 5
    context:          str  = "any"
    server:           str  = "any"
    cve_ref:          str  = ""
    waf_blocked_count:int  = 0  
    encoded_already:  bool = False

@dataclass
class DetectionSignal:
    detector:  str
    score:     float
    indicator: str
    evidence:  str  = ""

@dataclass
class RawLDAPFinding:
    host:         str
    port:         int
    finding_type: str
    severity:     Severity
    evidence:     str
    bind_dn:      str   = ""
    bind_pw:      str   = ""
    server_type:  str   = "generic"
    rootdse_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class InconclusiveFinding:
    endpoint_url:    str
    parameter_name:  str
    signal_fired:    str
    reason:          str
    payloads_tried:  List[str]
    recommendation:  str

@dataclass
class HandoffFinding:
    finding_id:              str
    scan_id:                 str
    timestamp:               str
    endpoint_url:            str
    http_method:             str
    parameter_name:          str
    auth_state:              str
    severity:                str
    confidence:              int
    verification_grade:      str
    payload_raw:             str
    payload_technique:       str
    ldap_error_snippet:      Optional[str] = None
    curl_poc:                str           = ""
    reproduction_confidence: int           = 0
    impact_scenario:         str           = ""
    exploiter_context:       Dict[str, Any] = field(default_factory=dict)
    oob_triggered:           bool          = False

_TECHNIQUE_TO_FAMILY = {
    "auth_bypass": "bypass", "ad_bypass": "bypass", "ol_bypass": "bypass", "spring_ldap": "bypass", "shiro_ldap": "bypass", "adsi_bypass": "bypass", "or_chain": "bypass", "null_byte": "bypass", "url_encoded": "bypass", "bool_true": "boolean", "bool_false": "boolean", "bool_enum": "boolean", "structural": "probe", "syntax": "probe", "wildcard": "probe", "oob_referral": "oob", "dn_inject": "dn_inject", "attr_harvest": "attr_harvest", "attr_inject": "attr_inject", "ad_enum": "enum", "ol_enum": "enum", "waf_url": "waf_bypass", "waf_hex": "waf_bypass", "second_order": "second_order", "cve_shiro": "bypass", "cve_spring": "bypass", "cve_null": "bypass", "cve_ldap3": "bypass", "cve_log4shell": "oob", "cve_nss": "bypass", "cve_nopac": "bypass", "cve_jboss": "bypass", "cve_manage": "bypass", "cve_vmware": "bypass", "cve_cisco": "bypass", "cve_openfire": "bypass", "cve_citrix": "bypass", "cve_confluence": "bypass",
}

_CVSS_VECTORS = {
    "bypass": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1), "boolean": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5), "probe": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3), "oob": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6), "dn_inject": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2), "attr_harvest": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5), "attr_inject": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2), "enum": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3), "waf_bypass": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4), "second_order": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
}
