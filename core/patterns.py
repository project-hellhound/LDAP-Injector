import re
from typing import List, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# §4  REGEX ARSENAL — Detection patterns only
# ═══════════════════════════════════════════════════════════════════════════════

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

AUTH_SUCCESS_HIGH_RE = re.compile(
    r"\b(logout|sign.out|authenticated|dashboard|admin.panel|control.panel|"
    r"authorized|session.active|access\s+granted|valid\s+(?:user|login|credentials?)|"
    r"user.menu|user.avatar|logout.btn|sign.out.link|account.menu|profile|"
    r"flag\{|HTB\{|ROOT\{)\b",
    re.I,
)

AUTH_SUCCESS_LOW_RE = re.compile(
    r"\b(my.account|login\s+success|"
    r"you\s+are\s+(?:logged|connected|authenticated)\b|"
    r"vous\s+[êe]tes\s+connect|bienvenue|connexion\s+r.ussie|"
    r"bienvenido|acceso\s+concedido|willkommen|erfolgreich\s+angemeldet|"
    r"bem.vindo|acesso\s+permitido)\b",
    re.I,
)

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

LOCKOUT_RE = re.compile(
    r"account\s+locked|too\s+many\s+attempts|locked\s+out|"
    r"temporary\s+block|retry\s+later|suspicious\s+activity|"
    r"blocked\s+due\s+to\s+security",
    re.I,
)

AUTH_FAIL_HTML_RE = re.compile(
    r'class=["\'][^"\']*(?:error|alert[\s_-]*danger|login[\s_-]*error|'
    r'auth[\s_-]*error|invalid[\s_-]*credential|form[\s_-]*error|'
    r'message[\s_-]*error|alert[\s_-]*red|flash[\s_-]*error)[^"\']*["\']|'
    r'id=["\'][^"\']*(?:error[\s_-]*message|login[\s_-]*error|'
    r'auth[\s_-]*fail|invalid[\s_-]*msg)[^"\']*["\']',
    re.I,
)

LDAP_FILTER_REFLECT_RE = re.compile(
    r"\(&\s*\([a-zA-Z]+=|\(objectClass=\w+\)|\(\|\s*\(uid=|"
    r"\(\|\s*\(cn=|filter\s+(?:used|applied|executed)\s*[:\-]?\s*[\(\[]|"
    r"Bad\s+filter\s*:\s*[\(\[]|filter\s+error.*[\(\[]|"
    r"^\s*\(&|^\s*\(\||"
    r"(?:search|query)\s+filter\s*[=:]\s*[\(\[]",
    re.I | re.M,
)

PROTECTED_PATH_RE = re.compile(
    r"/(dashboard|admin|panel|portal|home|account|profile|"
    r"management|settings|overview|control|users|directory|protected)",
    re.I,
)

DYNAMIC_TOKEN_RE = re.compile(
    r"(?:csrf|nonce|token|_token|requestId|viewstate|__viewstate|"
    r"authenticity_token|_csrf)\s*[:=]\s*[\"']?[a-zA-Z0-9+/=_\-]{8,}[\"']?|"
    r"\b\d{10,13}\b|"
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|"
    r'"_csrf"\s*:\s*"[a-zA-Z0-9\-_]{10,}"',
    re.I,
)

STATIC_EXT_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|'
    r'map|pdf|zip|gz|mp4|mp3|avi|mov)$',
    re.I,
)

AUTH_EP_RE = re.compile(
    r"/login|/signin|/auth|/sso|/bind|/token|/session|/oidc|/saml|/cas",
    re.I,
)

LDAP_METACHAR_SET = ["*", "(", ")", "|", "&", "\\", "\x00", "%00"]

JS_FETCH_RE    = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*"""
    r"""\(\s*[`'"](\/[^`'"?#\s]{1,200})[`'"]""",
    re.I,
)
JS_API_PATH_RE = re.compile(
    r"""[`'"](\/api\/[v\d]*\/?[a-zA-Z0-9_\-\/]{1,100})[`'"]"""
)

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]
_ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.7"]

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

HIGH_RISK_RE = re.compile(
    r"user|uid|login|account|principal|sAMAccountName|"
    r"search|query|filter|ldap|dn|cn|ou|dc|"
    r"directory|member|group|role|credential",
    re.I
)
MED_RISK_RE = re.compile(
    r"name|email|mail|id|value|text|data|param|"
    r"username|password|pass|pwd|token|session",
    re.I
)
