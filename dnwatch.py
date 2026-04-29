import sys
import argparse
import traceback
import os
from typing import Dict, Optional
from core.models import ScanConfig
from core.orchestrator import ScanOrchestrator
from core.utils import BANNER, warn, info, err

def _parse_cookies(s: Optional[str]) -> Dict[str, str]:
    if not s: return {}
    res = {}
    for p in s.split(";"):
        p = p.strip()
        if "=" in p: k, _, v = p.partition("="); res[k.strip()] = v.strip()
    return res

def _parse_headers(s: Optional[str]) -> Dict[str, str]:
    if not s: return {}
    res = {}
    for p in s.split(","):
        p = p.strip()
        if ":" in p: k, _, v = p.partition(":"); res[k.strip()] = v.strip()
    return res

def _parse_auth_data(s: Optional[str]) -> Dict[str, str]:
    if not s: return {}
    return dict(p.split("=", 1) for p in s.split("&") if "=" in p)

def _parse_args():
    p = argparse.ArgumentParser(prog="dnwatch", description="DNwatch: Advanced LDAP Injection Security Toolkit")
    p.add_argument("target", help="Target base URL (e.g., http://nexus-corp.internal)")
    
    auth = p.add_argument_group("Authentication & Connection")
    auth.add_argument("--auth-url", metavar="URL", help="URL to perform authentication")
    auth.add_argument("--auth-data", metavar="DATA", help="POST data for auth (e.g., 'user=admin&pass=123')")
    auth.add_argument("--cookies", metavar="COOKIES", help="Semicolon-separated cookies")
    auth.add_argument("--headers", metavar="HEADERS", help="Comma-separated headers (e.g., 'X-API-Key:foo')")
    auth.add_argument("--proxy", metavar="PROXY", help="HTTP/S proxy URL")
    auth.add_argument("--verify-ssl", action="store_true", help="Enable SSL verification")
    auth.add_argument("--timeout", type=int, default=12, help="Request timeout in seconds")

    scan = p.add_argument_group("Scan Orchestration")
    scan.add_argument("--threads", type=int, default=8, help="Max concurrent threads")
    scan.add_argument("--rps", type=float, default=4.0, help="Requests per second limit")
    scan.add_argument("--budget", type=int, default=800, help="Global request budget")
    scan.add_argument("--depth", type=int, default=4, help="Crawl depth")
    scan.add_argument("--server", choices=["auto", "ad", "openldap", "389ds", "generic"], default="auto", help="Force LDAP server type")
    scan.add_argument("--force-scan", action="store_true", help="Skip tier-0 qualification and scan all params")

    oob = p.add_argument_group("OOB Detection")
    oob.add_argument("--collab", metavar="HOST", help="Collaborator host for OOB callbacks")
    oob.add_argument("--oob-port", type=int, default=53, help="Local port for OOB listener")

    out = p.add_argument_group("Output")
    out.add_argument("--output-dir", default=".", help="Directory to save findings")
    out.add_argument("--findings", default="dnwatch_findings.json", help="JSON output filename")
    out.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    out.add_argument("-q", "--quiet", action="store_true", help="Disable banner and info logs")

    return p.parse_args()

def main():
    args = _parse_args()
    if not args.quiet: print(f"\x1b[31m{BANNER}\x1b[0m")
    
    cfg = ScanConfig(
        target=args.target.rstrip("/"),
        auth_url=args.auth_url,
        auth_data=_parse_auth_data(args.auth_data),
        cookies=_parse_cookies(args.cookies),
        extra_headers=_parse_headers(args.headers),
        proxy=args.proxy,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        rps=args.rps,
        threads=args.threads,
        depth=args.depth,
        request_budget=args.budget,
        server_type=args.server,
        collab=args.collab,
        oob_port=args.oob_port,
        force_scan=args.force_scan,
        output_dir=args.output_dir,
        findings_file=args.findings,
        verbose=args.verbose,
        quiet=args.quiet
    )

    try:
        orchestrator = ScanOrchestrator(cfg)
        out_path = orchestrator.run()
        if not args.quiet: info(f"Scan complete. Findings saved to: {out_path}")
        return 0
    except KeyboardInterrupt:
        warn("\nScan interrupted by user")
        return 130
    except Exception as exc:
        err(f"Fatal execution error: {exc}")
        if args.verbose: traceback.print_exc()
        return 2

if __name__ == "__main__":
    sys.exit(main())
