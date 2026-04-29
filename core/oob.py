import socket
import threading
import hashlib
from typing import List, Dict, Optional, Tuple
from .utils import now_iso, success, info, warn
try: import dnslib; _DNSLIB_OK = True
except ImportError: _DNSLIB_OK = False

class OOBListener:
    def __init__(self, domain: str, scan_id: str, port: int = 53):
        self._domain = domain.lower().rstrip("."); self._scan_id = scan_id; self._port = port; self._received = []; self._lock = threading.Lock(); self._running = False; self._sock = None; self._payload_map = {}
    def start(self) -> int:
        for p in (self._port, 5353, 15353):
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self._sock.bind(("0.0.0.0", p)); self._sock.settimeout(1.0); self._running = True; threading.Thread(target=self._serve, daemon=True).start(); info(f"  OOB listener: port {p} (domain={self._domain})"); return p
            except Exception: pass
        warn("  OOB listener: bind failed"); return 0
    def stop(self): self._running = False; (self._sock.close() if self._sock else None)
    def register_payload(self, param: str, url: str) -> str:
        phash = hashlib.md5(param.encode()).hexdigest()[:6]; sub = f"{self._scan_id[:6]}.{phash}"
        with self._lock: self._payload_map[sub] = (param, url)
        return f"{sub}.{self._domain}"
    def _parse_qname_raw(self, data: bytes) -> str:
        try:
            off = 12; labels = []
            while off < len(data):
                ln = data[off]
                if not ln: break
                labels.append(data[off+1:off+1+ln].decode("ascii", errors="replace")); off += 1 + ln
            return ".".join(labels).lower()
        except Exception: return ""
    def _serve(self):
        while self._running and self._sock:
            try:
                data, addr = self._sock.recvfrom(512)
                if len(data) < 13: continue
                qname = str(dnslib.DNSRecord.parse(data).q.qname).lower().rstrip(".") if _DNSLIB_OK else self._parse_qname_raw(data)
                if self._domain in qname:
                    sub = qname.replace(f".{self._domain}", ""); info_ = self._payload_map.get(sub)
                    rec = {"src_ip": addr[0], "qname": qname, "timestamp": now_iso()}
                    if info_: rec["param"], rec["endpoint"] = info_; success(f"  OOB callback: {addr[0]} → {qname} [CORRELATED: {info_[1]}:{info_[0]}]")
                    else: success(f"  OOB callback: {addr[0]} → {qname}")
                    with self._lock: self._received.append(rec)
                if _DNSLIB_OK and self._sock:
                    reply = dnslib.DNSRecord.parse(data).reply(); reply.header.rcode = dnslib.RCODE.NXDOMAIN; self._sock.sendto(reply.pack(), addr)
            except Exception: pass
    def triggered(self) -> bool:
        with self._lock: return len(self._received) > 0
    @property
    def callbacks(self) -> List[Dict]:
        with self._lock: return list(self._received)
