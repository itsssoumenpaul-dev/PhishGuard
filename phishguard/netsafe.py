"""SSRF-safe, static-only page fetching.

The platform fetches attacker-controlled URLs, so every hop is resolved and
rejected if it points at a non-public address. Pages are never rendered or
executed; bodies are size-capped and only text-like content is read.

Known limitation: DNS is resolved by us and again by the HTTP client, so a
rebinding attacker has a small window. Run the service with an egress firewall
or in a network namespace that cannot reach internal ranges (see README).
"""
from __future__ import annotations
import ipaddress
import socket
import time
import warnings
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urljoin

import requests

from .config import Config

ALLOWED_PORTS = {80, 443, 8080, 8443}
UA = "PhishGuardBot/1.0 (static security analysis; no JS execution)"


class UnsafeTarget(Exception):
    pass


def is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int, allow_private: bool = False) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeTarget(f"DNS resolution failed: {e}") from e
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise UnsafeTarget("no addresses")
    if not allow_private:
        bad = [ip for ip in ips if not is_public_ip(ip)]
        if bad:
            raise UnsafeTarget(f"refusing non-public address {bad[0]}")
    return ips


def check_target(url: str, cfg: Config) -> tuple[str, int]:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeTarget("only http(s) URLs are allowed")
    port = p.port or (443 if p.scheme == "https" else 80)
    if port not in ALLOWED_PORTS and not cfg.allow_private:
        raise UnsafeTarget(f"port {port} not allowed")
    if cfg.proxy_does_dns and not cfg.allow_private:
        # An egress proxy resolves and connects; we can only refuse hosts that are *literally* internal.
        h = p.hostname.lower()
        if h == "localhost" or h.endswith((".localhost", ".local", ".internal", ".lan")):
            raise UnsafeTarget("refusing internal hostname")
        try:
            lit = socket.inet_ntoa(socket.inet_aton(h))      # catches decimal / hex / octal IPv4 spellings
        except OSError:
            lit = h.strip("[]") if ":" in h else None
        if lit and not is_public_ip(lit):
            raise UnsafeTarget(f"refusing non-public address {lit}")
        return p.hostname, port
    resolve_public(p.hostname, port, cfg.allow_private)
    return p.hostname, port


@dataclass
class FetchResult:
    ok: bool = False
    url: str = ""
    final_url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body: str = ""
    content_type: str = ""
    chain: list = field(default_factory=list)   # [{"url","status"}]
    tls_verified: bool | None = None
    non_html: bool = False
    truncated: bool = False
    error: str | None = None
    elapsed: float = 0.0


def safe_get(url: str, cfg: Config, max_redirects: int | None = None) -> FetchResult:
    res = FetchResult(url=url, final_url=url)
    max_redirects = cfg.max_redirects if max_redirects is None else max_redirects
    sess = requests.Session()
    sess.trust_env = cfg.trust_env
    sess.headers["User-Agent"] = UA
    t0 = time.time()
    cur = url
    verify = True
    try:
        for _hop in range(max_redirects + 1):
            check_target(cur, cfg)
            try:
                r = sess.get(cur, allow_redirects=False, stream=True,
                             timeout=cfg.fetch_timeout, verify=verify)
            except requests.exceptions.SSLError:
                if not verify:
                    raise
                verify = False  # still analyse a page with a bad certificate
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    r = sess.get(cur, allow_redirects=False, stream=True,
                                 timeout=cfg.fetch_timeout, verify=False)
            if cur.startswith("https"):
                res.tls_verified = verify if res.tls_verified is None else (res.tls_verified and verify)
            res.chain.append({"url": cur, "status": r.status_code})
            loc = r.headers.get("Location")
            if r.is_redirect and loc and _hop < max_redirects:
                cur = urljoin(cur, loc)
                r.close()
                continue
            res.final_url, res.status = cur, r.status_code
            res.headers = {k.lower(): v for k, v in r.headers.items()}
            try:
                res.set_cookies = list(r.raw.headers.getlist("Set-Cookie"))
            except Exception:
                res.set_cookies = []
            ct = res.headers.get("content-type", "").lower()
            res.content_type = ct
            if any(t in ct for t in ("html", "xml", "text", "json")) or not ct:
                buf, size = [], 0
                for chunk in r.iter_content(8192):
                    size += len(chunk)
                    buf.append(chunk)
                    if size >= cfg.max_bytes:
                        res.truncated = True
                        break
                raw = b"".join(buf)[: cfg.max_bytes]
                res.body = raw.decode(r.encoding or "utf-8", errors="replace")
            else:
                res.non_html = True
            r.close()
            res.ok = True
            break
    except UnsafeTarget as e:
        res.error = f"blocked: {e}"
    except requests.exceptions.RequestException as e:
        res.error = f"{type(e).__name__}: {str(e)[:200]}"
    res.elapsed = round(time.time() - t0, 2)
    return res
