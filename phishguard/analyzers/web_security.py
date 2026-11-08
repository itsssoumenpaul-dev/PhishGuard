"""Passive web-application security posture. Weights are *deductions* from a hygiene score,
kept separate from the phishing risk score (a misconfigured bank is not a phishing site)."""
from __future__ import annotations
import re
import time
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .. import data
from ..config import Config
from ..models import Signal
from ..netsafe import FetchResult, safe_get

# path -> (regex the body must match, title)  — only used when the owner has authorised a deep scan
EXPOSURE_PROBES = [
    ("/.git/HEAD", r"^ref:\s*refs/", "Exposed .git repository"),
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=.+", "Exposed .env file with secrets"),
    ("/phpinfo.php", r"PHP Version|phpinfo\(\)", "phpinfo() page exposed"),
    ("/server-status", r"Apache Server Status|Server Version:", "Apache server-status exposed"),
    ("/.DS_Store", r"^\x00\x00\x00\x01Bud1", "macOS .DS_Store exposed"),
    ("/wp-config.php.bak", r"DB_PASSWORD|DB_NAME", "WordPress config backup exposed"),
    ("/backup.sql", r"CREATE TABLE|INSERT INTO", "Database dump exposed"),
]


def _hdr(h: dict, k: str) -> str | None:
    return h.get(k.lower())


def grade(deduction: int) -> str:
    return "A" if deduction <= 5 else "B" if deduction <= 15 else "C" if deduction <= 30 else "D" if deduction <= 50 else "F"


def analyze_web_security(fr: FetchResult, https_redirect: bool | None = None) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    add = lambda *a, **k: sigs.append(Signal(*a, **k))
    info: dict = {"headers": {}, "cookies": [], "software": []}
    if not fr.ok:
        return sigs, {"available": False, **info}
    h = fr.headers
    is_https = fr.final_url.startswith("https://")

    # --- transport
    if not is_https:
        add("web.no_https", "web", "high", 25, "Site is served over HTTP only")
    else:
        hsts = _hdr(h, "strict-transport-security")
        info["headers"]["Strict-Transport-Security"] = hsts
        if not hsts:
            add("web.no_hsts", "web", "medium", 10, "Missing HSTS header", "Browsers can be downgraded to HTTP on first visit.")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15_552_000:
                add("web.hsts_short", "web", "low", 4, "HSTS max-age shorter than 6 months")
        if https_redirect is False:
            add("web.no_http_redirect", "web", "medium", 8, "http:// does not redirect to https://")
    if fr.tls_verified is False:
        add("web.tls_unverified", "web", "high", 20, "Browser-trusted TLS validation failed")

    # --- headers
    csp = _hdr(h, "content-security-policy")
    info["headers"]["Content-Security-Policy"] = csp
    if not csp:
        add("web.no_csp", "web", "medium", 10, "Missing Content-Security-Policy")
    else:
        if re.search(r"'unsafe-inline'|'unsafe-eval'", csp) and "script-src" in csp:
            add("web.csp_unsafe", "web", "low", 5, "CSP allows 'unsafe-inline' / 'unsafe-eval' scripts")
        if re.search(r"(?:script|default)-src[^;]*\s\*(?:\s|;|$)", csp):
            add("web.csp_wildcard", "web", "low", 5, "CSP allows scripts from any origin (*)")
    xfo = _hdr(h, "x-frame-options")
    info["headers"]["X-Frame-Options"] = xfo
    if not xfo and not (csp and "frame-ancestors" in csp):
        add("web.no_clickjack", "web", "medium", 8, "No clickjacking protection (X-Frame-Options / frame-ancestors)")
    xcto = _hdr(h, "x-content-type-options")
    info["headers"]["X-Content-Type-Options"] = xcto
    if (xcto or "").lower() != "nosniff":
        add("web.no_nosniff", "web", "low", 4, "Missing X-Content-Type-Options: nosniff")
    rp = _hdr(h, "referrer-policy")
    info["headers"]["Referrer-Policy"] = rp
    if not rp:
        add("web.no_referrer_policy", "web", "low", 3, "Missing Referrer-Policy")
    info["headers"]["Permissions-Policy"] = _hdr(h, "permissions-policy")
    acao, acac = _hdr(h, "access-control-allow-origin"), _hdr(h, "access-control-allow-credentials")
    if acao == "*" and (acac or "").lower() == "true":
        add("web.cors_wildcard_creds", "web", "high", 20, "CORS allows any origin together with credentials")
    elif acao == "null":
        add("web.cors_null", "web", "medium", 10, "CORS trusts the 'null' origin")

    # --- disclosure / outdated software
    for hn in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = _hdr(h, hn)
        if not v:
            continue
        info["software"].append(f"{hn}: {v}")
        if re.search(r"\d+\.\d+", v):
            add("web.version_disclosure", "web", "low", 3, f"Software version disclosed in {hn} header", v[:80])
        for name, pat, is_old, why in data.EOL_RULES:
            m = re.search(pat, v, re.I)
            if m and is_old(int(m.group(1)), int(m.group(2))):
                add(f"web.outdated.{name}", "web", "high", 15, f"Outdated {name} ({m.group(0)})", why)
    # --- cookies
    for raw in fr.set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        flags = {"secure": "secure" in low, "httponly": "httponly" in low, "samesite": "samesite" in low}
        info["cookies"].append({"name": name, **flags})
        sess_like = re.search(r"sess|auth|token|sid|login|jwt", name, re.I)
        if is_https and not flags["secure"]:
            add("web.cookie_secure", "web", "medium" if sess_like else "low", 8 if sess_like else 3, f"Cookie “{name}” lacks Secure flag")
        if not flags["httponly"] and sess_like:
            add("web.cookie_httponly", "web", "medium", 8, f"Session-like cookie “{name}” lacks HttpOnly")
        if not flags["samesite"] and sess_like:
            add("web.cookie_samesite", "web", "low", 4, f"Session-like cookie “{name}” lacks SameSite")

    # --- body checks
    if fr.body and not fr.non_html:
        low = fr.body[:400_000]
        if re.search(r"<title>\s*Index of /|<h1>Index of /", low, re.I):
            add("web.dir_listing", "web", "high", 15, "Directory listing is enabled")
        if re.search(r"Traceback \(most recent call last\)|Fatal error:.*on line \d+|Warning:.*mysqli?_|Stack trace:\s*#0|at [\w.$]+\([\w.]+\.java:\d+\)", low):
            add("web.error_leak", "web", "medium", 12, "Verbose error / stack trace visible to visitors")
        soup = BeautifulSoup(fr.body, "lxml")
        if is_https:
            mixed = [t.get("src") or t.get("href") for t in soup.find_all(["script", "link", "iframe"]) if
                     (t.get("src") or t.get("href") or "").startswith("http://")]
            mixed_img = [t.get("src") for t in soup.find_all("img") if (t.get("src") or "").startswith("http://")]
            if mixed:
                add("web.mixed_active", "web", "high", 12, "Active mixed content (scripts/frames over HTTP)", mixed[0][:100])
            elif mixed_img:
                add("web.mixed_passive", "web", "low", 3, "Passive mixed content (images over HTTP)")
        host = (urlsplit(fr.final_url).hostname or "")
        no_sri = [s.get("src") for s in soup.find_all("script", src=True)
                  if re.match(r"^(?:https?:)?//", s["src"]) and (urlsplit(s["src"] if not s["src"].startswith("//") else "https:" + s["src"]).hostname or host) != host
                  and not s.get("integrity")]
        if no_sri:
            add("web.no_sri", "web", "low", 4, f"{len(no_sri)} third-party script(s) loaded without Subresource Integrity", no_sri[0][:100])
        for s in soup.find_all("script", src=True):
            m = re.search(r"jquery[-.]?(\d+)\.(\d+)\.(\d+)", s["src"], re.I)
            if m and tuple(map(int, m.groups())) < (3, 5, 0):
                add("web.old_jquery", "web", "medium", 8, f"Outdated jQuery {'.'.join(m.groups())} (known XSS issues before 3.5.0)")
                break
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and re.search(r"\d+\.\d+", gen.get("content", "")):
            info["software"].append(f"generator: {gen['content'][:60]}")
            m = re.match(r"WordPress (\d+)\.(\d+)", gen["content"])
            if m and int(m.group(1)) < 6:
                add("web.outdated.wordpress", "web", "high", 15, f"Outdated {gen['content'][:40]}")
    total = sum(s.weight for s in sigs if s.weight > 0)
    info.update({"available": True, "deduction": total, "grade": grade(total)})
    return sigs, info


def check_https_redirect(host: str, cfg: Config) -> bool | None:
    r = safe_get(f"http://{host}/", cfg, max_redirects=0)
    if not r.ok:
        return None
    loc = r.headers.get("location", "")
    return 300 <= r.status < 400 and loc.lower().startswith("https://")


def probe_exposures(base_url: str, cfg: Config, delay: float = 0.4) -> list[Signal]:
    """Only run with the site owner's authorisation (the API requires an explicit attestation)."""
    sigs = []
    p = urlsplit(base_url)
    root = f"{p.scheme}://{p.netloc}"
    for path, pat, title in EXPOSURE_PROBES:
        r = safe_get(root + path, cfg, max_redirects=0)
        if r.ok and r.status == 200 and re.search(pat, r.body[:4000], re.M):
            sigs.append(Signal("web.exposed." + path.strip("/.").replace("/", "_"), "web", "critical", 35, title, f"{root}{path} returned sensitive content."))
        time.sleep(delay)
    return sigs
