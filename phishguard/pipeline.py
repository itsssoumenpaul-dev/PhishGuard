"""Orchestrates the analyzers into one report."""
from __future__ import annotations
import time
from urllib.parse import urlsplit

from .analyzers import cert_analyzer, content_analyzer, url_analyzer, web_security
from .config import Config
from .intel import IntelStore
from .models import Signal
from .netsafe import FetchResult, safe_get
from . import scoring


def analyze(url: str, cfg: Config, store: IntelStore, *, fetch: bool = True, deep: bool = False,
            authorized: bool = False, ct_fetcher=None, fetcher=None, cert_fetcher=None) -> dict:
    t0 = time.time()
    url = url_analyzer.normalize_url(url)
    errors: dict[str, str] = {}
    notes_extra: list[str] = []
    signals: list[Signal] = []

    ua = url_analyzer.analyze_url(url)
    signals += ua["signals"]
    uf = ua["features"]
    host = uf["host"]

    # --- threat intel (cheap, local)
    intel = store.lookup(url)
    com = intel["community"]
    if intel["status"] == "confirmed_malicious":
        src = ", ".join(intel["feeds"]) or f"{com['malicious_reporters']} community reporters"
        signals.append(Signal("intel.confirmed", "intel", "critical", 80, "Listed as malicious in threat intelligence", f"Source: {src}"))
    elif intel["status"] == "reported":
        signals.append(Signal("intel.reported", "intel", "high", min(40, int(15 + 10 * com["malicious_weight"])),
                              "Reported by the community", f"{com['malicious_reporters']} reporter(s), confidence {com['confidence']}."))
    elif intel["status"] == "community_safe":
        signals.append(Signal("intel.community_safe", "intel", "info", -10, "Community marked this site as safe"))

    # --- fetch + content + web-security
    fr = FetchResult(url=url, final_url=url, error="fetch disabled")
    content_info, web_info = {}, {"available": False}
    if fetch:
        fr = (fetcher or safe_get)(url, cfg)
        if fr.ok:
            try:
                s, content_info = content_analyzer.analyze_content(fr, uf)
                signals += s
            except Exception as e:  # never let one analyzer sink the report
                errors["content"] = repr(e)
            if fr.status >= 400:
                notes_extra.append(f"The server answered HTTP {fr.status}; security headers were not graded because error pages are not representative.")
            try:
                if fr.status >= 400:
                    raise StopIteration
                redirect_ok = None
                if fr.final_url.startswith("https://") and not uf["is_ip"]:
                    redirect_ok = web_security.check_https_redirect(urlsplit(fr.final_url).hostname, cfg) if fetcher is None else None
                s, web_info = web_security.analyze_web_security(fr, redirect_ok)
                signals += s
                if deep and authorized and fetcher is None:
                    signals += web_security.probe_exposures(fr.final_url, cfg)
                    web_info["deep_scan"] = True
            except StopIteration:
                pass
            except Exception as e:
                errors["web"] = repr(e)
        else:
            errors["fetch"] = fr.error or "unknown"
            if not (fr.error or "").startswith("blocked"):
                signals.append(Signal("content.unreachable", "content", "info", 0, "Site could not be fetched", fr.error or ""))

    # --- certificate
    cert_info = {"available": False}
    final_host = urlsplit(fr.final_url).hostname or host if fr.ok else host
    if (url.startswith("https://") or (fr.ok and fr.final_url.startswith("https://"))) and not uf["is_ip"]:
        try:
            cb = (cert_fetcher or cert_analyzer.fetch_certificate)(final_host, cfg)
            s, cert_info = cert_analyzer.analyze_certificate(cb, cfg, store, ct_fetcher=ct_fetcher)
            signals += s
        except Exception as e:
            errors["cert"] = repr(e)

    web_signals = [s for s in signals if scoring.is_hygiene(s)]
    result = scoring.combine(signals, intel)
    ded = sum(s.weight for s in web_signals if s.weight > 0)
    posture = {"grade": web_security.grade(ded), "deduction": ded, "scope": "headers, cookies, content, TLS configuration"} if web_info.get("available") else None

    notes = list(result["notes"]) + notes_extra
    confidence = result["confidence"]
    if fetch and not fr.ok:
        notes.append("The page could not be fetched, so content, headers and certificate were NOT analysed; this score reflects the URL and threat intelligence only.")
        confidence = "low"
    elif fetch and not cert_info.get("available") and url.startswith("https://"):
        notes.append("The TLS certificate could not be retrieved for analysis.")

    rep = {
        "url": url, "host": host, "registered_domain": uf["registered_domain"], "display_host": uf["display_host"],
        "final_url": fr.final_url if fr.ok else None,
        "risk_score": result["score"], "verdict": result["verdict"], "label": result["label"], "confidence": confidence,
        "notes": notes,
        "signals": [{**s.to_dict(), "group": "posture" if scoring.is_hygiene(s) else "risk"} for s in sorted(signals, key=lambda s: -s.weight)],
        "security_posture": posture,
        "certificate": cert_info, "content": content_info, "web": {k: v for k, v in web_info.items()},
        "intel": intel, "http": {"status": fr.status, "redirects": len(fr.chain) - 1 if fr.chain else 0, "tls_verified": fr.tls_verified,
                                 "error": fr.error if not fr.ok else None},
        "recommendations": scoring.recommendations(result["verdict"], bool(content_info.get("password_fields"))),
        "errors": errors, "elapsed_s": round(time.time() - t0, 2),
        "disclaimer": "Automated, static analysis. Treat as decision support, not proof.",
    }
    store.record_scan(url, result["score"], result["verdict"])
    return rep
