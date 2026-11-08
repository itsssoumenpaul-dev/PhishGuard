"""Combine signals into an explainable phishing-risk score (0-100)."""
from __future__ import annotations
from .models import Signal

RISK_CATEGORIES = ("url", "content", "cert", "intel")
# crypto-hygiene findings describe the site's configuration, not whether it is a phishing page
HYGIENE_IDS = {"cert.old_tls", "cert.weak_signature", "cert.long_lived", "cert.ec_small", "cert.rsa_exponent",
               "cert.rsa_small", "cert.no_sct", "cert.mass_issuance"}


def is_hygiene(s: Signal) -> bool:
    return s.category == "web" or (s.id in HYGIENE_IDS and s.severity != "critical")


def _verdict(score: int) -> tuple[str, str]:
    if score >= 75:
        return "malicious", "Likely malicious"
    if score >= 50:
        return "high_risk", "High risk"
    if score >= 25:
        return "suspicious", "Suspicious"
    return "low_risk", "Low risk"


def combine(signals: list[Signal], intel: dict | None = None) -> dict:
    risk_sigs = [s for s in signals if s.category in RISK_CATEGORIES and not is_hygiene(s)]
    pos = sorted((min(s.weight, 60) for s in risk_sigs if s.weight > 0), reverse=True)
    # noisy-OR: independent weak signals add up but saturate instead of exceeding 100
    p_clean = 1.0
    for w in pos:
        p_clean *= 1 - w / 100
    score = (1 - p_clean) * 100
    score += sum(s.weight for s in risk_sigs if s.weight < 0)
    has_critical = any(s.severity == "critical" for s in risk_sigs)
    if has_critical:
        score = max(score, 85)
    notes = []
    intel = intel or {}
    if intel.get("status") == "confirmed_malicious":
        score = 100
        notes.append("Confirmed malicious by threat-intelligence feeds or community consensus.")
    elif intel.get("allowlisted") and not has_critical:
        score = min(score, 8)
        notes.append("Domain is on the allow-list.")
    score = int(round(max(0, min(100, score))))
    vid, label = _verdict(score)
    return {"score": score, "verdict": vid, "label": label, "notes": notes,
            "confidence": "high" if (has_critical or score >= 75 or score <= 8 or len(pos) >= 4) else "medium" if score >= 25 else "medium"}


def recommendations(verdict: str, has_form: bool) -> list[str]:
    if verdict in ("malicious", "high_risk"):
        r = ["Do not enter passwords, card details, OTPs or personal data on this site.",
             "If you already did, change that password immediately and enable two-factor authentication.",
             "Contact your bank or the real organisation through its official app or website if money was involved.",
             "Report the site (in this platform and to the impersonated brand / your national CERT, e.g. CERT-In or cybercrime.gov.in in India)."]
    elif verdict == "suspicious":
        r = ["Do not log in from a link you were sent; open the organisation’s site by typing its address yourself.",
             "Check the sender and whether anyone is pressuring you to act urgently or pay a fee.",
             "If unsure, submit it as a community report so others benefit."]
    else:
        r = ["No strong phishing indicators were found, but no scan is a guarantee; stay careful with links received unexpectedly."]
    return r
