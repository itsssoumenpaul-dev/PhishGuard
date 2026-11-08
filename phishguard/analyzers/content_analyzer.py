"""Static page-content analysis (no JavaScript is executed)."""
from __future__ import annotations
import re
from urllib.parse import urlsplit, urljoin

from bs4 import BeautifulSoup

from .. import data
from ..models import Signal
from ..netsafe import FetchResult
from .url_analyzer import registered_domain, is_numeric_host

SENSITIVE_NAME = re.compile(r"otp|cvv|cvc|card|pan\b|aadhaar|aadhar|ssn|pin\b|upi|ifsc|account.?n|iban|passcode|seed|mnemonic|private.?key", re.I)


def _rd(u: str) -> str:
    h = (urlsplit(u).hostname or "").lower()
    return h if is_numeric_host(h) else registered_domain(h)


def analyze_content(fr: FetchResult, uf: dict) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    add = lambda *a, **k: sigs.append(Signal(*a, **k))
    info: dict = {"title": "", "forms": 0, "password_fields": 0, "external_resources": 0}
    page_rd = _rd(fr.final_url)

    # --- redirects
    if len(fr.chain) > 1:
        rds = {_rd(h["url"]) for h in fr.chain}
        info["redirects"] = len(fr.chain) - 1
        if len(fr.chain) - 1 >= 3:
            add("content.redirect_chain", "content", "low", 8, f"Long redirect chain ({len(fr.chain) - 1} hops)")
        if len(rds) > 1:
            add("content.cross_domain_redirect", "content", "low", 8,
                "Redirects through different domains", " → ".join(sorted(rds))[:200])

    if fr.non_html:
        ct = fr.content_type
        if any(x in ct for x in ("octet-stream", "msdownload", "android.package", "zip", "x-msi", "x-dosexec", "java-archive")):
            add("content.download", "content", "high", 30, "Link serves a downloadable executable/archive",
                f"Content-Type: {ct}. Not downloaded or analysed further.")
        return sigs, info
    if not fr.body:
        return sigs, info

    soup = BeautifulSoup(fr.body, "lxml")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    info["title"] = title[:200]
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:200_000]
    low = text.lower()

    # --- forms
    forms = soup.find_all("form")
    info["forms"] = len(forms)
    pw = soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})
    info["password_fields"] = len(pw)
    sensitive_inputs = [i.get("name") or i.get("id") or "" for i in soup.find_all("input")
                        if SENSITIVE_NAME.search((i.get("name") or "") + " " + (i.get("id") or "") + " " + (i.get("placeholder") or ""))]
    official = bool(uf.get("official_brand")) and not uf.get("user_content_host")
    for f in forms:
        action = (f.get("action") or "").strip()
        if action.lower().startswith("mailto:"):
            add("content.form_mailto", "content", "high", 25, "Form submits to an e-mail address (mailto:)")
            continue
        if action in ("", "#") or action.lower().startswith("javascript:"):
            continue
        tgt = urljoin(fr.final_url, action)
        if _rd(tgt) != page_rd and (f.find("input", attrs={"type": re.compile("password", re.I)}) or SENSITIVE_NAME.search(str(f)[:4000])):
            add("content.form_cross_domain", "content", "high", 28, "Sensitive form posts data to a different domain",
                f"Form on {page_rd} submits to {urlsplit(tgt).hostname}.")
            break
        if is_numeric_host(urlsplit(tgt).hostname or ""):
            add("content.form_ip", "content", "high", 28, "Form submits to a raw IP address")
            break
        if fr.final_url.startswith("https") and tgt.startswith("http://"):
            add("content.form_insecure", "content", "medium", 15, "HTTPS page submits a form over plain HTTP")
            break

    if pw and not official:
        add("content.password_form", "content", "low", 8, "Page asks for a password",
            "Not unusual on its own; it matters most together with impersonation signals.")
    if sensitive_inputs and not official:
        add("content.sensitive_fields", "content", "medium", 14, "Requests card / OTP / ID-style data",
            ", ".join(sorted({s for s in sensitive_inputs if s})[:6]))

    # --- brand claims in the page vs. where it is hosted
    claimed = []
    if not official:
        probe = (title + " " + " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"]))).lower()
        for token, doms in data.BRANDS.items():
            if len(token) < 4 or page_rd in doms:
                continue
            if re.search(rf"\b{re.escape(token)}\b", probe) or low.count(token) >= 4 and len(token) >= 5:
                claimed.append(token)
        claimed = [c for c in claimed if c in ("paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "whatsapp",
                                               "netflix", "linkedin", "dhl", "fedex", "binance", "coinbase", "metamask", "paytm",
                                               "phonepe", "sbi", "hdfc", "icici", "axisbank", "kotak", "pnb", "irctc", "uidai",
                                               "incometax", "epfo", "digilocker", "naukri", "flipkart", "jio", "airtel", "chase",
                                               "wellsfargo", "bankofamerica", "citibank", "hsbc", "dropbox", "adobe", "npci", "aadhaar")][:3]
        if claimed:
            strong = bool(pw or sensitive_inputs)
            add("content.brand_mismatch", "content", "high" if strong else "low", 30 if strong else 8,
                f"Page presents itself as {', '.join(claimed)} but is hosted on {page_rd}",
                "A login/payment form on a page that names a brand it is not hosted by is the classic phishing pattern."
                if strong else "Could be a news/blog page; no credential form was found.")
    info["claimed_brands"] = claimed

    # --- brand assets hot-linked from the real brand while hosted elsewhere
    ext = 0
    hot = set()
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href")):
        for el in soup.find_all(tag):
            u = el.get(attr)
            if not u or u.startswith(("data:", "#")):
                continue
            absu = urljoin(fr.final_url, u)
            r = _rd(absu)
            if r and r != page_rd:
                ext += 1
                for token, doms in data.BRANDS.items():
                    if r in doms and not official and len(token) >= 4:
                        hot.add(r)
    info["external_resources"] = ext
    if hot and (pw or sensitive_inputs):
        add("content.hotlinked_brand_assets", "content", "medium", 18, "Loads logos/styles directly from a brand’s real site",
            ", ".join(sorted(hot)[:4]) + " — typical of cloned pages.")

    # --- text themes
    theme_hits: dict[str, int] = {}
    for theme, pats in data.TEXT_THEMES.items():
        n = sum(1 for p in pats if re.search(p, low))
        if n:
            theme_hits[theme] = n
    info["themes"] = theme_hits
    if not official:
        labels = {"urgency": "Urgent / threatening language", "credentials": "Asks for sensitive credentials in text",
                  "payment_scam": "Payment / refund / reward lure language", "job_scam": "Job-scam style language"}
        for theme, n in theme_hits.items():
            w = {"urgency": 10, "credentials": 8, "payment_scam": 12, "job_scam": 12}[theme] + 3 * (n - 1)
            if n >= 2 or theme in ("payment_scam", "job_scam"):
                add(f"content.theme.{theme}", "content", "medium" if w >= 12 else "low", min(w, 20), labels[theme],
                    f"{n} matching phrase pattern(s).")

    # --- evasion / obfuscation
    scripts = "\n".join(s.get_text() for s in soup.find_all("script"))[:300_000]
    obf = len(re.findall(r"eval\s*\(|atob\s*\(|unescape\s*\(|fromCharCode|document\.write\s*\(\s*unescape", scripts))
    if obf >= 4:
        add("content.obfuscated_js", "content", "medium", 15, "Heavily obfuscated JavaScript", f"{obf} eval/atob/unescape-style calls.")
    if re.search(r"oncontextmenu\s*=\s*[\"']?\s*return\s+false|contextmenu[^;]{0,60}preventDefault", fr.body, re.I):
        add("content.no_rightclick", "content", "low", 6, "Right-click / inspect is disabled")
    for fr_el in soup.find_all("iframe"):
        st = (fr_el.get("style") or "").replace(" ", "").lower()
        if ("display:none" in st or "visibility:hidden" in st or fr_el.get("width") in ("0", "1") or fr_el.get("height") in ("0", "1")):
            add("content.hidden_iframe", "content", "high", 18, "Hidden iframe on page", (fr_el.get("src") or "")[:120])
            break
    meta = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta and "url=" in (meta.get("content") or "").lower():
        tgt = urljoin(fr.final_url, re.split(r"url=", meta["content"], flags=re.I)[-1].strip(" '\""))
        if _rd(tgt) != page_rd:
            add("content.meta_refresh", "content", "medium", 14, "Meta-refresh forwards to another domain", tgt[:120])
    if re.search(r"data:text/html;base64", fr.body, re.I):
        add("content.data_uri_html", "content", "medium", 12, "Embedded base64 HTML document")

    # near-empty page with a form and no navigation → kit landing page
    links = soup.find_all("a", href=True)
    real_links = [a for a in links if not a["href"].startswith(("#", "javascript:", "mailto:"))]
    if forms and (pw or sensitive_inputs) and len(real_links) <= 2 and not official:
        add("content.thin_login", "content", "low", 7, "Login-style page with almost no other links")
    return sigs, info
