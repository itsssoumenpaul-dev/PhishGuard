"""Lexical / structural URL analysis: impersonation, typosquatting, homoglyphs, obfuscation."""
from __future__ import annotations
import ipaddress
import math
import re
import unicodedata
from urllib.parse import urlsplit, parse_qsl

import idna as idna_lib

from .. import data
from ..models import Signal

MAX_URL = 2048


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_URL:
        raise ValueError("URL is empty or longer than 2048 characters")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw) and not re.match(r"^https?://", raw, re.I):
        if not re.match(r"^[^/]+:\d+", raw):  # allow host:port without scheme
            raise ValueError("only http and https URLs are supported")
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw.lstrip("/")
    p = urlsplit(raw)
    if not p.hostname:
        raise ValueError("URL has no host")
    return raw


def registered_domain(host: str) -> str:
    parts = host.strip(".").split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in data.MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split_host(host: str) -> tuple[str, str, str]:
    """-> (subdomain, sld, suffix)"""
    parts = host.split(".")
    if len(parts) == 1:
        return "", host, ""
    n = 2 if ".".join(parts[-2:]) in data.MULTI_SUFFIX else 1
    suffix = ".".join(parts[-n:])
    rest = parts[:-n]
    return ".".join(rest[:-1]), (rest[-1] if rest else ""), suffix


def is_numeric_host(host: str) -> bool:
    if re.fullmatch(r"\d+", host) or re.fullmatch(r"0x[0-9a-f]+", host, re.I):
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"[0-9.x]+", host, re.I) and host.count(".") >= 1 and not host.endswith("."))


def decode_host(host: str) -> str:
    """Punycode labels -> unicode, for display and confusable analysis."""
    out = []
    for lab in host.split("."):
        if lab.startswith("xn--"):
            try:
                lab = idna_lib.decode(lab)
            except Exception:
                try:
                    lab = lab.encode().decode("punycode")
                except Exception:
                    pass
        out.append(lab)
    return ".".join(out)


def skeleton_variants(s: str) -> set[str]:
    s = unicodedata.normalize("NFKC", s).lower()
    s = "".join(data.CONFUSABLES.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    outs = set()
    for one in ("l", "i"):
        v = s.translate(str.maketrans({"0": "o", "1": one, "3": "e", "5": "s", "4": "a", "$": "s"}))
        v = v.replace("rn", "m").replace("vv", "w").replace("cl", "d")
        outs.add(v)
    return outs


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def match_brand(host: str, path_query: str) -> dict:
    """Return the strongest brand relationship for this host."""
    rd = registered_domain(host)
    sub, sld, _suffix = split_host(host)
    sld_variants = skeleton_variants(sld)
    best = {"official": None, "hits": []}
    for token, officials in data.BRANDS.items():
        if rd in officials or any(host == o or host.endswith("." + o) for o in officials):
            if best["official"] is None:
                best["official"] = token
            continue
    if best["official"]:
        return best
    labels = re.split(r"[-_.]", sld)
    seen = set()
    for token in data.BRANDS:
        kind = None
        if sld == token:  # same name, different TLD (paypal.net)
            kind = "same_name_other_tld"
        elif len(token) >= 5 and token in sld_variants and sld != token:
            kind = "lookalike"       # homoglyph / leetspeak resolves exactly to the brand
        elif len(token) >= 6 and sld != token and levenshtein(sld, token, 2) <= (1 if len(token) <= 7 else 2):
            kind = "typosquat"
        elif token in labels or (len(token) >= 6 and (sld.startswith(token) or sld.endswith(token))):
            kind = "combosquat"
        elif re.search(rf"(?:^|[.\-_]){re.escape(token)}(?:$|[.\-_])", sub) or any(token in re.split(r"[.\-_]", v) for v in skeleton_variants(sub)):
            kind = "subdomain"       # paypal.com.evil.tk
        elif len(token) >= 5 and token in path_query.lower():
            kind = "path"
        if kind and (token, kind) not in seen:
            seen.add((token, kind))
            best["hits"].append({"brand": token, "kind": kind})
    return best


def analyze_url(url: str) -> dict:
    p = urlsplit(url)
    host = (p.hostname or "").lower().rstrip(".")
    sigs: list[Signal] = []
    add = lambda *a, **k: sigs.append(Signal(*a, **k))
    display_host = decode_host(host)
    numeric = is_numeric_host(host)
    rd = host if numeric else registered_domain(host)
    sub, sld, suffix = ("", host, "") if numeric else split_host(display_host)
    path_query = (p.path or "") + "?" + (p.query or "")
    feats = {"host": host, "display_host": display_host, "scheme": p.scheme, "registered_domain": rd,
             "sld": sld, "suffix": suffix, "is_ip": numeric, "official_brand": None, "brand_hits": [],
             "user_content_host": False, "free_hosting": False}

    if numeric:
        add("url.ip_host", "url", "high", 30, "Address is a raw IP / numeric host",
            "Legitimate services rarely ask users to log in at a bare IP address.")
    if p.username is not None or "@" in (p.netloc or ""):
        add("url.userinfo", "url", "high", 28, "URL contains user-info (@) before the host",
            "Text before @ is ignored by browsers and is used to disguise the real destination.")
    if p.scheme == "http":
        add("url.no_https", "url", "low", 8, "Connection is not encrypted (HTTP)",
            "Credentials entered here travel in clear text.")
    if p.port and p.port not in (80, 443):
        add("url.odd_port", "url", "medium", 10, f"Non-standard port {p.port}")

    # --- IDN / homoglyphs
    if host.startswith("xn--") or ".xn--" in host:
        scripts = {unicodedata.name(c, "?").split()[0] for c in display_host if c.isalpha()}
        mixed = len(scripts - {"LATIN"}) > 0 and "LATIN" in scripts
        add("url.punycode", "url", "high" if mixed else "medium", 25 if mixed else 12,
            "Internationalised (punycode) domain" + (" mixing scripts" if mixed else ""),
            f"Displays as “{display_host}”. Attackers use look-alike Unicode letters to imitate brands.")
    elif any(ord(c) > 127 for c in host):
        add("url.non_ascii", "url", "medium", 15, "Non-ASCII characters in host")

    # --- brand impersonation
    bm = match_brand(display_host if not numeric else host, path_query) if not numeric else {"official": None, "hits": []}
    feats["official_brand"] = bm["official"]
    feats["brand_hits"] = bm["hits"]
    kind_meta = {
        "lookalike": ("critical", 48, "Look-alike spelling of “{b}” (homoglyph/leetspeak)"),
        "typosquat": ("high", 38, "Domain is a near-miss spelling of “{b}” (typosquatting)"),
        "subdomain": ("high", 38, "Brand name “{b}” used as a subdomain of an unrelated domain"),
        "combosquat": ("high", 32, "Brand name “{b}” embedded in an unrelated domain"),
        "same_name_other_tld": ("medium", 22, "Same name as “{b}” on a different domain extension"),
        "path": ("low", 10, "Brand name “{b}” appears in the URL path of an unrelated site"),
    }
    rank = ["lookalike", "typosquat", "subdomain", "combosquat", "same_name_other_tld", "path"]
    for hit in sorted(bm["hits"], key=lambda h: rank.index(h["kind"]))[:2]:
        sev, w, t = kind_meta[hit["kind"]]
        add(f"url.brand.{hit['kind']}", "url", sev, w, t.format(b=hit["brand"]),
            f"The real {hit['brand']} sites are: {', '.join(data.BRANDS[hit['brand']][:3])}.")

    # --- official domains
    host_is_ucp = any(host == h or host.endswith("." + h) for h in data.USER_CONTENT_HOSTS)
    feats["user_content_host"] = host_is_ucp
    feats["free_hosting"] = any(host == h or host.endswith("." + h) for h in data.FREE_HOSTING)
    if bm["official"] and not host_is_ucp:
        add("url.official", "url", "info", -30, f"Belongs to a known organisation ({bm['official']})",
            "Registered domain matches the official list.")
    elif bm["official"]:
        add("url.official_ugc", "url", "info", -5, "Official platform that also hosts user-generated content",
            "The domain is genuine, but the page itself may be created by anyone.")

    if feats["free_hosting"]:
        add("url.free_hosting", "url", "medium", 12, "Hosted on a free hosting / site-builder platform",
            "Phishing kits frequently live on free subdomains that cost nothing to create.")
    if rd in data.URL_SHORTENERS:
        add("url.shortener", "url", "medium", 12, "URL shortener hides the real destination")

    # --- structure
    if not numeric:
        if suffix.split(".")[-1] in data.SUSPICIOUS_TLDS:
            add("url.tld", "url", "low", 10, f"Domain extension “.{suffix.split('.')[-1]}” is heavily abused")
        depth = len([x for x in sub.split(".") if x]) if sub else 0
        if depth >= 3:
            add("url.subdomains", "url", "medium", 10 + 3 * (depth - 3), f"Unusually many subdomains ({depth})")
        if sld.count("-") >= 2:
            add("url.hyphens", "url", "low", 8, "Many hyphens in the domain name")
        if len(sld) >= 12 and "-" not in sld and entropy(sld) > 3.7 and not feats["official_brand"]:
            add("url.entropy", "url", "low", 8, "Domain name looks randomly generated")
        if sum(c.isdigit() for c in sld) >= 4 and len(sld) > 6:
            add("url.digits", "url", "low", 6, "Many digits in the domain name")
    if len(url) > 120:
        add("url.long", "url", "low", 6, f"Very long URL ({len(url)} chars)")
    if re.search(r"%[0-9a-f]{2}", url, re.I) and len(re.findall(r"%[0-9a-f]{2}", url, re.I)) >= 6:
        add("url.encoded", "url", "low", 6, "Heavily percent-encoded URL")
    if "//" in (p.path or "")[1:]:
        add("url.double_slash", "url", "low", 5, "Double slash inside path")

    kws = sorted({k for k in data.URL_KEYWORDS if k in (host + path_query).lower()})
    if kws and not feats["official_brand"]:
        w = min(4 * len(kws), 16)
        add("url.keywords", "url", "low", w, "Credential/payment keywords in URL", ", ".join(kws[:8]))

    for k, v in parse_qsl(p.query):
        if re.match(r"^(?:https?:)?//", v) or re.match(r"^https?%3a", v, re.I):
            add("url.open_redirect", "url", "medium", 14, f"Parameter “{k}” carries another URL (possible redirect)", v[:100])
            break

    feats["host_is_ip"] = numeric
    return {"signals": sigs, "features": feats}
