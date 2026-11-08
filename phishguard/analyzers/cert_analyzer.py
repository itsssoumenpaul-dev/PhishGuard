"""TLS certificate and trust-chain validation, weak-key detection and CT cross-checks.

Weak-key tests are inspired by public discussion of CA key-generation failures
(e.g. certificates whose RSA keys were not generated with sound randomness).
They are heuristics: a clean result does NOT prove a key is strong.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import math
import socket
import ssl
from dataclasses import dataclass, field
from math import gcd, isqrt

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..config import Config
from ..models import Signal
from ..netsafe import resolve_public, UnsafeTarget

# ---------------------------------------------------------------- weak-key maths


def _primes_below(n: int) -> list[int]:
    sieve = bytearray([1]) * n
    sieve[:2] = b"\x00\x00"
    for i in range(2, int(n ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(n) if sieve[i]]


SMALL_PRIMES = _primes_below(20000)


def rsa_modulus_weaknesses(n: int, e: int) -> list[tuple[str, str, int, str]]:
    """-> [(id, severity, weight, message)]"""
    out = []
    bits = n.bit_length()
    if bits < 2048:
        sev, w = ("critical", 40) if bits < 1024 else ("high", 28)
        out.append(("cert.rsa_small", sev, w, f"RSA key is only {bits} bits (minimum for public TLS is 2048)"))
    if n % 2 == 0:
        out.append(("cert.rsa_even", "critical", 60, "RSA modulus is even: key generation is broken"))
        return out
    for p in SMALL_PRIMES:
        if n % p == 0:
            out.append(("cert.rsa_small_factor", "critical", 60,
                        f"RSA modulus is divisible by the small prime {p}: the private key can be derived trivially"))
            return out
    # Fermat: finds factors when p and q are suspiciously close
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(60_000):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            out.append(("cert.rsa_close_primes", "critical", 60,
                        "RSA modulus factors by Fermat's method (p and q are nearly equal): the private key is recoverable"))
            break
        a += 1
    if e < 65537 or e % 2 == 0:
        out.append(("cert.rsa_exponent", "medium" if e % 2 else "high", 12 if e % 2 else 30,
                    f"Unusual public exponent e={e} (65537 expected)"))
    return out


# ---------------------------------------------------------------- fetching the cert

@dataclass
class CertBundle:
    host: str
    port: int = 443
    ok: bool = False
    error: str | None = None
    verify_error: str | None = None
    leaf: x509.Certificate | None = None
    chain: list = field(default_factory=list)   # DER-parsed certs sent by server (leaf first)
    tls_version: str | None = None
    cipher: str | None = None


def _chain_der(sock: ssl.SSLSocket) -> list[bytes]:
    try:
        raw = sock.get_unverified_chain()
    except Exception:
        raw = None
    out = []
    for c in raw or []:
        if isinstance(c, (bytes, bytearray)):
            out.append(bytes(c))
        else:
            try:
                out.append(c.public_bytes(ssl._ssl.ENCODING_DER))
            except Exception:
                pass
    if not out:
        d = sock.getpeercert(True)
        if d:
            out.append(d)
    return out


def fetch_certificate(host: str, cfg: Config, port: int = 443) -> CertBundle:
    cb = CertBundle(host=host, port=port)
    try:
        ip = resolve_public(host, port, cfg.allow_private)[0]
    except UnsafeTarget as e:
        cb.error = f"blocked: {e}"
        return cb

    def connect(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=cfg.fetch_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return _chain_der(ss), ss.version(), (ss.cipher() or [None])[0]

    try:
        try:
            ders, cb.tls_version, cb.cipher = connect(True)
        except ssl.SSLCertVerificationError as e:
            cb.verify_error = e.verify_message or str(e)
            ders, cb.tls_version, cb.cipher = connect(False)
        cb.chain = [x509.load_der_x509_certificate(d) for d in ders]
        cb.leaf = cb.chain[0] if cb.chain else None
        cb.ok = cb.leaf is not None
    except (OSError, ssl.SSLError, ValueError) as e:
        cb.error = f"{type(e).__name__}: {str(e)[:160]}"
    return cb


# ---------------------------------------------------------------- CT

def crtsh_fetch(domain: str, timeout: float = 10.0) -> list[dict] | None:
    """Query crt.sh for certificates issued for `domain`. None = lookup failed."""
    try:
        r = requests.get("https://crt.sh/", params={"q": domain, "output": "json"}, timeout=timeout,
                         headers={"User-Agent": "PhishGuard/1.0"})
        if r.status_code != 200:
            return None
        return r.json()
    except (requests.RequestException, ValueError):
        return None


def _norm_serial(s) -> str:
    return str(s).replace(":", "").lstrip("0").lower()


def _issuer_key(name: str) -> str:
    return " ".join((name or "").lower().split())


# ---------------------------------------------------------------- analysis

def spki_sha256(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _name(n: x509.Name, oid) -> str:
    a = n.get_attributes_for_oid(oid)
    return a[0].value if a else ""


def _san_match(host: str, sans: list[str]) -> bool:
    host = host.lower()
    for s in sans:
        s = s.lower()
        if s == host:
            return True
        if s.startswith("*.") and host.count(".") == s.count(".") and host.endswith(s[1:]):
            return True
    return False


def analyze_certificate(cb: CertBundle, cfg: Config, store=None, ct_fetcher=None, now: dt.datetime | None = None) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    add = lambda *a, **k: sigs.append(Signal(*a, **k))
    now = now or dt.datetime.now(dt.timezone.utc)
    if not cb.ok or cb.leaf is None:
        info = {"available": False, "error": cb.error}
        if cb.error and not cb.error.startswith("blocked"):
            add("cert.unavailable", "cert", "low", 6, "No valid TLS handshake on port 443", cb.error)
        return sigs, info

    c = cb.leaf
    nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    try:
        sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    issuer_cn, issuer_o = _name(c.issuer, NameOID.COMMON_NAME), _name(c.issuer, NameOID.ORGANIZATION_NAME)
    subject_cn = _name(c.subject, NameOID.COMMON_NAME)
    self_signed = c.issuer == c.subject
    pub = c.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_desc = f"RSA {pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_desc = f"EC {pub.curve.name}"
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_desc = "EdDSA"
    else:
        key_desc = type(pub).__name__
    try:
        sig_hash = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none"
    except Exception:
        sig_hash = "unknown"
    try:
        c.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        has_sct = True
    except x509.ExtensionNotFound:
        has_sct = False
    try:
        pols = c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        oids = {p.policy_identifier.dotted_string for p in pols}
    except x509.ExtensionNotFound:
        oids = set()
    validation = ("EV" if "2.23.140.1.1" in oids else "OV" if "2.23.140.1.2.2" in oids
                  else "IV" if "2.23.140.1.2.3" in oids else "DV" if "2.23.140.1.2.1" in oids else "unknown")
    spki = spki_sha256(c)
    age_days = (now - nb).days
    life_days = (na - nb).days
    info = {
        "available": True, "subject_cn": subject_cn, "issuer_cn": issuer_cn, "issuer_org": issuer_o,
        "serial": format(c.serial_number, "x"), "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "age_days": age_days, "validity_days": life_days, "sans": sans[:20], "key": key_desc, "signature_hash": sig_hash,
        "has_sct": has_sct, "validation": validation, "tls_version": cb.tls_version, "cipher": cb.cipher,
        "spki_sha256": spki, "self_signed": self_signed, "chain_length": len(cb.chain),
        "trusted": cb.verify_error is None, "verify_error": cb.verify_error,
    }

    # trust & identity
    if cb.verify_error:
        v = cb.verify_error.lower()
        if "self" in v and "signed" in v or self_signed:
            add("cert.self_signed", "cert", "high", 25, "Self-signed certificate", cb.verify_error)
        elif "expired" in v:
            add("cert.expired", "cert", "high", 25, "Certificate has expired", cb.verify_error)
        elif "hostname" in v or "match" in v:
            add("cert.hostname_mismatch", "cert", "high", 28, "Certificate was issued for a different name", cb.verify_error)
        else:
            add("cert.untrusted", "cert", "high", 24, "Certificate chain is not trusted", cb.verify_error)
    if sans and not _san_match(cb.host, sans) and not cb.verify_error:
        add("cert.san_mismatch", "cert", "high", 28, "Hostname is not listed in the certificate")
    if now < nb:
        add("cert.not_yet_valid", "cert", "high", 20, "Certificate is not yet valid")

    # freshness: most phishing certificates are days old
    if age_days <= 7:
        add("cert.very_new", "cert", "medium", 14, f"Certificate was issued only {max(age_days, 0)} day(s) ago",
            "Fresh certificates are common on newly-created phishing sites (and on legitimate new sites).")
    elif age_days <= 30:
        add("cert.new", "cert", "low", 6, f"Certificate issued {age_days} days ago")
    if life_days > 398 and not cb.verify_error:
        add("cert.long_lived", "cert", "low", 8, f"Validity period of {life_days} days exceeds the 398-day public-TLS limit")

    # crypto hygiene
    if sig_hash in ("sha1", "md5", "md2", "md4"):
        add("cert.weak_signature", "cert", "high", 30, f"Weak signature hash ({sig_hash.upper()})")
    if isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.key_size < 224:
        add("cert.ec_small", "cert", "high", 28, f"Weak elliptic curve {pub.curve.name}")
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        for wid, sev, w, msg in rsa_modulus_weaknesses(nums.n, nums.e):
            add(wid, "cert", sev, w, msg)
        if store is not None:
            try:
                clash = store.moduli_sharing_factor(nums.n, cb.host)
                if clash:
                    add("cert.rsa_shared_factor", "cert", "critical", 60,
                        "RSA modulus shares a prime factor with another observed certificate",
                        "Indicates broken randomness during key generation; private keys of both can be computed. Seen on: "
                        + ", ".join(clash[:3]))
            except Exception:
                pass
    if cb.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        add("cert.old_tls", "cert", "medium", 10, f"Server negotiated legacy {cb.tls_version}")
    if not has_sct and na > now and age_days > 1 and (now - nb).days < 3650:
        add("cert.no_sct", "cert", "low", 8, "No Certificate Transparency timestamp embedded",
            "Publicly-trusted certificates are expected to be logged; absence can mean a private/unusual CA.")

    # operator watch-list (distrusted CAs / keys)
    chain_names = [(_issuer_key(_name(x.issuer, NameOID.COMMON_NAME) + " " + _name(x.issuer, NameOID.ORGANIZATION_NAME))) for x in cb.chain]
    for wl in cfg.distrusted_issuers:
        if any(wl in n for n in chain_names):
            add("cert.distrusted_issuer", "cert", "critical", 60, f"Chain includes a watch-listed issuer ({wl})",
                "Your trust watch-list marks this CA as compromised or distrusted.")
            break
    if spki in cfg.distrusted_spki:
        add("cert.distrusted_key", "cert", "critical", 70, "Public key is on the distrusted-key watch-list")

    # cross-domain key reuse (collaborative)
    if store is not None:
        try:
            others = store.key_reuse(spki, cb.host)
            if len(others) >= 3:
                add("cert.key_reuse", "cert", "medium", 14, f"Same public key is used by {len(others)} other unrelated domains",
                    ", ".join(others[:4]))
            store.record_cert(cb.host, spki, hex(pub.public_numbers().n) if isinstance(pub, rsa.RSAPublicKey) else None,
                              issuer_cn or issuer_o, format(c.serial_number, "x"))
        except Exception:
            pass

    # Certificate Transparency
    ct = {"checked": False}
    fetcher = ct_fetcher or (crtsh_fetch if cfg.ct_enabled else None)
    if fetcher and not cb.verify_error:
        base = cb.host[4:] if cb.host.startswith("www.") else cb.host
        entries = fetcher(base)
        if entries is None:
            ct = {"checked": False, "error": "CT lookup unavailable"}
        else:
            ct = {"checked": True, "entries": len(entries)}
            serials = {_norm_serial(e.get("serial_number", "")) for e in entries}
            if entries and _norm_serial(format(c.serial_number, "x")) not in serials and age_days >= 2:
                add("cert.not_in_ct", "cert", "high", 22, "Served certificate was not found in Certificate Transparency logs",
                    "A publicly-trusted certificate that is absent from CT can indicate mis-issuance or a rogue CA.")
            hist = []
            for e in entries:
                try:
                    hist.append((dt.datetime.fromisoformat(e["not_before"].replace("Z", "")).replace(tzinfo=dt.timezone.utc),
                                 _issuer_key(e.get("issuer_name", ""))))
                except Exception:
                    continue
            old = [(t, i) for t, i in hist if (now - t).days > 120]
            recent_30 = [1 for t, _ in hist if (now - t).days <= 30]
            ct.update({"history": len(hist), "recent_30d": len(recent_30)})
            if len(old) >= 3:
                old_issuers = sorted({i for _, i in old})
                known = " | ".join(old_issuers)
                cur_names = [n.lower() for n in (issuer_o, issuer_cn) if n]
                if cur_names and not any(n in known for n in cur_names):
                    add("cert.issuer_change", "cert", "medium", 14, "Certificate issuer differs from this domain’s history",
                        f"Earlier certificates came from: {old_issuers[0][:100]}; this one from {issuer_o or issuer_cn}.")
            if len(recent_30) >= 25:
                add("cert.mass_issuance", "cert", "low", 8, f"{len(recent_30)} certificates issued for this name in 30 days")
    info["ct"] = ct

    if validation in ("EV", "OV") and not cb.verify_error:
        add("cert.org_validated", "cert", "info", -6, f"{validation}-validated certificate",
            "The CA verified the organisation behind the site.")
    return sigs, info
