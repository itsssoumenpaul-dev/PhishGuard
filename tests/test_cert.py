import datetime as dt
import socket
import ssl
import tempfile
import threading
from math import isqrt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from phishguard.analyzers import cert_analyzer as ca
from phishguard.analyzers.cert_analyzer import CertBundle, analyze_certificate, rsa_modulus_weaknesses, fetch_certificate
from conftest import make_cert, rand_prime, next_prime


def bundle(cert, host="example.test", verify_error=None):
    return CertBundle(host=host, ok=True, leaf=cert, chain=[cert], verify_error=verify_error, tls_version="TLSv1.3")


def sig_ids(sigs):
    return {s.id for s in sigs}


# ---- weak-key mathematics (the eMudhra-style class of failure: bad key generation)
def test_healthy_modulus_passes():
    p, q = rand_prime(1024), rand_prime(1024)
    assert rsa_modulus_weaknesses(p * q, 65537) == []


def test_small_factor_detected():
    n = 7 * rand_prime(1100)
    assert "cert.rsa_small_factor" in [w[0] for w in rsa_modulus_weaknesses(n, 65537)]


def test_close_primes_detected_by_fermat():
    p = rand_prime(1024)
    q = next_prime(p + 2 ** 20)
    ids = [w[0] for w in rsa_modulus_weaknesses(p * q, 65537)]
    assert "cert.rsa_close_primes" in ids


def test_small_key_and_exponent_flagged():
    p, q = rand_prime(512), rand_prime(512)
    ids = [w[0] for w in rsa_modulus_weaknesses(p * q, 3)]
    assert "cert.rsa_small" in ids and "cert.rsa_exponent" in ids


def test_even_modulus():
    assert rsa_modulus_weaknesses(2 * rand_prime(2047), 65537)[0][0] == "cert.rsa_even"


# ---- certificate analysis
def test_fresh_self_signed_cert(cfg):
    cert, _ = make_cert("evil.test", days_old=1, sans=["evil.test"])
    s, info = analyze_certificate(bundle(cert, "evil.test", "self-signed certificate"), cfg)
    assert {"cert.self_signed", "cert.very_new"} <= sig_ids(s)
    assert info["self_signed"] and info["key"] == "RSA 2048"


def test_hostname_mismatch(cfg):
    cert, _ = make_cert("other.test", self_signed=False, issuer_cn="Some CA", days_old=200)
    s, _ = analyze_certificate(bundle(cert, "bank.test", "Hostname mismatch, certificate is not valid for 'bank.test'"), cfg)
    assert "cert.hostname_mismatch" in sig_ids(s)


def test_weak_rsa_1024_and_sha1(cfg):
    key = rsa.generate_private_key(65537, 1024)
    cert, _ = make_cert("legacy.test", key=key, hash_alg=hashes.SHA256(), days_old=400, valid_days=900)
    s, _ = analyze_certificate(bundle(cert, "legacy.test"), cfg)
    assert {"cert.rsa_small", "cert.long_lived"} <= sig_ids(s)


def test_distrusted_issuer_watchlist(cfg):
    cfg.distrusted_issuers = ["bad ca"]
    cert, _ = make_cert("site.test", issuer_cn="Bad CA Root", days_old=100, issuer_key=rsa.generate_private_key(65537, 2048))
    s, _ = analyze_certificate(bundle(cert, "site.test"), cfg)
    assert "cert.distrusted_issuer" in sig_ids(s)
    assert next(x for x in s if x.id == "cert.distrusted_issuer").severity == "critical"


def test_distrusted_key_watchlist(cfg):
    cert, _ = make_cert("site.test", days_old=100)
    cfg.distrusted_spki = [ca.spki_sha256(cert)]
    s, _ = analyze_certificate(bundle(cert, "site.test"), cfg)
    assert "cert.distrusted_key" in sig_ids(s)


def test_shared_prime_across_domains_via_store(cfg, store):
    p, q1, q2 = rand_prime(1024), rand_prime(1024), rand_prime(1024)
    def cert_for(host, n):
        key = rsa.RSAPrivateNumbers  # build a key from primes
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers, rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
        pp, qq = n
        d = pow(65537, -1, (pp - 1) * (qq - 1))
        priv = RSAPrivateNumbers(pp, qq, d, rsa_crt_dmp1(d, pp), rsa_crt_dmq1(d, qq), rsa_crt_iqmp(pp, qq), RSAPublicNumbers(65537, pp * qq)).private_key()
        return make_cert(host, key=priv, days_old=100)[0]
    c1, c2 = cert_for("a.test", (p, q1)), cert_for("b.example", (p, q2))
    analyze_certificate(bundle(c1, "a.test"), cfg, store)
    s, _ = analyze_certificate(bundle(c2, "b.example"), cfg, store)
    assert "cert.rsa_shared_factor" in sig_ids(s)


def test_ct_not_logged_and_issuer_change(cfg):
    cert, _ = make_cert("shop.test", self_signed=False, issuer_cn="Rogue CA", days_old=30)
    now = dt.datetime.now(dt.timezone.utc)
    old = [{"serial_number": f"0{i}", "not_before": (now - dt.timedelta(days=200 + 60 * i)).strftime("%Y-%m-%dT%H:%M:%S"),
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3"} for i in range(4)]
    s, info = analyze_certificate(bundle(cert, "shop.test"), cfg, ct_fetcher=lambda d: old)
    assert {"cert.not_in_ct", "cert.issuer_change"} <= sig_ids(s)
    assert info["ct"]["checked"]


def test_ct_unavailable_is_not_a_finding(cfg):
    cert, _ = make_cert("shop.test", days_old=100)
    s, info = analyze_certificate(bundle(cert, "shop.test"), cfg, ct_fetcher=lambda d: None)
    assert "cert.not_in_ct" not in sig_ids(s) and info["ct"]["checked"] is False


# ---- real TLS handshake against a local server
def _serve(cert, key, ready, stop):
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f.name)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); srv.settimeout(0.3)
    ready.append(srv.getsockname()[1])
    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except OSError:
            continue
        try:
            with ctx.wrap_socket(c, server_side=True):
                pass
        except Exception:
            pass
    srv.close()


def test_live_handshake_reads_untrusted_cert(cfg):
    cfg.allow_private = True
    cert, key = make_cert("localhost", days_old=2)
    ready, stop = [], threading.Event()
    t = threading.Thread(target=_serve, args=(cert, key, ready, stop), daemon=True); t.start()
    while not ready:
        pass
    try:
        cb = fetch_certificate("localhost", cfg, port=ready[0])
        assert cb.ok and cb.verify_error and cb.leaf.serial_number == cert.serial_number
        s, info = analyze_certificate(cb, cfg)
        assert "cert.self_signed" in sig_ids(s) and info["trusted"] is False
    finally:
        stop.set()


def test_fetch_blocked_for_private_host(cfg):
    cb = fetch_certificate("localhost", cfg, port=443)
    assert not cb.ok and cb.error.startswith("blocked")
