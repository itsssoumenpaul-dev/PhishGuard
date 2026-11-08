import json
import pytest

from phishguard import pipeline
from phishguard.analyzers.cert_analyzer import CertBundle
from phishguard.app import create_app
from phishguard.intel import IntelStore
from phishguard.netsafe import FetchResult
from test_content_web import PHISH, fetch

no_cert = lambda host, cfg: CertBundle(host=host, error="ConnectionRefusedError")


def run(url, body, store, cfg, headers=None):
    fr = fetch(body, url, headers)
    return pipeline.analyze(url, cfg, store, fetcher=lambda u, c: fr, cert_fetcher=no_cert)


def test_phishing_scores_high(cfg, store):
    r = run("https://secure-paypa1.example-host.top/login", PHISH, store, cfg)
    assert r["risk_score"] >= 75 and r["verdict"] == "malicious"
    assert r["signals"][0]["weight"] >= r["signals"][-1]["weight"]
    assert any("Do not enter" in x for x in r["recommendations"])


def test_legit_site_scores_low(cfg, store):
    hdr = {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}
    r = run("https://www.google.com/", "<html><title>Google</title></html>", store, cfg, hdr)
    assert r["risk_score"] == 0 and r["verdict"] == "low_risk" and r["security_posture"]["grade"] == "A"


def test_hygiene_issues_do_not_make_a_site_look_like_phishing(cfg, store):
    r = run("https://example.edu/", "<html><title>College</title><a href='/a'>x</a></html>", store, cfg)
    assert r["risk_score"] < 25 and r["security_posture"]["grade"] in ("C", "D", "F")


def test_confirmed_intel_overrides(cfg, store):
    store.import_feed("openphish", ["innocent-looking.test"])
    r = run("https://innocent-looking.test/", "<html><title>hi</title></html>", store, cfg)
    assert r["risk_score"] == 100


def test_allowlist_dampens_but_not_critical(cfg, store):
    store.add_allow("shop.example.org")
    r = run("https://shop.example.org/login", "<html><title>Shop</title></html>", store, cfg)
    assert r["risk_score"] <= 8


def test_fetch_failure_still_gives_url_verdict(cfg, store):
    bad = FetchResult(ok=False, error="blocked: refusing non-public address 10.0.0.1")
    r = pipeline.analyze("http://paypal.com.evil.top/login", cfg, store, fetcher=lambda u, c: bad)
    assert r["risk_score"] >= 40 and "fetch" in r["errors"]


def test_analyzer_exception_is_contained(cfg, store, monkeypatch):
    from phishguard.analyzers import content_analyzer
    monkeypatch.setattr(content_analyzer, "analyze_content", lambda *a: 1 / 0)
    r = run("https://example.com/", "<html></html>", store, cfg)
    assert "content" in r["errors"] and "risk_score" in r


# ------------------------------------------------------------------ API
@pytest.fixture
def client(cfg, store):
    cfg.admin_key = "adm"
    fr = fetch(PHISH, "https://secure-paypa1.example-host.top/login")
    app = create_app(cfg, store, fetcher=lambda u, c: fr, cert_fetcher=no_cert)
    return app.test_client()


def test_api_analyze_and_validation(client):
    r = client.post("/api/analyze", json={"url": "https://secure-paypa1.example-host.top/login"})
    assert r.status_code == 200 and r.json["risk_score"] >= 75
    assert client.post("/api/analyze", json={"url": "javascript:alert(1)"}).status_code == 400
    assert client.post("/api/analyze", json={"url": 5}).status_code == 400
    assert client.post("/api/analyze", data="notjson").status_code == 400


def test_deep_scan_requires_attestation(client):
    r = client.post("/api/analyze", json={"url": "https://example.com", "deep": True})
    assert r.status_code == 400 and "authorized" in r.json["error"]


def test_security_headers_on_responses(client):
    r = client.get("/")
    assert r.status_code == 200 and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_report_flow_and_blocklist(client, store):
    keys = [client.post("/api/reporters", json={"name": n}).json["api_key"] for n in ("a", "b")]
    with store.db:
        store.db.execute("UPDATE reporters SET created_at=0")
    for k in keys:
        assert client.post("/api/reports", json={"url": "http://scam.test/pay", "verdict": "malicious"}, headers={"X-API-Key": k}).status_code == 201
    assert client.get("/api/intel/lookup", query_string={"url": "http://scam.test/pay"}).json["status"] == "confirmed_malicious"
    assert "scam.test" in client.get("/api/blocklist?format=txt").get_data(as_text=True)
    assert client.get("/api/blocklist?format=stix").json["type"] == "bundle"
    assert client.post("/api/reports", json={"url": "x.test", "verdict": "malicious"}).status_code == 401


def test_admin_endpoints_protected(client):
    assert client.post("/api/feeds/import", json={"entries": ["a.test"]}).status_code == 403
    r = client.post("/api/feeds/import", json={"source": "t", "entries": ["a.test"]}, headers={"X-Admin-Key": "adm"})
    assert r.status_code == 200 and r.json["imported"] == 1


def test_analyze_rate_limit(cfg, store):
    cfg.analyze_per_minute = 2
    app = create_app(cfg, store, fetcher=lambda u, c: fetch("<html></html>", u), cert_fetcher=no_cert)
    c = app.test_client()
    codes = [c.post("/api/analyze", json={"url": "https://example.com"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_oversized_body_rejected(client):
    assert client.post("/api/analyze", data="x" * 1_200_000, content_type="application/json").status_code == 413


def test_error_pages_are_not_graded(cfg, store):
    fr = fetch("<html>Forbidden</html>", "https://example.com/")
    fr.status = 403
    r = pipeline.analyze("https://example.com/", cfg, store, fetcher=lambda u, c: fr, cert_fetcher=no_cert)
    assert r["security_posture"] is None and any("403" in n for n in r["notes"])


def test_unreachable_page_lowers_confidence(cfg, store):
    bad = FetchResult(ok=False, error="ConnectionError")
    r = pipeline.analyze("https://example.com/", cfg, store, fetcher=lambda u, c: bad, cert_fetcher=no_cert)
    assert r["confidence"] == "low" and any("could not be fetched" in n for n in r["notes"])


def test_proxy_dns_mode_still_blocks_literal_internal_hosts(cfg):
    from phishguard.netsafe import safe_get
    cfg.proxy_does_dns = True
    for u in ["http://127.0.0.1/", "http://2130706433/", "http://localhost/", "http://[::1]/", "http://169.254.169.254/", "http://metadata.internal/"]:
        r = safe_get(u, cfg)
        assert not r.ok and r.error.startswith("blocked"), u
def test_signals_are_grouped(cfg, store):
    r = run('https://secure-paypa1.example-host.top/login', PHISH, store, cfg)
    g = {s['id']: s['group'] for s in r['signals']}
    assert g['url.brand.subdomain'] == 'risk' and g['web.no_hsts'] == 'posture'
