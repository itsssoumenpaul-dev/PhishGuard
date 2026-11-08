import pytest
from phishguard.analyzers.url_analyzer import analyze_url, normalize_url, registered_domain, levenshtein


def ids(u):
    r = analyze_url(normalize_url(u))
    return {s.id for s in r["signals"]}, r["features"]


def test_official_domain_gets_trust():
    i, f = ids("https://www.paypal.com/signin")
    assert "url.official" in i and f["official_brand"] == "paypal"
    assert not any(x.startswith("url.brand") for x in i)


def test_multi_part_suffix():
    assert registered_domain("www.sbi.co.in") == "sbi.co.in"
    assert registered_domain("a.b.example.com") == "example.com"


@pytest.mark.parametrize("url,kind", [
    ("https://gooogle.com", "url.brand.typosquat"),
    ("https://paypa1.com", "url.brand.lookalike"),
    ("https://paypal.com.evil.top/x", "url.brand.subdomain"),
    ("https://secure-hdfcbank-kyc.xyz/login", "url.brand.combosquat"),
    ("https://login.microsoftonline.com.auth-check.xyz/", "url.brand.subdomain"),
    ("https://paypa1-secure-login.verify-account.tk/", "url.brand.subdomain"),
])
def test_impersonation_kinds(url, kind):
    assert kind in ids(url)[0]


def test_homoglyph_idn():
    i, f = ids("https://xn--pypal-4ve.com/")   # "pаypal" with Cyrillic a
    assert "url.punycode" in i and "url.brand.lookalike" in i


def test_ip_and_userinfo_and_http():
    i, _ = ids("http://192.0.2.7/login")
    assert {"url.ip_host", "url.no_https"} <= i
    assert "url.userinfo" in ids("https://google.com@evil.example/")[0]
    assert "url.ip_host" in ids("http://2130706433/")[0]          # decimal-encoded IP


def test_no_false_positive_on_ordinary_names():
    for u in ["https://pineapple.com", "https://www.nitrkl.ac.in/", "https://example.org/about"]:
        assert not any(x.startswith("url.brand") for x in ids(u)[0]), u


def test_free_hosting_and_shortener():
    assert "url.free_hosting" in ids("https://my-site.weebly.com/login")[0]
    assert "url.shortener" in ids("https://bit.ly/abc")[0]


def test_ugc_on_official_platform_not_fully_trusted():
    i, _ = ids("https://docs.google.com/forms/d/e/abc/viewform")
    assert "url.official" not in i and "url.official_ugc" in i


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x.com", "", "a" * 3000, "file:///etc/passwd"])
def test_rejects_bad_schemes(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


def test_scheme_less_input_ok():
    assert normalize_url("example.com/login").startswith("http://example.com")


def test_levenshtein():
    assert levenshtein("google", "gooogle") == 1 and levenshtein("abc", "xyzxyz", 2) > 2
