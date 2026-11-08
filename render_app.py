"""Safe hosted demo entry point for Render.

This intentionally uses a canned sample page and performs no outbound scans.
It is suitable for a public judging demo without exposing a public URL-fetching
service.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from phishguard.app import create_app
from phishguard.analyzers.cert_analyzer import CertBundle
from phishguard.config import Config
from phishguard.netsafe import FetchResult
from test_content_web import PHISH


def demo_fetcher(url, cfg):
    return FetchResult(
        ok=True,
        url=url,
        final_url=url,
        status=200,
        body=PHISH,
        content_type="text/html",
        tls_verified=False,
        headers={"server": "Demo Server", "x-powered-by": "PhishGuard Demo"},
        set_cookies=[],
        chain=[{"url": url, "status": 200}],
    )


app = create_app(
    Config(db_path=os.environ.get("PHISHGUARD_DB", ":memory:"), ct_enabled=False),
    fetcher=demo_fetcher,
    cert_fetcher=lambda host, cfg: CertBundle(host=host, error="demo mode: no live TLS lookup"),
)
