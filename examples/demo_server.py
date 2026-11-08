"""Offline demo: serves the UI with a canned phishing page so you can see a full report without network access.
    python examples/demo_server.py   ->  http://127.0.0.1:8081
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from phishguard.app import create_app
from phishguard.analyzers.cert_analyzer import CertBundle
from phishguard.config import Config
from phishguard.netsafe import FetchResult
from test_content_web import PHISH

def fetcher(url, cfg):
    return FetchResult(ok=True, url=url, final_url=url, status=200, body=PHISH, content_type="text/html", tls_verified=False,
                       headers={"server": "Apache/2.2.15", "x-powered-by": "PHP/5.6.40"}, set_cookies=["PHPSESSID=abc; path=/"],
                       chain=[{"url": url, "status": 200}])

if __name__ == "__main__":
    app = create_app(Config(db_path=":memory:", ct_enabled=False), fetcher=fetcher,
                     cert_fetcher=lambda h, c: CertBundle(host=h, error="demo: no network"))
    app.run(port=8081)
