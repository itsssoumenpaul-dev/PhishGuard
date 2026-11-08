from __future__ import annotations
import hmac
import time
from collections import defaultdict, deque

from flask import Flask, Response, jsonify, request, send_from_directory

from . import pipeline
from .config import Config
from .intel import IntelError, IntelStore


def create_app(cfg: Config | None = None, store: IntelStore | None = None, **pipeline_kwargs) -> Flask:
    cfg = cfg or Config.from_env()
    store = store or IntelStore(cfg.db_path, cfg.reports_per_hour)
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000
    app.config["PG_CFG"], app.config["PG_STORE"] = cfg, store
    hits: dict[str, deque] = defaultdict(deque)

    def limited(key: str, limit: int, window: int = 60) -> bool:
        q, now = hits[key], time.time()
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False

    def admin_only():
        k = request.headers.get("X-Admin-Key", "")
        if not cfg.admin_key or not hmac.compare_digest(k, cfg.admin_key):
            raise IntelError("admin key required", 403)

    @app.after_request
    def secure(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store" if request.path.startswith("/api") else resp.headers.get("Cache-Control", "no-cache")
        return resp

    @app.errorhandler(IntelError)
    def intel_err(e):
        return jsonify(error=str(e)), e.status

    @app.errorhandler(413)
    def too_big(_e):
        return jsonify(error="request too large"), 413

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", **store.stats())

    @app.post("/api/analyze")
    def analyze():
        if limited("analyze:" + (request.remote_addr or "?"), cfg.analyze_per_minute):
            return jsonify(error="rate limit exceeded"), 429
        body = request.get_json(silent=True) or {}
        url = body.get("url", "")
        if not isinstance(url, str):
            return jsonify(error="url must be a string"), 400
        deep = bool(body.get("deep"))
        if deep and body.get("authorized") is not True:
            return jsonify(error="deep scans probe for exposed files and require authorized=true (you must own or be permitted to test the site)"), 400
        try:
            rep = pipeline.analyze(url, cfg, store, fetch=body.get("fetch", True) is not False, deep=deep,
                                   authorized=body.get("authorized") is True, **pipeline_kwargs)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        return jsonify(rep)

    @app.get("/api/intel/lookup")
    def lookup():
        url = request.args.get("url", "")
        if not url:
            return jsonify(error="url is required"), 400
        return jsonify(store.lookup(url))

    @app.post("/api/reporters")
    def register():
        if limited("reg:" + (request.remote_addr or "?"), 5, 3600):
            return jsonify(error="rate limit exceeded"), 429
        key = store.register_reporter((request.get_json(silent=True) or {}).get("name", ""))
        return jsonify(api_key=key, note="Store this key; it cannot be shown again."), 201

    @app.post("/api/reports")
    def report():
        b = request.get_json(silent=True) or {}
        out = store.submit_report(request.headers.get("X-API-Key"), b.get("url", ""), b.get("verdict", ""),
                                  b.get("category", "phishing"), b.get("comment", ""))
        return jsonify(out), 201

    @app.post("/api/reports/<int:rid>/vote")
    def vote(rid):
        return jsonify(store.vote(request.headers.get("X-API-Key"), rid, (request.get_json(silent=True) or {}).get("value", 0)))

    @app.get("/api/blocklist")
    def blocklist():
        items = store.export_blocklist(float(request.args.get("min_confidence", 0.6)))
        fmt = request.args.get("format", "json")
        if fmt == "txt":
            return Response("\n".join(i["indicator"] for i in items) + "\n", mimetype="text/plain")
        if fmt == "stix":
            return jsonify(store.to_stix(items))
        return jsonify(indicators=items, count=len(items))

    @app.post("/api/feeds/import")
    def feed_import():
        admin_only()
        b = request.get_json(silent=True) or {}
        n = store.import_feed(str(b.get("source", "feed")), b.get("entries", []), b.get("ttl_days", 30))
        return jsonify(imported=n)

    @app.post("/api/admin/resolve")
    def resolve():
        admin_only()
        b = request.get_json(silent=True) or {}
        return jsonify(adjusted_reports=store.resolve(b.get("url", ""), b.get("truth", "")))

    @app.get("/api/recent")
    def recent():
        return jsonify(scans=store.recent_scans(int(request.args.get("limit", 15))))

    return app


def main():
    import os
    app = create_app()
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))


if __name__ == "__main__":
    main()
