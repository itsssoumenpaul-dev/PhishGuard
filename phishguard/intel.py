"""Collaborative threat-intelligence store (SQLite).

* Reporters register and receive an API key (stored hashed).
* Reports are weighted by reporter reputation and account age; reputation is
  adjusted when a domain is later confirmed (feed match or admin resolution).
* External feeds (OpenPhish/PhishTank-style lists) can be imported.
* Indicators are exported as JSON, plain text or STIX 2.1.
"""
from __future__ import annotations
import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from math import gcd
from urllib.parse import urlsplit

SCHEMA = """
CREATE TABLE IF NOT EXISTS reporters(id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, reputation REAL DEFAULT 1.0, created_at REAL);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, url TEXT, url_hash TEXT, host TEXT, verdict TEXT, category TEXT, comment TEXT,
  reporter_id INTEGER, created_at REAL, UNIQUE(reporter_id, url_hash));
CREATE INDEX IF NOT EXISTS ix_rep_host ON reports(host); CREATE INDEX IF NOT EXISTS ix_rep_hash ON reports(url_hash);
CREATE TABLE IF NOT EXISTS votes(report_id INTEGER, reporter_id INTEGER, value INTEGER, created_at REAL, PRIMARY KEY(report_id, reporter_id));
CREATE TABLE IF NOT EXISTS feed_entries(id INTEGER PRIMARY KEY, indicator TEXT, kind TEXT, source TEXT, added_at REAL, expires_at REAL, UNIQUE(indicator, source));
CREATE INDEX IF NOT EXISTS ix_feed_ind ON feed_entries(indicator);
CREATE TABLE IF NOT EXISTS allowlist(host TEXT PRIMARY KEY, note TEXT, added_at REAL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, url TEXT, host TEXT, score INTEGER, verdict TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS certs(id INTEGER PRIMARY KEY, host TEXT, spki TEXT, modulus_hex TEXT, issuer TEXT, serial TEXT, first_seen REAL, UNIQUE(host, spki));
CREATE INDEX IF NOT EXISTS ix_cert_spki ON certs(spki);
"""

MAL = ("malicious", "phishing")
VALID_VERDICTS = ("malicious", "phishing", "suspicious", "safe")
VALID_CATEGORIES = ("phishing", "malware", "scam", "fake_job", "payment_fraud", "impersonation", "other")


def canon(url: str) -> tuple[str, str, str]:
    """-> (canonical url, sha256, host)"""
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    p = urlsplit(u)
    host = (p.hostname or "").lower().rstrip(".")
    c = f"{host}{p.path.rstrip('/') or ''}" + (f"?{p.query}" if p.query else "")
    return c, hashlib.sha256(c.encode()).hexdigest(), host


class IntelError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


class IntelStore:
    def __init__(self, path: str = ":memory:", reports_per_hour: int = 30):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.rph = reports_per_hour
        with self.lock:
            if path != ":memory:":
                self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)

    # ------------------------------------------------------------ reporters
    def register_reporter(self, name: str) -> str:
        name = (name or "").strip()[:60]
        if not name:
            raise IntelError("name is required")
        key = "pg_" + secrets.token_urlsafe(24)
        with self.lock, self.db:
            self.db.execute("INSERT INTO reporters(name,key_hash,created_at) VALUES(?,?,?)", (name, hashlib.sha256(key.encode()).hexdigest(), time.time()))
        return key

    def _reporter(self, key: str | None):
        if not key:
            raise IntelError("missing API key", 401)
        with self.lock:
            r = self.db.execute("SELECT * FROM reporters WHERE key_hash=?", (hashlib.sha256(key.encode()).hexdigest(),)).fetchone()
        if not r:
            raise IntelError("invalid API key", 401)
        return r

    @staticmethod
    def _weight(r) -> float:
        age_days = (time.time() - r["created_at"]) / 86400
        return round(r["reputation"] * min(1.0, 0.4 + age_days / 10), 3)   # new accounts count for less (Sybil damping)

    # ------------------------------------------------------------ reports
    def submit_report(self, key: str, url: str, verdict: str, category: str = "phishing", comment: str = "") -> dict:
        r = self._reporter(key)
        if verdict not in VALID_VERDICTS:
            raise IntelError(f"verdict must be one of {VALID_VERDICTS}")
        if category not in VALID_CATEGORIES:
            category = "other"
        c, h, host = canon(url)
        if not host or "." not in host and ":" not in host:
            raise IntelError("invalid URL")
        verdict = "malicious" if verdict == "phishing" else verdict
        with self.lock, self.db:
            n = self.db.execute("SELECT COUNT(*) FROM reports WHERE reporter_id=? AND created_at>?", (r["id"], time.time() - 3600)).fetchone()[0]
            if n >= self.rph:
                raise IntelError("report rate limit reached; try again later", 429)
            self.db.execute(
                "INSERT INTO reports(url,url_hash,host,verdict,category,comment,reporter_id,created_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(reporter_id,url_hash) DO UPDATE SET verdict=excluded.verdict,category=excluded.category,comment=excluded.comment,created_at=excluded.created_at",
                (c, h, host, verdict, category, (comment or "")[:500], r["id"], time.time()))
            rid = self.db.execute("SELECT id FROM reports WHERE reporter_id=? AND url_hash=?", (r["id"], h)).fetchone()[0]
        return {"report_id": rid, "intel": self.lookup(url)}

    def vote(self, key: str, report_id: int, value: int) -> dict:
        r = self._reporter(key)
        if value not in (1, -1):
            raise IntelError("value must be 1 (confirm) or -1 (dispute)")
        with self.lock, self.db:
            rep = self.db.execute("SELECT reporter_id FROM reports WHERE id=?", (report_id,)).fetchone()
            if not rep:
                raise IntelError("report not found", 404)
            if rep["reporter_id"] == r["id"]:
                raise IntelError("you cannot vote on your own report", 403)
            self.db.execute("INSERT OR REPLACE INTO votes VALUES(?,?,?,?)", (report_id, r["id"], value, time.time()))
        return {"ok": True}

    def _community(self, c_hash: str, host: str) -> dict:
        with self.lock:
            rows = self.db.execute(
                "SELECT rp.id, rp.verdict, rp.category, rp.created_at, rp.url_hash, r.reputation, r.created_at AS rc, r.id AS rid "
                "FROM reports rp JOIN reporters r ON r.id=rp.reporter_id WHERE rp.url_hash=? OR rp.host=?", (c_hash, host)).fetchall()
            mal = safe = 0.0
            mal_reporters, cats, first, last = set(), {}, None, None
            for x in rows:
                w = self._weight({"reputation": x["reputation"], "created_at": x["rc"]})
                votes = self.db.execute("SELECT value FROM votes WHERE report_id=?", (x["id"],)).fetchall()
                w *= max(0.1, 1 + 0.15 * sum(v["value"] for v in votes))
                exact = 1.0 if x["url_hash"] == c_hash else 0.7   # host-level reports are slightly weaker evidence
                if x["verdict"] in ("malicious", "suspicious"):
                    k = 1.0 if x["verdict"] == "malicious" else 0.5
                    mal += w * k * exact
                    mal_reporters.add(x["rid"])
                    cats[x["category"]] = cats.get(x["category"], 0) + 1
                else:
                    safe += w * exact
                first = x["created_at"] if first is None else min(first, x["created_at"])
                last = x["created_at"] if last is None else max(last, x["created_at"])
        return {"malicious_weight": round(mal, 2), "safe_weight": round(safe, 2), "reports": len(rows),
                "malicious_reporters": len(mal_reporters), "confidence": round(mal / (mal + safe + 0.5), 2) if rows else 0.0,
                "categories": cats, "first_seen": first, "last_seen": last}

    def lookup(self, url: str) -> dict:
        c, h, host = canon(url)
        now = time.time()
        with self.lock:
            feeds = [dict(source=r["source"]) for r in self.db.execute(
                "SELECT DISTINCT source FROM feed_entries WHERE indicator IN (?,?) AND (expires_at IS NULL OR expires_at>?)", (c, host, now))]
            allow = self.db.execute("SELECT 1 FROM allowlist WHERE host=?", (host,)).fetchone() is not None
        com = self._community(h, host)
        if feeds or (com["malicious_reporters"] >= 2 and com["confidence"] >= 0.7):
            status = "confirmed_malicious"
        elif com["malicious_weight"] > com["safe_weight"] and com["malicious_weight"] > 0:
            status = "reported"
        elif com["safe_weight"] > 0 and com["malicious_weight"] > 0:
            status = "disputed"
        elif com["safe_weight"] >= 1:
            status = "community_safe"
        else:
            status = "unknown"
        return {"status": status, "feeds": [f["source"] for f in feeds], "allowlisted": allow, "community": com}

    # ------------------------------------------------------------ feeds / admin
    def import_feed(self, source: str, lines, ttl_days: int | None = 30) -> int:
        now = time.time()
        exp = now + ttl_days * 86400 if ttl_days else None
        n = 0
        rows = []
        for ln in lines:
            ln = (ln or "").strip()
            if not ln or ln.startswith("#"):
                continue
            c, _h, host = canon(ln.split()[0])
            if not host:
                continue
            kind = "url" if "/" in ln.split("://", 1)[-1].rstrip("/") else "domain"
            rows.append((c if kind == "url" else host, kind, source[:60], now, exp))
        with self.lock, self.db:
            for r in rows:
                cur = self.db.execute("INSERT OR REPLACE INTO feed_entries(indicator,kind,source,added_at,expires_at) VALUES(?,?,?,?,?)", r)
                n += cur.rowcount
        self._settle_from_feeds()
        return n

    def _settle_from_feeds(self) -> None:
        """Reporters who flagged an indicator that an external feed independently confirms gain reputation."""
        with self.lock, self.db:
            rows = self.db.execute(
                "SELECT rp.reporter_id, rp.verdict FROM reports rp JOIN feed_entries f ON f.indicator IN (rp.url, rp.host)").fetchall()
            for r in rows:
                self._adjust(r["reporter_id"], +0.05 if r["verdict"] == "malicious" else -0.2)

    def resolve(self, host_or_url: str, truth: str) -> int:
        """Admin ground-truth ('malicious' | 'safe'): adjust reporter reputation accordingly."""
        if truth not in ("malicious", "safe"):
            raise IntelError("truth must be malicious or safe")
        c, h, host = canon(host_or_url)
        with self.lock, self.db:
            rows = self.db.execute("SELECT reporter_id, verdict FROM reports WHERE host=? OR url_hash=?", (host, h)).fetchall()
            for r in rows:
                agree = (r["verdict"] in ("malicious", "suspicious")) == (truth == "malicious")
                self._adjust(r["reporter_id"], +0.2 if agree else -0.4)
            if truth == "safe":
                self.db.execute("INSERT OR REPLACE INTO allowlist VALUES(?,?,?)", (host, "resolved safe", time.time()))
        return len(rows)

    def _adjust(self, reporter_id: int, delta: float) -> None:
        self.db.execute("UPDATE reporters SET reputation=MIN(5.0, MAX(0.1, reputation+?)) WHERE id=?", (delta, reporter_id))

    def add_allow(self, host: str, note: str = "") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO allowlist VALUES(?,?,?)", (host.lower(), note[:100], time.time()))

    # ------------------------------------------------------------ export
    def export_blocklist(self, min_confidence: float = 0.6) -> list[dict]:
        now = time.time()
        out: dict[str, dict] = {}
        with self.lock:
            for r in self.db.execute("SELECT indicator,kind,source,added_at FROM feed_entries WHERE expires_at IS NULL OR expires_at>?", (now,)):
                e = out.setdefault(r["indicator"], {"indicator": r["indicator"], "type": r["kind"], "confidence": 0.95, "sources": [], "first_seen": r["added_at"]})
                e["sources"].append(r["source"])
            hosts = [r["host"] for r in self.db.execute("SELECT DISTINCT host FROM reports WHERE verdict IN ('malicious')")]
        for host in hosts:
            lk = self.lookup(host)
            com = lk["community"]
            if lk["allowlisted"] or com["confidence"] < min_confidence or com["malicious_reporters"] < 2:
                continue
            e = out.setdefault(host, {"indicator": host, "type": "domain", "confidence": com["confidence"], "sources": [], "first_seen": com["first_seen"]})
            e["sources"].append("community")
            e["confidence"] = max(e["confidence"], com["confidence"])
        return sorted(out.values(), key=lambda x: -x["confidence"])

    @staticmethod
    def to_stix(indicators: list[dict]) -> dict:
        ts = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t or time.time()))
        objs = []
        for i in indicators:
            kind = "url:value" if i["type"] == "url" else "domain-name:value"
            val = i["indicator"].replace("\\", "\\\\").replace("'", "\\'")
            objs.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, i['indicator'])}",
                         "created": ts(i["first_seen"]), "modified": ts(time.time()), "name": f"Malicious {i['type']}: {i['indicator']}",
                         "pattern": f"[{kind} = '{val}']", "pattern_type": "stix", "valid_from": ts(i["first_seen"]),
                         "confidence": int(i["confidence"] * 100), "indicator_types": ["malicious-activity"], "labels": i["sources"]})
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}

    # ------------------------------------------------------------ scans / certs / stats
    def record_scan(self, url: str, score: int, verdict: str) -> None:
        _c, _h, host = canon(url)
        with self.lock, self.db:
            self.db.execute("INSERT INTO scans(url,host,score,verdict,created_at) VALUES(?,?,?,?,?)", (url[:300], host, score, verdict, time.time()))

    def recent_scans(self, limit: int = 20) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT url,score,verdict,created_at FROM scans ORDER BY id DESC LIMIT ?", (min(limit, 100),))]

    def record_cert(self, host: str, spki: str, modulus_hex: str | None, issuer: str, serial: str) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO certs(host,spki,modulus_hex,issuer,serial,first_seen) VALUES(?,?,?,?,?,?)",
                            (host, spki, modulus_hex, issuer[:100], serial, time.time()))

    def key_reuse(self, spki: str, host: str) -> list[str]:
        def base(h):  # same registrable family isn't suspicious
            return ".".join(h.split(".")[-2:])
        with self.lock:
            hosts = [r["host"] for r in self.db.execute("SELECT DISTINCT host FROM certs WHERE spki=? AND host!=?", (spki, host))]
        return sorted({h for h in hosts if base(h) != base(host)})

    def moduli_sharing_factor(self, n: int, host: str, limit: int = 5000) -> list[str]:
        with self.lock:
            rows = self.db.execute("SELECT host, modulus_hex FROM certs WHERE modulus_hex IS NOT NULL AND host!=? ORDER BY id DESC LIMIT ?", (host, limit)).fetchall()
        out = []
        for r in rows:
            m = int(r["modulus_hex"], 16)
            if m != n:                       # identical modulus is key reuse, not a shared prime
                g = gcd(n, m)
                if g not in (1, n, m):
                    out.append(r["host"])
        return out

    def stats(self) -> dict:
        with self.lock:
            q = lambda s: self.db.execute(s).fetchone()[0]
            return {"reporters": q("SELECT COUNT(*) FROM reporters"), "reports": q("SELECT COUNT(*) FROM reports"),
                    "feed_indicators": q("SELECT COUNT(*) FROM feed_entries"), "scans": q("SELECT COUNT(*) FROM scans"),
                    "certificates_observed": q("SELECT COUNT(*) FROM certs")}
