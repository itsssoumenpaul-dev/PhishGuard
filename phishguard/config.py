from __future__ import annotations
import json
import os
from dataclasses import dataclass, field


def _b(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    db_path: str = "phishguard.db"
    fetch_timeout: float = 8.0
    max_bytes: int = 1_500_000
    max_redirects: int = 5
    allow_private: bool = False        # only ever True in tests
    trust_env: bool = True             # honour HTTP(S)_PROXY for outbound fetches
    proxy_does_dns: bool = False       # egress proxy resolves names & enforces network policy (skip local DNS check)
    ct_enabled: bool = True            # query Certificate Transparency (crt.sh)
    admin_key: str = ""                # required for feed import / resolve endpoints
    reports_per_hour: int = 30
    analyze_per_minute: int = 20
    watchlist_path: str = ""           # JSON: {"distrusted_issuers": [...], "distrusted_spki_sha256": [...]}
    distrusted_issuers: list = field(default_factory=list)
    distrusted_spki: list = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Config":
        c = cls(
            db_path=os.environ.get("PHISHGUARD_DB", "phishguard.db"),
            ct_enabled=_b("PHISHGUARD_CT", True),
            trust_env=_b("PHISHGUARD_TRUST_ENV", True),
            proxy_does_dns=_b("PHISHGUARD_PROXY_DNS", False),
            admin_key=os.environ.get("PHISHGUARD_ADMIN_KEY", ""),
            watchlist_path=os.environ.get("PHISHGUARD_WATCHLIST", ""),
        )
        c.load_watchlist()
        return c

    def load_watchlist(self) -> None:
        if self.watchlist_path and os.path.exists(self.watchlist_path):
            with open(self.watchlist_path) as f:
                d = json.load(f)
            self.distrusted_issuers = [s.lower() for s in d.get("distrusted_issuers", [])]
            self.distrusted_spki = [s.lower() for s in d.get("distrusted_spki_sha256", [])]
