"""CLI: python -m phishguard.cli scan <url> | report | import-feed | export"""
from __future__ import annotations
import argparse
import json
import sys

from .config import Config
from .intel import IntelStore
from . import pipeline

COL = {"malicious": "\033[91m", "high_risk": "\033[91m", "suspicious": "\033[93m", "low_risk": "\033[92m"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("url"); s.add_argument("--no-fetch", action="store_true"); s.add_argument("--no-ct", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("--deep", action="store_true", help="probe for exposed files; ONLY for sites you own / may test")
    s.add_argument("--i-am-authorized", action="store_true")
    f = sub.add_parser("import-feed"); f.add_argument("source"); f.add_argument("file")
    e = sub.add_parser("export"); e.add_argument("--format", choices=["json", "txt", "stix"], default="json")
    a = ap.parse_args(argv)
    cfg = Config.from_env()
    if getattr(a, "no_ct", False):
        cfg.ct_enabled = False
    store = IntelStore(cfg.db_path, cfg.reports_per_hour)

    if a.cmd == "scan":
        if a.deep and not a.i_am_authorized:
            print("--deep requires --i-am-authorized (only test sites you own or have permission to test)", file=sys.stderr)
            return 2
        r = pipeline.analyze(a.url, cfg, store, fetch=not a.no_fetch, deep=a.deep, authorized=a.i_am_authorized)
        if a.json:
            print(json.dumps(r, indent=2, default=str))
        else:
            c = COL.get(r["verdict"], "")
            print(f"{c}{r['label']} — risk {r['risk_score']}/100\033[0m   {r['url']}")
            if r["security_posture"]:
                print(f"Security posture grade: {r['security_posture']['grade']}")
            for sg in r["signals"]:
                if sg["weight"] or sg["severity"] != "info":
                    print(f"  [{sg['category']:7}] {sg['weight']:+4}  {sg['title']}")
            for line in r["recommendations"][:2]:
                print("  →", line)
        return 0 if r["verdict"] in ("low_risk", "suspicious") else 1
    if a.cmd == "import-feed":
        with open(a.file) as fh:
            print("imported", store.import_feed(a.source, fh.read().splitlines()))
    if a.cmd == "export":
        items = store.export_blocklist()
        print(json.dumps(store.to_stix(items) if a.format == "stix" else items, indent=2) if a.format != "txt" else "\n".join(i["indicator"] for i in items))
    return 0


if __name__ == "__main__":
    sys.exit(main())
