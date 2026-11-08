# PhishGuard

Detects phishing and malicious websites by combining four engines in one explainable score:

| Engine | What it checks |
|---|---|
| **Threat analysis** (`url_analyzer`, `content_analyzer`) | Brand impersonation (typosquatting, homoglyph/IDN, combosquatting, brand-as-subdomain), raw-IP and `@` tricks, free-hosting abuse, cross-domain credential forms, hot-linked brand assets, hidden iframes, obfuscated JS, urgency / fake-job / payment-scam language, executable downloads |
| **Certificate validation** (`cert_analyzer`) | Live TLS handshake; trust/expiry/hostname; certificate age; SCT presence; **weak RSA key tests** (small prime factors, Fermat-close primes, even modulus, odd exponents, short keys); **shared prime factors across observed certificates**; same key reused across unrelated domains; **Certificate Transparency cross-check** (cert missing from CT, unexpected issuer change); operator watch-list of distrusted CAs/keys |
| **Web security** (`web_security`) | HSTS, CSP, clickjacking, nosniff, referrer policy, CORS, cookie flags, version disclosure and end-of-life software, mixed content, SRI, old jQuery/WordPress, directory listing, error leakage; opt-in probes for exposed `.git`/`.env`/etc. |
| **Collaborative intelligence** (`intel`) | Reporter API keys, reputation- and age-weighted reports, votes, feed import (OpenPhish/PhishTank-style lists), reputation settling against feeds/admin truth, allow-list, JSON / text / **STIX 2.1** blocklist export |

Output: a **phishing risk score 0–100** (noisy-OR of explainable signals; trust signals subtract) and a separate **security-posture grade A–F**. Server misconfiguration never inflates the phishing score.

## Windows quick start

1. Install Python 3.11 or newer and enable **Add Python to PATH**.
2. Extract the ZIP and open the `phishguard` folder.
3. Double-click `setup_windows.bat` (first run only; internet is required to install packages).
4. Double-click `start_windows.bat`.
5. Open `http://127.0.0.1:8080` in your browser.

To stop the server, focus the terminal window and press `Ctrl+C`.

For a canned interface demonstration, use `start_demo_windows.bat`. Demo mode
does not fetch or scan the URL typed by the visitor; it displays a sample report.

## Run

```bash
pip install -r requirements.txt
python -m pytest tests -q                         # 92 tests, offline
python examples/demo_server.py                    # UI with a canned phishing page, no network needed
python -m phishguard.app                          # real service on 127.0.0.1:8080
python -m phishguard.cli scan https://example.com [--json] [--no-ct] [--no-fetch]
```

Environment: `PHISHGUARD_DB` (sqlite path), `PHISHGUARD_ADMIN_KEY`, `PHISHGUARD_CT=0` (disable crt.sh), `PHISHGUARD_WATCHLIST` (JSON file, see below), `PHISHGUARD_PROXY_DNS=1` (behind an egress proxy that resolves names).

Watch-list file:
```json
{"distrusted_issuers": ["name of a CA you no longer trust"], "distrusted_spki_sha256": ["<hex sha256 of SubjectPublicKeyInfo>"]}
```

## API

| Method & path | Purpose |
|---|---|
| `POST /api/analyze` `{url, fetch?, deep?, authorized?}` | Full report. `deep` (exposed-file probes) requires `authorized: true`: only for sites you own or may test |
| `GET /api/intel/lookup?url=` | Community/feed status |
| `POST /api/reporters` `{name}` | Get an API key (shown once) |
| `POST /api/reports` (`X-API-Key`) `{url, verdict, category, comment}` | Submit `malicious` / `suspicious` / `safe` |
| `POST /api/reports/<id>/vote` `{value: 1 \| -1}` | Confirm or dispute |
| `GET /api/blocklist?format=json\|txt\|stix&min_confidence=` | Share indicators |
| `POST /api/feeds/import`, `POST /api/admin/resolve` (`X-Admin-Key`) | Import feeds; settle ground truth and adjust reporter reputation |

## Safety design

* **SSRF**: every URL and redirect hop is resolved and refused if non-public (loopback, RFC1918, link-local/cloud metadata, CGNAT, IPv6 ULA, decimal/hex IP spellings); only ports 80/443/8080/8443.
* Pages are **never rendered or executed**; bodies are size-capped; non-text content is not downloaded.
* UI renders all analysed text with `textContent` (attacker-controlled strings), strict CSP, rate limits, 1 MB request cap, API keys stored hashed.
* Active probing is opt-in and attested.

## Honest limitations

* **Heuristic, not ground truth.** Brand list and weights are starting points; expect false positives (e.g. legitimate sites that embed brand names) and misses (new brands, cloaking, JS-only kits). Tune `data.py` and weights using your own labelled data, which the intel store collects.
* DNS rebinding: resolution is checked, then the HTTP client resolves again. Deploy with an egress firewall/network namespace (or a policy-enforcing proxy with `PHISHGUARD_PROXY_DNS=1`).
* Certificate retrieval uses direct TLS on 443 and does not go through HTTP proxies. Where only a proxy is available, certificate analysis reports "could not be retrieved".
* Weak-key tests catch *gross* generation failures only. A clean result does not prove a key is strong, and no ROCA-style fingerprint test is included. Cross-domain shared-prime detection only sees certificates this instance has scanned, so it improves as it is used (or by seeding it from CT).
* CT lookups use crt.sh, a best-effort public service; failures are reported as "unavailable", never as findings. A cert absent from CT is not proof of mis-issuance (logging delay).
* Revocation (OCSP/CRL) is not checked. End-of-life tables in `data.py` need periodic maintenance.
* Sybil resistance is basic (account-age damping, per-reporter rate limit, dedupe). Add SSO/CAPTCHA before opening registration publicly.

## Layout

```
phishguard/  analyzers/{url,content,cert,web_security}.py  intel.py  scoring.py  pipeline.py  netsafe.py  app.py  cli.py  static/
tests/       92 tests incl. a real local TLS server, weak-key maths, SSRF cases, consensus/reputation, API
examples/    demo_server.py
```


## Hosted judging demo (Render)

This repository includes `render_app.py`, a **safe demo-mode** entry point for public hosting.
It uses a canned sample page and does not fetch or probe the URL entered by a visitor.
The displayed analysis is therefore a demonstration of the interface and reporting flow,
not a live verdict about the entered website.

On Render, create a **Web Service** connected to this repository and set:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --bind 0.0.0.0:$PORT render_app:app`

After deployment, open the Render URL and try a sample URL such as `https://example.com`.
For live URL analysis, use a private/local deployment with appropriate network egress
controls; do not expose an unrestricted URL scanner publicly.
