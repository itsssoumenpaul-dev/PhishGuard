import json
import time
import pytest
from phishguard.intel import IntelStore, IntelError, canon


def age(store, key_hash_all=True):
    """Make all reporters 'old' so weights are not damped in tests."""
    with store.db:
        store.db.execute("UPDATE reporters SET created_at=?", (time.time() - 30 * 86400,))


def test_canon_normalises():
    assert canon("HTTP://Evil.COM/path/?a=1")[0] == "evil.com/path?a=1"
    assert canon("evil.com/")[2] == "evil.com"


def test_registration_and_auth(store):
    with pytest.raises(IntelError) as e:
        store.submit_report("nope", "evil.test", "malicious")
    assert e.value.status == 401
    k = store.register_reporter("alice")
    assert store.submit_report(k, "http://evil.test/login", "phishing")["report_id"]


def test_consensus_needs_multiple_reporters(store):
    keys = [store.register_reporter(n) for n in "abc"]
    age(store)
    store.submit_report(keys[0], "http://evil.test/login", "malicious")
    assert store.lookup("http://evil.test/login")["status"] == "reported"
    store.submit_report(keys[1], "http://evil.test/login", "malicious")
    assert store.lookup("http://evil.test/login")["status"] == "confirmed_malicious"


def test_new_accounts_have_less_weight(store):
    k = store.register_reporter("fresh")
    store.submit_report(k, "evil.test", "malicious")
    w_new = store.lookup("evil.test")["community"]["malicious_weight"]
    age(store)
    assert store.lookup("evil.test")["community"]["malicious_weight"] > w_new


def test_sybil_reports_from_same_reporter_dedupe(store):
    k = store.register_reporter("spam")
    for _ in range(3):
        store.submit_report(k, "evil.test/a", "malicious")
    assert store.lookup("evil.test/a")["community"]["reports"] == 1


def test_disputed_when_safe_votes_outweigh(store):
    ks = [store.register_reporter(n) for n in "abcd"]; age(store)
    store.submit_report(ks[0], "site.test", "malicious")
    store.submit_report(ks[1], "site.test", "safe"); store.submit_report(ks[2], "site.test", "safe")
    assert store.lookup("site.test")["status"] == "disputed"


def test_votes_and_self_vote_forbidden(store):
    a, b = store.register_reporter("a"), store.register_reporter("b"); age(store)
    rid = store.submit_report(a, "x.test", "malicious")["report_id"]
    with pytest.raises(IntelError):
        store.vote(a, rid, 1)
    before = store.lookup("x.test")["community"]["malicious_weight"]
    store.vote(b, rid, 1)
    assert store.lookup("x.test")["community"]["malicious_weight"] > before


def test_report_rate_limit(store):
    k = store.register_reporter("rl")
    for i in range(5):
        store.submit_report(k, f"s{i}.test", "malicious")
    with pytest.raises(IntelError) as e:
        store.submit_report(k, "s9.test", "malicious")
    assert e.value.status == 429


def test_feed_import_confirms_and_adjusts_reputation(store):
    k = store.register_reporter("good")
    store.submit_report(k, "http://evil.test/login", "malicious")
    n = store.import_feed("openphish", ["# comment", "http://evil.test/login", "bad-domain.test"])
    assert n == 2
    assert store.lookup("http://evil.test/login")["status"] == "confirmed_malicious"
    assert store.lookup("bad-domain.test/anything")["feeds"] == ["openphish"]
    rep = store.db.execute("SELECT reputation FROM reporters").fetchone()[0]
    assert rep > 1.0


def test_admin_resolve_penalises_false_reports_and_allowlists(store):
    k = store.register_reporter("troll")
    store.submit_report(k, "legit.test", "malicious")
    store.resolve("legit.test", "safe")
    assert store.db.execute("SELECT reputation FROM reporters").fetchone()[0] < 1.0
    assert store.lookup("legit.test")["allowlisted"]


def test_blocklist_export_formats(store):
    ks = [store.register_reporter(n) for n in "ab"]; age(store)
    for k in ks:
        store.submit_report(k, "evil.test/x", "malicious")
    store.import_feed("feed", ["worse.test"])
    items = store.export_blocklist()
    assert {i["indicator"] for i in items} >= {"worse.test", "evil.test"}
    stix = store.to_stix(items)
    assert stix["type"] == "bundle" and all(o["pattern"].startswith("[") and o["spec_version"] == "2.1" for o in stix["objects"])
    json.dumps(stix)


def test_key_reuse_ignores_same_family(store):
    store.record_cert("a.example.com", "spki1", None, "ca", "1")
    store.record_cert("b.example.com", "spki1", None, "ca", "2")
    store.record_cert("x.other.net", "spki1", None, "ca", "3")
    assert store.key_reuse("spki1", "a.example.com") == ["x.other.net"]
