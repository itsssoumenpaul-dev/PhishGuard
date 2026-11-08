import pytest
from phishguard.netsafe import is_public_ip, safe_get, check_target, UnsafeTarget


@pytest.mark.parametrize("ip,pub", [("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.1", False),
                                    ("169.254.169.254", False), ("172.16.0.1", False), ("::1", False), ("::ffff:127.0.0.1", False),
                                    ("100.64.0.1", False), ("fd00::1", False), ("0.0.0.0", False)])
def test_ip_classification(ip, pub):
    assert is_public_ip(ip) is pub


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
                                 "http://2130706433/", "http://0x7f000001/", "http://[::1]/", "http://10.0.0.1:8080/"])
def test_private_targets_blocked(url, cfg):
    r = safe_get(url, cfg)
    assert not r.ok and r.error.startswith("blocked")


def test_odd_ports_and_schemes_blocked(cfg):
    with pytest.raises(UnsafeTarget):
        check_target("http://example.com:22/", cfg)
    with pytest.raises(UnsafeTarget):
        check_target("file:///etc/passwd", cfg)
