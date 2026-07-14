from tb_executor.guard import is_blockable_ip, is_blockable_network


def test_public_ip_is_blockable():
    ok, _ = is_blockable_ip("8.8.8.8")
    assert ok is True


def test_loopback_rejected():
    ok, reason = is_blockable_ip("127.0.0.1")
    assert ok is False and "loopback" in reason


def test_private_ranges_rejected_by_default():
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.0.1"):
        ok, _ = is_blockable_ip(ip)
        assert ok is False


def test_link_local_rejected():
    ok, _ = is_blockable_ip("169.254.10.10")
    assert ok is False


def test_allowlisted_ip_rejected():
    ok, reason = is_blockable_ip("8.8.8.8", allowlist=["8.8.8.8"])
    assert ok is False and "allowlist" in reason


def test_garbage_rejected():
    ok, reason = is_blockable_ip("not-an-ip")
    assert ok is False and "valid" in reason


def test_allow_private_permits_lan_ip_but_never_loopback():
    ok, _ = is_blockable_ip("192.168.1.50", allow_private=True)
    assert ok is True
    ok2, reason = is_blockable_ip("127.0.0.1", allow_private=True)
    assert ok2 is False and "loopback" in reason


def test_public_cidr_blockable():
    ok, _ = is_blockable_network("8.8.8.0/24")
    assert ok is True


def test_too_broad_cidr_refused():
    ok, reason = is_blockable_network("10.0.0.0/8", allow_private=True)
    assert ok is False and "broad" in reason


def test_cidr_containing_allowlisted_ip_refused():
    ok, reason = is_blockable_network("8.8.8.0/24", allowlist=["8.8.8.8"])
    assert ok is False and "allowlisted" in reason


def test_invalid_cidr_refused():
    ok, _ = is_blockable_network("not-a-range")
    assert ok is False
