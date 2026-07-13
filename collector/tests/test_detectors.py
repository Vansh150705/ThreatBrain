from tb_collector.authevent import AuthEvent
from tb_collector.detectors import (
    DistributedBruteForce,
    LowAndSlow,
    PasswordSpraying,
    PerSourceGuessing,
    SuccessAfterFailure,
    UsernameEnumeration,
)


def ev(outcome="fail", ip="1.1.1.1", user="root", ts=0.0, service="ssh", count=1):
    return AuthEvent(service, ip, user, outcome, ts, "raw", count)


def test_per_source_guessing_fires_at_threshold():
    d = PerSourceGuessing(threshold=3, window=60)
    assert d.feed(ev(ts=0)) is None
    assert d.feed(ev(ts=1)) is None
    out = d.feed(ev(ts=2))
    assert out and out.kind == "brute_force" and out.count == 3


def test_per_source_uses_rsyslog_count_weight():
    d = PerSourceGuessing(threshold=10, window=60)
    out = d.feed(ev(ts=0, count=12))
    assert out and out.count == 12


def test_success_after_failure_needs_prior_fails():
    d = SuccessAfterFailure(min_fails=3, window=600)
    assert d.feed(ev(outcome="success", ts=0)) is None
    d.feed(ev(ts=1))
    d.feed(ev(ts=2))
    d.feed(ev(ts=3))
    out = d.feed(ev(outcome="success", ts=4))
    assert out and out.kind == "brute_force_success" and out.severity == "critical"


def test_password_spraying_counts_distinct_users():
    d = PasswordSpraying(distinct_users=3, window=300)
    assert d.feed(ev(user="a", ts=0)) is None
    assert d.feed(ev(user="b", ts=1)) is None
    out = d.feed(ev(user="c", ts=2))
    assert out and out.kind == "password_spraying"
    assert set(out.extra["usernames"]) == {"a", "b", "c"}


def test_password_spraying_same_user_does_not_trip():
    d = PasswordSpraying(distinct_users=3, window=300)
    last = None
    for i in range(5):
        last = d.feed(ev(user="a", ts=i))
    assert last is None


def test_username_enumeration_invalid_only():
    d = UsernameEnumeration(distinct_invalid=3, window=300)
    d.feed(ev(outcome="invalid", user="x", ts=0))
    d.feed(ev(outcome="invalid", user="y", ts=1))
    out = d.feed(ev(outcome="invalid", user="z", ts=2))
    assert out and out.kind == "username_enumeration"

    d2 = UsernameEnumeration(distinct_invalid=2, window=300)
    d2.feed(ev(outcome="fail", user="p", ts=0))
    assert d2.feed(ev(outcome="fail", user="q", ts=1)) is None


def test_distributed_many_ips_one_target():
    d = DistributedBruteForce(distinct_ips=3, window=300)
    d.feed(ev(ip="1.1.1.1", user="root", ts=0))
    d.feed(ev(ip="2.2.2.2", user="root", ts=1))
    out = d.feed(ev(ip="3.3.3.3", user="root", ts=2))
    assert out and out.kind == "distributed_brute_force"
    assert set(out.extra["source_ips"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}


def test_low_and_slow_uses_long_window():
    d = LowAndSlow(threshold=3, window=86400)
    d.feed(ev(ts=0))
    d.feed(ev(ts=40000))
    out = d.feed(ev(ts=80000))
    assert out and out.kind == "brute_force_slow"
