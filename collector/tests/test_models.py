from datetime import datetime, timezone

from tb_collector.models import Detection


def test_detection_holds_fields():
    now = datetime(2026, 7, 12, tzinfo=timezone.utc)
    d = Detection(
        kind="ssh_bruteforce",
        source_ip="203.0.113.42",
        username="root",
        count=12,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
    )
    assert d.source_ip == "203.0.113.42"
    assert d.count == 12
    assert d.sample_lines == []
