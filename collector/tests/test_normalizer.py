from datetime import datetime, timezone

from tb_collector.models import Detection
from tb_collector.normalizer import detection_to_ingest_payload


def _sample() -> Detection:
    now = datetime(2026, 7, 12, 9, 0, 0, tzinfo=timezone.utc)
    return Detection(
        kind="ssh_bruteforce",
        source_ip="203.0.113.42",
        username="root",
        count=12,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
        sample_lines=["Failed password for root from 203.0.113.42"],
    )


def test_payload_shape_and_required_title():
    p = detection_to_ingest_payload(_sample(), collector_id="kali-01", asset_name="kali-box")
    assert p["source_system"] == "tb-collector/ssh_bruteforce"
    assert p["collector_id"] == "kali-01"
    ev = p["event"]
    assert ev["title"] and isinstance(ev["title"], str)
    assert ev["source_ip"] == "203.0.113.42"
    assert ev["username"] == "root"
    assert ev["event_type"] == "authentication.brute_force"
    assert ev["asset_name"] == "kali-box"
    assert ev["raw_data"]["failed_count"] == 12
    assert ev["raw_data"]["window_seconds"] == 60


def test_asset_name_optional():
    p = detection_to_ingest_payload(_sample(), collector_id="kali-01")
    assert p["event"]["asset_name"] is None
