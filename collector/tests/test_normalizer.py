from datetime import datetime, timezone

from tb_collector.models import Detection
from tb_collector.normalizer import detection_to_ingest_payload


def _det(kind, **kw) -> Detection:
    now = datetime(2026, 7, 12, 9, 0, 0, tzinfo=timezone.utc)
    base = dict(
        kind=kind, source_ip="203.0.113.42", username="root", count=12,
        window_seconds=60, first_seen=now, last_seen=now, sample_lines=["raw line"],
        severity="high", mitre=["T1110.001"], extra={"service": "ssh"},
    )
    base.update(kw)
    return Detection(**base)


def test_brute_force_payload_shape():
    p = detection_to_ingest_payload(_det("brute_force"), collector_id="kali-01", asset_name="kali-box")
    assert p["source_system"] == "tb-collector/ssh"
    assert p["collector_id"] == "kali-01"
    ev = p["event"]
    assert ev["title"] and isinstance(ev["title"], str)
    assert ev["event_type"] == "authentication.brute_force"
    assert ev["source_ip"] == "203.0.113.42"
    assert ev["asset_name"] == "kali-box"
    assert ev["raw_data"]["detection_kind"] == "brute_force"
    assert ev["raw_data"]["mitre"] == ["T1110.001"]


def test_compromise_event_type_and_severity_hint():
    d = _det("brute_force_success", severity="critical", mitre=["T1110", "T1078"])
    p = detection_to_ingest_payload(d, collector_id="k")
    assert p["event"]["event_type"] == "authentication.brute_force_success"
    assert p["event"]["raw_data"]["severity_hint"] == "critical"
    assert "compromise" in p["event"]["title"].lower()


def test_distributed_titles_by_user():
    d = _det("distributed_brute_force", source_ip="9.9.9.9", username="admin",
             extra={"service": "ssh", "source_ips": ["1.1.1.1", "2.2.2.2"]})
    p = detection_to_ingest_payload(d, collector_id="k")
    assert p["event"]["event_type"] == "authentication.distributed_brute_force"
    assert "admin" in p["event"]["title"]


def test_asset_name_optional():
    p = detection_to_ingest_payload(_det("brute_force"), collector_id="k")
    assert p["event"]["asset_name"] is None
