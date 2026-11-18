"""Threat-intel and notification connectors under fault injection.

VERIFIED HERE: behaviour against a scripted HTTP transport (timeouts, 5xx, 429, auth failures, garbage, oversize, partial outages).
NOT VERIFIED HERE: the real AbuseIPDB / VirusTotal / OTX / Discord services (no outbound credentials in the build environment).
"""

from __future__ import annotations

import time

import httpx
import pytest

from app.core.config import get_settings
from app.integrations import _http
from app.integrations.intel import enrich_ip

SECRET = "super-secret-feed-key-0123456789"


@pytest.fixture()
def feeds(monkeypatch):
    s = get_settings()
    for k in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY"):
        monkeypatch.setattr(s, k, SECRET)
    monkeypatch.setattr("tenacity.nap.time.sleep", lambda *_: None)       # retries are exercised, not waited for
    state = {"calls": {}, "plan": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        feed = "abuseipdb" if "abuseipdb" in request.url.host else "virustotal" if "virustotal" in request.url.host else "otx"
        state["calls"][feed] = state["calls"].get(feed, 0) + 1
        what = state["plan"].get(feed, "ok")
        if what == "timeout":
            raise httpx.ReadTimeout("read timed out", request=request)
        if what == "connect":
            raise httpx.ConnectError("refused", request=request)
        if what in ("500", "503", "429", "401", "403"):
            return httpx.Response(int(what), headers={"Retry-After": "3600"})
        if what == "garbage":
            return httpx.Response(200, content=b"<html>not json</html>")
        if what == "array":
            return httpx.Response(200, json=[1, 2, 3])
        if what == "empty":
            return httpx.Response(200, content=b"")
        if what == "huge":
            return httpx.Response(200, content=b'{"data": "' + b"A" * 3_000_000 + b'"}')
        if feed == "abuseipdb":
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 9, "countryCode": "RU"}})
        if feed == "virustotal":
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 1}}}})
        return httpx.Response(200, json={"pulse_info": {"count": 2, "pulses": []}})

    monkeypatch.setattr(_http, "_transport", httpx.MockTransport(handler))
    return state


@pytest.mark.parametrize("fault", ["timeout", "connect", "500", "503", "429", "401", "403", "garbage", "array", "empty", "huge"])
def test_every_fault_in_one_feed_degrades_that_feed_only(feeds, fault):
    feeds["plan"]["virustotal"] = fault
    t0 = time.monotonic()
    out = enrich_ip("203.0.113.42")
    assert time.monotonic() - t0 < 5
    assert {"abuseipdb", "otx"} <= set(out["feeds"]) and out["composite_score"] is not None
    if fault not in ("array", "empty"):
        assert "virustotal" in out["errors"] or "virustotal" not in out["feeds"], out
    assert SECRET not in str(out), "an API key leaked into the enrichment result"


def test_transport_errors_are_retried_a_bounded_number_of_times(feeds):
    feeds["plan"]["abuseipdb"] = "timeout"
    enrich_ip("203.0.113.42")
    assert feeds["calls"]["abuseipdb"] == 3                # three attempts, then give up: no retry storm against a struggling provider
    feeds["calls"].clear()
    feeds["plan"]["abuseipdb"] = "503"
    enrich_ip("203.0.113.42")
    assert feeds["calls"]["abuseipdb"] == 1                # a definite HTTP answer is not hammered


def test_rate_limited_and_unauthorised_feeds_are_reported_not_retried(feeds):
    feeds["plan"].update(abuseipdb="429", virustotal="401")
    out = enrich_ip("203.0.113.42")
    assert feeds["calls"]["abuseipdb"] == 1 and feeds["calls"]["virustotal"] == 1
    assert set(out["errors"]) >= {"abuseipdb", "virustotal"} and set(out["feeds"]) == {"otx"}


def test_all_feeds_down_returns_a_clean_empty_result_not_an_exception(feeds):
    feeds["plan"].update(abuseipdb="connect", virustotal="timeout", otx="500")
    out = enrich_ip("203.0.113.42")
    assert out["feeds"] == {} and len(out["errors"]) == 3 and out["composite_score"] is None


def test_oversized_response_is_refused_without_being_parsed(feeds):
    feeds["plan"]["otx"] = "huge"
    out = enrich_ip("203.0.113.42")
    assert "otx" in out["errors"] and "too large" in str(out["errors"]["otx"])


def test_pipeline_still_files_a_threat_when_every_intel_feed_is_down(client, auth, db, feeds):
    from tests.test_pipeline import _ingest

    feeds["plan"].update(abuseipdb="timeout", virustotal="500", otx="connect")
    r = _ingest(client, auth)
    assert r.status_code == 200 and r.json()["summary"]["promoted_threat_id"]


def test_discord_notifier_survives_every_transport_failure(monkeypatch):
    from app.services import notifier

    s = get_settings()
    monkeypatch.setattr(s, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1/x")
    inc = {"short_id": "INC-1", "title": "Bad", "severity": "critical", "priority": "p1", "threat_count": 2, "source_ips": ["203.0.113.1"]}
    for exc in (httpx.ConnectTimeout("t"), httpx.ReadError("r"), RuntimeError("boom")):
        def boom(request, exc=exc):
            raise exc
        monkeypatch.setattr(notifier, "_transport", httpx.MockTransport(boom))
        assert notifier.notify_incident(inc) is False       # never raises into the pipeline
    monkeypatch.setattr(notifier, "_transport", httpx.MockTransport(lambda r: httpx.Response(429, headers={"Retry-After": "5"})))
    assert notifier.notify_incident(inc) is False
