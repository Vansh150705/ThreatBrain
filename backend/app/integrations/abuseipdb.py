from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)




class AbuseIPDBError(Exception):
    """Base class for AbuseIPDB failures."""


class AbuseIPDBNotConfigured(AbuseIPDBError):
    """Raised when ABUSEIPDB_API_KEY is not set."""


class AbuseIPDBRateLimited(AbuseIPDBError):
    """Raised when we exceed the daily quota."""


_retry = retry(
    retry=retry_if_exception_type(
        (httpx.HTTPError, httpx.TransportError, httpx.TimeoutException)
    ),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    reraise=True,
)

def check_ip(
    ip_address: str,
    *,
    max_age_days: int = 90,
    verbose: bool = True,
) -> dict[str, Any]:
    """Look up an IP's reputation in AbuseIPDB.

    Args:
        ip_address:   IPv4 or IPv6 to check.
        max_age_days: Only consider reports newer than this (1-365).
        verbose:      If True, include detailed report list.

    Returns:
        Dict with the raw "data" object from AbuseIPDB's response, e.g.:

        {
            "ipAddress": "203.0.113.42",
            "isPublic": true,
            "abuseConfidenceScore": 95,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Some ISP",
            "domain": "example.com",
            "totalReports": 1247,
            "lastReportedAt": "2026-05-27T...",
            "reports": [...]   # only if verbose=True
        }

    Raises:
        AbuseIPDBNotConfigured: API key missing.
        AbuseIPDBRateLimited:   429 from API.
        AbuseIPDBError:         any other failure after retries.
    """
    settings = get_settings()
    if not settings.ABUSEIPDB_API_KEY:
        raise AbuseIPDBNotConfigured(
            "ABUSEIPDB_API_KEY is not configured. Set it in backend/.env."
        )

    params: dict[str, str] = {
        "ipAddress": ip_address,
        "maxAgeInDays": str(max(1, min(365, max_age_days))),
    }
    if verbose:
        params["verbose"] = ""

    log.info("abuseipdb_check_starting", ip=ip_address)

    @_retry
    def _call() -> httpx.Response:
        return httpx.get(
            f"{settings.ABUSEIPDB_BASE_URL}/check",
            headers={
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params=params,
            timeout=10.0,
        )

    try:
        response = _call()
    except Exception as exc:
        log.exception("abuseipdb_request_failed", ip=ip_address)
        raise AbuseIPDBError(f"AbuseIPDB request failed: {exc}") from exc

    if response.status_code == 429:
        log.warning("abuseipdb_rate_limited", ip=ip_address)
        raise AbuseIPDBRateLimited(
            "AbuseIPDB daily quota exceeded. Resets at midnight UTC."
        )

    if response.status_code == 401 or response.status_code == 403:
        raise AbuseIPDBError(
            f"AbuseIPDB auth failed ({response.status_code}). Check ABUSEIPDB_API_KEY."
        )

    if response.status_code != 200:
        raise AbuseIPDBError(
            f"AbuseIPDB returned {response.status_code}: {response.text[:200]}"
        )

    body = response.json()
    data = body.get("data", {})

    log.info(
        "abuseipdb_check_completed",
        ip=ip_address,
        abuse_score=data.get("abuseConfidenceScore"),
        country=data.get("countryCode"),
        total_reports=data.get("totalReports"),
    )

    return data


def derive_reputation(abuse_score: int) -> str:
    """Map AbuseIPDB's 0-100 confidence score to our reputation enum.

    Score buckets:
        0       → benign
        1-39    → unknown
        40-74   → suspicious
        75-100  → malicious
    """
    if abuse_score >= 75:
        return "malicious"
    if abuse_score >= 40:
        return "suspicious"
    if abuse_score >= 1:
        return "unknown"
    return "benign"


__all__ = [
    "AbuseIPDBError",
    "AbuseIPDBNotConfigured",
    "AbuseIPDBRateLimited",
    "check_ip",
    "derive_reputation",
]