from __future__ import annotations

from collections import defaultdict
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import CurrentUser, get_current_user
from app.schemas.threat import (
    GeoThreatPoint,
    GeoThreatResponse,
    GeoThreatSummary,
    ThreatDetail,
    ThreatListItem,
    ThreatListResponse,
)
from app.services import threat_service
from app.services.supabase_client import get_supabase_admin

router = APIRouter(prefix="/threats", tags=["threats"])

# look up a lat lon for a country and city
_CITY_COORDINATES: dict[tuple[str, str], tuple[float, float]] = {
    ("RU", "Moscow"):        (55.7558,  37.6173),
    ("RU", "St Petersburg"): (59.9311,  30.3609),
    ("CN", "Shenzhen"):      (22.5431, 114.0579),
    ("CN", "Beijing"):       (39.9042, 116.4074),
    ("KP", "Pyongyang"):     (39.0392, 125.7625),
    ("US", "Mountain View"): (37.3861, -122.0839),
    ("DE", "Frankfurt"):     (50.1109,   8.6821),
    ("DE", "Berlin"):        (52.5200,  13.4050),
    ("JP", "Tokyo"):         (35.6762, 139.6503),
    ("GB", "London"):        (51.5074,  -0.1278),
    ("FR", "Paris"):         (48.8566,   2.3522),
    ("BR", "São Paulo"):     (-23.5505, -46.6333),
    ("IN", "Mumbai"):        (19.0760,  72.8777),
    ("IN", "Delhi"):         (28.7041,  77.1025),
}

# country code to lat lon centroid
_COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "RU": (61.5240,  105.3188),
    "CN": (35.8617,  104.1954),
    "KP": (40.3399,  127.5101),
    "US": (37.0902,  -95.7129),
    "DE": (51.1657,   10.4515),
    "JP": (36.2048,  138.2529),
    "GB": (55.3781,   -3.4360),
    "FR": (46.6034,    1.8883),
    "BR": (-14.2350, -51.9253),
    "IN": (20.5937,   78.9629),
    "UA": (48.3794,   31.1656),
    "IR": (32.4279,   53.6880),
    "KR": (35.9078,  127.7669),
    "NG": (9.0820,    8.6753),
    "ZA": (-30.5595,  22.9375),
    "AU": (-25.2744, 133.7751),
    "CA": (56.1304,  -106.3468),
    "MX": (23.6345,  -102.5528),
    "NL": (52.1326,    5.2913),
    "RO": (45.9432,   24.9668),
}

_COUNTRY_NAMES: dict[str, str] = {
    "RU": "Russia",
    "CN": "China",
    "KP": "North Korea",
    "US": "United States",
    "DE": "Germany",
    "JP": "Japan",
    "GB": "United Kingdom",
    "FR": "France",
    "BR": "Brazil",
    "IN": "India",
    "UA": "Ukraine",
    "IR": "Iran",
    "KR": "South Korea",
    "NG": "Nigeria",
    "ZA": "South Africa",
    "AU": "Australia",
    "CA": "Canada",
    "MX": "Mexico",
    "NL": "Netherlands",
    "RO": "Romania",
}

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


# List threats
@router.get("", response_model=ThreatListResponse)
async def list_threats(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1, description="Page number, starts at 1")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 25,
    severity: Annotated[str | None, Query(description="Filter by severity: critical, high, medium, low, info")] = None,
    threat_status: Annotated[str | None, Query(alias="status", description="Filter by status: open, investigating, resolved, false_positive")] = None,
    sort_by: Annotated[str, Query(description="Sort field: created_at, severity, status, confidence")] = "created_at",
    sort_dir: Annotated[str, Query(description="Sort direction: asc or desc")] = "desc",
) -> ThreatListResponse:
    """List threats for the caller's organization with filters, sorting, and pagination."""
    result = threat_service.list_threats(
        organization_id=user.organization_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=threat_status,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return ThreatListResponse(
        items=[ThreatListItem(**row) for row in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        has_more=result["has_more"],
    )


# keep this above /{identifier} or the router treats geo as an id
@router.get("/geo", response_model=GeoThreatResponse)
async def get_geo_threats(
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> GeoThreatResponse:
    """Return threat counts aggregated by country for the attack map."""
    admin = get_supabase_admin()

    # Fetch active threats for this org
    threats_res = (
        admin.table("threats")
        .select("id, short_id, title, severity, status, source_ips, detected_at")
        .eq("organization_id", user.organization_id)
        .is_("deleted_at", "null")
        .in_("status", ["open", "investigating", "contained"])
        .order("detected_at", desc=True)
        .execute()
    )
    threats = threats_res.data or []
    if not threats:
        return GeoThreatResponse(items=[], total_countries=0, total_threats=0)

    # Collect all unique source IPs across all threats
    all_ips: set[str] = set()
    for t in threats:
        for ip in (t.get("source_ips") or []):
            all_ips.add(ip)

    # Look up geo for all IPs in one query
    ip_geo: dict[str, dict] = {}
    if all_ips:
        ioc_res = (
            admin.table("iocs")
            .select("normalized_value, geo_country, geo_city")
            .in_("normalized_value", list(all_ips))
            .not_.is_("geo_country", "null")
            .execute()
        )
        for row in (ioc_res.data or []):
            ip_geo[row["normalized_value"]] = row

    # group by country and city, one dot per city
    point_threats: dict[tuple, list[dict]] = defaultdict(list)
    point_ips: dict[tuple, set[str]] = defaultdict(set)

    for t in threats:
        matched_keys: set[tuple] = set()
        for ip in (t.get("source_ips") or []):
            geo = ip_geo.get(ip)
            if not geo or not geo.get("geo_country"):
                continue
            cc = geo["geo_country"]
            if cc not in _COUNTRY_COORDS:
                continue
            city = geo.get("geo_city") or None
            # Use city-level key only when we have known coordinates for it
            if city and (cc, city) in _CITY_COORDINATES:
                key = (cc, city)
            else:
                key = (cc, None)
            matched_keys.add(key)
            point_ips[key].add(ip)
        for key in matched_keys:
            point_threats[key].append(t)

    # one response item per country and city
    items: list[GeoThreatPoint] = []
    for (cc, city), pt_threats in point_threats.items():
        if city and (cc, city) in _CITY_COORDINATES:
            lat, lon = _CITY_COORDINATES[(cc, city)]
        else:
            lat, lon = _COUNTRY_COORDS[cc]

        top_sev = max(pt_threats, key=lambda t: _SEVERITY_ORDER.get(t["severity"], 0))["severity"]
        recent = sorted(pt_threats, key=lambda t: t["detected_at"], reverse=True)[:5]
        items.append(
            GeoThreatPoint(
                country=cc,
                country_name=_COUNTRY_NAMES.get(cc, cc),
                city=city,
                latitude=lat,
                longitude=lon,
                threat_count=len(pt_threats),
                severity=top_sev,
                source_ips=sorted(point_ips[(cc, city)]),
                recent_threats=[
                    GeoThreatSummary(
                        short_id=t["short_id"],
                        title=t["title"],
                        severity=t["severity"],
                        detected_at=t["detected_at"],
                    )
                    for t in recent
                ],
            )
        )

    items.sort(key=lambda p: _SEVERITY_ORDER.get(p.severity, 0), reverse=True)

    unique_countries = len({cc for (cc, _) in point_threats})
    return GeoThreatResponse(
        items=items,
        total_countries=unique_countries,
        total_threats=sum(p.threat_count for p in items),
    )


# Threat detail by UUID or short_id
@router.get("/{identifier}", response_model=ThreatDetail)
async def get_threat(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ThreatDetail:
    """Fetch a single threat by UUID or short_id."""
    # Try UUID first, fall back to short_id
    threat = None
    try:
        uuid_value = UUID(identifier)
        threat = threat_service.get_threat_detail(user.organization_id, uuid_value)
    except ValueError:
        threat = threat_service.get_threat_by_short_id(user.organization_id, identifier)

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat '{identifier}' not found",
        )

    return ThreatDetail(**threat)