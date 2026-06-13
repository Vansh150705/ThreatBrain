"""Signup and login endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from supabase import Client, create_client
from supabase.client import ClientOptions

from app.api.v1.endpoints.meta import MeResponse
from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.organization import OrganizationMini
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# request and response models

class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    full_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class SignupResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: MeResponse


# helpers

def _get_anon_client() -> Client:
    """Fresh anon client for password sign in. Not cached because sign in mutates session state."""
    settings = get_settings()
    return create_client(
        supabase_url=str(settings.SUPABASE_URL),
        supabase_key=settings.SUPABASE_ANON_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )


def _seed_starter_data(admin: Client, org_id: str) -> None:
    """Give a new workspace some starter threats, an incident, and iocs so it isn't empty."""
    now = datetime.now(timezone.utc)

    def ago(**kwargs: int) -> str:
        return (now - timedelta(**kwargs)).isoformat()

    # iocs first so the attack map has points to plot
    admin.table("iocs").insert([
        {
            "organization_id": org_id,
            "ioc_type": "ipv4",
            "value": "203.0.113.42",
            "normalized_value": "203.0.113.42",
            "reputation": "malicious",
            "confidence": 95,
            "threat_score": 92,
            "tags": ["botnet", "brute-force", "ssh"],
            "source_feeds": ["abuseipdb", "otx"],
            "enrichment": {"abuseipdb": {"confidence": 95, "reports": 1247}},
            "geo_country": "RU",
            "geo_city": "Moscow",
            "asn": 12389,
            "times_seen": 47,
        },
        {
            "organization_id": org_id,
            "ioc_type": "ipv4",
            "value": "198.51.100.23",
            "normalized_value": "198.51.100.23",
            "reputation": "suspicious",
            "confidence": 70,
            "threat_score": 55,
            "tags": ["exfiltration", "anomaly"],
            "source_feeds": ["otx"],
            "enrichment": {},
            "geo_country": "RU",
            "geo_city": "Moscow",
            "asn": 12389,
            "times_seen": 3,
        },
    ]).execute()

    # incident before threats since threats point at it
    incident_id = str(uuid.uuid4())
    admin.table("incidents").insert({
        "id": incident_id,
        "organization_id": org_id,
        "title": "Coordinated intrusion attempt from Russian infrastructure",
        "description": (
            "SSH brute-force from 203.0.113.42 (Moscow) combined with a "
            "suspicious OAuth grant suggests a coordinated account-takeover "
            "attempt. Investigation in progress."
        ),
        "severity": "high",
        "status": "investigating",
        "priority": "p2",
        "confidence": 85,
        "risk_score": 80,
        "threat_count": 2,
        "asset_count": 0,
        "mitre_tactics": ["TA0001", "TA0003", "TA0006"],
        "mitre_techniques": ["T1110", "T1110.001", "T1098.001"],
        "source_ips": ["203.0.113.42"],
        "attribution": {"actor": "unknown", "infrastructure": "RU botnet"},
        "tags": ["brute-force", "oauth", "active"],
        "first_seen_at": ago(hours=3),
        "last_seen_at": ago(minutes=18),
    }).execute()

    admin.table("threats").insert([
        {
            "organization_id": org_id,
            "incident_id": incident_id,
            "title": "SSH brute-force from Russian botnet",
            "description": (
                "Sustained SSH brute-force attempts (~900 attempts/hour) from "
                "203.0.113.42 targeting root and admin accounts."
            ),
            "severity": "high",
            "status": "open",
            "confidence": 88,
            "risk_score": 82,
            "mitre_tactics": ["TA0001", "TA0006"],
            "mitre_techniques": ["T1110", "T1110.001"],
            "source_ips": ["203.0.113.42"],
            "affected_users": ["root", "admin"],
            "tags": ["brute-force", "ssh", "network"],
            "detected_at": ago(hours=3),
        },
        {
            "organization_id": org_id,
            "incident_id": incident_id,
            "title": "Suspicious OAuth grant to unverified third-party app",
            "description": (
                "A new OAuth grant with mailbox read scope was issued to an "
                "app whose publisher is unverified and registered yesterday."
            ),
            "severity": "medium",
            "status": "investigating",
            "confidence": 80,
            "risk_score": 65,
            "mitre_tactics": ["TA0003"],
            "mitre_techniques": ["T1098.001"],
            "source_ips": [],
            "affected_users": [],
            "tags": ["oauth", "persistence", "iam"],
            "detected_at": ago(hours=1, minutes=40),
        },
        {
            "organization_id": org_id,
            "title": "Anomalous outbound data transfer detected",
            "description": (
                "Outbound transfer of 1.2 GB to 198.51.100.23 outside of "
                "business hours deviates from the host's baseline."
            ),
            "severity": "low",
            "status": "open",
            "confidence": 60,
            "risk_score": 40,
            "mitre_tactics": ["TA0010"],
            "mitre_techniques": ["T1048"],
            "source_ips": ["198.51.100.23"],
            "affected_users": [],
            "tags": ["exfiltration", "anomaly"],
            "detected_at": ago(minutes=50),
        },
    ]).execute()


def _cleanup_failed_signup(admin: Client, user_id: str | None, org_id: str | None) -> None:
    """Roll back a half done signup so we don't leave orphan rows."""
    if org_id:
        try:
            admin.table("organizations").delete().eq("id", org_id).execute()
        except Exception:
            log.exception("signup_cleanup_org_failed", org_id=org_id)
    if user_id:
        try:
            admin.auth.admin.delete_user(user_id)
        except Exception:
            log.exception("signup_cleanup_auth_user_failed", user_id=user_id)


def _me_response(
    user_id: str,
    email: str,
    full_name: str,
    org_row: dict[str, Any],
) -> MeResponse:
    return MeResponse(
        id=user_id,
        email=email,
        full_name=full_name,
        role="owner",
        status="active",
        organization_id=str(org_row["id"]),
        avatar_url=None,
        organization=OrganizationMini.model_validate(
            {k: org_row[k] for k in ("id", "name", "slug", "plan")}
        ),
    )


# endpoints

@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
async def signup(request: SignupRequest) -> SignupResponse:
    """Create a verified user and set up their own workspace."""
    admin = get_supabase_admin()

    # create the auth user, email_confirm skips the confirmation email
    try:
        auth_response = admin.auth.admin.create_user(
            {
                "email": request.email,
                "password": request.password,
                "email_confirm": True,
                "user_metadata": {"full_name": request.full_name},
            }
        )
        user_id = auth_response.user.id
    except Exception as exc:
        message = str(exc)
        log.warning("signup_create_user_failed", email=request.email, error=message)
        if "already" in message.lower() or "registered" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email already exists. Try signing in instead.",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not create the account: {message}",
        ) from exc

    org_id: str | None = None
    try:
        # new org, a trigger seeds its default agents
        first_name = request.full_name.split()[0]
        org_name = f"{first_name}'s Workspace"
        org_slug = f"workspace-{user_id[:8]}"
        org_result = admin.table("organizations").insert(
            {
                "name": org_name,
                "slug": org_slug,
                "plan": "free",
                "status": "active",
                "is_demo_org": True,  # treat every signup as a demo org for now
            }
        ).execute()
        org_row = org_result.data[0]
        org_id = str(org_row["id"])

        # a trigger already made the users row, so upsert to set the org and owner role
        admin.table("users").upsert(
            {
                "id": user_id,
                "email": request.email,
                "full_name": request.full_name,
                "organization_id": org_id,
                "role": "owner",
                "status": "active",
            },
            on_conflict="id",
        ).execute()

        # fill the dashboard with some starter data
        _seed_starter_data(admin, org_id)
    except Exception as exc:
        log.exception("signup_provisioning_failed", email=request.email)
        _cleanup_failed_signup(admin, user_id, org_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signup failed while provisioning the workspace: {exc}",
        ) from exc

    # sign them in so we can hand back a session
    try:
        session_response = _get_anon_client().auth.sign_in_with_password(
            {"email": request.email, "password": request.password}
        )
        session = session_response.session
        if session is None:
            raise RuntimeError("Supabase returned no session.")
    except Exception as exc:
        log.exception("signup_autologin_failed", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account created, but automatic sign-in failed. Please sign in manually.",
        ) from exc

    log.info("signup_succeeded", user_id=user_id, org_id=org_id)
    return SignupResponse(
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        user=_me_response(user_id, request.email, request.full_name, org_row),
    )


@router.post("/login", response_model=SignupResponse)
async def login(request: LoginRequest) -> SignupResponse:
    """Password login returning the same shape as signup."""
    try:
        session_response = _get_anon_client().auth.sign_in_with_password(
            {"email": request.email, "password": request.password}
        )
        session = session_response.session
        user = session_response.user
        if session is None or user is None:
            raise RuntimeError("Supabase returned no session.")
    except Exception as exc:
        log.warning("login_failed", email=request.email, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        ) from exc

    # look up the profile and org like /me does
    admin = get_supabase_admin()
    profile_rows = (
        admin.table("users")
        .select("id, email, full_name, role, status, organization_id, avatar_url")
        .eq("id", user.id)
        .limit(1)
        .execute()
    ).data or []
    profile = profile_rows[0] if profile_rows else {}

    org: OrganizationMini | None = None
    if profile.get("organization_id"):
        org_rows = (
            admin.table("organizations")
            .select("id, name, slug, plan")
            .eq("id", profile["organization_id"])
            .limit(1)
            .execute()
        ).data or []
        if org_rows:
            org = OrganizationMini.model_validate(org_rows[0])

    return SignupResponse(
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        user=MeResponse(
            id=user.id,
            email=profile.get("email") or request.email,
            full_name=profile.get("full_name"),
            role=profile.get("role", "viewer"),
            status=profile.get("status", "active"),
            organization_id=profile.get("organization_id"),
            avatar_url=profile.get("avatar_url"),
            organization=org,
        ),
    )
