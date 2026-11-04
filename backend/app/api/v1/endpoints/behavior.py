"""Behavioural analytics (UEBA): status, anomalies with explanations, baselines, tuning and analyst feedback."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import CurrentUser, require_admin, require_analyst, require_viewer
from app.behavior import config as bconfig
from app.behavior.features import FEATURES
from app.services import behavior_service, case_service, queue_service

router = APIRouter(prefix="/behavior", tags=["behavior"])
EntityType = Literal["user", "host"]
Disposition = Literal["confirmed", "benign", "expected"]


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    sensitivity: Literal["low", "balanced", "high"] | None = None
    params: dict[str, float | int] | None = None


class DispositionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: Disposition
    note: str | None = Field(default=None, max_length=500)


class SuppressionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_type: Literal["user", "host", "*"] = "*"
    entity_id: str = Field(default="*", max_length=256)
    feature: str = Field(default="*", max_length=64)
    value_key: str = Field(default="*", max_length=200)
    reason: str = Field(min_length=3, max_length=500)
    expires_in_days: float | None = Field(default=None, gt=0, le=365)


@router.get("/status", summary="Learning state, volume of anomalies and analyst feedback (precision of past alerts)")
def get_status(user: Annotated[CurrentUser, Depends(require_viewer)]) -> dict[str, Any]:
    return behavior_service.status(user.organization_id)


@router.get("/features", summary="What is measured, how heavily it weighs, and the ATT&CK techniques it maps to")
def get_features(user: Annotated[CurrentUser, Depends(require_viewer)]) -> list[dict[str, Any]]:
    return [{"feature": f.name, "family": f.family, "entity": f.entity, "method": f.kind, "weight": f.weight,
             "detection_id": f.code, "title": f.title, "techniques": list(f.techniques)} for f in FEATURES.values()]


@router.get("/anomalies", summary="Recorded deviations; most were never alerts")
def list_anomalies(
    user: Annotated[CurrentUser, Depends(require_analyst)],
    entity_id: str | None = Query(default=None, max_length=256),
    entity_type: EntityType | None = None,
    feature: str | None = Query(default=None, max_length=64),
    alerted: bool | None = None,
    disposition: Literal["open", "confirmed", "benign", "expected"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return behavior_service.list_anomalies(user.organization_id, entity_id=entity_id, entity_type=entity_type, feature=feature,
                                           alerted=alerted, disposition=disposition, limit=limit)


@router.get("/entities/{entity_type}/{entity_id:path}", summary="What this account/host normally does (the baseline, summarised)")
def entity_baseline(entity_type: EntityType, entity_id: str, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    out = behavior_service.entity_summary(user.organization_id, entity_type, entity_id)
    if out is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error": "not_found", "message": "No baseline for this entity yet."})
    return out


@router.patch("/anomalies/{anomaly_id}", summary="Analyst feedback: confirmed | benign (30-day suppression) | expected (teaches the baseline)")
def set_disposition(anomaly_id: str, body: DispositionIn, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    try:
        row = behavior_service.set_disposition(user.organization_id, anomaly_id, body.disposition, user.id, body.note)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"error": "not_found", "message": "Anomaly not found."})
    case_service.audit(user, action="behavior.disposition", target_type="behavior_anomaly",
                       row={"id": anomaly_id, "title": f"{row['feature']} {row['entity_id']}"}, changes={"disposition": body.disposition})
    return row


@router.get("/settings", summary="Sensitivity, switches and tunable thresholds (with their bounds)")
def get_settings(user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    row = behavior_service.get_settings_row(user.organization_id)
    return {"enabled": row["enabled"], "sensitivity": row["sensitivity"], "params": row.get("params") or {},
            "bounds": {k: list(v) for k, v in bconfig.BOUNDS.items()},
            "effective": bconfig.build(row["sensitivity"], row.get("params") or {}).__dict__}


@router.put("/settings", summary="Change behavioural settings (admin; audited; bounded)")
def put_settings(body: SettingsIn, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        row = behavior_service.update_settings(user.organization_id, enabled=body.enabled, sensitivity=body.sensitivity,
                                               params=body.params, user_id=user.id)
    except bconfig.ConfigError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error": "invalid_settings", "message": str(exc)}) from exc
    case_service.audit(user, action="behavior.settings_updated", target_type="organization",
                       row={"id": user.organization_id, "title": "behavior settings"},
                       changes={k: v for k, v in body.model_dump(exclude_none=True).items()})
    return {k: row[k] for k in ("enabled", "sensitivity", "params")}


@router.post("/suppressions", status_code=status.HTTP_201_CREATED, summary="Silence a known-good pattern (admin; audited)")
def add_suppression(body: SuppressionIn, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    row = behavior_service.add_suppression(user.organization_id, entity_type=body.entity_type, entity_id=body.entity_id,
                                           feature=body.feature, value_key=body.value_key, reason=body.reason,
                                           user_id=user.id, expires_in_days=body.expires_in_days)
    case_service.audit(user, action="behavior.suppression_added", target_type="organization",
                       row={"id": user.organization_id, "title": "behavior suppression"}, changes=body.model_dump(), reason=body.reason)
    return row


@router.post("/learn", status_code=status.HTTP_202_ACCEPTED, summary="Build baselines from stored history (admin)")
def learn_from_history(user: Annotated[CurrentUser, Depends(require_admin)], days: int = Query(default=14, ge=1, le=90)) -> dict[str, Any]:
    job = queue_service.enqueue(user.organization_id, "behavior.backfill", {"days": days}, queue="maintenance", priority=2, max_attempts=2)
    return {"queued": True, "job_id": (job or {}).get("id"), "days": days}


@router.post("/recluster", status_code=status.HTTP_202_ACCEPTED, summary="Recompute peer groups (admin)")
def recluster(user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    job = queue_service.enqueue(user.organization_id, "behavior.recluster", {}, queue="maintenance", priority=2, max_attempts=2)
    return {"queued": True, "job_id": (job or {}).get("id")}
