"""Detection content management: built-in rule tuning, custom rules, Sigma import, ATT&CK coverage."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, require_admin, require_analyst
from app.detection import sigma
from app.detection.correlation import load_correlations
from app.detection.engine import RuleError
from app.services import case_service, rule_service

router = APIRouter(prefix="/rules", tags=["detection-rules"])

Severity = Literal["info", "low", "medium", "high", "critical"]


class RuleDefinition(BaseModel):
    rule_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    severity: Severity
    confidence: int = Field(default=60, ge=0, le=100)
    techniques: list[str] = Field(default_factory=list, max_length=20)
    tags: list[str] = Field(default_factory=list, max_length=20)
    match: dict[str, Any]
    rule_references: list[str] = Field(default_factory=list, max_length=10)
    tuning_guidance: str | None = Field(default=None, max_length=2000)
    tests: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    origin: Literal["native", "sigma", "proposal"] = "native"
    sigma_source: str | None = Field(default=None, max_length=50_000)


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = None
    severity: Severity | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    techniques: list[str] | None = None
    tags: list[str] | None = None
    match: dict[str, Any] | None = None
    rule_references: list[str] | None = None
    tuning_guidance: str | None = None
    tests: list[dict[str, Any]] | None = None
    change_note: str | None = Field(default=None, max_length=300)


def _bad(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"error": "invalid_rule", "message": str(exc)})


@router.get("", summary="Built-in rules (with this tenant's overrides) and custom rules")
def list_rules(user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    return rule_service.list_rules(user.organization_id)


@router.get("/coverage", summary="MITRE ATT&CK coverage of the rules enabled for this tenant")
def coverage(user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    return rule_service.coverage(user.organization_id)


@router.get("/correlations", summary="Multi-event correlation definitions")
def correlations(user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    return {"items": [{"id": c.id, "name": c.name, "severity": c.severity, "kind": c.kind, "group_by": c.group_by,
                       "window_minutes": c.window_minutes, "techniques": list(c.techniques), "tactics": c.tactics}
                      for c in load_correlations()]}


@router.post("/validate", summary="Validate a rule and run its inline tests (nothing is saved)")
def validate(body: RuleDefinition, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    try:
        return rule_service.validate_definition(body.model_dump())
    except RuleError as exc:
        raise _bad(exc) from exc


class DryRun(BaseModel):
    rule: RuleDefinition
    event: dict[str, Any]


@router.post("/dry-run", summary="Evaluate a draft rule against one sample event")
def dry_run(body: DryRun, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    try:
        return rule_service.dry_run(body.rule.model_dump(), body.event)
    except RuleError as exc:
        raise _bad(exc) from exc


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a custom rule (as a draft)")
def create(body: RuleDefinition, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        row = rule_service.create_rule(user.organization_id, user.id, body.model_dump())
    except RuleError as exc:
        raise _bad(exc) from exc
    case_service.audit(user, action="detection_rule.created", target_type="detection_rule",
                       row={"id": row["id"], "title": row["rule_key"]}, changes={"severity": row["severity"]})
    return row


@router.put("/{rule_id}", summary="Edit a custom rule (new version; an enabled rule returns to draft)")
def update(rule_id: str, body: RuleUpdate, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    changes = body.model_dump(exclude_unset=True)
    note = changes.pop("change_note", None) or ""
    try:
        row = rule_service.update_rule(user.organization_id, user.id, rule_id, changes, note)
    except RuleError as exc:
        raise _bad(exc) from exc
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    case_service.audit(user, action="detection_rule.updated", target_type="detection_rule",
                       row={"id": row["id"], "title": row["rule_key"]}, changes={"version": row["version"], "fields": sorted(changes)})
    return row


class StatusBody(BaseModel):
    status: Literal["draft", "enabled", "disabled"]


@router.post("/{rule_id}/status", summary="Enable/disable a custom rule (enabling requires passing positive + negative tests)")
def set_status(rule_id: str, body: StatusBody, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        row = rule_service.set_status(user.organization_id, rule_id, body.status)
    except RuleError as exc:
        raise _bad(exc) from exc
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    case_service.audit(user, action=f"detection_rule.{body.status}", target_type="detection_rule",
                       row={"id": row["id"], "title": row["rule_key"]}, changes={}, severity="medium")
    return row


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response, response_model=None)
def delete(rule_id: str, user: Annotated[CurrentUser, Depends(require_admin)]) -> Response:
    row = rule_service.delete_rule(user.organization_id, rule_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    case_service.audit(user, action="detection_rule.deleted", target_type="detection_rule",
                       row={"id": rule_id, "title": row["rule_key"]}, changes={}, severity="medium")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{rule_id}/versions")
def versions(rule_id: str, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    return {"items": rule_service.versions(user.organization_id, rule_id)}


class RollbackBody(BaseModel):
    version: int = Field(ge=1)


@router.post("/{rule_id}/rollback", summary="Restore an earlier version (as a new version, in draft)")
def rollback(rule_id: str, body: RollbackBody, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        row = rule_service.rollback(user.organization_id, user.id, rule_id, body.version)
    except RuleError as exc:
        raise _bad(exc) from exc
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule or version not found.")
    case_service.audit(user, action="detection_rule.rolled_back", target_type="detection_rule",
                       row={"id": rule_id, "title": row["rule_key"]}, changes={"to_version": body.version}, severity="medium")
    return row


class OverrideBody(BaseModel):
    enabled: bool = True
    severity_override: Severity | None = None
    reason: str | None = Field(default=None, max_length=500)


@router.put("/builtin/{rule_key}/override", summary="Disable a built-in rule or change its severity for this tenant")
def override(rule_key: str, body: OverrideBody, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    if not body.enabled and not (body.reason or "").strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A reason is required to disable a built-in rule.")
    try:
        row = rule_service.set_override(user.organization_id, user.id, rule_key, enabled=body.enabled,
                                        severity=body.severity_override, reason=body.reason)
    except RuleError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    case_service.audit(user, action="detection_rule.override", target_type="detection_rule",
                       row={"id": None, "title": rule_key}, changes=body.model_dump(), reason=body.reason, severity="high")
    return row


class SigmaBody(BaseModel):
    sigma: str = Field(min_length=10, max_length=50_000)


@router.post("/sigma/convert", summary="Convert a Sigma rule (preview; nothing is saved)")
def sigma_convert(body: SigmaBody, user: Annotated[CurrentUser, Depends(require_analyst)]) -> dict[str, Any]:
    try:
        return sigma.convert(body.sigma)
    except RuleError as exc:
        raise _bad(exc) from exc


@router.post("/sigma/import", status_code=status.HTTP_201_CREATED, summary="Import a Sigma rule as a draft")
def sigma_import(body: SigmaBody, user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        converted = sigma.convert(body.sigma)
        row = rule_service.create_rule(user.organization_id, user.id, converted["rule"])
    except RuleError as exc:
        raise _bad(exc) from exc
    case_service.audit(user, action="detection_rule.sigma_imported", target_type="detection_rule",
                       row={"id": row["id"], "title": row["rule_key"]}, changes={})
    return {"rule": row, "warnings": converted["warnings"]}
