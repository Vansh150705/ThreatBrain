"""Organization member lifecycle: role changes and (re)activation, with privilege-escalation guards."""

from __future__ import annotations

from typing import Any

from app.api.deps import CurrentUser
from app.services import case_service
from app.services.supabase_client import get_supabase_admin

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}


class MemberError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def list_all(org_id: str) -> list[dict[str, Any]]:
    return case_service.list_members(org_id)


def update_member(actor: CurrentUser, target_id: str, *, role: str | None, status: str | None) -> dict[str, Any]:
    client = get_supabase_admin()
    rows = (client.table("users").select("id, full_name, email, role, status")
            .eq("organization_id", actor.organization_id).eq("id", target_id).is_("deleted_at", "null").limit(1).execute().data)
    if not rows:
        raise MemberError(404, "member_not_found", "Member not found.")
    target = rows[0]
    if target_id == actor.id:
        raise MemberError(409, "self_modification", "You cannot change your own role or status.")
    if role is None and status is None:
        raise MemberError(422, "nothing_to_change", "Provide a role or a status.")
    if role is not None and role not in ROLE_RANK:
        raise MemberError(422, "bad_role", f"Role must be one of {sorted(ROLE_RANK)}.")
    if status is not None and status not in ("active", "disabled"):
        raise MemberError(422, "bad_status", "Status must be active or disabled.")

    # Only an owner may create, change or disable an owner; nobody may grant more than they hold.
    actor_rank, target_rank = ROLE_RANK[actor.role], ROLE_RANK.get(target["role"], 1)
    if target["role"] == "owner" or role == "owner":
        if actor.role != "owner":
            raise MemberError(403, "owner_required", "Only an owner can change owner access.")
    elif target_rank >= actor_rank or (role is not None and ROLE_RANK[role] >= actor_rank):
        # Least privilege: you can manage and grant only roles strictly below your own (admins cannot mint admins).
        raise MemberError(403, "insufficient_privilege", "You can only manage and grant roles below your own.")

    demoting_owner = (target["role"] == "owner" and target.get("status") == "active"
                      and (role not in (None, "owner") or status == "disabled"))
    if demoting_owner:
        others = [o for o in (client.table("users").select("id").eq("organization_id", actor.organization_id)
                              .eq("role", "owner").eq("status", "active").is_("deleted_at", "null").execute().data or [])
                  if o["id"] != target_id]
        if not others:
            raise MemberError(409, "last_owner", "An organization must keep at least one active owner.")

    patch = {k: v for k, v in (("role", role), ("status", status)) if v is not None}
    updated = (client.table("users").update(patch).eq("organization_id", actor.organization_id).eq("id", target_id).execute().data or [None])[0]
    if updated is None:
        raise MemberError(404, "member_not_found", "Member not found.")
    case_service.audit(
        actor, action="member.disabled" if status == "disabled" else "member.updated", target_type="user",
        row={"id": target_id, "title": target.get("email") or target.get("full_name")},
        changes={"from": {"role": target["role"], "status": target["status"]}, "to": patch}, severity="high",
    )
    return {k: updated.get(k) for k in ("id", "full_name", "email", "role", "status")}
