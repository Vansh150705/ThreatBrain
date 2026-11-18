"""Member lifecycle: who may change whose role/status, and the guards against lock-out and escalation."""

from __future__ import annotations

from tests.conftest import ORG_A, ORG_B

BASE = "/api/v1/organizations/members"


def uid(db, role, org=ORG_A):
    return next(u["id"] for u in db.rows("users") if u["role"] == role and u["organization_id"] == org)


def patch(client, auth, who, target, **body):
    return client.patch(f"{BASE}/{target}", json=body, headers=auth(who))


def test_admin_can_promote_analyst_and_disable_viewer(client, auth, db):
    assert patch(client, auth, "admin_a", uid(db, "analyst"), role="admin").status_code == 403   # admins cannot mint admins
    viewer = uid(db, "viewer")
    assert patch(client, auth, "owner_a", uid(db, "analyst"), role="admin").status_code == 200
    assert patch(client, auth, "admin_a", viewer, status="disabled").json()["status"] == "disabled"
    assert any(a["action"] == "member.disabled" for a in db.rows("audit_logs", organization_id=ORG_A))


def test_disabled_member_is_locked_out_immediately(client, auth, db):
    target = uid(db, "analyst")
    assert client.get("/api/v1/organizations/me", headers=auth("analyst_a")).status_code == 200
    assert patch(client, auth, "admin_a", target, status="disabled").status_code == 200
    r = client.get("/api/v1/organizations/me", headers=auth("analyst_a"))
    assert r.status_code == 403 and r.json()["detail"]["error"] == "user_disabled"
    assert patch(client, auth, "admin_a", target, status="active").status_code == 200
    assert client.get("/api/v1/organizations/me", headers=auth("analyst_a")).status_code == 200


def test_cannot_modify_self(client, auth, db):
    assert patch(client, auth, "owner_a", uid(db, "owner"), role="viewer").status_code == 409
    assert patch(client, auth, "admin_a", uid(db, "admin"), status="disabled").status_code == 409


def test_admin_cannot_touch_owners_or_grant_owner(client, auth, db):
    assert patch(client, auth, "admin_a", uid(db, "owner"), status="disabled").status_code == 403
    assert patch(client, auth, "admin_a", uid(db, "analyst"), role="owner").status_code == 403


def test_last_owner_guard(db, users):
    """Defence in depth against races: an owner actor who is not themselves an active owner (e.g. concurrently
    demoted) must not be able to remove the final active owner."""
    import pytest

    from app.api.deps import CurrentUser
    from app.services import member_service

    owner_id = uid(db, "owner")
    ghost_actor = CurrentUser(id="00000000-0000-0000-0000-00000000dead", organization_id=ORG_A, role="owner")
    for kwargs in ({"role": "viewer", "status": None}, {"role": None, "status": "disabled"}):
        with pytest.raises(member_service.MemberError) as exc:
            member_service.update_member(ghost_actor, owner_id, **kwargs)
        assert exc.value.code == "last_owner"


def test_owner_can_demote_another_owner_when_two_exist(client, auth, db):
    assert patch(client, auth, "owner_a", uid(db, "admin"), role="owner").status_code == 200
    assert patch(client, auth, "admin_a", uid(db, "owner"), role="viewer").status_code == 200   # admin_a is an owner now


def test_analyst_and_viewer_cannot_manage_members(client, auth, db):
    t = uid(db, "viewer")
    assert patch(client, auth, "analyst_a", t, role="analyst").status_code == 403
    assert patch(client, auth, "viewer_a", t, role="analyst").status_code == 403


def test_cross_tenant_member_is_invisible(client, auth, db):
    assert patch(client, auth, "owner_a", uid(db, "owner", ORG_B), role="viewer").status_code == 404
    assert patch(client, auth, "owner_b", uid(db, "viewer"), role="admin").status_code == 404


def test_validation(client, auth, db):
    t = uid(db, "viewer")
    assert patch(client, auth, "owner_a", t).status_code == 422
    assert patch(client, auth, "owner_a", t, role="superuser").status_code == 422
    assert patch(client, auth, "owner_a", t, status="deleted").status_code == 422


def test_member_list_hides_disabled_unless_admin_asks(client, auth, db):
    patch(client, auth, "owner_a", uid(db, "viewer"), status="disabled")
    assert all(m["status"] != "disabled" for m in client.get(BASE, headers=auth("analyst_a")).json()["items"])
    assert any(m["status"] == "disabled" for m in client.get(BASE, params={"include_disabled": True}, headers=auth("admin_a")).json()["items"])
    assert all(m["status"] != "disabled" for m in client.get(BASE, params={"include_disabled": True}, headers=auth("analyst_a")).json()["items"])
