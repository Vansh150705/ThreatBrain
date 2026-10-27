from __future__ import annotations

from typing import Any

from tb_common.session import ApiError, ApiSession


class ExecutorError(Exception):
    pass


class ExecutorClient:
    """Talks to the ThreatBrain backend: list approved actions, report results.

    Uses an ``executor``-scoped API key (preferred) or an analyst login.
    """

    def __init__(
        self,
        base_url: str,
        email: str | None = None,
        password: str | None = None,
        http: Any = None,
        *,
        api_key: str | None = None,
    ) -> None:
        self.session = ApiSession(base_url, email, password, api_key=api_key, http=http)

    def list_pending_actions(self) -> list[dict[str, Any]]:
        """All approved-but-not-yet-executed actions (any action_type)."""
        try:
            body = self.session.json(
                "get", "/playbooks/approvals", params={"pending_execution": "true"}, timeout=30
            )
        except ApiError as exc:
            raise ExecutorError(f"list failed: {exc}") from exc
        return body.get("items", [])

    def report(self, approval_id: str, result: str, detail: str | None = None) -> dict[str, Any]:
        try:
            return self.session.json(
                "post",
                f"/playbooks/approvals/{approval_id}/execution",
                json={"result": result, "detail": detail},
                timeout=30,
            )
        except ApiError as exc:
            raise ExecutorError(f"report failed: {exc}") from exc
