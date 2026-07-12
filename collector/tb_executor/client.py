from __future__ import annotations

from typing import Any


class ExecutorError(Exception):
    pass


class ExecutorClient:
    """Talks to the ThreatBrain backend: list approved blocks, report results."""

    def __init__(self, base_url: str, email: str, password: str, http: Any = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        if http is None:
            import requests

            http = requests.Session()
        self.http = http
        self._token: str | None = None

    def _login(self) -> None:
        resp = self.http.post(
            f"{self.base_url}/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise ExecutorError(f"login failed: {resp.status_code}")
        self._token = resp.json()["access_token"]

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def list_pending_blocks(self) -> list[dict[str, Any]]:
        if self._token is None:
            self._login()
        params = {"pending_execution": "true", "action_type": "block_ip"}
        resp = self.http.get(
            f"{self.base_url}/playbooks/approvals",
            params=params,
            headers=self._headers(),
            timeout=30,
        )
        if resp.status_code == 401:
            self._login()
            resp = self.http.get(
                f"{self.base_url}/playbooks/approvals",
                params=params,
                headers=self._headers(),
                timeout=30,
            )
        if resp.status_code != 200:
            raise ExecutorError(f"list failed: {resp.status_code}")
        return resp.json().get("items", [])

    def report(self, approval_id: str, result: str, detail: str | None = None) -> dict[str, Any]:
        if self._token is None:
            self._login()
        url = f"{self.base_url}/playbooks/approvals/{approval_id}/execution"
        payload = {"result": result, "detail": detail}
        resp = self.http.post(url, json=payload, headers=self._headers(), timeout=30)
        if resp.status_code == 401:
            self._login()
            resp = self.http.post(url, json=payload, headers=self._headers(), timeout=30)
        if resp.status_code != 200:
            raise ExecutorError(f"report failed: {resp.status_code}")
        return resp.json()
